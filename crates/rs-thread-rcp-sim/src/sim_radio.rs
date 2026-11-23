//! A [`Radio`] on OpenThread's real-time simulation radio protocol
//! (`examples/platforms/simulation/radio.c` with `OPENTHREAD_SIMULATION_VIRTUAL_TIME=0`).
//!
//! Every node sends its frames as UDP datagrams (`u8` channel, PSDU with FCS)
//! to the multicast group `224.0.0.116` on port `PORT_BASE + PORT_OFFSET * 34`
//! from the port of its own node ID (`+ node ID`), and receives everything on
//! that group port; the sender's port tells which node a frame is from.
//!
//! The radio does what a hardware 802.15.4 radio does: address filtering,
//! immediate ACKs (Frame Pending from the source match table for data
//! requests), and the wait for the ACK of a transmitted frame.

#![allow(clippy::std_instead_of_core)]

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::task::Poll;
use std::time::{Duration, Instant};

use rs_thread_core::types::{PanId, ShortAddress};
use rs_thread_mac::frame::{Address, Frame, FrameType};
use rs_thread_mac::mac::{crc16, fcs};
use rs_thread_platform::radio::{
    Capabilities, Config, MacCapabilities, PsduRxInfo, PsduTxInfo, Radio, RadioCaps, RadioClock,
    RadioErrorKind, SrcMatchConfig,
};
use socket2::{Domain, Protocol, Socket, Type};

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 116);
const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
/// `MAX_NETWORK_SIZE + 1` of the OpenThread simulation.
const PORT_STRIDE: u16 = 34;
/// Time to wait for the ACK of a transmitted frame.
const ACK_TIMEOUT: Duration = Duration::from_millis(16);
/// RSSI the OpenThread simulation reports for every frame.
const RSSI: i8 = -20;
/// Noise floor of the simulation (energy scan result).
const NOISE_FLOOR: i8 = -100;
const MAX_PSDU: usize = 127;

/// Appends a line to the file named by `RSTHREAD_RCP_LOG`, if set (stdout
/// and stderr carry the Spinel link and must stay clean).
pub fn log(line: &str) {
    use std::io::Write;
    static FILE: std::sync::OnceLock<Option<std::sync::Mutex<std::fs::File>>> =
        std::sync::OnceLock::new();
    let f = FILE.get_or_init(|| {
        let path = std::env::var_os("RSTHREAD_RCP_LOG")?;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()?;
        Some(std::sync::Mutex::new(f))
    });
    if let Some(f) = f {
        if let Ok(mut f) = f.lock() {
            let _ = writeln!(f, "{:>10} {line}", micros_since_start());
        }
    }
}

fn micros_since_start() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_micros() as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Sleep,
    Receive(u8),
}

/// The simulation radio of one node.
#[derive(Debug)]
pub struct SimRadio {
    rx: UdpSocket,
    tx: UdpSocket,
    group_addr: SocketAddr,
    own_port: u16,
    state: State,
    config: Config,
    src_match: SrcMatchConfig,
    queue: VecDeque<(Vec<u8>, PsduRxInfo)>,
    /// Sequence number of the transmitted frame whose ACK is awaited.
    awaiting_ack: Option<u8>,
    ack: Option<(Vec<u8>, bool)>,
}

impl SimRadio {
    /// Joins the simulation as node `node_id`; `port_base` and `port_offset`
    /// are `PORT_BASE` / `PORT_OFFSET` of the simulation.
    pub fn new(node_id: u16, port_base: u16, port_offset: u16) -> io::Result<Self> {
        let group_port = port_base + port_offset * PORT_STRIDE;
        let own_port = group_port + node_id;

        let rx = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        rx.set_reuse_address(true)?;
        rx.set_reuse_port(true)?;
        rx.set_multicast_if_v4(&LOOPBACK)?;
        rx.join_multicast_v4(&GROUP, &LOOPBACK)?;
        rx.bind(&SocketAddrV4::new(GROUP, group_port).into())?;
        rx.set_nonblocking(true)?;

        let tx = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        tx.set_multicast_if_v4(&LOOPBACK)?;
        tx.set_multicast_loop_v4(true)?;
        tx.bind(&SocketAddrV4::new(LOOPBACK, own_port).into())?;
        tx.set_nonblocking(true)?;

        Ok(Self {
            rx: rx.into(),
            tx: tx.into(),
            group_addr: SocketAddrV4::new(GROUP, group_port).into(),
            own_port,
            state: State::Sleep,
            config: Config::new(),
            src_match: SrcMatchConfig::new(),
            queue: VecDeque::new(),
            awaiting_ack: None,
            ack: None,
        })
    }

    /// The radio capabilities: ACK handling, filtering and source matching in
    /// "hardware"; the RCP adds frame retries.
    pub fn caps() -> RadioCaps {
        RadioCaps {
            phy: Capabilities::ACK_TIMEOUT
                | Capabilities::ENERGY_SCAN
                | Capabilities::CSMA_BACKOFF
                | Capabilities::SLEEP_TO_TX
                | Capabilities::TRANSMIT_TIMING,
            mac: MacCapabilities::all(),
            clock: Some(RadioClock(micros_since_start)),
            receive_sensitivity: -100,
            default_tx_power: 0,
            default_cca_threshold: -75,
            csl_accuracy_ppm: 20,
            csl_uncertainty: 10,
            ..RadioCaps::default()
        }
    }

    fn send(&self, channel: u8, psdu: &[u8]) {
        let mut msg = [0u8; MAX_PSDU + 3];
        msg[0] = channel;
        msg[1..=psdu.len()].copy_from_slice(psdu);
        let _ = self.tx.send_to(&msg[..=psdu.len()], self.group_addr);
    }

    fn send_ack(&self, channel: u8, seq: u8, frame_pending: bool) {
        let mut ack = [0x02 | ((frame_pending as u8) << 4), 0x00, seq, 0, 0];
        let crc = fcs(&ack[..3]);
        ack[3..].copy_from_slice(&crc);
        self.send(channel, &ack);
    }

    /// Whether `frame` is addressed to this node (`otMacFrameDoesAddrMatch`).
    fn matches(&self, frame: &Frame<'_>) -> bool {
        if self.config.promiscuous {
            return true;
        }
        if let Some(pan) = frame.dst_pan_id() {
            if pan != PanId::BROADCAST && Some(pan.0) != self.config.pan_id {
                return false;
            }
        }
        match frame.dst_address() {
            Address::None => true,
            Address::Short(a) => {
                a == ShortAddress::BROADCAST
                    || Some(a.0) == self.config.short_addr
                    || Some(a.0) == self.config.alt_short_addr
            }
            Address::Extended(e) => self.config.ext_addr == Some(u64::from_be_bytes(e.0)),
        }
    }

    /// Reads what arrived: ACKs for the pending transmission, ACKs the radio
    /// owes, frames for the receive queue.
    fn pump(&mut self) {
        let mut buf = [0u8; MAX_PSDU + 8];
        loop {
            let (n, from) = match self.rx.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => return,
            };
            if from.port() == self.own_port || n < 1 + 5 {
                continue;
            }
            let State::Receive(channel) = self.state else {
                continue;
            };
            if buf[0] != channel {
                continue;
            }
            let psdu = &buf[1..n];
            let len = psdu.len();
            if len > MAX_PSDU || crc16(&psdu[..len - 2]).to_le_bytes() != psdu[len - 2..] {
                continue;
            }
            let Ok(frame) = Frame::parse(&psdu[..len - 2]) else {
                log(&format!("rx unparsable len {len}"));
                continue;
            };
            log(&format!(
                "rx {:?} len {len} seq {:?} dst {:?} ar {} match {}",
                frame.frame_type(),
                frame.sequence(),
                frame.dst_address(),
                frame.ack_request(),
                self.matches(&frame)
            ));
            if std::env::var_os("RSTHREAD_RCP_HEX").is_some() {
                let hex: String = psdu.iter().map(|b| format!("{b:02x}")).collect();
                log(&format!("   {hex}"));
            }
            if frame.frame_type() == FrameType::Ack {
                if self.awaiting_ack.is_some() && frame.sequence() == self.awaiting_ack {
                    self.ack = Some((psdu.to_vec(), frame.frame_pending()));
                }
                continue;
            }
            if !self.matches(&frame) {
                continue;
            }
            let unicast = !matches!(frame.dst_address(), Address::Short(a) if a == ShortAddress::BROADCAST)
                && !frame.dst_address().is_none();
            if frame.ack_request() && unicast {
                if let Some(seq) = frame.sequence() {
                    let pending = frame.is_data_request()
                        && self.src_match.ack_frame_pending(
                            match frame.src_address() {
                                Address::Short(a) => a.0,
                                _ => 0xfffe,
                            },
                            match frame.src_address() {
                                Address::Extended(e) => u64::from_be_bytes(e.0),
                                _ => 0,
                            },
                        );
                    self.send_ack(channel, seq, pending);
                }
            }
            let info = PsduRxInfo {
                len,
                channel,
                rssi: Some(RSSI),
                lqi: None,
                timestamp_us: Some(micros_since_start()),
                ack_security: None,
                acked_with_frame_pending: None,
            };
            if self.queue.len() < 16 {
                self.queue.push_back((psdu.to_vec(), info));
            }
        }
    }
}

impl Radio for SimRadio {
    type Error = RadioErrorKind;

    async fn init(&mut self) -> Result<RadioCaps, Self::Error> {
        self.state = State::Sleep;
        Ok(Self::caps())
    }

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        self.config = config.clone();
        Ok(())
    }

    async fn set_src_match_config(&mut self, config: &SrcMatchConfig) -> Result<(), Self::Error> {
        self.src_match = config.clone();
        Ok(())
    }

    async fn set_receive(&mut self, channel: u8) -> Result<(), Self::Error> {
        self.state = State::Receive(channel);
        Ok(())
    }

    async fn set_sleep(&mut self) -> Result<(), Self::Error> {
        self.state = State::Sleep;
        self.queue.clear();
        Ok(())
    }

    async fn energy_scan(
        &mut self,
        _channel: u8,
        _duration_millis: u16,
    ) -> Result<i8, Self::Error> {
        Ok(NOISE_FLOOR)
    }

    async fn transmit(
        &mut self,
        psdu: &mut [u8],
        psdu_tx: &mut PsduTxInfo,
        channel: u8,
        _power: i8,
        _cca_threshold: Option<i8>,
        ack_psdu_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduRxInfo>, Self::Error> {
        let len = psdu.len();
        if !(5..=MAX_PSDU).contains(&len) {
            return Err(RadioErrorKind::TxInvalid);
        }
        let crc = fcs(&psdu[..len - 2]);
        psdu[len - 2..].copy_from_slice(&crc);
        let (ack_request, seq) = Frame::parse(&psdu[..len - 2])
            .map(|f| (f.ack_request(), f.sequence()))
            .map_err(|_| RadioErrorKind::TxInvalid)?;
        let before = self.state;
        // The ACK arrives on the channel the frame went out on.
        self.state = State::Receive(channel);
        if let Some(at) = psdu_tx.tx_at_us {
            // A timed transmission (CSL): wait for the time, receiving meanwhile.
            core::future::poll_fn(|_| {
                self.pump();
                if micros_since_start() >= at {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        log(&format!(
            "tx len {len} ch {channel} ar {ack_request} seq {seq:?}"
        ));
        self.send(channel, psdu);
        let result = if ack_request {
            self.awaiting_ack = seq;
            self.ack = None;
            let deadline = Instant::now() + ACK_TIMEOUT;
            let got = core::future::poll_fn(|_| {
                self.pump();
                if self.ack.is_some() {
                    Poll::Ready(true)
                } else if Instant::now() >= deadline {
                    Poll::Ready(false)
                } else {
                    Poll::Pending
                }
            })
            .await;
            self.awaiting_ack = None;
            match (got, self.ack.take(), ack_psdu_buf) {
                (true, Some((ack, pending)), Some(buf)) if ack.len() <= buf.len() => {
                    buf[..ack.len()].copy_from_slice(&ack);
                    Ok(Some(PsduRxInfo {
                        len: ack.len(),
                        channel,
                        rssi: Some(RSSI),
                        lqi: None,
                        timestamp_us: Some(micros_since_start()),
                        ack_security: None,
                        acked_with_frame_pending: Some(pending),
                    }))
                }
                (true, _, _) => Ok(None),
                _ => Err(RadioErrorKind::RxAckTimeout),
            }
        } else {
            Ok(None)
        };
        self.state = before;
        result
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduRxInfo, Self::Error> {
        core::future::poll_fn(|_| {
            self.pump();
            match self.queue.pop_front() {
                Some((psdu, info)) if psdu.len() <= psdu_buf.len() => {
                    psdu_buf[..psdu.len()].copy_from_slice(&psdu);
                    Poll::Ready(Ok(info))
                }
                Some(_) => Poll::Ready(Err(RadioErrorKind::RxInvalid)),
                None => Poll::Pending,
            }
        })
        .await
    }
}
