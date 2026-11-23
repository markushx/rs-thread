//! Host-side Spinel driver: drives an RCP over a [`Transport`] and exposes a
//! [`Radio`] interface to the rs-thread MAC layer.
//!
//! This is the mirror of [`crate::rcp::Rcp`]: where the device side *answers*
//! Spinel property GET/SET commands, this side *sends* them and waits for
//! their responses.  Unsolicited `STREAM_RAW` frames that arrive while a
//! command is in flight are queued and returned by later [`Radio::receive`]
//! calls.
//!
//! The driver is **cooperative / inline**: every `Radio` method writes one
//! Spinel command and loops reading from the transport until it sees the
//! matching TID.  This matches the single-threaded model of the embassy
//! runner that calls `Radio` methods sequentially.

extern crate std;
#[allow(unused_imports)]
use std::prelude::v1::*;

use std::collections::VecDeque;

use rs_thread_platform::radio::{
    AckSecurity, Capabilities, Config, MacCapabilities, MacKeys, PsduRxInfo, PsduTxInfo, Radio,
    RadioCaps, RadioError, RadioErrorKind, SrcMatchConfig, RSSI_INVALID,
};
use rs_thread_spinel::codec::{Reader, Writer};
use rs_thread_spinel::consts::{cmd, md_flag, prop, scan_state, status};
use rs_thread_spinel::frame::{self, Frame, Header};
use rs_thread_spinel::hdlc;

use crate::rcp::Transport;

/// Largest Spinel frame on the wire.
const MAX_FRAME: usize = 320;
/// HDLC output buffer (worst-case encoded size).
const HDLC_BUF: usize = hdlc::max_encoded_len(MAX_FRAME);

// ── Error ────────────────────────────────────────────────────────────────────

/// Errors from [`RadioSpinel`].
#[derive(Debug)]
pub enum Error {
    /// The transport failed.
    Transport(String),
    /// The RCP sent a malformed or unexpected Spinel frame.
    Protocol,
    /// The RCP returned a non-OK `LAST_STATUS` code.
    Rcp(u32),
}

impl RadioError for Error {
    fn kind(&self) -> RadioErrorKind {
        RadioErrorKind::Other
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Transport(s) => write!(f, "transport: {s}"),
            Error::Protocol => write!(f, "protocol error"),
            Error::Rcp(c) => write!(f, "RCP status {c}"),
        }
    }
}

impl std::error::Error for Error {}

fn transport_err<E: core::fmt::Debug>(e: E) -> Error {
    Error::Transport(format!("{e:?}"))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Decodes a `PROP_VALUE_IS` response payload: packed key + value bytes.
fn decode_prop(payload: &[u8]) -> Result<(u32, &[u8]), Error> {
    let mut r = Reader::new(payload);
    let key = r.packed().map_err(|_| Error::Protocol)?;
    Ok((key, r.rest()))
}

// ── RX frame buffer ──────────────────────────────────────────────────────────

struct RxFrame {
    psdu: Vec<u8>,
    info: PsduRxInfo,
}

// ── Response ─────────────────────────────────────────────────────────────────

struct Response {
    command: u32,
    payload: Vec<u8>,
}

impl Response {
    fn property(&self) -> Result<(u32, &[u8]), Error> {
        decode_prop(&self.payload)
    }
}

// ── RadioSpinel ───────────────────────────────────────────────────────────────

/// Host-side Spinel driver.  Implements [`Radio`] by driving an RCP over a
/// [`Transport`].
pub struct RadioSpinel<T> {
    io: T,
    dec: hdlc::Decoder<MAX_FRAME>,
    /// Next TID to use (1 ..= 15, wrapping).
    tid: u8,
    inbuf: [u8; 64],
    spinel_buf: [u8; MAX_FRAME],
    hdlc_buf: [u8; HDLC_BUF],
    rx_queue: VecDeque<RxFrame>,
    channel: u8,
    cca_threshold: i8,
    rx_on: bool,
}

impl<T> core::fmt::Debug for RadioSpinel<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RadioSpinel")
            .field("channel", &self.channel)
            .field("rx_on", &self.rx_on)
            .finish_non_exhaustive()
    }
}

impl<T: Transport> RadioSpinel<T> {
    /// Wraps `io` in a new host driver. Call [`Radio::init`] before any other
    /// method.
    pub fn new(io: T) -> Self {
        Self {
            io,
            dec: hdlc::Decoder::new(),
            tid: 0,
            inbuf: [0; 64],
            spinel_buf: [0; MAX_FRAME],
            hdlc_buf: [0; HDLC_BUF],
            rx_queue: VecDeque::new(),
            channel: 11,
            cca_threshold: RadioCaps::DEFAULT_CCA_THRESHOLD,
            rx_on: false,
        }
    }

    fn next_tid(&mut self) -> u8 {
        self.tid = if self.tid >= 15 { 1 } else { self.tid + 1 };
        self.tid
    }

    async fn send_cmd(
        &mut self,
        tid: u8,
        spinel_cmd: u32,
        spinel_prop: u32,
        value_fn: impl FnOnce(&mut Writer<'_>) -> rs_thread_spinel::Result<()>,
    ) -> Result<(), Error> {
        let header = Header::new(0, tid);
        let mut w = Writer::new(&mut self.spinel_buf);
        frame::begin_property(&mut w, header, spinel_cmd, spinel_prop)
            .and_then(|()| value_fn(&mut w))
            .map_err(|_| Error::Protocol)?;
        let n = w.len();
        let len = hdlc::encode(&self.spinel_buf[..n], &mut self.hdlc_buf)
            .map_err(|_| Error::Protocol)?;
        self.io
            .write_all(&self.hdlc_buf[..len])
            .await
            .map_err(transport_err)
    }

    async fn read_one_raw(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            let n = self.io.read(&mut self.inbuf).await.map_err(transport_err)?;
            for &b in &self.inbuf[..n] {
                match self.dec.feed(b) {
                    Some(Ok(payload)) => return Ok(payload.to_vec()),
                    Some(Err(_)) | None => {}
                }
            }
        }
    }

    /// Reads frames until one with TID `tid` arrives; queues unsolicited RX.
    async fn transact(&mut self, tid: u8) -> Result<Response, Error> {
        loop {
            let raw = self.read_one_raw().await?;
            let f = Frame::parse(&raw).map_err(|_| Error::Protocol)?;
            if f.header.tid == 0 {
                if f.command == cmd::PROP_VALUE_IS {
                    if let Ok((key, value)) = decode_prop(f.payload) {
                        if key == prop::STREAM_RAW {
                            if let Some(rx) = Self::parse_rx_frame(value) {
                                self.rx_queue.push_back(rx);
                            }
                        }
                    }
                }
                continue;
            }
            if f.header.tid == tid {
                return Ok(Response {
                    command: f.command,
                    payload: f.payload.to_vec(),
                });
            }
        }
    }

    async fn get_prop(&mut self, spinel_prop: u32) -> Result<Response, Error> {
        let tid = self.next_tid();
        self.send_cmd(tid, cmd::PROP_VALUE_GET, spinel_prop, |_| Ok(()))
            .await?;
        self.transact(tid).await
    }

    async fn set_prop(
        &mut self,
        spinel_prop: u32,
        value_fn: impl FnOnce(&mut Writer<'_>) -> rs_thread_spinel::Result<()>,
    ) -> Result<(), Error> {
        let tid = self.next_tid();
        self.send_cmd(tid, cmd::PROP_VALUE_SET, spinel_prop, value_fn)
            .await?;
        let resp = self.transact(tid).await?;
        if resp.command == cmd::PROP_VALUE_IS {
            if let Ok((key, val)) = resp.property() {
                if key == prop::LAST_STATUS {
                    let code = Reader::new(val).packed().unwrap_or(status::FAILURE);
                    if code != status::OK {
                        return Err(Error::Rcp(code));
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_rx_frame(payload: &[u8]) -> Option<RxFrame> {
        let mut r = Reader::new(payload);
        let psdu = r.data().ok()?.to_vec();
        let rssi = r.i8().ok()?;
        let _noise = r.i8().ok()?;
        let flags = r.u16().ok()?;
        // PHY metadata struct: channel, lqi, timestamp_us.
        let channel = r
            .structure()
            .ok()
            .and_then(|mut s| s.u8().ok())
            .unwrap_or(11);
        let info = PsduRxInfo {
            len: psdu.len(),
            channel,
            rssi: Some(rssi),
            lqi: None,
            timestamp_us: None,
            ack_security: None,
            acked_with_frame_pending: Some(flags & md_flag::ACKED_FP != 0),
        };
        Some(RxFrame { psdu, info })
    }

    async fn wait_rx_frame(&mut self) -> Result<RxFrame, Error> {
        loop {
            if let Some(frame) = self.rx_queue.pop_front() {
                return Ok(frame);
            }
            let raw = self.read_one_raw().await?;
            let f = Frame::parse(&raw).map_err(|_| Error::Protocol)?;
            if f.header.tid == 0 && f.command == cmd::PROP_VALUE_IS {
                if let Ok((key, value)) = decode_prop(f.payload) {
                    if key == prop::STREAM_RAW {
                        if let Some(rx) = Self::parse_rx_frame(value) {
                            return Ok(rx);
                        }
                    }
                }
            }
        }
    }

    async fn wait_energy_scan(&mut self) -> Result<i8, Error> {
        let mut best = RSSI_INVALID;
        loop {
            let raw = self.read_one_raw().await?;
            let f = Frame::parse(&raw).map_err(|_| Error::Protocol)?;
            if f.header.tid != 0 || f.command != cmd::PROP_VALUE_IS {
                continue;
            }
            let Ok((key, value)) = decode_prop(f.payload) else {
                continue;
            };
            if key == prop::MAC_ENERGY_SCAN_RESULT {
                let mut r = Reader::new(value);
                let _ch = r.u8().unwrap_or(0);
                if let Ok(rssi) = r.i8() {
                    if rssi != RSSI_INVALID && (best == RSSI_INVALID || rssi > best) {
                        best = rssi;
                    }
                }
            } else if key == prop::MAC_SCAN_STATE {
                if Reader::new(value).u8().unwrap_or(scan_state::IDLE) == scan_state::IDLE {
                    return Ok(best);
                }
            }
        }
    }

    async fn read_i8_prop(&mut self, spinel_prop: u32) -> Option<i8> {
        self.get_prop(spinel_prop)
            .await
            .ok()
            .and_then(|r| r.property().ok().and_then(|(_, v)| Reader::new(v).i8().ok()))
    }
}

// ── Radio impl ────────────────────────────────────────────────────────────────

#[allow(async_fn_in_trait)]
impl<T: Transport> Radio for RadioSpinel<T> {
    type Error = Error;

    async fn init(&mut self) -> Result<RadioCaps, Self::Error> {
        let raw_caps: u32 = self
            .get_prop(prop::RADIO_CAPS)
            .await
            .ok()
            .and_then(|r| {
                r.property()
                    .ok()
                    .and_then(|(_, v)| Reader::new(v).packed().ok())
            })
            .unwrap_or(0);
        let phy = Capabilities::from_bits_truncate(raw_caps as u16);

        let sensitivity = self
            .read_i8_prop(prop::PHY_RX_SENSITIVITY)
            .await
            .unwrap_or(RadioCaps::DEFAULT_RECEIVE_SENSITIVITY);

        let tx_power = self
            .read_i8_prop(prop::PHY_TX_POWER)
            .await
            .unwrap_or(RadioCaps::DEFAULT_TX_POWER);

        let cca = self
            .read_i8_prop(prop::PHY_CCA_THRESHOLD)
            .await
            .unwrap_or(RadioCaps::DEFAULT_CCA_THRESHOLD);
        self.cca_threshold = cca;

        let mac = MacCapabilities::all();

        Ok(RadioCaps {
            phy,
            mac,
            receive_sensitivity: sensitivity,
            default_tx_power: tx_power,
            default_cca_threshold: cca,
            bus_speed: 1_000_000,
            bus_latency_us: 100,
            ..RadioCaps::default()
        })
    }

    async fn set_config(&mut self, config: &Config) -> Result<(), Self::Error> {
        self.set_prop(prop::PHY_ENABLED, |w| w.bool(true)).await?;
        if let Some(pan_id) = config.pan_id {
            self.set_prop(prop::MAC_15_4_PANID, |w| w.u16(pan_id))
                .await?;
        }
        if let Some(short_addr) = config.short_addr {
            self.set_prop(prop::MAC_15_4_SADDR, |w| w.u16(short_addr))
                .await?;
        }
        if let Some(alt) = config.alt_short_addr {
            self.set_prop(prop::MAC_15_4_ALT_SADDR, |w| w.u16(alt))
                .await?;
        }
        if let Some(ext) = config.ext_addr {
            self.set_prop(prop::MAC_15_4_LADDR, |w| w.array(&ext.to_be_bytes()))
                .await?;
        }
        self.set_prop(prop::MAC_PROMISCUOUS_MODE, |w| {
            w.u8(config.promiscuous as u8)
        })
        .await?;
        self.set_prop(prop::MAC_RX_ON_WHEN_IDLE_MODE, |w| {
            w.bool(!config.auto_sleep)
        })
        .await
    }

    async fn set_src_match_config(&mut self, cfg: &SrcMatchConfig) -> Result<(), Self::Error> {
        self.set_prop(prop::MAC_SRC_MATCH_ENABLED, |w| w.bool(cfg.enabled))
            .await?;
        self.set_prop(prop::MAC_SRC_MATCH_SHORT_ADDRESSES, |w| {
            cfg.short_addrs.iter().try_for_each(|&a| w.u16(a))
        })
        .await?;
        self.set_prop(prop::MAC_SRC_MATCH_EXTENDED_ADDRESSES, |w| {
            cfg.ext_addrs
                .iter()
                .try_for_each(|&a| w.array(&a.to_be_bytes()))
        })
        .await
    }

    async fn set_receive(&mut self, channel: u8) -> Result<(), Self::Error> {
        self.set_prop(prop::PHY_CHAN, |w| w.u8(channel)).await?;
        self.set_prop(prop::PHY_ENABLED, |w| w.bool(true)).await?;
        self.set_prop(prop::MAC_RAW_STREAM_ENABLED, |w| w.bool(true))
            .await?;
        self.channel = channel;
        self.rx_on = true;
        Ok(())
    }

    async fn set_sleep(&mut self) -> Result<(), Self::Error> {
        self.set_prop(prop::MAC_RAW_STREAM_ENABLED, |w| w.bool(false))
            .await?;
        self.set_prop(prop::PHY_ENABLED, |w| w.bool(false)).await?;
        self.rx_on = false;
        Ok(())
    }

    async fn set_mac_keys(&mut self, keys: Option<&MacKeys>) -> Result<(), Self::Error> {
        let Some(k) = keys else {
            return Ok(());
        };
        self.set_prop(prop::RCP_MAC_KEY, |w| {
            w.u8(k.key_id_mode)?;
            w.u8(k.key_id)?;
            w.data(&k.prev)?;
            w.data(&k.curr)?;
            w.data(&k.next)
        })
        .await
    }

    async fn set_mac_frame_counter(
        &mut self,
        frame_counter: u32,
        if_larger: bool,
    ) -> Result<(), Self::Error> {
        self.set_prop(prop::RCP_MAC_FRAME_COUNTER, |w| {
            w.u32(frame_counter)?;
            w.bool(if_larger)
        })
        .await
    }

    async fn energy_scan(&mut self, channel: u8, duration_ms: u16) -> Result<i8, Self::Error> {
        self.set_prop(prop::MAC_SCAN_MASK, |w| w.u8(channel))
            .await?;
        self.set_prop(prop::MAC_SCAN_PERIOD, |w| w.u16(duration_ms))
            .await?;
        let tid = self.next_tid();
        self.send_cmd(tid, cmd::PROP_VALUE_SET, prop::MAC_SCAN_STATE, |w| {
            w.u8(scan_state::ENERGY)
        })
        .await?;
        let _ = self.transact(tid).await?;
        self.wait_energy_scan().await
    }

    async fn transmit(
        &mut self,
        psdu: &mut [u8],
        psdu_tx: &mut PsduTxInfo,
        channel: u8,
        power: i8,
        cca_threshold: Option<i8>,
        ack_psdu_buf: Option<&mut [u8]>,
    ) -> Result<Option<PsduRxInfo>, Self::Error> {
        let csma = cca_threshold.is_some();
        let max_csma_backoffs = psdu_tx.max_csma_backoffs.unwrap_or(4);
        let tx_delay: u32 = psdu_tx
            .tx_at_us
            .map(|t| (t & 0xffff_ffff) as u32)
            .unwrap_or(0);
        let psdu_snap = psdu.to_vec();

        let tid = self.next_tid();
        self.send_cmd(tid, cmd::PROP_VALUE_SET, prop::STREAM_RAW, |w| {
            w.data(&psdu_snap)?;
            w.u8(channel)?;
            w.u8(max_csma_backoffs)?;
            w.u8(15u8)?; // max_retries
            w.bool(csma)?;
            w.bool(psdu_tx.header_updated)?;
            w.bool(psdu_tx.retransmission)?;
            w.bool(psdu_tx.security_processed)?;
            w.u32(tx_delay)?;
            w.u32(0u32)?; // tx_delay_base_time
            w.u8(channel)?; // rx_channel_after_tx
            w.i8(power)
        })
        .await?;

        let resp = self.transact(tid).await?;
        if resp.command != cmd::PROP_VALUE_IS {
            return Err(Error::Protocol);
        }
        let (key, val) = resp.property()?;
        if key != prop::LAST_STATUS {
            return Err(Error::Protocol);
        }
        let mut r = Reader::new(val);
        let code = r.packed().map_err(|_| Error::Protocol)?;
        if code != status::OK {
            return Err(Error::Rcp(code));
        }
        let _frame_pending = r.bool().unwrap_or(false);
        psdu_tx.header_updated = r.bool().unwrap_or(psdu_tx.header_updated);

        // Decode the optional ACK frame (pack_radio_frame encoding).
        let ack_info = r.data().ok().and_then(|ack_psdu| {
            if ack_psdu.is_empty() {
                return None;
            }
            let rssi = r.i8().unwrap_or(RSSI_INVALID);
            let _noise = r.i8().unwrap_or(-128);
            let flags = r.u16().unwrap_or(0);
            let ch = r
                .structure()
                .ok()
                .and_then(|mut s| s.u8().ok())
                .unwrap_or(channel);
            let ack_sec = if flags & md_flag::ACKED_SEC != 0 {
                let _ = r.structure(); // skip error struct
                r.structure().ok().and_then(|mut s| {
                    Some(AckSecurity {
                        key_id: s.u8().ok()?,
                        frame_counter: s.u32().ok()?,
                    })
                })
            } else {
                None
            };
            if let Some(buf) = ack_psdu_buf {
                let n = ack_psdu.len().min(buf.len());
                buf[..n].copy_from_slice(&ack_psdu[..n]);
                Some(PsduRxInfo {
                    len: ack_psdu.len(),
                    channel: ch,
                    rssi: Some(rssi),
                    lqi: None,
                    timestamp_us: None,
                    ack_security: ack_sec,
                    acked_with_frame_pending: Some(flags & md_flag::ACKED_FP != 0),
                })
            } else {
                None
            }
        });

        Ok(ack_info)
    }

    async fn receive(&mut self, psdu_buf: &mut [u8]) -> Result<PsduRxInfo, Self::Error> {
        let frame = if let Some(f) = self.rx_queue.pop_front() {
            f
        } else {
            self.wait_rx_frame().await?
        };
        let n = frame.psdu.len().min(psdu_buf.len());
        psdu_buf[..n].copy_from_slice(&frame.psdu[..n]);
        let mut info = frame.info;
        info.len = n;
        Ok(info)
    }
}
