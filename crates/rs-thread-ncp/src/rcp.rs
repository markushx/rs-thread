//! Spinel radio co-processor (RCP): any [`Radio`] behind the Spinel
//! property set OpenThread's `RadioSpinel` (posix host, `ot-br-posix`) uses.
//!
//! The host-side semantics are those of OpenThread's `NcpBase` in RCP mode
//! (`src/ncp/ncp_base_radio.cpp`, `ncp_base_mtd.cpp`): the host drives the
//! radio through `PHY_*` / `MAC_*` properties and `STREAM_RAW`, and the RCP
//! reports received frames as unsolicited `STREAM_RAW` frames. The mapping to
//! the [`Radio`] trait is direct because the trait mirrors
//! `otPlatRadio*`: capabilities are reported unchanged, so the host
//! implements in software whatever the radio does not.
//!
//! [`Rcp::run`] is the whole RCP: it reads HDLC-lite framed Spinel from a
//! [`Transport`] (UART, USB CDC, a pipe) and serves it forever.

use embassy_futures::select::{Either, select};
use heapless::Vec;
use rs_thread_core::crypto::CryptoBackend;
use rs_thread_core::types::ExtAddress;
use rs_thread_mac::frame::{Frame as MacFrame, FrameMut, KeyIdentifier};
use rs_thread_mac::security::seal_psdu;
use rs_thread_platform::radio::{
    Capabilities, Config, MacKeys, PsduRxInfo, PsduTxInfo, Radio, RadioCaps, RadioError,
    RadioErrorKind, SRC_MATCH_CAPACITY, SrcMatchConfig,
};
use rs_thread_spinel::codec::{Reader, Writer};
use rs_thread_spinel::consts::{self, cap, cmd, md_flag, prop, reset, scan_state, status};
use rs_thread_spinel::frame::{self, Frame, Header};
use rs_thread_spinel::hdlc;

/// Largest Spinel frame served (the largest is a `STREAM_RAW` frame with a
/// 127 byte PSDU and metadata).
pub const MAX_FRAME: usize = 320;
/// Size of the HDLC output buffer.
const HDLC_BUF: usize = hdlc::max_encoded_len(MAX_FRAME);

/// First and last IEEE 802.15.4 channel of the 2.4 GHz O-QPSK PHY.
const CHANNEL_MIN: u8 = 11;
const CHANNEL_MAX: u8 = 26;
/// `OT_RADIO_POWER_INVALID`: no per-frame transmit power.
const POWER_INVALID: i8 = 127;
/// `OT_RADIO_LQI_NONE`
const LQI_NONE: u8 = 255;
/// Largest PSDU including the FCS.
const MAX_PSDU: usize = 127;

/// A byte stream carrying the HDLC-lite framed Spinel link.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Transport error.
    type Error: core::fmt::Debug;

    /// Waits for at least one byte; returns how many were read. Must not
    /// lose data when the future is dropped before it completes.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Writes all of `data`.
    async fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error>;
}

/// The output side: Spinel frame buffer, HDLC buffer and the transport.
struct Out<'a, T> {
    io: &'a mut T,
    buf: [u8; MAX_FRAME],
    hdlc: [u8; HDLC_BUF],
}

impl<T: Transport> Out<'_, T> {
    /// Frames and sends the first `n` bytes of the Spinel buffer.
    async fn send(&mut self, n: usize) -> Result<(), T::Error> {
        let len = hdlc::encode(&self.buf[..n], &mut self.hdlc).unwrap_or(0);
        self.io.write_all(&self.hdlc[..len]).await
    }
}

/// Static description of the RCP for `NCP_VERSION` and `HWADDR`.
#[derive(Debug, Clone, Copy)]
pub struct RcpInfo {
    /// `NCP_VERSION` string, e.g. `"OPENTRUST/0.1; RCP; nrf52840"`.
    pub version: &'static str,
    /// IEEE EUI-64 of the radio (`HWADDR`), canonical byte order.
    pub eui64: [u8; 8],
    /// Monotonic microsecond clock for `RCP_TIMESTAMP` when the radio has none.
    pub now_us: fn() -> u64,
}

/// What the radio was configured to by the host.
#[derive(Debug)]
struct State {
    phy_enabled: bool,
    rx_on: bool,
    rx_on_when_idle: bool,
    channel: u8,
    tx_power: i8,
    cca_threshold: i8,
    fem_lna_gain: i8,
    config: Config,
    src_match_enabled: bool,
    short_list: Vec<u16, SRC_MATCH_CAPACITY>,
    ext_list: Vec<u64, SRC_MATCH_CAPACITY>,
    scan_mask: u32,
    scan_period_ms: u16,
    mac_keys: Option<MacKeys>,
    mac_frame_counter: u32,
}

impl State {
    fn new(caps: &RadioCaps) -> Self {
        Self {
            phy_enabled: false,
            rx_on: false,
            rx_on_when_idle: true,
            channel: CHANNEL_MIN,
            tx_power: caps.default_tx_power,
            cca_threshold: caps.default_cca_threshold,
            fem_lna_gain: 0,
            config: Config::new(),
            src_match_enabled: false,
            short_list: Vec::new(),
            ext_list: Vec::new(),
            scan_mask: 0,
            scan_period_ms: 0,
            mac_keys: None,
            mac_frame_counter: 0,
        }
    }
}

/// The RCP: a [`Radio`] served over Spinel.
pub struct Rcp<R: Radio, C: CryptoBackend> {
    radio: R,
    crypto: C,
    caps: RadioCaps,
    info: RcpInfo,
    st: State,
    rx_buf: [u8; MAX_PSDU + 2],
    tx_buf: [u8; MAX_PSDU + 2],
    ack_buf: [u8; MAX_PSDU + 2],
}

impl<R: Radio, C: CryptoBackend> core::fmt::Debug for Rcp<R, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rcp")
            .field("caps", &self.caps)
            .field("state", &self.st)
            .finish_non_exhaustive()
    }
}

/// Spinel status of a radio error.
pub fn status_of(kind: RadioErrorKind) -> u32 {
    match kind {
        RadioErrorKind::TxAckTimeout
        | RadioErrorKind::RxAckTimeout
        | RadioErrorKind::RxAckInvalid
        | RadioErrorKind::TxAckFailed
        | RadioErrorKind::RxAckFailed => status::NO_ACK,
        RadioErrorKind::TxFailed => status::CCA_FAILURE,
        RadioErrorKind::TxInvalid | RadioErrorKind::RxInvalid => status::INVALID_ARGUMENT,
        _ => status::FAILURE,
    }
}

fn enc(_: rs_thread_spinel::Error) -> u32 {
    status::NOMEM
}

fn parse(_: rs_thread_spinel::Error) -> u32 {
    status::PARSE_ERROR
}

impl<R: Radio, C: CryptoBackend> Rcp<R, C> {
    /// Initialises the radio and builds the RCP around it. `crypto` secures
    /// outgoing frames for a radio without `TRANSMIT_SEC`.
    pub async fn new(mut radio: R, crypto: C, info: RcpInfo) -> Result<Self, R::Error> {
        let caps = radio.init().await?;
        let st = State::new(&caps);
        Ok(Self {
            radio,
            crypto,
            caps,
            info,
            st,
            rx_buf: [0; MAX_PSDU + 2],
            tx_buf: [0; MAX_PSDU + 2],
            ack_buf: [0; MAX_PSDU + 2],
        })
    }

    /// The radio behind the RCP.
    pub fn radio(&mut self) -> &mut R {
        &mut self.radio
    }

    /// The capabilities of the radio as reported to the host.
    pub fn caps(&self) -> &RadioCaps {
        &self.caps
    }

    fn now_us(&self) -> u64 {
        match self.caps.clock {
            Some(c) => c.now_us(),
            None => (self.info.now_us)(),
        }
    }

    /// Serves the host until the transport fails.
    pub async fn run<T: Transport>(&mut self, io: &mut T) -> Result<(), T::Error> {
        let mut out = Out {
            io,
            buf: [0; MAX_FRAME],
            hdlc: [0; HDLC_BUF],
        };
        let mut dec = hdlc::Decoder::<MAX_FRAME>::new();
        let mut inbuf = [0u8; 64];
        self.send_reset_status(&mut out, status::RESET_POWER_ON)
            .await?;
        loop {
            // The radio buffer and the transport are separate futures: the
            // radio's receive is cancellation safe, so a host frame arriving
            // first drops it without losing a frame.
            let ev = {
                let Self { radio, rx_buf, .. } = &mut *self;
                select(out.io.read(&mut inbuf), radio.receive(rx_buf)).await
            };
            match ev {
                Either::First(n) => {
                    for &b in &inbuf[..n?] {
                        if let Some(Ok(f)) = dec.feed(b) {
                            self.handle_frame(&mut out, f).await?;
                        }
                    }
                }
                Either::Second(Ok(info)) => {
                    let n = info.len;
                    self.send_rx_frame(&mut out, n, &info).await?;
                }
                Either::Second(Err(_)) => {}
            }
        }
    }

    async fn send_reset_status<T: Transport>(
        &mut self,
        out: &mut Out<'_, T>,
        code: u32,
    ) -> Result<(), T::Error> {
        let mut w = Writer::new(&mut out.buf);
        let _ = frame::write_last_status(&mut w, Header::UNSOLICITED, code);
        let n = w.len();
        out.send(n).await
    }

    async fn last_status<T: Transport>(
        &mut self,
        out: &mut Out<'_, T>,
        header: Header,
        code: u32,
    ) -> Result<(), T::Error> {
        let mut w = Writer::new(&mut out.buf);
        let _ = frame::write_last_status(&mut w, header, code);
        let n = w.len();
        out.send(n).await
    }

    /// Unsolicited `STREAM_RAW` frame for a received PSDU of `len` bytes
    /// (in `rx_buf`).
    async fn send_rx_frame<T: Transport>(
        &mut self,
        out: &mut Out<'_, T>,
        len: usize,
        info: &PsduRxInfo,
    ) -> Result<(), T::Error> {
        let psdu = &self.rx_buf[..len.min(self.rx_buf.len())];
        let now = self.now_us();
        let mut w = Writer::new(&mut out.buf);
        let r = (|| {
            frame::begin_property(
                &mut w,
                Header::UNSOLICITED,
                cmd::PROP_VALUE_IS,
                prop::STREAM_RAW,
            )?;
            pack_radio_frame(&mut w, Some((psdu, info)), now, status::OK)
        })();
        if r.is_err() {
            return Ok(());
        }
        let n = w.len();
        out.send(n).await
    }

    async fn handle_frame<T: Transport>(
        &mut self,
        out: &mut Out<'_, T>,
        data: &[u8],
    ) -> Result<(), T::Error> {
        let Ok(f) = Frame::parse(data) else {
            return Ok(());
        };
        let header = f.header;
        match f.command {
            cmd::NOOP => self.last_status(out, header, status::OK).await,
            cmd::RESET => {
                self.reset().await;
                self.send_reset_status(out, status::RESET_SOFTWARE).await
            }
            cmd::PROP_VALUE_GET
            | cmd::PROP_VALUE_SET
            | cmd::PROP_VALUE_INSERT
            | cmd::PROP_VALUE_REMOVE => {
                let Ok((key, value)) = f.property() else {
                    return self.last_status(out, header, status::PARSE_ERROR).await;
                };
                self.handle_property(out, header, f.command, key, value)
                    .await
            }
            _ => self.last_status(out, header, status::INVALID_COMMAND).await,
        }
    }

    async fn reset(&mut self) {
        let _ = self.radio.set_sleep().await;
        let _ = self.radio.set_mac_keys(None).await;
        self.st = State::new(&self.caps);
        let _ = self.radio.set_config(&self.st.config).await;
        let _ = self
            .radio
            .set_src_match_config(&SrcMatchConfig::new())
            .await;
    }

    async fn handle_property<T: Transport>(
        &mut self,
        out: &mut Out<'_, T>,
        header: Header,
        command: u32,
        key: u32,
        value: &[u8],
    ) -> Result<(), T::Error> {
        match command {
            cmd::PROP_VALUE_GET => {
                let r = self.get_async(out, header, key).await?;
                if let Err(code) = r {
                    self.last_status(out, header, code).await?;
                }
                Ok(())
            }
            cmd::PROP_VALUE_SET => {
                if key == prop::STREAM_RAW {
                    return self.stream_raw_tx(out, header, value).await;
                }
                let mut r = Reader::new(value);
                match self.set(key, &mut r).await {
                    Err(code) => self.last_status(out, header, code).await,
                    Ok(()) => {
                        if key == prop::MAC_SCAN_STATE {
                            self.send_property(out, header, cmd::PROP_VALUE_IS, key)
                                .await?;
                            return self.energy_scan(out).await;
                        }
                        // The echo of the new value; properties without a
                        // getter are acknowledged with `LAST_STATUS`.
                        if self
                            .send_property(out, header, cmd::PROP_VALUE_IS, key)
                            .await?
                            .is_none()
                        {
                            self.last_status(out, header, status::OK).await?;
                        }
                        Ok(())
                    }
                }
            }
            _ => {
                let mut r = Reader::new(value);
                match self
                    .list_change(command == cmd::PROP_VALUE_INSERT, key, &mut r)
                    .await
                {
                    Err(code) => self.last_status(out, header, code).await,
                    Ok(()) => {
                        let reply = if command == cmd::PROP_VALUE_INSERT {
                            cmd::PROP_VALUE_INSERTED
                        } else {
                            cmd::PROP_VALUE_REMOVED
                        };
                        let mut w = Writer::new(&mut out.buf);
                        let ok = frame::begin_property(&mut w, header, reply, key)
                            .and_then(|()| w.bytes(value))
                            .is_ok();
                        let n = w.len();
                        if ok {
                            out.send(n).await
                        } else {
                            self.last_status(out, header, status::NOMEM).await
                        }
                    }
                }
            }
        }
    }

    /// Sends `cmd key value` with the current value of `key`; `Ok(None)` if
    /// there is no getter (nothing is sent).
    async fn send_property<T: Transport>(
        &mut self,
        out: &mut Out<'_, T>,
        header: Header,
        command: u32,
        key: u32,
    ) -> Result<Option<()>, T::Error> {
        let mut w = Writer::new(&mut out.buf);
        if frame::begin_property(&mut w, header, command, key).is_err() {
            return Ok(Some(()));
        }
        match self.get(key, &mut w) {
            Ok(()) => {
                let n = w.len();
                out.send(n).await?;
                Ok(Some(()))
            }
            Err(status::PROP_NOT_FOUND) => Ok(None),
            Err(code) => {
                self.last_status(out, header, code).await?;
                Ok(Some(()))
            }
        }
    }

    /// `GET`: asynchronous properties first, the rest through [`Self::get`].
    async fn get_async<T: Transport>(
        &mut self,
        out: &mut Out<'_, T>,
        header: Header,
        key: u32,
    ) -> Result<Result<(), u32>, T::Error> {
        if key == prop::PHY_RSSI {
            // No instantaneous RSSI in the radio trait: a 1 ms energy scan
            // of the receive channel.
            let rssi = match self.radio.energy_scan(self.st.channel, 1).await {
                Ok(v) => v,
                Err(_) => rs_thread_platform::radio::RSSI_INVALID,
            };
            if self.st.rx_on {
                let _ = self.radio.set_receive(self.st.channel).await;
            }
            let mut w = Writer::new(&mut out.buf);
            let ok = frame::begin_property(&mut w, header, cmd::PROP_VALUE_IS, key)
                .and_then(|()| w.i8(rssi))
                .is_ok();
            let n = w.len();
            if ok {
                out.send(n).await?;
                return Ok(Ok(()));
            }
            return Ok(Err(status::NOMEM));
        }
        Ok(
            match self
                .send_property(out, header, cmd::PROP_VALUE_IS, key)
                .await?
            {
                Some(()) => Ok(()),
                None => Err(status::PROP_NOT_FOUND),
            },
        )
    }

    /// Writes the value of `key` (`Err(PROP_NOT_FOUND)` if there is none).
    fn get(&self, key: u32, w: &mut Writer<'_>) -> Result<(), u32> {
        let s = &self.st;
        let c = &self.caps;
        match key {
            prop::PROTOCOL_VERSION => w
                .packed(consts::PROTOCOL_VERSION_MAJOR)
                .and_then(|()| w.packed(consts::PROTOCOL_VERSION_MINOR)),
            prop::NCP_VERSION => w.utf8(self.info.version),
            prop::INTERFACE_TYPE => w.packed(consts::INTERFACE_TYPE_THREAD),
            prop::VENDOR_ID => w.packed(0),
            prop::INTERFACE_COUNT => w.u8(1),
            prop::CAPS => self.write_caps(w),
            prop::HWADDR => w.array(&self.info.eui64),
            prop::PHY_ENABLED => w.bool(s.phy_enabled),
            prop::PHY_CHAN => w.u8(s.channel),
            prop::PHY_CHAN_SUPPORTED | prop::PHY_CHAN_PREFERRED => {
                (CHANNEL_MIN..=CHANNEL_MAX).try_for_each(|ch| w.u8(ch))
            }
            prop::PHY_FREQ => {
                w.u32(2_405_000 + 5_000 * u32::from(s.channel.saturating_sub(CHANNEL_MIN)))
            }
            prop::PHY_CCA_THRESHOLD => w.i8(s.cca_threshold),
            prop::PHY_TX_POWER => w.i8(s.tx_power),
            prop::PHY_RX_SENSITIVITY => w.i8(c.receive_sensitivity),
            prop::PHY_FEM_LNA_GAIN => w.i8(s.fem_lna_gain),
            prop::RADIO_CAPS => w.packed(u32::from(
                (c.phy | Capabilities::TRANSMIT_RETRIES | Capabilities::TRANSMIT_SEC).bits(),
            )),
            prop::MAC_15_4_LADDR => w.array(&s.config.ext_addr.unwrap_or(0).to_be_bytes()),
            prop::MAC_15_4_SADDR => w.u16(s.config.short_addr.unwrap_or(0xfffe)),
            prop::MAC_15_4_ALT_SADDR => w.u16(s.config.alt_short_addr.unwrap_or(0xfffe)),
            prop::MAC_15_4_PANID => w.u16(s.config.pan_id.unwrap_or(0xffff)),
            prop::MAC_RAW_STREAM_ENABLED => w.bool(s.rx_on),
            prop::MAC_PROMISCUOUS_MODE => w.u8(s.config.promiscuous as u8),
            prop::MAC_RX_ON_WHEN_IDLE_MODE => w.bool(s.rx_on_when_idle),
            prop::MAC_SRC_MATCH_ENABLED => w.bool(s.src_match_enabled),
            prop::MAC_SRC_MATCH_SHORT_ADDRESSES => s.short_list.iter().try_for_each(|&a| w.u16(a)),
            prop::MAC_SRC_MATCH_EXTENDED_ADDRESSES => s
                .ext_list
                .iter()
                .try_for_each(|a| w.array(&a.to_be_bytes())),
            prop::MAC_SCAN_STATE => w.u8(scan_state::IDLE),
            prop::MAC_SCAN_PERIOD => w.u16(s.scan_period_ms),
            prop::RCP_API_VERSION => w.packed(consts::RCP_API_VERSION),
            prop::RCP_MIN_HOST_API_VERSION => w.packed(consts::MIN_HOST_SUPPORTED_RCP_API_VERSION),
            prop::RCP_TIMESTAMP => w.u64(self.now_us()),
            prop::RCP_CSL_ACCURACY => w.u8(c.csl_accuracy_ppm),
            prop::RCP_CSL_UNCERTAINTY => w.u8(c.csl_uncertainty),
            prop::RCP_VERSION => w.utf8(self.info.version),
            _ => return Err(status::PROP_NOT_FOUND),
        }
        .map_err(enc)
    }

    fn write_caps(&self, w: &mut Writer<'_>) -> rs_thread_spinel::Result<()> {
        for c in [
            cap::CONFIG_RADIO,
            cap::MAC_RAW,
            cap::WRITABLE_RAW_STREAM,
            cap::IEEE_802_15_4_2003,
            cap::IEEE_802_15_4_2006,
            cap::IEEE_802_15_4_2011,
            cap::IEEE_802_15_4_2450MHZ_OQPSK,
            cap::RCP_API_VERSION,
            cap::RCP_MIN_HOST_API_VERSION,
        ] {
            w.packed(c)?;
        }
        Ok(())
    }

    async fn apply_config(&mut self) -> Result<(), u32> {
        let c = Config {
            auto_sleep: !self.st.rx_on_when_idle,
            ..self.st.config.clone()
        };
        self.radio
            .set_config(&c)
            .await
            .map_err(|e| status_of(e.kind()))
    }

    async fn apply_src_match(&mut self) -> Result<(), u32> {
        let cfg = SrcMatchConfig {
            enabled: self.st.src_match_enabled,
            short_addrs: self.st.short_list.clone(),
            ext_addrs: self.st.ext_list.clone(),
        };
        self.radio
            .set_src_match_config(&cfg)
            .await
            .map_err(|e| status_of(e.kind()))
    }

    async fn apply_rx(&mut self) -> Result<(), u32> {
        let r = if self.st.rx_on && self.st.phy_enabled {
            self.radio.set_receive(self.st.channel).await
        } else {
            self.radio.set_sleep().await
        };
        r.map_err(|e| status_of(e.kind()))
    }

    /// `SET` of everything except `STREAM_RAW`.
    async fn set(&mut self, key: u32, r: &mut Reader<'_>) -> Result<(), u32> {
        match key {
            prop::PHY_ENABLED => {
                self.st.phy_enabled = r.bool().map_err(parse)?;
                self.apply_rx().await
            }
            prop::MAC_RAW_STREAM_ENABLED => {
                let on = r.bool().map_err(parse)?;
                if on && !self.st.phy_enabled {
                    return Err(status::INVALID_STATE);
                }
                self.st.rx_on = on;
                self.apply_rx().await
            }
            prop::PHY_CHAN => {
                let ch = r.u8().map_err(parse)?;
                if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&ch) {
                    return Err(status::INVALID_ARGUMENT);
                }
                self.st.channel = ch;
                if self.st.rx_on {
                    self.apply_rx().await?;
                }
                Ok(())
            }
            prop::PHY_TX_POWER => {
                self.st.tx_power = r.i8().map_err(parse)?;
                Ok(())
            }
            prop::PHY_CCA_THRESHOLD => {
                self.st.cca_threshold = r.i8().map_err(parse)?;
                Ok(())
            }
            prop::PHY_FEM_LNA_GAIN => {
                self.st.fem_lna_gain = r.i8().map_err(parse)?;
                Ok(())
            }
            prop::MAC_15_4_PANID => {
                self.st.config.pan_id = Some(r.u16().map_err(parse)?);
                self.apply_config().await
            }
            prop::MAC_15_4_SADDR => {
                self.st.config.short_addr = Some(r.u16().map_err(parse)?);
                self.apply_config().await
            }
            prop::MAC_15_4_ALT_SADDR => {
                let a = r.u16().map_err(parse)?;
                self.st.config.alt_short_addr = (a != 0xfffe && a != 0xffff).then_some(a);
                self.apply_config().await
            }
            prop::MAC_15_4_LADDR => {
                let a: [u8; 8] = r.array().map_err(parse)?;
                self.st.config.ext_addr = Some(u64::from_be_bytes(a));
                self.apply_config().await
            }
            prop::MAC_PROMISCUOUS_MODE => {
                self.st.config.promiscuous = r.u8().map_err(parse)? != 0;
                self.apply_config().await
            }
            prop::MAC_RX_ON_WHEN_IDLE_MODE => {
                self.st.rx_on_when_idle = r.bool().map_err(parse)?;
                self.apply_config().await
            }
            prop::MAC_SRC_MATCH_ENABLED => {
                self.st.src_match_enabled = r.bool().map_err(parse)?;
                self.apply_src_match().await
            }
            prop::MAC_SRC_MATCH_SHORT_ADDRESSES => {
                self.st.short_list.clear();
                while r.remaining() >= 2 {
                    let a = r.u16().map_err(parse)?;
                    self.st.short_list.push(a).map_err(|_| status::NOMEM)?;
                }
                self.apply_src_match().await
            }
            prop::MAC_SRC_MATCH_EXTENDED_ADDRESSES => {
                self.st.ext_list.clear();
                while r.remaining() >= 8 {
                    let a: [u8; 8] = r.array().map_err(parse)?;
                    self.st
                        .ext_list
                        .push(u64::from_be_bytes(a))
                        .map_err(|_| status::NOMEM)?;
                }
                self.apply_src_match().await
            }
            prop::MAC_SCAN_MASK => {
                self.st.scan_mask = 0;
                while let Ok(ch) = r.u8() {
                    if (CHANNEL_MIN..=CHANNEL_MAX).contains(&ch) {
                        self.st.scan_mask |= 1 << ch;
                    }
                }
                Ok(())
            }
            prop::MAC_SCAN_PERIOD => {
                self.st.scan_period_ms = r.u16().map_err(parse)?;
                Ok(())
            }
            prop::MAC_SCAN_STATE => match r.u8().map_err(parse)? {
                scan_state::ENERGY if self.st.scan_mask != 0 => Ok(()),
                scan_state::ENERGY => Err(status::INVALID_ARGUMENT),
                scan_state::IDLE => Ok(()),
                _ => Err(status::INVALID_ARGUMENT),
            },
            prop::MAC_RX_AT => {
                let when = r.u64().map_err(parse)?;
                let duration = r.u32().map_err(parse)?;
                let channel = r.u8().map_err(parse)?;
                if !self.caps.phy.contains(Capabilities::RECEIVE_TIMING) {
                    return Err(status::NOT_CAPABLE);
                }
                self.radio
                    .set_receive_at(channel, when, duration)
                    .await
                    .map_err(|e| status_of(e.kind()))
            }
            prop::RCP_MAC_KEY => {
                // The wire value is OpenThread's `Mac::Frame::kKeyIdMode1`
                // (security control bits 3-4), the radio trait's mode is 1.
                let key_id_mode = r.u8().map_err(parse)?;
                if key_id_mode != 0x08 {
                    return Err(status::INVALID_ARGUMENT);
                }
                let key_id = r.u8().map_err(parse)?;
                let mut key = || -> Result<[u8; 16], u32> {
                    r.data()
                        .map_err(parse)?
                        .try_into()
                        .map_err(|_| status::INVALID_ARGUMENT)
                };
                let (prev, curr, next) = (key()?, key()?, key()?);
                let keys = MacKeys {
                    key_id_mode: 1,
                    key_id,
                    prev,
                    curr,
                    next,
                };
                self.st.mac_keys = Some(keys);
                self.radio
                    .set_mac_keys(Some(&keys))
                    .await
                    .map_err(|e| status_of(e.kind()))
            }
            prop::RCP_MAC_FRAME_COUNTER => {
                let counter = r.u32().map_err(parse)?;
                let if_larger = if r.is_empty() {
                    false
                } else {
                    r.bool().map_err(parse)?
                };
                if !if_larger || counter > self.st.mac_frame_counter {
                    self.st.mac_frame_counter = counter;
                }
                self.radio
                    .set_mac_frame_counter(counter, if_larger)
                    .await
                    .map_err(|e| status_of(e.kind()))
            }
            prop::RCP_LOG_CRASH_DUMP => Ok(()),
            _ => Err(status::PROP_NOT_FOUND),
        }
    }

    /// `INSERT` / `REMOVE` of source match entries.
    async fn list_change(&mut self, insert: bool, key: u32, r: &mut Reader<'_>) -> Result<(), u32> {
        match key {
            prop::MAC_SRC_MATCH_SHORT_ADDRESSES => {
                let a = r.u16().map_err(parse)?;
                let l = &mut self.st.short_list;
                if insert {
                    if !l.contains(&a) {
                        l.push(a).map_err(|_| status::NOMEM)?;
                    }
                } else {
                    let i = l
                        .iter()
                        .position(|&x| x == a)
                        .ok_or(status::ITEM_NOT_FOUND)?;
                    l.swap_remove(i);
                }
            }
            prop::MAC_SRC_MATCH_EXTENDED_ADDRESSES => {
                let a = u64::from_be_bytes(r.array().map_err(parse)?);
                let l = &mut self.st.ext_list;
                if insert {
                    if !l.contains(&a) {
                        l.push(a).map_err(|_| status::NOMEM)?;
                    }
                } else {
                    let i = l
                        .iter()
                        .position(|&x| x == a)
                        .ok_or(status::ITEM_NOT_FOUND)?;
                    l.swap_remove(i);
                }
            }
            _ => return Err(status::INVALID_COMMAND_FOR_PROP),
        }
        self.apply_src_match().await
    }

    /// Energy scan of the channels in the scan mask (one result per channel),
    /// then back to the receive state.
    async fn energy_scan<T: Transport>(&mut self, out: &mut Out<'_, T>) -> Result<(), T::Error> {
        let period = self.st.scan_period_ms.max(1);
        for ch in CHANNEL_MIN..=CHANNEL_MAX {
            if self.st.scan_mask & (1 << ch) == 0 {
                continue;
            }
            let rssi = self
                .radio
                .energy_scan(ch, period)
                .await
                .unwrap_or(rs_thread_platform::radio::RSSI_INVALID);
            let mut w = Writer::new(&mut out.buf);
            let ok = frame::begin_property(
                &mut w,
                Header::UNSOLICITED,
                cmd::PROP_VALUE_IS,
                prop::MAC_ENERGY_SCAN_RESULT,
            )
            .and_then(|()| w.u8(ch))
            .and_then(|()| w.i8(rssi))
            .is_ok();
            let n = w.len();
            if ok {
                out.send(n).await?;
            }
        }
        let _ = self.apply_rx().await;
        let mut w = Writer::new(&mut out.buf);
        let ok = frame::begin_property(
            &mut w,
            Header::UNSOLICITED,
            cmd::PROP_VALUE_IS,
            prop::MAC_SCAN_STATE,
        )
        .and_then(|()| w.u8(scan_state::IDLE))
        .is_ok();
        let n = w.len();
        if ok {
            out.send(n).await?;
        }
        Ok(())
    }

    /// Software `TRANSMIT_SEC` for the frame in `tx_buf[..len]` (PSDU with
    /// FCS): assigns the frame counter and key index unless the header is
    /// already updated, then seals the frame with the current key.
    fn secure_tx(&mut self, len: usize, tx: &mut PsduTxInfo) -> Result<(), u32> {
        let psdu = &mut self.tx_buf[..len.saturating_sub(2)];
        let secured = MacFrame::parse(psdu)
            .map_err(|_| status::PARSE_ERROR)?
            .security_header()
            .is_some();
        if !secured {
            tx.security_processed = true;
            return Ok(());
        }
        let keys = self.st.mac_keys.ok_or(status::INVALID_STATE)?;
        if !tx.header_updated {
            let counter = self.st.mac_frame_counter;
            let mut fm = FrameMut::new(psdu).map_err(|_| status::PARSE_ERROR)?;
            fm.set_frame_counter(counter)
                .and_then(|()| fm.set_key_index(keys.key_id))
                .map_err(|_| status::INVALID_ARGUMENT)?;
            self.st.mac_frame_counter = counter.wrapping_add(1);
            tx.header_updated = true;
        }
        let source = ExtAddress(
            self.st
                .config
                .ext_addr
                .ok_or(status::INVALID_STATE)?
                .to_be_bytes(),
        );
        let cipher = self.crypto.aes128(&keys.curr);
        seal_psdu(&cipher, psdu, &source).map_err(|_| status::FAILURE)?;
        tx.security_processed = true;
        Ok(())
    }

    /// `SET STREAM_RAW`: transmit one frame; the answer is the transmit-done
    /// `LAST_STATUS` with the ACK.
    async fn stream_raw_tx<T: Transport>(
        &mut self,
        out: &mut Out<'_, T>,
        header: Header,
        value: &[u8],
    ) -> Result<(), T::Error> {
        let mut r = Reader::new(value);
        let req = match TxRequest::decode(&mut r, &mut self.tx_buf, self.st.cca_threshold) {
            Ok(q) => q,
            Err(code) => return self.last_status(out, header, code).await,
        };
        if !self.st.phy_enabled {
            return self.last_status(out, header, status::INVALID_STATE).await;
        }
        let len = req.len;
        let power = if req.power == POWER_INVALID {
            self.st.tx_power
        } else {
            req.power
        };
        let mut tx = PsduTxInfo {
            security_processed: req.security_processed,
            header_updated: req.header_updated,
            csl_present: false,
            retransmission: req.retransmission,
            tx_at_us: None,
            max_csma_backoffs: Some(req.max_csma_backoffs),
        };
        if req.tx_delay != 0 && self.caps.phy.contains(Capabilities::TRANSMIT_TIMING) {
            // `tx_delay_base_time` holds the low 32 bits of the radio time.
            let target = req.tx_delay_base_time.wrapping_add(req.tx_delay);
            let now = self.now_us();
            let mut at = (now & !0xffff_ffff) | u64::from(target);
            if at + (1 << 31) < now {
                at += 1 << 32;
            }
            tx.tx_at_us = Some(at);
        }
        // A radio without `TRANSMIT_SEC` gets finished, secured frames: the
        // frame counter and key index are assigned and the frame is sealed
        // here, as the host expects of an RCP.
        if !self.caps.phy.contains(Capabilities::TRANSMIT_SEC)
            && !tx.security_processed
            && let Err(code) = self.secure_tx(len, &mut tx)
        {
            return self.last_status(out, header, code).await;
        }
        let cca = req.csma.then_some(self.st.cca_threshold);
        // The host expects the RCP to retry unacknowledged frames
        // (`TRANSMIT_RETRIES` is always reported): a radio that does not do
        // so itself is retried here.
        let attempts = if self.caps.phy.contains(Capabilities::TRANSMIT_RETRIES) {
            1
        } else {
            1 + usize::from(req.max_retries)
        };
        let mut attempt = 1;
        let result = loop {
            let r = {
                let Self {
                    radio,
                    tx_buf,
                    ack_buf,
                    ..
                } = &mut *self;
                radio
                    .transmit(
                        &mut tx_buf[..len],
                        &mut tx,
                        req.channel,
                        power,
                        cca,
                        Some(ack_buf),
                    )
                    .await
            };
            match &r {
                Err(e)
                    if attempt < attempts
                        && matches!(status_of(e.kind()), status::NO_ACK | status::CCA_FAILURE) =>
                {
                    attempt += 1;
                    tx.retransmission = true;
                }
                _ => break r,
            }
        };
        // The radio returns to the receive channel the host asked for.
        if self.st.rx_on {
            if req.rx_channel_after_tx != self.st.channel {
                let _ = self.radio.set_receive(req.rx_channel_after_tx).await;
            }
        } else {
            let _ = self.radio.set_sleep().await;
        }
        let now = self.now_us();
        let ack = match &result {
            Ok(Some(info)) => Some((&self.ack_buf[..info.len.min(self.ack_buf.len())], info)),
            _ => None,
        };
        let frame_pending = ack.is_some_and(|(p, _)| p.first().is_some_and(|b| b & 0x10 != 0));
        let code = match &result {
            Ok(_) => status::OK,
            Err(e) => status_of(e.kind()),
        };
        // Security material the radio assigned to the frame.
        let sec = if tx.header_updated && len > 2 {
            MacFrame::parse(&self.tx_buf[..len - 2]).ok().and_then(|f| {
                let h = f.security_header()?;
                let id = match h.key {
                    KeyIdentifier::Index(i)
                    | KeyIdentifier::Source4 { index: i, .. }
                    | KeyIdentifier::Source8 { index: i, .. } => i,
                    KeyIdentifier::Implicit => 0,
                };
                Some((id, h.frame_counter?))
            })
        } else {
            None
        };
        let mut w = Writer::new(&mut out.buf);
        let ok = (|| {
            frame::begin_property(&mut w, header, cmd::PROP_VALUE_IS, prop::LAST_STATUS)?;
            w.packed(code)?;
            w.bool(frame_pending)?;
            w.bool(tx.header_updated)?;
            if code == status::OK {
                pack_radio_frame(&mut w, ack, now, status::OK)?;
            }
            if let Some((id, fc)) = sec {
                w.u8(id)?;
                w.u32(fc)?;
            }
            Ok::<(), rs_thread_spinel::Error>(())
        })()
        .is_ok();
        let n = w.len();
        if ok {
            out.send(n).await
        } else {
            self.last_status(out, header, status::NOMEM).await
        }
    }
}

/// The decoded `STREAM_RAW` transmit request.
struct TxRequest {
    len: usize,
    channel: u8,
    max_csma_backoffs: u8,
    max_retries: u8,
    csma: bool,
    header_updated: bool,
    retransmission: bool,
    security_processed: bool,
    tx_delay: u32,
    tx_delay_base_time: u32,
    rx_channel_after_tx: u8,
    power: i8,
}

impl TxRequest {
    /// `d` frame, `C` channel (required), then the optional metadata:
    /// `C` max CSMA backoffs, `C` max retries, `b` CSMA, `b` header updated,
    /// `b` retransmission, `b` security processed, `L` delay, `L` delay base
    /// time, `C` rx channel after tx, `c` power. Missing fields keep their
    /// defaults like in `NcpBase::DecodeStreamRawTxRequest`.
    fn decode(r: &mut Reader<'_>, psdu: &mut [u8], _cca: i8) -> Result<Self, u32> {
        let data = r.data().map_err(parse)?;
        if data.len() > psdu.len() || data.len() < 2 {
            return Err(status::PARSE_ERROR);
        }
        psdu[..data.len()].copy_from_slice(data);
        let channel = r.u8().map_err(parse)?;
        let mut q = Self {
            len: data.len(),
            channel,
            max_csma_backoffs: 4,
            max_retries: 15,
            csma: true,
            header_updated: false,
            retransmission: false,
            security_processed: false,
            tx_delay: 0,
            tx_delay_base_time: 0,
            rx_channel_after_tx: channel,
            power: POWER_INVALID,
        };
        // Optional fields: stop at the first one that is missing.
        let _ = (|| -> rs_thread_spinel::Result<()> {
            q.max_csma_backoffs = r.u8()?;
            q.max_retries = r.u8()?;
            q.csma = r.bool()?;
            q.header_updated = r.bool()?;
            q.retransmission = r.bool()?;
            q.security_processed = r.bool()?;
            q.tx_delay = r.u32()?;
            q.tx_delay_base_time = r.u32()?;
            q.rx_channel_after_tx = r.u8()?;
            q.power = r.i8()?;
            Ok(())
        })();
        Ok(q)
    }
}

/// `PackRadioFrame` of `NcpBase`: frame `d`, RSSI, noise floor, flags, PHY
/// struct (channel, LQI, timestamp), vendor struct (receive error), MAC
/// struct (ACK key ID and frame counter). `frame` is `None` for "no ACK".
fn pack_radio_frame(
    w: &mut Writer<'_>,
    frame: Option<(&[u8], &PsduRxInfo)>,
    now_us: u64,
    error: u32,
) -> rs_thread_spinel::Result<()> {
    let mut flags = 0u16;
    match frame {
        Some((psdu, info)) => {
            w.data(psdu)?;
            w.i8(info.rssi.unwrap_or(rs_thread_platform::radio::RSSI_INVALID))?;
            w.i8(-128)?;
            if info.acked_with_frame_pending == Some(true) {
                flags |= md_flag::ACKED_FP;
            }
            if info.ack_security.is_some() {
                flags |= md_flag::ACKED_SEC;
            }
            w.u16(flags)?;
            w.structure(|w| {
                w.u8(info.channel)?;
                w.u8(info.lqi.unwrap_or(LQI_NONE))?;
                w.u64(info.timestamp_us.unwrap_or(now_us))
            })?;
            w.structure(|w| w.packed(error))?;
            w.structure(|w| {
                let sec = info.ack_security;
                w.u8(sec.map_or(0, |s| s.key_id))?;
                w.u32(sec.map_or(0, |s| s.frame_counter))
            })
        }
        None => {
            w.u16(0)?;
            w.i8(0)?;
            w.i8(-128)?;
            w.u16(0)?;
            w.structure(|w| {
                w.u8(0)?;
                w.u8(LQI_NONE)?;
                w.u64(0)
            })?;
            w.structure(|w| w.packed(error))?;
            w.structure(|w| {
                w.u8(0)?;
                w.u32(0)
            })
        }
    }
}

/// Spinel `RESET` types, re-exported for transports that implement a real
/// reset (a firmware may reboot instead of just clearing the state).
pub use reset::{BOOTLOADER, PLATFORM, STACK};
