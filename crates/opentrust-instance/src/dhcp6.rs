//! DHCPv6 address client and server (RFC 8415 subset used by Thread: Solicit
//! with Rapid Commit, answered by a Reply) for Border Router prefixes with
//! the DHCP flag.
//!
//! OpenThread: `Dhcp6::Client`, `Dhcp6::Server`.

use core::net::{Ipv6Addr, SocketAddrV6};

use heapless::Vec;
use opentrust_core::time::{Duration, Instant};
use opentrust_core::types::ExtAddress;
use opentrust_mesh::netdata::tlv::{BrFlags, NetPrefix};
use opentrust_net::header::{MAX_DATAGRAM_LEN, PROTO_UDP};
use opentrust_net::netif::{AddressOrigin, UnicastAddress};
use opentrust_net::udp::{SocketHandle, UdpMeta, UdpSendOpts};
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::{Instance, InstanceCrypto, MAX_UDP_PAYLOAD};

/// DHCPv6 client port.
const CLIENT_PORT: u16 = 546;
/// DHCPv6 server port.
const SERVER_PORT: u16 = 547;

/// First ALOC16 of the DHCP agents (`0xfc00 | context id`).
const ALOC16_DHCP_AGENT_START: u16 = 0xfc00;

const MSG_SOLICIT: u8 = 1;
const MSG_REPLY: u8 = 7;

const OPT_CLIENT_ID: u16 = 1;
const OPT_SERVER_ID: u16 = 2;
const OPT_IA_NA: u16 = 3;
const OPT_IA_ADDRESS: u16 = 5;
const OPT_ELAPSED_TIME: u16 = 8;
const OPT_STATUS_CODE: u16 = 13;
const OPT_RAPID_COMMIT: u16 = 14;

/// DUID-LL.
const DUID_LL: u16 = 3;
/// Hardware type EUI-64.
const HW_EUI64: u16 = 27;
/// `kDefaultT1`, `kDefaultT2` and the default lifetimes: infinite.
const INFINITE: u32 = 0xffff_ffff;

/// Trickle `Imin` / `Imax` of the client's Solicit (OT `kTrickleTimerImin`,
/// `kTrickleTimerImax`).
const IMIN_MS: u32 = 1_000;
const IMAX_MS: u32 = 120_000;

/// Prefixes the client tracks / the server serves (OT
/// `OPENTHREAD_CONFIG_DHCP6_CLIENT_NUM_PREFIXES` / `..._SERVER_NUM_PREFIXES`).
const NUM_PREFIXES: usize = 4;

/// Largest message built or accepted.
const MAX_MSG: usize = 256;

// ------------------------------------------------------------------ codec

struct Writer {
    buf: [u8; MAX_MSG],
    len: usize,
}

impl Writer {
    fn new() -> Self {
        Self {
            buf: [0; MAX_MSG],
            len: 0,
        }
    }
    fn put(&mut self, b: &[u8]) {
        if let Some(d) = self.buf.get_mut(self.len..self.len + b.len()) {
            d.copy_from_slice(b);
            self.len += b.len();
        }
    }
    fn opt(&mut self, code: u16, body: &[u8]) {
        self.put(&code.to_be_bytes());
        self.put(&(body.len() as u16).to_be_bytes());
        self.put(body);
    }
    fn duid_opt(&mut self, code: u16, ext: &ExtAddress) {
        let mut b = [0u8; 12];
        b[..2].copy_from_slice(&DUID_LL.to_be_bytes());
        b[2..4].copy_from_slice(&HW_EUI64.to_be_bytes());
        b[4..].copy_from_slice(&ext.0);
        self.opt(code, &b);
    }
    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

fn ia_address(addr: &Ipv6Addr, preferred: u32, valid: u32) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[..16].copy_from_slice(&addr.octets());
    b[16..20].copy_from_slice(&preferred.to_be_bytes());
    b[20..].copy_from_slice(&valid.to_be_bytes());
    b
}

/// Options of a message body: `(code, value)`.
fn options(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    core::iter::from_fn(move || {
        if b.len() < 4 {
            return None;
        }
        let code = u16::from_be_bytes([b[0], b[1]]);
        let len = usize::from(u16::from_be_bytes([b[2], b[3]]));
        let v = b.get(4..4 + len)?;
        b = &b[4 + len..];
        Some((code, v))
    })
}

fn find_opt(body: &[u8], code: u16) -> Option<&[u8]> {
    options(body).find(|(c, _)| *c == code).map(|(_, v)| v)
}

fn duid_ext(v: &[u8]) -> Option<ExtAddress> {
    if v.len() != 12
        || u16::from_be_bytes([v[0], v[1]]) != DUID_LL
        || u16::from_be_bytes([v[2], v[3]]) != HW_EUI64
    {
        return None;
    }
    let mut e = [0u8; 8];
    e.copy_from_slice(&v[4..]);
    Some(ExtAddress(e))
}

/// Status of a message or IA (absent means success).
fn status_ok(body: &[u8]) -> bool {
    match find_opt(body, OPT_STATUS_CODE) {
        Some(v) if v.len() >= 2 => u16::from_be_bytes([v[0], v[1]]) == 0,
        Some(_) => false,
        None => true,
    }
}

/// The IA Address options inside the IA_NA option value.
fn ia_addresses(ia_na: &[u8]) -> impl Iterator<Item = (Ipv6Addr, u32, u32)> + '_ {
    options(ia_na.get(12..).unwrap_or(&[])).filter_map(|(c, v)| {
        if c != OPT_IA_ADDRESS || v.len() < 24 {
            return None;
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&v[..16]);
        Some((
            Ipv6Addr::from(a),
            u32::from_be_bytes([v[16], v[17], v[18], v[19]]),
            u32::from_be_bytes([v[20], v[21], v[22], v[23]]),
        ))
    })
}

fn prefix_matches(addr: &Ipv6Addr, prefix: &[u8; 8], len: u8) -> bool {
    NetPrefix::new(
        &{
            let mut p = [0u8; 16];
            p[..8].copy_from_slice(prefix);
            p
        }[..usize::from(len).div_ceil(8)],
        len,
    )
    .is_ok_and(|p| p.contains(addr))
}

// ------------------------------------------------------------------ state

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IaState {
    Invalid,
    Solicit,
    Soliciting,
    Replied,
}

#[derive(Debug, Clone, Copy)]
struct Ia {
    state: IaState,
    prefix: [u8; 8],
    prefix_len: u8,
    agent_rloc: u16,
    /// The assigned address once replied.
    addr: Option<Ipv6Addr>,
}

impl Ia {
    const EMPTY: Self = Self {
        state: IaState::Invalid,
        prefix: [0; 8],
        prefix_len: 0,
        agent_rloc: 0,
        addr: None,
    };
}

/// State of the DHCPv6 client and server.
pub(crate) struct Dhcp6 {
    client_sock: Option<SocketHandle>,
    server_sock: Option<SocketHandle>,
    ias: [Ia; NUM_PREFIXES],
    current: Option<usize>,
    xid: [u8; 3],
    start: Instant,
    /// Trickle state.
    interval_ms: u32,
    interval_start: Instant,
    tx_at: Instant,
    sent: bool,
    running: bool,
}

impl Dhcp6 {
    pub(crate) fn new() -> Self {
        Self {
            client_sock: None,
            server_sock: None,
            ias: [Ia::EMPTY; NUM_PREFIXES],
            current: None,
            xid: [0; 3],
            start: Instant::from_millis(0),
            interval_ms: IMIN_MS,
            interval_start: Instant::from_millis(0),
            tx_at: Instant::from_millis(0),
            sent: true,
            running: false,
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        if !self.running {
            return None;
        }
        let iv_end = self.interval_start + Duration::from_millis(u64::from(self.interval_ms));
        Some(if self.sent { iv_end } else { self.tx_at })
    }
}

impl<S: SettingsStore, C: InstanceCrypto, R: Rng + CryptoRng> Instance<S, C, R> {
    /// Network Data changed or the role did: update the client's
    /// associations and the server's prefix agents (OT
    /// `Dhcp6::Client::UpdateAddresses`, `Server::UpdateService`).
    #[inline(never)]
    pub(crate) fn dhcp6_update(&mut self, now: Instant, attached: bool) -> Vec<u16, NUM_PREFIXES> {
        // DHCP agent ALOC16s of the prefixes this node serves.
        let mut alocs: Vec<u16, NUM_PREFIXES> = Vec::new();
        // Agents of the whole network: prefixes with the DHCP flag.
        let mut want: Vec<([u8; 8], u8, u16), NUM_PREFIXES> = Vec::new();
        // Prefixes this node serves (DHCP or Configure flag, own RLOC16).
        let mut serve: Vec<([u8; 8], u8), NUM_PREFIXES> = Vec::new();
        if attached {
            let own = self.mle.rloc16().0;
            let view = self.core.netdata.view();
            for e in view.on_mesh_prefixes() {
                let mut p = [0u8; 8];
                let o = e.prefix.addr().octets();
                p.copy_from_slice(&o[..8]);
                if e.flags.has(BrFlags::DHCP)
                    && !want.iter().any(|w| w.0 == p && w.1 == e.prefix.len())
                {
                    let _ = want.push((p, e.prefix.len(), e.rloc16));
                }
                if (e.flags.has(BrFlags::DHCP) || e.flags.has(BrFlags::CONFIGURE))
                    && e.rloc16 == own
                    && e.prefix.len() <= 64
                    && !serve.iter().any(|w| w.0 == p && w.1 == e.prefix.len())
                {
                    let _ = serve.push((p, e.prefix.len()));
                    if let Some(c) = view
                        .contexts()
                        .filter(|c| c.prefix.contains(&e.prefix.addr()))
                        .max_by_key(|c| c.prefix.len())
                    {
                        let _ = alocs.push(ALOC16_DHCP_AGENT_START | u16::from(c.id));
                    }
                }
            }
        }
        // Server.
        if serve.is_empty() {
            if let Some(s) = self.dhcp6.server_sock.take() {
                let _ = self.udp.close(s);
            }
        } else if self.dhcp6.server_sock.is_none() {
            self.dhcp6.server_sock = self.dhcp6_open(SERVER_PORT);
        }
        // Client: drop addresses whose prefix lost the flag.
        for i in 0..NUM_PREFIXES {
            let ia = self.dhcp6.ias[i];
            if ia.state == IaState::Invalid {
                continue;
            }
            if !want
                .iter()
                .any(|w| w.0 == ia.prefix && w.1 == ia.prefix_len)
            {
                if let Some(a) = ia.addr {
                    let _ = self.core.ip6.netif.remove_unicast(&a);
                }
                self.dhcp6.ias[i] = Ia::EMPTY;
                if self.dhcp6.current == Some(i) {
                    self.dhcp6.current = None;
                }
            }
        }
        // New prefixes.
        for (p, len, rloc) in &want {
            if let Some(ia) =
                self.dhcp6.ias.iter_mut().find(|ia| {
                    ia.state != IaState::Invalid && ia.prefix == *p && ia.prefix_len == *len
                })
            {
                ia.agent_rloc = *rloc;
                continue;
            }
            if let Some(ia) = self
                .dhcp6
                .ias
                .iter_mut()
                .find(|ia| ia.state == IaState::Invalid)
            {
                *ia = Ia {
                    state: IaState::Solicit,
                    prefix: *p,
                    prefix_len: *len,
                    agent_rloc: *rloc,
                    addr: None,
                };
            }
        }
        if want.is_empty() {
            self.dhcp6_stop();
        } else if self.dhcp6.client_sock.is_none() {
            self.dhcp6.client_sock = self.dhcp6_open(CLIENT_PORT);
            if self.dhcp6.client_sock.is_some() {
                self.dhcp6_next_ia(now);
            }
        } else if self.dhcp6.current.is_none() {
            self.dhcp6_next_ia(now);
        }
        alocs
    }

    fn dhcp6_open(&mut self, port: u16) -> Option<SocketHandle> {
        let s = self.udp.open().ok()?;
        let any = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
        if self.udp.bind(s, any, &self.core.ip6.netif).is_err() {
            let _ = self.udp.close(s);
            return None;
        }
        Some(s)
    }

    fn dhcp6_stop(&mut self) {
        self.dhcp6.running = false;
        if let Some(s) = self.dhcp6.client_sock.take() {
            let _ = self.udp.close(s);
        }
    }

    /// Start soliciting the next association (OT
    /// `ProcessNextIdentityAssociation`).
    fn dhcp6_next_ia(&mut self, now: Instant) -> bool {
        if let Some(c) = self.dhcp6.current
            && self.dhcp6.ias[c].state == IaState::Soliciting
        {
            return false;
        }
        self.dhcp6.running = false;
        let Some(i) = self
            .dhcp6
            .ias
            .iter()
            .position(|ia| ia.state == IaState::Solicit)
        else {
            self.dhcp6.current = None;
            return false;
        };
        let r = self.prng.next_u32();
        self.dhcp6.xid = [(r >> 8) as u8, (r >> 16) as u8, (r >> 24) as u8];
        self.dhcp6.current = Some(i);
        self.dhcp6.running = true;
        self.dhcp6.interval_ms = IMIN_MS;
        self.dhcp6.interval_start = now;
        self.dhcp6_pick_tx(now);
        // The first transmission fires at once (OT
        // `IndicateInconsistent`).
        self.dhcp6.tx_at = now;
        self.dhcp6.sent = false;
        true
    }

    /// Choose the transmission time within the current trickle interval:
    /// uniformly in `[I/2, I)`.
    fn dhcp6_pick_tx(&mut self, _now: Instant) {
        let i = self.dhcp6.interval_ms;
        let off = i / 2 + self.prng.next_u32() % (i / 2).max(1);
        self.dhcp6.tx_at = self.dhcp6.interval_start + Duration::from_millis(u64::from(off));
        self.dhcp6.sent = false;
    }

    /// Timers of the client.
    #[inline(never)]
    pub(crate) fn dhcp6_poll(&mut self, now: Instant) {
        if !self.dhcp6.running {
            return;
        }
        let iv_end =
            self.dhcp6.interval_start + Duration::from_millis(u64::from(self.dhcp6.interval_ms));
        if !self.dhcp6.sent && now >= self.dhcp6.tx_at {
            self.dhcp6.sent = true;
            self.dhcp6_solicit(now);
        }
        if now >= iv_end {
            self.dhcp6.interval_start = iv_end;
            self.dhcp6.interval_ms = (self.dhcp6.interval_ms.saturating_mul(2)).min(IMAX_MS);
            self.dhcp6_pick_tx(now);
        }
    }

    fn dhcp6_solicit(&mut self, now: Instant) {
        let Some(c) = self.dhcp6.current else { return };
        if self.dhcp6.ias[c].state == IaState::Solicit {
            self.dhcp6.start = now;
            self.dhcp6.ias[c].state = IaState::Soliciting;
        }
        let rloc16 = self.dhcp6.ias[c].agent_rloc;
        let mut w = Writer::new();
        w.put(&[MSG_SOLICIT]);
        w.put(&self.dhcp6.xid);
        let elapsed = (now - self.dhcp6.start).as_millis() / 1000;
        w.opt(
            OPT_ELAPSED_TIME,
            &(elapsed.min(0xffff) as u16).to_be_bytes(),
        );
        w.duid_opt(OPT_CLIENT_ID, &self.cm.eui64);
        // IA_NA with the prefixes of this agent.
        let mut ia = [0u8; 12 + 28 * NUM_PREFIXES];
        let mut n = 12; // IAID 0, T1 0, T2 0
        for a in &self.dhcp6.ias {
            if matches!(a.state, IaState::Solicit | IaState::Soliciting) && a.agent_rloc == rloc16 {
                let mut p = [0u8; 16];
                p[..8].copy_from_slice(&a.prefix);
                let o = ia_address(&Ipv6Addr::from(p), 0, 0);
                ia[n..n + 4].copy_from_slice(&[0, OPT_IA_ADDRESS as u8, 0, 24]);
                ia[n + 4..n + 28].copy_from_slice(&o);
                n += 28;
            }
        }
        w.opt(OPT_IA_NA, &ia[..n]);
        w.opt(OPT_RAPID_COMMIT, &[]);
        let ml = self.core.cfg.cur.mesh_local_prefix;
        // The stable copy of the Network Data carries the DHCP agent ALOC16
        // instead of the RLOC16.
        let dst = if rloc16 & 0xfff0 == ALOC16_DHCP_AGENT_START {
            ml.aloc(rloc16).unwrap_or(Ipv6Addr::UNSPECIFIED)
        } else {
            ml.rloc(opentrust_core::types::Rloc16(rloc16))
        };
        let src = self.core.ip6.netif.rloc();
        let Some(sock) = self.dhcp6.client_sock else {
            return;
        };
        let to = SocketAddrV6::new(dst, SERVER_PORT, 0, 0);
        self.dhcp6_send(now, sock, to, src, w.bytes());
    }

    fn dhcp6_send(
        &mut self,
        now: Instant,
        sock: SocketHandle,
        to: SocketAddrV6,
        src: Option<Ipv6Addr>,
        payload: &[u8],
    ) {
        let mut buf = [0u8; MAX_DATAGRAM_LEN];
        let opts = UdpSendOpts {
            src,
            ..UdpSendOpts::default()
        };
        if let Ok((info, n)) = self.udp.build_send(
            sock,
            Some(to),
            &opts,
            payload,
            &mut buf,
            &self.core.ip6.netif,
        ) {
            let _ = self.ip6_send(now, &info, PROTO_UDP, &buf[..n]);
        }
    }

    /// A datagram queued on socket `h`: consumed here if it is for the
    /// DHCPv6 client or server.
    pub(crate) fn dhcp6_rx(&mut self, now: Instant, h: SocketHandle) -> bool {
        let client = self.dhcp6.client_sock == Some(h);
        let server = self.dhcp6.server_sock == Some(h);
        if !client && !server {
            return false;
        }
        let mut buf = [0u8; MAX_UDP_PAYLOAD];
        while let Ok(Some(info)) = self.udp.recv(h, &mut buf) {
            if info.truncated || info.len > MAX_MSG {
                continue;
            }
            let payload = &buf[..info.len];
            if client {
                self.dhcp6_client_rx(now, payload);
            } else {
                self.dhcp6_server_rx(now, &info.meta, payload);
            }
        }
        true
    }

    fn dhcp6_client_rx(&mut self, now: Instant, m: &[u8]) {
        if m.len() < 4 || m[0] != MSG_REPLY || m[1..4] != self.dhcp6.xid {
            return;
        }
        let body = &m[4..];
        let eui = self.cm.eui64;
        if !status_ok(body)
            || find_opt(body, OPT_SERVER_ID).is_none_or(|v| duid_ext(v).is_none())
            || !find_opt(body, OPT_CLIENT_ID).is_some_and(|v| duid_ext(v) == Some(eui))
            || find_opt(body, OPT_RAPID_COMMIT).is_none()
        {
            return;
        }
        let Some(ia_na) = find_opt(body, OPT_IA_NA) else {
            return;
        };
        if ia_na.len() < 12 || !status_ok(&ia_na[12..]) {
            return;
        }
        for (addr, preferred, valid) in ia_addresses(ia_na) {
            let ia = self.dhcp6.ias.iter_mut().find(|ia| {
                ia.state != IaState::Invalid
                    && ia.addr.is_none()
                    && prefix_matches(&addr, &ia.prefix, ia.prefix_len)
            });
            let Some(ia) = ia else { return };
            ia.addr = Some(addr);
            ia.state = IaState::Replied;
            let _ = self.core.ip6.netif.add_unicast(UnicastAddress {
                addr,
                prefix_len: ia.prefix_len,
                origin: AddressOrigin::Dhcp6,
                preferred: preferred != 0,
                valid: valid != 0,
                scope_override: None,
                rloc: false,
                mesh_local: false,
            });
        }
        // Next association, or done.
        self.dhcp6.current = None;
        if !self.dhcp6_next_ia(now) {
            self.dhcp6_stop();
        }
    }

    fn dhcp6_server_rx(&mut self, now: Instant, meta: &UdpMeta, m: &[u8]) {
        if m.len() < 4 || m[0] != MSG_SOLICIT {
            return;
        }
        let xid = [m[1], m[2], m[3]];
        let body = &m[4..];
        let Some(client) = find_opt(body, OPT_CLIENT_ID).and_then(duid_ext) else {
            return;
        };
        if find_opt(body, OPT_SERVER_ID).is_some() || find_opt(body, OPT_RAPID_COMMIT).is_none() {
            return;
        }
        if find_opt(body, OPT_ELAPSED_TIME).is_some_and(|v| v.len() < 2) {
            return;
        }
        let Some(ia_na) = find_opt(body, OPT_IA_NA) else {
            return;
        };
        if ia_na.len() < 12 {
            return;
        }
        let iaid = [ia_na[0], ia_na[1], ia_na[2], ia_na[3]];
        // The prefixes this node serves.
        let own = self.mle.rloc16().0;
        let mut agents: Vec<([u8; 8], u8), NUM_PREFIXES> = Vec::new();
        for e in self.core.netdata.view().on_mesh_prefixes() {
            if (e.flags.has(BrFlags::DHCP) || e.flags.has(BrFlags::CONFIGURE))
                && e.rloc16 == own
                && e.prefix.len() <= 64
            {
                let mut p = [0u8; 8];
                p.copy_from_slice(&e.prefix.addr().octets()[..8]);
                if !agents.iter().any(|a| a.0 == p && a.1 == e.prefix.len()) {
                    let _ = agents.push((p, e.prefix.len()));
                }
            }
        }
        if agents.is_empty() {
            return;
        }
        // Requested prefixes select the agents; none requested: all.
        let mut mask: u8 = 0;
        for (addr, _, _) in ia_addresses(ia_na) {
            if let Some(i) = agents.iter().position(|a| prefix_matches(&addr, &a.0, a.1)) {
                mask |= 1 << i;
            }
        }
        let mut iid = client.0;
        iid[0] ^= 0x02;
        let mut w = Writer::new();
        w.put(&[MSG_REPLY]);
        w.put(&xid);
        w.duid_opt(OPT_SERVER_ID, &self.cm.eui64);
        w.duid_opt(OPT_CLIENT_ID, &client);
        let mut ia = [0u8; 12 + 6 + 28 * NUM_PREFIXES];
        ia[..4].copy_from_slice(&iaid);
        ia[4..8].copy_from_slice(&INFINITE.to_be_bytes());
        ia[8..12].copy_from_slice(&INFINITE.to_be_bytes());
        // Status Code: success.
        ia[12..18].copy_from_slice(&[0, OPT_STATUS_CODE as u8, 0, 2, 0, 0]);
        let mut n = 18;
        for (i, a) in agents.iter().enumerate() {
            if mask != 0 && mask & (1 << i) == 0 {
                continue;
            }
            let mut ab = [0u8; 16];
            ab[..8].copy_from_slice(&a.0);
            ab[8..].copy_from_slice(&iid);
            ia[n..n + 4].copy_from_slice(&[0, OPT_IA_ADDRESS as u8, 0, 24]);
            ia[n + 4..n + 28].copy_from_slice(&ia_address(&Ipv6Addr::from(ab), INFINITE, INFINITE));
            n += 28;
        }
        w.opt(OPT_IA_NA, &ia[..n]);
        w.opt(OPT_RAPID_COMMIT, &[]);
        let Some(sock) = self.dhcp6.server_sock else {
            return;
        };
        let to = SocketAddrV6::new(*meta.peer.ip(), CLIENT_PORT, 0, 0);
        self.dhcp6_send(now, sock, to, None, w.bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_round_trip() {
        let mut w = Writer::new();
        w.duid_opt(OPT_CLIENT_ID, &ExtAddress([1, 2, 3, 4, 5, 6, 7, 8]));
        w.opt(OPT_RAPID_COMMIT, &[]);
        let b = w.bytes();
        assert_eq!(
            find_opt(b, OPT_CLIENT_ID).and_then(duid_ext),
            Some(ExtAddress([1, 2, 3, 4, 5, 6, 7, 8]))
        );
        assert!(find_opt(b, OPT_RAPID_COMMIT).is_some());
        assert!(find_opt(b, OPT_SERVER_ID).is_none());
    }

    #[test]
    fn prefix_match() {
        let a: Ipv6Addr = "2001::1".parse().unwrap();
        assert!(prefix_matches(&a, &[0x20, 0x01, 0, 0, 0, 0, 0, 0], 64));
        assert!(!prefix_matches(&a, &[0x20, 0x02, 0, 0, 0, 0, 0, 0], 64));
    }

    #[test]
    fn ia_address_parse() {
        let a: Ipv6Addr = "2001::5".parse().unwrap();
        let mut ia = [0u8; 12 + 28];
        ia[12..16].copy_from_slice(&[0, 5, 0, 24]);
        ia[16..40].copy_from_slice(&ia_address(&a, 7, 9));
        assert_eq!(ia_addresses(&ia).next(), Some((a, 7, 9)));
    }
}
