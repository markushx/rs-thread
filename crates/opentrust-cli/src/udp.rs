//! `udp open|bind|send|close` (OT `cli_udp.cpp`) with one socket.

use core::fmt::Write;
use core::net::SocketAddrV6;

use opentrust_instance::{InstanceCrypto, UdpSocket};
use opentrust_net::udp::UdpSendOpts;
use opentrust_platform::SettingsStore;
use rand_core::{CryptoRng, Rng};

use crate::Ctx;
use crate::util::{Args, E, Ip6, R, ln, out, parse_hex, parse_ip6, parse_u16};

/// Largest payload of `udp send` and of a printed datagram.
/// Largest payload of `udp send -s` and of a printed datagram.
const MAX_PAYLOAD: usize = if cfg!(feature = "ip6-fragmentation") {
    opentrust_net::header::MAX_DATAGRAM_LEN - 48
} else {
    512
};

impl<S, C, Rn, W> Ctx<'_, S, C, Rn, W>
where
    S: SettingsStore,
    C: InstanceCrypto,
    Rn: Rng + CryptoRng,
    W: Write,
{
    pub(crate) fn udp(&mut self, a: &Args<'_>) -> R {
        match a.get(1) {
            "open" => {
                if self.st.udp.is_some() {
                    return Err(E::ALREADY);
                }
                self.st.udp = Some(self.i.udp_open()?);
                Ok(())
            }
            "close" => {
                let s = self.st.udp.take().ok_or(E::INVALID_STATE)?;
                self.i.udp_close(s).map_err(E::from)
            }
            "bind" => {
                let s = self.st.udp.ok_or(E::INVALID_STATE)?;
                let mut k = 2;
                if a.get(k) == "-u" || a.get(k) == "-b" {
                    k += 1;
                }
                let addr = parse_ip6(a.get(k))?;
                let port = parse_u16(a.get(k + 1))?;
                self.i
                    .udp_bind(s, SocketAddrV6::new(addr, port, 0, 0))
                    .map_err(E::from)
            }
            "send" => self.udp_send(a),
            _ => Err(E::INVALID_COMMAND),
        }
    }

    fn udp_send(&mut self, a: &Args<'_>) -> R {
        let s: UdpSocket = self.st.udp.ok_or(E::INVALID_STATE)?;
        let mut k = 2;
        let mut peer = None;
        if !a.get(4).is_empty() {
            let addr = parse_ip6(a.get(2))?;
            let port = parse_u16(a.get(3))?;
            peer = Some(SocketAddrV6::new(addr, port, 0, 0));
            k = 4;
        }
        let peer = peer.ok_or(E::INVALID_ARGS)?;
        let mut buf = [0u8; MAX_PAYLOAD];
        let n = match a.get(k) {
            "-s" => {
                let n = usize::from(parse_u16(a.get(k + 1))?);
                if n > MAX_PAYLOAD {
                    return Err(E::NO_BUFS);
                }
                for (i, b) in buf[..n].iter_mut().enumerate() {
                    *b = b"0123456789abcdef"[i % 16];
                }
                n
            }
            "-x" => {
                if a.get(k + 1).is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                parse_hex(a.get(k + 1), &mut buf)?
            }
            t => {
                let t = if t == "-t" { a.get(k + 1) } else { t };
                if t.is_empty() {
                    return Err(E::INVALID_ARGS);
                }
                let b = t.as_bytes();
                let dst = buf.get_mut(..b.len()).ok_or(E::NO_BUFS)?;
                dst.copy_from_slice(b);
                b.len()
            }
        };
        self.i
            .udp_send_to(s, peer, &buf[..n], &UdpSendOpts::default(), self.now)
            .map_err(E::from)
    }

    pub(crate) fn udp_readable(&mut self, s: UdpSocket) {
        if self.st.udp != Some(s) {
            return;
        }
        let mut buf = [0u8; MAX_PAYLOAD];
        while let Ok(Some(info)) = self.i.udp_recv(s, &mut buf) {
            let n = info.len.min(MAX_PAYLOAD);
            out!(
                self.o,
                "{} bytes from {} {} ",
                n,
                Ip6(*info.meta.peer.ip()),
                info.meta.peer.port()
            );
            for &b in &buf[..n] {
                let c = if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                };
                let _ = self.o.write_char(c);
            }
            ln!(self.o);
        }
    }
}
