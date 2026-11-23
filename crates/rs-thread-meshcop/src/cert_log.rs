//! Certification trace of the commissioning messages (OpenThread's
//! `[THCI]` lines of a reference device build, `LogCert`): the
//! `thread-cert` scripts read them from the CLI output to check the JOIN_FIN
//! and JOIN_ENT exchange. With feature `cert-log` every message goes to the
//! `log` crate with target [`TARGET`]; without it the calls compile to
//! nothing.

/// `log` target of the trace records.
#[cfg(feature = "cert-log")]
pub const TARGET: &str = "thci";

/// Commissioning message types that are traced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Msg {
    /// JOIN_FIN.req (with its TLVs).
    FinReq,
    /// JOIN_FIN.rsp (with its TLVs).
    FinRsp,
    /// JOIN_ENT.ntf.
    EntNtf,
    /// JOIN_ENT.rsp.
    EntRsp,
}

#[cfg(feature = "cert-log")]
struct Hex<'a>(&'a [u8]);

#[cfg(feature = "cert-log")]
impl core::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Trace one message: `send` (else received), its type and, for JOIN_FIN,
/// the CoAP payload. The record reads `<send|recv> <TYPE> <hex>`.
#[cfg(feature = "cert-log")]
pub(crate) fn cert_log(send: bool, msg: Msg, payload: &[u8]) {
    let t = match msg {
        Msg::FinReq => "JOIN_FIN.req",
        Msg::FinRsp => "JOIN_FIN.rsp",
        Msg::EntNtf => "JOIN_ENT.ntf",
        Msg::EntRsp => "JOIN_ENT.rsp",
    };
    log::info!(
        target: TARGET,
        "{} {} {}",
        if send { "send" } else { "recv" },
        t,
        Hex(payload)
    );
}

#[cfg(not(feature = "cert-log"))]
#[inline(always)]
pub(crate) fn cert_log(_send: bool, _msg: Msg, _payload: &[u8]) {}
