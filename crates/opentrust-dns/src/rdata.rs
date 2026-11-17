//! Record data helpers: TXT entries, KEY / SIG(0) (RFC 2535 / RFC 2931 with
//! the ECDSA P-256 algorithm of RFC 6605), EDNS(0) OPT with the Update Lease
//! option (RFC 9664).

use opentrust_core::crypto::ecdsa::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use opentrust_core::{Error, Result};

use crate::wire::{MAX_LABEL_LEN, Name, Record, Writer, class, rtype};

/// Longest dotted name (service type or host name) a query may use.
pub const MAX_NAME: usize = 128;
/// Longest instance label.
pub const MAX_LABEL: usize = MAX_LABEL_LEN + 1;
/// Longest TXT rdata kept in a resolved or registered service.
pub const MAX_TXT: usize = 256;

// --------------------------------------------------------------------- TXT

/// One DNS-SD TXT entry (RFC 6763 section 6): `key` or `key=value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxtEntry<'a> {
    /// Key (1+ printable ASCII bytes, no `=`).
    pub key: &'a [u8],
    /// Value; `None` is a boolean attribute (no `=`), `Some(&[])` is
    /// `key=` with an empty value.
    pub value: Option<&'a [u8]>,
}

/// Encode `entries` into `out` and return the length. No entries encode as a
/// single zero-length string (RFC 6763 6.1; OT `TxtEntry::AppendEntries`).
pub fn encode_txt(entries: &[TxtEntry<'_>], out: &mut [u8]) -> Result<usize> {
    if entries.is_empty() {
        *out.first_mut().ok_or(Error::NoBufs)? = 0;
        return Ok(1);
    }
    let mut n = 0;
    for e in entries {
        if e.key.is_empty() || e.key.contains(&b'=') {
            return Err(Error::InvalidArgs);
        }
        let len = e.key.len() + e.value.map_or(0, |v| 1 + v.len());
        let len8 = u8::try_from(len).map_err(|_| Error::InvalidArgs)?;
        let dst = out.get_mut(n..n + 1 + len).ok_or(Error::NoBufs)?;
        dst[0] = len8;
        dst[1..1 + e.key.len()].copy_from_slice(e.key);
        if let Some(v) = e.value {
            dst[1 + e.key.len()] = b'=';
            dst[2 + e.key.len()..].copy_from_slice(v);
        }
        n += 1 + len;
    }
    Ok(n)
}

/// Iterator over the entries of encoded TXT rdata. Empty strings and
/// strings starting with `=` are skipped (RFC 6763 6.4); a truncated string
/// yields `Err` once.
#[derive(Debug, Clone)]
pub struct TxtIter<'a> {
    data: &'a [u8],
}

impl<'a> TxtIter<'a> {
    /// Iterate over `data`.
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Iterator for TxtIter<'a> {
    type Item = Result<TxtEntry<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (&len, rest) = self.data.split_first()?;
            let len = usize::from(len);
            let Some(s) = rest.get(..len) else {
                self.data = &[];
                return Some(Err(Error::Parse));
            };
            self.data = &rest[len..];
            if s.is_empty() || s[0] == b'=' {
                continue;
            }
            return Some(Ok(match s.iter().position(|&c| c == b'=') {
                Some(i) => TxtEntry {
                    key: &s[..i],
                    value: Some(&s[i + 1..]),
                },
                None => TxtEntry {
                    key: s,
                    value: None,
                },
            }));
        }
    }
}

impl<'a> Record<'a> {
    /// TXT rdata entries.
    pub fn txt(&self) -> TxtIter<'a> {
        TxtIter::new(self.rdata)
    }
}

// ------------------------------------------------------------- KEY and SIG

/// KEY protocol value for DNSSEC.
pub const KEY_PROTOCOL_DNSSEC: u8 = 3;
/// DNSSEC algorithm number for ECDSA P-256 with SHA-256 (RFC 6605).
pub const ALGORITHM_ECDSAP256SHA256: u8 = 13;
/// KEY flags as OT sends them: authentication and confidentiality permitted,
/// non-zone entity owner, general signatory.
pub const KEY_FLAGS_SRP: [u8; 2] = [0x02, 0x01];
/// Fixed part of SIG rdata before the signer name.
pub const SIG_FIXED_LEN: usize = 18;

/// KEY rdata with an ECDSA P-256 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRdata<'a> {
    /// Flags.
    pub flags: [u8; 2],
    /// Protocol.
    pub protocol: u8,
    /// Algorithm.
    pub algorithm: u8,
    /// Public key (`X || Y`).
    pub public_key: &'a [u8; PUBLIC_KEY_LEN],
}

/// SIG rdata (RFC 2535 section 4.1).
#[derive(Debug, Clone, Copy)]
pub struct SigRdata<'a> {
    /// Type covered (0 for SIG(0)).
    pub type_covered: u16,
    /// Algorithm.
    pub algorithm: u8,
    /// Labels.
    pub labels: u8,
    /// Original TTL.
    pub original_ttl: u32,
    /// Signature expiration.
    pub expiration: u32,
    /// Signature inception.
    pub inception: u32,
    /// Key tag.
    pub key_tag: u16,
    /// Signer's name.
    pub signer: Name<'a>,
    /// Offset of the signer's name in the message.
    pub signer_off: usize,
    /// The signature (`r || s`).
    pub signature: &'a [u8; SIGNATURE_LEN],
}

impl<'a> Record<'a> {
    /// KEY rdata (ECDSA P-256 only).
    pub fn key(&self) -> Result<KeyRdata<'a>> {
        let r = self.rdata;
        if r.len() != 4 + PUBLIC_KEY_LEN {
            return Err(Error::Parse);
        }
        Ok(KeyRdata {
            flags: [r[0], r[1]],
            protocol: r[2],
            algorithm: r[3],
            public_key: r[4..].try_into().map_err(|_| Error::Parse)?,
        })
    }

    /// SIG rdata (ECDSA P-256 signatures only).
    pub fn sig(&self) -> Result<SigRdata<'a>> {
        let r = self.rdata;
        let f = r.get(..SIG_FIXED_LEN).ok_or(Error::Parse)?;
        let signer_off = self.rdata_off + SIG_FIXED_LEN;
        let signer = Name::new(self.msg, signer_off);
        let end = signer.end_offset()?;
        let sig = self
            .msg
            .get(end..self.rdata_off + r.len())
            .ok_or(Error::Parse)?;
        Ok(SigRdata {
            type_covered: u16::from_be_bytes([f[0], f[1]]),
            algorithm: f[2],
            labels: f[3],
            original_ttl: u32::from_be_bytes([f[4], f[5], f[6], f[7]]),
            expiration: u32::from_be_bytes([f[8], f[9], f[10], f[11]]),
            inception: u32::from_be_bytes([f[12], f[13], f[14], f[15]]),
            key_tag: u16::from_be_bytes([f[16], f[17]]),
            signer,
            signer_off,
            signature: sig.try_into().map_err(|_| Error::Parse)?,
        })
    }
}

impl Writer<'_> {
    /// Write a complete KEY record (owner name already written).
    pub fn write_key(&mut self, ttl: u32, public_key: &[u8; PUBLIC_KEY_LEN]) -> Result<()> {
        let m = self.begin_record(rtype::KEY, class::IN, ttl)?;
        self.put(&KEY_FLAGS_SRP)?;
        self.put(&[KEY_PROTOCOL_DNSSEC, ALGORITHM_ECDSAP256SHA256])?;
        self.put(public_key)?;
        self.end_record(m)
    }
}

// --------------------------------------------------------------------- OPT

/// EDNS(0) option code: Update Lease (RFC 9664).
pub const OPT_UPDATE_LEASE: u16 = 2;
/// DO ("DNSSEC OK") flag in the OPT flags (SRP clients set it, OT does).
pub const OPT_FLAG_DO: u16 = 0x8000;

/// Update Lease option (RFC 9664): lease and key lease in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeaseOption {
    /// Lease interval.
    pub lease: u32,
    /// Key lease interval (equals `lease` in the 4-byte short variant).
    pub key_lease: u32,
}

impl LeaseOption {
    /// Parse the option data (4-byte short or 8-byte long variant).
    pub fn parse(data: &[u8]) -> Result<Self> {
        match data.len() {
            4 => {
                let l = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok(Self {
                    lease: l,
                    key_lease: l,
                })
            }
            8 => Ok(Self {
                lease: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                key_lease: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            }),
            _ => Err(Error::Parse),
        }
    }
}

/// Iterator over the options in OPT rdata: `(code, data)`.
#[derive(Debug, Clone)]
pub struct OptIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for OptIter<'a> {
    type Item = Result<(u16, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        let r = (|| {
            let h = self.data.get(..4).ok_or(Error::Parse)?;
            let code = u16::from_be_bytes([h[0], h[1]]);
            let len = usize::from(u16::from_be_bytes([h[2], h[3]]));
            let d = self.data.get(4..4 + len).ok_or(Error::Parse)?;
            self.data = &self.data[4 + len..];
            Ok((code, d))
        })();
        if r.is_err() {
            self.data = &[];
        }
        Some(r)
    }
}

impl<'a> Record<'a> {
    /// Options of an OPT record.
    pub fn opt_options(&self) -> OptIter<'a> {
        OptIter { data: self.rdata }
    }

    /// The Update Lease option of an OPT record, if present.
    pub fn update_lease(&self) -> Result<Option<LeaseOption>> {
        for o in self.opt_options() {
            let (code, d) = o?;
            if code == OPT_UPDATE_LEASE {
                return LeaseOption::parse(d).map(Some);
            }
        }
        Ok(None)
    }

    /// For an OPT record: advertised UDP payload size.
    pub const fn opt_udp_payload(&self) -> u16 {
        self.class
    }

    /// For an OPT record: the extended RCODE (upper 8 bits).
    pub const fn opt_extended_rcode(&self) -> u8 {
        (self.ttl >> 24) as u8
    }

    /// For an OPT record: is the DO flag set?
    pub const fn opt_dnssec_ok(&self) -> bool {
        (self.ttl & OPT_FLAG_DO as u32) != 0
    }
}

impl Writer<'_> {
    /// Write an OPT pseudo-record (root owner name) advertising
    /// `udp_payload` and optionally an Update Lease option (long variant).
    pub fn write_opt(
        &mut self,
        udp_payload: u16,
        dnssec_ok: bool,
        lease: Option<LeaseOption>,
    ) -> Result<()> {
        self.write_root()?;
        let flags = if dnssec_ok { OPT_FLAG_DO } else { 0 };
        let m = self.begin_record(rtype::OPT, udp_payload, u32::from(flags))?;
        if let Some(l) = lease {
            self.put_u16(OPT_UPDATE_LEASE)?;
            self.put_u16(8)?;
            self.put_u32(l.lease)?;
            self.put_u32(l.key_lease)?;
        }
        self.end_record(m)
    }
}
