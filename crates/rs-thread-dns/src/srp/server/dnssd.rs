//! DNS-SD answers from the SRP registrations (OT `Dns::ServiceDiscovery::Server`
//! with `ResolveBySrp`): PTR (browse, subtypes), SRV, TXT, AAAA and KEY
//! queries for names below `default.service.arpa.`.
//!
//! Not implemented: SOA / NS queries, upstream forwarding and the discovery
//! proxy (see `OPENTRUST-OPENTHREAD-DIFFERENCES.md`).

use rs_thread_core::time::Instant;

use super::{Service, SrpServer, WireName};
use crate::wire::{Header, Parser, Writer, class, opcode, rcode, rtype};

/// The only domain the DNS-SD server answers for (OT `kDefaultDomainName`).
const DOMAIN: &str = "default.service.arpa";

struct Qs {
    t1: u16,
    t2: u16,
}

impl Qs {
    fn is_for(&self, t: u16) -> bool {
        self.t1 == t || self.t2 == t
    }
}

struct Answer<'a, 'b> {
    w: &'a mut Writer<'b>,
    qname: &'a WireName,
    qs: Qs,
    an: u16,
    ar: u16,
    /// Records go to the answer section.
    answer: bool,
    now: Instant,
}

type W = rs_thread_core::Result<()>;

fn ttl_of(expire: Instant, now: Instant) -> u32 {
    u32::try_from(expire.saturating_duration_since(now).as_secs()).unwrap_or(u32::MAX)
}

impl Answer<'_, '_> {
    fn count(&mut self) {
        if self.answer {
            self.an += 1;
        } else {
            self.ar += 1;
        }
    }

    fn name(&mut self, n: &WireName) -> W {
        // For ANY queries all records are for the query name.
        if self.qs.is_for(rtype::ANY) {
            return self.w.write_wire_name(self.qname.as_bytes(), true);
        }
        self.w.write_wire_name(n.as_bytes(), true)
    }

    fn ptr(&mut self, s: &Service, now: Instant) -> W {
        self.w.write_wire_name(self.qname.as_bytes(), true)?;
        let m = self
            .w
            .begin_record(rtype::PTR, class::IN, ttl_of(s.expire_time(), now))?;
        self.w.write_wire_name(s.instance.as_bytes(), true)?;
        self.w.end_record(m)?;
        self.count();
        Ok(())
    }

    fn srv(&mut self, s: &Service, host: &WireName) -> W {
        self.name(&s.instance)?;
        let m = self
            .w
            .begin_record(rtype::SRV, class::IN, ttl_of(s.expire_time(), self.now))?;
        self.w.put_u16(s.priority)?;
        self.w.put_u16(s.weight)?;
        self.w.put_u16(s.port)?;
        self.w.write_wire_name(host.as_bytes(), true)?;
        self.w.end_record(m)?;
        self.count();
        Ok(())
    }

    fn txt(&mut self, s: &Service) -> W {
        self.name(&s.instance)?;
        let m = self
            .w
            .begin_record(rtype::TXT, class::IN, ttl_of(s.expire_time(), self.now))?;
        if s.txt.is_empty() {
            self.w.put(&[0])?;
        } else {
            self.w.put(&s.txt)?;
        }
        self.w.end_record(m)?;
        self.count();
        Ok(())
    }

    fn addresses(&mut self, h: &super::Host) -> W {
        let ttl = ttl_of(h.expire_time(), self.now);
        for a in &h.addresses {
            self.name(&h.name)?;
            self.w.write_aaaa(ttl, a)?;
            self.count();
        }
        Ok(())
    }

    fn key(&mut self, h: &super::Host) -> W {
        self.w.write_wire_name(self.qname.as_bytes(), true)?;
        self.w
            .write_key(ttl_of(h.expire_time(), self.now), &h.key)?;
        self.count();
        Ok(())
    }

    /// SRV and TXT in the section their question asks for, then the other
    /// in the additional section, then the host addresses.
    fn service_records(&mut self, s: &Service, h: &super::Host) -> W {
        for answer in [true, false] {
            self.answer = answer;
            if !answer && self.qs.is_for(rtype::ANY) {
                return Ok(());
            }
            let wanted_here = |qs: &Qs, t: u16| (qs.is_for(t) || qs.is_for(rtype::ANY)) == answer;
            if wanted_here(&self.qs, rtype::SRV) {
                self.srv(s, &h.name)?;
            }
            if wanted_here(&self.qs, rtype::TXT) {
                self.txt(s)?;
            }
        }
        self.addresses(h)
    }
}

impl<const H: usize, const S: usize, const U: usize> SrpServer<H, S, U> {
    /// Answer the DNS query in `msg` from the registrations. `None`: drop
    /// (not a query).
    pub fn handle_query(&self, now: Instant, msg: &[u8], out: &mut [u8]) -> Option<usize> {
        let (mut p, h) = Parser::new(msg).ok()?;
        if h.response {
            return None;
        }
        let mut hdr = Header {
            id: h.id,
            response: true,
            opcode: h.opcode,
            rd: h.rd,
            ..Header::default()
        };
        let mut w = Writer::new(out).ok()?;
        let fail = |w: &mut Writer<'_>, hdr: &mut Header, rc: u8| {
            w.truncate(crate::wire::HEADER_LEN);
            hdr.rcode = rc;
            hdr.qd = 0;
            hdr.an = 0;
            hdr.ar = 0;
            w.set_header(hdr);
            Some(w.len())
        };
        if h.opcode != opcode::QUERY {
            return fail(&mut w, &mut hdr, rcode::NOT_IMPLEMENTED);
        }
        if h.tc || h.qd == 0 || h.qd > 2 {
            return fail(&mut w, &mut hdr, rcode::FORMAT_ERROR);
        }
        let Ok(q1) = p.question() else {
            return fail(&mut w, &mut hdr, rcode::FORMAT_ERROR);
        };
        let mut qs = Qs {
            t1: q1.qtype,
            t2: 0,
        };
        let Ok(qname) = WireName::from_msg(&q1.name) else {
            return fail(&mut w, &mut hdr, rcode::FORMAT_ERROR);
        };
        let mut second = None;
        if h.qd == 2 {
            let Ok(q2) = p.question() else {
                return fail(&mut w, &mut hdr, rcode::FORMAT_ERROR);
            };
            qs.t2 = q2.qtype;
            if !(q2.name.eq_name(&q1.name) && qs.is_for(rtype::SRV) && qs.is_for(rtype::TXT)) {
                return fail(&mut w, &mut hdr, rcode::FORMAT_ERROR);
            }
            second = Some((q2.qtype, q2.qclass));
        }
        // Questions.
        let ok = (|| {
            w.write_wire_name(qname.as_bytes(), true).ok()?;
            w.put_u16(q1.qtype).ok()?;
            w.put_u16(q1.qclass).ok()?;
            if let Some((t, c)) = second {
                w.write_wire_name(qname.as_bytes(), true).ok()?;
                w.put_u16(t).ok()?;
                w.put_u16(c).ok()?;
            }
            Some(())
        })();
        if ok.is_none() {
            return fail(&mut w, &mut hdr, rcode::SERVER_FAILURE);
        }
        hdr.qd = h.qd;
        let domain = WireName::from_dotted(DOMAIN)?;
        if !qname.is_subdomain_of(&domain) {
            hdr.rcode = rcode::NAME_ERROR;
            w.set_header(&hdr);
            return Some(w.len());
        }

        let mut a = Answer {
            w: &mut w,
            qname: &qname,
            qs,
            an: 0,
            ar: 0,
            answer: true,
            now,
        };
        let r = self.resolve(&mut a, &domain);
        let (an, ar) = (a.an, a.ar);
        match r {
            Ok(true) => {}
            Ok(false) => hdr.rcode = rcode::NAME_ERROR,
            Err(_) => return fail(&mut w, &mut hdr, rcode::SERVER_FAILURE),
        }
        hdr.an = an;
        hdr.ar = ar;
        w.set_header(&hdr);
        Some(w.len())
    }

    /// `Ok(false)`: nothing matches the name.
    fn resolve(&self, a: &mut Answer<'_, '_>, _domain: &WireName) -> rs_thread_core::Result<bool> {
        let now = a.now;
        let mut matched: Option<(&Service, &super::Host)> = None;
        for h in self.hosts() {
            if h.is_deleted() {
                continue;
            }
            if h.name.eq_name(a.qname) {
                if a.qs.is_for(rtype::AAAA) || a.qs.is_for(1) || a.qs.is_for(rtype::ANY) {
                    a.answer = a.qs.is_for(rtype::AAAA) || a.qs.is_for(rtype::ANY);
                    a.addresses(h)?;
                }
                if a.qs.is_for(rtype::KEY) || a.qs.is_for(rtype::ANY) {
                    a.answer = true;
                    a.key(h)?;
                }
                return Ok(true);
            }
            for s in self.services_of(h) {
                if s.deleted {
                    continue;
                }
                if s.instance.eq_name(a.qname) {
                    if a.qs.is_for(rtype::KEY) || a.qs.is_for(rtype::ANY) {
                        a.answer = true;
                        a.key(h)?;
                    }
                    if a.qs.is_for(rtype::SRV) || a.qs.is_for(rtype::TXT) || a.qs.is_for(rtype::ANY)
                    {
                        a.service_records(s, h)?;
                    }
                    return Ok(true);
                }
                if (a.qs.is_for(rtype::PTR) || a.qs.is_for(rtype::ANY))
                    && (s.service_name.eq_name(a.qname)
                        || s.sub_types.iter().any(|t| t.eq_name(a.qname)))
                {
                    a.answer = true;
                    a.ptr(s, now)?;
                    matched = Some((s, h));
                }
            }
        }
        let Some((s, h)) = matched else {
            return Ok(false);
        };
        // With a single match the SRV / TXT / AAAA records come along.
        if a.qs.is_for(rtype::PTR) && a.an == 1 {
            a.service_records(s, h)?;
        }
        Ok(true)
    }
}
