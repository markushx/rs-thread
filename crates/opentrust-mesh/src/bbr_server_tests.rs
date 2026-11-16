//! Backbone Router service: the state machine and the registrations.

use core::net::Ipv6Addr;
use std::vec::Vec as StdVec;

use opentrust_core::Error;
use opentrust_core::time::Instant;
use opentrust_core::types::Iid;

use crate::bbr_server::*;
use crate::mlr::{build_mlr_request, parse_mlr_response};
use crate::netdata::backbone::BackboneRouterLeader;
use crate::sim::XRng;
use crate::tlv::mlr_status;

fn ctx(leader: &BackboneRouterLeader) -> BbrContext<'_> {
    BbrContext {
        attached: true,
        is_leader: true,
        rloc16: 0x0400,
        leader,
    }
}

fn primary() -> BbrServer {
    let leader = BackboneRouterLeader::new();
    let mut s = BbrServer::new();
    let _ = s.set_enabled(true, &ctx(&leader));
    s.force_state(LocalState::Primary);
    s
}

#[test]
fn enable_adds_service_and_disable_removes_it() {
    let leader = BackboneRouterLeader::new();
    let mut s = BbrServer::new();
    s.seed(&mut XRng(5));
    assert_eq!(s.state(), LocalState::Disabled);
    let a = s.set_enabled(true, &ctx(&leader));
    assert!(matches!(a, ServiceAction::Add(c) if c.sequence_number < 127));
    assert_eq!(s.state(), LocalState::Secondary);
    assert_eq!(s.set_enabled(false, &ctx(&leader)), ServiceAction::Remove);
    assert_eq!(s.state(), LocalState::Disabled);
}

#[test]
fn config_rules() {
    let leader = BackboneRouterLeader::new();
    let mut s = BbrServer::new();
    assert!(s.set_config(None, Some(0), None, &ctx(&leader)).is_err());
    assert!(
        s.set_config(None, Some(10), Some(20), &ctx(&leader))
            .is_err()
    );
    assert!(
        s.set_config(Some(7), Some(10), Some(21), &ctx(&leader))
            .is_ok()
    );
    assert_eq!(s.config().sequence_number, 7);
}

#[test]
fn mlr_needs_primary_and_validates_scope() {
    let leader = BackboneRouterLeader::new();
    let mut s = BbrServer::new();
    let now = Instant::from_secs(10);
    let mut req = [0u8; 64];
    let a: Ipv6Addr = "ff04::1234".parse().unwrap();
    let n = build_mlr_request(&[a], &mut req).unwrap();
    let Reply::Payload(p) = s.handle_mlr_request(&req[..n], now, None, &ctx(&leader)) else {
        panic!()
    };
    assert_eq!(
        parse_mlr_response(&p).unwrap().status,
        mlr_status::BBR_NOT_PRIMARY
    );
    let mut s = primary();
    let Reply::Payload(p) = s.handle_mlr_request(&req[..n], now, None, &ctx(&leader)) else {
        panic!()
    };
    assert_eq!(parse_mlr_response(&p).unwrap().status, mlr_status::SUCCESS);
    assert_eq!(s.listeners.iter().count(), 1);
    let bad: Ipv6Addr = "ff03::1".parse().unwrap();
    let n = build_mlr_request(&[bad], &mut req).unwrap();
    let Reply::Payload(p) = s.handle_mlr_request(&req[..n], now, None, &ctx(&leader)) else {
        panic!()
    };
    let r = parse_mlr_response(&p).unwrap();
    assert_eq!(r.status, mlr_status::INVALID);
    assert_eq!(r.failed.iter().copied().collect::<StdVec<_>>(), [bad]);
}

#[test]
fn nd_proxy_detects_duplicates() {
    let mut t = NdProxyTable::new();
    assert!(t.register(Iid([1; 8]), Iid([2; 8]), 0x400).is_ok());
    assert!(t.register(Iid([1; 8]), Iid([2; 8]), 0x800).is_ok());
    assert_eq!(
        t.register(Iid([1; 8]), Iid([3; 8]), 0x400),
        Err(Error::Already)
    );
    // A new DUA of the same device replaces the old one.
    assert!(t.register(Iid([4; 8]), Iid([2; 8]), 0x400).is_ok());
    assert!(!t.is_registered(&Iid([1; 8])));
}
