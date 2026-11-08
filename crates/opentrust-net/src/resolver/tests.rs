#![allow(unused_must_use)]

use super::*;
use crate::netif::UnicastAddress;
use std::vec::Vec;

struct Env {
    route: bool,
    ftd: bool,
    own: u16,
    child: Option<u16>,
}

impl Env {
    const FTD: Env = Env {
        route: true,
        ftd: true,
        own: 0x0400,
        child: Some(0x0401),
    };
}

impl ResolverEnv for Env {
    fn has_route_to(&self, _: Rloc16) -> bool {
        self.route
    }
    fn is_ftd(&self) -> bool {
        self.ftd
    }
    fn is_own_rloc16(&self, r: Rloc16) -> bool {
        r.0 == self.own
    }
    fn is_minimal_child(&self, r: Rloc16) -> bool {
        self.child == Some(r.0)
    }
}

fn eid(n: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, n)
}

fn t(s: u64) -> Instant {
    Instant::from_secs(s)
}

type R = AddressResolver<4>;

/// Collects events from a closure that receives the sink.
fn ev(f: impl FnOnce(&mut dyn FnMut(ResolverEvent))) -> Vec<ResolverEvent> {
    let mut v = Vec::new();
    let mut sink = |e| v.push(e);
    f(&mut sink);
    v
}

fn resolve(
    r: &mut R,
    now: u64,
    e: u16,
    allow: bool,
    env: &Env,
) -> (Result<Resolution>, Vec<ResolverEvent>) {
    let mut v = Vec::new();
    let res = r.resolve(t(now), &eid(e), allow, env, &mut |x| v.push(x));
    (res, v)
}

fn notify(
    r: &mut R,
    now: u64,
    e: u16,
    iid: u8,
    rloc: u16,
    ltt: Option<u32>,
) -> (NotifyOutcome, Vec<ResolverEvent>) {
    let mut v = Vec::new();
    let o = r.handle_notify(
        t(now),
        &eid(e),
        Iid([iid; 8]),
        Rloc16(rloc),
        ltt,
        &mut |x| v.push(x),
    );
    (o, v)
}

fn poll(r: &mut R, now: u64) -> Vec<ResolverEvent> {
    ev(|s| r.poll(t(now), &mut |e| s(e)))
}

#[test]
fn query_notify_lifecycle() {
    let env = Env::FTD;
    let mut r = R::new();
    // Not allowed to query, nothing cached.
    assert_eq!(resolve(&mut r, 0, 1, false, &env).0, Err(Error::NotFound));
    assert!(r.is_empty());
    // Allowed: a query goes out, the datagram waits.
    let (res, evs) = resolve(&mut r, 0, 1, true, &env);
    assert_eq!(res, Ok(Resolution::QueryPending));
    assert_eq!(evs, [ResolverEvent::SendQuery { eid: eid(1) }]);
    let info = r.info(&eid(1)).unwrap();
    assert_eq!(
        (info.state, info.timeout, info.can_evict),
        (EntryState::Query, 3, false)
    );
    // Second resolve while waiting: pending, no new query.
    let (res, evs) = resolve(&mut r, 1, 1, true, &env);
    assert_eq!((res, evs.len()), (Ok(Resolution::QueryPending), 0));
    assert_eq!(resolve(&mut r, 1, 1, false, &env).0, Err(Error::NotFound));
    // Notification resolves it.
    let (o, evs) = notify(&mut r, 2, 1, 7, 0x0800, Some(10));
    assert_eq!(o, NotifyOutcome::Updated);
    assert_eq!(evs, [ResolverEvent::Resolved { eid: eid(1) }]);
    assert_eq!(
        resolve(&mut r, 2, 1, true, &env).0,
        Ok(Resolution::Resolved(Rloc16(0x0800)))
    );
    assert_eq!(r.info(&eid(1)).unwrap().state, EntryState::Cached);
    // Stale entries without a route are dropped and re-queried; with a route kept.
    let no_route = Env {
        route: false,
        ..Env::FTD
    };
    // Fresh right after the notification, even without a route.
    assert_eq!(
        resolve(&mut r, 2, 1, true, &no_route).0,
        Ok(Resolution::Resolved(Rloc16(0x0800)))
    );
    // Freshness lasts FRESHNESS_TIMEOUT ticks; afterwards a route is required.
    poll(&mut r, 10);
    assert_eq!(
        resolve(&mut r, 10, 1, false, &env).0,
        Ok(Resolution::Resolved(Rloc16(0x0800)))
    );
    let (res, evs) = resolve(&mut r, 10, 1, true, &no_route);
    assert_eq!(res, Ok(Resolution::QueryPending));
    assert_eq!(evs, [ResolverEvent::SendQuery { eid: eid(1) }]);
}

#[test]
fn query_timeout_and_exponential_backoff() {
    let env = Env::FTD;
    let mut r = R::new();
    let mut now = 0u64;
    resolve(&mut r, now, 1, true, &env);
    // Expected (timeout, retry_delay) after each failed query: OT doubles
    // the retry delay 15 -> 30 -> 60 -> 120 (cap).
    for (wait, next_delay) in [(15u16, 30u16), (30, 60), (60, 120), (120, 120), (120, 120)] {
        // 3 seconds without a notification.
        let mut failed = Vec::new();
        for _ in 0..3 {
            now += 1;
            failed.extend(poll(&mut r, now));
        }
        assert_eq!(failed, [ResolverEvent::ResolutionFailed { eid: eid(1) }]);
        let i = r.info(&eid(1)).unwrap();
        assert_eq!(
            (i.state, i.timeout, i.retry_delay, i.can_evict),
            (EntryState::QueryRetry, wait, next_delay, true)
        );
        // During the wait, resolves are refused (OT kErrorDrop).
        assert_eq!(resolve(&mut r, now, 1, true, &env).0, Err(Error::Drop));
        // Wait it out: ramp-down starts; now a new query is allowed.
        for _ in 0..wait {
            now += 1;
            poll(&mut r, now);
        }
        let i = r.info(&eid(1)).unwrap();
        assert_eq!((i.state, i.timeout), (EntryState::QueryRetry, 120));
        let (res, evs) = resolve(&mut r, now, 1, true, &env);
        assert_eq!(res, Ok(Resolution::QueryPending));
        assert_eq!(evs, [ResolverEvent::SendQuery { eid: eid(1) }]);
        // The retry delay is kept for the next failure.
        assert_eq!(r.info(&eid(1)).unwrap().retry_delay, next_delay);
    }
}

#[test]
fn retry_delay_ramps_down_when_left_alone() {
    let env = Env::FTD;
    let mut r = R::new();
    resolve(&mut r, 0, 1, true, &env);
    let mut now = 0;
    // Fail 3 times: delay -> 120, but each retry resolve restarts the query.
    for _ in 0..3 {
        for _ in 0..3 {
            now += 1;
            poll(&mut r, now);
        }
        let w = r.info(&eid(1)).unwrap().timeout;
        for _ in 0..w {
            now += 1;
            poll(&mut r, now);
        }
        resolve(&mut r, now, 1, true, &env);
    }
    for _ in 0..3 {
        now += 1;
        poll(&mut r, now);
    }
    let i = r.info(&eid(1)).unwrap();
    assert_eq!(
        (i.state, i.retry_delay, i.timeout),
        (EntryState::QueryRetry, 120, 120)
    );
    // Leave it alone: wait (120), ramp-down start (120), then halve every 120 s.
    for _ in 0..120 + 120 {
        now += 1;
        poll(&mut r, now);
    }
    assert_eq!(r.info(&eid(1)).unwrap().retry_delay, 60);
    for _ in 0..120 {
        now += 1;
        poll(&mut r, now);
    }
    assert_eq!(r.info(&eid(1)).unwrap().retry_delay, 30);
    for _ in 0..120 {
        now += 1;
        poll(&mut r, now);
    }
    let i = r.info(&eid(1)).unwrap();
    assert_eq!(i.retry_delay, INITIAL_RETRY_DELAY_S);
    // Settled: no more ticks needed.
    for _ in 0..130 {
        now += 1;
        poll(&mut r, now);
    }
    assert_eq!(r.next_deadline(), None);
}

#[test]
fn eviction_order() {
    let env = Env::FTD;
    let mut r = R::new();
    // 1: cached; 2: query-retry (evictable); 3: query (not evictable); 4: snooped (blocking).
    resolve(&mut r, 0, 1, true, &env);
    notify(&mut r, 0, 1, 1, 0x0800, None);
    resolve(&mut r, 0, 2, true, &env);
    poll(&mut r, 1);
    poll(&mut r, 2);
    poll(&mut r, 3); // 2 -> QueryRetry
    assert_eq!(r.info(&eid(2)).unwrap().state, EntryState::QueryRetry);
    resolve(&mut r, 3, 3, true, &env);
    r.update_snooped(
        t(3),
        &eid(4),
        Rloc16(0x0c00),
        Rloc16(0x0400),
        &env,
        &mut |_| {},
    );
    assert_eq!(r.info(&eid(4)).unwrap().state, EntryState::Snooped);
    assert!(!r.info(&eid(4)).unwrap().can_evict);
    assert_eq!(r.len(), 4);
    // New query: snooped is blocked, so the retry entry (2) goes first.
    let (res, _) = resolve(&mut r, 3, 5, true, &env);
    assert_eq!(res, Ok(Resolution::QueryPending));
    assert!(r.info(&eid(2)).is_none());
    // Next: snooped still blocked, no retry left; the pending queries cannot
    // be evicted until timeout; the cached entry is the victim.
    let (res, _) = resolve(&mut r, 3, 6, true, &env);
    assert_eq!(res, Ok(Resolution::QueryPending));
    assert!(r.info(&eid(1)).is_none());
    // Now everything left is protected: the snooped entry (blocking) and 3
    // queries (3, 5, 6). Nothing can be reclaimed.
    assert_eq!(resolve(&mut r, 3, 7, true, &env).0, Err(Error::NoBufs));
    // After the snoop block expires the snooped entry is the next victim.
    for s in 4..=6 {
        poll(&mut r, s);
    }
    // (the queries also timed out into retry state by now; the snooped entry
    // is still evicted first)
    let (res, _) = resolve(&mut r, 6, 7, true, &env);
    assert_eq!(res, Ok(Resolution::QueryPending));
    assert!(r.info(&eid(4)).is_none());
}

#[test]
fn evicting_a_pending_query_reports_failure() {
    let env = Env::FTD;
    let mut r = AddressResolver::<1>::new();
    resolve_one(&mut r, 1, &env);
    // The first query cannot be evicted before its timeout.
    let mut v = Vec::new();
    assert_eq!(
        r.resolve(t(0), &eid(2), true, &env, &mut |e| v.push(e)),
        Err(Error::NoBufs)
    );
    // After the timeout the entry is in retry and can be evicted.
    let mut v = Vec::new();
    for s in 1..=3 {
        r.poll(t(s), &mut |e| v.push(e));
    }
    assert_eq!(v, [ResolverEvent::ResolutionFailed { eid: eid(1) }]);
    let mut v = Vec::new();
    assert_eq!(
        r.resolve(t(3), &eid(2), true, &env, &mut |e| v.push(e)),
        Ok(Resolution::QueryPending)
    );
    assert_eq!(v, [ResolverEvent::SendQuery { eid: eid(2) }]);
    // clear() reports the outstanding query.
    let v = ev(|s| r.clear(&mut |e| s(e)));
    assert_eq!(v, [ResolverEvent::ResolutionFailed { eid: eid(2) }]);
    assert!(r.is_empty());
}

fn resolve_one(r: &mut AddressResolver<1>, e: u16, env: &Env) {
    r.resolve(t(0), &eid(e), true, env, &mut |_| {}).unwrap();
}

#[test]
fn snooping_rules() {
    let env = Env::FTD;
    let snoop = |r: &mut R, e: u16, rloc: u16, dest: u16, env: &Env| {
        r.update_snooped(t(0), &eid(e), Rloc16(rloc), Rloc16(dest), env, &mut |_| {});
    };
    let mut r = R::new();
    // MTDs do not snoop.
    snoop(
        &mut r,
        1,
        0x0800,
        0x0400,
        &Env {
            ftd: false,
            ..Env::FTD
        },
    );
    assert!(r.is_empty());
    // Source is us / our minimal child: nothing to learn.
    snoop(&mut r, 1, 0x0400, 0x0400, &env);
    snoop(&mut r, 1, 0x0401, 0x0400, &env);
    // Destination is neither us nor our minimal child.
    snoop(&mut r, 1, 0x0800, 0x0c00, &env);
    assert!(r.is_empty());
    // Destination is a minimal child of ours: learn it.
    snoop(&mut r, 1, 0x0800, 0x0401, &env);
    let i = r.info(&eid(1)).unwrap();
    assert_eq!(
        (i.state, i.timeout, i.can_evict, i.rloc16),
        (EntryState::Snooped, 3, false, Rloc16(0x0800))
    );
    // The number of eviction-blocking snooped entries is limited to max(1, N/16) = 1.
    snoop(&mut r, 2, 0x0800, 0x0400, &env);
    let i2 = r.info(&eid(2)).unwrap();
    assert_eq!((i2.timeout, i2.can_evict), (0, true));
    // Updating an existing snooped entry changes its RLOC16.
    snoop(&mut r, 1, 0x0c00, 0x0400, &env);
    assert_eq!(r.info(&eid(1)).unwrap().rloc16, Rloc16(0x0c00));
    // Block expires after 3 ticks.
    for s in 1..=3 {
        poll(&mut r, s);
    }
    assert!(r.info(&eid(1)).unwrap().can_evict);
    // Using a snooped entry promotes it to cached.
    let (res, _) = resolve(&mut r, 3, 1, true, &env);
    assert_eq!(res, Ok(Resolution::Resolved(Rloc16(0x0c00))));
    assert_eq!(r.info(&eid(1)).unwrap().state, EntryState::Cached);
    // A snooped datagram resolves an outstanding query.
    resolve(&mut r, 3, 9, true, &env);
    let v = ev(|s| {
        r.update_snooped(
            t(3),
            &eid(9),
            Rloc16(0x1000),
            Rloc16(0x0400),
            &env,
            &mut |e| s(e),
        )
    });
    assert_eq!(v, [ResolverEvent::Resolved { eid: eid(9) }]);
    assert_eq!(r.info(&eid(9)).unwrap().state, EntryState::Cached);
    // Snooped entries without a route and not fresh are discarded on use.
    snoop(&mut r, 3, 0x0800, 0x0400, &env);
    let (res, _) = resolve(
        &mut r,
        3,
        3,
        false,
        &Env {
            route: false,
            ..Env::FTD
        },
    );
    assert_eq!(res, Err(Error::NotFound));
    assert!(r.info(&eid(3)).is_none());
}

#[test]
fn notification_handling_and_duplicates() {
    let env = Env::FTD;
    let mut r = R::new();
    // Unknown target: ignored (no ACK).
    assert_eq!(
        notify(&mut r, 0, 1, 1, 0x0800, None).0,
        NotifyOutcome::Ignored
    );
    resolve(&mut r, 0, 1, true, &env);
    assert_eq!(
        notify(&mut r, 1, 1, 7, 0x0800, Some(50)).0,
        NotifyOutcome::Updated
    );
    // Same IID, larger last-transaction-time: older information, ignored.
    assert_eq!(
        notify(&mut r, 2, 1, 7, 0x0c00, Some(60)).0,
        NotifyOutcome::Ignored
    );
    assert_eq!(r.info(&eid(1)).unwrap().rloc16, Rloc16(0x0800));
    // Smaller time: newer, accepted (device moved).
    assert_eq!(
        notify(&mut r, 2, 1, 7, 0x0c00, Some(5)).0,
        NotifyOutcome::Updated
    );
    assert_eq!(r.info(&eid(1)).unwrap().rloc16, Rloc16(0x0c00));
    // Different IID: duplicate address -> Address Error, entry untouched.
    let (o, evs) = notify(&mut r, 3, 1, 9, 0x1000, Some(1));
    assert_eq!(o, NotifyOutcome::DuplicateAddress);
    assert_eq!(
        evs,
        [ResolverEvent::SendAddressError {
            target: eid(1),
            mesh_local_iid: Iid([9; 8])
        }]
    );
    assert_eq!(r.info(&eid(1)).unwrap().rloc16, Rloc16(0x0c00));
    // Entries without a valid last transaction time accept any notification.
    let mut s = Env::FTD;
    s.child = Some(0x0401);
    r.update_snooped(
        t(3),
        &eid(2),
        Rloc16(0x0800),
        Rloc16(0x0401),
        &s,
        &mut |_| {},
    );
    assert_eq!(
        notify(&mut r, 3, 2, 4, 0x0800, None).0,
        NotifyOutcome::Updated
    );
    // A notification for a retrying entry resolves it as well.
    resolve(&mut r, 3, 3, true, &env);
    for sec in 4..=6 {
        poll(&mut r, sec);
    }
    assert_eq!(r.info(&eid(3)).unwrap().state, EntryState::QueryRetry);
    let (o, evs) = notify(&mut r, 6, 3, 5, 0x0800, None);
    assert_eq!((o, evs.len()), (NotifyOutcome::Updated, 1));
    assert_eq!(r.info(&eid(3)).unwrap().state, EntryState::Cached);
}

#[test]
fn removal_helpers() {
    let env = Env::FTD;
    let mut r = AddressResolver::<8>::new();
    for (e, rloc) in [(1u16, 0x0800u16), (2, 0x0801), (3, 0x0c00), (4, 0x0c05)] {
        r.resolve(t(0), &eid(e), true, &env, &mut |_| {}).unwrap();
        r.handle_notify(
            t(0),
            &eid(e),
            Iid([e as u8; 8]),
            Rloc16(rloc),
            Some(1),
            &mut |_| {},
        );
    }
    r.resolve(t(0), &eid(9), true, &env, &mut |_| {}).unwrap();
    assert_eq!(r.len(), 5);
    r.remove_entries_for_rloc16(Rloc16(0x0801));
    assert!(r.info(&eid(2)).is_none());
    r.remove_entries_for_router_id(3); // 0x0c00 and 0x0c05
    assert!(r.info(&eid(3)).is_none() && r.info(&eid(4)).is_none());
    r.replace_entries_for_rloc16(Rloc16(0x0800), Rloc16(0x1000));
    assert_eq!(r.info(&eid(1)).unwrap().rloc16, Rloc16(0x1000));
    // Router-ID removal leaves in-flight queries alone.
    assert_eq!(r.info(&eid(9)).unwrap().state, EntryState::Query);
    // Removing the EID of a pending query reports the failure.
    let v = ev(|s| r.remove_entry_for_address(&eid(9), &mut |e| s(e)));
    assert_eq!(v, [ResolverEvent::ResolutionFailed { eid: eid(9) }]);
    let v = ev(|s| r.remove_entry_for_address(&eid(1), &mut |e| s(e)));
    assert!(v.is_empty() && r.is_empty());
    // abort_query frees only query entries.
    r.resolve(t(0), &eid(7), true, &env, &mut |_| {}).unwrap();
    r.abort_query(&eid(7));
    assert!(r.is_empty());
}

#[test]
fn restart_queries_resends_everything() {
    let env = Env::FTD;
    let mut r = R::new();
    resolve(&mut r, 0, 1, true, &env);
    for s in 1..=3 {
        poll(&mut r, s);
    }
    resolve(&mut r, 3, 2, true, &env);
    assert_eq!(r.info(&eid(1)).unwrap().state, EntryState::QueryRetry);
    let v = ev(|s| r.restart_queries(t(4), &mut |e| s(e)));
    assert_eq!(v.len(), 2);
    assert!(v.contains(&ResolverEvent::SendQuery { eid: eid(1) }));
    assert!(v.contains(&ResolverEvent::SendQuery { eid: eid(2) }));
    for e in [1, 2] {
        let i = r.info(&eid(e)).unwrap();
        assert_eq!(
            (i.state, i.timeout, i.retry_delay, i.can_evict),
            (EntryState::Query, 3, 15, false)
        );
    }
    // Nothing to do on an idle cache.
    assert!(ev(|s| AddressResolver::<2>::new().restart_queries(t(0), &mut |e| s(e))).is_empty());
}

#[test]
fn address_error_and_query_decisions() {
    let mut n = Netif::<4, 4>::new();
    n.add_unicast(UnicastAddress::manual(eid(1))).unwrap();
    let own = Iid([1; 8]);
    // Someone else claims our address with a different ML-EID IID: conflict.
    assert!(address_error_conflict(&n, &eid(1), &Iid([2; 8]), &own));
    // Same IID (our own message echoed back) or not our address: no conflict.
    assert!(!address_error_conflict(&n, &eid(1), &own, &own));
    assert!(!address_error_conflict(&n, &eid(2), &Iid([2; 8]), &own));

    struct Kids;
    impl ChildLookup for Kids {
        fn child_with_address(&self, t: &Ipv6Addr) -> Option<(Iid, u32)> {
            (*t == eid(5)).then_some((Iid([5; 8]), 42))
        }
    }
    assert_eq!(
        address_query_response(&n, &own, &Kids, &eid(1)),
        Some(QueryResponse {
            mesh_local_iid: own,
            last_transaction_time: None
        })
    );
    assert_eq!(
        address_query_response(&n, &own, &Kids, &eid(5)),
        Some(QueryResponse {
            mesh_local_iid: Iid([5; 8]),
            last_transaction_time: Some(42)
        })
    );
    assert_eq!(address_query_response(&n, &own, &Kids, &eid(6)), None);
}

#[test]
fn ticks_run_only_while_needed() {
    let env = Env::FTD;
    let mut r = R::new();
    assert_eq!(r.next_deadline(), None);
    resolve(&mut r, 10, 1, true, &env);
    assert_eq!(r.next_deadline(), Some(t(11)));
    // Polling late catches up on all missed ticks.
    let v = poll(&mut r, 14);
    assert_eq!(v, [ResolverEvent::ResolutionFailed { eid: eid(1) }]);
    assert_eq!(r.info(&eid(1)).unwrap().state, EntryState::QueryRetry);
    r.remove_entry_for_address(&eid(1), &mut |_| {});
    poll(&mut r, 15);
    assert_eq!(r.next_deadline(), None);
    // Freshness ticks stop once exhausted.
    resolve(&mut r, 20, 2, true, &env);
    notify(&mut r, 20, 2, 1, 0x0800, None);
    for s in 21..=30 {
        poll(&mut r, s);
    }
    assert_eq!(r.next_deadline(), None);
}
