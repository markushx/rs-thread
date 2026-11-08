use super::*;

fn ext(n: u8) -> ExtAddress {
    ExtAddress([0, 0, 0, 0, 0, 0, 0, n])
}

fn t(s: u64) -> Instant {
    Instant::from_secs(s)
}

fn rx(ks: u32, fc: u32) -> RxSecurity {
    RxSecurity {
        key_sequence: ks,
        frame_counter: fc,
    }
}

fn ml_prefix() -> Prefix64 {
    Prefix64([0xfd, 0, 0x0d, 0xb8, 0, 0, 0, 0])
}

fn addr(n: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n)
}

#[test]
fn state_predicates_and_filters() {
    use NeighborState::*;
    let all = [
        Invalid,
        Restored,
        ParentRequest,
        ParentResponse,
        ChildIdRequest,
        LinkRequest,
        ChildUpdateRequest,
        Valid,
    ];
    let count = |f: StateFilter| all.iter().filter(|s| f.matches(**s)).count();
    assert_eq!(count(StateFilter::Valid), 1);
    assert_eq!(count(StateFilter::ValidOrRestoring), 3);
    assert_eq!(count(StateFilter::ChildIdRequest), 1);
    // Valid, LinkRequest, ChildIdRequest, Restored, ChildUpdateRequest.
    assert_eq!(count(StateFilter::ValidOrAttaching), 5);
    assert_eq!(count(StateFilter::Invalid), 1);
    assert_eq!(count(StateFilter::AnyExceptInvalid), 7);
    assert_eq!(count(StateFilter::AnyExceptValidOrRestoring), 5);
    assert_eq!(count(StateFilter::Any), 8);
    assert!(Restored.is_restoring() && ChildUpdateRequest.is_restoring() && !Valid.is_restoring());
}

#[test]
fn neighbor_state_and_connection_time() {
    let mut n = Neighbor::new(ext(1), t(10));
    assert_eq!(n.rloc16, Rloc16::INVALID);
    assert!(
        !n.is_thread_version_1p1(),
        "invalid neighbors have no version"
    );
    assert_eq!(n.connection_time_secs(t(100)), 0);
    n.set_state(NeighborState::Valid, t(20));
    assert!(n.is_valid());
    assert_eq!(n.connection_time_secs(t(50)), 30);
    assert!(n.is_thread_version_1p1());
    n.version = 5;
    assert!(n.is_thread_version_1p2_or_higher() && !n.is_thread_version_1p1());
    // Re-setting Valid keeps the original start.
    n.set_state(NeighborState::Valid, t(40));
    assert_eq!(n.connection_time_secs(t(50)), 30);
    n.set_state(NeighborState::Invalid, t(60));
    assert_eq!(n.connection_time_secs(t(70)), 0);
    n.clear(t(70));
    assert_eq!(n.ext_address, ext(1));
}

#[test]
fn mle_replay_same_key_sequence() {
    let mut link = LinkFrameCounters::with(3, 100);
    let mut r = MleReplay::with(50);
    // Below the Link-Accept counter: dropped.
    assert_eq!(r.check_and_update(&mut link, &rx(3, 49)), Err(Error::Drop));
    assert_eq!(r.check_and_update(&mut link, &rx(3, 50)), Ok(false));
    assert_eq!(r.frame_counter(), Some(51));
    // Duplicate and older.
    assert_eq!(r.check_and_update(&mut link, &rx(3, 50)), Err(Error::Drop));
    assert_eq!(r.check_and_update(&mut link, &rx(3, 10)), Err(Error::Drop));
    // Gaps are fine.
    assert_eq!(r.check_and_update(&mut link, &rx(3, 1000)), Ok(false));
    assert_eq!(r.frame_counter(), Some(1001));
    // The link counters are untouched.
    assert_eq!(link.key_sequence(), 3);
    assert_eq!(link.frame_counter(), Some(100));
}

#[test]
fn mle_replay_key_sequence_changes() {
    let mut link = LinkFrameCounters::with(3, 100);
    let mut r = MleReplay::with(500);
    // Older key sequence: dropped regardless of counter.
    assert_eq!(
        r.check_and_update(&mut link, &rx(2, u32::MAX)),
        Err(Error::Drop)
    );
    // Newer key sequence: any counter, link counters reset, MLE next = fc+1.
    assert_eq!(r.check_and_update(&mut link, &rx(4, 0)), Ok(true));
    assert_eq!(link, LinkFrameCounters::with(4, 0));
    assert_eq!(r.frame_counter(), Some(1));
    // Check alone does not change anything.
    let before = (r, link);
    assert!(r.check(&link, &rx(5, 0)).is_ok());
    assert_eq!((r, link), before);
}

#[test]
fn mle_replay_max_counter_does_not_wrap() {
    let mut link = LinkFrameCounters::new();
    let mut r = MleReplay::new();
    assert_eq!(r.check_and_update(&mut link, &rx(0, u32::MAX)), Ok(false));
    assert_eq!(r.frame_counter(), None);
    assert_eq!(r.check_and_update(&mut link, &rx(0, 0)), Err(Error::Drop));
    // A newer key sequence recovers.
    assert_eq!(r.check_and_update(&mut link, &rx(1, 0)), Ok(true));
    assert_eq!(r.frame_counter(), Some(1));
}

#[test]
fn child_addresses() {
    let mut c = Child::new(ext(1), t(0));
    assert!(c.ml_eid_iid().is_none());
    assert!(c.add_address(addr(1)).is_ok());
    assert_eq!(c.add_address(addr(1)), Err(Error::Already));
    for i in 2..=5 {
        c.add_address(addr(i)).unwrap();
    }
    assert_eq!(c.add_address(addr(6)), Err(Error::NoBufs));
    assert_eq!(c.addresses().len(), CHILD_MAX_ADDRESSES);
    assert_eq!(c.remove_address(&addr(3)), Ok(()));
    assert_eq!(c.remove_address(&addr(3)), Err(Error::NotFound));
    assert!(!c.has_address(&ml_prefix(), &addr(3)));
    assert!(c.has_address(&ml_prefix(), &addr(4)));

    let iid = Iid([1, 2, 3, 4, 5, 6, 7, 8]);
    c.set_ml_eid_iid(Some(iid));
    let eid = ml_prefix().with_iid(&iid);
    assert!(c.has_address(&ml_prefix(), &eid));
    assert_eq!(c.ip6_addresses(&ml_prefix()).next(), Some(eid));
    assert_eq!(c.ip6_addresses(&ml_prefix()).count(), 5);
    c.clear_addresses();
    assert_eq!(c.ip6_addresses(&ml_prefix()).count(), 1);
}

#[test]
fn child_request_tlvs_truncate() {
    let mut c = Child::new(ext(1), t(0));
    c.set_request_tlvs(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(c.request_tlvs(), &[1, 2, 3, 4, 5, 6]);
    c.set_request_tlvs(&[9]);
    assert_eq!(c.request_tlvs(), &[9]);
}

#[test]
fn child_timeout() {
    let mut c = Child::new(ext(1), t(100));
    c.timeout_secs = 240;
    assert!(!c.is_timed_out(t(339)));
    assert!(c.is_timed_out(t(340)));
    c.neighbor.heard(t(300));
    assert!(!c.is_timed_out(t(500)));
    assert!(c.is_timed_out(t(540)));
}

#[test]
fn child_info_roundtrip() {
    let mut c = Child::new(ext(7), t(0));
    c.neighbor.rloc16 = Rloc16(0x0403);
    c.neighbor.mode = DeviceMode::new(false, false, true);
    c.neighbor.version = 5;
    c.timeout_secs = 3600;
    let info = c.to_child_info();
    assert_eq!(info.mode, 0x05);
    let mut buf = [0u8; ChildInfo::ENCODED_LEN];
    info.encode(&mut buf).unwrap();
    let r = Child::from_child_info(&ChildInfo::decode(&buf).unwrap(), t(9));
    assert_eq!(r.neighbor.state, NeighborState::Restored);
    assert_eq!(r.neighbor.rloc16, Rloc16(0x0403));
    assert_eq!(r.neighbor.version, 5);
    assert_eq!(r.timeout_secs, 3600);
    assert!(r.neighbor.mode.full_network_data() && r.is_sleepy());
    assert_eq!(r.neighbor.last_heard, t(9));
}

#[test]
fn child_table_lookups() {
    let mut tab = ChildTable::<4>::new();
    for i in 1..=3u8 {
        let c = tab.add(ext(i), t(0)).unwrap();
        c.neighbor.rloc16 = Rloc16(0x0400 | u16::from(i));
    }
    assert_eq!(tab.add(ext(2), t(0)).unwrap_err(), Error::Already);
    // Invalid children are not found by Valid filters.
    assert!(tab.find_by_ext(&ext(2), StateFilter::Valid).is_none());
    assert!(tab.find_by_ext(&ext(2), StateFilter::Any).is_some());
    tab.find_by_ext_mut(&ext(2), StateFilter::Any)
        .unwrap()
        .neighbor
        .set_state(NeighborState::Valid, t(1));
    tab.find_by_rloc_mut(Rloc16(0x0403), StateFilter::Any)
        .unwrap()
        .neighbor
        .set_state(NeighborState::ChildIdRequest, t(1));
    assert_eq!(tab.count(StateFilter::Valid), 1);
    assert_eq!(tab.count(StateFilter::ValidOrAttaching), 2);
    assert_eq!(tab.count(StateFilter::Invalid), 1);
    assert_eq!(tab.index_by_ext(&ext(2), StateFilter::Valid), Some(1));
    assert_eq!(
        tab.find_by_rloc(Rloc16(0x0403), StateFilter::ChildIdRequest)
            .unwrap()
            .neighbor
            .ext_address,
        ext(3)
    );
    assert!(
        tab.find_by_rloc(Rloc16(0x0403), StateFilter::Valid)
            .is_none()
    );
    assert!(tab.has_children(StateFilter::Valid));

    // Address lookup.
    let c = tab.find_by_ext_mut(&ext(2), StateFilter::Valid).unwrap();
    c.add_address(addr(0x42)).unwrap();
    c.set_ml_eid_iid(Some(Iid([9; 8])));
    let eid = ml_prefix().with_iid(&Iid([9; 8]));
    for a in [addr(0x42), eid] {
        assert_eq!(
            tab.find_by_address(&ml_prefix(), &a, StateFilter::Valid)
                .unwrap()
                .neighbor
                .ext_address,
            ext(2)
        );
    }
    assert!(
        tab.find_by_address(&ml_prefix(), &addr(1), StateFilter::Any)
            .is_none()
    );

    // Sleepy detection: default mode is not rx-on-when-idle.
    assert!(tab.has_sleepy_children());
    tab.find_by_ext_mut(&ext(2), StateFilter::Valid)
        .unwrap()
        .neighbor
        .mode = DeviceMode::new(true, false, true);
    assert!(!tab.has_sleepy_children());
}

#[test]
fn child_table_capacity_remove_and_stable_slots() {
    let mut tab = ChildTable::<2>::new();
    tab.add(ext(1), t(0)).unwrap();
    tab.add(ext(2), t(0)).unwrap();
    assert_eq!(tab.add(ext(3), t(0)).unwrap_err(), Error::NoBufs);
    assert_eq!(tab.remove(0).unwrap().neighbor.ext_address, ext(1));
    assert!(tab.remove(0).is_none());
    assert!(tab.remove(9).is_none());
    // Slot 1 keeps its index; the freed slot 0 is reused.
    assert_eq!(tab.index_by_ext(&ext(2), StateFilter::Any), Some(1));
    tab.add(ext(3), t(0)).unwrap();
    assert_eq!(tab.index_by_ext(&ext(3), StateFilter::Any), Some(0));
    assert_eq!(
        tab.insert(Child::new(ext(3), t(0))).unwrap_err(),
        Error::Already
    );
    tab.clear();
    assert_eq!(tab.count(StateFilter::Any), 0);
}

#[test]
fn child_table_expire() {
    let mut tab = ChildTable::<4>::new();
    for (i, timeout) in [(1u8, 100u32), (2, 300), (3, 100)] {
        let c = tab.add(ext(i), t(0)).unwrap();
        c.timeout_secs = timeout;
        // Child 3 never became valid: not subject to expiry here.
        if i != 3 {
            c.neighbor.set_state(NeighborState::Valid, t(0));
        }
    }
    let mut removed = heapless::Vec::<usize, 4>::new();
    assert_eq!(tab.expire(t(150), |i, _| removed.push(i).unwrap()), 1);
    assert_eq!(removed.as_slice(), &[0]);
    assert_eq!(tab.expire(t(150), |_, _| panic!()), 0);
    assert_eq!(tab.count(StateFilter::Any), 2);
    assert_eq!(tab.expire(t(400), |_, _| {}), 1);
}

#[test]
fn router_table() {
    let mut rt = RouterTable::<3>::new();
    assert_eq!(rt.add(63, ext(1), t(0)).unwrap_err(), Error::InvalidArgs);
    let r = rt.add(5, ext(5), t(0)).unwrap();
    assert_eq!(r.rloc16(), Rloc16(0x1400));
    assert_eq!(r.cost, 16);
    assert_eq!(r.next_hop, None);
    rt.add(9, ext(9), t(0)).unwrap();
    assert_eq!(rt.add(5, ext(1), t(0)).unwrap_err(), Error::Already);
    rt.add(62, ext(62), t(0)).unwrap();
    assert_eq!(rt.add(1, ext(1), t(0)).unwrap_err(), Error::NoBufs);

    rt.find_by_id_mut(9)
        .unwrap()
        .neighbor
        .set_state(NeighborState::Valid, t(1));
    assert_eq!(rt.count(StateFilter::Valid), 1);
    assert_eq!(rt.count(StateFilter::Any), 3);
    assert_eq!(
        rt.find_by_ext(&ext(9), StateFilter::Valid)
            .unwrap()
            .router_id,
        9
    );
    assert!(rt.find_by_ext(&ext(5), StateFilter::Valid).is_none());
    // RLOC16 lookup ignores the child ID bits.
    assert_eq!(
        rt.find_by_rloc(Rloc16(0x2401), StateFilter::Valid)
            .unwrap()
            .router_id,
        9
    );
    assert_eq!(rt.remove(9).unwrap().router_id, 9);
    assert!(rt.remove(9).is_none());
    assert!(rt.find_by_id(9).is_none());
    rt.clear();
    assert_eq!(rt.count(StateFilter::Any), 0);
}
