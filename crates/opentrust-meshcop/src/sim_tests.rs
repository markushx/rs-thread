//! Multi-node scenarios: dataset distribution through MLE, MGMT_*_SET at
//! the leader, Pending Dataset delay timer, commissioner session.

use opentrust_coap::uri::Uri;
use opentrust_core::bytes::Writer;
use opentrust_core::time::Duration;
use opentrust_core::types::{ExtPanId, NetworkKey, NetworkName, Pskc};
use opentrust_mesh::netdata::NetworkDataView;
use opentrust_mle::Role;
use opentrust_mle::test_support::MLP;

use crate::dataset::{Dataset, DatasetType};
use crate::leader as commissioner;
use crate::mgmt::MgmtResult;
use crate::net_sim::Net;
use crate::steering::SteeringData;
use crate::timestamp::Timestamp;
use crate::tlv::{PAGE0_CHANNELS, SecurityPolicy, State, Tlvs, WriterExt, ty};

pub(crate) fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn ts(s: u64) -> Timestamp {
    Timestamp {
        seconds: s,
        ticks: 0,
        authoritative: false,
    }
}

/// A complete Active Dataset for the simulator network (mesh-local prefix
/// and network key of the MLE test environment).
pub(crate) fn dataset(seconds: u64, channel: u8, pan: u16, key: u8, name: &str) -> Dataset {
    let mut d = Dataset::new();
    d.set_timestamp(DatasetType::Active, &ts(seconds)).unwrap();
    d.set_channel(channel).unwrap();
    d.set_channel_mask(PAGE0_CHANNELS).unwrap();
    d.set_ext_pan_id(&ExtPanId([0xde, 0xad, 0, 0xbe, 0xef, 0, 0xca, 0xfe]))
        .unwrap();
    d.set_mesh_local_prefix(&MLP).unwrap();
    d.set_network_key(&NetworkKey([key; 16])).unwrap();
    d.set_network_name(&NetworkName::new(name).unwrap())
        .unwrap();
    d.set_pan_id(pan).unwrap();
    d.set_pskc(&Pskc([7; 16])).unwrap();
    d.set_security_policy(&SecurityPolicy::default()).unwrap();
    d
}

/// Leader (node 0), a router (node 1) and a child (node 2) in one
/// partition, all hearing each other.
pub(crate) fn form(initial: &Dataset) -> Net {
    let mut net = Net::ftds(3);
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        net.connect(a, b);
    }
    net.start_with(0, initial);
    assert!(net.run_until(secs(60), |n| n.role(0) == Role::Leader));
    net.sim.start(1);
    assert!(net.run_until(secs(30), |n| n.role(1) == Role::Child));
    net.sim.upgrade(0, 1);
    net.sim.start(2);
    assert!(net.run_until(secs(30), |n| n.role(2) == Role::Child));
    net.run(secs(5));
    net
}

fn read(net: &Net, i: usize, t: DatasetType) -> Option<Dataset> {
    let now = net.now();
    net.shared(i).ds.read(t, now)
}

pub(crate) fn payload(f: impl FnOnce(&mut Writer<'_>)) -> std::vec::Vec<u8> {
    let mut b = [0u8; 300];
    let mut w = Writer::new(&mut b);
    f(&mut w);
    w.written().to_vec()
}

pub(crate) fn leader_aloc() -> core::net::Ipv6Addr {
    MLP.aloc(0xfc00).unwrap()
}

#[test]
fn leader_dataset_reaches_children_and_routers() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let net = form(&d);
    for i in 0..3 {
        let got = read(&net, i, DatasetType::Active).unwrap_or_else(|| panic!("node {i}"));
        assert!(d.is_subset_of(&got) && got.is_subset_of(&d), "node {i}");
        assert_eq!(net.shared(i).ds.timestamp(DatasetType::Active), Some(ts(1)));
        let s = net.shared(i);
        assert_eq!(s.env.cur.channel, 15, "node {i}");
        assert_eq!(s.env.cur.pan_id, 0x1234);
    }
    // No Pending Dataset anywhere.
    for i in 0..3 {
        assert!(!net.shared(i).ds.is_saved(DatasetType::Pending));
    }
}

#[test]
fn mgmt_active_get_filters_tlvs_and_hides_key() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    // Everything but the key policy: the default policy allows the key.
    let p = payload(|w| w.get_list(&[ty::NETWORK_NAME, ty::CHANNEL]).unwrap());
    let a = net.rloc(0);
    net.post(2, a, Uri::ActiveGet, &p);
    let (_, body) = net.nodes[2].responses.pop().unwrap();
    let t = Tlvs(&body);
    assert_eq!(t.network_name().unwrap().as_str(), "OpenTrust");
    assert_eq!(t.channel().unwrap().channel, 15);
    assert!(!t.contains(ty::PAN_ID));

    // Without a Get TLV: everything.
    let a = net.rloc(1);
    net.post(2, a, Uri::ActiveGet, &[]);
    let (_, body) = net.nodes[2].responses.pop().unwrap();
    let all = Dataset::from_tlvs(&body).unwrap();
    assert!(all.contains_all_required_for(DatasetType::Active));

    // A policy that does not allow obtaining the key hides it.
    let mut d2 = dataset(2, 15, 0x1234, 0x42, "OpenTrust");
    let sp = SecurityPolicy {
        obtain_network_key: false,
        ..Default::default()
    };
    d2.set_security_policy(&sp).unwrap();
    net.post(1, leader_aloc(), Uri::ActiveSet, d2.as_bytes());
    assert_eq!(state_of(&mut net, 1), State::Accept);
    net.run(secs(10));
    let a = net.rloc(1);
    net.post(2, a, Uri::ActiveGet, &[]);
    let (_, body) = net.nodes[2].responses.pop().unwrap();
    let t = Tlvs(&body);
    assert!(!t.contains(ty::NETWORK_KEY));
    assert!(t.contains(ty::PSKC));
}

pub(crate) fn state_of(net: &mut Net, node: usize) -> State {
    let (_, body) = net.nodes[node].responses.pop().expect("no response");
    Tlvs(&body).state().unwrap()
}

#[test]
fn mgmt_active_set_newer_timestamp_propagates() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);

    // A device (node 2) sets a complete dataset with a newer timestamp.
    let d2 = dataset(2, 15, 0x1234, 0x42, "Renamed");
    net.post(2, leader_aloc(), Uri::ActiveSet, d2.as_bytes());
    assert_eq!(state_of(&mut net, 2), State::Accept);
    net.run(secs(60));
    for i in 0..3 {
        assert_eq!(
            net.shared(i).ds.timestamp(DatasetType::Active),
            Some(ts(2)),
            "node {i}"
        );
        let got = read(&net, i, DatasetType::Active).unwrap();
        assert_eq!(got.tlvs().network_name().unwrap().as_str(), "Renamed");
    }
    // Network Data version was incremented for the dataset change.
    assert!(net.nodes[0].nd.version() > 0);

    // Not newer: rejected; an incomplete dataset too.
    let old = dataset(2, 15, 0x1234, 0x42, "Again");
    net.post(2, leader_aloc(), Uri::ActiveSet, old.as_bytes());
    assert_eq!(state_of(&mut net, 2), State::Reject);
    let mut partial = Dataset::new();
    partial.set_timestamp(DatasetType::Active, &ts(9)).unwrap();
    partial
        .set_network_name(&NetworkName::new("x").unwrap())
        .unwrap();
    // Valid TLVs but without commissioner session: stored as given only if
    // it is a full dataset in OT? (OT accepts it: no completeness check
    // for a non-commissioner MGMT_ACTIVE_SET.)
    net.post(2, leader_aloc(), Uri::ActiveSet, partial.as_bytes());
    assert_eq!(state_of(&mut net, 2), State::Accept);
    // A request that is not a valid dataset is rejected.
    net.post(2, leader_aloc(), Uri::ActiveSet, &[ty::PAN_ID, 1, 0]);
    assert_eq!(state_of(&mut net, 2), State::Reject);
    // Nothing without an Active Timestamp.
    let nots = payload(|w| w.pan_id(5).unwrap());
    net.post(2, leader_aloc(), Uri::ActiveSet, &nots);
    assert_eq!(state_of(&mut net, 2), State::Reject);
}

#[test]
fn device_with_newer_local_dataset_syncs_with_leader() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    // The router's application sets a newer dataset locally; it sends
    // MGMT_ACTIVE_SET to the leader by itself.
    let d2 = dataset(5, 15, 0x1234, 0x42, "FromRouter");
    {
        let now = net.now();
        let s = &mut *net.shared(1);
        s.ds.save_local(&mut s.env, now, DatasetType::Active, &d2)
            .unwrap();
    }
    net.run(secs(30));
    assert_eq!(net.nodes[1].set_results, [MgmtResult::Accepted]);
    for i in 0..3 {
        assert_eq!(
            net.shared(i).ds.timestamp(DatasetType::Active),
            Some(ts(5)),
            "node {i}"
        );
    }
    assert_eq!(
        read(&net, 2, DatasetType::Active)
            .unwrap()
            .tlvs()
            .network_name()
            .unwrap()
            .as_str(),
        "FromRouter"
    );
}

#[test]
fn pending_dataset_switches_channel_pan_id_and_key() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);

    // Pending Dataset with new channel, PAN ID and network key.
    let mut p = dataset(2, 20, 0xbeef, 0x77, "OpenTrust");
    p.set_timestamp(DatasetType::Pending, &ts(2)).unwrap();
    p.set_delay_timer(10_000).unwrap();
    net.post(2, leader_aloc(), Uri::PendingSet, p.as_bytes());
    assert_eq!(state_of(&mut net, 2), State::Accept);
    net.run(secs(20));

    // The delay is raised to the default because the key changes; every
    // node has the Pending Dataset with the remaining delay.
    for i in 0..3 {
        assert_eq!(
            net.shared(i).ds.timestamp(DatasetType::Pending),
            Some(ts(2)),
            "node {i}"
        );
        let rem = net.shared(i).ds.remaining_delay_ms(net.now()).unwrap();
        assert!(rem > 250_000 && rem < 300_000, "node {i}: {rem}");
        assert_eq!(net.shared(i).env.cur.channel, 15);
    }

    // Before the delay elapses nothing changes; after it, everything does.
    net.run(secs(270));
    for i in 0..3 {
        assert_eq!(net.shared(i).env.cur.channel, 15, "node {i}");
    }
    net.run(secs(40));
    for i in 0..3 {
        let s = net.shared(i);
        assert_eq!(s.env.cur.channel, 20, "node {i}");
        assert_eq!(s.env.cur.pan_id, 0xbeef);
        assert_eq!(s.env.cur.network_key, NetworkKey([0x77; 16]));
        assert_eq!(s.ds.timestamp(DatasetType::Active), Some(ts(2)));
        assert!(!s.ds.is_saved(DatasetType::Pending), "node {i}");
        drop(s);
        assert_eq!(
            net.sim.nodes[i].env.keys.network_key(),
            &NetworkKey([0x77; 16])
        );
    }
    // The nodes still form one partition.
    assert_eq!(net.role(0), Role::Leader);
    assert_eq!(net.role(1), Role::Router);
    assert_eq!(net.role(2), Role::Child);
}

#[test]
fn active_set_affecting_connectivity_becomes_pending() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    // A new channel in MGMT_ACTIVE_SET is delayed with the Pending Dataset
    // (minimal delay).
    let d2 = dataset(2, 18, 0x1234, 0x42, "OpenTrust");
    net.post(2, leader_aloc(), Uri::ActiveSet, d2.as_bytes());
    assert_eq!(state_of(&mut net, 2), State::Accept);
    net.run(secs(5));
    assert!(net.shared(0).ds.is_saved(DatasetType::Pending));
    assert_eq!(net.shared(0).env.cur.channel, 15);
    net.run(secs(40));
    for i in 0..3 {
        assert_eq!(net.shared(i).env.cur.channel, 18, "node {i}");
        assert_eq!(net.shared(i).ds.timestamp(DatasetType::Active), Some(ts(2)));
    }
}

pub(crate) fn petition(net: &mut Net, from: usize, id: &str) {
    let p = payload(|w| w.commissioner_id(id).unwrap());
    net.post(from, leader_aloc(), Uri::LeaderPetition, &p);
}

pub(crate) fn keep(net: &mut Net, from: usize, session: u16) {
    let ka = payload(|w| {
        w.state(State::Accept).unwrap();
        w.commissioner_session_id(session).unwrap();
    });
    net.post(from, leader_aloc(), Uri::LeaderKeepAlive, &ka);
    assert_eq!(state_of(net, from), State::Accept);
}

fn commissioning(net: &Net, i: usize) -> Option<std::vec::Vec<u8>> {
    if net.role(i) == Role::Leader {
        return net.nodes[i].nd.commissioning_data().map(<[u8]>::to_vec);
    }
    NetworkDataView(&net.sim.nodes[i].env.nd)
        .commissioning_data()
        .map(<[u8]>::to_vec)
}

#[test]
fn commissioner_petition_keep_alive_and_timeout() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    assert!(commissioner::session_id(&net.nodes[0].nd).is_none());

    // Petition from node 1.
    petition(&mut net, 1, "OpenThread Commissioner");
    let (_, body) = net.nodes[1].responses.pop().unwrap();
    let t = Tlvs(&body);
    assert_eq!(t.state().unwrap(), State::Accept);
    assert_eq!(t.commissioner_id().unwrap(), "OpenThread Commissioner");
    let session = t.commissioner_session_id().unwrap();
    assert_eq!(session, commissioner::session_id(&net.nodes[0].nd).unwrap());
    assert_eq!(
        commissioner::border_agent_locator(&net.nodes[0].nd),
        Some(net.mle(1).rloc16().0)
    );
    let sd = commissioner::steering_data(&net.nodes[0].nd).unwrap();
    assert_eq!(sd.as_bytes(), &[0]);

    // The Commissioning Data reaches the other nodes through MLE.
    net.run(secs(30));
    let cd0 = commissioning(&net, 0).unwrap();
    for i in 1..3 {
        assert_eq!(
            commissioning(&net, i).as_deref(),
            Some(&cd0[..]),
            "node {i}"
        );
    }

    // Another commissioner is refused, with the active ID in the answer.
    petition(&mut net, 2, "Other");
    let (_, body) = net.nodes[2].responses.pop().unwrap();
    let t = Tlvs(&body);
    assert_eq!(t.state().unwrap(), State::Reject);
    assert_eq!(t.commissioner_id().unwrap(), "OpenThread Commissioner");
    assert!(!t.contains(ty::COMMISSIONER_SESSION_ID));

    // Keep-alive restarts the timeout.
    net.run(secs(15));
    let ka = payload(|w| {
        w.state(State::Accept).unwrap();
        w.commissioner_session_id(session).unwrap();
    });
    net.post(1, leader_aloc(), Uri::LeaderKeepAlive, &ka);
    assert_eq!(state_of(&mut net, 1), State::Accept);
    net.run(secs(40));
    assert_eq!(commissioner::session_id(&net.nodes[0].nd), Some(session));
    assert!(commissioner::border_agent_locator(&net.nodes[0].nd).is_some());

    // A keep-alive with a wrong session ID is rejected.
    let bad = payload(|w| {
        w.state(State::Accept).unwrap();
        w.commissioner_session_id(session.wrapping_add(7)).unwrap();
    });
    net.post(1, leader_aloc(), Uri::LeaderKeepAlive, &bad);
    assert_eq!(state_of(&mut net, 1), State::Reject);

    // A keep-alive from another node moves the Border Agent Locator.
    net.post(2, leader_aloc(), Uri::LeaderKeepAlive, &ka);
    assert_eq!(state_of(&mut net, 2), State::Accept);
    assert_eq!(
        commissioner::border_agent_locator(&net.nodes[0].nd),
        Some(net.mle(2).rloc16().0)
    );

    // No keep-alive for 50 s: the commissioner is resigned, the data keeps
    // a bare, incremented session ID.
    net.run(secs(55));
    assert!(commissioner::border_agent_locator(&net.nodes[0].nd).is_none());
    assert_eq!(
        commissioner::session_id(&net.nodes[0].nd),
        Some(session.wrapping_add(1))
    );
    net.run(secs(30));
    for i in 1..3 {
        assert_eq!(commissioning(&net, i), commissioning(&net, 0), "node {i}");
    }

    // Keep-alive after the timeout: rejected. A new petition is accepted
    // with a new session ID.
    net.post(1, leader_aloc(), Uri::LeaderKeepAlive, &ka);
    assert_eq!(state_of(&mut net, 1), State::Reject);
    petition(&mut net, 2, "Other");
    let (_, body) = net.nodes[2].responses.pop().unwrap();
    let t = Tlvs(&body);
    assert_eq!(t.state().unwrap(), State::Accept);
    assert_eq!(
        t.commissioner_session_id().unwrap(),
        session.wrapping_add(2)
    );

    // Keep-alive with state reject resigns the commissioner.
    let off = payload(|w| {
        w.state(State::Reject).unwrap();
        w.commissioner_session_id(session.wrapping_add(2)).unwrap();
    });
    net.post(2, leader_aloc(), Uri::LeaderKeepAlive, &off);
    assert_eq!(state_of(&mut net, 2), State::Reject);
    assert!(commissioner::border_agent_locator(&net.nodes[0].nd).is_none());
}

#[test]
fn petition_from_non_rloc_or_without_id_is_rejected() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    // No Commissioner ID: Reject (state only).
    net.post(1, leader_aloc(), Uri::LeaderPetition, &[]);
    let (_, body) = net.nodes[1].responses.pop().unwrap();
    assert_eq!(Tlvs(&body).state().unwrap(), State::Reject);
    assert!(commissioner::session_id(&net.nodes[0].nd).is_none());
}

#[test]
fn commissioner_set_and_get_steering_data() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    petition(&mut net, 1, "comm");
    let (_, body) = net.nodes[1].responses.pop().unwrap();
    let session = Tlvs(&body).commissioner_session_id().unwrap();

    // COMM_SET with steering data and joiner UDP port.
    let mut sd = SteeringData::new(16);
    sd.add_joiner_id(&opentrust_core::types::ExtAddress([2, 1, 2, 3, 4, 5, 6, 7]))
        .unwrap();
    let set = payload(|w| {
        w.commissioner_session_id(session).unwrap();
        w.steering_data(&sd).unwrap();
        w.joiner_udp_port(1000).unwrap();
    });
    net.post(1, leader_aloc(), Uri::CommissionerSet, &set);
    assert_eq!(state_of(&mut net, 1), State::Accept);
    assert_eq!(commissioner::steering_data(&net.nodes[0].nd), Some(sd));
    assert_eq!(commissioner::joiner_udp_port(&net.nodes[0].nd), Some(1000));
    // The Border Agent Locator was kept.
    assert_eq!(
        commissioner::border_agent_locator(&net.nodes[0].nd),
        Some(net.mle(1).rloc16().0)
    );
    net.run(secs(30));
    assert_eq!(commissioning(&net, 2), commissioning(&net, 0));

    // Wrong session ID, Border Agent Locator in the request, no session ID.
    let bad = payload(|w| {
        w.commissioner_session_id(session.wrapping_add(1)).unwrap();
        w.steering_data(&SteeringData::new(1)).unwrap();
    });
    net.post(1, leader_aloc(), Uri::CommissionerSet, &bad);
    assert_eq!(state_of(&mut net, 1), State::Reject);
    let with_ba = payload(|w| {
        w.commissioner_session_id(session).unwrap();
        w.border_agent_locator(0x1234).unwrap();
    });
    net.post(1, leader_aloc(), Uri::CommissionerSet, &with_ba);
    assert_eq!(state_of(&mut net, 1), State::Reject);
    let nosession = payload(|w| w.steering_data(&SteeringData::new(1)).unwrap());
    net.post(1, leader_aloc(), Uri::CommissionerSet, &nosession);
    assert_eq!(state_of(&mut net, 1), State::Reject);

    // COMM_GET: selected and all sub-TLVs.
    let get = payload(|w| {
        w.get_list(&[ty::STEERING_DATA, ty::JOINER_UDP_PORT, ty::PAN_ID])
            .unwrap()
    });
    net.post(2, leader_aloc(), Uri::CommissionerGet, &get);
    let (_, body) = net.nodes[2].responses.pop().unwrap();
    let t = Tlvs(&body);
    assert_eq!(t.steering_data().unwrap(), sd);
    assert_eq!(t.joiner_udp_port().unwrap(), 1000);
    assert!(!t.contains(ty::PAN_ID) && !t.contains(ty::COMMISSIONER_SESSION_ID));
    net.post(2, leader_aloc(), Uri::CommissionerGet, &[]);
    let (_, body) = net.nodes[2].responses.pop().unwrap();
    let t = Tlvs(&body);
    assert_eq!(t.commissioner_session_id().unwrap(), session);
    assert!(t.contains(ty::BORDER_AGENT_LOCATOR));
}

#[test]
fn commissioner_dataset_updates() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    net.commissioner = Some(1);
    petition(&mut net, 1, "comm");
    let (_, body) = net.nodes[1].responses.pop().unwrap();
    let session = Tlvs(&body).commissioner_session_id().unwrap();
    net.nodes[1].comm_aloc = Some(opentrust_mesh::netdata::aloc::commissioner_aloc16(session));

    // A partial MGMT_ACTIVE_SET from the commissioner merges into the
    // Active Dataset.
    let part = payload(|w| {
        w.commissioner_session_id(session).unwrap();
        w.active_timestamp(&ts(3)).unwrap();
        w.network_name(&NetworkName::new("ByComm").unwrap())
            .unwrap();
    });
    net.post(1, leader_aloc(), Uri::ActiveSet, &part);
    assert_eq!(state_of(&mut net, 1), State::Accept);
    net.run(secs(30));
    keep(&mut net, 1, session);
    let got = read(&net, 2, DatasetType::Active).unwrap();
    assert_eq!(got.tlvs().network_name().unwrap().as_str(), "ByComm");
    assert!(got.contains_all_required_for(DatasetType::Active));
    assert_eq!(got.tlvs().channel().unwrap().channel, 15);
    // A request from the commissioner is not reported back to it.
    assert_eq!(net.nodes[1].dataset_changed_rx, 0);

    // Wrong session ID: rejected. Affecting connectivity from the
    // commissioner in an ACTIVE_SET: rejected.
    let wrong = payload(|w| {
        w.commissioner_session_id(session.wrapping_add(1)).unwrap();
        w.active_timestamp(&ts(4)).unwrap();
    });
    net.post(1, leader_aloc(), Uri::ActiveSet, &wrong);
    assert_eq!(state_of(&mut net, 1), State::Reject);
    let chan = payload(|w| {
        w.commissioner_session_id(session).unwrap();
        w.active_timestamp(&ts(4)).unwrap();
        w.channel_page0(22).unwrap();
    });
    net.post(1, leader_aloc(), Uri::ActiveSet, &chan);
    assert_eq!(state_of(&mut net, 1), State::Reject);

    // The same channel change through MGMT_PENDING_SET is fine.
    let pend = payload(|w| {
        w.commissioner_session_id(session).unwrap();
        w.active_timestamp(&ts(4)).unwrap();
        w.pending_timestamp(&ts(4)).unwrap();
        w.delay_timer(30_000).unwrap();
        w.channel_page0(22).unwrap();
    });
    net.post(1, leader_aloc(), Uri::PendingSet, &pend);
    assert_eq!(state_of(&mut net, 1), State::Accept);
    net.run(secs(40));
    keep(&mut net, 1, session);
    net.run(secs(20));
    keep(&mut net, 1, session);
    for i in 0..3 {
        assert_eq!(net.shared(i).env.cur.channel, 22, "node {i}");
    }

    // MGMT_ACTIVE_REPLACE needs a full dataset and the commissioner.
    let mut full = dataset(10, 22, 0x1234, 0x42, "Replaced");
    full.set_timestamp(DatasetType::Active, &ts(10)).unwrap();
    let rep = {
        let mut p = full.clone();
        p.remove(ty::ACTIVE_TIMESTAMP);
        let mut v = payload(|w| w.commissioner_session_id(session).unwrap());
        v.extend_from_slice(full.as_bytes());
        v
    };
    net.post(1, leader_aloc(), Uri::ActiveReplace, &rep);
    assert_eq!(state_of(&mut net, 1), State::Accept);
    net.run(secs(30));
    assert_eq!(
        read(&net, 2, DatasetType::Active)
            .unwrap()
            .tlvs()
            .network_name()
            .unwrap()
            .as_str(),
        "Replaced"
    );
    net.post(2, leader_aloc(), Uri::ActiveReplace, full.as_bytes());
    assert_eq!(state_of(&mut net, 2), State::Reject);

    // A device (not the commissioner) changes the dataset: the
    // commissioner is notified with /c/dc.
    let by_dev = dataset(11, 22, 0x1234, 0x42, "ByDevice");
    net.post(2, leader_aloc(), Uri::ActiveSet, by_dev.as_bytes());
    assert_eq!(state_of(&mut net, 2), State::Accept);
    net.run(secs(10));
    assert_eq!(net.nodes[1].dataset_changed_rx, 1);
}

#[test]
fn leader_reset_recovers_network_data_and_commissioner_session() {
    use opentrust_mle::MleEnv;
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    petition(&mut net, 1, "OpenThread Commissioner");
    let (_, body) = net.nodes[1].responses.pop().unwrap();
    let session = Tlvs(&body).commissioner_session_id().unwrap();
    net.run(secs(30));
    let version = net.nodes[0].nd.version();
    let ctx_before = net.nodes[0].nd.data().len();
    assert!(ctx_before > 0);

    // The leader resets and restores its role: it waits for the Network
    // Data and refuses a new petition meanwhile.
    net.reset_leader_state(0);
    assert!(net.nodes[0].nd.is_waiting_for_sync());
    assert!(net.nodes[0].nd.data().is_empty());
    petition(&mut net, 2, "Other");
    assert!(commissioner::session_id(&net.nodes[0].nd).is_none());

    // A neighbor answers the Data Request: the data and the session ID are
    // adopted, the commissioner of the previous run is resigned (bare,
    // incremented session ID).
    let ld = *net.mle(1).leader_data();
    let data = net.sim.nodes[1].env.nd.clone();
    net.sim.nodes[0].env.set_network_data(&ld, &data);
    net.run(secs(30));
    let n0 = &net.nodes[0];
    assert!(!n0.nd.is_waiting_for_sync());
    assert!(commissioner::border_agent_locator(&n0.nd).is_none());
    assert_eq!(
        commissioner::session_id(&n0.nd),
        Some(session.wrapping_add(1))
    );
    assert_eq!(n0.leader_state.session_id(), session.wrapping_add(1));
    assert_ne!(n0.nd.version(), version);
    for i in 1..3 {
        assert_eq!(commissioning(&net, i), commissioning(&net, 0), "node {i}");
    }
    // A new petition works and continues the session counter.
    petition(&mut net, 2, "Other");
    let (_, body) = net.nodes[2].responses.pop().unwrap();
    let t = Tlvs(&body);
    assert_eq!(t.state().unwrap(), State::Accept);
    assert_eq!(
        t.commissioner_session_id().unwrap(),
        session.wrapping_add(2)
    );
}

#[test]
fn leader_without_network_data_detaches_after_the_sync_wait() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    net.reset_leader_state(0);
    net.run(secs(70));
    assert_ne!(net.role(0), Role::Leader);
    assert!(!net.nodes[0].nd.is_waiting_for_sync());
}

/// Run the network in one-second steps and feed the dataset events of
/// node `i` to `u`; the outcome once it finished.
fn run_updater(
    net: &mut Net,
    i: usize,
    u: &mut crate::updater::DatasetUpdater,
    max: u64,
) -> Option<crate::updater::UpdateOutcome> {
    for _ in 0..max {
        net.run(secs(1));
        let now = net.now();
        let events: std::vec::Vec<_> = net.shared(i).env.events.drain(..).collect();
        for e in events {
            let s = net.shared(i);
            if let Some(o) = u.handle_event(&s.ds, now, e) {
                return Some(o);
            }
        }
    }
    None
}

#[test]
fn dataset_updater_changes_the_channel() {
    use crate::updater::{DatasetUpdater, UpdateOutcome};
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    let mut u = DatasetUpdater::new();

    let mut changes = Dataset::default();
    changes.set_channel(20).unwrap();
    // Already the case: refused. Timestamps in the request: refused.
    let mut same = Dataset::default();
    same.set_channel(15).unwrap();
    let now = net.now();
    {
        let s = &mut *net.shared(2);
        assert_eq!(
            u.request_update(&mut s.ds, &mut s.env, now, &same, [1, 1]),
            Err(opentrust_core::Error::Already)
        );
        let mut bad = changes.clone();
        bad.set_timestamp(DatasetType::Active, &ts(5)).unwrap();
        assert_eq!(
            u.request_update(&mut s.ds, &mut s.env, now, &bad, [1, 1]),
            Err(opentrust_core::Error::InvalidArgs)
        );
        u.request_update(&mut s.ds, &mut s.env, now, &changes, [7, 9])
            .unwrap();
        assert_eq!(
            u.request_update(&mut s.ds, &mut s.env, now, &changes, [7, 9]),
            Err(opentrust_core::Error::Busy)
        );
    }
    assert!(u.is_update_ongoing());
    // The Pending Dataset travels to the leader and applies after the
    // default delay; the update finishes with the new Active Dataset.
    assert_eq!(
        run_updater(&mut net, 2, &mut u, 400),
        Some(UpdateOutcome::Done)
    );
    assert!(!u.is_update_ongoing());
    net.run(secs(30));
    for i in 0..3 {
        let s = net.shared(i);
        assert_eq!(s.env.cur.channel, 20, "node {i}");
        let a = s.ds.read(DatasetType::Active, net.now()).unwrap();
        assert_eq!(a.tlvs().pan_id().unwrap(), 0x1234);
        let ats = s.ds.timestamp(DatasetType::Active).unwrap();
        assert!(compare_ts(&ats, &ts(1)).is_gt(), "node {i}");
    }
}

fn compare_ts(a: &Timestamp, b: &Timestamp) -> core::cmp::Ordering {
    crate::timestamp::compare(Some(a), Some(b))
}

#[test]
fn dataset_updater_reports_a_conflicting_update() {
    use crate::updater::{DatasetUpdater, UpdateOutcome};
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    let mut u = DatasetUpdater::new();
    let mut changes = Dataset::default();
    changes.set_channel(20).unwrap();
    let now = net.now();
    {
        let s = &mut *net.shared(2);
        u.request_update(&mut s.ds, &mut s.env, now, &changes, [1, 1])
            .unwrap();
    }
    // Another device sets a different channel with a much newer timestamp.
    let mut p = dataset(9, 22, 0x1234, 0x42, "OpenTrust");
    p.set_timestamp(DatasetType::Pending, &ts(9)).unwrap();
    p.set_delay_timer(10_000).unwrap();
    net.post(1, leader_aloc(), Uri::PendingSet, p.as_bytes());
    assert_eq!(
        run_updater(&mut net, 2, &mut u, 200),
        Some(UpdateOutcome::Conflict)
    );
    assert!(!u.is_update_ongoing());
}

#[test]
fn pending_delay_survives_a_reset_by_the_last_checkpoint() {
    use crate::manager::Datasets;
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    let mut p = dataset(2, 20, 0x1234, 0x42, "OpenTrust");
    p.set_timestamp(DatasetType::Pending, &ts(2)).unwrap();
    p.set_delay_timer(250_000).unwrap();
    net.post(2, leader_aloc(), Uri::PendingSet, p.as_bytes());
    assert_eq!(state_of(&mut net, 2), State::Accept);
    // 130 s later node 2 resets and restores its datasets from settings:
    // the stored Pending Dataset carries the delay of the last checkpoint
    // (at most one interval old), not the full delay.
    net.run(secs(130));
    let full = net.shared(2).ds.remaining_delay_ms(net.now()).unwrap() + 130_000;
    assert!(full > 240_000, "{full}");
    let now = net.now();
    let s = &mut *net.shared(2);
    s.ds = Datasets::new();
    s.ds.restore(&mut s.env, now, DatasetType::Pending).unwrap();
    let rem = s.ds.remaining_delay_ms(now).unwrap();
    assert!(rem < 200_000, "restarted with {rem}");
    assert!(rem > 100_000, "{rem}");
}

#[test]
fn restoring_a_held_pending_dataset_does_not_restart_the_delay() {
    let d = dataset(1, 15, 0x1234, 0x42, "OpenTrust");
    let mut net = form(&d);
    let mut p = dataset(2, 20, 0x1234, 0x42, "OpenTrust");
    p.set_timestamp(DatasetType::Pending, &ts(2)).unwrap();
    p.set_delay_timer(250_000).unwrap();
    net.post(2, leader_aloc(), Uri::PendingSet, p.as_bytes());
    assert_eq!(state_of(&mut net, 2), State::Accept);
    // A reattach restores the Pending Dataset several times; the delay
    // keeps counting down from the first save (OT reads the stored delay
    // minus the time since the last save).
    for _ in 0..4 {
        net.run(secs(20));
        let now = net.now();
        let s = &mut *net.shared(2);
        s.ds.restore(&mut s.env, now, DatasetType::Pending).unwrap();
    }
    let rem = net.shared(2).ds.remaining_delay_ms(net.now()).unwrap();
    assert!(rem < 175_000, "delay restarted: {rem}");
    assert!(rem > 150_000, "{rem}");
}
