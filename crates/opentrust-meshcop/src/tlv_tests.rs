use opentrust_core::bytes::Writer;
use opentrust_core::types::{ExtPanId, NetworkKey, NetworkName, Prefix64, Pskc};

use crate::steering::SteeringData;
use crate::timestamp::Timestamp;
use crate::tlv::*;

#[test]
fn security_policy_default_wire() {
    let p = SecurityPolicy::default();
    assert_eq!(p.to_bytes(), [0x02, 0xa0, 0xf7, 0xf8]);
    assert_eq!(SecurityPolicy::from_bytes(&p.to_bytes()).unwrap(), p);
}

#[test]
fn security_policy_flags() {
    // 1.1 format: only one flag byte, the rest default.
    let p = SecurityPolicy::from_bytes(&[0x00, 0x10, 0x00]).unwrap();
    assert_eq!(p.rotation_time, 16);
    assert!(!p.obtain_network_key && !p.routers && !p.native_commissioning);
    assert!(p.commercial_commissioning && p.autonomous_enrollment && p.network_key_provisioning);
    assert!(p.toble_link && !p.non_ccm_routers);
    // 1.2 flags.
    let p = SecurityPolicy::from_bytes(&[0x00, 0x10, 0xff, 0x05]).unwrap();
    assert!(!p.toble_link && p.non_ccm_routers);
    assert_eq!(p.version_threshold_for_routing, 5);
    assert!(SecurityPolicy::from_bytes(&[0, 1]).is_err());
    let mut q = p;
    q.version_threshold_for_routing = 7;
    assert_eq!(SecurityPolicy::from_bytes(&q.to_bytes()).unwrap(), q);
}

#[test]
fn channel_mask() {
    // Channels 11..=26 on page 0: OT's default dataset value.
    assert_eq!(
        channel_mask_entry(PAGE0_CHANNELS),
        [0, 4, 0x00, 0x1f, 0xff, 0xe0]
    );
    assert_eq!(
        parse_channel_mask(&[0, 4, 0x00, 0x1f, 0xff, 0xe0]).unwrap(),
        PAGE0_CHANNELS
    );
    // Unknown pages are skipped, bad lengths rejected.
    assert_eq!(
        parse_channel_mask(&[2, 1, 0xff, 0, 4, 0x00, 0x10, 0, 0]).unwrap(),
        1 << 11
    );
    assert!(parse_channel_mask(&[]).is_err());
    assert!(parse_channel_mask(&[0, 3, 0, 0, 0]).is_err());
    assert!(parse_channel_mask(&[0, 4, 0, 0]).is_err());
    assert!(parse_channel_mask(&[0]).is_err());
}

#[test]
fn round_trip_all() {
    let mut buf = [0u8; 400];
    let mut w = Writer::new(&mut buf);
    let ts = Timestamp {
        seconds: 0x0102_0304_0506,
        ticks: 0x1234,
        authoritative: true,
    };
    let mut sd = SteeringData::new(4);
    sd.set_permit_all();
    w.channel_page0(15).unwrap();
    w.pan_id(0xface).unwrap();
    w.ext_pan_id(&ExtPanId([1; 8])).unwrap();
    w.network_name(&NetworkName::new("OpenTrust").unwrap())
        .unwrap();
    w.pskc(&Pskc([2; 16])).unwrap();
    w.network_key(&NetworkKey([3; 16])).unwrap();
    w.network_key_sequence(7).unwrap();
    w.mesh_local_prefix(&Prefix64([0xfd, 0, 0, 0, 0, 0, 0, 1]))
        .unwrap();
    w.steering_data(&sd).unwrap();
    w.border_agent_locator(0x0400).unwrap();
    w.commissioner_id("comm").unwrap();
    w.commissioner_session_id(0xbeef).unwrap();
    w.security_policy(&SecurityPolicy::default()).unwrap();
    w.get_list(&[0, 1]).unwrap();
    w.active_timestamp(&ts).unwrap();
    w.pending_timestamp(&ts).unwrap();
    w.delay_timer(30_000).unwrap();
    w.channel_mask(PAGE0_CHANNELS).unwrap();
    w.state(State::Reject).unwrap();
    w.commissioner_udp_port(49191).unwrap();
    w.joiner_udp_port(1000).unwrap();
    w.count(2).unwrap();
    w.period(100).unwrap();
    w.scan_duration(32).unwrap();
    w.energy_list(&[0xc4, 0xd0]).unwrap();
    w.thread_domain_name("DefaultDomain").unwrap();
    w.discovery_request(&DiscoveryRequest {
        version: 2,
        joiner: true,
    })
    .unwrap();
    w.discovery_response(&DiscoveryResponse {
        version: 2,
        native_commissioner: true,
        commercial_commissioning: false,
    })
    .unwrap();
    let t = Tlvs(w.written());
    t.validate().unwrap();
    assert_eq!(
        t.channel().unwrap(),
        ChannelValue {
            page: 0,
            channel: 15
        }
    );
    assert_eq!(t.pan_id().unwrap(), 0xface);
    assert_eq!(t.ext_pan_id().unwrap().0, [1; 8]);
    assert_eq!(t.network_name().unwrap().as_str(), "OpenTrust");
    assert_eq!(t.pskc().unwrap().0, [2; 16]);
    assert_eq!(t.network_key().unwrap().0, [3; 16]);
    assert_eq!(t.network_key_sequence().unwrap(), 7);
    assert_eq!(t.mesh_local_prefix().unwrap().0[0], 0xfd);
    assert!(t.steering_data().unwrap().permits_all());
    assert_eq!(t.border_agent_locator().unwrap(), 0x0400);
    assert_eq!(t.commissioner_id().unwrap(), "comm");
    assert_eq!(t.commissioner_session_id().unwrap(), 0xbeef);
    assert_eq!(t.security_policy().unwrap(), SecurityPolicy::default());
    assert_eq!(t.get_list().unwrap(), &[0, 1]);
    assert_eq!(t.active_timestamp().unwrap(), ts);
    assert_eq!(t.pending_timestamp().unwrap(), ts);
    assert_eq!(t.delay_timer().unwrap(), 30_000);
    assert_eq!(t.channel_mask().unwrap(), PAGE0_CHANNELS);
    assert_eq!(t.state().unwrap(), State::Reject);
    assert_eq!(t.commissioner_udp_port().unwrap(), 49191);
    assert_eq!(t.joiner_udp_port().unwrap(), 1000);
    assert_eq!(t.count().unwrap(), 2);
    assert_eq!(t.period().unwrap(), 100);
    assert_eq!(t.scan_duration().unwrap(), 32);
    assert_eq!(t.energy_list().unwrap(), &[0xc4, 0xd0]);
    assert_eq!(t.thread_domain_name().unwrap(), "DefaultDomain");
    assert_eq!(
        t.discovery_request().unwrap(),
        DiscoveryRequest {
            version: 2,
            joiner: true
        }
    );
    assert!(t.discovery_response().unwrap().native_commissioner);
    assert_eq!(t.value(ty::CHANNEL_MASK).unwrap().len(), 6);
    assert_eq!(t.iter().count(), 28);
}

#[test]
fn malformed() {
    assert!(Tlvs(&[ty::PAN_ID, 1, 0]).pan_id().is_err());
    assert!(Tlvs(&[ty::PAN_ID, 2, 0]).validate().is_err());
    assert!(Tlvs(&[]).pan_id().is_err());
    assert!(Tlvs(&[ty::NETWORK_NAME, 0]).network_name().is_err());
    assert!(Tlvs(&[ty::STATE, 1, 5]).state().is_err());
    assert!(Tlvs(&[ty::STEERING_DATA, 0]).steering_data().is_err());
    assert!(
        !ChannelValue {
            page: 0,
            channel: 10
        }
        .is_valid()
    );
    assert!(
        ChannelValue {
            page: 0,
            channel: 26
        }
        .is_valid()
    );
    assert!(
        !ChannelValue {
            page: 1,
            channel: 20
        }
        .is_valid()
    );
    assert_eq!(State::from_u8(0xff), Some(State::Reject));
}

#[test]
fn extended_length() {
    let big = [0xa5u8; 300];
    let mut buf = [0u8; 400];
    let mut w = Writer::new(&mut buf);
    opentrust_core::tlv::write(&mut w, ty::VENDOR_DATA, &big).unwrap();
    let t = Tlvs(w.written());
    assert_eq!(t.value(ty::VENDOR_DATA).unwrap(), &big[..]);
}
