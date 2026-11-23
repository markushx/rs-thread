use std::vec;

use rs_thread_core::Result;
use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::{ExtPanId, NetworkKey, NetworkName, Prefix64, Pskc};
use rs_thread_mle::Role;

use crate::dataset::{Dataset, DatasetType, MAX_LEN};
use crate::manager::{Configuration, CurrentConfig, DatasetEnv, DatasetEvent, Datasets};
use crate::timestamp::Timestamp;
use crate::tlv::{PAGE0_CHANNELS, SecurityPolicy, ty};

pub fn ts(s: u64) -> Timestamp {
    Timestamp {
        seconds: s,
        ticks: 0,
        authoritative: false,
    }
}

/// A complete Active Dataset.
pub fn full(seconds: u64, channel: u8, pan: u16, key: u8) -> Dataset {
    let mut d = Dataset::new();
    d.set_timestamp(DatasetType::Active, &ts(seconds)).unwrap();
    d.set_channel(channel).unwrap();
    d.set_channel_mask(PAGE0_CHANNELS).unwrap();
    d.set_ext_pan_id(&ExtPanId([0xde, 0xad, 0, 0xbe, 0xef, 0, 0xca, 0xfe]))
        .unwrap();
    d.set_mesh_local_prefix(&Prefix64([0xfd, 0xde, 0xad, 0, 0xbe, 0xef, 0, 0]))
        .unwrap();
    d.set_network_key(&NetworkKey([key; 16])).unwrap();
    d.set_network_name(&NetworkName::new("RsThread").unwrap())
        .unwrap();
    d.set_pan_id(pan).unwrap();
    d.set_pskc(&Pskc([7; 16])).unwrap();
    d.set_security_policy(&SecurityPolicy::default()).unwrap();
    d
}

#[derive(Default)]
pub struct TestDatasetEnv {
    pub cur: Option<CurrentConfig>,
    pub applied: std::vec::Vec<Configuration>,
    pub role: Option<Role>,
    pub stored: [Option<std::vec::Vec<u8>>; 2],
    pub events: std::vec::Vec<DatasetEvent>,
    pub session: Option<u16>,
    pub version_bumps: u32,
}

impl DatasetEnv for TestDatasetEnv {
    fn current(&self) -> CurrentConfig {
        self.cur.clone().unwrap_or(CurrentConfig {
            channel: 11,
            pan_id: 1,
            mesh_local_prefix: Prefix64([0; 8]),
            network_key: NetworkKey([0; 16]),
        })
    }
    fn apply(&mut self, cfg: &Configuration) -> Result<()> {
        self.applied.push(cfg.clone());
        if let Some(c) = &mut self.cur {
            if let Some(ch) = cfg.channel {
                c.channel = ch;
            }
            if let Some(p) = cfg.pan_id {
                c.pan_id = p;
            }
            if let Some(k) = &cfg.network_key {
                c.network_key = k.clone();
            }
        }
        Ok(())
    }
    fn role(&self) -> Role {
        self.role.unwrap_or(Role::Disabled)
    }
    fn store(&mut self, t: DatasetType, tlvs: &[u8]) -> Result<()> {
        self.stored[t.index()] = Some(tlvs.to_vec());
        Ok(())
    }
    fn load(&self, t: DatasetType, out: &mut [u8]) -> Option<usize> {
        let s = self.stored[t.index()].as_ref()?;
        out[..s.len()].copy_from_slice(s);
        Some(s.len())
    }
    fn delete(&mut self, t: DatasetType) {
        self.stored[t.index()] = None;
    }
    fn event(&mut self, e: DatasetEvent) {
        self.events.push(e);
    }
    fn commissioning_session_id(&self) -> Option<u16> {
        self.session
    }
    fn network_data_changed(&mut self) {
        self.version_bumps += 1;
    }
}

const T0: Instant = Instant::from_secs(100);

#[test]
fn validate_rules() {
    let d = full(1, 15, 0x1234, 3);
    d.validate().unwrap();
    assert!(d.contains_all_required_for(DatasetType::Active));
    assert!(!d.contains_all_required_for(DatasetType::Pending));
    assert!(d.is_commissioned());
    assert_eq!(Dataset::from_tlvs(d.as_bytes()).unwrap(), d);

    // Duplicate TLV.
    assert!(Dataset::from_tlvs(&[ty::PAN_ID, 2, 0, 1, ty::PAN_ID, 2, 0, 2]).is_err());
    // Truncated value.
    assert!(Dataset::from_tlvs(&[ty::PAN_ID, 1, 0]).is_err());
    // Bad channel.
    assert!(Dataset::from_tlvs(&[ty::CHANNEL, 3, 0, 0, 5]).is_err());
    // Extended TLV.
    let mut ext = std::vec![ty::VENDOR_DATA, 0xff, 0, 1, 0];
    ext.push(0);
    assert!(Dataset::from_tlvs(&ext).is_err());
    // Too short key.
    assert!(Dataset::from_tlvs(&[ty::NETWORK_KEY, 4, 0, 0, 0, 0]).is_err());
    // Security policy without flags.
    assert!(Dataset::from_tlvs(&[ty::SECURITY_POLICY, 2, 0, 1]).is_err());
    // Too long.
    assert!(Dataset::from_tlvs(&[0u8; MAX_LEN + 1]).is_err());
}

#[test]
fn write_remove_and_subset() {
    let mut d = full(1, 15, 0x1234, 3);
    let len = d.len();
    d.set_pan_id(0x4321).unwrap();
    assert_eq!(d.len(), len);
    assert_eq!(d.tlvs().pan_id().unwrap(), 0x4321);
    d.remove(ty::PAN_ID);
    assert_eq!(d.len(), len - 4);
    assert!(!d.contains(ty::PAN_ID));
    d.validate().unwrap();

    let a = full(1, 15, 0x1234, 3);
    let mut b = full(2, 15, 0x1234, 3);
    assert!(a.is_subset_of(&b));
    b.set_channel(16).unwrap();
    assert!(!a.is_subset_of(&b));

    // Capacity.
    let mut d = full(1, 15, 1, 1);
    d.set_delay_timer(1).unwrap();
    d.set_timestamp(DatasetType::Pending, &ts(1)).unwrap();
    assert!(d.contains_all_required_for(DatasetType::Pending));
    assert!(d.write_tlv(ty::VENDOR_DATA, &[0u8; 200]).is_err());
}

#[test]
fn copy_without_timestamp() {
    let d = full(5, 15, 1, 1);
    let mut out = [0u8; MAX_LEN];
    let n = d.copy_without(ty::ACTIVE_TIMESTAMP, &mut out).unwrap();
    assert_eq!(n, d.len() - 10);
    let e = Dataset::from_tlvs(&out[..n]).unwrap();
    assert!(!e.contains(ty::ACTIVE_TIMESTAMP));
}

fn env_with(role: Role) -> TestDatasetEnv {
    TestDatasetEnv {
        cur: Some(CurrentConfig {
            channel: 11,
            pan_id: 1,
            mesh_local_prefix: Prefix64([0xfd, 0xde, 0xad, 0, 0xbe, 0xef, 0, 0]),
            network_key: NetworkKey([3; 16]),
        }),
        role: Some(role),
        ..Default::default()
    }
}

#[test]
fn save_local_and_restore() {
    let mut env = env_with(Role::Disabled);
    let mut ds = Datasets::new();
    ds.save_local(&mut env, T0, DatasetType::Active, &full(1, 15, 7, 3))
        .unwrap();
    // Disabled: applied right away, network timestamp known.
    assert_eq!(env.applied.len(), 1);
    assert_eq!(env.applied[0].channel, Some(15));
    assert_eq!(env.applied[0].pan_id, Some(7));
    assert!(ds.is_complete());
    assert_eq!(ds.timestamp(DatasetType::Active), Some(ts(1)));
    assert!(env.stored[0].is_some());
    assert!(env.events.contains(&DatasetEvent::ActiveChanged));

    // A fresh manager restores it from settings.
    let mut ds2 = Datasets::new();
    ds2.restore(&mut env, T0, DatasetType::Active).unwrap();
    assert_eq!(
        ds2.read(DatasetType::Active, T0),
        ds.read(DatasetType::Active, T0)
    );
    assert!(ds2.restore(&mut env, T0, DatasetType::Pending).is_err());

    ds.clear(&mut env, DatasetType::Active);
    assert!(env.stored[0].is_none());
    assert!(!ds.is_saved(DatasetType::Active));
    assert_eq!(ds.read(DatasetType::Active, T0), None);
}

#[test]
fn save_from_network_timestamp_rules() {
    let mut env = env_with(Role::Child);
    let mut ds = Datasets::new();
    ds.save(&mut env, T0, DatasetType::Active, &full(5, 15, 7, 3), false)
        .unwrap();
    assert_eq!(ds.local_timestamp(DatasetType::Active), Some(ts(5)));
    // An older network dataset does not replace the local one but arms the
    // MGMT_SET retry timer.
    ds.save(&mut env, T0, DatasetType::Active, &full(3, 16, 7, 3), false)
        .unwrap();
    assert_eq!(ds.local_timestamp(DatasetType::Active), Some(ts(5)));
    assert_eq!(ds.timestamp(DatasetType::Active), Some(ts(3)));
    assert!(ds.next_deadline().is_some());
    // The local dataset is then offered to the leader.
    ds.poll(&mut env, T0 + Duration::from_secs(6));
    let d = ds
        .take_set_request(
            Role::Router,
            T0 + Duration::from_secs(6),
            DatasetType::Active,
        )
        .unwrap();
    assert_eq!(d.tlvs().channel().unwrap().channel, 15);
    // One request at a time.
    assert!(
        ds.take_set_request(Role::Router, T0, DatasetType::Active)
            .is_none()
    );
    ds.mgmt_set_finished(T0, DatasetType::Active);
    // Equal timestamps: nothing to send.
    ds.save(&mut env, T0, DatasetType::Active, &full(5, 15, 7, 3), false)
        .unwrap();
    ds.poll(&mut env, T0 + Duration::from_secs(20));
    assert!(
        ds.take_set_request(Role::Router, T0, DatasetType::Active)
            .is_none()
    );
}

#[test]
fn dataset_received_adds_timestamp() {
    let mut env = env_with(Role::Child);
    let mut ds = Datasets::new();
    let d = full(9, 15, 7, 3);
    let mut b = [0u8; MAX_LEN];
    let n = d.copy_without(ty::ACTIVE_TIMESTAMP, &mut b).unwrap();
    ds.dataset_received(&mut env, T0, Some((ts(9), Some(&b[..n]))), None);
    assert_eq!(ds.timestamp(DatasetType::Active), Some(ts(9)));
    let r = ds.read(DatasetType::Active, T0).unwrap();
    assert!(d.is_subset_of(&r) && r.is_subset_of(&d));
    assert_eq!(r.timestamp(DatasetType::Active), Some(ts(9)));
    let mut out = [0u8; MAX_LEN];
    let m = ds.mle_dataset(DatasetType::Active, T0, &mut out).unwrap();
    assert_eq!(m, n);
    // Invalid datasets are ignored.
    ds.dataset_received(
        &mut env,
        T0,
        Some((ts(10), Some(&[ty::PAN_ID, 1, 0]))),
        None,
    );
    assert_eq!(ds.timestamp(DatasetType::Active), Some(ts(9)));
    // Timestamp only (no dataset bytes): nothing to save.
    ds.dataset_received(&mut env, T0, Some((ts(11), None)), None);
    assert_eq!(ds.timestamp(DatasetType::Active), Some(ts(9)));
}

fn pending(active_ts: u64, delay_ms: u32, channel: u8, key: u8) -> Dataset {
    let mut d = full(active_ts, channel, 7, key);
    d.set_timestamp(DatasetType::Pending, &ts(active_ts))
        .unwrap();
    d.set_delay_timer(delay_ms).unwrap();
    d
}

#[test]
fn pending_delay_timer_replaces_active() {
    let mut env = env_with(Role::Child);
    let mut ds = Datasets::new();
    ds.save(&mut env, T0, DatasetType::Active, &full(1, 15, 7, 3), false)
        .unwrap();
    ds.save(
        &mut env,
        T0,
        DatasetType::Pending,
        &pending(2, 60_000, 20, 3),
        false,
    )
    .unwrap();
    assert_eq!(ds.next_deadline(), Some(T0 + Duration::from_secs(60)));
    // The remaining delay counts down.
    let p = ds
        .read(DatasetType::Pending, T0 + Duration::from_secs(20))
        .unwrap();
    assert_eq!(p.tlvs().delay_timer().unwrap(), 40_000);
    assert_eq!(
        ds.remaining_delay_ms(T0 + Duration::from_secs(20)),
        Some(40_000)
    );
    assert!(ds.pending_active_timestamp().is_some());

    // Not yet.
    ds.poll(&mut env, T0 + Duration::from_secs(59));
    assert_eq!(env.cur.as_ref().unwrap().channel, 15);
    assert!(ds.is_saved(DatasetType::Pending));

    ds.poll(&mut env, T0 + Duration::from_secs(60));
    assert_eq!(env.cur.as_ref().unwrap().channel, 20);
    assert_eq!(ds.timestamp(DatasetType::Active), Some(ts(2)));
    assert!(!ds.is_saved(DatasetType::Pending));
    assert!(env.stored[1].is_none());
    // Active has neither pending timestamp nor delay timer.
    let a = ds.read(DatasetType::Active, T0).unwrap();
    assert!(!a.contains(ty::PENDING_TIMESTAMP) && !a.contains(ty::DELAY_TIMER));
    assert_eq!(ds.next_deadline(), None);
}

#[test]
fn pending_with_old_active_timestamp_but_new_key_still_replaces() {
    let mut env = env_with(Role::Child);
    let mut ds = Datasets::new();
    ds.save(&mut env, T0, DatasetType::Active, &full(5, 15, 7, 3), false)
        .unwrap();
    // Not newer, same key: dropped without replacing.
    ds.save(
        &mut env,
        T0,
        DatasetType::Pending,
        &pending(5, 1000, 20, 3),
        false,
    )
    .unwrap();
    ds.poll(&mut env, T0 + Duration::from_secs(2));
    assert_eq!(env.cur.as_ref().unwrap().channel, 15);
    assert!(!ds.is_saved(DatasetType::Pending));
    // Not newer but a different key: replaces.
    ds.save(
        &mut env,
        T0,
        DatasetType::Pending,
        &pending(5, 1000, 20, 9),
        false,
    )
    .unwrap();
    ds.poll(&mut env, T0 + Duration::from_secs(2));
    assert_eq!(env.cur.as_ref().unwrap().channel, 20);
    assert_eq!(env.cur.as_ref().unwrap().network_key, NetworkKey([9; 16]));
}

#[cfg(feature = "ftd")]
#[test]
fn leader_save_local_bumps_network_data_and_generates() {
    let mut env = env_with(Role::Leader);
    let mut ds = Datasets::new();
    ds.save_local(&mut env, T0, DatasetType::Active, &full(1, 15, 7, 3))
        .unwrap();
    assert_eq!(env.version_bumps, 1);

    // generate_local fills missing TLVs.
    let mut env = env_with(Role::Leader);
    let mut ds = Datasets::new();
    let cfg = Configuration {
        channel: Some(13),
        pan_id: Some(0x55),
        ext_pan_id: Some(ExtPanId([1; 8])),
        network_name: Some(NetworkName::new("gen").unwrap()),
        network_key: Some(NetworkKey([4; 16])),
        pskc: Some(Pskc([5; 16])),
        mesh_local_prefix: Some(Prefix64([0xfd, 0, 0, 0, 0, 0, 0, 2])),
        security_policy: None,
    };
    ds.generate_local(&mut env, T0, &cfg, PAGE0_CHANNELS)
        .unwrap();
    let d = ds.read(DatasetType::Active, T0).unwrap();
    assert!(d.contains_all_required_for(DatasetType::Active));
    assert_eq!(d.tlvs().channel().unwrap().channel, 13);
    assert_eq!(d.tlvs().active_timestamp().unwrap(), Timestamp::default());
    assert!(
        ds.generate_local(&mut env, T0, &cfg, PAGE0_CHANNELS)
            .is_err()
    );
}

#[test]
fn security_policy_and_delay_minimum() {
    let mut ds = Datasets::new();
    assert_eq!(ds.security_policy(), SecurityPolicy::default());
    assert_eq!(ds.delay_timer_minimal_ms(), 30_000);
    ds.set_delay_timer_minimal_ms(1000).unwrap();
    assert!(ds.set_delay_timer_minimal_ms(0).is_err());
    assert!(ds.set_delay_timer_minimal_ms(30_000).is_err());
}

/// A network name with a control character is invalid, like in OpenThread
/// (`IsValidUtf8String`); found by the differential tests.
#[test]
fn network_name_with_control_character_is_invalid() {
    let mut ok = vec![ty::NETWORK_NAME, 4];
    ok.extend_from_slice(b"abcd");
    assert!(Dataset::from_tlvs(&ok).is_ok());
    let mut bad = vec![ty::NETWORK_NAME, 4];
    bad.extend_from_slice(b"ab\x0fd");
    assert!(Dataset::from_tlvs(&bad).is_err());
}
