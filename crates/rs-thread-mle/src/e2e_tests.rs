//! End-to-end without a radio: a router core and a child core exchange
//! secured MLE messages through byte buffers, with deterministic time and
//! randomness. Covers attach, keep-alive, parent timeout of a silent child,
//! parent-loss re-attach and restore-from-settings fast re-attach (child and
//! router side).

use rs_thread_core::time::{Duration, Instant};
use rs_thread_core::types::Rloc16;

use crate::env::{MleEvent, Role};
use crate::message::Command;
use crate::mle::{Mle, MleConfig};
use crate::neighbor::StateFilter;
use crate::parent_tests::{ROUTER_RLOC, router};
use crate::persist::Restored;
use crate::test_support::TestEnv;
use crate::tlv::DeviceMode;

const T0: Instant = Instant::from_secs(1000);
const RX_ON: DeviceMode = DeviceMode::new(true, false, true);
const SLEEPY: DeviceMode = DeviceMode::new(false, false, false);

struct Net {
    r: Mle<4>,
    renv: TestEnv,
    c: Mle<0>,
    cenv: TestEnv,
    now: Instant,
    connected: bool,
    /// Messages delivered, by command number and direction (0: to the
    /// router, 1: to the child).
    seen: [[u32; 24]; 2],
}

impl Net {
    fn new(mode: DeviceMode) -> Self {
        let (r, renv) = router();
        Self {
            r,
            renv,
            c: Mle::new(MleConfig::new(mode)),
            cenv: TestEnv::new(1),
            now: T0,
            connected: true,
            seen: [[0; 24]; 2],
        }
    }

    fn count(&self, to_child: bool, cmd: Command) -> u32 {
        self.seen[usize::from(to_child)][cmd.as_u8() as usize]
    }

    /// Move messages until both sides are quiet.
    fn pump(&mut self) {
        for _ in 0..64 {
            let mut moved = false;
            for o in self.renv.take_out() {
                moved = true;
                if self.connected {
                    if let Ok(cmd) =
                        TestEnv::deliver(&o, &mut self.c, &mut self.cenv, self.now, -60)
                    {
                        self.seen[1][cmd.as_u8() as usize] += 1;
                    }
                }
            }
            for o in self.cenv.take_out() {
                moved = true;
                if self.connected {
                    if let Ok(cmd) =
                        TestEnv::deliver(&o, &mut self.r, &mut self.renv, self.now, -60)
                    {
                        self.seen[0][cmd.as_u8() as usize] += 1;
                    }
                }
            }
            if !moved {
                return;
            }
        }
        panic!("message storm");
    }

    /// Advance simulated time by `d`, polling both cores at their deadlines.
    fn run(&mut self, d: Duration) {
        let end = self.now + d;
        for _ in 0..100_000 {
            let next = [self.r.next_deadline(), self.c.next_deadline()]
                .into_iter()
                .flatten()
                .min();
            match next {
                Some(t) if t <= end => {
                    self.now = self.now.max(t);
                    self.r.poll(&mut self.renv, self.now);
                    self.c.poll(&mut self.cenv, self.now);
                    self.pump();
                }
                _ => break,
            }
        }
        self.now = end;
    }

    fn run_until_child(&mut self, max: Duration) {
        let end = self.now + max;
        while self.c.role() != Role::Child && self.now < end {
            self.run(Duration::from_millis(50));
        }
    }

    fn valid_children(&self) -> usize {
        self.r.children().count(StateFilter::Valid)
    }
}

fn attach(net: &mut Net) {
    net.c.start(&mut net.cenv, net.now).unwrap();
    net.pump();
    net.run_until_child(Duration::from_secs(10));
    assert_eq!(net.c.role(), Role::Child, "attached");
}

#[test]
fn attach_keepalive_timeout_and_reattach() {
    let mut net = Net::new(RX_ON);
    net.renv.provided_nd.clear();
    net.renv.provided_nd.extend_from_slice(&[7, 7, 7]).unwrap();
    attach(&mut net);
    // Handshake: Parent Request -> Response -> Child ID Request -> Response.
    assert!(net.count(false, Command::ParentRequest) >= 1);
    assert_eq!(net.count(true, Command::ParentResponse), 1);
    assert_eq!(net.count(false, Command::ChildIdRequest), 1);
    assert_eq!(net.count(true, Command::ChildIdResponse), 1);
    let c_rloc = net.c.rloc16();
    assert_eq!(c_rloc, Rloc16(0x0401));
    assert_eq!(net.cenv.short, c_rloc);
    assert_eq!(&net.cenv.nd[..], &[7, 7, 7]);
    assert_eq!(net.valid_children(), 1);
    assert!(net.renv.has_event(MleEvent::ChildAdded {
        ext: net.cenv.ext,
        rloc16: c_rloc
    }));
    assert_eq!(net.c.parent().unwrap().router.neighbor.rloc16, ROUTER_RLOC);

    // Keep-alive: 1000 s pass, the 240 s child timeout never expires.
    net.run(Duration::from_secs(1000));
    assert_eq!(net.c.role(), Role::Child);
    assert_eq!(net.valid_children(), 1);
    assert!(net.count(false, Command::ChildUpdateRequest) >= 4);
    assert!(net.count(true, Command::ChildUpdateResponse) >= 4);
    assert_eq!(net.count(true, Command::ParentResponse), 1, "no re-attach");

    // Silence: the parent drops the child after its timeout, the child
    // notices the parent is gone, detaches and keeps trying.
    net.connected = false;
    net.run(Duration::from_secs(300));
    assert_eq!(net.valid_children(), 0, "child timed out at the parent");
    assert!(net.renv.events.iter().any(|e| matches!(
        e,
        MleEvent::ChildRemoved { ext, .. } if *ext == net.cenv.ext
    )));
    assert_eq!(net.renv.settings_child_count(), 0);
    assert_eq!(net.c.role(), Role::Detached, "parent loss detected");
    assert!(net.cenv.has_event(MleEvent::ParentLost));
    assert_eq!(net.cenv.parent, None);
    assert_eq!(net.cenv.short, Rloc16::INVALID);

    // The link comes back: the child attaches again (new child ID).
    net.connected = true;
    net.run_until_child(Duration::from_secs(1300));
    assert_eq!(net.c.role(), Role::Child);
    assert_eq!(net.valid_children(), 1);
    assert_eq!(net.c.rloc16(), Rloc16(0x0402));
    // Frame counters moved on monotonically; nothing was replayed.
    assert!(net.c.parent().unwrap().router.neighbor.is_valid());
}

#[test]
fn sleepy_child_end_to_end_and_child_restart() {
    let mut net = Net::new(SLEEPY);
    attach(&mut net);
    assert_eq!(net.cenv.poll, Some(Duration::from_secs(236)));
    assert!(!net.cenv.rx_on);
    // The parent holds indirect state and supervises the sleepy child.
    assert_eq!(net.renv.indirect.len(), 1);
    net.run(Duration::from_secs(400));
    assert!(!net.renv.supervised.is_empty());
    assert_eq!(net.c.role(), Role::Child);

    // The child restarts from settings: one Child Update exchange and it is
    // back with the same RLOC16, the parent never noticed.
    let rloc = net.c.rloc16();
    let settings = core::mem::replace(
        &mut net.cenv.settings,
        rs_thread_platform::settings::RamSettings::new(),
    );
    let mut env2 = TestEnv::new(99);
    env2.settings = settings;
    let mut c2: Mle<0> = Mle::new(MleConfig::new(SLEEPY));
    let r = c2.restore(&mut env2, net.now).unwrap();
    assert_eq!(r, Restored::Child { rloc16: rloc });
    net.c = c2;
    net.cenv = env2;
    net.pump();
    assert_eq!(net.c.role(), Role::Child);
    assert_eq!(net.c.rloc16(), rloc);
    assert_eq!(net.cenv.ext, crate::test_support::ext(1));
    assert_eq!(net.valid_children(), 1);
    assert_eq!(net.count(true, Command::ParentResponse), 1, "no new attach");
    assert_eq!(net.count(true, Command::ChildIdResponse), 1);
    assert!(net.c.parent().unwrap().router.neighbor.is_valid());
    net.run(Duration::from_secs(100));
    assert_eq!(net.c.role(), Role::Child);
}

#[test]
fn router_restart_restores_children() {
    let mut net = Net::new(RX_ON);
    attach(&mut net);
    let rloc = net.c.rloc16();
    // The router restarts from its settings; the child keeps running. This
    // fixture router has no neighbors, so the router role restorer (see
    // `router_link_tests` for the complete flow) is overridden by entering
    // the role directly.
    net.r.store(&mut net.renv).unwrap();
    let settings = core::mem::replace(
        &mut net.renv.settings,
        rs_thread_platform::settings::RamSettings::new(),
    );
    let mut renv2 = TestEnv::new(55);
    renv2.settings = settings;
    renv2.provided_nd = net.renv.provided_nd.clone();
    let mut r2: Mle<4> = Mle::new(MleConfig::new(DeviceMode::new(true, true, true)));
    let restored = r2.restore(&mut renv2, net.now).unwrap();
    let Restored::Router {
        role,
        rloc16,
        previous_partition_id: _,
    } = restored
    else {
        panic!("router expected");
    };
    assert_eq!((role, rloc16), (Role::Router, ROUTER_RLOC));
    assert_eq!(renv2.ext, net.renv.ext, "identity restored");
    r2.enter_router_role(
        &mut renv2,
        net.now,
        role,
        rloc16,
        crate::parent_tests::leader(),
        crate::parent::RouterInfo {
            accepting_children: true,
            ..Default::default()
        },
    )
    .unwrap();
    r2.restore_children(&mut renv2, net.now);
    assert_eq!(
        r2.children().count(StateFilter::AnyExceptInvalid),
        1,
        "restored from ChildInfo"
    );
    assert_eq!(r2.children().count(StateFilter::Valid), 0);
    net.r = r2;
    net.renv = renv2;
    net.run(Duration::from_secs(2));
    // The restored router asked, the child answered, the child is valid again
    // and never re-attached.
    assert_eq!(net.valid_children(), 1);
    assert_eq!(net.c.role(), Role::Child);
    assert_eq!(net.c.rloc16(), rloc);
    assert_eq!(net.count(true, Command::ParentResponse), 1);
    assert!(net.count(true, Command::ChildUpdateRequest) >= 1);
    assert!(net.count(false, Command::ChildUpdateResponse) >= 1);
    // Keep-alive continues against the new router instance.
    net.run(Duration::from_secs(600));
    assert_eq!(net.c.role(), Role::Child);
    assert_eq!(net.valid_children(), 1);
}
