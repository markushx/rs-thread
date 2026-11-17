//! RAM footprint of [`Instance`]: prints the per-component breakdown
//! (`cargo test -p opentrust-instance size -- --nocapture`) and asserts an
//! upper bound per feature set so regressions show up. The numbers include a
//! caller-provided `RamSettings<4096>` and are for a 64-bit host; 32-bit
//! targets are somewhat smaller.

extern crate std;

use core::mem::size_of_val;

use opentrust_core::crypto::soft::SoftCrypto;
use opentrust_platform::RamSettings;

use super::*;

/// Upper bound of `size_of::<Instance>()` for the enabled feature set.
#[cfg(all(feature = "srp-server", feature = "border-agent"))]
const TOTAL_BOUND: usize = 140_200;
#[cfg(all(feature = "border-agent", not(feature = "srp-server")))]
const TOTAL_BOUND: usize = 114_000;
#[cfg(all(feature = "srp-server", feature = "ftd", not(feature = "border-agent")))]
const TOTAL_BOUND: usize = 113_200;
#[cfg(all(
    feature = "ftd",
    not(feature = "border-agent"),
    not(feature = "srp-server")
))]
const TOTAL_BOUND: usize = 86_950;
#[cfg(not(feature = "ftd"))]
const TOTAL_BOUND: usize = 78_200;

fn row<T>(name: &str, v: &T) {
    std::println!("{:>8} {}", size_of_val(v), name);
}

#[test]
fn instance_size_breakdown() {
    let cfg = Config::router(ExtAddress([1; 8]), Default::default());
    let i = std::boxed::Box::new(Instance::new(
        cfg,
        RamSettings::<4096>::new(),
        SoftCrypto,
        MacRng::new(1),
    ));
    let total = size_of_val(&*i);
    std::println!("{total:>8} total (bound {TOTAL_BOUND})");
    row("mle", &i.mle);
    row("core", &i.core);
    row("agent", &i.agent);
    row("sink", &i.sink);
    row("udp", &i.udp);
    row("resolver", &i.resolver);
    row("fwd", &i.fwd);
    #[cfg(feature = "ftd")]
    row("leader", &i.leader);
    row("local", &i.local);
    row("notifier", &i.notifier);
    row("publisher", &i.publisher);
    row("alocs", &i.alocs);
    row("slaac", &i.slaac);
    row("glue", &i.glue);
    row("dnssrp", &i.dnssrp);
    row("bbrg", &i.bbrg);
    row("diag_in", &i.diag_in);
    row("cm", &i.cm);
    #[cfg(feature = "ftd")]
    row("solicit", &i.solicit);
    row("ping", &i.ping);
    let c = &i.core;
    row("core.mac", &c.mac);
    row("core.settings", &c.settings);
    row("core.ip6", &c.ip6);
    row("core.netdata", &c.netdata);
    row("core.datasets", &c.datasets);
    row("core.mle_events", &c.mle_events);
    row("core.mle_out", &c.mle_out);
    row("core.mactx", &c.mactx);
    row("core.events", &c.events);
    row("cm.joiner", &i.cm.joiner);
    #[cfg(feature = "commissioner")]
    row("cm.comm", &i.cm.comm);
    #[cfg(feature = "border-agent")]
    row("cm.ba", &i.cm.ba);
    #[cfg(feature = "border-agent")]
    row("cm.ba_out", &i.cm.ba_out);
    row("dnssrp.srp", &i.dnssrp.srp);
    row("dnssrp.dns", &i.dnssrp.dns);
    #[cfg(feature = "srp-server")]
    row("dnssrp.srpd", &i.dnssrp.srpd);
    // The Link Metrics Manager's subject table.
    let lmm = if cfg!(feature = "link-metrics-manager") {
        450
    } else {
        0
    };
    assert!(total <= TOTAL_BOUND + lmm, "Instance grew to {total} B");
}
