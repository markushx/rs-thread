//! Integration tests for rsthread-br-posix.
//!
//! These tests require the `rs-thread-rcp-sim` Spinel socket simulator to be
//! running as a backend.  They are marked `#[ignore]` and must be run
//! explicitly with `-- --ignored`.
//!
//! Planned scenarios:
//! 1. Binary starts, Thread attaches as leader with `--become-leader`.
//! 2. OMR prefix appears in Network Data after a second rs-thread node joins.
//! 3. SRP registration on a Thread device is bridged to backbone mDNS.
//! 4. DNS query from a Thread device resolves through the DNS proxy.
//!
//! To run:
//! ```sh
//! cargo build -p rsthread-br-posix
//! cargo test -p rsthread-br-posix -- --ignored
//! ```

#[test]
#[ignore = "requires rs-thread-rcp-sim binary (run with -- --ignored)"]
fn border_router_starts_and_forms_network() {
    // Start `rs-thread-rcp-sim --spinel-socket 127.0.0.1:9100` in the
    // background, then spawn `rsthread-br-posix --radio-url
    // spinel+socket://127.0.0.1:9100 --become-leader`, wait for Thread to
    // attach, and assert the binary's log shows "Thread network formed".
    todo!("integrate with rs-thread-rcp-sim")
}

#[test]
#[ignore = "requires rs-thread-rcp-sim binary (run with -- --ignored)"]
fn srp_registration_is_bridged_to_mdns() {
    // Attach a second rs-thread node through the rcp-sim virtual radio,
    // register a service via SRP on that node, and verify the service
    // appears in the mDNS browse results on the backbone.
    todo!("integrate with rs-thread-rcp-sim")
}

#[test]
#[ignore = "requires rs-thread-rcp-sim binary (run with -- --ignored)"]
fn dns_query_resolves_through_proxy() {
    // Send a DNS query to `--dns-addr` from the host and verify the proxy
    // forwards it to the upstream resolver and returns a valid response.
    todo!("integrate with rs-thread-rcp-sim")
}
