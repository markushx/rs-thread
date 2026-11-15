//! Nodes of the simulator driven only through CLI strings; the expected
//! output is what OpenThread's `ot-cli-ftd` prints.

use opentrust_cli::Cli;
use opentrust_core::time::Duration;
use opentrust_sim::{Kind, Network};

struct H {
    net: Network,
    cli: Vec<Cli>,
    out: Vec<String>,
}

impl H {
    fn new(kinds: &[Kind], seed: u64) -> Self {
        Self {
            net: Network::new(kinds, seed),
            cli: kinds.iter().map(|_| Cli::new()).collect(),
            out: kinds.iter().map(|_| String::new()).collect(),
        }
    }

    /// Run a command; returns the output that is printed synchronously.
    fn cmd(&mut self, i: usize, line: &str) -> String {
        self.out[i].clear();
        let (cli, out) = (&mut self.cli[i], &mut self.out[i]);
        self.net
            .with(i, |inst, now| cli.process_line(inst, now, line, out));
        self.pump();
        core::mem::take(&mut self.out[i]).replace("\r\n", "\n")
    }

    /// Feed events to the interpreters and run their timers.
    fn pump(&mut self) {
        for i in 0..self.cli.len() {
            let events = self.net.take_events(i);
            let (cli, out) = (&mut self.cli[i], &mut self.out[i]);
            self.net.with(i, |inst, now| {
                for ev in &events {
                    cli.handle_event(inst, now, ev, out);
                }
                cli.poll(inst, now, out);
            });
        }
    }

    /// Run virtual time until the async output of node `i` contains `pat`.
    fn wait_for(&mut self, i: usize, pat: &str, max_s: u64) -> String {
        for _ in 0..max_s * 5 {
            if self.out[i].contains(pat) {
                break;
            }
            self.net.run_for(Duration::from_millis(200));
            self.pump();
        }
        core::mem::take(&mut self.out[i]).replace("\r\n", "\n")
    }

    fn run(&mut self, secs: u64) {
        for _ in 0..secs * 5 {
            self.net.run_for(Duration::from_millis(200));
            self.pump();
        }
    }

    /// Run until `state` of node `i` prints `want`.
    fn wait_state(&mut self, i: usize, want: &str, max_s: u64) {
        for _ in 0..max_s {
            if self.cmd(i, "state") == format!("{want}\nDone\n") {
                return;
            }
            self.run(1);
        }
        panic!("node {i} did not reach {want}: {}", self.cmd(i, "state"));
    }
}

fn line_value(s: &str) -> String {
    s.lines().next().unwrap().to_string()
}

#[test]
fn single_node_basics() {
    let mut h = H::new(&[Kind::Router], 1);
    assert_eq!(h.cmd(0, "state"), "disabled\nDone\n");
    assert_eq!(h.cmd(0, "ifconfig"), "down\nDone\n");
    assert_eq!(h.cmd(0, "bogus"), "Error 35: InvalidCommand\n");
    assert_eq!(h.cmd(0, "channel zz"), "Error 7: InvalidArgs\n");
    assert_eq!(h.cmd(0, "ifconfig up"), "Done\n");
    assert_eq!(h.cmd(0, "ifconfig"), "up\nDone\n");
    assert_eq!(h.cmd(0, ""), "");
    assert_eq!(h.cmd(0, "extaddr"), "0200000000000001\nDone\n");
    assert!(h.cmd(0, "help").contains("\nifconfig\n"));
    assert_eq!(h.cmd(0, "mode"), "rdn\nDone\n");
    assert_eq!(h.cmd(0, "mode rn"), "Done\n");
    assert_eq!(h.cmd(0, "mode"), "rn\nDone\n");
    assert_eq!(h.cmd(0, "mode -"), "Done\n");
    assert_eq!(h.cmd(0, "mode"), "-\nDone\n");
    assert_eq!(h.cmd(0, "mode rdn"), "Done\n");
    // The leaderdata of a detached node.
    assert_eq!(h.cmd(0, "leaderdata"), "Error 16: Detached\n");
    // Router parameters.
    assert_eq!(h.cmd(0, "routerupgradethreshold 12"), "Done\n");
    assert_eq!(h.cmd(0, "routerupgradethreshold"), "12\nDone\n");
    assert_eq!(h.cmd(0, "routereligible"), "Enabled\nDone\n");
    assert_eq!(h.cmd(0, "routereligible disable"), "Done\n");
    assert_eq!(h.cmd(0, "routereligible"), "Disabled\nDone\n");
}

#[test]
fn dataset_commands() {
    let mut h = H::new(&[Kind::Router], 2);
    assert_eq!(h.cmd(0, "dataset init active"), "Error 23: NotFound\n");
    assert_eq!(h.cmd(0, "dataset init new"), "Done\n");
    assert_eq!(h.cmd(0, "dataset channel 17"), "Done\n");
    assert_eq!(h.cmd(0, "dataset channel"), "17\nDone\n");
    assert_eq!(h.cmd(0, "dataset panid 0xface"), "Done\n");
    assert_eq!(h.cmd(0, "dataset panid"), "0xface\nDone\n");
    assert_eq!(h.cmd(0, "dataset networkname TestNet"), "Done\n");
    assert_eq!(h.cmd(0, "dataset networkname"), "TestNet\nDone\n");
    assert_eq!(
        h.cmd(0, "dataset networkkey 00112233445566778899aabbccddeeff"),
        "Done\n"
    );
    assert_eq!(h.cmd(0, "dataset extpanid dead00beef00cafe"), "Done\n");
    assert_eq!(h.cmd(0, "dataset activetimestamp 7"), "Done\n");
    assert_eq!(h.cmd(0, "dataset securitypolicy 672 onrc"), "Done\n");
    assert_eq!(h.cmd(0, "dataset meshlocalprefix fd00:db8::/64"), "Done\n");
    assert_eq!(h.cmd(0, "dataset commit active"), "Done\n");
    let a = h.cmd(0, "dataset active");
    assert!(a.contains("Active Timestamp: 7\n"), "{a}");
    assert!(a.contains("Channel: 17\n"), "{a}");
    assert!(a.contains("Ext PAN ID: dead00beef00cafe\n"), "{a}");
    assert!(a.contains("Mesh Local Prefix: fd00:db8:0:0::/64\n"), "{a}");
    assert!(
        a.contains("Network Key: 00112233445566778899aabbccddeeff\n"),
        "{a}"
    );
    assert!(a.contains("Network Name: TestNet\n"), "{a}");
    assert!(a.contains("PAN ID: 0xface\n"), "{a}");
    assert!(a.contains("Security Policy: 672 onrc 0\n"), "{a}");
    assert!(a.ends_with("Done\n"));
    let ns = h.cmd(0, "dataset active -ns");
    assert!(ns.contains("Network Key: [Redacted]\n"), "{ns}");
    assert!(ns.contains("PSKc: [Redacted]\n"), "{ns}");
    let x = h.cmd(0, "dataset active -x");
    assert!(x.ends_with("\nDone\n") && x.len() > 40, "{x}");
    assert_eq!(h.cmd(0, "dataset clear"), "Done\n");
    assert_eq!(h.cmd(0, "dataset"), "Done\n");
    assert_eq!(h.cmd(0, "dataset init active"), "Done\n");
    assert_eq!(h.cmd(0, "dataset panid"), "0xface\nDone\n");
    // Getters before Thread runs follow the Active Dataset.
    assert_eq!(h.cmd(0, "channel"), "17\nDone\n");
    assert_eq!(h.cmd(0, "panid"), "0xface\nDone\n");
    assert_eq!(h.cmd(0, "networkname"), "TestNet\nDone\n");
    assert_eq!(h.cmd(0, "extpanid"), "dead00beef00cafe\nDone\n");
}

#[test]
fn form_join_ping_and_tables() {
    let mut h = H::new(&[Kind::Router, Kind::Router, Kind::EndDevice], 7);
    h.net.medium.connect(0, 1, -60);
    h.net.medium.connect(0, 2, -60);
    h.net.medium.connect(1, 2, -60);

    // Node 0 forms a network with the legacy setters.
    assert_eq!(h.cmd(0, "channel 15"), "Done\n");
    assert_eq!(h.cmd(0, "panid 0xface"), "Done\n");
    assert_eq!(h.cmd(0, "networkname OTcli"), "Done\n");
    assert_eq!(h.cmd(0, "ifconfig up"), "Done\n");
    assert_eq!(h.cmd(0, "thread start"), "Done\n");
    h.wait_state(0, "leader", 60);
    assert_eq!(h.cmd(0, "channel"), "15\nDone\n");
    assert_eq!(h.cmd(0, "networkname"), "OTcli\nDone\n");
    assert_eq!(h.cmd(0, "rloc16").len(), "0000\nDone\n".len());

    // The others join with the dataset TLVs.
    let tlvs = line_value(&h.cmd(0, "dataset active -x"));
    for i in 1..3 {
        assert_eq!(h.cmd(i, &format!("dataset set active {tlvs}")), "Done\n");
        assert_eq!(h.cmd(i, "ifconfig up"), "Done\n");
        assert_eq!(h.cmd(i, "thread start"), "Done\n");
    }
    h.wait_state(1, "router", 300);
    // Node 2 is an end device: the Router role is not for it.
    let st2 = h.cmd(2, "state");
    assert!(st2 == "child\nDone\n" || st2 == "detached\nDone\n", "{st2}");
    h.run(60);
    assert_eq!(h.cmd(2, "state"), "child\nDone\n");

    // leaderdata
    let ld = h.cmd(1, "leaderdata");
    assert!(ld.starts_with("Partition ID: "), "{ld}");
    assert!(ld.contains("\nWeighting: 64\n"), "{ld}");
    assert!(ld.contains("\nLeader Router ID: "), "{ld}");

    // ping the leader's ML-EID from node 1
    let mleid = line_value(&h.cmd(0, "ipaddr mleid"));
    assert!(mleid.starts_with("fd"), "{mleid}");
    assert_eq!(h.cmd(1, &format!("ping {mleid} 8 2 1")), "");
    let o = h.wait_for(1, "Done", 30);
    assert!(
        o.contains(&format!("16 bytes from {mleid}: icmp_seq=1 hlim=64 time=")),
        "{o}"
    );
    assert!(o.contains("icmp_seq=2 hlim=64 time="), "{o}");
    assert!(
        o.contains("2 packets transmitted, 2 packets received. Packet loss = 0.0%. Round-trip min/avg/max = "),
        "{o}"
    );
    assert!(o.ends_with("Done\n"), "{o}");

    // and back, from the leader to node 1's ML-EID
    let mleid1 = line_value(&h.cmd(1, "ipaddr mleid"));
    assert_eq!(h.cmd(0, &format!("ping async {mleid1}")), "Done\n");
    let o = h.wait_for(0, "packets transmitted", 10);
    assert!(
        o.contains(&format!("bytes from {mleid1}: icmp_seq=1")),
        "{o}"
    );
    assert!(
        !o.contains("Done"),
        "async ping prints no Done after the statistics: {o}"
    );

    // A ping to an address nobody has times out with 100% loss.
    assert_eq!(h.cmd(1, "ping fd00:dead:beef::1 8 1 1 64 1"), "");
    let o = h.wait_for(1, "Done", 30);
    assert_eq!(
        o,
        "1 packets transmitted, 0 packets received. Packet loss = 100.0%.\nDone\n"
    );

    // router table on the leader
    let rt = h.cmd(0, "router table");
    let mut l = rt.lines();
    assert_eq!(
        l.next().unwrap(),
        "| ID | RLOC16 | Next Hop | Path Cost | LQ In | LQ Out | Age | Extended MAC     | Link |"
    );
    assert_eq!(
        l.next().unwrap(),
        "+----+--------+----------+-----------+-------+--------+-----+------------------+------+"
    );
    let rows: Vec<_> = l.collect();
    assert_eq!(rows.last().unwrap(), &"Done");
    assert!(rows.len() >= 3, "{rt}");
    assert!(rows.iter().any(|r| r.contains("0200000000000002")), "{rt}");
    let rl = h.cmd(0, "router list");
    assert!(
        rl.ends_with("\nDone\n") && rl.starts_with(|c: char| c.is_ascii_digit()),
        "{rl}"
    );

    // child table on the leader (or on router 1 if the end device attached there)
    let (ct0, ct1) = (h.cmd(0, "child table"), h.cmd(1, "child table"));
    let ct = if ct0.contains("0200000000000003") {
        ct0
    } else {
        ct1
    };
    assert!(
        ct.starts_with(
            "| ID  | RLOC16 | Timeout    | Age        | LQ In | C_VN |R|D|N|Ver|CSL|QMsgCnt|Suprvsn| Extended MAC     |\n"
        ),
        "{ct}"
    );
    assert!(ct.contains("0200000000000003"), "{ct}");
    assert!(ct.contains("|1|0|0|"), "R=1 D=0: {ct}");

    // neighbor table
    let nt = h.cmd(0, "neighbor table");
    assert!(
        nt.starts_with(
            "| Role | RLOC16 | Age | Avg RSSI | Last RSSI | LQ In |R|D|N| Extended MAC     | Version |\n"
        ),
        "{nt}"
    );
    assert!(nt.contains("0200000000000002"), "{nt}");

    // router <id> for the neighbor router (by RLOC16) and for an unused ID
    let ri = h.cmd(0, "router 0x0c00");
    assert!(
        ri.starts_with("Alloc: 1\nRouter ID: 3\nRloc: 0c00\n"),
        "{ri}"
    );
    assert!(ri.contains("Link: 1\nExt Addr: 0200000000000002\n"), "{ri}");
    assert_eq!(h.cmd(0, "router 40"), "Alloc: 0\nDone\n");

    // The end device can reach the leader's RLOC through its parent.
    let rloc = line_value(&h.cmd(0, "ipaddr rloc"));
    assert_eq!(h.cmd(2, &format!("ping {rloc}")), "");
    let o = h.wait_for(2, "Done", 30);
    assert!(o.contains(&format!("bytes from {rloc}: icmp_seq=1")), "{o}");
}

#[test]
fn udp_between_nodes() {
    let mut h = H::new(&[Kind::Router, Kind::Router], 11);
    h.net.medium.connect(0, 1, -60);
    assert_eq!(h.cmd(0, "dataset init new"), "Done\n");
    assert_eq!(h.cmd(0, "dataset commit active"), "Done\n");
    assert_eq!(h.cmd(0, "ifconfig up"), "Done\n");
    assert_eq!(h.cmd(0, "thread start"), "Done\n");
    h.wait_state(0, "leader", 60);
    let tlvs = line_value(&h.cmd(0, "dataset active -x"));
    assert_eq!(h.cmd(1, &format!("dataset set active {tlvs}")), "Done\n");
    assert_eq!(h.cmd(1, "ifconfig up"), "Done\n");
    assert_eq!(h.cmd(1, "thread start"), "Done\n");
    h.wait_state(1, "router", 300);
    // A new router has no usable route to the leader until the leader's
    // advertisement reports the link back (as in OpenThread).
    h.run(60);

    assert_eq!(h.cmd(0, "udp send ::1 1 hi"), "Error 13: InvalidState\n");
    assert_eq!(h.cmd(0, "udp open"), "Done\n");
    assert_eq!(h.cmd(0, "udp open"), "Error 24: Already\n");
    assert_eq!(h.cmd(0, "udp bind :: 1234"), "Done\n");
    assert_eq!(h.cmd(1, "udp open"), "Done\n");
    assert_eq!(h.cmd(1, "udp bind :: 4321"), "Done\n");
    let mleid0 = line_value(&h.cmd(0, "ipaddr mleid"));
    let mleid1 = line_value(&h.cmd(1, "ipaddr mleid"));
    // The first datagram goes out while the address query still runs: it
    // is held until the answer arrives.
    assert_eq!(h.cmd(1, &format!("udp send {mleid0} 1234 hello")), "Done\n");
    let o = h.wait_for(0, "hello", 30);
    assert_eq!(o, format!("5 bytes from {mleid1} 4321 hello\n"));
    assert_eq!(h.cmd(0, "udp close"), "Done\n");
}

#[test]
fn scan_and_discover() {
    let mut h = H::new(&[Kind::Router, Kind::Router], 13);
    h.net.medium.connect(0, 1, -60);
    assert_eq!(h.cmd(0, "channel 15"), "Done\n");
    assert_eq!(h.cmd(0, "panid 0x1234"), "Done\n");
    assert_eq!(h.cmd(0, "networkname ScanMe"), "Done\n");
    assert_eq!(h.cmd(0, "ifconfig up"), "Done\n");
    assert_eq!(h.cmd(0, "thread start"), "Done\n");
    h.wait_state(0, "leader", 60);

    assert_eq!(h.cmd(1, "ifconfig up"), "Done\n");
    let hdr = h.cmd(1, "discover");
    assert_eq!(
        hdr,
        "| Network Name     | Extended PAN     | PAN  | MAC Address      | Ch | dBm | LQI |\n\
         +------------------+------------------+------+------------------+----+-----+-----+\n"
    );
    let o = h.wait_for(1, "Done", 60);
    assert!(o.contains("| ScanMe           | "), "{o}");
    assert!(o.contains(" | 1234 | 0200000000000001 | 15 | "), "{o}");
    assert!(o.ends_with("Done\n"), "{o}");

    let hdr = h.cmd(1, "scan 15");
    assert_eq!(
        hdr,
        "| PAN  | MAC Address      | Ch | dBm | LQI |\n+------+------------------+----+-----+-----+\n"
    );
    let o = h.wait_for(1, "Done", 60);
    assert!(o.ends_with("Done\n"), "{o}");
}

#[test]
fn netdata_prefix_and_route() {
    let mut h = H::new(&[Kind::Router], 17);
    assert_eq!(h.cmd(0, "dataset init new"), "Done\n");
    assert_eq!(h.cmd(0, "dataset commit active"), "Done\n");
    assert_eq!(h.cmd(0, "ifconfig up"), "Done\n");
    assert_eq!(h.cmd(0, "thread start"), "Done\n");
    h.wait_state(0, "leader", 60);
    assert_eq!(
        h.cmd(0, "prefix add fd00:dead:beef:cafe::/64 paros med"),
        "Done\n"
    );
    assert_eq!(h.cmd(0, "route add fd49:7770:7fc5::/64 s high"), "Done\n");
    assert_eq!(h.cmd(0, "netdata register"), "Done\n");
    h.run(10);
    let rloc = line_value(&h.cmd(0, "rloc16"));
    let nd = h.cmd(0, "netdata show");
    assert!(
        nd.starts_with(&format!(
            "Prefixes:\nfd00:dead:beef:cafe::/64 paros med {rloc}\nRoutes:\nfd49:7770:7fc5:0::/64 s high {rloc}\nServices:\n"
        )),
        "{nd}"
    );
    assert!(nd.ends_with("Done\n"));
    // The SLAAC address of the on-mesh prefix shows up in ipaddr.
    assert!(h.cmd(0, "ipaddr").contains("fd00:dead:beef:cafe:"));
    assert_eq!(h.cmd(0, "prefix remove fd00:dead:beef:cafe::/64"), "Done\n");
    assert_eq!(h.cmd(0, "route remove fd49:7770:7fc5::/64"), "Done\n");
    h.run(10);
    let nd = h.cmd(0, "netdata show");
    assert!(nd.starts_with("Prefixes:\nRoutes:\nServices:\n"), "{nd}");
}

#[test]
fn commissioner_and_joiner() {
    let mut h = H::new(&[Kind::Router, Kind::Router], 19);
    h.net.medium.connect(0, 1, -60);
    assert_eq!(h.cmd(0, "dataset init new"), "Done\n");
    assert_eq!(
        h.cmd(0, "dataset pskc 3aa55f91ca47d1e4e71a08cb35e91591"),
        "Done\n"
    );
    assert_eq!(h.cmd(0, "dataset commit active"), "Done\n");
    assert_eq!(h.cmd(0, "ifconfig up"), "Done\n");
    assert_eq!(h.cmd(0, "thread start"), "Done\n");
    h.wait_state(0, "leader", 60);
    let o = h.cmd(0, "commissioner start");
    assert!(o.starts_with("Done\n"), "{o}");
    let o = o + &h.wait_for(0, "Commissioner: active", 30);
    assert!(o.contains("Commissioner: active\n"), "{o}");
    assert_eq!(h.cmd(0, "commissioner state"), "active\nDone\n");
    assert_eq!(h.cmd(0, "commissioner joiner add * J01NU5"), "Done\n");
    h.run(5);

    assert_eq!(h.cmd(1, "ifconfig up"), "Done\n");
    assert_eq!(h.cmd(1, "joiner state"), "Idle\nDone\n");
    assert_eq!(h.cmd(1, "joiner start J01NU5"), "Done\n");
    let o = h.wait_for(1, "Join ", 120);
    assert!(o.contains("Join success\n"), "{o}");
    assert_eq!(h.cmd(1, "thread start"), "Done\n");
    h.wait_state(1, "router", 300);
}
