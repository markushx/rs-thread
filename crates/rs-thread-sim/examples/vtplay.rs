//! Interactive driver for mixed OpenThread / rs-thread virtual-time networks.
//!
//! ```text
//! cargo run -p rs-thread-sim --example vtplay -- 1:ot 2:rust 3:ot
//! > 1 dataset init new            node 1 runs a command
//! > run 10                        advance virtual time by 10 s
//! > ping 2 fe80::1                send a command, advance 3 s, print the output
//! > sniff                         frames seen since the last call
//! ```
//!
//! `OT_CLI_PATH` / `RSTHREAD_CLI_VT` select the programs (see `vtsim`).

#![allow(clippy::std_instead_of_core, clippy::print_stdout)]

use std::io::BufRead;

use rs_thread_sim::vtsim::{VtSim, rs_thread_cli_vt, ot_cli_ftd};

fn main() {
    let ot = ot_cli_ftd().expect("ot-cli-ftd");
    let rust = rs_thread_cli_vt().expect("rs-thread-cli-vt");
    let mut sim = VtSim::new(240).expect("simulator");
    let dir = std::env::temp_dir().join(format!("vtplay-{}", std::process::id()));
    for spec in std::env::args().skip(1) {
        let (id, kind) = spec.split_once(':').expect("<id>:<ot|rust>");
        let id: u16 = id.parse().expect("node id");
        let exe = if kind == "rust" { &rust } else { &ot };
        sim.spawn(id, exe, &dir.join(format!("n{id}"))).unwrap();
    }
    let mut seen = 0;
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let line = line.trim();
        if let Some(s) = line.strip_prefix("run ") {
            sim.run(s.parse().unwrap());
            println!("t = {:.3} s", sim.now_us() as f64 / 1e6);
        } else if line == "sniff" {
            for f in &sim.sniffed[seen..] {
                let kind = match f.psdu.first().map(|b| b & 7) {
                    Some(0) => "beacon",
                    Some(1) => "data",
                    Some(2) => "ack",
                    Some(3) => "cmd",
                    _ => "?",
                };
                println!(
                    "{:>10} us node {} ch {} {kind} len {} {}",
                    f.time,
                    f.node,
                    f.channel,
                    f.psdu.len(),
                    f.psdu
                        .iter()
                        .take(40)
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                );
            }
            seen = sim.sniffed.len();
        } else if let Some((id, cmd)) = line.split_once(' ')
            && let Ok(id) = id.parse::<u16>()
        {
            if cmd.starts_with("ping") || cmd.starts_with("scan") {
                sim.send(id, cmd);
                sim.run(3.0);
                for l in sim.drain(id) {
                    println!("{l}");
                }
            } else {
                for l in sim.cmd(id, cmd) {
                    println!("{l}");
                }
            }
        }
    }
}
