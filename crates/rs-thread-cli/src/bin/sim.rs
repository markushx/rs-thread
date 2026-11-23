//! `rs-thread-cli-sim`: OpenThread-style CLI prompts for simulated nodes.
//!
//! Reads commands from stdin and prints the output of the OpenThread CLI
//! (prompt `> `), on one node or on several nodes that share a simulated
//! radio medium with virtual time.
//!
//! ```text
//! rs-thread-cli-sim [--nodes N] [--end-devices K] [--seed S] [--isolated]
//!
//! > 1 dataset init new          # "<node> <command>"; node 1 is the first
//! > 1 dataset commit active
//! > run 10                      # advance virtual time by 10 s
//! > link 1 2 -60                # radio link between node 1 and 2 (RSSI)
//! > exit
//! ```
//!
//! With one node the node number can be left out. Nodes are routers, the
//! last `K` are minimal end devices; they all hear each other unless
//! `--isolated` is given (then add links with `link`). Time only passes in
//! `run`; asynchronous output (ping replies, scan results) appears while
//! time runs.

use std::io::{BufRead, Write};

use rs_thread_cli::Cli;
use rs_thread_core::time::Duration;
use rs_thread_sim::{Kind, Network};

struct Sim {
    net: Network,
    cli: Vec<Cli>,
}

/// Output of a command: collected, then printed.
type Out = String;

impl Sim {
    fn command(&mut self, node: usize, line: &str, out: &mut Out) {
        let cli = &mut self.cli[node];
        self.net
            .with(node, |inst, now| cli.process_line(inst, now, line, out));
        self.pump(out);
    }

    fn pump(&mut self, out: &mut Out) {
        let single = self.cli.len() == 1;
        for i in 0..self.cli.len() {
            let events = self.net.take_events(i);
            let mut text = Out::new();
            let cli = &mut self.cli[i];
            self.net.with(i, |inst, now| {
                for ev in &events {
                    cli.handle_event(inst, now, ev, &mut text);
                }
                cli.poll(inst, now, &mut text);
            });
            for l in text.split_inclusive('\n') {
                if !single {
                    out.push_str(&format!("[{}] ", i + 1));
                }
                out.push_str(l);
            }
        }
    }

    fn run(&mut self, secs: f64, out: &mut Out) {
        let steps = (secs * 10.0) as u64;
        for _ in 0..steps {
            self.net.run_for(Duration::from_millis(100));
            self.pump(out);
        }
    }
}

fn main() {
    let mut nodes = 1usize;
    let mut end_devices = 0usize;
    let mut seed = 1u64;
    let mut isolated = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut num = |name: &str| -> u64 {
            args.next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("{name} needs a number"))
        };
        match a.as_str() {
            "--nodes" => nodes = num("--nodes") as usize,
            "--end-devices" => end_devices = num("--end-devices") as usize,
            "--seed" => seed = num("--seed"),
            "--isolated" => isolated = true,
            _ => {
                eprintln!(
                    "usage: rs-thread-cli-sim [--nodes N] [--end-devices K] [--seed S] [--isolated]"
                );
                std::process::exit(2);
            }
        }
    }
    let end_devices = end_devices.min(nodes);
    let kinds: Vec<Kind> = (0..nodes)
        .map(|i| {
            if i >= nodes - end_devices {
                Kind::EndDevice
            } else {
                Kind::Router
            }
        })
        .collect();
    let mut sim = Sim {
        net: Network::new(&kinds, seed),
        cli: kinds.iter().map(|_| Cli::new()).collect(),
    };
    if !isolated {
        for a in 0..nodes {
            for b in a + 1..nodes {
                sim.net.medium.connect(a, b, -60);
            }
        }
    }

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    loop {
        let _ = write!(stdout, "> ");
        let _ = stdout.flush();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let line = line.trim();
        let mut out = Out::new();
        let mut words = line.split_whitespace();
        match words.next() {
            None => {}
            Some("exit") => break,
            Some("run") => {
                let secs = words.next().and_then(|s| s.parse().ok()).unwrap_or(1.0);
                sim.run(secs, &mut out);
                out.push_str("Done\r\n");
            }
            Some("link") => {
                let v: Vec<i64> = words.filter_map(|w| w.parse().ok()).collect();
                if v.len() >= 2 && v[0] >= 1 && v[1] >= 1 {
                    let rssi = v.get(2).copied().unwrap_or(-60) as i8;
                    sim.net
                        .medium
                        .connect((v[0] - 1) as usize, (v[1] - 1) as usize, rssi);
                    out.push_str("Done\r\n");
                } else {
                    out.push_str("Error 7: InvalidArgs\r\n");
                }
            }
            Some(first) => {
                let (node, rest) = match first.parse::<usize>() {
                    Ok(n) if nodes > 1 || n == 1 => (n, line[first.len()..].trim()),
                    _ => (1, line),
                };
                if node == 0 || node > nodes {
                    out.push_str("Error 7: InvalidArgs\r\n");
                } else {
                    sim.command(node - 1, rest, &mut out);
                }
            }
        }
        let _ = stdout.write_all(out.as_bytes());
    }
}
