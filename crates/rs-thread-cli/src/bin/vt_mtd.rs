//! `rs-thread-cli-vt-mtd`: `rs-thread-cli-vt` built as a minimal thread
//! device (no router role, no commissioner, no Border Agent), like
//! OpenThread's `ot-cli-mtd`.

#![allow(clippy::std_instead_of_core)]

#[path = "vt.rs"]
mod vt;

fn main() {
    vt::main();
}
