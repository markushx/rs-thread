# rs-matter-sc with early CASE acknowledgements

Copy of `rs-matter-sc` 0.4.1 from rs-matter rev 1c2e0a9 (Apache-2.0) with two
added `exchange.acknowledge()` calls in `src/case/responder.rs` (Sigma1 and
Sigma3), and a standalone `Cargo.toml` (workspace inheritance replaced by the
same git revision). Used through `[patch]` in the workspace manifests. Drop
this directory once rs-matter acknowledges slow responses itself (see the
`MRP_STANDALONE_ACK_TIMEOUT_MS` TODO in `rs-matter-transport/src/mrp.rs`).
