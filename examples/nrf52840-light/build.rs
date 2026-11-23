use std::path::PathBuf;

fn main() {
    // memory.x for cortex-m-rt's link.x
    let dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rustc-link-search={}", dir.display());
    println!("cargo:rerun-if-changed=memory.x");

    // Build-time Thread network: the Active Dataset (TLVs, hex as printed by
    // `ot-ctl dataset active -x`) in RSTHREAD_DATASET is embedded; without
    // it the file is empty and the light forms its own network.
    println!("cargo:rerun-if-env-changed=RSTHREAD_DATASET");
    let hex: String = std::env::var("RSTHREAD_DATASET")
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let hex = hex.strip_prefix("0x").map(str::to_owned).unwrap_or(hex);
    assert!(
        hex.len() & 1 == 0 && hex.chars().all(|c| c.is_ascii_hexdigit()),
        "RSTHREAD_DATASET must be an even number of hex digits"
    );
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    // TLV framing check: type, length, value (the extended length escape
    // 0xff is not used by dataset TLVs).
    let mut p = 0;
    while p < bytes.len() {
        assert!(
            p + 2 <= bytes.len()
                && bytes[p + 1] != 0xff
                && p + 2 + bytes[p + 1] as usize <= bytes.len(),
            "RSTHREAD_DATASET is not a TLV list (offset {p})"
        );
        p += 2 + bytes[p + 1] as usize;
    }
    assert!(
        bytes.len() <= 254,
        "RSTHREAD_DATASET longer than a dataset"
    );
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("dataset.bin"), bytes).unwrap();
}
