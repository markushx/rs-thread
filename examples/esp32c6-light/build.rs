fn main() {
    // Build-time Thread network: the Active Dataset (TLVs, hex) in
    // RSTHREAD_DATASET is embedded; without it the file is empty and the
    // light forms its own standalone network.
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
    // TLV framing sanity check.
    let mut p = 0;
    while p < bytes.len() {
        assert!(
            p + 2 <= bytes.len()
                && bytes[p + 1] != 0xff
                && p + 2 + bytes[p + 1] as usize <= bytes.len(),
            "RSTHREAD_DATASET is not a valid TLV list (offset {p})"
        );
        p += 2 + bytes[p + 1] as usize;
    }
    assert!(bytes.len() <= 254, "RSTHREAD_DATASET longer than a dataset");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("dataset.bin"), bytes).unwrap();
}
