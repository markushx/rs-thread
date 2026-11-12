fn main() {
    // memory.x for cortex-m-rt's link.x
    let dir = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rustc-link-search={}", dir.display());
    println!("cargo:rerun-if-changed=memory.x");
}
