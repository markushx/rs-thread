extern crate bindgen;

use std::fs;
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let src = PathBuf::from("./vendor/openthread/");
    let include = PathBuf::from("./vendor/openthread/include");
    let out_core_dir = PathBuf::from("./vendor/openthread/src/core/");
    let out_cli_dir = PathBuf::from("./vendor/openthread/src/cli/");
    let out_plat_dir = PathBuf::from("./vendor/openthread/src/lib/platform/");
    let out_mbed_dir = PathBuf::from("./vendor/openthread/third_party/mbedtls/");

    // not packaged yet
    //./vendor/openthread/src/lib/spinel/libopenthread-spinel-ncp.a
    //./vendor/openthread/src/lib/hdlc/libopenthread-hdlc.a

    println!("cargo:include={}", fs::canonicalize(&include).unwrap().display());

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    let output = Command::new("sh")
    .current_dir(&src)
    .arg("-c")
    .arg("./bootstrap")
    .output()
    .expect("failed to execute bootstrap");
    println!("mab:bootstrap_done stdout: {:}", std::str::from_utf8(&output.stdout).unwrap());
    println!("mab:bootstrap_done stderr: {:}", std::str::from_utf8(&output.stderr).unwrap());

    let output = Command::new("sh")
    .current_dir(&src)
    .arg("-c")
    .arg("./configure --enable-cli --enable-ftd --with-examples=no --disable-tools --disable-docs")
    .output()
    .expect("failed to execute configure");
    println!("mab:configure_done stdout: {:}", std::str::from_utf8(&output.stdout).unwrap());
    println!("mab:configure_done stderr: {:}", std::str::from_utf8(&output.stderr).unwrap());

    let output = Command::new("sh")
    .current_dir(&src)
    .arg("-c")
    .arg("make")
    .output()
    .expect("failed to execute make");
    println!("mab:make_done stdout: {:}", std::str::from_utf8(&output.stdout).unwrap());
    println!("mab:make_done stderr: {:}", std::str::from_utf8(&output.stderr).unwrap());

    println!("cargo:rustc-link-search=native={}", fs::canonicalize(&out_core_dir).unwrap().display());
    println!("cargo:rustc-link-search=native={}", fs::canonicalize(&out_cli_dir).unwrap().display());
    println!("cargo:rustc-link-search=native={}", fs::canonicalize(&out_plat_dir).unwrap().display());
    println!("cargo:rustc-link-search=native={}", fs::canonicalize(&out_mbed_dir).unwrap().display());

    // println!("rustc-link-lib=openthread");
    if cfg!(feature = "ftd") {
        println!("cargo:rustc-link-lib=openthread-ftd");
        if cfg!(feature = "cli") {
            println!("cargo:rustc-link-lib=openthread-cli-ftd");
        }
    }
    println!("cargo:rustc-link-lib=openthread-platform");
    println!("cargo:rustc-link-lib=mbedcrypto");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .clang_arg("-Ivendor/openthread/include")
        .clang_arg("-Ivendor/openthread/include/platform")
        .whitelist_function("ot.*")
        .whitelist_var("OT.*")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
