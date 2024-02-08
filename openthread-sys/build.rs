extern crate bindgen;

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let src = PathBuf::from("./vendor/openthread/");
    let include = PathBuf::from("./vendor/openthread/include");
    let out_core_dir = PathBuf::from("./vendor/openthread/build/simulation/src/core/");
    let out_cli_dir = PathBuf::from("./vendor/openthread/build/simulation/src/cli/");
    let out_plat_dir = PathBuf::from("./vendor/openthread/build/simulation/src/lib/platform/");
    let out_mbed_dir = PathBuf::from("./vendor/openthread/build/simulation/third_party/mbedtls/repo/library");
    let out_tcplp_dir = PathBuf::from("./vendor/openthread/build/simulation/third_party/tcplp");

    // not packaged yet
    //./vendor/openthread/build/simulation/src/lib/spinel/libopenthread-spinel-ncp.a
    //./vendor/openthread/build/simulation/src/lib/hdlc/libopenthread-hdlc.a

    println!(
        "cargo:include={}",
        fs::canonicalize(&include).unwrap().display()
    );

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    let output = Command::new("sh")
        .current_dir(&src)
        .arg("-c")
        .arg("./script/bootstrap")
        .output()
        .expect("failed to execute bootstrap");
    println!(
        "mab:bootstrap_done stdout: {:}",
        std::str::from_utf8(&output.stdout).unwrap()
    );
    println!(
        "mab:bootstrap_done stderr: {:}",
        std::str::from_utf8(&output.stderr).unwrap()
    );

    let output = Command::new("sh")
        .current_dir(&src)
        .arg("-c")
        .arg("./script/cmake-build simulation")
        .output()
        .expect("failed to execute cmake-build");
    println!(
        "mab:cmake-build_done stdout: {:}",
        std::str::from_utf8(&output.stdout).unwrap()
    );
    println!(
        "mab:cmake-build_done stderr: {:}",
        std::str::from_utf8(&output.stderr).unwrap()
    );

    println!(
        "cargo:rustc-link-search=native={}",
        fs::canonicalize(&out_core_dir).unwrap().display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        fs::canonicalize(&out_cli_dir).unwrap().display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        fs::canonicalize(&out_plat_dir).unwrap().display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        fs::canonicalize(&out_mbed_dir).unwrap().display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        fs::canonicalize(&out_tcplp_dir).unwrap().display()
    );

    println!("cargo:rustc-link-lib=openthread-radio");
    if cfg!(feature = "ftd") {
        println!("cargo:rustc-link-lib=openthread-ftd");
        println!("cargo:rustc-link-lib=tcplp-ftd");
        if cfg!(feature = "cli") {
            println!("cargo:rustc-link-lib=openthread-cli-ftd");
            println!("cargo:rustc-link-lib=openthread-radio-cli");
        }
    }
    println!("cargo:rustc-link-lib=openthread-platform");
    println!("cargo:rustc-link-lib=mbedcrypto");
    println!("cargo:rustc-link-lib=gcov");
    println!("cargo:rustc-link-lib=mbedtls");
    println!("cargo:rustc-link-lib=mbedx509");
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
        .allowlist_function("ot.*")
        .allowlist_var("OT.*")
        .use_core()
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
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
