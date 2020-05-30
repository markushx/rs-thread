extern crate bindgen;
extern crate cmake;

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

    //./vendor/openthread/src/lib/spinel/libopenthread-spinel-ncp.a
    //./vendor/openthread/src/lib/hdlc/libopenthread-hdlc.a

    println!("cargo:include={}", fs::canonicalize(&include).unwrap().display());

    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    //println!("cargo:rustc-link-lib=bz2");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    let output = Command::new("sh")
    .current_dir(&src)
    .arg("-c")
    .arg("./bootstrap")
    .output()
    .expect("failed to execute process");
    println!("mab:bootstrap_done stdout: {:}", std::str::from_utf8(&output.stdout).unwrap());
    println!("mab:bootstrap_done stderr: {:}", std::str::from_utf8(&output.stderr).unwrap());

    let output = Command::new("sh")
    .current_dir(&src)
    .arg("-c")
    .arg("./configure --enable-cli --enable-ftd")
    .output()
    .expect("failed to execute process");
    println!("mab:configure_done stdout: {:}", std::str::from_utf8(&output.stdout).unwrap());
    println!("mab:configure_done stderr: {:}", std::str::from_utf8(&output.stderr).unwrap());

    let output = Command::new("make")
    .current_dir(&src)
//    .arg("-f ../../Makefile-rustlib")
    .output()
    .expect("failed to execute process");
    println!("mab:make_done stdout: {:}", std::str::from_utf8(&output.stdout).unwrap());
    println!("mab:make_done stderr: {:}", std::str::from_utf8(&output.stderr).unwrap());

    /*
    println!(
        "cargo:rerun-if-changed={}",
        src.join("CMakeLists.txt").display()
    );

    let mut cmk = cmake::Config::new(&src);
    cmk.build_target("lib");
    let mut dst = cmk.build();
    dst.push("build");
    dst.push("library");
    println!(
        "cargo:rustc-link-search=native={}",
        dst.to_str().expect("link-search UTF-8 error")
    );
    */

    println!("cargo:rustc-link-search=native={}", fs::canonicalize(&out_core_dir).unwrap().display());
    println!("cargo:rustc-link-search=native={}", fs::canonicalize(&out_cli_dir).unwrap().display());
    println!("cargo:rustc-link-search=native={}", fs::canonicalize(&out_plat_dir).unwrap().display());
    println!("cargo:rustc-link-search=native={}", fs::canonicalize(&out_mbed_dir).unwrap().display());

//    println!("rustc-link-lib=openthread");
    println!("cargo:rustc-link-lib=openthread-ftd");
    println!("cargo:rustc-link-lib=openthread-cli-ftd");
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


/*

extern crate bindgen;
extern crate cmake;

//mod config;
//mod headers;
#[path = "bindgen.rs"]
mod mod_bindgen;
#[path = "cmake.rs"]
mod mod_cmake;

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn have_feature(feature: &'static str) -> bool {
    env::var_os(
        format!("CARGO_FEATURE_{}", feature)
            .to_uppercase()
            .replace("-", "_"),
    )
    .is_some()
}

struct BuildConfig {
    out_dir: PathBuf,
    mbedtls_src: PathBuf,
    config_h: PathBuf,
}

impl BuildConfig {
    fn create_config_h(&self) {
        let target = env::var("TARGET").unwrap();
        let mut defines = config::DEFAULT_DEFINES
            .iter()
            .cloned()
            .collect::<HashMap<_, _>>();
        for &(feat, def) in config::FEATURE_DEFINES {
            if (feat == "std") && (target == "x86_64-fortanix-unknown-sgx") {
                continue;
            }
            if have_feature(feat) {
                defines.insert(def.0, def.1);
            }
        }

        File::create(&self.config_h)
            .and_then(|mut f| {
                f.write_all(config::PREFIX.as_bytes())?;
                for (name, def) in defines {
                    f.write_all(def.define(name).as_bytes())?;
                }
                if have_feature("custom_printf") {
                    writeln!(f, "int mbedtls_printf(const char *format, ...);")?;
                }
                if have_feature("custom_threading") {
                    writeln!(f, "typedef void* mbedtls_threading_mutex_t;")?;
                }
                f.write_all(config::SUFFIX.as_bytes())
            })
            .expect("config.h I/O error");
    }

    fn print_rerun_files(&self) {
        println!("cargo:rerun-if-env-changed=RUST_MBEDTLS_SYS_SOURCE");
        println!(
            "cargo:rerun-if-changed={}",
            self.mbedtls_src.join("CMakeLists.txt").display()
        );
        let include = self.mbedtls_src.join(Path::new("include").join("mbedtls"));
        for h in headers::enabled_ordered() {
            println!("cargo:rerun-if-changed={}", include.join(h).display());
        }
        for f in self
            .mbedtls_src
            .join("library")
            .read_dir()
            .expect("read_dir failed")
        {
            println!(
                "cargo:rerun-if-changed={}",
                f.expect("DirEntry failed").path().display()
            );
        }
    }
}

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR environment not set?"));
    let src = PathBuf::from(env::var("RUST_MBEDTLS_SYS_SOURCE").unwrap_or("vendor".to_owned()));
    let cfg = BuildConfig {
        config_h: out_dir.join("config.h"),
        out_dir: out_dir,
        mbedtls_src: src,
    };

    cfg.create_config_h();
    cfg.print_rerun_files();
    cfg.cmake();
    cfg.bindgen();
}
*/