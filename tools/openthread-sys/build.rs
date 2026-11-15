//! Builds OpenThread (simulation platform, virtual time) with cmake and ninja
//! into `OUT_DIR`, links the static libraries and generates the bindings.
//!
//! Nothing is written to the OpenThread source tree and no system package is
//! installed. The source tree is `vendor/openthread` or `$OPENTHREAD_SRC`.
//! The reference CLI nodes (`ot-cli-ftd`, with feature `mtd` also
//! `ot-cli-mtd`) are copied to `<target dir>/ot-sim/` and their directory is
//! exported to dependents as `DEP_OPENTHREAD_BIN_DIR`.

extern crate bindgen;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn run(cmd: &mut Command, what: &str) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("cannot run {what}: {e} (cmake and ninja must be installed)"));
    assert!(status.success(), "{} failed: {}", what, status);
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-env-changed=OPENTHREAD_SRC");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");
    let src = env::var_os("OPENTHREAD_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("vendor/openthread"));
    let src = fs::canonicalize(&src).unwrap_or_else(|e| {
        panic!(
            "OpenThread source {} not found ({e}); run `git submodule update --init` or set OPENTHREAD_SRC",
            src.display()
        )
    });
    let include = src.join("include");
    println!("cargo:include={}", include.display());

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let build = out.join("ot-build");
    let mtd = env::var_os("CARGO_FEATURE_MTD").is_some();

    let mut conf = Command::new("cmake");
    conf.args(["-GNinja", "-DCMAKE_BUILD_TYPE=MinSizeRel"])
        .arg("-DOT_PLATFORM=simulation")
        .args([
            "-DBUILD_TESTING=OFF",
            "-DOT_SIMULATION_VIRTUAL_TIME=ON",
            "-DOT_SIMULATION_INFRA_IF=OFF",
            "-DOT_THREAD_VERSION=1.4",
            "-DOT_FTD=ON",
            "-DOT_RCP=OFF",
            "-DOT_APP_NCP=OFF",
            "-DOT_APP_RCP=OFF",
            "-DOT_COMPILE_WARNING_AS_ERROR=OFF",
            // Features the thread-cert scripts rely on (as OpenThread's
            // `script/test build`).
            "-DOT_ANYCAST_LOCATOR=ON",
            "-DOT_DNS_CLIENT=ON",
            "-DOT_DNS_DSO=OFF",
            "-DOT_ECDSA=ON",
            "-DOT_LOG_OUTPUT=PLATFORM_DEFINED",
            "-DOT_COAP=ON",
            "-DOT_COAP_BLOCK=ON",
            "-DOT_COAP_OBSERVE=ON",
            "-DOT_CHANNEL_MANAGER=ON",
            "-DOT_CHANNEL_MONITOR=ON",
            "-DOT_DATASET_UPDATER=ON",
            "-DOT_DHCP6_CLIENT=ON",
            "-DOT_DHCP6_SERVER=ON",
            "-DOT_DIAGNOSTIC=ON",
            "-DOT_IP6_FRAGM=ON",
            "-DOT_JAM_DETECTION=ON",
            "-DOT_LOG_LEVEL_DYNAMIC=ON",
            "-DOT_MAC_FILTER=ON",
            "-DOT_NEIGHBOR_DISCOVERY_AGENT=ON",
            "-DOT_NETDIAG_CLIENT=ON",
            "-DOT_SNTP_CLIENT=ON",
            "-DOT_COAPS=ON",
            "-DOT_DNSSD_SERVER=ON",
            "-DOT_HISTORY_TRACKER=ON",
            "-DOT_NETDATA_PUBLISHER=ON",
            "-DOT_PING_SENDER=ON",
            "-DOT_REFERENCE_DEVICE=ON",
            "-DOT_SERVICE=ON",
            "-DOT_SRP_CLIENT=ON",
            "-DOT_SRP_SERVER=ON",
            "-DOT_UPTIME=ON",
            "-DOT_DUA=ON",
            "-DOT_MLR=ON",
            "-DOT_CSL_RECEIVER=ON",
            "-DOT_LINK_METRICS_INITIATOR=ON",
            "-DOT_LINK_METRICS_SUBJECT=ON",
            "-DOT_LINK_METRICS_MANAGER=ON",
            "-DOT_COMMISSIONER=ON",
            "-DOT_JOINER=ON",
        ]);
    conf.arg(format!("-DOT_MTD={}", if mtd { "ON" } else { "OFF" }));
    conf.arg("-S").arg(&src).arg("-B").arg(&build);
    run(&mut conf, "cmake configure");

    let mut targets = vec!["ot-cli-ftd"];
    if mtd {
        targets.push("ot-cli-mtd");
    }
    run(
        Command::new("ninja").arg("-C").arg(&build).args(&targets),
        "ninja",
    );

    // Executables for the thread-cert harness: `<target dir>/ot-sim/`.
    let bin_dir = out
        .ancestors()
        .nth(4)
        .map(|t| t.join("ot-sim"))
        .unwrap_or_else(|| out.join("bin"));
    fs::create_dir_all(&bin_dir).unwrap();
    for t in &targets {
        let from = build.join("examples/apps/cli").join(t);
        fs::copy(&from, bin_dir.join(t))
            .unwrap_or_else(|e| panic!("cannot copy {}: {e}", from.display()));
    }
    println!("cargo:bin_dir={}", bin_dir.display());

    // Link the static libraries of the build.
    for dir in [
        "src/core",
        "src/cli",
        "src/lib/platform",
        "src/lib/url",
        "src/lib/spinel",
        "src/lib/hdlc",
        "src/lib/utils",
        "examples/platforms/simulation",
        "examples/platforms/utils",
        "third_party/mbedtls",
        "third_party/mbedtls/repo/library",
        "third_party/mbedtls/repo/3rdparty/everest",
        "third_party/mbedtls/repo/3rdparty/p256-m",
        "third_party/tcplp",
    ] {
        let p = build.join(dir);
        if p.is_dir() {
            println!("cargo:rustc-link-search=native={}", p.display());
        }
    }
    println!("cargo:rustc-link-lib=openthread-ftd");
    if cfg!(feature = "cli") {
        println!("cargo:rustc-link-lib=openthread-cli-ftd");
    }
    println!("cargo:rustc-link-lib=tcplp-ftd");
    println!("cargo:rustc-link-lib=openthread-simulation");
    println!("cargo:rustc-link-lib=openthread-platform");
    println!("cargo:rustc-link-lib=c++");
    println!("cargo:rustc-link-lib=mbedtls");
    println!("cargo:rustc-link-lib=mbedx509");
    println!("cargo:rustc-link-lib=mbedcrypto");
    println!("cargo:rustc-link-lib=everest");
    println!("cargo:rustc-link-lib=p256m");

    gen_bindings(&include, &out);
}

fn gen_bindings(include: &Path, out: &Path) {
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", include.display()))
        .clang_arg(format!("-I{}", include.join("platform").display()))
        .allowlist_function("ot.*")
        .allowlist_var("OT.*")
        .use_core()
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file(out.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
