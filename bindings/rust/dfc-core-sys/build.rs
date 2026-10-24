use std::{env, fs, path::Path, path::PathBuf};

fn rerun_for_tree(path: &Path) {
    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .map(|entry| entry.expect("cannot read native source entry"))
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            rerun_for_tree(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn exactly_one<'a>(features: &[(&'a str, bool)], kind: &str) -> &'a str {
    let enabled: Vec<_> = features
        .iter()
        .filter(|(_, on)| *on)
        .map(|(n, _)| *n)
        .collect();
    if enabled.len() != 1 {
        panic!("select exactly one {kind} feature; selected: {enabled:?}");
    }
    enabled[0]
}

fn main() {
    let bundled = cfg!(feature = "bundled");
    let system = cfg!(feature = "system");
    if bundled == system {
        panic!("select exactly one of `bundled` or `system`");
    }

    let role = exactly_one(
        &[
            ("simulator", cfg!(feature = "role-simulator")),
            ("host", cfg!(feature = "role-host")),
            ("target", cfg!(feature = "role-target")),
        ],
        "role",
    );
    let profile = exactly_one(
        &[
            ("minimal_ev1", cfg!(feature = "profile-minimal-ev1")),
            ("full_ev1", cfg!(feature = "profile-full-ev1")),
            ("full_ev2", cfg!(feature = "profile-full-ev2")),
            ("full_ev3", cfg!(feature = "profile-full-ev3")),
            ("minimal_ev3", cfg!(feature = "profile-minimal-ev3")),
        ],
        "profile",
    );
    #[cfg(not(feature = "bundled"))]
    let _ = profile;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    println!(
        "cargo:rerun-if-changed={}",
        root.join("CMakeLists.txt").display()
    );
    for directory in ["src", "ffi", "port"] {
        rerun_for_tree(&root.join(directory));
    }
    let bridge_header = if role == "target" {
        "ffi/dfc_target_ffi.h"
    } else {
        "ffi/dfc_ffi.h"
    };
    println!(
        "cargo:rerun-if-changed={}",
        root.join(bridge_header).display()
    );

    if bundled {
        #[cfg(feature = "bundled")]
        {
            let mut config = cmake::Config::new(&root);
            config
                .define("DFC_ROLE", role)
                .define("DFC_PROFILE", profile)
                .define("DFC_CRYPTO", "tiny")
                .define("DFC_BUILD_SHARED", "OFF")
                .define(
                    "DFC_BUILD_STATIC_FFI",
                    if role == "target" { "OFF" } else { "ON" },
                )
                .define(
                    "DFC_BUILD_RUST_TARGET_BRIDGE",
                    if role == "target" { "ON" } else { "OFF" },
                )
                .define("DFC_BUILD_TESTS", "OFF");
            if role == "target" {
                config.define("CMAKE_TRY_COMPILE_TARGET_TYPE", "STATIC_LIBRARY");
            }
            if let Ok(path) = env::var("DFC_TINY_CRYPTO_DIR") {
                config.define("DFC_TINY_CRYPTO_DIR", path);
            }
            let destination = config.build();
            println!(
                "cargo:rustc-link-search=native={}",
                destination.join("lib").display()
            );
        }
    } else if let Ok(path) = env::var("DFC_LIB_DIR") {
        println!("cargo:rustc-link-search=native={path}");
    }
    if role == "target" {
        println!("cargo:rustc-link-lib=static=dfc_rust_target");
        println!("cargo:rustc-link-lib=static=dfc_core");
    } else if bundled || env::var_os("DFC_STATIC").is_some() {
        println!("cargo:rustc-link-lib=static=dfc");
        #[cfg(target_os = "windows")]
        println!("cargo:rustc-link-lib=bcrypt");
    } else {
        println!("cargo:rustc-link-lib=dylib=dfc");
    }
}
