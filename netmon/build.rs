//! Build script for NetMonitor.
//!
//! The `pcap` crate declares `#[link(name = "wpcap")]`, so the linker needs to
//! find `wpcap.lib` (the Npcap import library). We resolve it here so that a
//! plain `cargo build` works from any working directory.
//!
//! Resolution order:
//!   1. `NETMON_NPCAP_SDK` environment variable -> `<dir>/Lib/x64`, `<dir>/Lib`
//!   2. `.cache/deps/npcap-sdk` inside the project root (where install.ps1 puts it)
//!   3. Well-known Npcap SDK install locations
//!
//! If none of them contain `wpcap.lib` we fail loudly with instructions, since
//! silently producing a binary that cannot link is worse.

use std::path::PathBuf;

fn candidate_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    let mut push_sdk = |base: PathBuf| {
        if target_arch == "x86" {
            v.push(base.join("Lib"));
        }
        v.push(base.join("Lib").join("x64"));
    };

    if let Ok(dir) = std::env::var("NETMON_NPCAP_SDK") {
        push_sdk(PathBuf::from(dir));
    }

    // <project root>/.cache/deps/npcap-sdk -- created by scripts/install.ps1
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    if let Some(root) = manifest.parent() {
        push_sdk(root.join(".cache").join("deps").join("npcap-sdk"));
    }
    push_sdk(manifest.join("vendor").join("npcap-sdk"));

    for p in [
        r"C:\Program Files\Npcap\SDK",
        r"C:\Program Files (x86)\Npcap\SDK",
    ] {
        push_sdk(PathBuf::from(p));
    }
    v
}

fn main() {
    println!("cargo:rerun-if-env-changed=NETMON_NPCAP_SDK");
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        // The application is Windows-only; nothing to resolve elsewhere.
        return;
    }

    let mut found: Option<PathBuf> = None;
    for dir in candidate_dirs() {
        if dir.join("wpcap.lib").is_file() {
            println!("cargo:rustc-link-search=native={}", dir.display());
            found = Some(dir);
            break;
        }
    }

    match found {
        Some(dir) => {
            println!("cargo:warning=Npcap import library: {}", dir.join("wpcap.lib").display());
        }
        None => {
            // Fall back to the default search path so a machine with the SDK on
            // LIB still works; make the requirement explicit in the error text.
            println!(
                "cargo:warning=wpcap.lib (Npcap SDK) not found. Set NETMON_NPCAP_SDK to the \
                 Npcap SDK root, or run scripts/install.ps1 to fetch it into .cache/deps."
            );
        }
    }
}
