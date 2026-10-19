//! Detects which shape of the `rustc_private` API the compiling toolchain has.
//!
//! The wrapper builds against a window of compiler versions, and some changes
//! inside that window cannot be bridged by trait shims: an item renamed, or an
//! enum variant whose arity changed. Those hang off one cfg per change, and
//! this script sets each cfg by compiling a tiny probe against the very
//! `rustc` cargo is about to build the wrapper with.
//!
//! Probing beats comparing release numbers because nightlies carry the
//! version of the release they lead to, not of the change: `UseTree` and
//! `PhantomDeref` reached nightly while it still reported 1.100, and the
//! `compiler_entrypoint` rename reached it a week after it began reporting
//! 1.101. A version gate therefore broke every 1.100 beta and stable
//! toolchain, and early 1.101 nightlies. A probe is right on all of them, and
//! a standalone `cargo build` needs no extra flags.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One `rustc_private` change the wrapper selects with a cfg.
struct Probe {
    /// The cfg set when the probe compiles.
    cfg: &'static str,
    /// Items that only compile on the newer shape.
    source: &'static str,
}

const PROBES: &[Probe] = &[
    // rust-lang/rust#163647 renamed `rustc_driver_impl::run_compiler`
    // (first nightly 2026-10-03, 1.101).
    Probe {
        cfg: "rusi_rustc_compiler_entrypoint",
        source: "pub use rustc_driver_impl::compiler_entrypoint;",
    },
    // rust-lang/rust#161349 keeps a `use` tree in one HIR item, with
    // `UseKind::Nested { items }` in place of `ListStem` (first nightly
    // 2026-09-26, 1.100).
    Probe {
        cfg: "rusi_rustc_hir_use_tree",
        source: "pub fn probe(tree: rustc_hir::UseTree<'_>) -> usize {
                     match tree.kind {
                         rustc_hir::UseKind::Nested { items } => items.len(),
                         _ => 0,
                     }
                 }",
    },
    // rust-lang/rust#159103 added `ProjectionElem::PhantomDeref` (first
    // nightly 2026-08-29, 1.100).
    Probe {
        cfg: "rusi_rustc_mir_phantom_deref",
        source: "pub fn probe(elem: rustc_middle::mir::PlaceElem<'_>) -> bool {
                     matches!(elem, rustc_middle::mir::ProjectionElem::PhantomDeref)
                 }",
    },
];

/// The crates every probe may name; the same set the wrapper links against.
const PRELUDE: &str = "#![feature(rustc_private)]
#![allow(warnings)]
extern crate rustc_driver;
extern crate rustc_driver_impl;
extern crate rustc_hir;
extern crate rustc_middle;
";

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    // Unlocks `rustc_private` on a release compiler; whether it is set
    // decides whether any probe can compile.
    println!("cargo::rerun-if-env-changed=RUSTC_BOOTSTRAP");
    for probe in PROBES {
        println!("cargo::rustc-check-cfg=cfg({})", probe.cfg);
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let probe_dir = out_dir.join("rustc-api-probes");
    if let Err(error) = fs::create_dir_all(&probe_dir) {
        println!(
            "cargo::warning=cannot create {}: {error}",
            probe_dir.display()
        );
        return;
    }

    // Without the prelude compiling, no probe can, and every cfg would stay
    // unset for a reason that has nothing to do with the API shape. Say why
    // instead; the wrapper's own compile then fails with the same cause.
    if let Err(stderr) = compile(&probe_dir, "baseline", "") {
        let reason = stderr
            .lines()
            .find(|line| line.starts_with("error"))
            .unwrap_or("the probe failed without an error line");
        println!(
            "cargo::warning=rustc_private is unavailable to this toolchain ({reason}); \
             the wrapper needs the rustc-dev component, and RUSTC_BOOTSTRAP=1 on a \
             stable or beta compiler"
        );
        return;
    }

    for probe in PROBES {
        if compile(&probe_dir, probe.cfg, probe.source).is_ok() {
            println!("cargo::rustc-cfg={}", probe.cfg);
        }
    }

    link_sysroot_llvm();
}

/// `rustc_driver` links `-lLLVM`. Some toolchains ship the LLVM library only
/// in `<sysroot>/lib` — macOS nightlies and betas installed without the
/// `llvm-tools` component — where the linker does not look, so linking the
/// wrapper failed with "library 'LLVM' not found" unless the user passed
/// `-L` by hand. Point the linker there whenever an LLVM library is present.
fn link_sysroot_llvm() {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let Ok(output) = Command::new(rustc).args(["--print", "sysroot"]).output() else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let lib = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()).join("lib");
    let has_llvm = fs::read_dir(&lib).is_ok_and(|entries| {
        entries.filter_map(Result::ok).any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("libLLVM") || name.starts_with("LLVM")
        })
    });
    if has_llvm {
        println!("cargo::rustc-link-search=native={}", lib.display());
    }
}

/// Compile `PRELUDE` plus `body` to metadata only. `Err` carries rustc's
/// stderr.
fn compile(dir: &Path, name: &str, body: &str) -> Result<(), String> {
    let source = dir.join(format!("{name}.rs"));
    fs::write(&source, format!("{PRELUDE}{body}\n")).map_err(|error| error.to_string())?;

    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let mut command = Command::new(rustc);
    command
        .args([
            "--edition",
            "2024",
            "--crate-type",
            "lib",
            "--emit",
            "metadata",
        ])
        .arg("--crate-name")
        .arg(format!("rusi_probe_{name}"))
        .arg("--out-dir")
        .arg(dir)
        .arg(&source);
    // Probe for the target being built, with the flags cargo passes to every
    // compilation of it (a `--sysroot` or `-L` there changes what resolves).
    if let (Some(target), Some(host)) = (env::var_os("TARGET"), env::var_os("HOST"))
        && target != host
    {
        command.arg("--target").arg(target);
    }
    if let Ok(flags) = env::var("CARGO_ENCODED_RUSTFLAGS") {
        command.args(flags.split('\x1f').filter(|flag| !flag.is_empty()));
    }

    let output = command.output().map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}
