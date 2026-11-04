use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect(&p, files);
            } else if p.extension().is_some_and(|x| x == "rs") {
                files.push(p);
            }
        }
    }
}
fn main() {
    for p in ["src", "tests", "Cargo.toml", "Cargo.lock", "build.rs"] {
        println!("cargo:rerun-if-changed={p}");
    }
    let mut files = vec![
        PathBuf::from("Cargo.toml"),
        PathBuf::from("Cargo.lock"),
        PathBuf::from("build.rs"),
    ];
    collect(Path::new("src"), &mut files);
    collect(Path::new("tests"), &mut files);
    files.sort();
    let mut hash = Sha256::new();
    let mut build_environment: Vec<_> = std::env::vars()
        .filter(|(key, _)| {
            key.starts_with("CARGO_FEATURE_")
                || [
                    "TARGET",
                    "HOST",
                    "PROFILE",
                    "OPT_LEVEL",
                    "DEBUG",
                    "CARGO_ENCODED_RUSTFLAGS",
                    "RUSTFLAGS",
                ]
                .contains(&key.as_str())
        })
        .collect();
    build_environment.sort();
    for (key, value) in build_environment {
        hash.update(key.as_bytes());
        hash.update([0]);
        hash.update(value.as_bytes());
        hash.update([0]);
    }
    if let Ok(rustc) = std::env::var("RUSTC")
        && let Ok(output) = std::process::Command::new(rustc)
            .args(["--version", "--verbose"])
            .output()
    {
        hash.update(output.stdout);
    }
    for f in files {
        if let Ok(data) = std::fs::read(&f) {
            hash.update(f.to_string_lossy().as_bytes());
            hash.update([0]);
            hash.update((data.len() as u64).to_be_bytes());
            hash.update(data);
        }
    }
    println!("cargo:rustc-env=VDG_BUILD_ID={:x}", hash.finalize());
}
