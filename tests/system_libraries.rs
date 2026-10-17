//! A macOS server loads only libraries every Mac has, however it was built (see
//! `build.rs`). One that loads from `/nix/store` stops starting when that path
//! is garbage-collected, or at boot before the Nix volume mounts.
#![cfg(target_os = "macos")]

use std::process::Command;

#[test]
fn server_links_only_system_libraries() {
    let server = env!("CARGO_BIN_EXE_flower");
    let output = Command::new("otool")
        .args(["-L", server])
        .output()
        .expect("otool runs (Xcode command line tools)");
    assert!(
        output.status.success(),
        "otool -L {server}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The first line names the binary; each following line is one library.
    let listing = String::from_utf8(output.stdout).unwrap();
    let foreign: Vec<&str> = listing
        .lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().next())
        .filter(|path| !path.starts_with("/usr/lib/") && !path.starts_with("/System/Library/"))
        .collect();
    assert!(
        foreign.is_empty(),
        "the server links libraries outside the system: {foreign:?}"
    );
}
