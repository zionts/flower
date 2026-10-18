//! Link the server only against libraries it calls. On Apple targets the `libc`
//! crate asks for libiconv whether or not anything uses it, and inside
//! `nix develop` the linker finds that library in the Nix store. A server built
//! there then fails to start once garbage collection removes the store path, or
//! at boot before the Nix volume mounts. Flower calls no iconv function, so
//! `-dead_strip_dylibs` drops the reference and the server links only system
//! libraries; `tests/system_libraries.rs` checks the result.
fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo::rustc-link-arg-bins=-Wl,-dead_strip_dylibs");
    }
}
