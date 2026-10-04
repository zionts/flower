//! Independent-only build script. Compiles the ACTUAL ordinary managed source
//! helpers into the test reference, without changing/importing shared modules.
//! Never used as a production crypto implementation or allocation proof.
use std::{env, fs, path::PathBuf};
fn item(source: &str, prefix: &str) -> String {
    let start = source
        .find(prefix)
        .expect("ordinary reference item changed");
    let open = start + source[start..].find('{').expect("item body");
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return source[start..=open + offset].to_owned();
                }
            }
            _ => (),
        }
    }
    panic!("ordinary reference item unterminated")
}
fn main() {
    println!("cargo:rustc-check-cfg=cfg(sql_managed_harness)");
    println!("cargo:rustc-cfg=sql_managed_harness");
    let source_path = PathBuf::from(file!())
        .parent()
        .unwrap()
        .join("../managed.rs");
    println!("cargo:rerun-if-changed={}", source_path.display());
    let source = fs::read_to_string(source_path).unwrap();
    let mut reference = String::from(
        r#"
use anyhow::{anyhow, ensure, Context, Result};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;
#[derive(serde::Serialize)] enum Algorithm { Ed25519 }
"#,
    );
    for name in ["cipher", "seal", "open", "aad"] {
        reference.push_str(&item(&source, &format!("\nfn {name}(")));
        reference.push('\n');
    }
    reference.push_str(&item(&source, "struct MountedKey {"));
    reference.push_str(&item(&source, "impl MountedKey {"));
    reference.push_str(r#"
pub(crate) fn aad_ed(domain: &str, id: &str, version: u64, purpose: &str) -> Vec<u8> {
    aad(domain, id, version, Algorithm::Ed25519, purpose).unwrap()
}
pub(crate) fn seal_bytes(key: &[u8], nonce: [u8;12], aad: &[u8], bytes: &[u8]) -> Vec<u8> {
    seal(&cipher(key).unwrap(), nonce, aad, bytes).unwrap()
}
pub(crate) fn open_bytes(key: &[u8], nonce: [u8;12], aad: &[u8], bytes: &[u8]) -> Vec<u8> {
    open(&cipher(key).unwrap(), nonce, aad, bytes).unwrap().to_vec()
}
pub(crate) fn wrap_from_file(path: &Path, nonce: [u8;12], aad: &[u8], dek: &[u8]) -> (String, Vec<u8>) {
    let mount = MountedKey::read(path).unwrap();
    let encrypted = seal(&mount.cipher, nonce, aad, dek).unwrap();
    (mount.id, encrypted)
}
"#);
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("ordinary_reference.rs");
    fs::write(output, reference).unwrap();
}
