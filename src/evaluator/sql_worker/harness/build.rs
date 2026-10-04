use std::{fs, path::PathBuf};
fn main() {
    // Actual current source error enum only, not a fake Consensus or source.
    // The actual JobControl is compiled directly without rewriting it.
    let source = PathBuf::from("../../sqlite/mod.rs");
    println!("cargo:rerun-if-changed={}", source.display());
    let text = fs::read_to_string(source).expect("actual SQLite error enum");
    let start = text
        .find("pub enum SqlError {")
        .expect("actual error enum start");
    let end = text[start..].find("\n}").expect("actual error enum end") + start + 2;
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    fs::write(
        output.join("error.rs"),
        format!(
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n{}\n",
            &text[start..end]
        ),
    )
    .expect("write exact enum extraction");
}
