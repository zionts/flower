use std::{env, fs, path::PathBuf};
fn section<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let text = &text[text.find(start).expect("actual native start marker")..];
    &text[..text.find(end).expect("actual native end marker")]
}
fn main() {
    println!("cargo:rustc-check-cfg=cfg(sql_policy_harness)");
    println!("cargo:rustc-cfg=sql_policy_harness");
    println!("cargo:rustc-check-cfg=cfg(sql_policy_typed_harness)");
    println!("cargo:rustc-cfg=sql_policy_typed_harness");
    let evaluator = PathBuf::from(file!())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let path = evaluator.join("rust_engine/access.rs");
    println!("cargo:rerun-if-changed={}", path.display());
    let access = fs::read_to_string(path).unwrap();
    let json_path = evaluator.join("rust_engine/json.rs");
    println!("cargo:rerun-if-changed={}", json_path.display());
    let json = fs::read_to_string(json_path).unwrap();
    // Compile UNMODIFIED policy parse/validate/fold/evaluate/redact/equality
    // bodies from actual current sources, excluding serving Engine sections.
    let mut output = String::from(
        "use std::{collections::BTreeMap, sync::Arc, cell::OnceCell, cmp::Ordering, sync::atomic::{AtomicBool, AtomicU64}};\nuse serde::{Deserialize,Serialize};\nuse serde_json::{Value,json};\n",
    );
    output.push_str(section(
        &json,
        "pub(super) fn compare(",
        "#[derive(Clone, Debug, Eq, PartialEq)]",
    ));
    output.push_str(section(
        &json,
        "pub fn canonical_json(",
        "pub(super) fn string_len(",
    ));
    output.push_str(section(
        &json,
        "pub(super) fn allocation_cost(",
        "pub(super) fn depth(",
    ));
    output.push_str(section(
        &json,
        "pub(super) fn source_id(",
        "pub(super) fn collection_id(",
    ));
    output.push_str("#[derive(Debug)] pub struct EngineError; impl EngineError { fn new(_: &str, _: &str) -> Self { Self } } type EngineResult<T> = Result<T,EngineError>;\n");
    output.push_str(section(&json, "pub(super) fn source_pair(", "#[cfg(test)]"));
    output.push_str(section(
        &access,
        "const RELAXED:",
        "/// The rows one access check looks up",
    ));
    output.push_str(section(
        &access,
        "/// No policies: what a",
        "    /// When every row the caller",
    ));
    output.push_str("}\n");
    output.push_str(r#"
#[allow(clippy::too_many_arguments)]
pub fn run(policy: &Value, principal: &Value, row: &Value, key: &str, selecting: &[&str], now: u64, targets: &[(String,Value)], rows: &[(String,String,Option<Value>)]) -> (bool,Value,(bool,Option<u64>)) {
    let policy: Policy = serde_json::from_value(policy.clone()).unwrap();
    policy.validate().unwrap();
    let policies: BTreeMap<String,Policy> = targets.iter().map(|(name,value)| (name.clone(),serde_json::from_value(value.clone()).unwrap())).collect();
    struct Captured<'a>(&'a [(String,String,Option<Value>)]);
    impl Rows for Captured<'_> {
        fn readable(&self, collection: &str, key: &str, visible: &dyn Fn(&Value)->bool) -> bool {
            self.0.iter().find(|(c,k,_)| c == collection && k == key).and_then(|(_,_,row)| row.as_ref()).is_some_and(visible)
        }
    }
    let access = Access::new("root", &policy, &policies, principal, now);
    let rows = Captured(rows);
    let fields = selecting.iter().map(|field| field.to_string()).collect::<Vec<_>>();
    let visible = access.visible(key, row, &fields, &rows);
    let redacted = access.redact(key, &Arc::new(row.clone()), &rows);
    (visible,(*redacted).clone(),access.clock.take())
}
"#);
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("ordinary_access.rs"),
        output,
    )
    .unwrap();
}
