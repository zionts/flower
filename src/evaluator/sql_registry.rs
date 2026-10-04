//! Tiny committed terminal-alias registry, installed atomically with code and
//! httpMethods. SQL dispatch must inspect this bounded record before any ordinary
//! source snapshot/authentication/cache path. It is metadata, not authority.
use super::HttpMethod;
use anyhow::{Result, ensure};
use serde::{Serialize, Serializer, ser::SerializeMap};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) const RECORD: &str = "terminalMethods";
pub(crate) const MAX_BYTES: usize = 32 * 1024;
const MAX_METHODS: usize = 32;

struct Aliases<'a>(&'a BTreeMap<String, HttpMethod>);
impl Serialize for Aliases<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let count = self
            .0
            .values()
            .filter(|method| method.terminal.is_some())
            .count();
        let mut map = serializer.serialize_map(Some(count))?;
        for (alias, method) in self
            .0
            .iter()
            .filter(|(_, method)| method.terminal.is_some())
        {
            map.serialize_entry(alias, method)?;
        }
        map.end()
    }
}
struct Registry<'a>(&'a BTreeMap<String, HttpMethod>);
impl Serialize for Registry<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("format", &1u8)?;
        map.serialize_entry("methods", &Aliases(self.0))?;
        map.end()
    }
}

/// Serialization is counted through a fixed scalar writer BEFORE cloning any
/// aliases, descriptors or signer data into a JSON tree. Tree shape is bounded
/// by validated HttpMethod/TerminalMethod plus the method/encoded byte caps.
pub(super) fn build(http: &BTreeMap<String, HttpMethod>) -> Result<Value> {
    let mut count = 0;
    for (alias, method) in http.iter().filter(|(_, method)| method.terminal.is_some()) {
        count += 1;
        ensure!(
            count <= MAX_METHODS,
            "At most 32 terminal SQL aliases can be exposed"
        );
        ensure!(
            alias.len() <= 256 && method.name.len() <= 256,
            "Terminal SQL alias and method names exceed 256 bytes"
        );
    }
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|bytes| *bytes <= MAX_BYTES)
                .ok_or(std::io::ErrorKind::InvalidData)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let registry = Registry(http);
    ensure!(
        serde_json::to_writer(Counter(0), &registry).is_ok(),
        "Terminal SQL registry exceeds 32 KiB"
    );
    Ok(serde_json::to_value(registry)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn method(name: &str, terminal: bool) -> HttpMethod {
        serde_json::from_value(if terminal {
            json!({"name":name,"kind":"query","cache":false,"watch":false,"terminal":{"catalog":"app","operation":"query","finalizer":"run.$sql.finalize","signingKeys":[]}})
        } else { json!({"name":name,"kind":"query"}) }).unwrap()
    }
    #[test]
    fn registry_contains_only_terminal_aliases_and_has_no_implicit_callback_exposure() {
        let http = BTreeMap::from([
            ("plain".into(), method("plain", false)),
            ("sql.query".into(), method("run", true)),
        ]);
        let registry = build(&http).unwrap();
        assert_eq!(registry["format"], 1);
        assert_eq!(registry["methods"].as_object().unwrap().len(), 1);
        assert_eq!(registry["methods"]["sql.query"]["name"], "run");
        assert!(registry["methods"].get("run.$sql.finalize").is_none());
        assert_eq!(
            build(&BTreeMap::new()).unwrap(),
            json!({"format":1,"methods":{}})
        );
    }
    #[test]
    fn registry_caps_method_count_names_and_encoded_bytes_before_json_tree_creation() {
        let http = (0..33)
            .map(|index| (format!("sql{index}"), method("run", true)))
            .collect();
        assert!(build(&http).is_err());
        let http = BTreeMap::from([("x".repeat(257), method("run", true))]);
        assert!(build(&http).is_err());
        let mut entry = method("run", true);
        entry.terminal.as_mut().unwrap().signing_keys = vec![
            json!({"kind":"key","name":"x".repeat(MAX_BYTES),"algorithm":"HS256","usages":["sign"]}),
        ];
        assert!(build(&BTreeMap::from([("sql".into(), entry)])).is_err());
    }
}
