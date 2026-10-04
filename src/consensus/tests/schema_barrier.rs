//! Native schema/lifetime compaction boundary. These checks protect ordered
//! individual schema effects; they are not sticky-roster or transfer proofs.
use super::*;
use crate::consensus::source_sensitive_key;

#[test]
fn schema_lifetime_barrier_refuses_native_compaction_before_losing_intermediate_values() {
    for replace_schema in [false, true] {
        let mut first = commit("schema-first", 0, 1);
        // The boundary is the REAL raw namespace record key, not a collection
        // label or a guessed protected row. Any schema mutation is a barrier.
        first
            .puts
            .insert("schema".into(), json!({"indexes": [], "aggregates": {}}));
        let mut second = commit("schema-second", 1, 2);
        if replace_schema {
            second
                .puts
                .insert("schema".into(), json!({"indexes": [], "aggregates": {}}));
        } else {
            second.deletes.push("schema".into());
        }
        assert!(CompactBatch::new(vec![first, second]).is_err());
    }
    let mut delete = commit("schema-delete", 0, 1);
    delete.deletes.push("schema".into());
    assert!(CompactBatch::new(vec![delete]).is_err());
}

#[test]
fn schema_lifetime_barrier_validates_decoded_native_batches_before_any_staging() {
    let ordinary = CompactBatch::new(vec![commit("data-a", 0, 1), commit("data-b", 1, 2)]).unwrap();
    assert!(ordinary.validate().is_ok());
    for put in [false, true] {
        let mut unsafe_batch = ordinary.clone();
        if put {
            unsafe_batch.puts.insert("schema".into(), json!({}));
        } else {
            unsafe_batch.deletes.push("schema".into());
        }
        let encoded = serde_json::to_vec(&unsafe_batch).unwrap();
        let decoded: CompactBatch = serde_json::from_slice(&encoded).unwrap();
        assert!(decoded.validate().is_err());
    }
}

#[test]
fn schema_lifetime_barrier_preserves_ordinary_data_only_batching_and_real_key_distinction() {
    let mut first = commit("rows-a", 0, 1);
    let second = commit("rows-b", 1, 2);
    // A collection called schema is not the native raw namespace schema record.
    first
        .puts
        .insert(r#"source:["schema","row"]"#.into(), json!(null));
    first
        .puts
        .insert("schema-like-application-key".into(), json!(true));
    let batch = CompactBatch::new(vec![first, second]).unwrap();
    assert_eq!(batch.items.len(), 2);
    assert!(batch.validate().is_ok());
}

#[test]
fn source_sensitive_barrier_covers_all_actual_code_keys_and_preserves_prelog_entry_pairing() {
    for key in ["bundle", "schema", "httpMethods", "terminalMethods"] {
        assert!(source_sensitive_key(key));
        let mut a = commit("paired-a", 0, 1);
        a.puts
            .insert("bundle".into(), json!({"javascript":"bundle1"}));
        a.puts.insert("httpMethods".into(), json!({}));
        a.puts
            .insert("terminalMethods".into(), json!({"format":1,"methods":{}}));
        let mut b = commit("unpaired-b", 1, 2);
        b.puts.insert(key.into(), json!({"javascript":"bundle2"}));
        assert!(CompactBatch::new(vec![a, b]).is_err());
        let mut ordinary = CompactBatch::new(vec![commit("data", 0, 1)]).unwrap();
        ordinary.deletes.push(key.into());
        assert!(ordinary.validate().is_err());
    }
    for key in [
        r#"source:["schema","row"]"#,
        "schema-like",
        "schema\0suffix",
        "Bundle",
        "other",
    ] {
        assert!(!source_sensitive_key(key));
    }
}
