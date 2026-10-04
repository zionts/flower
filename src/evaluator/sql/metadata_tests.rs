use super::*;
use serde_json::json;

fn cancel(shape: Option<CancelResultShape>) -> TerminalMethod {
    TerminalMethod {
        catalog: "native_catalog".into(),
        operation: Operation::Cancel,
        cancel_result: shape,
        finalizer: "sql.cancel.$sql.finalize".into(),
        signing_keys: vec![],
    }
}

#[test]
fn cancellation_metadata_is_closed_and_cannot_select_a_signer_or_non_cancel_shape() {
    for shape in [
        None,
        Some(CancelResultShape::Boolean),
        Some(CancelResultShape::Cancelled),
    ] {
        let descriptor = cancel(shape);
        descriptor.validate().unwrap();
        let roundtrip: TerminalMethod =
            serde_json::from_value(serde_json::to_value(&descriptor).unwrap()).unwrap();
        assert_eq!(roundtrip, descriptor);
        for operation in [Operation::Query, Operation::Explain, Operation::Catalog] {
            let mut other = descriptor.clone();
            other.operation = operation;
            assert_eq!(other.validate().is_err(), shape.is_some());
            assert!(other.native_cancel_result(true).is_err());
        }
    }
    let mut signed = cancel(None);
    signed
        .signing_keys
        .push(json!({"name":"signer","usages":["sign"]}));
    assert!(signed.validate().is_err());
    assert!(signed.native_cancel_result(true).is_err());
    for (name, value) in [
        ("cancelResult", json!("callback")),
        ("cancelResult", json!(true)),
        ("callback", json!("public.target")),
    ] {
        let mut invalid = serde_json::to_value(cancel(None)).unwrap();
        invalid[name] = value;
        assert!(serde_json::from_value::<TerminalMethod>(invalid).is_err());
    }
}

#[test]
fn cancellation_result_is_only_a_literal_boolean_or_exact_cancelled_envelope() {
    for (shape, expected_false, expected_true) in [
        (None, &b"false"[..], &b"true"[..]),
        (
            Some(CancelResultShape::Boolean),
            &b"false"[..],
            &b"true"[..],
        ),
        (
            Some(CancelResultShape::Cancelled),
            &b"{\"cancelled\":false}"[..],
            &b"{\"cancelled\":true}"[..],
        ),
    ] {
        let descriptor = cancel(shape);
        assert_eq!(
            descriptor.native_cancel_result(false).unwrap(),
            expected_false
        );
        assert_eq!(
            descriptor.native_cancel_result(true).unwrap(),
            expected_true
        );
        #[cfg(feature = "sql")]
        {
            let (result, allocations, bytes) =
                crate::allocation_probe::measure(|| descriptor.native_cancel_result(true));
            assert_eq!(result.unwrap(), expected_true);
            assert_eq!((allocations, bytes), (0, 0));
        }
    }
}

#[test]
fn generated_finalizer_name_accepts_the_whole_bounded_public_method_name() {
    let mut descriptor = cancel(None);
    descriptor.finalizer = format!("{}.$sql.finalize", "a".repeat(256));
    descriptor.validate().unwrap();
    descriptor.finalizer = "a".repeat(384);
    descriptor.validate().unwrap();
    descriptor.finalizer.push('a');
    assert!(descriptor.validate().is_err());
}
