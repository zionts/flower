//! Additional production-shaped canonical-key success/refusal heap probes.
use super::*;

#[test]
fn canonical_typed_utf16_numbers_and_escapes_use_no_postadmission_heap() {
    let values = [
        json!({"\u{e000}":1,"\u{10000}":2,"10":[null,true],"2":"q\n\"\\\u{b}"}),
        json!([9007199254740993u64, 1e21, 1e-7, -0.0, [null, true]]),
        json!("q\n\"\\\u{b}"),
        json!(null),
        json!(true),
        json!(7),
    ];
    let mut job = job();
    let cancel = job.cancellation().clone();
    let control = FrameControl::new(&cancel, job.deadline());
    let mut frame = FrameBuilder::new(limits(), &control).unwrap();
    let prepared: Vec<_> = values
        .iter()
        .map(|value| {
            let encoded = crate::reference::canonical_json(value);
            prepare(
                &mut frame,
                "root",
                &encoded,
                Some(&encoded),
                Some("{}"),
                &control,
            )
        })
        .collect();
    let refused = prepare(
        &mut frame,
        "root",
        "[1e301]",
        Some("[1e301]"),
        Some("{}"),
        &control,
    );
    for prepared in prepared {
        let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
        let (result, count, bytes) = crate::allocation_probe::measure(|| {
            bind(&frame, prepared, &control, &budget, &mut job)
        });
        assert!(result.is_ok());
        assert_eq!((count, bytes), (0, 0));
        budget.finish(&mut job, 100).unwrap();
    }
    let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
    let (result, count, bytes) =
        crate::allocation_probe::measure(|| bind(&frame, refused, &control, &budget, &mut job));
    assert!(matches!(result, Err(PolicyError::Unsupported)));
    assert_eq!((count, bytes), (0, 0));
}

#[test]
fn unrelated_duplicate_names_rows_and_foreign_owner_fail_before_any_candidate() {
    let mut job = job();
    let cancel = job.cancellation().clone();
    let control = FrameControl::new(&cancel, job.deadline());
    let mut frame = FrameBuilder::new(limits(), &control).unwrap();
    let good = prepare(&mut frame, "root", "k", None, Some("{}"), &control);
    let principal = put(&mut frame, "{}", &control);
    let mut foreign = FrameBuilder::new(limits(), &control).unwrap();
    let other = prepare(&mut foreign, "root", "other", None, Some("{}"), &control);
    let collections = [CapturedCollection {
        name: "root",
        policy: None,
    }];
    for state in [0, 1, 2, 3] {
        let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
        let good = bind(&frame, good, &control, &budget, &mut job).unwrap();
        let other = bind(&foreign, other, &control, &budget, &mut job).unwrap();
        let duplicate = [collections[0], collections[0]];
        let bad_name = [CapturedCollection {
            name: "source:[x]",
            policy: None,
        }];
        let rows = if state == 2 {
            [good, other]
        } else {
            [good, good]
        };
        let (result, count, bytes) = crate::allocation_probe::measure(|| {
            let descriptors = match state {
                0 => &duplicate[..],
                1 => &bad_name[..],
                _ => &collections[..],
            };
            let support = CapturedSupport::from_owned_native_capture(
                descriptors,
                if state >= 2 { &rows[..] } else { &[] },
                &budget,
                &mut job,
            )?;
            let verified = VerifiedPrincipal::from_native_auth(
                frame.json(principal, &control).unwrap(),
                &budget,
                &mut job,
            )?;
            PolicyEngine::new(support, verified, 100)
                .authorize_native(good, &[], &budget, &mut job)
                .map(|read| read.decision.allowed)
        });
        assert_eq!(
            (result, count, bytes),
            (Err(PolicyError::Unsupported), 0, 0)
        );
        assert_eq!(budget.finish(&mut job, 100), Err(PolicyError::Unsupported));
    }
}
