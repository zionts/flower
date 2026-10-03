use super::*;
use serde_json::json;

fn limits() -> WireLimits {
    WireLimits {
        message_bytes: 4096,
        text_bytes: 8192,
        nodes: 1024,
        keys: 512,
        logical_key_bytes: 8192,
        output_bytes: 4096,
        depth: 64,
        job_work: 2_000_000,
    }
}
fn arena() -> WireArena {
    WireArena::new(limits()).unwrap()
}
fn string(tag: u8, bytes: &[u8], count: usize) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&(count as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}
fn utf16(s: &str) -> Vec<u8> {
    let units: Vec<_> = s.encode_utf16().collect();
    let mut bytes = Vec::new();
    for u in &units {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    string(UTF16, &bytes, units.len())
}
fn depth(levels: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 1..levels {
        bytes.extend_from_slice(&[ARRAY, 1, 0, 0, 0]);
    }
    bytes.push(NULL);
    bytes
}
fn bridge_value(arena: &mut WireArena, root: WireId) -> serde_json::Value {
    serde_json::from_slice(arena.json(root).unwrap()).unwrap()
}

#[test]
fn canonical_reference_roundtrip_and_interning() {
    let fixture = json!({"z": [null, true, false, -2147483648_i64, 2.25, "é😀\u{0}"], "𐀀": [{"key": 4, "é": true}, {"key": 5, "é": false}], "\u{e000}": "latin"});
    let bytes = super::super::wire::encode(&fixture).unwrap();
    let mut arena = arena();
    let root = arena.decode(&bytes).unwrap();
    assert_eq!(
        arena
            .value(root)
            .unwrap()
            .member("z")
            .unwrap()
            .index(3)
            .unwrap()
            .as_i32(),
        Some(i32::MIN)
    );
    assert_eq!(arena.encode(root).unwrap(), bytes);
    assert_eq!(bridge_value(&mut arena, root), fixture);
    assert_eq!(
        arena
            .value(root)
            .unwrap()
            .member("z")
            .unwrap()
            .iter()
            .unwrap()
            .len(),
        6
    );
}
#[test]
fn all_native_string_encodings_and_raw_numbers() {
    let mut arena = arena();
    for bytes in [
        string(LATIN1, &[0, 0xe9, 0xff], 3),
        string(UTF8, "\0éÿ".as_bytes(), 5),
        utf16("\0éÿ"),
    ] {
        arena.reset().unwrap();
        let root = arena.decode(&bytes).unwrap();
        assert_eq!(arena.value(root).unwrap().as_str(), Some("\0éÿ"));
    }
    for value in [
        -0.0,
        1.0e21,
        f64::MIN_POSITIVE,
        f64::MAX,
        -9_223_372_036_854_775_808.0,
        18_446_744_073_709_551_616.0,
    ] {
        arena.reset().unwrap();
        let mut bytes = vec![FLOAT];
        bytes.extend_from_slice(&value.to_le_bytes());
        let root = arena.decode(&bytes).unwrap();
        assert_eq!(
            arena.value(root).unwrap().as_f64().unwrap().to_bits(),
            value.to_bits()
        );
        assert_eq!(arena.encode(root).unwrap(), bytes);
        assert_eq!(
            arena.json(root).unwrap(),
            ryu_js::Buffer::new().format(value).as_bytes()
        );
    }
}
#[test]
fn duplicate_decoded_keys_and_unknown_refs_are_rejected() {
    let mut arena = arena();
    for key in [
        string(LATIN1, &[0xe9], 1),
        utf16("é"),
        vec![KEY, 0, 0, 0, 0],
    ] {
        let mut bytes = vec![MAP, 2, 0, 0, 0];
        bytes.extend(string(UTF8, "é".as_bytes(), 2));
        bytes.push(NULL);
        bytes.extend(key);
        bytes.push(NULL);
        arena.reset().unwrap();
        assert_eq!(
            arena.decode(&bytes),
            Err(WireError::Invalid("duplicate decoded map key"))
        );
    }
    arena.reset().unwrap();
    assert_eq!(
        arena.decode(&[MAP, 1, 0, 0, 0, KEY, 0, 0, 0, 0, NULL]),
        Err(WireError::Invalid("unknown key reference"))
    );
}
#[test]
fn all_truncations_and_malformed_wire_fail_closed() {
    let good = super::super::wire::encode(&json!({"a":["😀", -10, 2.5], "b":true})).unwrap();
    let mut arena = arena();
    for end in 0..good.len() {
        arena.reset().unwrap();
        assert!(arena.decode(&good[..end]).is_err(), "prefix {end}");
    }
    let mut malformed = vec![
        vec![11],
        vec![KEY, 0, 0, 0, 0],
        vec![NULL, NULL],
        string(UTF8, &[0xff], 1),
        string(UTF16, &[0, 0xd8], 1),
        string(UTF16, &[0, 0xdc], 1),
        string(UTF16, &[0, 0xd8, 0, 0], 2),
        vec![ARRAY, 255, 255, 255, 255],
        vec![MAP, 255, 255, 255, 255],
    ];
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let mut bytes = vec![FLOAT];
        bytes.extend(value.to_le_bytes());
        malformed.push(bytes);
    }
    for bytes in malformed {
        arena.reset().unwrap();
        assert!(arena.decode(&bytes).is_err());
        assert_eq!(arena.decode(&[NULL]), Err(WireError::Poisoned));
    }
}
#[test]
fn depth_count_and_unicode_quota_admission() {
    let mut arena = arena();
    let root = arena.decode(&depth(64)).unwrap();
    assert!(arena.encode(root).is_ok());
    arena.reset().unwrap();
    assert_eq!(arena.decode(&depth(65)), Err(WireError::Capacity));
    let mut small = WireArena::new(WireLimits {
        nodes: 2,
        ..limits()
    })
    .unwrap();
    assert_eq!(
        small.decode(&[ARRAY, 2, 0, 0, 0, NULL, NULL]),
        Err(WireError::Capacity)
    );
    assert_eq!(small.node_len, 0);
    let mut small = WireArena::new(WireLimits {
        text_bytes: 2,
        ..limits()
    })
    .unwrap();
    assert_eq!(
        small.decode(&string(LATIN1, &[0xe9, 0xe9], 2)),
        Err(WireError::Capacity)
    );
    assert_eq!(small.text_len, 0);
    small.reset().unwrap();
    assert_eq!(small.decode(&utf16("€")), Err(WireError::Capacity));
    assert_eq!(small.text_len, 0);
    small.reset().unwrap();
    assert_eq!(
        small.decode(&[UTF8, 255, 255, 255, 255]),
        Err(WireError::Capacity)
    );
}
#[test]
fn repeated_keys_are_logically_charged_and_key_counts_are_bounded() {
    let mut bytes = vec![ARRAY, 3, 0, 0, 0, MAP, 1, 0, 0, 0];
    bytes.extend(string(LATIN1, b"long_key", 8));
    bytes.push(NULL);
    for _ in 0..2 {
        bytes.extend([MAP, 1, 0, 0, 0, KEY, 0, 0, 0, 0, NULL]);
    }
    let mut arena = WireArena::new(WireLimits {
        logical_key_bytes: 16,
        ..limits()
    })
    .unwrap();
    assert_eq!(arena.decode(&bytes), Err(WireError::Capacity));
    assert_eq!(arena.key_len, 1);
    assert_eq!(arena.key_uses, 2);
    assert_eq!(arena.logical_key_bytes, 16);
    let mut arena = WireArena::new(WireLimits {
        keys: 2,
        ..limits()
    })
    .unwrap();
    assert_eq!(arena.decode(&bytes), Err(WireError::Capacity));
}
#[test]
fn typed_outcomes_and_failure_schema() {
    let fixture = json!({"x": 1});
    let mut arena = arena();
    let success = super::super::wire::success(&fixture).unwrap();
    let WireOutcome::Success(root) = arena.decode_outcome(&success).unwrap() else {
        panic!()
    };
    assert_eq!(
        arena.encode_outcome(WireOutcome::Success(root)).unwrap(),
        success
    );
    arena.reset().unwrap();
    let failure = super::super::wire::failure("DENIED", "No access", Some(&fixture));
    let outcome = arena.decode_outcome(&failure).unwrap();
    let WireOutcome::Failure {
        code,
        message,
        details,
    } = outcome
    else {
        panic!()
    };
    assert_eq!(arena.value(code).unwrap().as_str(), Some("DENIED"));
    assert_eq!(arena.value(message).unwrap().as_str(), Some("No access"));
    assert!(details.is_some());
    assert_eq!(arena.encode_outcome(outcome).unwrap(), failure);
    for value in [
        json!(null),
        json!({"code":"x"}),
        json!({"code":4,"message":"x"}),
        json!({"code":"x","message":"x","unknown":null}),
    ] {
        arena.reset().unwrap();
        let mut bytes = vec![FAILURE];
        bytes.extend(super::super::wire::encode(&value).unwrap());
        assert!(arena.decode_outcome(&bytes).is_err());
    }
    arena.reset().unwrap();
    assert!(arena.decode_outcome(&[3, NULL]).is_err());
}
#[test]
fn builder_canonical_reply_cycles_reuse_and_depth() {
    let mut arena = arena();
    let root = arena.object().unwrap();
    let item = arena.text("é😀\0").unwrap();
    arena.insert(root, "z", item).unwrap();
    let nested = arena.array().unwrap();
    let b = arena.boolean(true).unwrap();
    arena.push(nested, b).unwrap();
    arena.insert(root, "a", nested).unwrap();
    let fixture = json!({"a":[true],"z":"é😀\u{0}"});
    assert_eq!(
        arena.encode(root).unwrap(),
        super::super::wire::encode(&fixture).unwrap()
    );
    assert_eq!(bridge_value(&mut arena, root), fixture);
    assert_eq!(
        arena.push(nested, root),
        Err(WireError::Invalid("wire builder cycle"))
    );
    arena.reset().unwrap();
    let a = arena.array().unwrap();
    let v = arena.null().unwrap();
    arena.push(a, v).unwrap();
    assert_eq!(
        arena.push(a, v),
        Err(WireError::Invalid("node already attached"))
    );
    arena.reset().unwrap();
    let mut parent = arena.null().unwrap();
    for _ in 1..64 {
        let next = arena.array().unwrap();
        arena.push(next, parent).unwrap();
        parent = next;
    }
    assert!(arena.encode(parent).is_ok());
    let extra = arena.array().unwrap();
    assert_eq!(arena.push(extra, parent), Err(WireError::Capacity));
    arena.reset().unwrap();
    let details = arena.integer(7).unwrap();
    let fail = arena.failure("CODE", "msg", Some(details)).unwrap();
    assert_eq!(
        arena.encode_outcome(fail).unwrap(),
        super::super::wire::failure("CODE", "msg", Some(&json!(7)))
    );
}
#[test]
fn reset_invalidates_handles_and_never_replenishes_work() {
    let mut arena = arena();
    let other = super::tests::arena();
    let id = arena.decode(&[NULL]).unwrap();
    let before = arena.work_remaining();
    arena.reset().unwrap();
    assert!(arena.work_remaining() < before);
    assert!(matches!(arena.value(id), Err(WireError::StaleId)));
    assert!(matches!(other.value(id), Err(WireError::StaleId)));
    let mut tiny = WireArena::new(WireLimits {
        job_work: 3,
        ..limits()
    })
    .unwrap();
    let id = tiny.decode(&[NULL]).unwrap();
    assert_eq!(tiny.encode(id), Err(WireError::WorkLimit));
    let remaining = tiny.work_remaining();
    assert_eq!(tiny.reset(), Err(WireError::WorkLimit));
    assert!(tiny.work_remaining() <= remaining);
    assert_eq!(tiny.decode(&[NULL]), Err(WireError::Poisoned));
}
#[test]
fn cancelled_work_does_not_expose_partial_input_or_output() {
    let input = string(LATIN1, &vec![b'x'; 3000], 3000);
    let mut arena = arena();
    let mut calls = 0;
    let mut check = || {
        calls += 1;
        if calls >= 2 {
            Err(WireError::Cancelled)
        } else {
            Ok(())
        }
    };
    assert_eq!(
        arena.decode_checked(&input, &mut check),
        Err(WireError::Cancelled)
    );
    assert_eq!(calls, 2);
    assert_eq!(arena.decode(&[NULL]), Err(WireError::Poisoned));
    arena.reset().unwrap();
    let root = arena.decode(&[NULL]).unwrap();
    assert_eq!(
        arena.encode_checked(root, &mut || Err(WireError::Cancelled)),
        Err(WireError::Cancelled)
    );
    assert_eq!(arena.output_len, 0);
}
#[test]
fn mapped_retained_bound_and_limit_validation() {
    let arena = WireArena::new(WireLimits::default()).unwrap();
    assert!(arena.allocation_bytes() <= MAX_ARENA_BYTES);
    assert!(arena.allocation_bytes() > CONTROL_BYTES);
    let max = WireArena::new(WireLimits {
        nodes: MAX_NODES,
        keys: MAX_KEYS,
        ..WireLimits::default()
    });
    match max {
        Ok(max) => assert!(max.allocation_bytes() <= MAX_ARENA_BYTES),
        Err(error) => assert_eq!(error, WireError::Capacity),
    }
    println!(
        "default admitted retained bytes: {}",
        arena.allocation_bytes()
    );
    for limits in [
        WireLimits {
            message_bytes: MAX_MESSAGE_BYTES + 1,
            ..limits()
        },
        WireLimits {
            depth: 65,
            ..limits()
        },
        WireLimits {
            text_bytes: MAX_TEXT_BYTES + 1,
            ..limits()
        },
        WireLimits {
            job_work: MAX_WORK + 1,
            ..limits()
        },
    ] {
        assert!(WireArena::new(limits).is_err());
    }
}
#[test]
fn output_exhaustion_is_fixed_and_callback_poisoned() {
    let mut arena = WireArena::new(WireLimits {
        output_bytes: 5,
        ..limits()
    })
    .unwrap();
    let root = arena.text("xxxxx").unwrap();
    let bytes = arena.allocation_bytes();
    assert_eq!(arena.encode(root), Err(WireError::Capacity));
    assert_eq!(arena.allocation_bytes(), bytes);
    assert_eq!(arena.output_len, 0);
    assert_eq!(arena.json(root), Err(WireError::Poisoned));
    arena.reset().unwrap();
    let root = arena.text("\0").unwrap();
    assert_eq!(arena.json(root), Err(WireError::Capacity));
    assert_eq!(arena.output_len, 0);
}

#[test]
fn utf8_boundary_validation_and_literal_key_numbering() {
    let mut arena = WireArena::new(WireLimits {
        message_bytes: 64 * 1024,
        text_bytes: 64 * 1024,
        ..limits()
    })
    .unwrap();
    for prefix in 4093..=4096 {
        let text = format!("{}😀é𐀀", "x".repeat(prefix));
        arena.reset().unwrap();
        let root = arena
            .decode(&string(UTF8, text.as_bytes(), text.len()))
            .unwrap();
        assert_eq!(arena.value(root).unwrap().as_str(), Some(text.as_str()));
    }
    let mut bytes = vec![ARRAY, 3, 0, 0, 0, MAP, 1, 0, 0, 0];
    bytes.extend(string(UTF8, "é".as_bytes(), 2));
    bytes.push(NULL);
    bytes.extend([MAP, 1, 0, 0, 0]);
    bytes.extend(utf16("é"));
    bytes.push(TRUE);
    bytes.extend([MAP, 1, 0, 0, 0, KEY, 1, 0, 0, 0, FALSE]);
    arena.reset().unwrap();
    let root = arena.decode(&bytes).unwrap();
    assert_eq!(arena.key_len, 2);
    assert_eq!(
        arena
            .value(root)
            .unwrap()
            .index(2)
            .unwrap()
            .member("é")
            .unwrap()
            .as_bool(),
        Some(false)
    );
    assert_eq!(
        bridge_value(&mut arena, root),
        json!([{"é":null},{"é":true},{"é":false}])
    );
}

#[test]
fn builder_duplicate_key_and_nonfinite_refusal() {
    let mut arena = arena();
    let object = arena.object().unwrap();
    let a = arena.null().unwrap();
    let b = arena.null().unwrap();
    arena.insert(object, "é", a).unwrap();
    assert_eq!(
        arena.insert(object, "é", b),
        Err(WireError::Invalid("duplicate decoded map key"))
    );
    assert!(matches!(arena.value(object), Err(WireError::Poisoned)));
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        arena.reset().unwrap();
        assert_eq!(
            arena.real(value),
            Err(WireError::Invalid("number is not finite"))
        );
    }
}

#[test]
fn hard_message_and_zero_capacities_admit_nothing_extra() {
    let mut arena = WireArena::new(WireLimits {
        message_bytes: 1,
        ..limits()
    })
    .unwrap();
    assert_eq!(arena.decode(&[NULL, NULL]), Err(WireError::Capacity));
    assert_eq!(arena.node_len, 0);
    let mut arena = WireArena::new(WireLimits {
        nodes: 0,
        text_bytes: 0,
        keys: 0,
        output_bytes: 0,
        ..limits()
    })
    .unwrap();
    assert_eq!(arena.decode(&[NULL]), Err(WireError::Capacity));
    arena.reset().unwrap();
    assert_eq!(arena.null(), Err(WireError::Capacity));
}

#[test]
fn deterministic_reference_cases_cover_mixed_nested_shapes() {
    fn random(seed: &mut u64) -> u64 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *seed
    }
    fn value(seed: &mut u64, depth: usize) -> serde_json::Value {
        let pick = random(seed) % if depth > 0 { 8 } else { 6 };
        match pick {
            0 => json!(null),
            1 => json!(random(seed) & 1 == 0),
            2 => json!(random(seed) as i32),
            3 => json!((random(seed) as i32) as f64 / 8.0),
            4 => json!("é😀\u{0}\n\\\""),
            5 => json!("ascii"),
            6 => {
                let count = random(seed) as usize % 5;
                serde_json::Value::Array((0..count).map(|_| value(seed, depth - 1)).collect())
            }
            _ => {
                let count = random(seed) as usize % 5;
                let keys = ["a", "é", "𐀀", "\u{e000}"];
                serde_json::Value::Object(
                    (0..count)
                        .map(|i| (keys[i].to_owned(), value(seed, depth - 1)))
                        .collect(),
                )
            }
        }
    }
    let mut arena = WireArena::new(WireLimits {
        job_work: MAX_WORK,
        ..limits()
    })
    .unwrap();
    let mut seed = 7;
    for _ in 0..512 {
        let value = value(&mut seed, 5);
        let reference = super::super::wire::encode(&value).unwrap();
        arena.reset().unwrap();
        let root = arena.decode(&reference).unwrap();
        assert_eq!(arena.encode(root).unwrap(), reference);
        assert_eq!(bridge_value(&mut arena, root), value);
    }
}

#[test]
fn adversarial_prefix_sorting_stops_at_the_work_quota() {
    let mut arena = WireArena::new(WireLimits {
        text_bytes: 8192,
        keys: 64,
        job_work: 50_000,
        ..limits()
    })
    .unwrap();
    let root = arena.object().unwrap();
    for i in 0..32 {
        let child = arena.null().unwrap();
        arena
            .insert(root, &format!("{}{:02}", "a".repeat(100), i), child)
            .unwrap();
    }
    assert_eq!(arena.encode(root), Err(WireError::WorkLimit));
    assert_eq!(arena.output_len, 0);
}
