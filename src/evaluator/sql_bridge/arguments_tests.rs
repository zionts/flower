use super::*;

fn arena() -> WireArena {
    WireArena::new(WireLimits::default()).unwrap()
}

#[test]
fn arguments_empty_scalar_boundaries_and_whole_stream() {
    let mut arena = arena();
    let root = arena.decode_arguments(&[]).unwrap();
    assert_eq!(arena.value(root).unwrap().kind(), WireKind::Array);
    assert_eq!(arena.value(root).unwrap().len(), Some(0));
    arena.reset().unwrap();
    let root = arena
        .decode_arguments(&[NULL; WireArena::MAX_ARGUMENTS])
        .unwrap();
    assert_eq!(arena.value(root).unwrap().len(), Some(8));
    arena.reset().unwrap();
    assert_eq!(arena.decode_arguments(&[NULL; 9]), Err(WireError::Capacity));
    assert_eq!(arena.decode_arguments(&[]), Err(WireError::Poisoned));
    arena.reset().unwrap();
    assert_eq!(
        arena.decode_arguments(&[NULL, INT, 1]),
        Err(WireError::Invalid("truncated wire value"))
    );
    arena.reset().unwrap();
    assert_eq!(
        arena.decode_arguments(&[NULL, 255]),
        Err(WireError::Invalid("unknown wire tag"))
    );
}

#[test]
fn argument_roots_share_key_literals_ordinals_and_unicode() {
    // The second literal deliberately repeats the spelling: KEY 1 must refer
    // to literal occurrence 1, not to a distinct-key dictionary index.
    let bytes = [
        MAP, 1, 0, 0, 0, LATIN1, 1, 0, 0, 0, b'x', INT, 1, 0, 0, 0, MAP, 1, 0, 0, 0, LATIN1, 1, 0,
        0, 0, b'x', TRUE, MAP, 1, 0, 0, 0, KEY, 1, 0, 0, 0, UTF16, 2, 0, 0, 0, 0x3d, 0xd8, 0x00,
        0xde,
    ];
    let mut arena = arena();
    let root = arena.decode_arguments(&bytes).unwrap();
    assert_eq!(
        arena.json(root).unwrap(),
        "[{\"x\":1},{\"x\":true},{\"x\":\"😀\"}]".as_bytes()
    );
}

#[test]
fn arguments_key_table_resets_between_calls_and_keeps_quotas() {
    let bytes = [
        MAP, 1, 0, 0, 0, LATIN1, 1, 0, 0, 0, b'x', NULL, MAP, 1, 0, 0, 0, KEY, 0, 0, 0, 0, NULL,
    ];
    let mut arena = arena();
    for _ in 0..3 {
        let root = arena.decode_arguments(&bytes).unwrap();
        assert_eq!(arena.value(root).unwrap().len(), Some(2));
        arena.reset().unwrap();
        assert_eq!(
            arena.decode_arguments(&bytes[12..]),
            Err(WireError::Invalid("unknown key reference"))
        );
        arena.reset().unwrap();
    }
    let mut small = WireArena::new(WireLimits {
        keys: 1,
        ..WireLimits::default()
    })
    .unwrap();
    assert_eq!(small.decode_arguments(&bytes), Err(WireError::Capacity));
}

#[test]
fn arguments_depth_nodes_message_work_and_cancellation_are_admitted() {
    let mut small = WireArena::new(WireLimits {
        nodes: 1,
        ..WireLimits::default()
    })
    .unwrap();
    assert_eq!(small.decode_arguments(&[NULL]), Err(WireError::Capacity));
    let mut small = WireArena::new(WireLimits {
        depth: 1,
        ..WireLimits::default()
    })
    .unwrap();
    assert_eq!(small.decode_arguments(&[NULL]), Err(WireError::Capacity));
    let mut small = WireArena::new(WireLimits {
        message_bytes: 1,
        ..WireLimits::default()
    })
    .unwrap();
    assert_eq!(
        small.decode_arguments(&[NULL, NULL]),
        Err(WireError::Capacity)
    );
    let mut small = WireArena::new(WireLimits {
        job_work: 1,
        ..WireLimits::default()
    })
    .unwrap();
    assert_eq!(small.decode_arguments(&[NULL]), Err(WireError::WorkLimit));
    let mut arena = arena();
    assert_eq!(
        arena.decode_arguments_checked(&[], &mut || Err(WireError::Cancelled)),
        Err(WireError::Cancelled)
    );
    arena.reset().unwrap();
    let mut checks = 0;
    assert_eq!(
        arena.decode_arguments_checked(&[NULL], &mut || {
            checks += 1;
            if checks == 2 {
                Err(WireError::Cancelled)
            } else {
                Ok(())
            }
        }),
        Err(WireError::Cancelled)
    );
}
