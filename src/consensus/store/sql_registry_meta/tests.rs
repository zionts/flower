use super::*;
use crate::consensus::backing::encode;
use openraft::CommittedLeaderId;
use redb::ReadableTableMetadata;
use serde_json::json;

fn database() -> Database {
    Database::builder()
        .create_with_backend(redb::backends::InMemoryBackend::new())
        .unwrap()
}
fn root_row(tx: &WriteTransaction, tables: Tables, key: &[u8], row: Option<&[u8]>) {
    let mut data = tx.open_table(tables.data).unwrap();
    match row {
        Some(bytes) => {
            data.insert(key, bytes).unwrap();
        }
        None => {
            data.remove(key).unwrap();
        }
    }
}
fn root_code(
    tx: &WriteTransaction,
    tables: Tables,
    registry: u64,
    bundle: u64,
    schema: Option<u64>,
) {
    root_row(
        tx,
        tables,
        b"terminalMethods",
        Some(&encode(registry, br#"{"methods":{}}"#)),
    );
    root_row(
        tx,
        tables,
        b"bundle",
        Some(&encode(bundle, br#"{"javascript":"actual code"}"#)),
    );
    root_row(
        tx,
        tables,
        b"schema",
        schema
            .map(|v| encode(v, br#"{"collections":[]}"#))
            .as_deref(),
    );
}
fn info(name: &str, epoch: u64, phase: PartitionPhase) -> PartitionInfo {
    PartitionInfo {
        partition: name.into(),
        epoch,
        phase,
        operation: "native-test".into(),
        transfer: None,
        revision: 0,
        digest: None,
        bytes: 0,
        received_bytes: 0,
        next_chunk: 0,
        base_bytes: 0,
    }
}
fn scoped_code(
    tx: &WriteTransaction,
    tables: Tables,
    info: &PartitionInfo,
    registry: u64,
    bundle: u64,
    schema: Option<u64>,
) {
    // Use ACTUAL PartitionInfo and physical partition tables, not replacement
    // Tables/Records types. Native Store tests below exercise Metadata writes.
    let mut metadata = tx.open_table(tables.partition_meta).unwrap();
    metadata
        .insert(
            info.partition.as_str(),
            serde_json::to_vec(info).unwrap().as_slice(),
        )
        .unwrap();
    drop(metadata);
    let mut data = tx.open_table(tables.partition_data).unwrap();
    let partition = info.partition.as_bytes();
    data.insert(
        (partition, b"terminalMethods".as_slice()),
        encode(registry, br#"{"methods":{}}"#).as_slice(),
    )
    .unwrap();
    data.insert(
        (partition, b"bundle".as_slice()),
        encode(bundle, br#"{"javascript":"scope code"}"#).as_slice(),
    )
    .unwrap();
    match schema {
        Some(version) => {
            data.insert(
                (partition, b"schema".as_slice()),
                encode(version, br#"{"collections":[]}"#).as_slice(),
            )
            .unwrap();
        }
        None => {
            data.remove((partition, b"schema".as_slice())).unwrap();
        }
    }
}
fn current(projected: Projection) -> RegistryMetadata {
    match projected {
        Projection::Current(meta) => meta,
        unknown => panic!("expected current: {unknown:?}"),
    }
}
fn assert_no_sidecar(tx: &WriteTransaction, tables: Tables, scope: Scope<'_>) {
    let sidecar = tx.open_table(SIDECAR).unwrap();
    assert!(sidecar.get(scope.key(&tables, HEADER)).unwrap().is_none());
    assert!(sidecar.get(scope.key(&tables, BODY)).unwrap().is_none());
}
fn root_meta(tx: &WriteTransaction, tables: Tables) -> Loaded<RegistryMetadata> {
    with_root(tx, tables, |view| view.metadata).unwrap()
}

#[test]
fn sql_registry_meta_actual_rows_exact_physical_versions_and_absent_schema() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 17, 31, None);
    let meta = current(project_root(&tx, tables).unwrap());
    assert_eq!(
        (meta.epoch, meta.registry, meta.bundle, meta.schema),
        (0, 17, 31, SourceStamp::KnownAbsent)
    );
    assert_eq!(
        meta.encoded_bytes as usize,
        encode(17, br#"{"methods":{}}"#).len()
    );
    assert_eq!(meta.json_bytes as usize, br#"{"methods":{}}"#.len());
    assert_eq!(root_meta(&tx, tables), Loaded::Current(meta));
    let body = with_root(&tx, tables, |view| {
        assert_eq!(view.encoded, encode(17, br#"{"methods":{}}"#));
        view.encoded.len()
    })
    .unwrap();
    assert_eq!(body, Loaded::Current(meta.encoded_bytes as usize));
    let sidecar = tx.open_table(SIDECAR).unwrap();
    let header = sidecar
        .get(Scope::ROOT.key(&tables, HEADER))
        .unwrap()
        .unwrap();
    assert_eq!(header.value().len(), HEADER_BYTES);
    assert_eq!(header.value()[32], 0);
    assert_eq!(&header.value()[33..41], &[0; 8]);
}

#[test]
fn sql_registry_meta_schema_present_uses_actual_positive_version_not_high_water() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 3, 7, Some(u64::MAX));
    let meta = current(project_root(&tx, tables).unwrap());
    assert_eq!(meta.schema, SourceStamp::present(u64::MAX).unwrap());
    assert_eq!((meta.registry, meta.bundle), (3, 7));
    assert_eq!(root_meta(&tx, tables), Loaded::Current(meta));
    let sidecar = tx.open_table(SIDECAR).unwrap();
    let header = sidecar
        .get(Scope::ROOT.key(&tables, HEADER))
        .unwrap()
        .unwrap();
    assert_eq!(header.value()[32], 1);
    assert_eq!(&header.value()[33..41], &u64::MAX.to_le_bytes());
}

#[test]
fn sql_registry_meta_missing_is_unknown_not_explicit_empty_and_key_is_exact() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_row(&tx, tables, b"bundle", Some(&encode(9, b"{}")));
    root_row(
        &tx,
        tables,
        b"terminalmethods",
        Some(&encode(10, br#"{"methods":{}}"#)),
    );
    assert_eq!(
        project_root(&tx, tables).unwrap(),
        Projection::Unknown(Unknown::MissingRegistry)
    );
    assert_no_sidecar(&tx, tables, Scope::ROOT);
    root_row(
        &tx,
        tables,
        b"terminalMethods",
        Some(&encode(11, br#"{"methods":{}}"#)),
    );
    let meta = current(project_root(&tx, tables).unwrap());
    assert_eq!(meta.registry, 11);
    root_row(&tx, tables, b"terminalMethods", None);
    assert_eq!(
        project_root(&tx, tables).unwrap(),
        Projection::Unknown(Unknown::MissingRegistry)
    );
    assert_no_sidecar(&tx, tables, Scope::ROOT);
    assert_eq!(
        root_meta(&tx, tables),
        Loaded::Unknown(Unknown::MissingRegistry)
    );
}

#[test]
fn sql_registry_meta_missing_bundle_invalidates_header_and_body() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 1, 2, None);
    project_root(&tx, tables).unwrap();
    root_row(&tx, tables, b"bundle", None);
    assert_eq!(
        project_root(&tx, tables).unwrap(),
        Projection::Unknown(Unknown::MissingBundle)
    );
    assert_no_sidecar(&tx, tables, Scope::ROOT);
}

#[test]
fn sql_registry_meta_malformed_lengths_and_zero_versions_refuse_real_rows() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    for key in [b"terminalMethods".as_slice(), b"bundle", b"schema"] {
        for malformed in (0..=8)
            .map(|length| vec![1; length])
            .chain([encode(0, b"{}")])
        {
            root_code(&tx, tables, 1, 2, Some(3));
            project_root(&tx, tables).unwrap();
            root_row(&tx, tables, key, Some(&malformed));
            assert_eq!(
                project_root(&tx, tables).unwrap(),
                Projection::Unknown(Unknown::MalformedRecord),
                "key {key:?} length {}",
                malformed.len()
            );
            assert_no_sidecar(&tx, tables, Scope::ROOT);
        }
    }
}

#[test]
fn sql_registry_meta_caps_encoded_body_and_packed_advertised_json_before_insert() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 1, 2, None);
    let mut raw = 4u64.to_le_bytes().to_vec();
    raw.extend(vec![b' '; MAX_BYTES + 1]);
    root_row(&tx, tables, b"terminalMethods", Some(&raw));
    assert_eq!(
        project_root(&tx, tables).unwrap(),
        Projection::Unknown(Unknown::Oversized)
    );
    assert_no_sidecar(&tx, tables, Scope::ROOT);
    let encoded = encode(4, &vec![b' '; MAX_BYTES + 1]);
    assert!(encoded.len() < MAX_BYTES); // actual pack, still too much decoded JSON
    root_row(&tx, tables, b"terminalMethods", Some(&encoded));
    assert_eq!(
        project_root(&tx, tables).unwrap(),
        Projection::Unknown(Unknown::Oversized)
    );
    assert_no_sidecar(&tx, tables, Scope::ROOT);
}

#[test]
fn sql_registry_meta_exact_caps_accept_without_unpacking() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 1, 2, None);
    let mut raw = 9u64.to_le_bytes().to_vec();
    raw.extend_from_slice(br#"{"methods":{}}"#);
    raw.resize(MAX_ROW_BYTES, b' ');
    root_row(&tx, tables, b"terminalMethods", Some(&raw));
    let meta = current(project_root(&tx, tables).unwrap());
    assert_eq!(meta.encoded_bytes as usize, MAX_ROW_BYTES);
    assert_eq!(meta.json_bytes as usize, MAX_BYTES);
    let mut json = br#"{"methods":{}}"#.to_vec();
    json.resize(MAX_BYTES, b' ');
    let packed = encode(10, &json);
    assert_eq!(packed[8], 0);
    root_row(&tx, tables, b"terminalMethods", Some(&packed));
    let meta = current(project_root(&tx, tables).unwrap());
    assert_eq!(meta.json_bytes as usize, MAX_BYTES);
    assert_eq!(
        with_root(&tx, tables, |view| view.encoded == packed).unwrap(),
        Loaded::Current(true)
    );
}

#[test]
fn sql_registry_meta_malformed_packed_header_block_and_length_are_unknown() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    for malformed in [
        vec![0],
        vec![0, 1],
        vec![0, 1, 0, 0, 0],
        vec![0, 0, 0, 0, 0, 0],
        vec![0, 1, 0, 0, 0, 0x20, b'a'],       // truncated literal
        vec![0, 1, 0, 0, 0, 0x10, b'a', 0, 0], // invalid zero match offset
        vec![0, 5, 0, 0, 0, 0, 1, 0],          // match before output
        vec![0, 1, 0, 0, 0, 0xf0, 255],        // truncated length extension
        vec![0, 2, 0, 0, 0, 0x10, b'a'],       // exact advertised mismatch
    ] {
        root_code(&tx, tables, 1, 2, None);
        project_root(&tx, tables).unwrap();
        let mut encoded = 3u64.to_le_bytes().to_vec();
        encoded.extend(malformed);
        root_row(&tx, tables, b"terminalMethods", Some(&encoded));
        assert_eq!(
            project_root(&tx, tables).unwrap(),
            Projection::Unknown(Unknown::MalformedRecord)
        );
        assert_no_sidecar(&tx, tables, Scope::ROOT);
    }
}

#[test]
fn sql_registry_meta_real_packed_shapes_and_corrupted_advertised_sizes() {
    for size in [1, 16, 127, 128, 129, 255, 256, 257, 512, 4096, MAX_BYTES] {
        for pattern in [
            b" ".as_slice(),
            b"{\"methods\":{\"unicode\":\"actual code\"}}",
            "\"🌺\"".as_bytes(),
        ] {
            let json: Vec<_> = pattern.iter().copied().cycle().take(size).collect();
            let encoded = encode(55, &json);
            assert_eq!(registry_shape(&encoded).unwrap(), (55, size as u32));
            if encoded[8] == 0 {
                let mut corrupted = encoded.clone();
                corrupted[9..13].copy_from_slice(&((size as u32) - 1).to_le_bytes());
                assert!(registry_shape(&corrupted).is_err());
            }
        }
    }
}

#[test]
fn sql_registry_meta_sidecar_missing_or_stale_never_calls_loader() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 1, 2, None);
    assert_eq!(
        with_root(&tx, tables, |_| panic!("missing header callback")).unwrap(),
        Loaded::<()>::Unknown(Unknown::MissingHeader)
    );
    project_root(&tx, tables).unwrap();
    root_row(&tx, tables, b"bundle", Some(&encode(3, b"{}")));
    assert_eq!(
        with_root(&tx, tables, |_| panic!("stale callback")).unwrap(),
        Loaded::<()>::Unknown(Unknown::Stale)
    );
    project_root(&tx, tables).unwrap();
    tx.open_table(SIDECAR)
        .unwrap()
        .remove(Scope::ROOT.key(&tables, BODY))
        .unwrap();
    assert_eq!(
        with_root(&tx, tables, |_| panic!("missing body callback")).unwrap(),
        Loaded::<()>::Unknown(Unknown::MissingBody)
    );
}

#[test]
fn sql_registry_meta_stale_all_actual_code_versions_and_schema_presence() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    for key in [b"terminalMethods".as_slice(), b"bundle", b"schema"] {
        root_code(&tx, tables, 1, 2, Some(3));
        project_root(&tx, tables).unwrap();
        let body = if key == b"terminalMethods" {
            br#"{"methods":{}}"#.as_slice()
        } else {
            b"{}".as_slice()
        };
        root_row(&tx, tables, key, Some(&encode(99, body)));
        assert_eq!(root_meta(&tx, tables), Loaded::Unknown(Unknown::Stale));
    }
    root_code(&tx, tables, 1, 2, None);
    project_root(&tx, tables).unwrap();
    root_row(&tx, tables, b"schema", Some(&encode(3, b"{}")));
    assert_eq!(root_meta(&tx, tables), Loaded::Unknown(Unknown::Stale));
    project_root(&tx, tables).unwrap();
    root_row(&tx, tables, b"schema", None);
    assert_eq!(root_meta(&tx, tables), Loaded::Unknown(Unknown::Stale));
}

#[test]
fn sql_registry_meta_malformed_header_fixed_type_discriminant_and_positive_schema() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 1, 2, None);
    let valid = encode_header(current(project_root(&tx, tables).unwrap()));
    let mut malformed: Vec<Vec<u8>> = (0..HEADER_BYTES)
        .map(|length| valid[..length].to_vec())
        .collect();
    let mut long = valid.to_vec();
    long.push(0);
    malformed.push(long);
    for offset in [0, 7, 32, 49, 55] {
        let mut header = valid;
        header[offset] = 2;
        malformed.push(header.to_vec());
    }
    for range in [16..24, 24..32, 41..45, 45..49] {
        let mut header = valid;
        header[range].fill(0);
        malformed.push(header.to_vec());
    }
    let mut present_zero = valid;
    present_zero[32] = 1;
    malformed.push(present_zero.to_vec());
    let mut absent_positive = valid;
    absent_positive[33] = 7;
    malformed.push(absent_positive.to_vec());
    for header in malformed {
        tx.open_table(SIDECAR)
            .unwrap()
            .insert(Scope::ROOT.key(&tables, HEADER), header.as_slice())
            .unwrap();
        assert_eq!(
            with_root(&tx, tables, |_| panic!("corrupt header callback")).unwrap(),
            Loaded::<()>::Unknown(Unknown::MalformedHeader)
        );
    }
}

#[test]
fn sql_registry_meta_body_corruption_even_same_version_and_bounds_are_refused() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 1, 2, None);
    project_root(&tx, tables).unwrap();
    tx.open_table(SIDECAR)
        .unwrap()
        .insert(
            Scope::ROOT.key(&tables, BODY),
            encode(1, br#"{"methods":{"bad":1}}"#).as_slice(),
        )
        .unwrap();
    assert_eq!(root_meta(&tx, tables), Loaded::Unknown(Unknown::Stale));
    tx.open_table(SIDECAR)
        .unwrap()
        .insert(
            Scope::ROOT.key(&tables, BODY),
            vec![7; MAX_ROW_BYTES + 1].as_slice(),
        )
        .unwrap();
    assert_eq!(root_meta(&tx, tables), Loaded::Unknown(Unknown::Oversized));
}

#[test]
fn sql_registry_meta_same_version_source_byte_damage_is_stale() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 1, 2, None);
    project_root(&tx, tables).unwrap();
    root_row(
        &tx,
        tables,
        b"terminalMethods",
        Some(&encode(1, br#"{"methods":{"x":0}}"#)),
    );
    assert_eq!(root_meta(&tx, tables), Loaded::Unknown(Unknown::Stale));
}

#[test]
fn sql_registry_meta_scoped_exact_long_utf8_nul_names_no_collision_and_root_separate() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 1, 2, None);
    let root = current(project_root(&tx, tables).unwrap());
    let long = format!("{}\0tail", "🌺".repeat(3000));
    let names = ["root", "a", "a\0", "a/b", long.as_str()];
    for (i, name) in names.iter().enumerate() {
        let native = info(name, (i + 1) as u64, PartitionPhase::Active);
        scoped_code(&tx, tables, &native, 100 + i as u64, 200 + i as u64, None);
        let meta = current(project_partition(&tx, tables, &native).unwrap());
        assert_eq!(
            with_partition(&tx, tables, &native, |view| view.metadata).unwrap(),
            Loaded::Current(meta)
        );
    }
    assert_eq!(root_meta(&tx, tables), Loaded::Current(root));
    for (i, name) in names.iter().enumerate() {
        let native = info(name, (i + 1) as u64, PartitionPhase::Active);
        assert_eq!(
            with_partition(&tx, tables, &native, |view| view.metadata.registry).unwrap(),
            Loaded::Current(100 + i as u64)
        );
    }
    let empty = info("", 1, PartitionPhase::Active);
    assert_eq!(
        project_partition(&tx, tables, &empty).unwrap(),
        Projection::Unknown(Unknown::InvalidPartition)
    );
    assert_eq!(root_meta(&tx, tables), Loaded::Current(root));
}

#[test]
fn sql_registry_meta_nonactive_actual_partition_phases_invalidate_both_rows() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    for phase in [
        PartitionPhase::Importing,
        PartitionPhase::Staged,
        PartitionPhase::Copied,
        PartitionPhase::Frozen,
        PartitionPhase::Retired,
    ] {
        let mut native = info("scope", 11, PartitionPhase::Active);
        scoped_code(&tx, tables, &native, 1, 2, None);
        project_partition(&tx, tables, &native).unwrap();
        native.phase = phase;
        scoped_code(&tx, tables, &native, 1, 2, None);
        assert_eq!(
            with_partition(&tx, tables, &native, |_| panic!("inactive callback")).unwrap(),
            Loaded::<()>::Unknown(Unknown::Inactive)
        );
        assert_eq!(
            project_partition(&tx, tables, &native).unwrap(),
            Projection::Unknown(Unknown::Inactive)
        );
        assert_no_sidecar(&tx, tables, partition_scope(&native));
    }
}

#[test]
fn sql_registry_meta_partition_safe_positive_epoch_and_epoch_staleness() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    let mut native = info("scope", MAX_EPOCH, PartitionPhase::Active);
    scoped_code(&tx, tables, &native, 1, 2, Some(3));
    project_partition(&tx, tables, &native).unwrap();
    native.epoch -= 1;
    assert_eq!(
        with_partition(&tx, tables, &native, |_| ()).unwrap(),
        Loaded::Unknown(Unknown::Stale)
    );
    for invalid in [0, MAX_EPOCH + 1, u64::MAX] {
        native.epoch = invalid;
        assert_eq!(
            project_partition(&tx, tables, &native).unwrap(),
            Projection::Unknown(Unknown::InvalidPartition)
        );
        assert_no_sidecar(&tx, tables, partition_scope(&native));
    }
}

#[test]
fn sql_registry_meta_scoped_missing_registry_bundle_and_present_schema_refusals() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    let native = info("scope", 8, PartitionPhase::Active);
    for (key, reason) in [
        (b"terminalMethods".as_slice(), Unknown::MissingRegistry),
        (b"bundle".as_slice(), Unknown::MissingBundle),
        (b"schema".as_slice(), Unknown::MalformedRecord),
    ] {
        scoped_code(&tx, tables, &native, 1, 2, Some(3));
        project_partition(&tx, tables, &native).unwrap();
        let mut data = tx.open_table(tables.partition_data).unwrap();
        if key == b"schema" {
            data.insert((native.partition.as_bytes(), key), &[0; 8][..])
                .unwrap();
        } else {
            data.remove((native.partition.as_bytes(), key)).unwrap();
        }
        drop(data);
        assert_eq!(
            project_partition(&tx, tables, &native).unwrap(),
            Projection::Unknown(reason)
        );
        assert_no_sidecar(&tx, tables, partition_scope(&native));
    }
}

#[test]
fn sql_registry_meta_exact_physical_store_namespace_one_global_table() {
    let db = database();
    let a = Tables::new("replica/1/");
    let b = Tables::new("replica/10/");
    let tx = db.begin_write().unwrap();
    root_code(&tx, a, 1, 2, None);
    root_code(&tx, b, 3, 4, Some(5));
    let ma = current(project_root(&tx, a).unwrap());
    let mb = current(project_root(&tx, b).unwrap());
    let native = info("same scope", 1, PartitionPhase::Active);
    scoped_code(&tx, a, &native, 6, 7, None);
    scoped_code(&tx, b, &native, 8, 9, None);
    project_partition(&tx, a, &native).unwrap();
    project_partition(&tx, b, &native).unwrap();
    assert_eq!(root_meta(&tx, a), Loaded::Current(ma));
    assert_eq!(root_meta(&tx, b), Loaded::Current(mb));
    assert_eq!(
        tx.list_tables()
            .unwrap()
            .filter(|table| table.name() == TABLE_NAME)
            .count(),
        1
    );
    assert_eq!(tx.open_table(SIDECAR).unwrap().len().unwrap(), 8);
    invalidate_store(&tx, a).unwrap();
    assert_eq!(root_meta(&tx, a), Loaded::Unknown(Unknown::MissingHeader));
    assert_eq!(root_meta(&tx, b), Loaded::Current(mb));
    assert_eq!(
        with_partition(&tx, b, &native, |view| view.metadata.registry).unwrap(),
        Loaded::Current(8)
    );
    assert_eq!(tx.open_table(SIDECAR).unwrap().len().unwrap(), 4);
}

#[test]
fn sql_registry_meta_explicit_invalidation_is_scope_specific() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 1, 2, None);
    let root = current(project_root(&tx, tables).unwrap());
    let native = info("scope", 1, PartitionPhase::Active);
    scoped_code(&tx, tables, &native, 3, 4, None);
    project_partition(&tx, tables, &native).unwrap();
    invalidate_partition(&tx, tables, &native).unwrap();
    assert_no_sidecar(&tx, tables, partition_scope(&native));
    assert_eq!(root_meta(&tx, tables), Loaded::Current(root));
    project_partition(&tx, tables, &native).unwrap();
    invalidate_root(&tx, tables).unwrap();
    assert_no_sidecar(&tx, tables, Scope::ROOT);
    assert_eq!(
        with_partition(&tx, tables, &native, |view| view.metadata.registry).unwrap(),
        Loaded::Current(3)
    );
}

#[test]
fn sql_registry_meta_coalesced_projection_versions_come_after_each_real_write() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 11, 12, Some(13));
    let first = current(project_root(&tx, tables).unwrap());
    assert_eq!(
        (first.registry, first.bundle, first.schema),
        (11, 12, SourceStamp::present(13).unwrap())
    );
    root_code(&tx, tables, 21, 22, None);
    let second = current(project_root(&tx, tables).unwrap());
    assert_eq!(
        (second.registry, second.bundle, second.schema),
        (21, 22, SourceStamp::KnownAbsent)
    );
    assert_eq!(root_meta(&tx, tables), Loaded::Current(second));
    tx.commit().unwrap();
    let tx = db.begin_write().unwrap();
    assert_eq!(root_meta(&tx, tables), Loaded::Current(second));
}

#[test]
fn sql_registry_meta_mixed_coalesced_root_and_scoped_transactions_never_mix_code() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    let native = info("scope", 1, PartitionPhase::Active);
    root_code(&tx, tables, 11, 12, None);
    project_root(&tx, tables).unwrap();
    scoped_code(&tx, tables, &native, 21, 22, Some(23));
    project_partition(&tx, tables, &native).unwrap();
    root_row(&tx, tables, b"bundle", Some(&encode(31, b"{}")));
    let root = current(project_root(&tx, tables).unwrap());
    scoped_code(&tx, tables, &native, 41, 42, None);
    let scoped = current(project_partition(&tx, tables, &native).unwrap());
    assert_eq!((root.registry, root.bundle), (11, 31));
    assert_eq!((scoped.registry, scoped.bundle), (41, 42));
    assert_eq!(root_meta(&tx, tables), Loaded::Current(root));
    assert_eq!(
        with_partition(&tx, tables, &native, |view| view.metadata).unwrap(),
        Loaded::Current(scoped)
    );
}

#[test]
fn sql_registry_meta_rollback_source_header_body_and_unknown_removal_are_atomic() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 1, 2, None);
    let original = current(project_root(&tx, tables).unwrap());
    tx.commit().unwrap();
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 3, 4, Some(5));
    let changed = current(project_root(&tx, tables).unwrap());
    assert_ne!(changed, original);
    tx.abort().unwrap();
    let tx = db.begin_write().unwrap();
    assert_eq!(root_meta(&tx, tables), Loaded::Current(original));
    root_row(&tx, tables, b"terminalMethods", None);
    project_root(&tx, tables).unwrap();
    assert_no_sidecar(&tx, tables, Scope::ROOT);
    tx.abort().unwrap();
    let tx = db.begin_write().unwrap();
    assert_eq!(root_meta(&tx, tables), Loaded::Current(original));
}

#[test]
fn sql_registry_meta_redb_error_is_typed_storage_and_aborted_source_not_published() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    let wrong: TableDefinition<u64, u64> = TableDefinition::new(TABLE_NAME);
    tx.open_table(wrong).unwrap().insert(1, 2).unwrap();
    tx.commit().unwrap();
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 1, 2, None);
    assert_eq!(project_root(&tx, tables), Err(MetaError::Storage));
    tx.abort().unwrap();
    let tx = db.begin_write().unwrap();
    assert!(
        tx.open_table(tables.data)
            .unwrap()
            .get(b"terminalMethods".as_slice())
            .unwrap()
            .is_none()
    );
}

#[test]
fn sql_registry_meta_fixed_header_and_lz4_shape_have_zero_rust_heap() {
    let encoded = encode(10, &vec![b' '; MAX_BYTES]);
    let meta = RegistryMetadata {
        epoch: 0,
        registry: 10,
        bundle: 20,
        schema: SourceStamp::KnownAbsent,
        encoded_bytes: encoded.len() as u32,
        json_bytes: MAX_BYTES as u32,
    };
    let ((shape, decoded), operations, bytes) = crate::allocation_probe::measure(|| {
        (
            registry_shape(&encoded),
            decode_header(&encode_header(meta), Scope::ROOT),
        )
    });
    assert_eq!((operations, bytes), (0, 0));
    assert_eq!(shape, Ok((10, MAX_BYTES as u32)));
    assert_eq!(decoded, Ok(meta));
    // redb's own page/I/O allocations are NOT covered by this helper-only probe.
}

fn entry(index: u64, revision: u64, version: u64) -> Entry<TypeConfig> {
    Entry {
        log_id: LogId::new(CommittedLeaderId::new(3, 1), index),
        payload: EntryPayload::Normal(
            Commit {
                internal: true,
                request_id: String::new(),
                fingerprint: String::new(),
                expected_revision: revision,
                puts: BTreeMap::from([
                    (
                        "terminalMethods".into(),
                        json!({"methods":{},"testGeneration":version}),
                    ),
                    (
                        "bundle".into(),
                        json!({"javascript":"actual store code","testGeneration":version}),
                    ),
                ]),
                deletes: Vec::new(),
                result: Value::Null,
            }
            .into(),
        ),
    }
}

#[tokio::test]
async fn sql_registry_meta_real_store_open_apply_drain_and_same_source_projection() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, directory.path().into()).await.unwrap();
    store.apply([entry(1, 0, 1)]).await.unwrap();
    store.inner.persistence.drain().await.unwrap();
    let actual_registry = store
        .inner
        .state
        .read()
        .await
        .application
        .data
        .raw_version("terminalMethods")
        .unwrap();
    let actual_bundle = store
        .inner
        .state
        .read()
        .await
        .application
        .data
        .raw_version("bundle")
        .unwrap();
    let tables = store.inner.tables;
    let meta = store.database_work().run(|db| {
        let tx = db.begin_write().unwrap();
        let meta = current(project_root(&tx, tables).unwrap());
        assert_eq!(root_meta(&tx, tables), Loaded::Current(meta));
        tx.commit().unwrap();
        meta
    });
    assert_eq!(
        (meta.registry, meta.bundle, meta.schema),
        (actual_registry, actual_bundle, SourceStamp::KnownAbsent)
    );
    store.apply([entry(2, 1, 2)]).await.unwrap();
    store.inner.persistence.drain().await.unwrap();
    store.database_work().run(|db| {
        let tx = db.begin_write().unwrap();
        // Hooks may already be wired by the parent; either path must validate
        // actual physical rows, never adopt old sidecar bytes.
        let fresh = current(project_root(&tx, tables).unwrap());
        assert_ne!(fresh.registry, meta.registry);
        assert_ne!(fresh.bundle, meta.bundle);
        assert_eq!(root_meta(&tx, tables), Loaded::Current(fresh));
        tx.commit().unwrap();
    });
    store.close().await.unwrap();
}

#[tokio::test]
async fn sql_registry_meta_real_queued_later_live_state_cannot_change_earlier_transaction() {
    use std::time::Duration;
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, directory.path().into()).await.unwrap();
    store.apply([entry(1, 0, 1)]).await.unwrap();
    store.inner.persistence.drain().await.unwrap();
    let first = store
        .inner
        .state
        .read()
        .await
        .application
        .data
        .raw_version("terminalMethods")
        .unwrap();
    let tables = store.inner.tables;
    let work = store.database_work();
    let (entered, seen) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let held = tokio::task::spawn_blocking(move || {
        work.run(|db| {
            let tx = db.begin_write().unwrap();
            entered.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(10)).unwrap();
            // This transaction contains the earlier durable projection while the
            // real Store has already published the later queued state in memory.
            let meta = current(project_root(&tx, tables).unwrap());
            assert_eq!(meta.registry, first);
            assert_eq!(root_meta(&tx, tables), Loaded::Current(meta));
            tx.commit().unwrap();
            meta
        })
    });
    tokio::time::timeout(Duration::from_secs(10), seen)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), store.apply([entry(2, 1, 2)]))
        .await
        .unwrap()
        .unwrap();
    let later = store
        .inner
        .state
        .read()
        .await
        .application
        .data
        .raw_version("terminalMethods")
        .unwrap();
    assert_ne!(first, later);
    release.send(()).unwrap();
    let earlier = held.await.unwrap();
    assert_eq!(earlier.registry, first);
    store.inner.persistence.drain().await.unwrap();
    store.database_work().run(|db| {
        let tx = db.begin_write().unwrap();
        let latest = current(project_root(&tx, tables).unwrap());
        assert_eq!(latest.registry, later);
        tx.commit().unwrap();
    });
    store.close().await.unwrap();
}

#[tokio::test]
async fn sql_registry_meta_real_store_scoped_apply_drain_actual_partition_info() {
    use crate::consensus::PartitionCommand;
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, directory.path().into()).await.unwrap();
    let name = format!("{}\0scope", "🌺".repeat(1200));
    for (index, control) in [
        (
            1,
            PartitionCommand::Create {
                partition: name.clone(),
                epoch: 7,
                operation: "native-scoped".into(),
            },
        ),
        (
            2,
            PartitionCommand::Activate {
                partition: name.clone(),
                epoch: 7,
                operation: "native-scoped".into(),
            },
        ),
    ] {
        let response = store
            .apply([Entry {
                log_id: LogId::new(CommittedLeaderId::new(3, 1), index),
                payload: EntryPayload::Normal(RaftCommand::PartitionControl {
                    partition_control: control,
                    leader_id: None,
                }),
            }])
            .await
            .unwrap();
        assert!(matches!(response.as_slice(), [ApplyResult::Partition(_)]));
    }
    let mut scoped = entry(3, 0, 1);
    let EntryPayload::Normal(command) = scoped.payload else {
        unreachable!()
    };
    scoped.payload = EntryPayload::Normal(RaftCommand::Scoped {
        partition: name.clone(),
        epoch: 7,
        command: Box::new(command),
    });
    assert!(matches!(
        store.apply([scoped]).await.unwrap().as_slice(),
        [ApplyResult::Committed(_)]
    ));
    store.inner.persistence.drain().await.unwrap();
    // This is the ACTUAL recovered/live native PartitionState produced by
    // these real commands, used only after drain in this nonconcurrent test.
    let guard = store.inner.state.read().await;
    let native = guard.partitions.get(&name).unwrap();
    let registry = native.snapshot.data.raw_version("terminalMethods").unwrap();
    let bundle = native.snapshot.data.raw_version("bundle").unwrap();
    let actual_info = native.info.clone();
    drop(guard);
    let tables = store.inner.tables;
    store.database_work().run(|db| {
        let tx = db.begin_write().unwrap();
        let meta = current(project_partition(&tx, tables, &actual_info).unwrap());
        assert_eq!(
            (meta.epoch, meta.registry, meta.bundle, meta.schema),
            (7, registry, bundle, SourceStamp::KnownAbsent)
        );
        assert_eq!(
            with_partition(&tx, tables, &actual_info, |view| view.metadata).unwrap(),
            Loaded::Current(meta)
        );
        assert_eq!(
            root_meta(&tx, tables),
            Loaded::Unknown(Unknown::MissingRegistry)
        );
        tx.commit().unwrap();
    });
    store.close().await.unwrap();
}

#[test]
fn sql_registry_meta_code_rows_malformed_packed_envelopes_never_become_absent() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    for key in [b"bundle".as_slice(), b"schema"] {
        for body in [
            vec![0],
            vec![0, 1],
            vec![0, 1, 0, 0, 0],
            vec![0, 0, 0, 0, 0, 0],
            vec![0, 255, 255, 255, 255, 0],
        ] {
            root_code(&tx, tables, 1, 2, Some(3));
            project_root(&tx, tables).unwrap();
            let mut malformed = 77u64.to_le_bytes().to_vec();
            malformed.extend(body);
            root_row(&tx, tables, key, Some(&malformed));
            assert_eq!(
                project_root(&tx, tables).unwrap(),
                Projection::Unknown(Unknown::MalformedRecord)
            );
            assert_no_sidecar(&tx, tables, Scope::ROOT);
        }
    }
}

#[test]
fn sql_registry_meta_large_bundle_schema_have_no_registry_size_clamp() {
    let db = database();
    let tables = Tables::new("");
    let tx = db.begin_write().unwrap();
    root_code(&tx, tables, 1, 2, None);
    let body = vec![b' '; MAX_BYTES * 3];
    root_row(&tx, tables, b"bundle", Some(&encode(2, &body)));
    root_row(&tx, tables, b"schema", Some(&encode(3, &body)));
    let meta = current(project_root(&tx, tables).unwrap());
    assert_eq!(
        (meta.bundle, meta.schema),
        (2, SourceStamp::present(3).unwrap())
    );
    assert_eq!(root_meta(&tx, tables), Loaded::Current(meta));
}
