//! Bounded metadata-only census of one open local replica, not a backup scanner.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

static PUBLICATIONS: std::sync::Mutex<u64> = std::sync::Mutex::new(1);
pub(super) fn next_generation() -> u64 {
    let mut next = PUBLICATIONS
        .lock()
        .expect("physical census publication identity lock");
    let generation = *next;
    *next = next
        .checked_add(1)
        .expect("physical census publication identity exhausted");
    generation
}

pub(crate) const MAX_BYTES: usize = 64 * 1024;
pub(crate) const MAX_CURSOR: usize = 4096;
#[cfg(test)]
thread_local! { static VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
fn visited() {
    #[cfg(test)]
    VISITS.with(|visits| visits.set(visits.get() + 1));
}

const SCOPE: &str = "local-live-store";
const MAX_IDENTITY_BYTES: usize = 1024;

pub(super) struct Identity {
    secret: [u8; 32],
    store: String,
}
impl Identity {
    pub(super) fn new() -> anyhow::Result<Self> {
        let mut secret = [0; 32];
        getrandom::fill(&mut secret).context("physical census identity randomness")?;
        Ok(Self {
            store: crate::evaluator::hash(&secret),
            secret,
        })
    }

    // HMAC-SHA256, domain separated. The token is an observation, not read authority.
    fn tag(&self, bytes: &[u8]) -> Vec<u8> {
        let mut inner_pad = [0x36; 64];
        let mut outer_pad = [0x5c; 64];
        for (position, byte) in self.secret.iter().enumerate() {
            inner_pad[position] ^= byte;
            outer_pad[position] ^= byte;
        }
        let mut inner = Sha256::new();
        inner.update(inner_pad);
        inner.update(b"flower-physical-census-v1\0");
        inner.update(bytes);
        let mut outer = Sha256::new();
        outer.update(outer_pad);
        outer.update(inner.finalize());
        outer.finalize().to_vec()
    }
    fn encode(&self, cursor: &Cursor) -> anyhow::Result<String> {
        let bytes = serde_json::to_vec(cursor)?;
        let token = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&bytes),
            URL_SAFE_NO_PAD.encode(self.tag(&bytes))
        );
        anyhow::ensure!(
            token.len() <= MAX_CURSOR,
            "PHYSICAL_CENSUS_BUDGET: cursor exceeds limit"
        );
        Ok(token)
    }
    fn decode(&self, token: &str) -> anyhow::Result<Cursor> {
        anyhow::ensure!(
            token.len() <= MAX_CURSOR,
            "PHYSICAL_CENSUS_CURSOR: cursor exceeds limit"
        );
        let parse = || -> anyhow::Result<Cursor> {
            let (payload, signature) = token.split_once('.').context("cursor separator")?;
            let bytes = URL_SAFE_NO_PAD.decode(payload)?;
            let tag = URL_SAFE_NO_PAD.decode(signature)?;
            anyhow::ensure!(
                tag.len() == 32 && bool::from(tag.ct_eq(&self.tag(&bytes))),
                "cursor signature"
            );
            let cursor: Cursor = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                serde_json::to_vec(&cursor)? == bytes && self.encode(&cursor)? == token,
                "noncanonical cursor"
            );
            Ok(cursor)
        };
        parse().map_err(|_| {
            anyhow::anyhow!("PHYSICAL_CENSUS_CURSOR: invalid local observation cursor")
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    scope: String,
    store: String,
    incarnation: String,
    group: Option<String>,
    fence: Fence,
    after: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fence {
    term: String,
    node: String,
    index: String,
    revision: String,
}
impl Fence {
    fn new(applied: LogId<u64>, revision: u64) -> Self {
        Self {
            term: applied.leader_id.term.to_string(),
            node: applied.leader_id.node_id.to_string(),
            index: applied.index.to_string(),
            revision: revision.to_string(),
        }
    }
}

fn state_metadata(data: &Records, requests: &Receipts) -> Value {
    json!({
        "applicationPresent": data.contains_key("bundle"),
        "recordsPresent": data.census_presence(),
        "receiptsPresent": requests.census_presence(),
        "deploymentJobPresent": data.contains_key("deployment:job"),
        "deploymentPlanPresent": data.contains_key("deployment:plan"),
        "stagedGenerationPresent": null,
        "cleanupPresent": null
    })
}
fn named_metadata(id: &str, state: &PartitionState) -> anyhow::Result<Value> {
    // Check borrowed lengths before cloning/serializing an arbitrarily long
    // restored name, operation, digest or transfer. Never skip a large entry.
    let mut bytes = id
        .len()
        .saturating_add(state.info.operation.len())
        .saturating_add(state.info.digest.as_ref().map_or(0, String::len));
    if let Some(transfer) = &state.info.transfer {
        for name in [
            &transfer.partition,
            &transfer.operation,
            &transfer.source,
            &transfer.destination,
        ] {
            bytes = bytes.saturating_add(name.len());
        }
    }
    anyhow::ensure!(
        bytes <= MAX_IDENTITY_BYTES,
        "PHYSICAL_CENSUS_BUDGET: physical identity metadata exceeds limit"
    );
    Ok(json!({
        "kind": "named", "partition": id,
        "info": {
            "partition": &state.info.partition, "epoch": state.info.epoch,
            "phase": state.info.phase, "operation": &state.info.operation,
            "transfer": &state.info.transfer, "revision": state.info.revision,
            "digest": &state.info.digest, "bytes": state.info.bytes.to_string(),
            "received_bytes": state.info.received_bytes.to_string(),
            "next_chunk": state.info.next_chunk.to_string(),
            "base_bytes": state.info.base_bytes.to_string()
        },
        "state": state_metadata(&state.snapshot.data, &state.snapshot.requests),
        "snapshotRevision": state.snapshot.revision.to_string(),
        "retainedBasePresent": state.base.is_some(),
        "retainedBaseRevision": state.base.as_ref().map(|base| base.revision.to_string()),
        "retainedBaseState": state.base.as_ref().map(|base| state_metadata(&base.data, &base.requests)),
        "importManifestPresent": state.info.phase == super::super::PartitionPhase::Importing || state.last_import.is_some(),
        "retainedImportManifestPresent": state.last_import.is_some(),
        "chunksPresent": if state.info.phase == super::super::PartitionPhase::Importing
            && !state.last_import.as_ref().is_some_and(|manifest| manifest.kind == partitions::ExportKind::Delta) {
                state.snapshot.data.census_presence()
            } else { state.chunks.census_presence() }
    }))
}
impl Store {
    pub(in crate::consensus) fn physical_partitions(
        &self,
        fresh: &super::super::read::ReadFence,
        limit: usize,
        token: Option<&str>,
        group: Option<&str>,
    ) -> anyhow::Result<Value> {
        anyhow::ensure!(
            (1..=100).contains(&limit),
            "PHYSICAL_CENSUS_REQUEST: limit must be 1..100"
        );
        anyhow::ensure!(
            group.is_none_or(|group| group.len() <= MAX_IDENTITY_BYTES),
            "PHYSICAL_CENSUS_BUDGET: group identity exceeds limit"
        );
        let namespace = self
            .inner
            .tables
            .meta
            .name()
            .strip_suffix("raft_meta_v1")
            .context("unavailable: unknown physical storage namespace")?;
        anyhow::ensure!(
            namespace.len() <= MAX_IDENTITY_BYTES,
            "PHYSICAL_CENSUS_BUDGET: storage namespace exceeds limit"
        );
        // A process-wide group label cannot identify EACH separately hosted
        // replica. Expose its native namespace instead; the manifest supplies
        // that replica's actual group identity, never infer it from a catalog.
        let group = if namespace.is_empty() { group } else { None };
        let identity = &self.inner.physical_identity;
        let cursor = token.map(|token| identity.decode(token)).transpose()?;
        // Bounded synchronous metadata work under the immutable publication
        // read guard. No Snapshot clone, record/receipt body decode, or async work.
        let state = self.inner.published.read().expect("published state lock");
        let applied = state
            .last_applied
            .context("unavailable: no local applied state")?;
        anyhow::ensure!(
            applied.index >= fresh.applied.index
                && applied.leader_id >= fresh.applied.leader_id
                && state.revision >= fresh.revision
                && (applied.index != fresh.applied.index || applied == fresh.applied)
                && (applied != fresh.applied || state.revision == fresh.revision),
            "PHYSICAL_CENSUS_DRIFT: local publication does not match fresh fence"
        );
        let fence = Fence::new(applied, state.revision);
        let incarnation = state.physical_generation.to_string();
        if let Some(cursor) = &cursor {
            anyhow::ensure!(
                cursor.version == 1
                    && cursor.scope == SCOPE
                    && cursor.store == identity.store
                    && cursor.group.as_deref() == group
                    && cursor.incarnation == incarnation
                    && cursor.fence == fence,
                "PHYSICAL_CENSUS_DRIFT: observation changed; restart the entire census"
            );
            anyhow::ensure!(
                cursor
                    .after
                    .as_ref()
                    .is_none_or(|id| state.partitions.get(id).is_some()),
                "PHYSICAL_CENSUS_CURSOR: missing physical cursor position"
            );
        }
        let mut items = Vec::with_capacity(limit);
        if cursor.is_none() {
            items.push(json!({
                "kind": "default", "partition": null, "info": null,
                "state": state_metadata(&state.data, &state.requests),
                "snapshotRevision": state.revision.to_string(),
                "retainedBasePresent": null, "retainedBaseRevision": null,
                "retainedBaseState": null, "importManifestPresent": null, "retainedImportManifestPresent": null,
                "chunksPresent": null
            }));
        }
        let mut after = cursor.as_ref().and_then(|cursor| cursor.after.as_deref());
        let mut candidates = state.partitions.after(after);
        let mut item_bytes = 0usize;
        // At most limit named candidates and one lookahead, regardless of the
        // catalog/map size. after() seeks in the physical persistent OrdMap.
        while items.len() < limit {
            let Some((id, partition)) = candidates.next() else {
                break;
            };
            visited();
            let item = named_metadata(id, partition)?;
            item_bytes = item_bytes.saturating_add(super::super::encoded_json_len(&item)?);
            anyhow::ensure!(
                item_bytes <= MAX_BYTES,
                "PHYSICAL_CENSUS_BUDGET: page exceeds byte limit; lower limit"
            );
            items.push(item);
            after = Some(id);
        }
        let complete = candidates.next().inspect(|_| visited()).is_none();
        let next_cursor = if complete {
            None
        } else {
            Some(identity.encode(&Cursor {
                version: 1,
                scope: SCOPE.into(),
                store: identity.store.clone(),
                incarnation: incarnation.clone(),
                group: group.map(str::to_owned),
                fence: fence.clone(),
                after: after.map(str::to_owned),
            })?)
        };
        let result = json!({
            "scope": SCOPE, "store": identity.store, "incarnation": incarnation,
            "node": self.inner.id.to_string(), "group": group, "storageNamespace": namespace,
            "persistentDatabaseIdentity": null,
            "fence": fence, "freshReadFence": Fence::new(fresh.applied, fresh.revision),
            "items": items, "nextCursor": next_cursor,
            "complete": complete, "defaultIncluded": cursor.is_none(),
            "externalScopeDiscovered": false,
            "coverage": "published-default-and-all-stored-named-partitions",
            "operatorFootprintManifestRequired": true,
            "excludedScopes": ["other stores and replicas", "backups", "restored or unmanaged directories", "archival snapshot files"],
            "unsupported": ["persistent database identity", "staged generation and cleanup state",
                "presence beyond 32 overlay slots or fully tombstoned backing"]
        });
        anyhow::ensure!(
            super::super::encoded_json_len(&result)? <= MAX_BYTES,
            "PHYSICAL_CENSUS_BUDGET: page exceeds byte limit; lower limit"
        );
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::partitions::copy::ImportManifest;
    use crate::consensus::{PartitionCommand, PartitionPhase, PartitionTransfer};
    use openraft::CommittedLeaderId;
    use std::io::{Seek, Write};
    use std::time::Duration;

    fn log() -> LogId<u64> {
        LogId::new(CommittedLeaderId::new(1, 1), 1)
    }
    fn seeded(count: usize, name_bytes: usize) -> StoredState {
        let mut state = StoredState {
            last_applied: Some(log()),
            ..StoredState::default()
        };
        state.application.revision = 1;
        state
            .application
            .data
            .insert("bundle".into(), json!("PRIVATE_APPLICATION_CANARY"));
        for n in 0..count {
            let partition = format!("p{n:05}{}", "x".repeat(name_bytes));
            state.partitions.insert(PartitionState {
                info: PartitionInfo {
                    partition,
                    epoch: 1,
                    phase: PartitionPhase::Active,
                    operation: "seed".into(),
                    transfer: None,
                    revision: 0,
                    digest: None,
                    bytes: 0,
                    received_bytes: 0,
                    next_chunk: 0,
                    base_bytes: 0,
                },
                snapshot: Snapshot::default(),
                base: None,
                last_import: None,
                chunks: Records::default(),
            });
        }
        state
    }
    async fn install(store: &mut Store, state: &StoredState) {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&serde_json::to_vec(state).unwrap()).unwrap();
        file.rewind().unwrap();
        let meta = SnapshotMeta {
            last_log_id: state.last_applied,
            last_membership: state.membership.clone(),
            snapshot_id: "physical-test".into(),
        };
        store
            .install_snapshot(&meta, Box::new(SnapshotData::from_std(file)))
            .await
            .unwrap();
    }
    fn page(store: &Store, limit: usize, token: Option<&str>) -> anyhow::Result<Value> {
        store.physical_partitions(&store.read_fence()?, limit, token, Some("local"))
    }

    #[tokio::test]
    async fn physical_census_native_restore_pages_seek_and_exhaust_ten_thousand_without_catalog() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(1, directory.path().into()).await.unwrap();
        install(&mut store, &seeded(10_000, 0)).await;
        let mut cursor: Option<String> = None;
        let mut ids = Vec::new();
        let mut defaults = 0;
        loop {
            VISITS.with(|visits| visits.set(0));
            let reply = page(&store, 25, cursor.as_deref()).unwrap();
            assert!(VISITS.with(|visits| visits.get()) <= 26);
            assert!(super::super::super::encoded_json_len(&reply).unwrap() <= MAX_BYTES);
            for item in reply["items"].as_array().unwrap() {
                if item["kind"] == "default" {
                    defaults += 1;
                } else {
                    ids.push(item["partition"].as_str().unwrap().to_owned());
                }
            }
            cursor = reply["nextCursor"].as_str().map(str::to_owned);
            assert_eq!(reply["complete"], cursor.is_none());
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(defaults, 1);
        assert_eq!(ids.len(), 10_000);
        assert_eq!(ids.first().unwrap(), "p00000");
        assert_eq!(ids.last().unwrap(), "p09999");
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn physical_census_cursors_bind_store_scope_group_canonical_position_and_same_fence_restore()
     {
        let directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(1, directory.path().into()).await.unwrap();
        let state = seeded(3, 0);
        install(&mut store, &state).await;
        let first = page(&store, 1, None).unwrap();
        assert_eq!(first["items"][0]["kind"], "default");
        let token = first["nextCursor"].as_str().unwrap();
        let second = page(&store, 1, Some(token)).unwrap();
        assert_eq!(second["items"][0]["partition"], "p00000");
        let identity = &store.inner.physical_identity;
        for change in [
            "scope",
            "group",
            "after",
            "store",
            "version",
            "fence",
            "incarnation",
        ] {
            let mut cursor = identity.decode(token).unwrap();
            match change {
                "scope" => cursor.scope = "all-stores".into(),
                "group" => cursor.group = Some("foreign".into()),
                "after" => cursor.after = Some("absent".into()),
                "store" => cursor.store = "other".into(),
                "version" => cursor.version = 2,
                "fence" => cursor.fence.index = "0".into(),
                "incarnation" => cursor.incarnation = "old".into(),
                _ => unreachable!(),
            }
            assert!(
                page(&store, 1, Some(&identity.encode(&cursor).unwrap())).is_err(),
                "{change}"
            );
        }
        for value in [json!({"offset": 1}), json!({"after": null}), json!([])] {
            let bytes = serde_json::to_vec(&value).unwrap();
            let malformed = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(&bytes),
                URL_SAFE_NO_PAD.encode(identity.tag(&bytes))
            );
            assert!(page(&store, 1, Some(&malformed)).is_err());
        }
        let canonical = serde_json::to_vec(&identity.decode(token).unwrap()).unwrap();
        let mut noncanonical = canonical.clone();
        noncanonical.push(b' ');
        let bad = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&noncanonical),
            URL_SAFE_NO_PAD.encode(identity.tag(&noncanonical))
        );
        assert!(page(&store, 1, Some(&bad)).is_err());
        let mut altered = serde_json::from_slice::<Value>(&canonical).unwrap();
        altered["offset"] = json!(1);
        let bytes = serde_json::to_vec(&altered).unwrap();
        let bad = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&bytes),
            URL_SAFE_NO_PAD.encode(identity.tag(&bytes))
        );
        assert!(page(&store, 1, Some(&bad)).is_err());
        let token = token.to_owned();
        // Identical log/revision/state installed again still MUST invalidate it.
        install(&mut store, &state).await;
        assert!(
            page(&store, 1, Some(&token))
                .unwrap_err()
                .to_string()
                .starts_with("PHYSICAL_CENSUS_DRIFT:")
        );
        store.close().await.unwrap();
        drop(store);
        let store = Store::open(1, directory.path().into()).await.unwrap();
        assert!(
            page(&store, 1, Some(&token))
                .unwrap_err()
                .to_string()
                .starts_with("PHYSICAL_CENSUS_CURSOR:")
        );
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn physical_census_hosted_namespaces_are_separate_local_stores_not_false_groups() {
        let directory = tempfile::tempdir().unwrap();
        let database = SharedDatabase::open(&directory.path().join("flower.redb")).unwrap();
        let mut a = Store::open(
            1,
            Storage::Shared {
                database: database.clone(),
                prefix: "a/".into(),
                directory: directory.path().join("a"),
            },
        )
        .await
        .unwrap();
        let mut b = Store::open(
            1,
            Storage::Shared {
                database,
                prefix: "b/".into(),
                directory: directory.path().join("b"),
            },
        )
        .await
        .unwrap();
        install(&mut a, &seeded(2, 0)).await;
        install(&mut b, &seeded(1, 0)).await;
        let first = page(&a, 1, None).unwrap();
        assert_eq!(first["storageNamespace"], "a/");
        assert_eq!(first["group"], Value::Null);
        let second = page(&b, 100, None).unwrap();
        assert_eq!(second["storageNamespace"], "b/");
        assert_eq!(second["items"].as_array().unwrap().len(), 2);
        assert_ne!(first["store"], second["store"]);
        assert!(
            page(&b, 1, first["nextCursor"].as_str())
                .unwrap_err()
                .to_string()
                .starts_with("PHYSICAL_CENSUS_CURSOR:")
        );
        let mut future = a.read_fence().unwrap();
        future.applied.index += 1;
        assert!(
            a.physical_partitions(&future, 1, None, Some("local"))
                .unwrap_err()
                .to_string()
                .starts_with("PHYSICAL_CENSUS_DRIFT:")
        );
        a.close().await.unwrap();
        b.close().await.unwrap();
    }

    #[tokio::test]
    async fn physical_census_budget_fails_closed_without_skipping_large_names_or_pages() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(1, directory.path().into()).await.unwrap();
        install(&mut store, &seeded(100, 900)).await;
        assert!(
            page(&store, 100, None)
                .unwrap_err()
                .to_string()
                .starts_with("PHYSICAL_CENSUS_BUDGET:")
        );
        let first = page(&store, 1, None).unwrap();
        assert_eq!(
            page(&store, 1, first["nextCursor"].as_str()).unwrap()["items"][0]["partition"],
            format!("p00000{}", "x".repeat(900))
        );
        install(&mut store, &seeded(1, 1024)).await;
        assert!(
            page(&store, 2, None)
                .unwrap_err()
                .to_string()
                .contains("identity metadata exceeds limit")
        );
        for limit in [0, 101, usize::MAX] {
            assert!(page(&store, limit, None).is_err());
        }
        store.close().await.unwrap();
    }

    #[test]
    fn physical_census_presence_never_decodes_bodies_or_fabricates_tombstone_absence() {
        use crate::consensus::backing::Backing;
        let backing = Arc::new(Backing::in_memory([(
            "private",
            1,
            b"NOT_JSON_PRIVATE_CANARY".to_vec(),
        )]));
        let data = Records::backed(backing.clone());
        let requests = Receipts::backed(backing);
        assert_eq!(data.census_presence(), Some(true));
        assert_eq!(requests.census_presence(), Some(true));
        let mut data = Records::backed(Arc::new(Backing::in_memory([(
            "private",
            2,
            b"true".to_vec(),
        )])));
        data.remove("private");
        assert_eq!(data.census_presence(), None);
        data.insert("visible".into(), json!("PRIVATE_VALUE_CANARY"));
        assert_eq!(data.census_presence(), Some(true));
        assert_eq!(Records::default().census_presence(), Some(false));
        let mut tombstones = Records::default();
        tombstones.keep_deletions();
        for n in 0..33 {
            tombstones.insert(format!("k{n}"), json!(true));
            tombstones.remove(&format!("k{n}"));
        }
        assert_eq!(tombstones.census_presence(), None);
        // Retained/import/chunk body selectors operate on native metadata only.
        let mut partition = seeded(1, 0).partitions.get("p00000").unwrap().clone();
        partition.base = Some(Snapshot {
            revision: 2,
            data,
            requests,
        });
        partition.last_import = Some(ImportManifest {
            kind: partitions::ExportKind::Base,
            revision: 2,
            digest: "0".repeat(64),
            bytes: 1,
            base_revision: None,
        });
        partition
            .chunks
            .insert("chunk".into(), json!("PRIVATE_CHUNK_CANARY"));
        let reply = named_metadata("p00000", &partition).unwrap();
        assert_eq!(reply["retainedBasePresent"], true);
        assert_eq!(reply["importManifestPresent"], true);
        assert_eq!(reply["chunksPresent"], true);
        assert!(!reply.to_string().contains("PRIVATE_"));
    }

    #[tokio::test]
    async fn physical_census_real_http_operator_auth_native_phases_private_canaries_and_readonly() {
        const OPERATOR: &str = "physical-local-test-operator";
        const PEER: &str = "physical-local-test-peer";
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let consensus = super::super::super::Consensus::open_with_tokens(
            1,
            address.clone(),
            directory.path().into(),
            OPERATOR.into(),
            PEER.into(),
        )
        .await
        .unwrap();
        let router = crate::service::router(consensus.clone(), OPERATOR.into());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        consensus
            .initialize(BTreeMap::from([(1, address.clone())]))
            .await
            .unwrap();
        consensus
            .raft
            .wait(Some(Duration::from_secs(5)))
            .current_leader(1, "local leader")
            .await
            .unwrap();
        consensus.read_query().await.unwrap();
        let seed = |id: &str, revision: u64| Commit {
            internal: false,
            request_id: id.into(),
            fingerprint: id.into(),
            expected_revision: revision,
            puts: BTreeMap::from([
                ("bundle".into(), json!("PRIVATE_CODE_CANARY")),
                (
                    "source:[\"private\",\"key\"]".into(),
                    json!("PRIVATE_RECORD_CANARY"),
                ),
                ("managedKeys".into(), json!("PRIVATE_KEYS_CANARY")),
                ("deployment:job".into(), json!("PRIVATE_JOB_CANARY")),
                ("deployment:plan".into(), json!("PRIVATE_PLAN_CANARY")),
            ]),
            deletes: vec![],
            result: json!("PRIVATE_RECEIPT_CANARY"),
        };
        let mut root = seed("default-seed", 0);
        root.puts.insert(
            "partition-catalog:partition:catalogued".into(),
            json!({"partition":"catalogued","private":"PRIVATE_CATALOG_CANARY"}),
        );
        consensus.commit(root).await.unwrap();
        for name in [
            "catalogued",
            "default",
            "orphan-active",
            "orphan-staged",
            "orphan-frozen",
            "orphan-retired",
            "orphan-captured",
        ] {
            consensus
                .control_partition(
                    PartitionCommand::Create {
                        partition: name.into(),
                        epoch: 1,
                        operation: "seed".into(),
                    },
                    None,
                )
                .await
                .unwrap();
            if name != "orphan-staged" {
                consensus
                    .control_partition(
                        PartitionCommand::Activate {
                            partition: name.into(),
                            epoch: 1,
                            operation: "seed".into(),
                        },
                        None,
                    )
                    .await
                    .unwrap();
                consensus
                    .partition(name, 1)
                    .unwrap()
                    .commit(seed(&format!("seed-{name}"), 0))
                    .await
                    .unwrap();
            }
        }
        let transfer = |name: &str| PartitionTransfer {
            partition: name.into(),
            operation: "copy".into(),
            source: "local".into(),
            destination: "elsewhere".into(),
            source_epoch: 1,
            epoch: 2,
        };
        consensus
            .control_partition(
                PartitionCommand::Capture {
                    transfer: transfer("orphan-captured"),
                    expected_revision: 1,
                    max_bytes: None,
                },
                None,
            )
            .await
            .unwrap();
        consensus
            .control_partition(
                PartitionCommand::Freeze {
                    transfer: transfer("orphan-frozen"),
                    expected_revision: 1,
                },
                None,
            )
            .await
            .unwrap();
        consensus
            .control_partition(
                PartitionCommand::Discard {
                    partition: "orphan-retired".into(),
                    epoch: 1,
                    operation: "retire".into(),
                },
                None,
            )
            .await
            .unwrap();
        let chunk = b"PRIVATE_IMPORT_CHUNK_CANARY";
        consensus
            .control_partition(
                PartitionCommand::BeginImport {
                    transfer: transfer("orphan-importing"),
                    revision: 1,
                    digest: crate::evaluator::hash(chunk),
                    bytes: chunk.len() as u64,
                },
                None,
            )
            .await
            .unwrap();
        consensus
            .control_partition(
                PartitionCommand::ImportChunk {
                    partition: "orphan-importing".into(),
                    epoch: 2,
                    operation: "copy".into(),
                    index: 0,
                    data: String::from_utf8(chunk.to_vec()).unwrap(),
                },
                None,
            )
            .await
            .unwrap();
        // Real base-copy seal and delta import exercise BOTH native chunk stores.
        let image = Snapshot {
            revision: 1,
            data: Records::from([("bundle".into(), json!("PRIVATE_COPIED_CODE_CANARY"))]),
            requests: Receipts::default(),
        };
        let image = serde_json::to_string(&image).unwrap();
        for name in ["orphan-copied", "orphan-delta"] {
            consensus
                .control_partition(
                    PartitionCommand::BeginCopy {
                        transfer: transfer(name),
                        revision: 1,
                        digest: crate::evaluator::hash(image.as_bytes()),
                        bytes: image.len() as u64,
                    },
                    None,
                )
                .await
                .unwrap();
            consensus
                .control_partition(
                    PartitionCommand::ImportChunk {
                        partition: name.into(),
                        epoch: 2,
                        operation: "copy".into(),
                        index: 0,
                        data: image.clone(),
                    },
                    None,
                )
                .await
                .unwrap();
            consensus
                .control_partition(
                    PartitionCommand::SealImport {
                        partition: name.into(),
                        epoch: 2,
                        operation: "copy".into(),
                    },
                    None,
                )
                .await
                .unwrap();
        }
        consensus
            .control_partition(
                PartitionCommand::BeginDelta {
                    transfer: transfer("orphan-delta"),
                    base_revision: 1,
                    revision: 2,
                    digest: crate::evaluator::hash(chunk),
                    bytes: chunk.len() as u64,
                },
                None,
            )
            .await
            .unwrap();
        consensus
            .control_partition(
                PartitionCommand::ImportChunk {
                    partition: "orphan-delta".into(),
                    epoch: 2,
                    operation: "copy".into(),
                    index: 0,
                    data: String::from_utf8(chunk.to_vec()).unwrap(),
                },
                None,
            )
            .await
            .unwrap();
        let before = consensus.local_snapshot().await;
        let before_infos = consensus.list_partitions().await.unwrap();
        let before_states: Vec<_> = before_infos
            .iter()
            .map(|info| consensus.store.partition_state(&info.partition).unwrap())
            .collect();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let url = format!("http://{address}/admin/partitions/physical");
        let user_jwt = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &json!({"sub":"fixture-user","exp":2000000000}),
            &jsonwebtoken::EncodingKey::from_secret(b"fixture-local-user-key"),
        )
        .unwrap();
        for bearer in [None, Some("wrong"), Some(PEER), Some(user_jwt.as_str())] {
            let request = client.post(&url).json(&json!({"scope":"local-live-store"}));
            let response = match bearer {
                Some(token) => request.bearer_auth(token),
                None => request,
            }
            .send()
            .await
            .unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
            let body = response.text().await.unwrap();
            assert!(!body.contains("orphan") && !body.contains("PRIVATE_"));
        }
        let default_page = client
            .post(&url)
            .bearer_auth(OPERATOR)
            .json(&json!({"scope":"local-live-store"}))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(default_page["items"].as_array().unwrap().len(), 11);
        assert_eq!(default_page["complete"], true);
        assert!(!default_page.to_string().contains("PRIVATE_"));
        let malformed = client
            .post(&url)
            .bearer_auth(OPERATOR)
            .json(&json!({"scope":"local-live-store","cursor":"offset:1"}))
            .send()
            .await
            .unwrap();
        assert_eq!(malformed.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            malformed.json::<Value>().await.unwrap()["error"]["code"],
            "PHYSICAL_CENSUS_CURSOR"
        );
        for bad in [
            json!({}),
            json!([]),
            json!(["local-live-store", 25]),
            json!(["local-live-store", 25, "cursor"]),
            json!({"scope":"all"}),
            json!({"scope":"local-live-store","offset":1}),
            json!({"scope":"local-live-store","limit":0}),
            json!({"scope":"local-live-store","limit":101}),
            json!({"scope":"local-live-store","limit":1.5}),
            json!({"scope":"local-live-store","limit":null}),
            json!({"scope":"local-live-store","cursor":null}),
        ] {
            let status = client
                .post(&url)
                .bearer_auth(OPERATOR)
                .json(&bad)
                .send()
                .await
                .unwrap()
                .status();
            assert!(
                matches!(
                    status,
                    axum::http::StatusCode::BAD_REQUEST
                        | axum::http::StatusCode::UNPROCESSABLE_ENTITY
                ),
                "{bad}: {status}"
            );
        }
        for bad in [
            r#"{"scope":"local-live-store","scope":"local-live-store"}"#,
            r#"{"scope":"local-live-store","limit":1,"limit":2}"#,
            r#"{"scope":"local-live-store","cursor":"x","cursor":"y"}"#,
        ] {
            let status = client
                .post(&url)
                .bearer_auth(OPERATOR)
                .header("content-type", "application/json")
                .body(bad)
                .send()
                .await
                .unwrap()
                .status();
            assert!(
                matches!(
                    status,
                    axum::http::StatusCode::BAD_REQUEST
                        | axum::http::StatusCode::UNPROCESSABLE_ENTITY
                ),
                "{bad}: {status}"
            );
        }
        let mut cursor: Option<String> = None;
        let mut items = Vec::new();
        let mut observation: Option<Value> = None;
        loop {
            let mut body = json!({"scope":"local-live-store","limit":2});
            if let Some(cursor) = &cursor {
                body["cursor"] = json!(cursor);
            }
            let response = client
                .post(&url)
                .bearer_auth(OPERATOR)
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            let reply: Value = response.json().await.unwrap();
            assert!(!reply.to_string().contains("PRIVATE_"));
            assert_eq!(reply["scope"], "local-live-store");
            assert_eq!(reply["externalScopeDiscovered"], false);
            if let Some(first) = &observation {
                for field in ["store", "incarnation", "fence"] {
                    assert_eq!(reply[field], first[field]);
                }
            } else {
                observation = Some(reply.clone());
            }
            items.extend(reply["items"].as_array().unwrap().iter().cloned());
            cursor = reply["nextCursor"].as_str().map(str::to_owned);
            if cursor.is_none() {
                assert_eq!(reply["complete"], true);
                break;
            }
        }
        assert_eq!(items.len(), 11);
        assert_eq!(
            items
                .iter()
                .filter(|item| item["kind"] == "default")
                .count(),
            1
        );
        assert_eq!(
            items
                .iter()
                .filter(|item| item["partition"] == "default")
                .count(),
            1
        );
        let named = |name: &str| items.iter().find(|item| item["partition"] == name).unwrap();
        assert_eq!(named("catalogued")["info"]["phase"], "active");
        assert_eq!(named("orphan-active")["state"]["applicationPresent"], true);
        assert_eq!(named("orphan-staged")["info"]["phase"], "staged");
        assert_eq!(named("orphan-frozen")["info"]["phase"], "frozen");
        assert_eq!(named("orphan-captured")["retainedBasePresent"], true);
        assert_eq!(named("orphan-importing")["info"]["phase"], "importing");
        assert_eq!(named("orphan-importing")["chunksPresent"], true);
        assert_eq!(named("orphan-copied")["info"]["phase"], "copied");
        assert_eq!(
            named("orphan-copied")["retainedImportManifestPresent"],
            true
        );
        assert_eq!(named("orphan-delta")["info"]["phase"], "importing");
        assert_eq!(named("orphan-delta")["chunksPresent"], true);
        assert_eq!(named("orphan-importing")["importManifestPresent"], true);
        assert_eq!(named("orphan-retired")["info"]["phase"], "retired");
        for selector in ["applicationPresent", "recordsPresent", "receiptsPresent"] {
            assert_eq!(named("orphan-retired")["state"][selector], false);
        }
        assert_eq!(consensus.local_snapshot().await, before);
        assert_eq!(consensus.list_partitions().await.unwrap(), before_infos);
        let after_states: Vec<_> = before_infos
            .iter()
            .map(|info| consensus.store.partition_state(&info.partition).unwrap())
            .collect();
        assert_eq!(before_states, after_states);
        // A real application write invalidates the old metadata observation.
        consensus
            .commit(seed("drift", before.revision))
            .await
            .unwrap();
        let old_cursor = observation.unwrap()["nextCursor"]
            .as_str()
            .unwrap()
            .to_owned();
        let response = client
            .post(&url)
            .bearer_auth(OPERATOR)
            .json(&json!({"scope":"local-live-store","cursor":old_cursor}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"]["code"],
            "PHYSICAL_CENSUS_DRIFT"
        );
        stop.send(()).unwrap();
        server.await.unwrap();
        consensus.shutdown().await.unwrap();
    }
}
