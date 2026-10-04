# Current-only SQL registry sidecar — parent integration seam

**Storage helper only. Whole node/worker/atomic source publication/routing and SQL serving remain HOLD.**

Owned files: `sql_registry_meta.rs`, `sql_registry_meta/tests.rs`, this note. No existing source, Cargo, Store queue or partition types changed by this child. No commit/push/PR.

## Required parent hooks

1. Add `#[cfg(feature = "sql")] mod sql_registry_meta;` beside Store's other child modules.
2. Exempt `sql_registry_meta::TABLE_NAME` (`sql_current_registry_v1`) in `Store::open`'s `list_tables` replica-prefix filter, just like `shared::FILE_META.name()`. There is ONE fixed global sidecar table, not another leaked name per Store. If a non-SQL binary may reopen a file that already contains this table, that name exemption must work with `sql` disabled too; an unprefixed auxiliary table must not be mistaken for single-replica application storage.
3. In the persistence transaction, **after each queued projection's source tables have been written and their mutable table handles closed**, call `project_root(transaction, tables)` and `project_partition(transaction, tables, &write.state.info)` for each actual projected partition. Scope metadata must be that queued `PartitionWrite`'s info after `write_partitions`, NOT a later live Store/Directory lookup. No extra queue fields, registry/body copies, snapshots, strings, versions, cells or controls are needed. `Projection::Unknown(reason)` is a typed current-invalidated state, not a persistence error. `MetaError::Storage` requires aborting the whole transaction.
4. At wholesale replacement/snapshot installation, call `invalidate_store(transaction, tables)` before reprojecting root and each actual installed partition, inside the SAME transaction as replacement. Removed partitions must not retain selectable sidecars. Root/partition-specific invalidators are also available.
5. At startup, after source recovery writes but before commit/publication, validate via `with_root` / `with_partition`. These accept only the existing `WriteTransaction` and higher-ranked bounded callback views; no read transaction, table, guard or source borrow is returned. For missing legacy META, reproject from actual recovered rows in this transaction, then validate. A missing registry/bundle stays UNKNOWN. A physically missing schema row becomes explicit `SourceStamp::KnownAbsent` only after mandatory registry and bundle rows are present and valid. Malformed/present-zero schema never becomes known absent.
6. The source-publication owner must bind `RegistryMetadata` and bounded raw bytes to its real Store/install/epoch/original admission correlation, run the prepaid semantic `terminalMethods` decoder, and atomically select actual current owned cells. The helper neither allocates a cell nor proves source provenance merely from scalars or `PartitionInfo`'s type. Persisted projection META is the transaction's current state, NOT evidence that a later live publication still has those stamps; never publish/select it for a mismatched newer live head or before the transaction successfully commits.

## Fixed physical format

Table key: `(Tables.meta.name().as_bytes(), kind:u8, exact_name_UTF8:&[u8], record:u8)`; root kind `0` has empty name/epoch `0`, scoped kind `1` requires the actual nonempty name and positive JS-safe epoch in `PartitionPhase::Active`. Arbitrary long Unicode/NUL names are not clamped, concatenated or hashed. Record `0` is header, `1` is body.

Header is exactly 56 bytes:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | `FLRG\0\0\0\x01` |
| 8 | 8 | epoch, LE u64 |
| 16 | 8 | actual terminalMethods physical version, LE u64, positive |
| 24 | 8 | actual bundle physical version, LE u64, positive |
| 32 | 1 | schema presence: absent `0`, present `1` |
| 33 | 8 | schema physical version: absent exactly `0`, present actual positive, LE u64 |
| 41 | 4 | complete raw encoded body length, LE u32 |
| 45 | 4 | advertised JSON length, LE u32 |
| 49 | 7 | reserved, exactly zero |

Body reuses **the existing complete raw encoded terminalMethods row**, including its original first-eight-byte physical version, by direct AccessGuard slice borrow into redb insert. No Vec, JSON serialization, packed unpack or decompression buffer in production helper code. Stored payload and advertised JSON are checked `<= 32768`; the actual 8-byte source-version header is separately retained, so the complete raw row may be 32776 bytes. A valid exact-32768-byte JSON body is not rejected by subtracting its header. LZ4 token/literal/match lengths and offsets are checked without producing output, including exact advertised length. Semantic JSON/registry schema validation belongs to the parent's prepaid bounded loader.

Loader validates header type, positive physical versions, schema discriminant, lengths, epoch, all code stamps against actual same-transaction source rows, and exact raw sidecar-body equality against the actual registry row. Missing header/body, stale metadata, inactive phases, malformed shape and oversize are fixed typed refusals; loader callback never runs on refusal. Helper errors map real redb failures to fixed `MetaError::Storage`, with no anyhow or serde IO/error-string construction in production helper code.

## Scope of evidence

Tests use the real `Tables`, real redb database/transactions, actual physical `backing::encode`, actual `PartitionInfo`, and real `Store::open/apply/persistence.drain` for queued-later-state checks. No replacement Tables/Records fixtures. A copied full-source native build with only a copied module hook can check code before the parent integrates; it is not evidence of whole-branch hook correctness. The header/LZ4 allocation probe covers only those fixed helpers, NOT redb's native page/I/O allocations or whole-node backing.

Parent review corrections after the original30test component freeze: exact32KiB payload now PLUS physical8B version header, and whole-Store invalidation uses a redb range confined to that physical Store namespace/native Root-Scoped tags, not a full global-table retain scan. These corrections require fresh actual native verification. Producer pairing is NOT established by merely observing current physical versions: a code rewrite without its matching registry, including later code rewrite within one apply, must be separately marked Unpaired by actual source/queued projection logic. No source-ready/ordinary-selection claim follows from this helper alone.

Coherent parent v3 ACTUALcheckout rerun after module/filter/cap/range corrections: registry+META91pass (META30actual cases), realStrongInner lifetime1pass andissuer1pass, default library/fmt/diff PASS;14ownedfiles unchanged. SQL libraryClippy exit0 with146Flowerwarnings (stagedAPIs/prior diagnostics), not strictglobal. Original copied30case run used explicit Flower-package debug overrides and is narrower historical evidence; v3 used unchanged actual checkout profiles. Wholequeued/pairing/replacement/startup/nativecurrent/routing/gates remain OPEN.
