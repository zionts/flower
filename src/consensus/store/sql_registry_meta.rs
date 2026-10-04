//! CURRENT registry sidecar derived from the REAL queued redb projection.
//!
//! Invoke only AFTER the source rows of that projection were applied to this
//! same WriteTransaction, with their tables closed. Scoped callers supply that
//! projection's actual PartitionWrite::state.info (or metadata just recovered
//! from this transaction), NEVER later live Store/Directory state. The type of
//! that argument is not itself proof of provenance. No source roots, queue
//! fields, new versions, registry copies or namespace Strings are created here.
//!
//! Storage errors require aborting the caller's transaction. Header, body and
//! source rows commit/roll back together; this helper never commits. Unknown
//! source data removes BOTH current sidecar records, not an invented methods:{}.
//! This is storage metadata, not SQL authority or a whole-node resource proof.
use super::*;
use crate::consensus::{PartitionPhase, sql_registry::SourceStamp};

/// ONE fixed shared table. Store::open's replica-table-name filter must exempt
/// this name, just as it exempts shared::FILE_META. No per-Store leaked name.
pub(in crate::consensus) const TABLE_NAME: &str = SQL_REGISTRY_META_NAME;
type SidecarKey = (&'static [u8], u8, &'static [u8], u8);
const SIDECAR: TableDefinition<SidecarKey, &'static [u8]> = TableDefinition::new(TABLE_NAME);
const HEADER: u8 = 0;
const BODY: u8 = 1;
const MAX_BYTES: usize = 32_768;
// Payload cap PLUS the actual physical source-version header, not a tighter
// 32KiB whole-row clamp. Pool cells separately charge their own real header.
const MAX_ROW_BYTES: usize = MAX_BYTES + 8;
const MAX_EPOCH: u64 = 9_007_199_254_740_991;
const HEADER_BYTES: usize = 56;
const MAGIC: &[u8; 8] = b"FLRG\0\0\0\x01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) enum MetaError {
    Storage,
}
impl std::fmt::Display for MetaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage => f.write_str("SQL registry sidecar storage failure"),
        }
    }
}
impl std::error::Error for MetaError {}

/// Fixed typed refusal. Missing/invalid/oversized is UNKNOWN, never empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) enum Unknown {
    MissingRegistry,
    MissingBundle,
    MalformedRecord,
    Oversized,
    InvalidPartition,
    Inactive,
    MissingHeader,
    MalformedHeader,
    MissingBody,
    Stale,
}

/// Actual physical versions from the first eight bytes of the source rows.
/// Schema absence is a separate native-checked variant, not Present(0).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) struct RegistryMetadata {
    pub(in crate::consensus) epoch: u64,
    pub(in crate::consensus) registry: u64,
    pub(in crate::consensus) bundle: u64,
    pub(in crate::consensus) schema: SourceStamp,
    pub(in crate::consensus) encoded_bytes: u32,
    pub(in crate::consensus) json_bytes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) enum Projection {
    Current(RegistryMetadata),
    Unknown(Unknown),
}

/// Borrow valid only during the callback. Neither AccessGuard nor a read
/// transaction can escape through this view. It is raw physical encoding:
/// version LE u64 followed by existing plain JSON / packed LZ4 bytes. Semantic
/// terminalMethods decoding belongs in the parent's prepaid bounded loader.
#[derive(Clone, Copy, Debug)]
pub(in crate::consensus) struct RegistryView<'a> {
    pub(in crate::consensus) metadata: RegistryMetadata,
    pub(in crate::consensus) encoded: &'a [u8],
}
#[derive(Debug, Eq, PartialEq)]
pub(in crate::consensus) enum Loaded<T> {
    Current(T),
    Unknown(Unknown),
}

#[derive(Clone, Copy)]
struct Scope<'a> {
    kind: u8,
    name: &'a [u8],
    epoch: u64,
}
impl<'s> Scope<'s> {
    const ROOT: Self = Self {
        kind: 0,
        name: &[],
        epoch: 0,
    };
    fn key<'a>(self, tables: &'a Tables, record: u8) -> (&'a [u8], u8, &'a [u8], u8)
    where
        's: 'a,
    {
        (tables.meta.name().as_bytes(), self.kind, self.name, record)
    }
}
fn partition_scope(info: &PartitionInfo) -> Scope<'_> {
    Scope {
        kind: 1,
        name: info.partition.as_bytes(),
        epoch: info.epoch,
    }
}
fn partition_status(info: &PartitionInfo) -> Result<(), Unknown> {
    if info.partition.is_empty() || info.epoch == 0 || info.epoch > MAX_EPOCH {
        return Err(Unknown::InvalidPartition);
    }
    if info.phase != PartitionPhase::Active {
        return Err(Unknown::Inactive);
    }
    Ok(())
}

/// Root namespace key is (exact Tables.meta.name UTF8 bytes, 0, empty, record).
pub(in crate::consensus) fn project_root(
    transaction: &WriteTransaction,
    tables: Tables,
) -> Result<Projection, MetaError> {
    let data = transaction
        .open_table(tables.data)
        .map_err(|_| MetaError::Storage)?;
    let registry = data
        .get(b"terminalMethods".as_slice())
        .map_err(|_| MetaError::Storage)?;
    let bundle = data
        .get(b"bundle".as_slice())
        .map_err(|_| MetaError::Storage)?;
    let schema = data
        .get(b"schema".as_slice())
        .map_err(|_| MetaError::Storage)?;
    project(
        transaction,
        tables,
        Scope::ROOT,
        registry.as_ref().map(|row| row.value()),
        bundle.as_ref().map(|row| row.value()),
        schema.as_ref().map(|row| row.value()),
    )
}

/// Scope identity uses the exact arbitrary UTF8 name, without a 4KiB clamp,
/// NUL-prefix concatenation or hash. Non-active phases invalidate the head.
pub(in crate::consensus) fn project_partition(
    transaction: &WriteTransaction,
    tables: Tables,
    info: &PartitionInfo,
) -> Result<Projection, MetaError> {
    let scope = partition_scope(info);
    if let Err(reason) = partition_status(info) {
        invalidate(transaction, tables, scope)?;
        return Ok(Projection::Unknown(reason));
    }
    let data = transaction
        .open_table(tables.partition_data)
        .map_err(|_| MetaError::Storage)?;
    let registry = data
        .get((scope.name, b"terminalMethods".as_slice()))
        .map_err(|_| MetaError::Storage)?;
    let bundle = data
        .get((scope.name, b"bundle".as_slice()))
        .map_err(|_| MetaError::Storage)?;
    let schema = data
        .get((scope.name, b"schema".as_slice()))
        .map_err(|_| MetaError::Storage)?;
    project(
        transaction,
        tables,
        scope,
        registry.as_ref().map(|row| row.value()),
        bundle.as_ref().map(|row| row.value()),
        schema.as_ref().map(|row| row.value()),
    )
}

fn project(
    transaction: &WriteTransaction,
    tables: Tables,
    scope: Scope<'_>,
    registry: Option<&[u8]>,
    bundle: Option<&[u8]>,
    schema: Option<&[u8]>,
) -> Result<Projection, MetaError> {
    let metadata = match source_metadata(scope, registry, bundle, schema) {
        Ok(metadata) => metadata,
        Err(reason) => {
            invalidate(transaction, tables, scope)?;
            return Ok(Projection::Unknown(reason));
        }
    };
    let header = encode_header(metadata);
    let mut sidecar = transaction
        .open_table(SIDECAR)
        .map_err(|_| MetaError::Storage)?;
    // Direct AccessGuard borrow -> redb insert, no Vec/JSON/unpacking/body copy
    // in this helper. redb itself owns the destination storage page.
    sidecar
        .insert(
            scope.key(&tables, BODY),
            registry.expect("validated registry"),
        )
        .map_err(|_| MetaError::Storage)?;
    sidecar
        .insert(scope.key(&tables, HEADER), header.as_slice())
        .map_err(|_| MetaError::Storage)?;
    Ok(Projection::Current(metadata))
}

pub(in crate::consensus) fn invalidate_root(
    transaction: &WriteTransaction,
    tables: Tables,
) -> Result<(), MetaError> {
    invalidate(transaction, tables, Scope::ROOT)
}
pub(in crate::consensus) fn invalidate_partition(
    transaction: &WriteTransaction,
    tables: Tables,
    info: &PartitionInfo,
) -> Result<(), MetaError> {
    invalidate(transaction, tables, partition_scope(info))
}
fn invalidate(
    transaction: &WriteTransaction,
    tables: Tables,
    scope: Scope<'_>,
) -> Result<(), MetaError> {
    let mut sidecar = transaction
        .open_table(SIDECAR)
        .map_err(|_| MetaError::Storage)?;
    sidecar
        .remove(scope.key(&tables, HEADER))
        .map_err(|_| MetaError::Storage)?;
    sidecar
        .remove(scope.key(&tables, BODY))
        .map_err(|_| MetaError::Storage)?;
    Ok(())
}

/// Whole-source replacement must discard obsolete scoped sidecars as well.
/// No list/Vec/name allocation; other Stores sharing the fixed table survive.
pub(in crate::consensus) fn invalidate_store(
    transaction: &WriteTransaction,
    tables: Tables,
) -> Result<(), MetaError> {
    let namespace = tables.meta.name().as_bytes();
    transaction
        .open_table(SIDECAR)
        .map_err(|_| MetaError::Storage)?
        .retain_in(
            // Only THIS physical Store namespace and native Root/Scoped tags.
            // 0xff is above every valid UTF8 leading byte; no heap successor
            // name or scan of unrelated Stores is needed for the range.
            (namespace, 0u8, b"".as_slice(), 0u8)..=(namespace, 1u8, b"\xff".as_slice(), u8::MAX),
            |_, _| false,
        )
        .map_err(|_| MetaError::Storage)
}

/// Startup/current validation uses the same source transaction; no ReadOnlyTable
/// or source guard is returned. The higher-ranked callback cannot return this
/// borrow. Missing legacy META is UNKNOWN; parent may project it from actual
/// recovered rows in this transaction, never fabricate an empty registry.
pub(in crate::consensus) fn with_root<T>(
    transaction: &WriteTransaction,
    tables: Tables,
    callback: impl for<'a> FnOnce(RegistryView<'a>) -> T,
) -> Result<Loaded<T>, MetaError> {
    let data = transaction
        .open_table(tables.data)
        .map_err(|_| MetaError::Storage)?;
    let registry = data
        .get(b"terminalMethods".as_slice())
        .map_err(|_| MetaError::Storage)?;
    let bundle = data
        .get(b"bundle".as_slice())
        .map_err(|_| MetaError::Storage)?;
    let schema = data
        .get(b"schema".as_slice())
        .map_err(|_| MetaError::Storage)?;
    with_current(
        transaction,
        tables,
        Scope::ROOT,
        registry.as_ref().map(|row| row.value()),
        bundle.as_ref().map(|row| row.value()),
        schema.as_ref().map(|row| row.value()),
        callback,
    )
}
pub(in crate::consensus) fn with_partition<T>(
    transaction: &WriteTransaction,
    tables: Tables,
    info: &PartitionInfo,
    callback: impl for<'a> FnOnce(RegistryView<'a>) -> T,
) -> Result<Loaded<T>, MetaError> {
    if let Err(reason) = partition_status(info) {
        return Ok(Loaded::Unknown(reason));
    }
    let scope = partition_scope(info);
    let data = transaction
        .open_table(tables.partition_data)
        .map_err(|_| MetaError::Storage)?;
    let registry = data
        .get((scope.name, b"terminalMethods".as_slice()))
        .map_err(|_| MetaError::Storage)?;
    let bundle = data
        .get((scope.name, b"bundle".as_slice()))
        .map_err(|_| MetaError::Storage)?;
    let schema = data
        .get((scope.name, b"schema".as_slice()))
        .map_err(|_| MetaError::Storage)?;
    with_current(
        transaction,
        tables,
        scope,
        registry.as_ref().map(|row| row.value()),
        bundle.as_ref().map(|row| row.value()),
        schema.as_ref().map(|row| row.value()),
        callback,
    )
}
#[allow(clippy::too_many_arguments)] // borrowed same-tx rows, no owned carrier
fn with_current<T>(
    transaction: &WriteTransaction,
    tables: Tables,
    scope: Scope<'_>,
    registry: Option<&[u8]>,
    bundle: Option<&[u8]>,
    schema: Option<&[u8]>,
    callback: impl for<'a> FnOnce(RegistryView<'a>) -> T,
) -> Result<Loaded<T>, MetaError> {
    let actual = match source_metadata(scope, registry, bundle, schema) {
        Ok(metadata) => metadata,
        Err(reason) => return Ok(Loaded::Unknown(reason)),
    };
    let sidecar = transaction
        .open_table(SIDECAR)
        .map_err(|_| MetaError::Storage)?;
    let Some(header) = sidecar
        .get(scope.key(&tables, HEADER))
        .map_err(|_| MetaError::Storage)?
    else {
        return Ok(Loaded::Unknown(Unknown::MissingHeader));
    };
    let metadata = match decode_header(header.value(), scope) {
        Ok(metadata) => metadata,
        Err(reason) => return Ok(Loaded::Unknown(reason)),
    };
    if metadata != actual {
        return Ok(Loaded::Unknown(Unknown::Stale));
    }
    let Some(body) = sidecar
        .get(scope.key(&tables, BODY))
        .map_err(|_| MetaError::Storage)?
    else {
        return Ok(Loaded::Unknown(Unknown::MissingBody));
    };
    // Validate before exposing the bytes, even if an old/corrupt sidecar was
    // installed independently. Equality also catches same-version byte damage.
    if let Err(reason) = registry_shape(body.value()) {
        return Ok(Loaded::Unknown(reason));
    }
    if body.value() != registry.expect("validated source registry") {
        return Ok(Loaded::Unknown(Unknown::Stale));
    }
    Ok(Loaded::Current(callback(RegistryView {
        metadata,
        encoded: body.value(),
    })))
}

fn source_metadata(
    scope: Scope<'_>,
    registry: Option<&[u8]>,
    bundle: Option<&[u8]>,
    schema: Option<&[u8]>,
) -> Result<RegistryMetadata, Unknown> {
    let registry = registry.ok_or(Unknown::MissingRegistry)?;
    let (registry_version, json_bytes) = registry_shape(registry)?;
    let bundle = physical_version(bundle.ok_or(Unknown::MissingBundle)?)?;
    let schema = match schema {
        None => SourceStamp::KnownAbsent,
        Some(bytes) => {
            SourceStamp::present(physical_version(bytes)?).map_err(|_| Unknown::MalformedRecord)?
        }
    };
    Ok(RegistryMetadata {
        epoch: scope.epoch,
        registry: registry_version,
        bundle,
        schema,
        encoded_bytes: registry.len() as u32, // registry_shape checked payload cap + physical header
        json_bytes,
    })
}
fn physical_version(bytes: &[u8]) -> Result<u64, Unknown> {
    let Some(version) = bytes.get(..8) else {
        return Err(Unknown::MalformedRecord);
    };
    let version = u64::from_le_bytes(version.try_into().expect("eight version bytes"));
    if version == 0 || bytes.len() == 8 {
        return Err(Unknown::MalformedRecord);
    }
    // Bundle/schema can legitimately be much larger than the registry. Only
    // inspect their constant-size physical envelope here; never scan/unpack
    // their bodies or impose the registry's cap on code/schema records.
    if bytes[8] == 0 {
        let Some(length) = bytes.get(9..13) else {
            return Err(Unknown::MalformedRecord);
        };
        let length = u32::from_le_bytes(length.try_into().expect("four length bytes")) as usize;
        if length == 0 || length > bytes.len().saturating_sub(13).saturating_mul(255) {
            return Err(Unknown::MalformedRecord);
        }
    }
    Ok(version)
}
fn registry_shape(bytes: &[u8]) -> Result<(u64, u32), Unknown> {
    // Cap stored payload and advertised JSON; the actual eight-byte physical
    // version header is separate and is not taken from the 32KiB payload.
    if bytes.len() > MAX_ROW_BYTES {
        return Err(Unknown::Oversized);
    }
    let version = physical_version(bytes)?;
    let body = &bytes[8..];
    let json_bytes = if body[0] == 0 {
        let Some(length) = body.get(1..5) else {
            return Err(Unknown::MalformedRecord);
        };
        let length = u32::from_le_bytes(length.try_into().expect("four length bytes"));
        if length as usize > MAX_BYTES {
            return Err(Unknown::Oversized);
        }
        if length == 0 || !lz4_shape(&body[5..], length as usize) {
            return Err(Unknown::MalformedRecord);
        }
        length
    } else {
        body.len() as u32
    };
    Ok((version, json_bytes))
}

/// Check LZ4 block offsets/lengths and EXACT advertised output size, WITHOUT
/// unpacking/copying any byte or allocating a decompression buffer. Semantic
/// JSON validity is intentionally left to the bounded native registry loader.
fn lz4_shape(block: &[u8], advertised: usize) -> bool {
    fn length(block: &[u8], at: &mut usize, nibble: u8) -> Option<usize> {
        let mut value = usize::from(nibble);
        if nibble == 15 {
            loop {
                let byte = *block.get(*at)?;
                *at += 1;
                value = value.checked_add(usize::from(byte))?;
                if byte != 255 {
                    break;
                }
            }
        }
        Some(value)
    }
    let mut at = 0;
    let mut produced = 0usize;
    while let Some(&token) = block.get(at) {
        at += 1;
        let Some(literals) = length(block, &mut at, token >> 4) else {
            return false;
        };
        let Some(end) = at.checked_add(literals) else {
            return false;
        };
        if end > block.len() {
            return false;
        }
        at = end;
        let Some(total) = produced.checked_add(literals) else {
            return false;
        };
        produced = total;
        if produced > advertised {
            return false;
        }
        if at == block.len() {
            return produced == advertised;
        }
        let Some(offset) = block.get(at..at + 2) else {
            return false;
        };
        at += 2;
        let offset = u16::from_le_bytes([offset[0], offset[1]]) as usize;
        if offset == 0 || offset > produced {
            return false;
        }
        let Some(matched) =
            length(block, &mut at, token & 15).and_then(|value| value.checked_add(4))
        else {
            return false;
        };
        let Some(total) = produced.checked_add(matched) else {
            return false;
        };
        produced = total;
        if produced > advertised {
            return false;
        }
    }
    false // a block ends in a literal sequence, not an incomplete match
}
fn encode_header(metadata: RegistryMetadata) -> [u8; HEADER_BYTES] {
    let mut bytes = [0; HEADER_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..16].copy_from_slice(&metadata.epoch.to_le_bytes());
    bytes[16..24].copy_from_slice(&metadata.registry.to_le_bytes());
    bytes[24..32].copy_from_slice(&metadata.bundle.to_le_bytes());
    if let SourceStamp::Present(version) = metadata.schema {
        bytes[32] = 1;
        bytes[33..41].copy_from_slice(&version.get().to_le_bytes());
    }
    bytes[41..45].copy_from_slice(&metadata.encoded_bytes.to_le_bytes());
    bytes[45..49].copy_from_slice(&metadata.json_bytes.to_le_bytes());
    bytes
}
fn decode_header(bytes: &[u8], scope: Scope<'_>) -> Result<RegistryMetadata, Unknown> {
    if bytes.len() != HEADER_BYTES
        || &bytes[..8] != MAGIC
        || bytes[49..].iter().any(|byte| *byte != 0)
    {
        return Err(Unknown::MalformedHeader);
    }
    let word = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed header word"));
    let schema = match (bytes[32], word(33)) {
        (0, 0) => SourceStamp::KnownAbsent,
        (1, version) => SourceStamp::present(version).map_err(|_| Unknown::MalformedHeader)?,
        _ => return Err(Unknown::MalformedHeader),
    };
    let metadata = RegistryMetadata {
        epoch: word(8),
        registry: word(16),
        bundle: word(24),
        schema,
        encoded_bytes: u32::from_le_bytes(bytes[41..45].try_into().expect("fixed length")),
        json_bytes: u32::from_le_bytes(bytes[45..49].try_into().expect("fixed length")),
    };
    if metadata.registry == 0
        || metadata.bundle == 0
        || !(9..=MAX_ROW_BYTES as u32).contains(&metadata.encoded_bytes)
        || !(1..=MAX_BYTES as u32).contains(&metadata.json_bytes)
    {
        return Err(Unknown::MalformedHeader);
    }
    if metadata.epoch != scope.epoch {
        return Err(Unknown::Stale);
    }
    Ok(metadata)
}

#[cfg(test)]
mod tests;
