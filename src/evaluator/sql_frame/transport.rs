//! Linux typed-only, consuming immutable frame transport (component, not admission).
//!
//! Six memfds replace the six typed anonymous slabs BEFORE input; no typed copy
//! and no second 128 MiB reservation. Raw/support/parser/key/provenance stay out
//! of the descriptor ABI. The parent retains provenance and the original Budget.
//!
//! `PreparationLease::from_precharged_owner` is an UNSAFE DRIVER CONTRACT, not a
//! verifier: its issuer must own the original USER reservation and actual finite
//! backing for these pages, file objects/FDs, VMAs/PTEs, control/stack/cold globals
//! and all simultaneous recipient mappings. Numeric plans, alloc Layouts and RSS
//! do NOT discharge it. No production issuer/controller is supplied here.
//!
//! Each RW map is consumed and actually unmapped before WRITE/GROW/SHRINK/SEAL
//! seals are set/read back. A fresh O_RDONLY descriptor of that SAME owned file
//! is opened through /proc/self/fd, then the RW descriptor is closed. There is no
//! map_files, foreign process access, fork, provider or source capability.
//!
//! Cleanup is fail-stop on actual unmap/close uncertainty, before ticket Drop;
//! callers must retain node/USER credit until process reaping in that case.
//! Before sealing, writable memfd maps are volatile-wiped on failed-owner Drop.
//! After sealing: RO unmap + final FD destruction, NOT a volatile-wipe or total
//! erasure theorem. Other processes/duplicate FDs extend the file lifetime.
use std::mem::size_of;
use std::ops::{Deref, DerefMut};

use super::control::Budget;
use super::slab::{Slab, mapped_bytes};
use super::*;

pub(crate) const TYPED_FILES: usize = 6;
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const MAGIC: u64 = 0x3145_4d41_5246_5153;

/// Scalar-only ABI. Expected identities must come from the trusted exporting
/// parent, not from the helper that supplies descriptors. No source IDs here.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameDescriptor {
    pub magic: u64,
    pub version: u32,
    pub byte_order: u32,
    /// text, tables, columns, rows, cells, row_order (no private bank).
    pub capacities: [u32; TYPED_FILES],
    pub counts: [u32; TYPED_FILES],
    pub files: [FileIdentity; TYPED_FILES],
}

/// Layout request ONLY. Actual physical/kernel/control enrollment is the
/// external strong lease contract, and remains a whole-controller HOLD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparationPlan {
    pub typed_mapping_bytes: usize,
    pub constructing_mapping_bytes: usize,
    pub control_allowance_bytes: usize,
    pub typed_file_count: usize,
    pub writable_mapping_count: usize,
    pub constructing_mapping_count: usize,
    pub parent_readonly_mapping_count: usize,
    pub helper_readonly_mapping_count: usize,
    /// Export peak is seven (one RO reopen); hostile receive can own seven
    /// incoming FDs beside six authoritative parent FDs, so charge thirteen.
    pub peak_owned_fd_count: usize,
    pub descriptor_bytes: usize,
    pub file_owner_bank_bytes: usize,
    pub received_owner_bank_bytes: usize,
    pub identity_bank_bytes: usize,
    pub validation_local_bytes: usize,
    limits: [usize; 14],
}
impl PreparationPlan {
    /// Exact inline layout for the caller's ACTUAL ticket type L. Numeric
    /// storage sizes only; not physical/stack/compiler-copy backing evidence.
    /// Lease, prepared, exported, read-only, partial-adoption owner respectively.
    pub(crate) fn owner_bytes<L>() -> [usize; 5] {
        [
            size_of::<PreparationLease<L>>(),
            size_of::<PreparedFrame<L>>(),
            size_of::<ExportedFrame<L>>(),
            size_of::<ReadOnlyFrame<L>>(),
            size_of::<PendingAdoption<L>>(),
        ]
    }
    pub(crate) fn for_limits(limits: FrameLimits) -> Result<Self, FrameError> {
        if !limits.valid() || !cfg!(target_endian = "little") || size_of::<usize>() != 8 {
            return Err(FrameError::Unsupported);
        }
        let typed = typed_sizes(capacities(limits))?;
        let index = limits
            .nodes
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(FrameError::Capacity)?;
        let capture = [
            mapped_bytes::<u8>(limits.raw_bytes)?,
            mapped_bytes::<u8>(limits.support_bytes)?,
            mapped_bytes::<u8>(limits.decoded_bytes)?,
            mapped_bytes::<JsonNode>(limits.nodes)?,
            mapped_bytes::<Document>(limits.documents)?,
            mapped_bytes::<ObjectKey>(index)?,
            mapped_bytes::<KeyEntry>(limits.keys)?,
            mapped_bytes::<u8>(limits.key_bytes)?,
            mapped_bytes::<u8>(limits.provenance_bytes)?,
        ];
        let typed_mapping_bytes = checked_sum(&typed)?;
        let constructing_mapping_bytes = typed_mapping_bytes
            .checked_add(checked_sum(&capture)?)
            .ok_or(FrameError::Capacity)?;
        if constructing_mapping_bytes
            .checked_add(CONTROL_BYTES)
            .is_none_or(|bytes| bytes > MAX_FRAME_BYTES)
        {
            return Err(FrameError::Capacity);
        }
        Ok(Self {
            typed_mapping_bytes,
            constructing_mapping_bytes,
            control_allowance_bytes: CONTROL_BYTES,
            typed_file_count: TYPED_FILES,
            writable_mapping_count: typed.iter().filter(|bytes| **bytes != 0).count(),
            constructing_mapping_count: typed
                .iter()
                .chain(&capture)
                .filter(|bytes| **bytes != 0)
                .count(),
            parent_readonly_mapping_count: typed.iter().filter(|bytes| **bytes != 0).count()
                + usize::from(limits.provenance_bytes != 0),
            helper_readonly_mapping_count: typed.iter().filter(|bytes| **bytes != 0).count(),
            peak_owned_fd_count: 13,
            descriptor_bytes: size_of::<FrameDescriptor>(),
            file_owner_bank_bytes: size_of::<[FrameFile; TYPED_FILES]>(),
            received_owner_bank_bytes: size_of::<[Option<FrameFile>; TYPED_FILES + 1]>(),
            identity_bank_bytes: size_of::<[FileIdentity; TYPED_FILES]>(),
            validation_local_bytes: size_of::<[u32; MAX_TABLES]>()
                + size_of::<[usize; TYPED_FILES]>(),
            limits: [
                limits.raw_bytes,
                limits.support_bytes,
                limits.decoded_bytes,
                limits.nodes,
                limits.documents,
                limits.keys,
                limits.key_bytes,
                limits.tables,
                limits.columns,
                limits.rows,
                limits.cells,
                limits.text_bytes,
                limits.provenance_bytes,
                limits.parse_work,
            ],
        })
    }
}
fn checked_sum(values: &[usize]) -> Result<usize, FrameError> {
    values.iter().try_fold(0usize, |sum, value| {
        sum.checked_add(*value).ok_or(FrameError::Capacity)
    })
}
fn capacities(limits: FrameLimits) -> [u32; TYPED_FILES] {
    [
        limits.text_bytes as u32,
        limits.tables as u32,
        limits.columns as u32,
        limits.rows as u32,
        limits.cells as u32,
        limits.rows as u32,
    ]
}
fn typed_sizes(cap: [u32; TYPED_FILES]) -> Result<[usize; TYPED_FILES], FrameError> {
    Ok([
        mapped_bytes::<u8>(cap[0] as usize)?,
        mapped_bytes::<OwnedTable>(cap[1] as usize)?,
        mapped_bytes::<OwnedColumn>(cap[2] as usize)?,
        mapped_bytes::<OwnedRow>(cap[3] as usize)?,
        mapped_bytes::<OwnedCell>(cap[4] as usize)?,
        mapped_bytes::<u32>(cap[5] as usize)?,
    ])
}

/// Opaque consuming strong backing owner. It is deliberately not Clone/Copy.
/// A generic owner permits the existing USER/node driver to retain its real
/// ticket without allocating a Box, Arc or a new reserve inside this component.
pub(crate) struct PreparationLease<L> {
    owner: L,
    plan: PreparationPlan,
}
impl<L> PreparationLease<L> {
    /// # Safety
    /// `owner` must retain actual pre-enrolled backing for the complete plan,
    /// INCLUDING real kernel/FD/map/control/preparation resources and this L's
    /// own storage, in the existing original USER reservation. It must not
    /// refund before every associated map/file owner is destroyed. A received
    /// helper FD/reference outside this owner requires the driver's own strong
    /// transfer/reap handshake. This function verifies NONE of those facts.
    pub(crate) unsafe fn from_precharged_owner(owner: L, plan: PreparationPlan) -> Self {
        Self { owner, plan }
    }
    pub(crate) fn prepare(
        self,
        limits: FrameLimits,
        control: &FrameControl<'_>,
    ) -> Result<PreparedFrame<L>, FrameError> {
        if self.plan != PreparationPlan::for_limits(limits)?
            || size_of::<ExportedFrame<L>>() + size_of::<ReadOnlyFrame<L>>() > CONTROL_BYTES
        {
            return Err(FrameError::Capacity);
        }
        let builder = FrameBuilder::new_backing(limits, control, true)?;
        Ok(PreparedFrame {
            builder,
            lease: self,
        })
    }
}
/// Field order is intentional: all maps/files are destroyed before the lease.
pub(crate) struct PreparedFrame<L> {
    builder: FrameBuilder,
    lease: PreparationLease<L>,
}
impl<L> Deref for PreparedFrame<L> {
    type Target = FrameBuilder;
    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}
impl<L> DerefMut for PreparedFrame<L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.builder
    }
}
impl<L> PreparedFrame<L> {
    pub(crate) fn seal(self, control: &FrameControl<'_>) -> Result<ExportedFrame<L>, FrameError> {
        let Self { builder, lease } = self;
        let frame = builder.seal(control)?;
        let SealedSqlFrame {
            typed,
            allocation_bytes: _,
            budget,
        } = frame;
        budget.check(control)?;
        let counts = [
            typed.text_len as u32,
            typed.table_len as u32,
            typed.column_len as u32,
            typed.row_len as u32,
            typed.cell_len as u32,
            typed.row_len as u32,
        ];
        let caps = [
            typed.text.len() as u32,
            typed.tables.len() as u32,
            typed.columns.len() as u32,
            typed.rows.len() as u32,
            typed.cells.len() as u32,
            typed.row_order.len() as u32,
        ];
        // One consuming move per owner: no copies, no borrowed lifetime tricks.
        let files = [
            typed.text.into_unmapped_file(&budget, control)?,
            typed.tables.into_unmapped_file(&budget, control)?,
            typed.columns.into_unmapped_file(&budget, control)?,
            typed.rows.into_unmapped_file(&budget, control)?,
            typed.cells.into_unmapped_file(&budget, control)?,
            typed.row_order.into_unmapped_file(&budget, control)?,
        ];
        // ALL six builder RW mappings are gone before the first seal syscall.
        // Keep successfully sealed and still-unsealed FDs in the same fixed
        // owner bank; on an error each remains owned until actual close.
        let mut pending_files = files.map(Some);
        for file in &mut pending_files {
            budget.debit(1, control)?;
            *file = Some(file.take().expect("owned unmapped FD").seal_readonly()?);
        }
        let files = pending_files.map(|file| file.expect("all sealed FDs"));
        let mut identities = [FileIdentity::default(); TYPED_FILES];
        for (identity, file) in identities.iter_mut().zip(&files) {
            *identity = file.identity()?;
        }
        budget.check(control)?;
        Ok(ExportedFrame {
            files,
            budget,
            provenance: typed.provenance,
            provenance_len: typed.provenance_len,
            descriptor: FrameDescriptor {
                magic: MAGIC,
                version: 1,
                byte_order: 1,
                capacities: caps,
                counts,
                files: identities,
            },
            lease,
        })
    }
}

/// Parent custody owner. Only descriptor()/borrowed FDs are transport data;
/// neither this Rust value, lease, provenance nor Budget is a helper payload.
pub(crate) struct ExportedFrame<L> {
    files: [FrameFile; TYPED_FILES],
    budget: Budget,
    provenance: Slab<u8>,
    provenance_len: usize,
    descriptor: FrameDescriptor,
    lease: PreparationLease<L>,
}
impl<L> ExportedFrame<L> {
    pub(crate) fn descriptor(&self) -> FrameDescriptor {
        self.descriptor
    }
    pub(crate) fn descriptors(&self) -> [i32; TYPED_FILES] {
        std::array::from_fn(|index| self.files[index].as_raw_fd())
    }
    pub(crate) fn parent_provenance(&self) -> &[u8] {
        &self.provenance[..self.provenance_len]
    }
    pub(crate) fn adopt(self, control: &FrameControl<'_>) -> Result<ReadOnlyFrame<L>, FrameError> {
        let Self {
            files,
            budget,
            provenance,
            provenance_len,
            descriptor,
            lease,
        } = self;
        adopt(
            files,
            None,
            descriptor,
            provenance,
            provenance_len,
            budget,
            lease,
            control,
        )
    }
    /// Native receive boundary, fixed bank including ONE overflow slot. The
    /// authoritative expected descriptor remains in this parent owner. Incoming
    /// extras/holes/duplicates/foreign/writable/unsealed FDs refuse the WHOLE
    /// batch before any trusted view. This is not a process handshake/issuer.
    pub(crate) fn adopt_received(
        self,
        mut received: [Option<FrameFile>; TYPED_FILES + 1],
        control: &FrameControl<'_>,
    ) -> Result<ReadOnlyFrame<L>, FrameError> {
        self.budget.check(control)?;
        if received[TYPED_FILES].is_some() || received[..TYPED_FILES].iter().any(Option::is_none) {
            return Err(FrameError::Invalid);
        }
        let files =
            std::array::from_fn(|index| received[index].take().expect("checked full FD bank"));
        let Self {
            files: originals,
            budget,
            provenance,
            provenance_len,
            descriptor,
            lease,
        } = self;
        // Authority originals remain owned until complete adoption or cleanup.
        adopt(
            files,
            Some(originals),
            descriptor,
            provenance,
            provenance_len,
            budget,
            lease,
            control,
        )
    }
}

/// Immutable logical owner. Typed views allocate nothing. The legacy SQLite
/// Source ABI intentionally still allocates separately budgeted batch Vecs.
pub(crate) struct ReadOnlyFrame<L> {
    frame: SealedSqlFrame,
    lease: PreparationLease<L>,
}
impl<L> Deref for ReadOnlyFrame<L> {
    type Target = SealedSqlFrame;
    fn deref(&self) -> &Self::Target {
        &self.frame
    }
}
impl<L> Source for ReadOnlyFrame<L> {
    fn scan(&mut self, request: ScanRequest<'_>) -> Result<Batch, SqlError> {
        self.frame.scan(request)
    }
}
// Own *all* partially adopted resources in one field-ordered object. On any
// caught error, every successful map and every remaining/original FD is cleaned
// before the preparation lease can refund. No fallible function is called after
// ownership is split into the final immutable return value.
struct PendingAdoption<L> {
    frame: Option<TypedArena>,
    text: Option<Slab<u8>>,
    tables: Option<Slab<OwnedTable>>,
    columns: Option<Slab<OwnedColumn>>,
    rows: Option<Slab<OwnedRow>>,
    cells: Option<Slab<OwnedCell>>,
    row_order: Option<Slab<u32>>,
    files: [Option<FrameFile>; TYPED_FILES],
    originals: Option<[FrameFile; TYPED_FILES]>,
    provenance: Option<Slab<u8>>,
    budget: Option<Budget>,
    lease: Option<PreparationLease<L>>,
}
#[allow(clippy::too_many_arguments)]
fn adopt<L>(
    files: [FrameFile; TYPED_FILES],
    originals: Option<[FrameFile; TYPED_FILES]>,
    descriptor: FrameDescriptor,
    provenance: Slab<u8>,
    provenance_len: usize,
    budget: Budget,
    lease: PreparationLease<L>,
    control: &FrameControl<'_>,
) -> Result<ReadOnlyFrame<L>, FrameError> {
    let mut pending = PendingAdoption {
        frame: None,
        text: None,
        tables: None,
        columns: None,
        rows: None,
        cells: None,
        row_order: None,
        files: files.map(Some),
        originals,
        provenance: Some(provenance),
        budget: Some(budget),
        lease: Some(lease),
    };
    let budget = pending.budget.as_ref().expect("owned original budget");
    budget.check(control)?;
    let refs: [&FrameFile; TYPED_FILES] =
        std::array::from_fn(|index| pending.files[index].as_ref().expect("fixed FD bank"));
    validate_descriptors(&refs, &descriptor, budget, control)?;
    let c = descriptor.capacities;
    let n = descriptor.counts;
    pending.text = Some(Slab::map_file(
        pending.files[0].take().expect("owned FD"),
        c[0] as usize,
        false,
        control,
    )?);
    pending.tables = Some(Slab::map_file(
        pending.files[1].take().expect("owned FD"),
        c[1] as usize,
        false,
        control,
    )?);
    pending.columns = Some(Slab::map_file(
        pending.files[2].take().expect("owned FD"),
        c[2] as usize,
        false,
        control,
    )?);
    pending.rows = Some(Slab::map_file(
        pending.files[3].take().expect("owned FD"),
        c[3] as usize,
        false,
        control,
    )?);
    pending.cells = Some(Slab::map_file(
        pending.files[4].take().expect("owned FD"),
        c[4] as usize,
        false,
        control,
    )?);
    pending.row_order = Some(Slab::map_file(
        pending.files[5].take().expect("owned FD"),
        c[5] as usize,
        false,
        control,
    )?);
    pending.frame = Some(TypedArena {
        text: pending.text.take().expect("mapped text"),
        tables: pending.tables.take().expect("mapped tables"),
        columns: pending.columns.take().expect("mapped columns"),
        rows: pending.rows.take().expect("mapped rows"),
        cells: pending.cells.take().expect("mapped cells"),
        row_order: pending.row_order.take().expect("mapped order"),
        provenance: pending.provenance.take().expect("parent provenance"),
        provenance_len,
        text_len: n[0] as usize,
        table_len: n[1] as usize,
        ordinary_tables: 0,
        column_len: n[2] as usize,
        row_len: n[3] as usize,
        cell_len: n[4] as usize,
    });
    validate_typed(
        pending.frame.as_ref().expect("owned untrusted POD maps"),
        budget,
        control,
    )?;
    budget.check(control)?;
    drop(pending.originals.take());
    let typed = pending.frame.take().expect("fully validated frame");
    let allocation_bytes = typed.bytes() + CONTROL_BYTES;
    let budget = pending.budget.take().expect("same original budget");
    let lease = pending.lease.take().expect("same strong preparation owner");
    Ok(ReadOnlyFrame {
        frame: SealedSqlFrame {
            typed,
            allocation_bytes,
            budget,
        },
        lease,
    })
}
fn validate_descriptors(
    files: &[&FrameFile; TYPED_FILES],
    descriptor: &FrameDescriptor,
    budget: &Budget,
    control: &FrameControl<'_>,
) -> Result<(), FrameError> {
    if descriptor.magic != MAGIC
        || descriptor.version != 1
        || descriptor.byte_order != 1
        || !cfg!(target_endian = "little")
    {
        return Err(FrameError::Invalid);
    }
    let max = [
        MAX_TEXT_BYTES as u32,
        MAX_TABLES as u32,
        (MAX_TABLES * MAX_COLUMNS) as u32,
        MAX_ROWS as u32,
        MAX_CELLS as u32,
        MAX_ROWS as u32,
    ];
    if descriptor.capacities[3] != descriptor.capacities[5]
        || descriptor.counts[3] != descriptor.counts[5]
    {
        return Err(FrameError::Invalid);
    }
    let sizes = typed_sizes(descriptor.capacities)?;
    for index in 0..TYPED_FILES {
        budget.debit(1, control)?;
        if descriptor.capacities[index] > max[index]
            || descriptor.counts[index] > descriptor.capacities[index]
            || descriptor.files[index].bytes != sizes[index] as u64
        {
            return Err(FrameError::Invalid);
        }
        let file = &files[index];
        file.validate_readonly()?;
        if file.identity()? != descriptor.files[index] {
            return Err(FrameError::Invalid);
        }
        for previous in &files[..index] {
            if previous.as_raw_fd() == file.as_raw_fd()
                || previous.identity()? == file.identity()?
            {
                return Err(FrameError::Invalid);
            }
        }
    }
    Ok(())
}

fn validate_typed(
    typed: &TypedArena,
    budget: &Budget,
    control: &FrameControl<'_>,
) -> Result<(), FrameError> {
    // UTF8 validation in bounded chunks; extend at most three bytes to avoid
    // splitting a code point, never trust a declared text boundary.
    let bytes = &typed.text[..typed.text_len];
    let mut start = 0;
    while start < bytes.len() {
        let mut end = (start + MAX_CAPTURE_SLICE).min(bytes.len());
        for _ in 0..3 {
            if end < bytes.len() && bytes[end] & 0xc0 == 0x80 {
                end += 1;
            } else {
                break;
            }
        }
        budget.debit(end - start, control)?;
        std::str::from_utf8(&bytes[start..end]).map_err(|_| FrameError::Invalid)?;
        start = end;
    }
    // This view is not exported: all refs/types/counts are still untrusted.
    let text = unsafe { std::str::from_utf8_unchecked(bytes) };
    let check_ref = |reference: TypedRef| -> Result<&str, FrameError> {
        let start = reference.start as usize;
        let end = start
            .checked_add(reference.len as usize)
            .ok_or(FrameError::Invalid)?;
        text.get(start..end).ok_or(FrameError::Invalid)
    };
    let mut next_column = 0usize;
    let mut next_order = 0usize;
    let mut ordinary = 0usize;
    for (index, table) in typed.tables[..typed.table_len].iter().enumerate() {
        budget.debit(1, control)?;
        let name = check_ref(table.name)?;
        if table.reserved != 0
            || !identifier(name)
            || matches!(
                name,
                "sqlite_master" | "sqlite_schema" | "sqlite_temp_master" | "sqlite_temp_schema"
            )
            || table.column_count == 0
            || table.column_count as usize > MAX_COLUMNS
            || table.column_start as usize != next_column
            || table.row_start as usize != next_order
        {
            return Err(FrameError::Invalid);
        }
        ordinary += usize::from(!matches!(
            name,
            "sql_tables" | "sql_columns" | "sql_relationships"
        ));
        if ordinary > 64 {
            return Err(FrameError::Invalid);
        }
        for previous in &typed.tables[..index] {
            budget.debit(1, control)?;
            if check_ref(previous.name)? == name {
                return Err(FrameError::Invalid);
            }
        }
        next_column = next_column
            .checked_add(table.column_count as usize)
            .ok_or(FrameError::Invalid)?;
        next_order = next_order
            .checked_add(table.row_count as usize)
            .ok_or(FrameError::Invalid)?;
        if next_column > typed.column_len || next_order > typed.row_len {
            return Err(FrameError::Invalid);
        }
        let columns = &typed.columns[table.column_start as usize..next_column];
        for (index, column) in columns.iter().enumerate() {
            budget.debit(1, control)?;
            let name = check_ref(column.name)?;
            let logical = check_ref(column.logical_type)?;
            let unit = check_ref(column.unit)?;
            if !identifier(name)
                || column.kind > 2
                || column.flags & !15 != 0
                || column.reserved != [0; 6]
                || logical.len() > 16_384
                || unit.len() > 16_384
                || (!column.has_logical_type() && !logical.is_empty())
                || (!column.has_unit() && !unit.is_empty())
            {
                return Err(FrameError::Invalid);
            }
            for previous in &columns[..index] {
                budget.debit(1, control)?;
                if check_ref(previous.name)? == name {
                    return Err(FrameError::Invalid);
                }
            }
        }
        let mut previous = None;
        for row_index in &typed.row_order[table.row_start as usize..next_order] {
            budget.debit(1, control)?;
            let row_index = *row_index as usize;
            if previous.is_some_and(|old| row_index <= old)
                || row_index >= typed.row_len
                || typed.rows[row_index].table as usize != index
            {
                return Err(FrameError::Invalid);
            }
            previous = Some(row_index);
        }
    }
    if next_column != typed.column_len || next_order != typed.row_len {
        return Err(FrameError::Invalid);
    }
    let mut next_cell = 0usize;
    for row in &typed.rows[..typed.row_len] {
        budget.debit(1, control)?;
        let table = typed.tables[..typed.table_len]
            .get(row.table as usize)
            .ok_or(FrameError::Invalid)?;
        if row.count != table.column_count || row.start as usize != next_cell {
            return Err(FrameError::Invalid);
        }
        next_cell = next_cell
            .checked_add(row.count as usize)
            .ok_or(FrameError::Invalid)?;
        if next_cell > typed.cell_len {
            return Err(FrameError::Invalid);
        }
        for (index, cell) in typed.cells[row.start as usize..next_cell]
            .iter()
            .enumerate()
        {
            budget.debit(1, control)?;
            let column = typed.columns[table.column_start as usize + index];
            match cell.tag {
                0 if column.nullable() && cell.payload == 0 => (),
                1 if column.kind == 0 => (),
                2 if column.kind == 1 && f64::from_bits(cell.payload).is_finite() => (),
                3 if column.kind == 2 => {
                    let value = check_ref(cell.text_ref().ok_or(FrameError::Invalid)?)?;
                    if value.len() > sqlite::MAX_CELL_BYTES {
                        return Err(FrameError::Invalid);
                    }
                }
                _ => return Err(FrameError::Invalid),
            }
        }
    }
    if next_cell != typed.cell_len {
        return Err(FrameError::Invalid);
    }
    // Reject smuggled bytes in all unused capacity AND page-rounded tails.
    validate_zero_tail(&typed.text, typed.text_len, budget, control)?;
    validate_zero_tail(&typed.tables, typed.table_len, budget, control)?;
    validate_zero_tail(&typed.columns, typed.column_len, budget, control)?;
    validate_zero_tail(&typed.rows, typed.row_len, budget, control)?;
    validate_zero_tail(&typed.cells, typed.cell_len, budget, control)?;
    validate_zero_tail(&typed.row_order, typed.row_len, budget, control)
}
fn validate_zero_tail<T: slab::MappedPod>(
    slab: &Slab<T>,
    used: usize,
    budget: &Budget,
    control: &FrameControl<'_>,
) -> Result<(), FrameError> {
    let offset = used
        .checked_mul(size_of::<T>())
        .ok_or(FrameError::Invalid)?;
    let bytes = slab.mapped_bytes();
    if offset > bytes {
        return Err(FrameError::Invalid);
    }
    if bytes == 0 {
        return Ok(());
    }
    // Typed POD structs have NO implicit padding; maps own their complete tail.
    let tail = unsafe {
        std::slice::from_raw_parts(slab.as_ptr().cast::<u8>().add(offset), bytes - offset)
    };
    for chunk in tail.chunks(MAX_CAPTURE_SLICE) {
        budget.debit(chunk.len(), control)?;
        if chunk.iter().any(|byte| *byte != 0) {
            return Err(FrameError::Invalid);
        }
    }
    Ok(())
}

/// Exact owned FD. No Clone: descriptor duplication is an explicit receiver /
/// driver action which must enroll its own finite bank and strong custody.
pub(crate) struct FrameFile {
    fd: i32,
}
impl FrameFile {
    pub(crate) fn as_raw_fd(&self) -> i32 {
        self.fd
    }
    /// # Safety
    /// fd must be uniquely owned (not borrowed/aliased), open and enrolled in
    /// the original driver's FD bank. Adoption will still verify its identity,
    /// access mode, complete seals, length and all typed data before logical use.
    pub(crate) unsafe fn from_owned_fd(fd: i32) -> Self {
        Self { fd }
    }
    pub(super) fn create(bytes: usize) -> Result<Self, FrameError> {
        let fd = unsafe {
            libc::memfd_create(
                c"sql-typed-frame".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(FrameError::Capacity);
        }
        let file = Self { fd };
        if unsafe { libc::ftruncate(fd, bytes as libc::off_t) } != 0 {
            return Err(FrameError::Capacity);
        }
        Ok(file)
    }
    fn identity(&self) -> Result<FileIdentity, FrameError> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(self.fd, stat.as_mut_ptr()) } != 0 {
            return Err(FrameError::Invalid);
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_size < 0 {
            return Err(FrameError::Invalid);
        }
        Ok(FileIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            bytes: stat.st_size as u64,
        })
    }
    fn validate_readonly(&self) -> Result<(), FrameError> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        let seals = unsafe { libc::fcntl(self.fd, libc::F_GET_SEALS) };
        let fd_flags = unsafe { libc::fcntl(self.fd, libc::F_GETFD) };
        if flags < 0
            || flags & libc::O_ACCMODE != libc::O_RDONLY
            || seals != SEALS
            || fd_flags < 0
            || fd_flags & libc::FD_CLOEXEC == 0
        {
            return Err(FrameError::Invalid);
        }
        Ok(())
    }
    pub(super) fn seal_readonly(self) -> Result<Self, FrameError> {
        if unsafe { libc::fcntl(self.fd, libc::F_ADD_SEALS, SEALS) } != 0 {
            // EBUSY means another shared writer still exists outside the owner
            // we consumed. Closing our FD is NOT proof that its pages died.
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EBUSY) {
                std::process::abort();
            }
            return Err(FrameError::Invalid);
        }
        if unsafe { libc::fcntl(self.fd, libc::F_GET_SEALS) } != SEALS {
            return Err(FrameError::Invalid);
        }
        // Fixed formatting of this exact owned fd; never an arbitrary fd path.
        let mut path = [0u8; 40];
        let prefix = b"/proc/self/fd/";
        path[..prefix.len()].copy_from_slice(prefix);
        let mut digits = [0u8; 10];
        let mut value = self.fd as u32;
        let mut count = 0;
        loop {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        for (index, digit) in digits[..count].iter().rev().enumerate() {
            path[prefix.len() + index] = *digit;
        }
        let fd = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(FrameError::Capacity);
        }
        let readonly = Self { fd };
        if readonly.identity()? != self.identity()? {
            return Err(FrameError::Invalid);
        }
        readonly.validate_readonly()?;
        drop(self); // RW FD closes AFTER actual unmap + seal readback.
        Ok(readonly)
    }
}
impl Drop for FrameFile {
    fn drop(&mut self) {
        #[cfg(test)]
        let identity = self.identity().ok();
        let result = unsafe { libc::close(self.fd) };
        #[cfg(test)]
        tests::closed(identity, result);
        if result != 0 {
            // No allocator/log/error String/lease destructor after uncertainty.
            std::process::abort();
        }
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
