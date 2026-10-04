//! Same-frame native capture correlation. No source/controller verification.
//! Caller-owned descriptor and witness banks are included in original admission.
use super::super::sql_frame::ArenaKind;
use super::super::sql_policy::{CapturedCollection, NativeKeyRow};
use super::*;

/// Exact native Source declaration and captured policy offsets, not guest flags.
#[derive(Clone, Copy)]
pub(crate) struct NativeCaptureCollection {
    declaration: JsonId,
    policy: Option<JsonId>,
}
impl NativeCaptureCollection {
    pub(crate) fn from_owned_offsets(declaration: JsonId, policy: Option<JsonId>) -> Self {
        Self {
            declaration,
            policy,
        }
    }
}
/// One representation for relation rows AND readable support/negative witnesses.
/// All offsets are rebound by the published exact native binder before use.
#[derive(Clone, Copy)]
pub(crate) struct NativeCaptureRow {
    declaration: JsonId,
    source_pair: JsonId,
    retained_key: KeyId,
    decoded_key: Option<JsonId>,
    row: Option<JsonId>,
}
impl NativeCaptureRow {
    pub(crate) fn bind<'a>(
        self,
        frame: &'a FrameBuilder,
        control: &'a FrameControl<'a>,
        budget: &PolicyBudget,
        job: &mut JobControl,
    ) -> Result<NativeKeyRow<'a>, HostError> {
        NativeKeyRow::bind_owned_native_capture(
            frame,
            self.declaration,
            self.source_pair,
            self.retained_key,
            self.decoded_key,
            self.row,
            control,
            budget,
            job,
        )
        .map_err(Into::into)
    }
    pub(crate) fn from_owned_offsets(
        declaration: JsonId,
        source_pair: JsonId,
        retained_key: KeyId,
        decoded_key: Option<JsonId>,
        row: Option<JsonId>,
    ) -> Self {
        Self {
            declaration,
            source_pair,
            retained_key,
            decoded_key,
            row,
        }
    }
}
/// Published native binder + same-frame support closure, privately issued here.
/// Correlation of exact owned bytes only; not an origin/source verifier.
#[derive(Clone, Copy)]
pub(super) struct SameFrameSupportWitness<'a> {
    frame: &'a FrameBuilder,
    pub(super) captured: CapturedSupport<'a>,
}
/// Private validated complete capture. Production hosts accept ONLY this type.
#[derive(Clone, Copy)]
pub(crate) struct NativeCapture<'a> {
    pub(super) frame: &'a FrameBuilder,
    pub(super) relations: &'a [OwnedRelation<'a>],
    descriptors: &'a [NativeCaptureRow],
    witnesses: &'a [NativeKeyRow<'a>],
    collections: &'a [NativeCaptureCollection],
    collection_bank: &'a [CapturedCollection<'a>],
    pub(super) support: SameFrameSupportWitness<'a>,
    pub(super) owner_bytes: usize,
}
impl<'a> NativeCapture<'a> {
    /// Banks must be resident, prepaid and sized exactly to their descriptors.
    /// The supplied FrameControl is from the ORIGINAL job. Origin, complete
    /// relation/absence certificates and catalog membership remain controller
    /// obligations; this method is deliberately NOT their verifier.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_owned_native_capture(
        admission: &mut HostAdmission,
        frame: &'a FrameBuilder,
        relations: &'a [OwnedRelation<'a>],
        collections: &'a [NativeCaptureCollection],
        descriptors: &'a [NativeCaptureRow],
        collection_bank: &'a mut [CapturedCollection<'a>],
        witness_bank: &'a mut [NativeKeyRow<'a>],
        control: &'a FrameControl<'a>,
        budget: &PolicyBudget,
        job: &mut JobControl,
    ) -> Result<Self, HostError> {
        let mut work = Work {
            budget: &mut admission.budget,
            job,
        };
        work.debit(0)?;
        let result = (|| {
            if !admission.job_stamp.matches(work.job) {
                return Err(HostError::Temporal(TemporalError::WrongOriginalJob));
            }
            let owner_bytes = std::mem::size_of_val(collections)
                .checked_add(std::mem::size_of_val(descriptors))
                .and_then(|n| n.checked_add(std::mem::size_of_val(collection_bank)))
                .and_then(|n| n.checked_add(std::mem::size_of_val(witness_bank)))
                .ok_or(HostError::Capacity)?;
            let mut required = std::mem::size_of_val(relations)
                .checked_add(owner_bytes)
                .ok_or(HostError::Capacity)?;
            for relation in relations {
                required = required
                    .checked_add(std::mem::size_of_val(relation.rows))
                    .and_then(|n| n.checked_add(relation.name.len()))
                    .ok_or(HostError::Capacity)?;
            }
            if required > admission.borrowed_owner_bytes {
                return Err(HostError::Capacity);
            }
            let identity = std::ptr::from_ref(budget) as usize;
            if admission
                .policy_identity
                .is_some_and(|original| original != identity)
            {
                return Err(HostError::Forbidden);
            }
            admission.policy_identity = Some(identity);
            if let Some(error) = budget.failure() {
                return Err(read::policy_failure(error, &mut work));
            }
            if admission
                .policy_work_ceiling
                .is_some_and(|remaining| budget.remaining_work() > remaining)
            {
                return Err(HostError::Forbidden);
            }

            if collections.len() != collection_bank.len()
                || descriptors.len() != witness_bank.len()
                || collections.len() > MAX_RELATIONS
                || descriptors.len() > MAX_CAPTURED_ROWS
            {
                return Err(HostError::Capacity);
            }
            // Every policy is obtained from THIS frame, not a foreign ArenaValue.
            for (descriptor, target) in collections.iter().zip(collection_bank.iter_mut()) {
                work.debit(1)?;
                let declaration = frame.json(descriptor.declaration, control)?;
                let name = source_name(declaration, &mut work)?;
                *target = CapturedCollection {
                    name,
                    policy: descriptor
                        .policy
                        .map(|id| frame.json(id, control))
                        .transpose()?,
                };
            }
            for (descriptor, target) in descriptors.iter().zip(witness_bank.iter_mut()) {
                *target = NativeKeyRow::bind_owned_native_capture(
                    frame,
                    descriptor.declaration,
                    descriptor.source_pair,
                    descriptor.retained_key,
                    descriptor.decoded_key,
                    descriptor.row,
                    control,
                    budget,
                    work.job,
                )
                .map_err(|e| read::policy_failure(e, &mut work))?;
            }
            // Verify ALL relation rows, even hidden rows or rows not queried. A
            // legacy unchecked OwnedRow can never enter production without an exact
            // matching native descriptor (including its actual row JSON offset).
            for relation in relations {
                let mut source = None;
                for descriptor in collections {
                    work.debit(1)?;
                    let name =
                        source_name(frame.json(descriptor.declaration, control)?, &mut work)?;
                    if work.same(name, relation.name)?
                        && source.replace(descriptor.declaration).is_some()
                    {
                        return Err(HostError::Invalid);
                    }
                }
                let source = source.ok_or(HostError::NeedCapture(NativeNeedCapture))?;
                for row in relation.rows {
                    let mut matches = 0usize;
                    for descriptor in descriptors {
                        work.debit(1)?;
                        if descriptor.declaration == source
                            && descriptor.retained_key == row.key
                            && descriptor.row == row.value
                        {
                            matches += 1;
                        }
                    }
                    if matches != 1 {
                        return Err(HostError::Invalid);
                    }
                }
            }
            Ok::<_, HostError>(owner_bytes)
        })();
        let owner_bytes = work.keep(result)?;
        let result = CapturedSupport::from_owned_native_capture(
            collection_bank,
            witness_bank,
            budget,
            work.job,
        )
        .map_err(|e| read::policy_failure(e, &mut work));
        let support = work.keep(result)?;
        let remaining = budget.remaining_work();
        admission.policy_work_ceiling = Some(
            admission
                .policy_work_ceiling
                .map_or(remaining, |old| old.min(remaining)),
        );
        Ok(Self {
            frame,
            relations,
            descriptors,
            witnesses: witness_bank,
            collections,
            collection_bank,
            support: SameFrameSupportWitness {
                frame,
                captured: support,
            },
            owner_bytes,
        })
    }
    pub(super) fn row(
        self,
        collection: &str,
        row: OwnedRow,
        control: &FrameControl<'_>,
        work: &mut Work<'_>,
    ) -> Result<NativeKeyRow<'a>, HostError> {
        if !std::ptr::eq(self.frame, self.support.frame) {
            return Err(work.fail(HostError::Invalid));
        }
        for (descriptor, witness) in self.descriptors.iter().zip(self.witnesses) {
            work.debit(1)?;
            if descriptor.retained_key == row.key && descriptor.row == row.value {
                work.debit(1)?;
                let name = source_name(self.frame.json(descriptor.declaration, control)?, work)?;
                if work.same(name, collection)? {
                    return Ok(*witness);
                }
            }
        }
        Err(work.fail(HostError::Invalid))
    }
    pub(super) fn source(
        self,
        declaration: JsonId,
        work: &mut Work<'_>,
    ) -> Result<&'a str, HostError> {
        for (descriptor, collection) in self.collections.iter().zip(self.support_collections()) {
            work.debit(1)?;
            if descriptor.declaration == declaration {
                return Ok(collection.name);
            }
        }
        Err(work.fail(HostError::Invalid))
    }
    fn support_collections(self) -> &'a [CapturedCollection<'a>] {
        self.collection_bank
    }
}
fn source_name<'a>(declaration: ArenaValue<'a>, work: &mut Work<'_>) -> Result<&'a str, HostError> {
    if declaration.kind() != ArenaKind::Object {
        return Err(HostError::Invalid);
    }
    let mut name = None;
    for entry in declaration.children() {
        work.debit(1)?;
        let entry = entry?;
        match entry.key {
            Some("name") => name = Some(entry.value.as_str().ok_or(HostError::Invalid)?),
            Some("jsonKey") if entry.value.as_bool().is_some() => (),
            _ => return Err(HostError::Invalid),
        }
    }
    let name = name
        .filter(|name| plain_collection(name))
        .ok_or(HostError::Forbidden)?;
    work.bytes(name.len())?;
    Ok(name)
}
