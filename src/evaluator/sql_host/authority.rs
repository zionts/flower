//! HOST-issued authority operation from a controller-validated descriptor.
//! No operation field in a guest plan/purpose/input can choose this value.
use super::*;
use crate::evaluator::sql::{Operation, TerminalMethod};

/// Opaque execution witness from the controller's actual captured/deployed
/// code/certificate verification. Scalar/borrowed strings only; no source owner,
/// Records, snapshot, cache, key, provider or closure can be retained here.
#[derive(Clone, Copy)]
pub(crate) struct NativeAuthorityExecution<'a> {
    point: NativeTimePoint,
    target: &'a str,
    code_version: &'a str,
    catalog_version: &'a str,
    code_hash: [u8; 32],
    certificate_hash: [u8; 32],
}
impl<'a> NativeAuthorityExecution<'a> {
    /// # Safety
    /// Controller verified the ACTUAL immutable deployed target/code hash and
    /// source/code/catalog certificate at this exact native point. Merely
    /// filling these fields or matching a signer does NOT verify that proof.
    pub(crate) unsafe fn from_certified_native_execution(
        point: NativeTimePoint,
        target: &'a str,
        code_version: &'a str,
        catalog_version: &'a str,
        code_hash: [u8; 32],
        certificate_hash: [u8; 32],
    ) -> Result<Self, HostError> {
        if !native_target(target)
            || code_version.is_empty()
            || code_version.len() > 4096
            || catalog_version.is_empty()
            || catalog_version.len() > 128
            || code_hash == [0; 32]
            || certificate_hash == [0; 32]
        {
            return Err(HostError::Invalid);
        }
        Ok(Self {
            point,
            target,
            code_version,
            catalog_version,
            code_hash,
            certificate_hash,
        })
    }
}

/// Closed Catalog.authority privilege, bound to ONE actual registered target,
/// captured catalog/code/certificate, native point and original native binding.
/// Only a private SYSTEM read phase accepts it; it is not a generic query grant.
#[derive(Clone, Copy)]
pub(crate) struct ClosedAuthorityPermit<'a> {
    point: NativeTimePoint,
    binding: NativeBinding<'a>,
    frame_identity: usize,
    catalog: NativeText<63>,
    target: NativeText<384>,
    code_hash: [u8; 32],
    certificate_hash: [u8; 32],
}
impl<'a> ClosedAuthorityPermit<'a> {
    /// # Safety
    /// `captured_catalog` is the actual controller-certified deployed Catalog
    /// (native schema validation already completed), captured in this owned
    /// frame at point. The two hashes are its ACTUAL native code/certificate
    /// witnesses, NOT guest properties, enum/phase flags or guessed hashes.
    /// This constructor checks correlation only. It is explicitly NOT the
    /// missing serving controller/certificate verifier.
    pub(crate) unsafe fn from_certified_native_registration(
        frame: &FrameBuilder,
        captured_catalog: JsonId,
        point: NativeTimePoint,
        binding: NativeBinding<'a>,
        code_hash: [u8; 32],
        certificate_hash: [u8; 32],
        control: &FrameControl<'_>,
    ) -> Result<Self, HostError> {
        point.validate_callback_binding(
            NativePhase::Authority,
            binding.clock,
            binding.permission_revision,
        )?;
        if code_hash == [0; 32] || certificate_hash == [0; 32] {
            return Err(HostError::Invalid);
        }
        let catalog = frame.json(captured_catalog, control)?;
        if catalog.kind() != super::super::sql_frame::ArenaKind::Object {
            return Err(HostError::Invalid);
        }
        let mut name = None;
        let mut version = None;
        let mut target = None;
        let mut count = 0;
        let mut tables = false;
        let mut relationships = false;
        for entry in catalog.children() {
            count += 1;
            if count > 5 {
                return Err(HostError::Invalid);
            }
            let entry = entry?;
            match entry.key.ok_or(HostError::Invalid)? {
                "name" if name.is_none() => {
                    name = Some(entry.value.as_str().ok_or(HostError::Invalid)?)
                }
                "version" if version.is_none() => {
                    version = Some(entry.value.as_str().ok_or(HostError::Invalid)?)
                }
                "authority" if target.is_none() => {
                    target = Some(entry.value.as_str().ok_or(HostError::Invalid)?)
                }
                "tables"
                    if !tables
                        && entry.value.kind() == super::super::sql_frame::ArenaKind::Array =>
                {
                    tables = true;
                }
                "relationships"
                    if !relationships
                        && entry.value.kind() == super::super::sql_frame::ArenaKind::Array =>
                {
                    relationships = true;
                }
                _ => return Err(HostError::Invalid),
            }
        }
        let catalog = name.ok_or(HostError::Invalid)?;
        let target = target.ok_or(HostError::Invalid)?;
        if !tables
            || !crate::evaluator::sql::identifier(catalog)
            || !native_target(target)
            || version != Some(binding.catalog_version)
        {
            return Err(HostError::Forbidden);
        }
        Ok(Self {
            point,
            binding,
            frame_identity: std::ptr::from_ref(frame) as usize,
            catalog: NativeText::new(catalog)?,
            target: NativeText::new(target)?,
            code_hash,
            certificate_hash,
        })
    }
    pub(super) fn validate(
        self,
        frame: &FrameBuilder,
        binding: NativeBinding<'_>,
        point: NativeTimePoint,
        execution: NativeAuthorityExecution<'_>,
    ) -> Result<(), HostError> {
        if self.frame_identity != std::ptr::from_ref(frame) as usize
            || self.point != point
            || execution.point != point
            || self.binding != binding
            || execution.target != self.target.as_str()
            || execution.code_version != binding.code_version
            || execution.catalog_version != binding.catalog_version
            || execution.code_hash != self.code_hash
            || execution.certificate_hash != self.certificate_hash
        {
            return Err(HostError::Temporal(TemporalError::ProvenanceMismatch));
        }
        Ok(())
    }
    pub(super) fn target(&self) -> &str {
        self.target.as_str()
    }
}
/// Private fixed UTF-8 owner, detached from transient ArenaValue/FrameControl
/// borrows. Constructed only from validated native strings; never heap/source.
#[derive(Clone, Copy)]
struct NativeText<const N: usize> {
    bytes: [u8; N],
    length: u16,
}
impl<const N: usize> NativeText<N> {
    fn new(value: &str) -> Result<Self, HostError> {
        if value.is_empty() || value.len() > N || value.len() > u16::MAX as usize {
            return Err(HostError::Invalid);
        }
        let mut bytes = [0; N];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            length: value.len() as u16,
        })
    }
    fn as_str(&self) -> &str {
        // Private constructor copied exactly valid UTF-8 with unchanged length.
        unsafe { std::str::from_utf8_unchecked(&self.bytes[..usize::from(self.length)]) }
    }
}
fn native_target(target: &str) -> bool {
    !target.is_empty()
        && target.len() <= 384
        && !target.contains(['\0', '\n', '\r'])
        && !target.starts_with("$flower.")
}

impl SqlHost<'_> {
    /// Build the exact native SqlAuthorityRequest. The controller must have
    /// certified this registered terminal descriptor/code and chosen its exact
    /// authority target. This method is not a manifest/freshness verifier.
    pub(crate) fn prepare_authority_input(
        &mut self,
        terminal: &TerminalMethod,
        purpose: JsonId,
    ) -> Result<&[u8], HostError> {
        let HostAdmission { output, budget, .. } = &mut *self.admission;
        let mut work = Work {
            budget,
            job: self.job,
        };
        work.debit(0)?;
        if self.phase != NativePhase::Authority
            || self.authority.is_none()
            || self.completed.is_some()
        {
            return Err(work.fail(HostError::Forbidden));
        }
        // Fixed scalar validation only. Ordinary manifest validation has
        // already checked signer declarations before entering the job.
        if self
            .authority
            .is_none_or(|permit| permit.catalog.as_str() != terminal.catalog)
            || !crate::evaluator::sql::identifier(&terminal.catalog)
            || (terminal.operation == Operation::Cancel && !terminal.signing_keys.is_empty())
        {
            return Err(work.fail(HostError::Invalid));
        }
        let operation = match terminal.operation {
            Operation::Query => "query",
            Operation::Explain => "explain",
            Operation::Catalog => "catalog",
            Operation::Cancel => "cancel",
        };
        let control = FrameControl::new(&self.cancellation, work.job.deadline());
        let result = output.reset_checked(&mut || work.checker());
        work.keep(result)?;
        let result = (|| {
            let root = output.object()?;
            let catalog = copy::text(output, &terminal.catalog, &mut work)?;
            copy::insert(output, root, "catalog", catalog, &mut work)?;
            let operation = copy::text(output, operation, &mut work)?;
            copy::insert(output, root, "operation", operation, &mut work)?;
            let invoker = copy::arena(
                self.frame.json(self.binding.invoker, &control)?,
                output,
                &mut work,
            )?;
            copy::insert(output, root, "invoker", invoker, &mut work)?;
            let purpose = copy::arena(self.frame.json(purpose, &control)?, output, &mut work)?;
            copy::insert(output, root, "purpose", purpose, &mut work)?;
            Ok::<_, HostError>(root)
        })();
        let root = work.keep(result)?;
        let result = output.encode_checked(root, &mut || work.checker());
        work.keep(result)
    }
}
