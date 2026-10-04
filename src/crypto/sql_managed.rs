//! SQL-only bounded JWT core, deliberately NOT activated.
//!
//! Production mounted-wire loading uses fixed pinned RustCrypto AES256GCM.
//! Owned private buffers and cipher state are locked and erased. Actual finite
//! stack/native allowance is an unsafe driver boundary, not a guessed estimate.
//! See sql_managed/API.md. Never route this through ordinary managed crypto.
#[path = "sql_managed/cipher.rs"]
mod cipher;
#[path = "sql_managed/codec.rs"]
mod codec;
#[path = "sql_managed/profile.rs"]
mod profile;
#[path = "sql_managed/slab.rs"]
mod slab;
pub(crate) use profile::{
    LockProfileCaps, LockProfileLayout, LockProfileStatus, NodeLockProfile, NodeStartup, SlotTicket,
};
#[cfg(test)]
#[path = "sql_managed/tests.rs"]
mod tests;

use crate::evaluator::sql_frame::{
    ArenaKind, ArenaValue, FrameBuilder, FrameControl, FrameError, JsonBank, JsonId,
};
use aes_gcm::aead::AeadInPlace;
#[cfg(test)]
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer};
use sha2::{Digest, Sha256, Sha512};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use zeroize::Zeroize;

pub(crate) const MAX_BORROWED_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_TOKEN_BYTES: usize = 64 * 1024;
pub(crate) const MAX_CLAIMS_BYTES: usize = 32 * 1024;
pub(crate) const MAX_OPTIONS_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 1024;
const MAX_KID_BYTES: usize = 192;
const MAX_NAME_BYTES: usize = 128;
// Native SDK method names are not key symbols: the private authorization name
// and generated .$sql.finalize suffix include punctuation, and public methods
// may contain Unicode. The registry caps public names at256 UTF-8 bytes.
const MAX_DEFINITION_BYTES: usize = 384;
const MAX_OPTION_TEXT: usize = 256;
const MAX_AUDIENCES: usize = 16;
const MAX_JOB_WORK: usize = 64 * 1024 * 1024;
const MAX_CRYPTO_CALLS: usize = 64;
// Unique stop/budget owner identity, NOT a grant/job/certificate authority.
// Address reuse or moving a Control must not recreate an admitted job budget.
static NEXT_CONTROL_ID: AtomicU64 = AtomicU64::new(1);
fn next_control_id() -> Result<u64, Error> {
    let mut current = NEXT_CONTROL_ID.load(Ordering::Relaxed);
    for _ in 0..64 {
        let next = current.checked_add(1).ok_or(Error::NativeAdmission)?;
        match NEXT_CONTROL_ID.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(current),
            Err(id) => current = id,
        }
    }
    Err(Error::NativeAdmission)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Capacity,
    Invalid,
    Unsupported,
    Authority,
    StalePoint,
    WorkLimit,
    Cancelled,
    Deadline,
    NativeAdmission,
    EnvelopeAuthentication,
    SecretUnavailable,
    Signature,
    Claims,
    Expired { at_ms: u64 },
    NotActive { changes_at_ms: u64 },
}
impl From<FrameError> for Error {
    fn from(error: FrameError) -> Self {
        match error {
            FrameError::Capacity => Self::Capacity,
            FrameError::Invalid => Self::Invalid,
            FrameError::Unsupported => Self::Unsupported,
            FrameError::WorkLimit => Self::WorkLimit,
            FrameError::Cancelled => Self::Cancelled,
            FrameError::Deadline => Self::Deadline,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::Capacity => "SQL managed crypto capacity exceeded",
            Self::Invalid => "invalid SQL managed crypto input",
            Self::Unsupported => "unsupported SQL managed crypto operation or value",
            Self::Authority => "SQL managed crypto authority denied",
            Self::StalePoint => "SQL managed crypto fresh point mismatch",
            Self::WorkLimit => "SQL managed crypto work limit",
            Self::Cancelled => "SQL managed crypto cancelled",
            Self::Deadline => "SQL managed crypto deadline",
            Self::NativeAdmission => "SQL managed native admission unavailable",
            Self::EnvelopeAuthentication => "SQL managed envelope authentication failed",
            Self::SecretUnavailable => "SQL managed crypto material unavailable",
            Self::Signature => "SQL managed JWT authentication failed",
            Self::Claims => "SQL managed JWT claims mismatch",
            Self::Expired { .. } => "SQL managed JWT expired",
            Self::NotActive { .. } => "SQL managed JWT not active",
        })
    }
}
impl std::error::Error for Error {}

/// Primitive-only, original native job deadline and cumulatively sticky work.
/// Neither control retains a provider/root/callback or reads a wall clock.
pub(crate) struct Control<'a> {
    identity: u64,
    cancelled: &'a AtomicBool,
    deadline: Instant,
    frame: FrameControl<'a>,
    work: Cell<usize>,
    failure: Cell<Option<Error>>,
    calls: Cell<usize>,
}
impl<'a> Control<'a> {
    pub(crate) fn new(
        cancelled: &'a AtomicBool,
        deadline: Instant,
        work: usize,
    ) -> Result<Self, Error> {
        if work > MAX_JOB_WORK {
            return Err(Error::Capacity);
        }
        Ok(Self {
            identity: next_control_id()?,
            cancelled,
            deadline,
            frame: FrameControl::new(cancelled, deadline),
            work: Cell::new(work),
            failure: Cell::new(None),
            calls: Cell::new(MAX_CRYPTO_CALLS),
        })
    }
    pub(crate) fn frame(&self) -> &FrameControl<'a> {
        &self.frame
    }
    fn fail(&self, error: Error) -> Error {
        let error = self.failure.get().unwrap_or(error);
        self.failure.set(Some(error));
        error
    }
    fn check(&self) -> Result<(), Error> {
        if let Some(error) = self.failure.get() {
            return Err(error);
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Err(self.fail(Error::Cancelled));
        }
        if Instant::now() >= self.deadline {
            return Err(self.fail(Error::Deadline));
        }
        Ok(())
    }
    fn begin_crypto_call(&self, cleanup_bytes: usize) -> Result<(), Error> {
        self.check()?;
        let calls = self
            .calls
            .get()
            .checked_sub(1)
            .ok_or_else(|| self.fail(Error::WorkLimit))?;
        self.calls.set(calls);
        // Count the actual page-rounded storage swept on completion/error.
        // This is not a guessed native primitive CPU or stack allowance.
        self.debit(cleanup_bytes)
    }
    fn debit(&self, bytes: usize) -> Result<(), Error> {
        self.check()?;
        let remaining = self
            .work
            .get()
            .checked_sub(bytes)
            .ok_or_else(|| self.fail(Error::WorkLimit))?;
        self.work.set(remaining);
        Ok(())
    }
}

/// This is an exact equality token, NOT a validator of a captured certificate.
/// Its integrity and freshness must be established by the native controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FreshPoint {
    pub job: u64,
    pub snapshot: u64,
    pub certificate: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    InitialAuthentication,
    FreshAuthentication,
    ReadlessFinalizer,
}

/// Borrowed trusted native declaration fields, never a guest key handle.
pub(crate) struct Attenuation<'a> {
    pub phase: Phase,
    pub definition: &'a str,
    /// Exact key named by authenticate; never definer-wide access.
    pub authentication_key: Option<&'a str>,
    /// Exact finalizer definition signingKeys membership, not caller options.
    pub signing_keys: &'a [&'a str],
}
pub(crate) struct EnvelopeFields<'a> {
    pub provider: &'a str,
    pub wrapping_id: &'a str,
    pub wrapped_dek: &'a str,
    pub wrapping_nonce: &'a str,
    pub ciphertext: &'a str,
    pub nonce: &'a str,
}
pub(crate) struct KeyFields<'a> {
    pub domain: &'a str,
    pub id: &'a str,
    pub name: &'a str,
    pub algorithm: &'a str,
    pub declaration_algorithm: &'a str,
    pub binding_usages: &'a [&'a str],
    pub declaration_usages: &'a [&'a str],
    pub version: u64,
    pub active_version: u64,
    pub revoked: bool,
    pub retired: bool,
    /// Destroyed versions must pass None.
    pub envelope: Option<EnvelopeFields<'a>>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Operation {
    Verify,
    Sign,
}

/// No Clone/Debug/Serialize/export, consumed by exactly one crypto operation.
pub(crate) struct Grant<'a> {
    key: KeyFields<'a>,
    point: FreshPoint,
    operation: Operation,
    kid: [u8; MAX_KID_BYTES],
    kid_len: usize,
    fingerprint: [u8; 32],
}
impl<'a> Grant<'a> {
    /// # Safety
    /// The native controller must have authenticated the exact captured point,
    /// catalog/binding/version/envelope and declaration, and independently
    /// verified the exact native phase attenuation BEFORE calling. No serving
    /// Records, guest definer, guest-supplied fields or mutable source may stand
    /// behind these borrowed views. This unsafe boundary does not supply those
    /// missing launch proofs; its finite checks defend the release subset only.
    pub(crate) unsafe fn from_trusted_capture(
        key: KeyFields<'a>,
        attenuation: Attenuation<'_>,
        point: FreshPoint,
        control: &Control<'_>,
    ) -> Result<Self, Error> {
        control.check()?;
        if point.job == 0 || point.certificate == [0; 32] {
            return Err(Error::StalePoint);
        }
        name(key.name)?;
        name(key.domain)?;
        name(key.id)?;
        definition_name(attenuation.definition)?;
        if key.algorithm != "Ed25519" || key.declaration_algorithm != "Ed25519" {
            return Err(Error::Unsupported);
        }
        if key.version == 0 || key.active_version == 0 || key.revoked {
            return Err(Error::Authority);
        }
        if key.binding_usages.len() > 3
            || key.declaration_usages.len() > 3
            || attenuation.signing_keys.len() > 64
        {
            return Err(Error::Capacity);
        }
        for usage in key.binding_usages.iter().chain(key.declaration_usages) {
            if !matches!(*usage, "sign" | "verify" | "publicKey") {
                return Err(Error::Unsupported);
            }
        }
        let operation = match attenuation.phase {
            Phase::InitialAuthentication | Phase::FreshAuthentication => {
                if attenuation.authentication_key != Some(key.name)
                    || !attenuation.signing_keys.is_empty()
                {
                    return Err(Error::Authority);
                }
                Operation::Verify
            }
            Phase::ReadlessFinalizer => {
                if attenuation.authentication_key.is_some() {
                    return Err(Error::Authority);
                }
                let mut member = false;
                for allowed in attenuation.signing_keys {
                    name(allowed)?;
                    control.debit(allowed.len())?;
                    member |= *allowed == key.name;
                }
                if !member || key.retired || key.version != key.active_version {
                    return Err(Error::Authority);
                }
                Operation::Sign
            }
        };
        let usage = match operation {
            Operation::Verify => "verify",
            Operation::Sign => "sign",
        };
        if !key.binding_usages.contains(&usage) || !key.declaration_usages.contains(&usage) {
            return Err(Error::Authority);
        }
        let envelope = key.envelope.as_ref().ok_or(Error::Authority)?;
        if envelope.provider != "mounted" {
            return Err(Error::Unsupported);
        }
        fixed_envelope(envelope, control)?;
        let mut kid = [0; MAX_KID_BYTES];
        let mut writer = codec::Writer::new(&mut kid, control);
        writer.bytes(b"flower.")?;
        writer.bytes(key.id.as_bytes())?;
        writer.bytes(b".")?;
        writer.integer(key.version)?;
        let kid_len = writer.len();
        let mut fingerprint = Sha256::new();
        fingerprint.update([attenuation.phase as u8]);
        for text in [
            attenuation.definition,
            key.domain,
            key.id,
            key.name,
            envelope.provider,
            envelope.wrapping_id,
            envelope.wrapped_dek,
            envelope.wrapping_nonce,
            envelope.ciphertext,
            envelope.nonce,
        ] {
            control.debit(text.len())?;
            fingerprint.update((text.len() as u64).to_le_bytes());
            fingerprint.update(text.as_bytes());
        }
        fingerprint.update(key.version.to_le_bytes());
        Ok(Self {
            key,
            point,
            operation,
            kid,
            kid_len,
            fingerprint: fingerprint.finalize().into(),
        })
    }
    fn kid(&self) -> &str {
        // Only canonical ASCII names, decimal version and literals were copied.
        unsafe { std::str::from_utf8_unchecked(&self.kid[..self.kid_len]) }
    }
    fn authorize(
        &self,
        point: FreshPoint,
        operation: Operation,
        control: &Control<'_>,
    ) -> Result<(), Error> {
        control.check()?;
        if self.point != point {
            return Err(Error::StalePoint);
        }
        if self.operation != operation {
            return Err(Error::Authority);
        }
        Ok(())
    }
}
fn definition_name(text: &str) -> Result<(), Error> {
    // This is an exact trusted, length-delimited native identity, not a file
    // path, key symbol or guest-supplied authorization selector. Fingerprints
    // still bind the entire bytes to the declaration and phase.
    if text.is_empty() || text.len() > MAX_DEFINITION_BYTES {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn name(text: &str) -> Result<(), Error> {
    if text.is_empty()
        || text.len() > MAX_NAME_BYTES
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
/// Exact existing managed envelope AAD, in caller-admitted fixed storage.
/// Public metadata only; this does not open an envelope or authorize a key.
#[derive(Clone, Copy)]
pub(crate) enum EnvelopePurpose {
    Dek,
    Material,
}
pub(crate) fn envelope_aad_into(
    grant: &Grant<'_>,
    purpose: EnvelopePurpose,
    output: &mut [u8],
    control: &Control<'_>,
) -> Result<usize, Error> {
    let mut writer = codec::Writer::new(output, control);
    writer.bytes(b"[\"flower-key-v1\",")?;
    writer.quoted(grant.key.domain)?;
    writer.bytes(b",")?;
    writer.quoted(grant.key.id)?;
    writer.bytes(b",")?;
    writer.integer(grant.key.version)?;
    writer.bytes(b",\"Ed25519\",")?;
    writer.quoted(match purpose {
        EnvelopePurpose::Dek => "dek",
        EnvelopePurpose::Material => "material",
    })?;
    writer.bytes(b"]")?;
    Ok(writer.len())
}

fn fixed_envelope(envelope: &EnvelopeFields<'_>, control: &Control<'_>) -> Result<(), Error> {
    for (text, len) in [
        (envelope.wrapping_id, 32),
        (envelope.wrapped_dek, 48),
        (envelope.wrapping_nonce, 12),
        (envelope.ciphertext, 48),
        (envelope.nonce, 12),
    ] {
        // Syntax/length validation only: do NOT make a deliberate unowned
        // decoded ciphertext stack buffer during trusted capture.
        if text.len() > 64 || codec::validated_len(text.as_bytes(), control)? != len {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

/// A one-use borrowed view of exactly 32 mounted wrapping-key bytes. Not a
/// provider callback, ordinary prepared key, seed importer or source handle.
/// Consumed by prepare_mounted; the input is erased on every return/unwind.
/// No public accessor, Clone, Debug, export or key/cache retention exists.
pub(crate) struct MountedWrapping<'a> {
    bytes: &'a mut [u8; 32],
}
impl<'a> MountedWrapping<'a> {
    /// # Safety
    /// Native mount acquisition must already have validated the configured
    /// regular-file/permissions/exact length as ordinary MountedKey::read does,
    /// and charged, locked and dump-excluded this owned input BEFORE reading it.
    /// It must NOT be guest-chosen material or a retained serving/provider root.
    /// The sole permitted interpretation is an AES256GCM wrapping key; this is
    /// NOT a general private-material setter. No provider capability is kept.
    pub(crate) unsafe fn from_trusted_mount(bytes: &'a mut [u8; 32]) -> Self {
        Self { bytes }
    }
}
impl Drop for MountedWrapping<'_> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Exactly one fixed32-byte page, already locked before a loader can write.
struct OwnedMountInput {
    storage: slab::Slab,
    binding: Option<SeedBinding>,
}

/// Exact finite native resources reserved by the driver BEFORE allocation or
/// thread launch. This is an unsafe attestation, not a certificate verifier or
/// a library-invented estimate of crypto demand. Stack guard pages/OS metadata,
/// code/static mappings and launch resources belong in other_native_bytes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeAllowance {
    stack_extent_bytes: usize,
    other_native_bytes: usize,
}
impl NativeAllowance {
    /// # Safety
    /// Driver must have admitted the actual hard stack extent (including every
    /// participating native thread and separate native signal stack) and all
    /// remaining native resources before allocating/launching them. It must
    /// enforce this same extent during use,
    /// with no stack growth/fallback/additional worker. This does not assert all
    /// transient stack/register copies are locked or erased.
    pub(crate) unsafe fn from_trusted_launch(
        stack_extent_bytes: usize,
        other_native_bytes: usize,
    ) -> Result<Self, Error> {
        if stack_extent_bytes == 0 {
            return Err(Error::NativeAdmission);
        }
        stack_extent_bytes
            .checked_add(other_native_bytes)
            .ok_or(Error::Capacity)?;
        Ok(Self {
            stack_extent_bytes,
            other_native_bytes,
        })
    }
}

#[derive(Clone, Copy)]
struct SeedBinding {
    point: FreshPoint,
    fingerprint: [u8; 32],
    operation: Operation,
}

/// Exact workspace owner/mappings plus the driver-attested finite native
/// extents. Not a certificate verifier; parser/control/grant/guest ownership
/// must still be admitted in the same terminal ledger by the parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Admission {
    pub mapped_bytes: usize,
    pub owner_bytes: usize,
    pub pinned_bytes: usize,
    pub stack_extent_bytes: usize,
    pub other_native_bytes: usize,
}
impl Admission {
    pub(crate) fn bytes(self) -> usize {
        self.mapped_bytes + self.owner_bytes + self.stack_extent_bytes + self.other_native_bytes
    }
}
/// Every storage mapping is fully admitted and pre-touched before input.
/// Every buffer/schedule mapping is mlocked/DONTDUMP and erased on exit.
/// All secret fields are private and this type has no Debug/Clone/export.
pub(crate) struct Workspace {
    decoded: slab::Slab,
    output: slab::Slab,
    secret: slab::Slab,
    cipher: cipher::CipherSlot,
    binding: Option<SeedBinding>,
    admission: Admission,
    mount: Option<OwnedMountInput>,
    // LAST: all actual mapping/typed crypto drops precede ticket release.
    ticket: Option<SlotTicket>,
}
impl Workspace {
    pub(crate) fn required_admission(native: NativeAllowance) -> Result<Admission, Error> {
        let data = slab::mapped_bytes(MAX_TOKEN_BYTES)?;
        let secret = slab::mapped_bytes(128)?;
        let cipher = cipher::CipherSlot::mapped_bytes()?;
        cipher::CipherSlot::validate_alignment()?;
        let mount = slab::mapped_bytes(32)?;
        let mapped_bytes = data
            .checked_mul(2)
            .and_then(|n| n.checked_add(secret))
            .and_then(|n| n.checked_add(cipher))
            .and_then(|n| n.checked_add(mount))
            .ok_or(Error::Capacity)?;
        mapped_bytes
            .checked_add(size_of::<Self>() + size_of::<Control<'_>>())
            .and_then(|n| n.checked_add(native.stack_extent_bytes))
            .and_then(|n| n.checked_add(native.other_native_bytes))
            .ok_or(Error::Capacity)?;
        Ok(Admission {
            mapped_bytes,
            owner_bytes: size_of::<Self>() + size_of::<Control<'_>>(),
            pinned_bytes: mapped_bytes,
            stack_extent_bytes: native.stack_extent_bytes,
            other_native_bytes: native.other_native_bytes,
        })
    }
    // Legacy numerical helper is an independent test fixture ONLY.
    #[cfg(test)]
    pub(crate) fn new(
        admitted_bytes: usize,
        native: NativeAllowance,
        control: &Control<'_>,
    ) -> Result<Self, Error> {
        let admission = Self::required_admission(native)?;
        if admitted_bytes < admission.bytes() {
            return Err(Error::Capacity);
        }
        control.check()?;
        Ok(Self {
            decoded: slab::Slab::new(MAX_TOKEN_BYTES, true, control)?,
            output: slab::Slab::new(MAX_TOKEN_BYTES, true, control)?,
            secret: slab::Slab::new(128, true, control)?,
            cipher: cipher::CipherSlot::new(control, None)?,
            binding: None,
            admission,
            mount: Some(OwnedMountInput {
                storage: slab::Slab::new(32, true, control)?,
                binding: None,
            }),
            ticket: None,
        })
    }
    #[cfg(not(test))]
    pub(crate) fn new(
        ticket: SlotTicket,
        native: NativeAllowance,
        control: &Control<'_>,
    ) -> Result<Self, Error> {
        Self::new_with_ticket(ticket, native, control)
    }
    pub(crate) fn new_with_ticket(
        ticket: SlotTicket,
        native: NativeAllowance,
        control: &Control<'_>,
    ) -> Result<Self, Error> {
        let admission = ticket.validate(native, control)?;
        // The ticket exists BEFORE the first mmap/mlock/pre-touch/private input.
        // Partial construction maps each own a strong lease and report munmap.
        let decoded = slab::Slab::new_ticket(MAX_TOKEN_BYTES, &ticket, control)?;
        let output = slab::Slab::new_ticket(MAX_TOKEN_BYTES, &ticket, control)?;
        let secret = slab::Slab::new_ticket(128, &ticket, control)?;
        let cipher = cipher::CipherSlot::new(control, Some(&ticket))?;
        let mount = OwnedMountInput {
            storage: slab::Slab::new_ticket(32, &ticket, control)?,
            binding: None,
        };
        ticket.check_control(control)?;
        Ok(Self {
            decoded,
            output,
            secret,
            cipher,
            binding: None,
            admission,
            mount: Some(mount),
            ticket: Some(ticket),
        })
    }
    /// # Safety
    /// Only after the real fresh verifier and captured declaration/Grant, the
    /// future certified native mount loader may write exactly32 bytes
    /// here, after source/file/permissions/length/controller checks. No guest
    /// pointer, provider callback, retained source or pre-loan plaintext read.
    /// This buffer is already charged, mandatory locked and dump-excluded. This
    /// API does NOT implement or certify that loader. No secret file is opened.
    pub(crate) unsafe fn mount_destination(
        &mut self,
        grant: &Grant<'_>,
        point: FreshPoint,
        control: &Control<'_>,
    ) -> Result<&mut [u8; 32], Error> {
        if let Err(error) = self.check_control(control) {
            self.reset();
            return Err(error);
        }
        self.reset();
        if grant.point != point {
            return Err(Error::StalePoint);
        }
        let mount = self.mount.as_mut().ok_or(Error::NativeAdmission)?;
        mount.binding = Some(SeedBinding {
            point: grant.point,
            fingerprint: grant.fingerprint,
            operation: grant.operation,
        });
        (&mut *mount.storage).try_into().map_err(|_| Error::Invalid)
    }
    pub(crate) fn prepare_owned_mounted(
        &mut self,
        grant: &Grant<'_>,
        point: FreshPoint,
        control: &Control<'_>,
    ) -> Result<(), Error> {
        // Taking the page prevents aliasing with Workspace during crypto. On
        // unwind it is erased/unmapped by its own owner, never fake-recredited.
        let mut mount = self.mount.take().ok_or(Error::NativeAdmission)?;
        let result = if mount.binding.take().is_some_and(|binding| {
            binding.point == grant.point
                && binding.fingerprint == grant.fingerprint
                && binding.operation == grant.operation
        }) {
            let input = MountedWrapping {
                bytes: (&mut *mount.storage)
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            };
            self.prepare_input(grant, point, input, control)
        } else {
            self.reset();
            Err(Error::SecretUnavailable)
        };
        mount.storage.zeroize();
        self.mount = Some(mount);
        result
    }
    fn check_control(&self, control: &Control<'_>) -> Result<(), Error> {
        if let Some(ticket) = self.ticket.as_ref() {
            ticket.check_control(control)
        } else {
            control.check()
        }
    }
    pub(crate) fn admission(&self) -> Admission {
        self.admission
    }
    pub(crate) fn reset(&mut self) {
        if let Some(mount) = self.mount.as_mut() {
            mount.storage.zeroize();
            mount.binding = None;
        }
        self.reset_workspace();
    }
    fn reset_workspace(&mut self) {
        self.clear_secret();
        self.decoded.zeroize();
        self.output.zeroize();
    }
    fn clear_secret(&mut self) {
        self.cipher.clear();
        self.secret.zeroize();
        self.binding = None;
    }
    fn require_seed(&self, grant: &Grant<'_>) -> Result<(), Error> {
        if self.binding.is_some_and(|binding| {
            binding.point == grant.point
                && binding.fingerprint == grant.fingerprint
                && binding.operation == grant.operation
        }) {
            Ok(())
        } else {
            Err(Error::SecretUnavailable)
        }
    }
    /// Real mounted wrap-open + per-DEK material-open, exclusively in admitted
    /// locked mappings. No AWS-LC/native error queues, provider I/O or fallback.
    /// The one-use mount input is consumed/erased, never kept by Workspace.
    #[cfg(test)]
    pub(crate) fn prepare_mounted(
        &mut self,
        grant: &Grant<'_>,
        point: FreshPoint,
        mounted: MountedWrapping<'_>,
        control: &Control<'_>,
    ) -> Result<(), Error> {
        self.prepare_input(grant, point, mounted, control)
    }
    fn prepare_input(
        &mut self,
        grant: &Grant<'_>,
        point: FreshPoint,
        mounted: MountedWrapping<'_>,
        control: &Control<'_>,
    ) -> Result<(), Error> {
        let mut erase = ExitErase::new(self);
        self.reset_workspace();
        self.check_control(control)?;
        control.begin_crypto_call(self.admission.mapped_bytes)?;
        // Only this audited native platform is enabled. In particular pinned
        // polyval's optional ARM PMULL backend lacks cleanup; no broad PASS.
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return Err(Error::Unsupported);
        }
        if grant.point != point {
            return Err(Error::StalePoint);
        }
        let envelope = grant.key.envelope.as_ref().ok_or(Error::Authority)?;
        let id = sha256(mounted.bytes, control)?;
        let mut expected_id = [0; 32];
        if codec::decode(envelope.wrapping_id.as_bytes(), &mut expected_id, control)? != 32
            || id != expected_id
        {
            return Err(Error::Authority);
        }
        self.secret[32..64].copy_from_slice(mounted.bytes);
        // Do not retain even the borrowed mounted-key input across private use.
        drop(mounted);
        self.open_envelope_part(
            grant,
            EnvelopePurpose::Dek,
            envelope.wrapped_dek,
            envelope.wrapping_nonce,
            control,
        )?;
        // Authenticated DEK32 replaces the wrapping key. Expanded wrap schedule
        // is dropped and scrubbed BEFORE initialization of the DEK schedule.
        self.secret.copy_within(64..96, 32);
        self.secret[64..].zeroize();
        self.cipher.clear();
        self.open_envelope_part(
            grant,
            EnvelopePurpose::Material,
            envelope.ciphertext,
            envelope.nonce,
            control,
        )?;
        self.secret.copy_within(64..96, 0);
        self.secret[32..].zeroize();
        self.cipher.clear();
        self.decoded.zeroize();
        self.check_control(control)?;
        self.binding = Some(SeedBinding {
            point: grant.point,
            fingerprint: grant.fingerprint,
            operation: grant.operation,
        });
        // Only the exact point/envelope/phase-bound seed survives until ONE
        // sign/verify. Every other owned byte/schedule has already been erased.
        erase.preserve_seed = true;
        Ok(())
    }
    fn open_envelope_part(
        &mut self,
        grant: &Grant<'_>,
        purpose: EnvelopePurpose,
        ciphertext: &str,
        nonce: &str,
        control: &Control<'_>,
    ) -> Result<(), Error> {
        control.check()?;
        let aad_len = envelope_aad_into(grant, purpose, &mut self.decoded[..512], control)?;
        if codec::decode(ciphertext.as_bytes(), &mut self.secret[64..112], control)? != 48
            || codec::decode(nonce.as_bytes(), &mut self.secret[112..124], control)? != 12
        {
            return Err(Error::Invalid);
        }
        let key = self.secret[32..64].try_into().map_err(|_| Error::Invalid)?;
        self.cipher.initialize(key);
        control.check()?;
        let (prefix, nonce) = self.secret.split_at_mut(112);
        let (prefix, tag) = prefix.split_at_mut(96);
        self.cipher
            .get()?
            .decrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(&nonce[..12]),
                &self.decoded[..aad_len],
                &mut prefix[64..96],
                aes_gcm::Tag::from_slice(tag),
            )
            .map_err(|_| Error::EnvelopeAuthentication)?;
        control.check()?;
        Ok(())
    }
    // Test-only injection is deliberately absent from the production API.
    #[cfg(test)]
    fn install_seed_for_test(&mut self, grant: &Grant<'_>, seed: &[u8; 32]) {
        self.clear_secret();
        self.secret[..32].copy_from_slice(seed);
        self.binding = Some(SeedBinding {
            point: grant.point,
            fingerprint: grant.fingerprint,
            operation: grant.operation,
        });
    }

    /// Header selector only: never authentication or authority. Caller may use
    /// it solely to select a version of its already-bound trusted declaration.
    /// No provider, private material, managed handle or ordinary JSON is used.
    pub(crate) fn untrusted_kid<'a>(
        &mut self,
        token: &[u8],
        parser: &'a mut FrameBuilder,
        control: &'a Control<'a>,
    ) -> Result<UntrustedKid<'a>, Error> {
        let _erase = ExitErase::new(self);
        self.check_control(control)?;
        control.begin_crypto_call(self.admission.mapped_bytes)?;
        let parts = codec::parts(token, control)?;
        let len = codec::decode(parts.header, &mut self.decoded[..MAX_HEADER_BYTES], control)?;
        let header = capture(parser, &self.decoded[..len], MAX_HEADER_BYTES, control)?;
        let header = parser.json(header, control.frame())?;
        self.check_control(control)?;
        Ok(UntrustedKid {
            value: selector_fields(header)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify<'a>(
        &mut self,
        grant: Grant<'_>,
        point: FreshPoint,
        token: &[u8],
        options: &[u8],
        now_ms: u64,
        parser: &'a mut FrameBuilder,
        control: &'a Control<'a>,
    ) -> Result<Verified<'a>, Error> {
        let _erase = ExitErase::new(self);
        let result = self.verify_inner(&grant, point, token, options, now_ms, parser, control);
        self.check_control(control)?;
        // Parsed values borrow the preadmitted parser only, never seed/workspace.
        result
    }
    #[allow(clippy::too_many_arguments)]
    fn verify_inner<'a>(
        &mut self,
        grant: &Grant<'_>,
        point: FreshPoint,
        token: &[u8],
        options: &[u8],
        now_ms: u64,
        parser: &'a mut FrameBuilder,
        control: &'a Control<'a>,
    ) -> Result<Verified<'a>, Error> {
        self.check_control(control)?;
        control.begin_crypto_call(self.admission.mapped_bytes)?;
        grant.authorize(point, Operation::Verify, control)?;
        self.require_seed(grant)?;
        let parts = codec::parts(token, control)?;
        let header_len =
            codec::decode(parts.header, &mut self.decoded[..MAX_HEADER_BYTES], control)?;
        let header = capture(
            parser,
            &self.decoded[..header_len],
            MAX_HEADER_BYTES,
            control,
        )?;
        let claims_len =
            codec::decode(parts.claims, &mut self.decoded[..MAX_CLAIMS_BYTES], control)?;
        let claims = capture(
            parser,
            &self.decoded[..claims_len],
            MAX_CLAIMS_BYTES,
            control,
        )?;
        let options = capture(
            parser,
            if options.is_empty() { b"{}" } else { options },
            MAX_OPTIONS_BYTES,
            control,
        )?;
        let header = parser.json(header, control.frame())?;
        let claims = parser.json(claims, control.frame())?;
        let options = parser.json(options, control.frame())?;
        object(header)?;
        object(claims)?;
        header_fields(header, grant, control)?;
        let options = verify_options(options, control)?;
        let mut signature = [0; 64];
        if codec::decode(parts.signature, &mut signature, control)? != 64 {
            return Err(Error::Signature);
        }
        control.debit(parts.message.len())?;
        // dalek default features include zeroize. This local has Drop-erasure.
        // Owned key Drop erases the seed; transient compiler/stack/register
        // copies remain outside the documented erasure guarantee.
        let seed: &[u8; 32] = self.secret[..32].try_into().map_err(|_| Error::Invalid)?;
        self.cipher.initialize_signing(seed);
        let key = self.cipher.signing_key()?;
        control.check()?;
        key.verifying_key()
            .verify_strict(parts.message, &Signature::from_bytes(&signature))
            .map_err(|_| Error::Signature)?;
        control.check()?;
        let dependency = validate_claims(claims, header, options, now_ms, control)?;
        Ok(Verified {
            claims,
            protected_header: header,
            dependency,
        })
    }

    pub(crate) fn sign<'a>(
        &'a mut self,
        grant: Grant<'_>,
        point: FreshPoint,
        claims: &[u8],
        options: &[u8],
        parser: &mut FrameBuilder,
        control: &Control<'_>,
    ) -> Result<&'a str, Error> {
        let mut erase = ExitErase::new(self);
        let result = self.sign_inner(&grant, point, claims, options, parser, control);
        self.check_control(control)?;
        match result {
            Ok(len) => {
                // Deliberate JWT result only; erased on next use/reset/drop.
                erase.preserve_output = true;
                Ok(unsafe { std::str::from_utf8_unchecked(&self.output[..len]) })
            }
            Err(error) => {
                self.output.zeroize();
                Err(error)
            }
        }
    }
    fn sign_inner(
        &mut self,
        grant: &Grant<'_>,
        point: FreshPoint,
        raw_claims: &[u8],
        raw_options: &[u8],
        parser: &mut FrameBuilder,
        control: &Control<'_>,
    ) -> Result<usize, Error> {
        self.check_control(control)?;
        control.begin_crypto_call(self.admission.mapped_bytes)?;
        grant.authorize(point, Operation::Sign, control)?;
        self.require_seed(grant)?;
        let claims = capture(parser, raw_claims, MAX_CLAIMS_BYTES, control)?;
        let options = capture(
            parser,
            if raw_options.is_empty() {
                b"{}"
            } else {
                raw_options
            },
            MAX_OPTIONS_BYTES,
            control,
        )?;
        let claims = parser.json(claims, control.frame())?;
        let options = parser.json(options, control.frame())?;
        object(claims)?;
        // The first release requires expiration even when issuing tokens.
        dates(claims, true)?;
        claim_shapes(claims, control)?;
        let typ = sign_options(options, grant, control)?;
        let mut header = codec::Writer::new(&mut self.decoded[..MAX_HEADER_BYTES], control);
        header.bytes(b"{\"alg\":\"EdDSA\",\"kid\":")?;
        header.quoted(grant.kid())?;
        header.bytes(b",\"typ\":")?;
        header.quoted(typ)?;
        header.bytes(b"}")?;
        let header_len = header.len();
        let mut len = codec::encode(&self.decoded[..header_len], &mut self.output, control)?;
        self.output[len] = b'.';
        len += 1;
        len += codec::encode(raw_claims, &mut self.output[len..], control)?;
        control.debit(len)?;
        let seed: &[u8; 32] = self.secret[..32].try_into().map_err(|_| Error::Invalid)?;
        self.cipher.initialize_signing(seed);
        let key = self.cipher.signing_key()?;
        control.check()?;
        let signature = key.sign(&self.output[..len]).to_bytes();
        control.check()?;
        self.output[len] = b'.';
        len += 1;
        len += codec::encode(&signature, &mut self.output[len..], control)?;
        Ok(len)
    }
}
// Private operation-local raw-pointer guard. Workspace is exclusively borrowed
// and never moved/dropped during an operation; no pointer escapes the call.
// Unlike a post-call cleanup only, this also erases material on panic unwinding.
struct ExitErase {
    secret: *mut slab::Slab,
    decoded: *mut slab::Slab,
    binding: *mut Option<SeedBinding>,
    cipher: *mut cipher::CipherSlot,
    output: *mut slab::Slab,
    mount: *mut Option<OwnedMountInput>,
    preserve_seed: bool,
    preserve_output: bool,
}
impl ExitErase {
    fn new(workspace: &mut Workspace) -> Self {
        Self {
            secret: &raw mut workspace.secret,
            decoded: &raw mut workspace.decoded,
            binding: &raw mut workspace.binding,
            cipher: &raw mut workspace.cipher,
            output: &raw mut workspace.output,
            mount: &raw mut workspace.mount,
            preserve_seed: false,
            preserve_output: false,
        }
    }
}
impl Drop for ExitErase {
    fn drop(&mut self) {
        // SAFETY: created and retained only inside the exclusive Workspace call;
        // these fields live until after this guard drops on return or unwind.
        unsafe {
            if let Some(mount) = (*self.mount).as_mut() {
                mount.storage.zeroize();
                mount.binding = None;
            }
            (*self.cipher).clear();
            if !self.preserve_seed {
                (*self.secret).zeroize();
                *self.binding = None;
            }
            (*self.decoded).zeroize();
            if !self.preserve_output {
                (*self.output).zeroize();
            }
        }
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        self.reset();
    }
}

pub(crate) struct Verified<'a> {
    pub claims: ArenaValue<'a>,
    pub protected_header: ArenaValue<'a>,
    pub dependency: TimeDependency,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TimeDependency {
    /// Exact explicit time provided by the invocation, not SystemTime.
    pub checked_at_ms: u64,
    /// nbf minus tolerance, clamped at zero. Both nbf/exp are authenticated.
    pub valid_from_ms: Option<u64>,
    /// exp plus tolerance; checked with integer millisecond arithmetic.
    pub expires_at_ms: u64,
}
fn capture(
    parser: &mut FrameBuilder,
    bytes: &[u8],
    cap: usize,
    control: &Control<'_>,
) -> Result<JsonId, Error> {
    control.check()?;
    if bytes.len() > cap || bytes.len() > MAX_BORROWED_BYTES {
        return Err(Error::Capacity);
    }
    let id = parser.reserve_json(JsonBank::Support, bytes.len())?;
    for chunk in bytes.chunks(1024) {
        control.debit(chunk.len())?;
        parser.append_json_chunk(id, chunk)?;
    }
    parser.finish_json(id, control.frame())?;
    Ok(id)
}
fn object(value: ArenaValue<'_>) -> Result<(), Error> {
    if value.kind() != ArenaKind::Object {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn text(value: ArenaValue<'_>, cap: usize) -> Result<&str, Error> {
    let text = value.as_str().ok_or(Error::Invalid)?;
    if text.len() > cap {
        return Err(Error::Capacity);
    }
    Ok(text)
}
fn optional_text<'a>(value: ArenaValue<'a>, key: &str) -> Result<Option<&'a str>, Error> {
    value
        .get(key)?
        .map(|v| text(v, MAX_OPTION_TEXT))
        .transpose()
}
fn equal(a: &str, b: &str, control: &Control<'_>) -> Result<bool, Error> {
    control.check()?;
    if a.len() != b.len() {
        return Ok(false);
    }
    for (a, b) in a.as_bytes().chunks(1024).zip(b.as_bytes().chunks(1024)) {
        control.debit(a.len())?;
        if a != b {
            return Ok(false);
        }
    }
    Ok(true)
}
/// Borrowed untrusted selector, deliberately not named a key capability.
pub(crate) struct UntrustedKid<'a> {
    pub value: &'a str,
}
fn selector_fields(header: ArenaValue<'_>) -> Result<&str, Error> {
    object(header)?;
    for entry in header.children() {
        let entry = entry?;
        match entry.key.ok_or(Error::Invalid)? {
            "alg" => {
                if text(entry.value, 16)? != "EdDSA" {
                    return Err(Error::Unsupported);
                }
            }
            "kid" => {
                text(entry.value, MAX_KID_BYTES)?;
            }
            "typ" => {
                text(entry.value, 128)?;
            }
            _ => return Err(Error::Unsupported),
        }
    }
    if header.get("alg")?.is_none() {
        return Err(Error::Invalid);
    }
    text(header.get("kid")?.ok_or(Error::Invalid)?, MAX_KID_BYTES)
}
fn header_fields(
    header: ArenaValue<'_>,
    grant: &Grant<'_>,
    control: &Control<'_>,
) -> Result<(), Error> {
    if !equal(selector_fields(header)?, grant.kid(), control)? {
        return Err(Error::Authority);
    }
    Ok(())
}
struct VerifyOptions<'a> {
    issuer: Option<&'a str>,
    audience: Option<ArenaValue<'a>>,
    subject: Option<&'a str>,
    typ: Option<&'a str>,
    tolerance_ms: u64,
}
fn verify_options<'a>(
    value: ArenaValue<'a>,
    control: &Control<'_>,
) -> Result<VerifyOptions<'a>, Error> {
    object(value)?;
    for entry in value.children() {
        let entry = entry?;
        match entry.key.ok_or(Error::Invalid)? {
            "issuer" | "subject" | "typ" => {
                text(entry.value, MAX_OPTION_TEXT)?;
            }
            "audience" => audiences(entry.value, control)?,
            "algorithms" => {
                if entry.value.kind() != ArenaKind::Array {
                    return Err(Error::Invalid);
                }
                let mut iter = entry.value.children();
                let first = iter.next().ok_or(Error::Invalid)??;
                if text(first.value, 16)? != "EdDSA" || iter.next().is_some() {
                    return Err(Error::Unsupported);
                }
            }
            "clockToleranceSeconds" => {
                integer_seconds(entry.value)?;
            }
            "requireExpiration" => {
                if entry.value.as_bool() != Some(true) {
                    return Err(Error::Unsupported);
                }
            }
            _ => return Err(Error::Unsupported),
        }
    }
    let tolerance_ms = value
        .get("clockToleranceSeconds")?
        .map(integer_seconds)
        .transpose()?
        .unwrap_or(0);
    if tolerance_ms > 3_600_000 {
        return Err(Error::Unsupported);
    }
    Ok(VerifyOptions {
        issuer: optional_text(value, "issuer")?,
        audience: value.get("audience")?,
        subject: optional_text(value, "subject")?,
        typ: optional_text(value, "typ")?,
        tolerance_ms,
    })
}
fn sign_options<'a>(
    value: ArenaValue<'a>,
    grant: &Grant<'_>,
    control: &Control<'_>,
) -> Result<&'a str, Error> {
    object(value)?;
    for entry in value.children() {
        let entry = entry?;
        match entry.key.ok_or(Error::Invalid)? {
            "algorithm" => {
                if text(entry.value, 16)? != "EdDSA" {
                    return Err(Error::Unsupported);
                }
            }
            "kid" => {
                if !equal(text(entry.value, MAX_KID_BYTES)?, grant.kid(), control)? {
                    return Err(Error::Authority);
                }
            }
            "typ" => {
                text(entry.value, 128)?;
            }
            _ => return Err(Error::Unsupported),
        }
    }
    Ok(value
        .get("typ")?
        .map(|v| text(v, 128))
        .transpose()?
        .unwrap_or("JWT"))
}
/// Explicit v1 subset: nonnegative canonical integer NumericDate seconds,
/// <= JS safe integer. Fractional/exponent/signed dates and fractional clock
/// tolerance are rejected rather than silently rounded or reinterpreted.
fn integer_seconds(value: ArenaValue<'_>) -> Result<u64, Error> {
    let lexeme = value.number_text().ok_or(Error::Invalid)?;
    if lexeme.is_empty() || lexeme.len() > 16 {
        return Err(Error::Unsupported);
    }
    let mut seconds = 0u64;
    for byte in lexeme.bytes() {
        if !byte.is_ascii_digit() {
            return Err(Error::Unsupported);
        }
        seconds = seconds
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(byte - b'0')))
            .ok_or(Error::Unsupported)?;
    }
    if seconds > 9_007_199_254_740_991 {
        return Err(Error::Unsupported);
    }
    seconds.checked_mul(1000).ok_or(Error::Unsupported)
}
fn date(claims: ArenaValue<'_>, key: &str) -> Result<Option<u64>, Error> {
    claims.get(key)?.map(integer_seconds).transpose()
}
fn dates(claims: ArenaValue<'_>, require_exp: bool) -> Result<(Option<u64>, Option<u64>), Error> {
    let exp = date(claims, "exp")?;
    let nbf = date(claims, "nbf")?;
    date(claims, "iat")?;
    if require_exp && exp.is_none() {
        return Err(Error::Claims);
    }
    Ok((exp, nbf))
}
fn audiences(value: ArenaValue<'_>, control: &Control<'_>) -> Result<(), Error> {
    if value.kind() != ArenaKind::Array {
        return Err(Error::Invalid);
    }
    let mut count = 0;
    for entry in value.children() {
        let entry = entry?;
        count += 1;
        if count > MAX_AUDIENCES {
            return Err(Error::Capacity);
        }
        let text = text(entry.value, MAX_OPTION_TEXT)?;
        control.debit(text.len())?;
    }
    Ok(())
}
fn claim_shapes(claims: ArenaValue<'_>, control: &Control<'_>) -> Result<(), Error> {
    optional_text(claims, "iss")?;
    optional_text(claims, "sub")?;
    if let Some(audience) = claims.get("aud")? {
        if audience.kind() == ArenaKind::Text {
            text(audience, MAX_OPTION_TEXT)?;
        } else {
            audiences(audience, control)?;
        }
    }
    Ok(())
}
fn expected_audience(
    actual: &str,
    expected: ArenaValue<'_>,
    control: &Control<'_>,
) -> Result<bool, Error> {
    for entry in expected.children() {
        if equal(actual, text(entry?.value, MAX_OPTION_TEXT)?, control)? {
            return Ok(true);
        }
    }
    Ok(false)
}
fn validate_claims(
    claims: ArenaValue<'_>,
    header: ArenaValue<'_>,
    options: VerifyOptions<'_>,
    now_ms: u64,
    control: &Control<'_>,
) -> Result<TimeDependency, Error> {
    claim_shapes(claims, control)?;
    for (key, expected) in [("iss", options.issuer), ("sub", options.subject)] {
        if let Some(expected) = expected {
            let actual = optional_text(claims, key)?.ok_or(Error::Claims)?;
            if !equal(actual, expected, control)? {
                return Err(Error::Claims);
            }
        }
    }
    if let Some(expected) = options.typ {
        let actual = optional_text(header, "typ")?.ok_or(Error::Claims)?;
        if !equal(actual, expected, control)? {
            return Err(Error::Claims);
        }
    }
    match (claims.get("aud")?, options.audience) {
        (None, None) => (),
        (Some(actual), Some(expected)) => {
            let mut matched = false;
            if actual.kind() == ArenaKind::Text {
                matched = expected_audience(text(actual, MAX_OPTION_TEXT)?, expected, control)?;
            } else {
                for entry in actual.children() {
                    matched |=
                        expected_audience(text(entry?.value, MAX_OPTION_TEXT)?, expected, control)?;
                }
            }
            if !matched {
                return Err(Error::Claims);
            }
        }
        _ => return Err(Error::Claims),
    }
    let (exp, nbf) = dates(claims, true)?;
    let expires_at_ms = exp
        .ok_or(Error::Claims)?
        .checked_add(options.tolerance_ms)
        .ok_or(Error::Unsupported)?;
    let valid_from_ms = nbf.map(|nbf| nbf.saturating_sub(options.tolerance_ms));
    if now_ms >= expires_at_ms {
        return Err(Error::Expired {
            at_ms: expires_at_ms,
        });
    }
    if let Some(changes_at_ms) = valid_from_ms
        && now_ms < changes_at_ms
    {
        // Expiration can change NotActive to Expired before activation when
        // nbf exceeds exp. Register the first outcome boundary, not a late wake.
        return Err(Error::NotActive {
            changes_at_ms: changes_at_ms.min(expires_at_ms),
        });
    }
    control.check()?;
    Ok(TimeDependency {
        checked_at_ms: now_ms,
        valid_from_ms,
        expires_at_ms,
    })
}

/// Pure stack SHA helpers do not authorize managed-key use or activate a raw
/// crypto callback. Caller must explicitly admit their output [32]/[64] bytes.
pub(crate) fn sha256(bytes: &[u8], control: &Control<'_>) -> Result<[u8; 32], Error> {
    if bytes.len() > MAX_BORROWED_BYTES {
        return Err(Error::Capacity);
    }
    let mut hash = Sha256::new();
    control.check()?;
    for chunk in bytes.chunks(1024) {
        control.debit(chunk.len())?;
        hash.update(chunk);
    }
    control.check()?;
    Ok(hash.finalize().into())
}
pub(crate) fn sha512(bytes: &[u8], control: &Control<'_>) -> Result<[u8; 64], Error> {
    if bytes.len() > MAX_BORROWED_BYTES {
        return Err(Error::Capacity);
    }
    let mut hash = Sha512::new();
    control.check()?;
    for chunk in bytes.chunks(1024) {
        control.debit(chunk.len())?;
        hash.update(chunk);
    }
    control.check()?;
    Ok(hash.finalize().into())
}
