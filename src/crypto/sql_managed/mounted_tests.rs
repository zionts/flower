#![allow(unexpected_cfgs)] // standalone-only actual-source reference selection
use super::*;
#[cfg(sql_managed_harness)]
use crate::ordinary_reference as reference;
// Integrated tests use an independent AWS-LC/serde reference. The external
// source-audit harness instead compiles ACTUAL current ordinary helper bodies.
#[cfg(not(sql_managed_harness))]
mod reference {
    use super::*;
    pub(super) fn aad_ed(domain: &str, id: &str, version: u64, purpose: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([
            "flower-key-v1",
            domain,
            id,
            version,
            "Ed25519",
            purpose
        ]))
        .unwrap()
    }
    pub(super) fn seal_bytes(key: &[u8], nonce: [u8; 12], aad: &[u8], bytes: &[u8]) -> Vec<u8> {
        let cipher = LessSafeKey::new(aws_lc_rs::aead::UnboundKey::new(&AES_256_GCM, key).unwrap());
        let mut bytes = bytes.to_vec();
        cipher
            .seal_in_place_append_tag(
                aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce),
                aws_lc_rs::aead::Aad::from(aad),
                &mut bytes,
            )
            .unwrap();
        bytes
    }
    pub(super) fn open_bytes(key: &[u8], nonce: [u8; 12], aad: &[u8], bytes: &[u8]) -> Vec<u8> {
        let cipher = LessSafeKey::new(aws_lc_rs::aead::UnboundKey::new(&AES_256_GCM, key).unwrap());
        let mut bytes = bytes.to_vec();
        let len = cipher
            .open_in_place(
                aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce),
                aws_lc_rs::aead::Aad::from(aad),
                &mut bytes,
            )
            .unwrap()
            .len();
        bytes.truncate(len);
        bytes
    }
}
const WRAP: [u8; 32] = [9; 32];
const DEK: [u8; 32] = [11; 32];
const WRAP_NONCE: [u8; 12] = [13; 12];
const SEED_NONCE: [u8; 12] = [15; 12];
struct Wire {
    wrapping_id: String,
    wrapped_dek: String,
    wrapping_nonce: String,
    ciphertext: String,
    nonce: String,
}
impl Wire {
    fn new() -> Self {
        let wrap_aad = reference::aad_ed("domain", "id", 1, "dek");
        let seed_aad = reference::aad_ed("domain", "id", 1, "material");
        Self {
            wrapping_id: URL_SAFE_NO_PAD.encode(Sha256::digest(WRAP)),
            wrapped_dek: URL_SAFE_NO_PAD
                .encode(reference::seal_bytes(&WRAP, WRAP_NONCE, &wrap_aad, &DEK)),
            wrapping_nonce: URL_SAFE_NO_PAD.encode(WRAP_NONCE),
            ciphertext: URL_SAFE_NO_PAD
                .encode(reference::seal_bytes(&DEK, SEED_NONCE, &seed_aad, &SEED)),
            nonce: URL_SAFE_NO_PAD.encode(SEED_NONCE),
        }
    }
    fn fields(&self) -> KeyFields<'_> {
        let mut key = fields();
        key.envelope = Some(EnvelopeFields {
            provider: "mounted",
            wrapping_id: &self.wrapping_id,
            wrapped_dek: &self.wrapped_dek,
            wrapping_nonce: &self.wrapping_nonce,
            ciphertext: &self.ciphertext,
            nonce: &self.nonce,
        });
        key
    }
    fn grant(&self, phase: Phase, control: &Control<'_>) -> Grant<'_> {
        unsafe { Grant::from_trusted_capture(self.fields(), attenuation(phase), point(), control) }
            .unwrap()
    }
    fn corrupt(text: &mut String) {
        let mut bytes = URL_SAFE_NO_PAD.decode(&*text).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        *text = URL_SAFE_NO_PAD.encode(bytes);
    }
}
fn assert_erased(workspace: &Workspace) {
    assert!(workspace.binding.is_none());
    assert!(workspace.secret.is_erased());
    assert!(workspace.decoded.is_erased());
    assert!(workspace.output.is_erased());
    assert!(workspace.cipher.is_erased());
}
fn load(
    workspace: &mut Workspace,
    grant: &Grant<'_>,
    point: FreshPoint,
    control: &Control<'_>,
) -> (Result<(), Error>, [u8; 32]) {
    // Independent native mount acquisition fixture: a separate admitted,
    // locked/DONTDUMP page, not a pageable raw-key owner on the worker stack.
    let fixture_cancelled = AtomicBool::new(false);
    let fixture = super::control(&fixture_cancelled);
    let mut mount = slab::Slab::new(32, true, &fixture).unwrap();
    mount.copy_from_slice(&WRAP);
    let result = workspace.prepare_mounted(
        grant,
        point,
        unsafe { MountedWrapping::from_trusted_mount((&mut *mount).try_into().unwrap()) },
        control,
    );
    let erased = (&*mount).try_into().unwrap();
    (result, erased)
}
#[test]
fn real_wire_load_sign_verify_and_aad_differential() {
    let wire = Wire::new();
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut workspace = workspace(&control);
    let mut parser = parser(&control);
    let signing = wire.grant(Phase::ReadlessFinalizer, &control);
    for (purpose, text) in [
        (EnvelopePurpose::Dek, "dek"),
        (EnvelopePurpose::Material, "material"),
    ] {
        let mut aad = [0; 512];
        let len = envelope_aad_into(&signing, purpose, &mut aad, &control).unwrap();
        assert_eq!(&aad[..len], reference::aad_ed("domain", "id", 1, text));
    }
    // Both ciphertext layers are genuine ordinary AES256GCM wire output.
    let dek = reference::open_bytes(
        &WRAP,
        WRAP_NONCE,
        &reference::aad_ed("domain", "id", 1, "dek"),
        &URL_SAFE_NO_PAD.decode(&wire.wrapped_dek).unwrap(),
    );
    assert_eq!(dek, DEK);
    assert_eq!(
        reference::open_bytes(
            &dek,
            SEED_NONCE,
            &reference::aad_ed("domain", "id", 1, "material"),
            &URL_SAFE_NO_PAD.decode(&wire.ciphertext).unwrap()
        ),
        SEED
    );
    assert_eq!(
        load(&mut workspace, &signing, point(), &control),
        (Ok(()), [0; 32])
    );
    assert!(workspace.secret[..32] == SEED);
    assert!(workspace.secret[32..].iter().all(|byte| *byte == 0));
    assert!(workspace.cipher.is_erased());
    let signed = workspace
        .sign(signing, point(), CLAIMS, b"{}", &mut parser, &control)
        .unwrap()
        .as_bytes()
        .to_vec();
    assert_eq!(signed, token(CLAIMS));
    let verification = wire.grant(Phase::FreshAuthentication, &control);
    assert_eq!(
        load(&mut workspace, &verification, point(), &control),
        (Ok(()), [0; 32])
    );
    assert!(
        workspace
            .verify(
                verification,
                point(),
                &signed,
                OPTIONS,
                15_000,
                &mut parser,
                &control
            )
            .is_ok()
    );
    assert_erased(&workspace);
}
#[cfg(sql_managed_harness)]
#[test]
fn actual_ordinary_mounted_file_wrap_is_accepted() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::env::temp_dir().join(format!("sql-managed-mount-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(&WRAP).unwrap();
    drop(file);
    let (id, encrypted) = reference::wrap_from_file(
        &path,
        WRAP_NONCE,
        &reference::aad_ed("domain", "id", 1, "dek"),
        &DEK,
    );
    std::fs::remove_file(path).unwrap();
    let mut wire = Wire::new();
    assert_eq!(wire.wrapping_id, id);
    wire.wrapped_dek = URL_SAFE_NO_PAD.encode(encrypted);
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut workspace = workspace(&control);
    assert_eq!(
        load(
            &mut workspace,
            &wire.grant(Phase::InitialAuthentication, &control),
            point(),
            &control
        ),
        (Ok(()), [0; 32])
    );
    workspace.reset();
    assert_erased(&workspace);
}
#[test]
fn both_bad_tags_and_both_wrong_aad_fail_closed_and_erase() {
    for case in 0..4 {
        let mut wire = Wire::new();
        match case {
            0 => Wire::corrupt(&mut wire.wrapped_dek),
            1 => Wire::corrupt(&mut wire.ciphertext),
            2 => {
                wire.wrapped_dek = URL_SAFE_NO_PAD.encode(reference::seal_bytes(
                    &WRAP,
                    WRAP_NONCE,
                    &reference::aad_ed("other", "id", 1, "dek"),
                    &DEK,
                ))
            }
            _ => {
                wire.ciphertext = URL_SAFE_NO_PAD.encode(reference::seal_bytes(
                    &DEK,
                    SEED_NONCE,
                    &reference::aad_ed("domain", "id", 2, "material"),
                    &SEED,
                ))
            }
        }
        let cancelled = AtomicBool::new(false);
        let control = control(&cancelled);
        let mut workspace = workspace(&control);
        let grant = wire.grant(Phase::FreshAuthentication, &control);
        assert_eq!(
            load(&mut workspace, &grant, point(), &control),
            (Err(Error::EnvelopeAuthentication), [0; 32])
        );
        assert_erased(&workspace);
    }
}
#[test]
fn mount_identity_and_stale_point_clear_prior_state_and_input() {
    let wire = Wire::new();
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut workspace = workspace(&control);
    let grant = wire.grant(Phase::FreshAuthentication, &control);
    assert_eq!(load(&mut workspace, &grant, point(), &control).0, Ok(()));
    let mut wrong_mount = [8; 32];
    assert_eq!(
        workspace.prepare_mounted(
            &grant,
            point(),
            unsafe { MountedWrapping::from_trusted_mount(&mut wrong_mount) },
            &control
        ),
        Err(Error::Authority)
    );
    assert_eq!(wrong_mount, [0; 32]);
    assert_erased(&workspace);
    let mut changed = point();
    changed.certificate[0] ^= 1;
    assert_eq!(
        load(&mut workspace, &grant, changed, &control),
        (Err(Error::StalePoint), [0; 32])
    );
    assert_erased(&workspace);
}
#[test]
fn finite_actual_native_extent_and_total_admission_required() {
    assert!(matches!(
        unsafe { NativeAllowance::from_trusted_launch(0, 0) },
        Err(Error::NativeAdmission)
    ));
    assert!(matches!(
        unsafe { NativeAllowance::from_trusted_launch(usize::MAX, 1) },
        Err(Error::Capacity)
    ));
    let native = native_allowance();
    assert!(native.stack_extent_bytes > 0);
    let admission = Workspace::required_admission(native).unwrap();
    assert_eq!(
        admission.bytes(),
        admission.mapped_bytes + admission.owner_bytes + native.stack_extent_bytes
    );
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    assert!(matches!(
        Workspace::new(
            admission.bytes() - native.stack_extent_bytes,
            native,
            &control
        ),
        Err(Error::Capacity)
    ));
}
#[test]
fn actual_mapped_aes_and_ghash_schedules_are_erased_on_reuse_and_unwind() {
    fn feature_evidence<T: zeroize::ZeroizeOnDrop>() {}
    feature_evidence::<aes::Aes256>();
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut workspace = workspace(&control);
    workspace.cipher.initialize(&WRAP);
    assert!(!workspace.cipher.is_erased());
    workspace.cipher.clear();
    assert!(workspace.cipher.is_erased());
    workspace.cipher.initialize_signing(&SEED);
    assert!(!workspace.cipher.is_erased());
    workspace.cipher.clear();
    assert!(workspace.cipher.is_erased());
    workspace.cipher.initialize(&DEK);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _erase = ExitErase::new(&mut workspace);
        workspace.secret[32..64].fill(23);
        workspace.output[0] = 42;
        panic!("test-only cipher-owner unwind");
    }));
    assert!(unwind.is_err());
    assert_erased(&workspace);
}
#[test]
fn real_loaded_grant_is_closed_across_phase_definition_point_and_envelope() {
    let wire = Wire::new();
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut workspace = workspace(&control);
    let mut parser = parser(&control);
    for change in 0..4 {
        let initial = wire.grant(Phase::InitialAuthentication, &control);
        assert_eq!(load(&mut workspace, &initial, point(), &control).0, Ok(()));
        let mut key = wire.fields();
        let mut attenuation = attenuation(Phase::InitialAuthentication);
        let mut fresh = point();
        match change {
            0 => attenuation.phase = Phase::FreshAuthentication,
            1 => attenuation.definition = "different",
            2 => fresh.snapshot += 1,
            _ => key.envelope.as_mut().unwrap().nonce = NONCE,
        }
        let other =
            unsafe { Grant::from_trusted_capture(key, attenuation, fresh, &control) }.unwrap();
        assert!(matches!(
            workspace.verify(
                other,
                fresh,
                &token(CLAIMS),
                OPTIONS,
                15_000,
                &mut parser,
                &control
            ),
            Err(Error::SecretUnavailable)
        ));
        assert_erased(&workspace);
    }
    let verify_only = wire.grant(Phase::FreshAuthentication, &control);
    assert_eq!(
        load(&mut workspace, &verify_only, point(), &control).0,
        Ok(())
    );
    assert_eq!(
        workspace.sign(verify_only, point(), CLAIMS, b"{}", &mut parser, &control),
        Err(Error::Authority)
    );
    assert_erased(&workspace);
}
#[test]
fn loader_cancel_deadline_and_worklimit_erase_all_owned_state() {
    let wire = Wire::new();
    for failure in 0..3 {
        let cancelled = AtomicBool::new(false);
        let good = control(&cancelled);
        let mut workspace = workspace(&good);
        let grant = wire.grant(Phase::FreshAuthentication, &good);
        assert_eq!(load(&mut workspace, &grant, point(), &good).0, Ok(()));
        let stopped = match failure {
            0 => {
                cancelled.store(true, Ordering::Release);
                control(&cancelled)
            }
            1 => Control::new(&cancelled, Instant::now(), MAX_JOB_WORK).unwrap(),
            _ => Control::new(&cancelled, Instant::now() + Duration::from_secs(1), 1).unwrap(),
        };
        let expected = [Error::Cancelled, Error::Deadline, Error::WorkLimit][failure];
        assert_eq!(
            load(&mut workspace, &grant, point(), &stopped),
            (Err(expected), [0; 32])
        );
        assert_erased(&workspace);
        assert_eq!(sha256(b"", &stopped), Err(expected));
    }
}
#[test]
fn fresh_thread_schedule_init_success_and_errors_allocate_zero_native_and_rust() {
    let Some((start, stop)) = native_probe() else {
        return;
    };
    // Stack is selected/admitted BEFORE launching each actual thread. Thread
    // launch/OS metadata are deliberately outside the component observation;
    // production driver must account them in the native allowance as well.
    const STACK: usize = 2 * 1024 * 1024;
    for case in 0..5 {
        let mut wire = Wire::new();
        if case == 2 {
            Wire::corrupt(&mut wire.wrapped_dek);
        }
        if case == 3 {
            Wire::corrupt(&mut wire.ciphertext);
        }
        let expected_token = token(CLAIMS);
        let counts = std::thread::Builder::new()
            .stack_size(STACK)
            .spawn(move || {
                let native = native_allowance();
                assert_eq!(native.stack_extent_bytes, STACK);
                let cancelled = AtomicBool::new(false);
                let control = control(&cancelled);
                let mut workspace = Workspace::new(
                    Workspace::required_admission(native).unwrap().bytes(),
                    native,
                    &control,
                )
                .unwrap();
                let mut parser = parser(&control);
                let mut mount = slab::Slab::new(32, true, &control).unwrap();
                mount.copy_from_slice(&if case == 4 { [8; 32] } else { WRAP });
                let ((result, native_count), rust_count, rust_bytes) = measure(|| {
                    unsafe { start() };
                    // No AES-GCM warm-up. Both wrapping and per-DEK schedules are
                    // first initialized INSIDE this fresh-thread observed phase.
                    let phase = if case == 1 {
                        Phase::FreshAuthentication
                    } else {
                        Phase::ReadlessFinalizer
                    };
                    let grant = wire.grant(phase, &control);
                    let result = workspace
                        .prepare_mounted(
                            &grant,
                            point(),
                            unsafe {
                                MountedWrapping::from_trusted_mount(
                                    (&mut *mount).try_into().unwrap(),
                                )
                            },
                            &control,
                        )
                        .and_then(|()| {
                            if case == 1 {
                                workspace
                                    .verify(
                                        grant,
                                        point(),
                                        &expected_token,
                                        OPTIONS,
                                        15_000,
                                        &mut parser,
                                        &control,
                                    )
                                    .map(|_| 0)
                            } else {
                                workspace
                                    .sign(grant, point(), CLAIMS, b"{}", &mut parser, &control)
                                    .map(str::len)
                            }
                        });
                    let count = unsafe { stop() };
                    (result, count)
                });
                assert!(mount.is_erased() && mount.is_locked());
                match case {
                    0 => {
                        let len = result.unwrap();
                        assert_eq!(&workspace.output[..len], expected_token);
                        workspace.reset();
                    }
                    1 => assert_eq!(result, Ok(0)),
                    2 | 3 => assert_eq!(result, Err(Error::EnvelopeAuthentication)),
                    _ => assert_eq!(result, Err(Error::Authority)),
                }
                assert_erased(&workspace);
                (native_count, rust_count, rust_bytes)
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(counts, (0, 0, 0), "fresh-thread case {case}");
    }
    eprintln!(
        "Mounted wrap+DEK schedule init/load/sign/verify cold success/error: 0C/0Rust; actual hard thread stack=2097152 bytes"
    );
}

#[test]
fn real_loaded_seed_is_one_operation_only_and_reset_disarms() {
    let wire = Wire::new();
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut workspace = workspace(&control);
    let mut parser = parser(&control);
    assert!(
        workspace.secret.is_locked()
            && workspace.decoded.is_locked()
            && workspace.output.is_locked()
    );
    let signing = wire.grant(Phase::ReadlessFinalizer, &control);
    assert_eq!(load(&mut workspace, &signing, point(), &control).0, Ok(()));
    assert!(
        workspace
            .sign(signing, point(), CLAIMS, b"{}", &mut parser, &control)
            .is_ok()
    );
    let signing = wire.grant(Phase::ReadlessFinalizer, &control);
    assert_eq!(
        workspace.sign(signing, point(), CLAIMS, b"{}", &mut parser, &control),
        Err(Error::SecretUnavailable)
    );
    assert_erased(&workspace);
    let signing = wire.grant(Phase::ReadlessFinalizer, &control);
    assert_eq!(load(&mut workspace, &signing, point(), &control).0, Ok(()));
    workspace.reset();
    assert_eq!(
        workspace.sign(signing, point(), CLAIMS, b"{}", &mut parser, &control),
        Err(Error::SecretUnavailable)
    );
    assert_erased(&workspace);
}
#[test]
fn native_probe_positive_control_observes_c_and_aligned_allocators() {
    let Some((start, stop)) = native_probe() else {
        return;
    };
    let pointer = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"sql_managed_native_probe_positive_control".as_ptr(),
        )
    };
    assert!(!pointer.is_null());
    let positive: unsafe extern "C" fn() -> libc::c_int = unsafe { std::mem::transmute(pointer) };
    let ((count, success), rust_calls, rust_bytes) = measure(|| {
        unsafe { start() };
        let success = unsafe { positive() };
        let count = unsafe { stop() };
        (count, success)
    });
    assert_eq!(success, 1);
    assert_eq!((count, rust_calls, rust_bytes), (5, 0, 0));
}

fn node_fixture(native: NativeAllowance) -> NodeLockProfile {
    let layout = NodeLockProfile::required_layout(1, native).unwrap();
    // This controlled component fixture has no other locked owners at entry.
    // It is not a production source audit, controller approval or launch proof.
    let evidence = unsafe {
        NodeStartup::from_trusted_node_startup(
            1,
            layout.total_software_bytes,
            layout.total_locked_bytes,
            Some(0),
        )
    }
    .unwrap();
    NodeLockProfile::fixture(
        evidence,
        LockProfileCaps {
            slots: 1,
            locked_bytes: layout.total_locked_bytes,
            software_bytes: layout.total_software_bytes,
        },
        native,
    )
    .unwrap()
}
#[test]
fn profile_owned_mount_cold_ticket_mapping_aes_jwt_and_drop_zero_c_zero_rust() {
    let Some((start, stop)) = native_probe() else {
        return;
    };
    const STACK: usize = 2 * 1024 * 1024;
    for case in 0..5 {
        let mut wire = Wire::new();
        if case == 2 {
            Wire::corrupt(&mut wire.wrapped_dek);
        }
        if case == 3 {
            Wire::corrupt(&mut wire.ciphertext);
        }
        let expected = token(CLAIMS);
        let counts = std::thread::Builder::new()
            .stack_size(STACK)
            .spawn(move || {
                let native = native_allowance();
                assert_eq!(native.stack_extent_bytes, STACK);
                let profile = node_fixture(native);
                let cancelled = AtomicBool::new(false);
                let control = control(&cancelled);
                let mut parser = parser(&control);
                let ((result, native_calls), rust_calls, rust_bytes) = measure(|| {
                    unsafe { start() };
                    let result = (|| {
                        let ticket = profile.claim(&control)?;
                        let mut workspace = Workspace::new_with_ticket(ticket, native, &control)?;
                        assert!(matches!(
                            profile.claim(&control),
                            Err(Error::NativeAdmission)
                        ));
                        let phase = if case == 1 {
                            Phase::FreshAuthentication
                        } else {
                            Phase::ReadlessFinalizer
                        };
                        let grant = wire.grant(phase, &control);
                        unsafe { workspace.mount_destination(&grant, point(), &control)? }
                            .copy_from_slice(&if case == 4 { [8; 32] } else { WRAP });
                        workspace.prepare_owned_mounted(&grant, point(), &control)?;
                        assert!(workspace.mount.as_ref().unwrap().storage.is_erased());
                        if case == 1 {
                            workspace.verify(
                                grant,
                                point(),
                                &expected,
                                OPTIONS,
                                15000,
                                &mut parser,
                                &control,
                            )?;
                        } else {
                            let token = workspace.sign(
                                grant,
                                point(),
                                CLAIMS,
                                b"{}",
                                &mut parser,
                                &control,
                            )?;
                            assert!(token.as_bytes() == expected);
                        }
                        drop(workspace); // typed crypto Drop + every actual unmap in observation.
                        Ok(())
                    })();
                    let native_calls = unsafe { stop() };
                    (result, native_calls)
                });
                match case {
                    0 | 1 => assert_eq!(result, Ok(())),
                    2 | 3 => assert_eq!(result, Err(Error::EnvelopeAuthentication)),
                    _ => assert_eq!(result, Err(Error::Authority)),
                }
                assert_eq!(profile.status().active_slots, 0);
                (native_calls, rust_calls, rust_bytes)
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(counts, (0, 0, 0));
    }
    eprintln!(
        "profile_cold cases=5 C_alloc=0 Rust_alloc=0 Rust_bytes=0 maps_per_capsule=5 locked_per_capsule=143360 pthread_stack=2097152"
    );
}
#[test]
fn owned_mount_regular_file_fixture_reads_into_locked_page_after_ticket_only() {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::env::temp_dir().join(format!(
        "sql-managed-owned-profile-mount-{}",
        std::process::id()
    ));
    let mut writer = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    writer.write_all(&WRAP).unwrap();
    drop(writer);
    let file = std::fs::File::open(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    assert_eq!(
        unsafe { libc::fstat(file.as_raw_fd(), metadata.as_mut_ptr()) },
        0
    );
    let metadata = unsafe { metadata.assume_init() };
    assert_eq!(metadata.st_mode & libc::S_IFMT, libc::S_IFREG);
    assert_eq!(metadata.st_mode & 0o777, 0o600);
    assert_eq!(metadata.st_size, 32);
    assert_eq!(metadata.st_uid, unsafe { libc::geteuid() });
    let wire = Wire::new();
    let native = native_allowance();
    let profile = node_fixture(native);
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut workspace =
        Workspace::new_with_ticket(profile.claim(&control).unwrap(), native, &control).unwrap();
    assert!(workspace.mount.as_ref().unwrap().storage.is_locked());
    let (result, calls, bytes) = measure(|| {
        let grant = wire.grant(Phase::FreshAuthentication, &control);
        let destination =
            unsafe { workspace.mount_destination(&grant, point(), &control) }.unwrap();
        assert_eq!(
            unsafe { libc::pread(file.as_raw_fd(), destination.as_mut_ptr().cast(), 32, 0) },
            32
        );
        workspace.prepare_owned_mounted(&grant, point(), &control)
    });
    assert_eq!(result, Ok(()));
    assert_eq!((calls, bytes), (0, 0));
    assert!(workspace.mount.as_ref().unwrap().storage.is_erased());
    workspace.reset();
    assert_erased(&workspace);
    drop(workspace);
    assert_eq!(profile.status().active_slots, 0);
}
#[test]
fn owned_mount_stale_point_cancel_and_nonoriginal_control_erase_input() {
    let native = native_allowance();
    let wire = Wire::new();
    for case in 0..3 {
        let profile = node_fixture(native);
        let cancelled = AtomicBool::new(false);
        let original = control(&cancelled);
        let mut workspace =
            Workspace::new_with_ticket(profile.claim(&original).unwrap(), native, &original)
                .unwrap();
        let grant = wire.grant(Phase::FreshAuthentication, &original);
        unsafe { workspace.mount_destination(&grant, point(), &original) }
            .unwrap()
            .copy_from_slice(&WRAP);
        let other = control(&cancelled);
        let mut fresh = point();
        if case == 0 {
            fresh.snapshot += 1;
        }
        if case == 1 {
            cancelled.store(true, Ordering::Release);
        }
        let result = workspace.prepare_owned_mounted(
            &grant,
            fresh,
            if case == 2 { &other } else { &original },
        );
        assert_eq!(
            result,
            Err([Error::StalePoint, Error::Cancelled, Error::NativeAdmission][case])
        );
        assert!(workspace.mount.as_ref().unwrap().storage.is_erased());
        assert_erased(&workspace);
        drop(workspace);
        assert_eq!(profile.status().active_slots, 0);
    }
}

#[test]
fn owned_mount_destination_requires_exact_point_and_captured_grant_binding() {
    let native = native_allowance();
    let wire = Wire::new();
    let profile = node_fixture(native);
    let cancelled = AtomicBool::new(false);
    let original = control(&cancelled);
    let mut workspace =
        Workspace::new_with_ticket(profile.claim(&original).unwrap(), native, &original).unwrap();
    let grant = wire.grant(Phase::FreshAuthentication, &original);
    let mut stale = point();
    stale.snapshot += 1;
    assert!(matches!(
        unsafe { workspace.mount_destination(&grant, stale, &original) },
        Err(Error::StalePoint)
    ));
    assert!(workspace.mount.as_ref().unwrap().storage.is_erased());
    unsafe { workspace.mount_destination(&grant, point(), &original) }
        .unwrap()
        .copy_from_slice(&WRAP);
    let finalizer = wire.grant(Phase::ReadlessFinalizer, &original);
    assert_eq!(
        workspace.prepare_owned_mounted(&finalizer, point(), &original),
        Err(Error::SecretUnavailable)
    );
    assert!(workspace.mount.as_ref().unwrap().storage.is_erased());
    assert_erased(&workspace);
}
