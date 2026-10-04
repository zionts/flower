//! Independent component fixtures: approvals/other-owner audit are NOT live.
use super::super::slab::observer::Observation;
use super::*;
use crate::allocation_probe::measure;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
fn control(cancelled: &AtomicBool) -> Control<'_> {
    Control::new(
        cancelled,
        Instant::now() + Duration::from_secs(30),
        64 * 1024 * 1024,
    )
    .unwrap()
}
fn native() -> NativeAllowance {
    let mut attr = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
    let mut address = std::ptr::null_mut();
    let mut bytes = 0;
    unsafe {
        assert_eq!(
            libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr()),
            0
        );
        assert_eq!(
            libc::pthread_attr_getstack(attr.as_ptr(), &mut address, &mut bytes),
            0
        );
        assert_eq!(libc::pthread_attr_destroy(attr.as_mut_ptr()), 0);
        NativeAllowance::from_trusted_launch(bytes, 0).unwrap()
    }
}
fn inputs(slots: usize, native: NativeAllowance, other: usize) -> (NodeStartup, LockProfileCaps) {
    let layout = NodeLockProfile::required_layout(slots, native).unwrap();
    let evidence = unsafe {
        NodeStartup::from_trusted_node_startup(
            slots,
            layout.total_software_bytes,
            layout.total_locked_bytes,
            Some(other),
        )
    }
    .unwrap();
    (
        evidence,
        LockProfileCaps {
            slots,
            software_bytes: layout.total_software_bytes,
            locked_bytes: layout.total_locked_bytes,
        },
    )
}
fn profile(slots: usize, native: NativeAllowance) -> NodeLockProfile {
    // Scalar VmLck is only a diagnostic; this fixture is NOT a production audit.
    let (evidence, caps) = inputs(slots, native, locked_diagnostic().unwrap());
    NodeLockProfile::fixture(evidence, caps, native).unwrap()
}
#[test]
fn exact_page_layout_and_actual_control_owner_are_recomputed() {
    let native = native();
    let one = NodeLockProfile::required_layout(1, native).unwrap();
    let two = NodeLockProfile::required_layout(2, native).unwrap();
    let eight = NodeLockProfile::required_layout(8, native).unwrap();
    assert_eq!(super::super::slab::page_size().unwrap(), 4096);
    assert_eq!(
        (
            one.total_locked_bytes,
            two.total_locked_bytes,
            eight.total_locked_bytes
        ),
        (143360, 286720, 1146880)
    );
    assert_eq!(
        one.control_bytes,
        one.control_allocation_bytes + size_of::<NodeLockProfile>() + one.global_control_bytes
    );
    assert_eq!(
        two.control_allocation_bytes - one.control_allocation_bytes,
        size_of::<Slot>()
    );
    assert_eq!(
        one.total_software_bytes,
        one.control_bytes + one.capsule_software_bytes
    );
    eprintln!(
        "fixture_layout locked={} workspace_owner={} control={} slot={} software={} stack={}",
        one.total_locked_bytes,
        Workspace::required_admission(native).unwrap().owner_bytes,
        one.control_bytes,
        one.slot_state_bytes,
        one.total_software_bytes,
        native.stack_extent_bytes
    );
}
#[test]
fn unknown_other_locked_owners_and_unapproved_caps_refuse() {
    let native = native();
    assert!(matches!(
        unsafe { NodeStartup::from_trusted_node_startup(1, usize::MAX, usize::MAX, None) },
        Err(Error::NativeAdmission)
    ));
    assert!(matches!(
        unsafe { NodeStartup::from_trusted_node_startup(0, 1, 1, Some(0)) },
        Err(Error::NativeAdmission)
    ));
    for case in 0..4 {
        let (evidence, mut caps) = inputs(1, native, locked_diagnostic().unwrap());
        match case {
            0 => caps.slots = 2,
            1 => caps.locked_bytes += 1,
            2 => caps.software_bytes += 1,
            _ => caps.locked_bytes -= 1,
        }
        let observation = Observation::begin();
        assert!(matches!(
            NodeLockProfile::fixture(evidence, caps, native),
            Err(Error::NativeAdmission)
        ));
        assert_eq!(observation.attempts(), 0);
    }
}
#[test]
fn finite_soft_hard_rounding_infinity_and_overflow_fail_closed() {
    for limits in [
        (libc::RLIM_INFINITY, 1),
        (1, libc::RLIM_INFINITY),
        (2, 1),
        (65536, 65536),
        (143359, 143360),
    ] {
        assert_eq!(
            validate_memlock(limits.0, limits.1, 143360),
            Err(Error::NativeAdmission)
        );
    }
    assert_eq!(validate_memlock(143360, 143360, 143360), Ok(()));
    assert!(matches!(
        NodeLockProfile::required_layout(usize::MAX, native()),
        Err(Error::Capacity)
    ));
    let huge = unsafe { NativeAllowance::from_trusted_launch(usize::MAX - 1, 0) }.unwrap();
    assert!(matches!(
        NodeLockProfile::required_layout(1, huge),
        Err(Error::Capacity)
    ));
    let (mut evidence, caps) = inputs(1, native(), 0);
    evidence.other_locked_bytes = usize::MAX;
    assert!(matches!(
        NodeLockProfile::fixture(evidence, caps, native()),
        Err(Error::Capacity)
    ));
}
#[test]
fn one_ticket_refuses_second_loan_and_reuses_only_after_exact_unmap() {
    let native = native();
    let profile = profile(1, native);
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let observation = Observation::begin();
    let (result, calls, bytes) = measure(|| {
        let ticket = profile.claim(&control)?;
        Workspace::new_with_ticket(ticket, native, &control)
    });
    let mut workspace = result.unwrap();
    assert_eq!((calls, bytes), (0, 0));
    assert_eq!(profile.status().active_slots, 1);
    assert!(matches!(
        profile.claim(&control),
        Err(Error::NativeAdmission)
    ));
    assert_eq!(observation.attempts(), 5);
    unsafe { workspace.mount_destination(&grant(&control), point(), &control) }
        .unwrap()
        .fill(17);
    workspace.secret.fill(19);
    workspace.output.fill(21);
    workspace.decoded.fill(23);
    workspace.cipher.initialize(&[31; 32]);
    workspace.reset();
    assert_eq!(profile.status().active_slots, 1); // reset does NOT return a live mapping loan.
    drop(workspace);
    let (released, len) = observation.releases();
    assert_eq!(len, 5);
    for region in &released[..len] {
        assert!(region.id != 0 && region.erased && region.result == 0);
    }
    assert_eq!(
        released[..len].iter().map(|r| r.bytes).sum::<usize>(),
        143360
    );
    assert_eq!(profile.status().active_slots, 0);
    let ticket = profile.claim(&control).unwrap();
    drop(ticket);
    assert_eq!(profile.status().active_slots, 0);
}
#[test]
fn outer_handle_drop_retains_ticket_and_mapping_control_until_last_owner() {
    let native = native();
    let profile = profile(1, native);
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let ticket = profile.claim(&control).unwrap();
    let before = DESTROYED.load(Ordering::Relaxed);
    drop(profile);
    assert_eq!(DESTROYED.load(Ordering::Relaxed), before);
    assert_eq!(ticket.status().active_slots, 1);
    let workspace = Workspace::new_with_ticket(ticket, native, &control).unwrap();
    assert_eq!(workspace.ticket.as_ref().unwrap().status().active_slots, 1);
    assert_eq!(DESTROYED.load(Ordering::Relaxed), before);
    drop(workspace);
    assert_eq!(DESTROYED.load(Ordering::Relaxed), before + 1);
}
#[test]
fn cross_thread_drop_and_concurrent_node_loans_share_one_ceiling() {
    let native = native();
    let profile = profile(1, native);
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let workspace =
        Workspace::new_with_ticket(profile.claim(&control).unwrap(), native, &control).unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| drop(workspace)).join().unwrap();
    });
    assert_eq!(profile.status().active_slots, 0);
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let cancel = AtomicBool::new(false);
            let original = self::control(&cancel);
            let ticket = profile.claim(&original).unwrap();
            barrier.wait();
            barrier.wait();
            drop(ticket);
        });
        barrier.wait();
        assert!(matches!(
            profile.claim(&control),
            Err(Error::NativeAdmission)
        ));
        barrier.wait();
        worker.join().unwrap();
    });
    assert_eq!(profile.status().active_slots, 0);
}
#[test]
fn mismatched_native_and_nonoriginal_control_refuse_before_mmap() {
    let native = native();
    let profile = profile(1, native);
    let cancelled = AtomicBool::new(false);
    let original = control(&cancelled);
    for case in 0..2 {
        let ticket = profile.claim(&original).unwrap();
        let other = control(&cancelled);
        let wrong =
            unsafe { NativeAllowance::from_trusted_launch(native.stack_extent_bytes + 1, 0) }
                .unwrap();
        let observation = Observation::begin();
        let result = Workspace::new_with_ticket(
            ticket,
            if case == 0 { wrong } else { native },
            if case == 0 { &original } else { &other },
        );
        assert!(matches!(result, Err(Error::NativeAdmission)));
        assert_eq!(observation.attempts(), 0);
        assert_eq!(profile.status().active_slots, 0);
    }
}
#[test]
fn cancel_deadline_partial_map_and_unwind_return_credit_after_wipe() {
    let native = native();
    let profile = profile(1, native);
    let cancelled = AtomicBool::new(false);
    let partial =
        Control::new(&cancelled, Instant::now() + Duration::from_secs(30), 70000).unwrap();
    let observation = Observation::begin();
    let ticket = profile.claim(&partial).unwrap();
    assert!(matches!(
        Workspace::new_with_ticket(ticket, native, &partial),
        Err(Error::WorkLimit)
    ));
    assert_eq!(profile.status().active_slots, 0);
    assert_eq!(observation.attempts(), 2);
    let (releases, len) = observation.releases();
    assert_eq!(len, 2);
    assert!(releases[..len].iter().all(|r| r.erased && r.result == 0));
    drop(observation);
    let original = control(&cancelled);
    let ticket = profile.claim(&original).unwrap();
    cancelled.store(true, Ordering::Release);
    let observation = Observation::begin();
    assert!(matches!(
        Workspace::new_with_ticket(ticket, native, &original),
        Err(Error::Cancelled)
    ));
    assert_eq!(observation.attempts(), 0);
    assert_eq!(profile.status().active_slots, 0);
    cancelled.store(false, Ordering::Release);
    let expired = Control::new(&cancelled, Instant::now(), 1000000).unwrap();
    assert!(matches!(profile.claim(&expired), Err(Error::Deadline)));
    drop(observation);
    let original = control(&cancelled);
    let observation = Observation::begin();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut workspace =
            Workspace::new_with_ticket(profile.claim(&original).unwrap(), native, &original)
                .unwrap();
        workspace.secret.fill(11);
        unsafe { workspace.mount_destination(&grant(&original), point(), &original) }
            .unwrap()
            .fill(13);
        panic!("fixed fixture unwind");
    }));
    assert!(unwind.is_err());
    let (releases, len) = observation.releases();
    assert_eq!(len, 5);
    assert!(releases[..len].iter().all(|r| r.erased && r.result == 0));
    assert_eq!(profile.status().active_slots, 0);
}
#[test]
fn exact_owner_unmap_evidence_survives_immediate_address_reuse() {
    let native = native();
    let profile = profile(1, native);
    let cancelled = AtomicBool::new(false);
    let original = control(&cancelled);
    let observation = Observation::begin();
    let workspace =
        Workspace::new_with_ticket(profile.claim(&original).unwrap(), native, &original).unwrap();
    drop(workspace);
    let (releases, len) = observation.releases();
    assert_eq!(len, 5);
    let region = releases[0];
    assert!(region.erased && region.result == 0);
    let replacement = unsafe {
        libc::mmap(
            region.address as *mut _,
            region.bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if replacement != libc::MAP_FAILED {
        assert_eq!(replacement as usize, region.address);
        assert_eq!(unsafe { libc::munmap(replacement, region.bytes) }, 0);
    } else {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EEXIST)
        );
    }
    assert_eq!(profile.status().active_slots, 0);
    drop(profile.claim(&original).unwrap());
}
fn child(mode: &str, limit: Option<usize>) {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "sql_managed::profile::tests::profile_subprocess_entry",
            "--exact",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("SQL_LOCK_PROFILE_FIXTURE", mode);
    if let Some(limit) = limit {
        unsafe {
            command.pre_exec(move || {
                let mut actual = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut actual) != 0
                    || actual.rlim_cur < limit as libc::rlim_t
                    || actual.rlim_max < limit as libc::rlim_t
                {
                    return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                }
                let lower = libc::rlimit {
                    rlim_cur: limit as libc::rlim_t,
                    rlim_max: limit as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_MEMLOCK, &lower) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    assert!(command.status().unwrap().success());
}
#[test]
fn fork_exec_64k_memlock_refuses_before_maps_and_private_input() {
    child("low", Some(65536));
}
#[test]
fn fork_exec_exact_one_capsule_memlock_and_startup_singleton() {
    child("exact", Some(143360));
}
#[test]
fn actual_munmap_failure_retains_fatal_hold_not_capacity() {
    child("hold", None);
}
#[test]
fn lowered_limit_after_startup_partial_lock_failure_is_erased() {
    child("partial", None);
}
#[test]
fn profile_subprocess_entry() {
    let Ok(mode) = std::env::var("SQL_LOCK_PROFILE_FIXTURE") else {
        return;
    };
    let native = native();
    let (evidence, caps) = inputs(1, native, 0);
    let observation = Observation::begin();
    let profile = NodeLockProfile::new(evidence, caps, native);
    if mode == "low" {
        assert!(matches!(profile, Err(Error::NativeAdmission)));
        assert_eq!(observation.attempts(), 0);
        eprintln!("memlock_low soft=65536 hard=65536 maps=0 private_reads=0");
        return;
    }
    let profile = profile.unwrap();
    let cancelled = AtomicBool::new(false);
    let original = control(&cancelled);
    if mode == "partial" {
        let lower = libc::rlimit {
            rlim_cur: 65536,
            rlim_max: 65536,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lower) }, 0);
    }
    let result = Workspace::new_with_ticket(profile.claim(&original).unwrap(), native, &original);
    if mode == "partial" {
        assert!(matches!(result, Err(Error::Capacity)));
        assert_eq!(observation.attempts(), 2);
        let (releases, len) = observation.releases();
        assert_eq!(len, 2);
        assert!(releases[..len].iter().all(|r| r.erased && r.result == 0));
        assert_eq!(profile.status().active_slots, 0);
        return;
    }
    let mut workspace = result.unwrap();
    assert_eq!(observation.attempts(), 5);
    assert!(matches!(
        profile.claim(&original),
        Err(Error::NativeAdmission)
    ));
    unsafe { workspace.mount_destination(&grant(&original), point(), &original) }
        .unwrap()
        .fill(29);
    if mode == "hold" {
        observation.fail_next_unmap();
    }
    drop(workspace);
    let (releases, len) = observation.releases();
    assert_eq!(len, 5);
    assert!(releases[..len].iter().all(|r| r.erased));
    if mode == "hold" {
        assert_eq!(profile.status().active_slots, 1);
        assert_eq!(profile.status().held_slots, 1);
        assert!(matches!(
            profile.claim(&original),
            Err(Error::NativeAdmission)
        ));
        assert_eq!(releases[0].result, -1);
        // Fixture-only kernel cleanup; deliberately does NOT return held credit.
        assert_eq!(
            unsafe { libc::munmap(releases[0].address as *mut _, releases[0].bytes) },
            0
        );
        assert_eq!(profile.status().active_slots, 1);
        let before = DESTROYED.load(Ordering::Relaxed);
        drop(profile);
        assert_eq!(DESTROYED.load(Ordering::Relaxed), before);
        eprintln!("munmap_failure held_slots=1 active_slots=1 credit_reused=0");
    } else {
        assert_eq!(profile.status().soft_memlock_bytes, 143360);
        assert_eq!(profile.status().hard_memlock_bytes, 143360);
        assert!(releases[..len].iter().all(|r| r.result == 0));
        assert_eq!(profile.status().active_slots, 0);
        drop(profile.claim(&original).unwrap());
        let (evidence, caps) = inputs(1, native, 0);
        assert!(matches!(
            NodeLockProfile::new(evidence, caps, native),
            Err(Error::NativeAdmission)
        ));
        drop(profile);
        let (evidence, caps) = inputs(1, native, 0);
        assert!(matches!(
            NodeLockProfile::new(evidence, caps, native),
            Err(Error::NativeAdmission)
        ));
        eprintln!(
            "memlock_exact soft=143360 hard=143360 maps=5 locked=143360 slots=1 startup_instances=1"
        );
    }
}

#[test]
fn existing_locked_owner_requires_explicit_bound_diagnostic_is_not_audit() {
    let native = native();
    let cancelled = AtomicBool::new(false);
    let original = control(&cancelled);
    let other = super::super::slab::Slab::new(32, true, &original).unwrap();
    let actual = locked_diagnostic().unwrap();
    assert!(actual >= 4096);
    let (evidence, caps) = inputs(1, native, 0);
    assert!(matches!(
        NodeLockProfile::fixture(evidence, caps, native),
        Err(Error::NativeAdmission)
    ));
    let (evidence, caps) = inputs(1, native, actual);
    let profile = NodeLockProfile::fixture(evidence, caps, native).unwrap();
    assert_eq!(profile.status().startup_vmlck_bytes, actual);
    assert_eq!(profile.status().charged_locked_bytes, actual);
    let workspace =
        Workspace::new_with_ticket(profile.claim(&original).unwrap(), native, &original).unwrap();
    assert_eq!(profile.status().charged_locked_bytes, actual + 143360);
    drop(workspace);
    drop(other);
    assert_eq!(profile.status().active_slots, 0);
}
#[test]
fn reduced_software_budget_and_control_stop_refuse_without_mapping() {
    let native = native();
    let (evidence, mut caps) = inputs(1, native, locked_diagnostic().unwrap());
    caps.software_bytes -= 1;
    let observation = Observation::begin();
    assert!(matches!(
        NodeLockProfile::fixture(evidence, caps, native),
        Err(Error::NativeAdmission)
    ));
    let profile = profile(1, native);
    let cancelled = AtomicBool::new(true);
    let stopped = control(&cancelled);
    let (_, calls, bytes) =
        measure(|| assert!(matches!(profile.claim(&stopped), Err(Error::Cancelled))));
    assert_eq!((calls, bytes), (0, 0));
    assert_eq!(observation.attempts(), 0);
}

fn point() -> super::super::FreshPoint {
    super::super::FreshPoint {
        job: 1,
        snapshot: 1,
        certificate: [1; 32],
    }
}
fn grant(control: &Control<'_>) -> super::super::Grant<'static> {
    use super::super::{Attenuation, EnvelopeFields, Grant, KeyFields, Phase};
    let key = KeyFields {
        domain: "domain",
        id: "id",
        name: "tokens",
        algorithm: "Ed25519",
        declaration_algorithm: "Ed25519",
        binding_usages: &["verify"],
        declaration_usages: &["verify"],
        version: 1,
        active_version: 1,
        revoked: false,
        retired: false,
        envelope: Some(EnvelopeFields {
            provider: "mounted",
            wrapping_id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            wrapped_dek: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            wrapping_nonce: "AAAAAAAAAAAAAAAA",
            ciphertext: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            nonce: "AAAAAAAAAAAAAAAA",
        }),
    };
    unsafe {
        Grant::from_trusted_capture(
            key,
            Attenuation {
                phase: Phase::FreshAuthentication,
                definition: "$flower.authorize",
                authentication_key: Some("tokens"),
                signing_keys: &[],
            },
            point(),
            control,
        )
    }
    .unwrap()
}

#[test]
fn original_control_identity_survives_move_but_not_reused_address() {
    let native = native();
    let profile = profile(1, native);
    let cancelled = AtomicBool::new(false);
    let original = control(&cancelled);
    let ticket = profile.claim(&original).unwrap();
    let moved = original;
    drop(Workspace::new_with_ticket(ticket, native, &moved).unwrap());
    assert_eq!(profile.status().active_slots, 0);
    let mut storage = std::mem::MaybeUninit::new(control(&cancelled));
    let address = storage.as_ptr() as usize;
    let (ticket, deadline, old_identity) = {
        let original = unsafe { storage.assume_init_ref() };
        (
            profile.claim(original).unwrap(),
            original.deadline,
            original.identity,
        )
    };
    unsafe {
        storage.assume_init_drop();
    }
    // Same address, same cancellation flag, same original deadline and work:
    // still a DIFFERENT stop/budget owner, never an admission retry reset.
    storage.write(Control::new(&cancelled, deadline, 64 * 1024 * 1024).unwrap());
    assert_eq!(storage.as_ptr() as usize, address);
    let replacement = unsafe { storage.assume_init_ref() };
    assert_ne!(replacement.identity, old_identity);
    let observation = Observation::begin();
    assert!(matches!(
        Workspace::new_with_ticket(ticket, native, replacement),
        Err(Error::NativeAdmission)
    ));
    assert_eq!(observation.attempts(), 0);
    assert_eq!(profile.status().active_slots, 0);
    unsafe {
        storage.assume_init_drop();
    }
}

#[test]
fn fatal_node_hold_refuses_even_when_slot_count_has_room() {
    let native = native();
    let profile = profile(1, native);
    let cancelled = AtomicBool::new(false);
    let original = control(&cancelled);
    let ticket = profile.claim(&original).unwrap();
    // Test-only state injection isolates the fatal-node gate from slot-full;
    // actual munmap failure/credit retention is independently fork-tested.
    profile.owner.inner().held.store(1, Ordering::Release);
    let observation = Observation::begin();
    assert!(matches!(
        Workspace::new_with_ticket(ticket, native, &original),
        Err(Error::NativeAdmission)
    ));
    assert_eq!(profile.status().active_slots, 0);
    assert!(matches!(
        profile.claim(&original),
        Err(Error::NativeAdmission)
    ));
    assert_eq!(observation.attempts(), 0);
}
