use super::*;
use crate::service::admission::Class;
use std::{mem::size_of, task::Poll};

fn config() -> AdmissionConfig {
    // Actual unchanged 432 MiB SQL blanket job, not a cheap terminal job.
    let per_job = 432 * 1024 * 1024;
    AdmissionConfig {
        workers: [2, 1, 1],
        memory: [per_job + NODE_BASELINE_BYTES, per_job, per_job],
        input: [4096, 4096, 4096],
        per_job,
    }
}
fn node() -> &'static NodeAdmission {
    NodeAdmission::prepare(config(), NodeLimits::default()).unwrap()
}
/// ONE real GLOBAL/mmap per isolated OS child. No resetting/replacing statics,
/// no per-test native pools in a shared process, no toy native-ready fixture.
fn isolated(name: &str) -> bool {
    const CHILD: &str = "FLOWER_NODE_K7_NATIVE_TEST";
    let full = format!("service::sql_node::tests::{name}");
    if std::env::var(CHILD).ok().as_deref() == Some(full.as_str()) {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &full, "--nocapture", "--test-threads=1"])
        .env(CHILD, &full)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated real native child {full} failed\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // A misspelled filter must not count as a native positive.
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    false
}

#[test]
fn missing_bootstrap_does_not_create_a_pool() {
    if !isolated("missing_bootstrap_does_not_create_a_pool") {
        return;
    }
    let (result, operations, bytes) = crate::allocation_probe::measure(NodeAdmission::global);
    assert_eq!(result.err(), Some(NodeResourceError::BootstrapMissing));
    assert_eq!((operations, bytes), (0, 0));
    assert!(GLOBAL.result.get().is_none());
    assert!(!GLOBAL.attempted.load(Ordering::Acquire));
}

#[test]
fn one_worker_default_refused_before_allocation_and_failure_never_retries() {
    if !isolated("one_worker_default_refused_before_allocation_and_failure_never_retries") {
        return;
    }
    let mut bad = config();
    bad.workers[0] = 1;
    bad.memory[0] = bad.per_job;
    let (result, operations, bytes) =
        crate::allocation_probe::measure(|| NodeAdmission::prepare(bad, NodeLimits::default()));
    let error = NodeResourceError::InsufficientUserMemory {
        configured: bad.per_job,
        per_job: bad.per_job,
    };
    assert_eq!(result.err(), Some(error));
    assert_eq!((operations, bytes), (0, 0));
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("FLOWER_PREPARATION_MEMORY_BYTES=452984832"));
    assert!(diagnostic.contains("16777216-byte"));
    assert!(diagnostic.contains("one-worker default is insufficient"));
    assert_eq!(NodeAdmission::global().err(), Some(error));
    let (result, operations, bytes) = crate::allocation_probe::measure(|| {
        NodeAdmission::prepare(config(), NodeLimits::default())
    });
    assert_eq!(result.err(), Some(error));
    assert_eq!((operations, bytes), (0, 0));
}

#[test]
fn exact_minimum_carves_user_only_without_capacity_or_default_rewrite() {
    if !isolated("exact_minimum_carves_user_only_without_capacity_or_default_rewrite") {
        return;
    }
    let config = config();
    let carved = config.carved().unwrap();
    assert_eq!(carved.memory[0], config.per_job);
    assert_eq!(carved.memory[1..], config.memory[1..]);
    assert_eq!(carved.workers, config.workers);
    assert_eq!(carved.input, config.input);
    assert_eq!(carved.per_job, config.per_job);
    assert_eq!(config.memory[0], 448 * 1024 * 1024);
    let node = node();
    let metrics = node.metrics();
    assert_eq!(metrics["baselineReservedBytes"], NODE_BASELINE_BYTES);
    assert_eq!(metrics["remainingUserMemoryBytes"], config.per_job);
    assert_eq!(
        metrics["registryMappedReservedBytes"],
        serde_json::Value::Null
    );
    assert_eq!(metrics["registryReservedCells"], serde_json::Value::Null);
    assert_eq!(metrics["nativePhysicalAggregate"], "HOLD");
    assert!(metrics["construction"].as_str().unwrap().contains("HOLD"));
    for (i, bytes) in carved.memory.into_iter().enumerate() {
        assert_eq!(
            node.admission().metrics()["classes"][i]["memoryBudgetBytes"],
            bytes
        );
    }
}

#[test]
fn hard_limits_are_lower_only_and_published_limits_are_immutable() {
    if !isolated("hard_limits_are_lower_only_and_published_limits_are_immutable") {
        return;
    }
    let hard = NodeLimits::default();
    assert_eq!(hard.validate(), Ok(hard));
    let lower = NodeLimits {
        registry_bytes: 64 * 1024,
        registry_cells: 2,
        cancel_slots: 1,
    };
    assert_eq!(lower.validate(), Ok(lower));
    for invalid in [
        NodeLimits {
            registry_bytes: 0,
            ..hard
        },
        NodeLimits {
            registry_bytes: NODE_BASELINE_BYTES + 1,
            ..hard
        },
        NodeLimits {
            registry_cells: 0,
            ..hard
        },
        NodeLimits {
            registry_cells: MAX_REGISTRY_CELLS + 1,
            ..hard
        },
        NodeLimits {
            cancel_slots: 0,
            ..hard
        },
        NodeLimits {
            cancel_slots: MAX_CANCEL_SLOTS + 1,
            ..hard
        },
        NodeLimits {
            registry_bytes: usize::MAX,
            ..hard
        },
    ] {
        assert_eq!(invalid.validate(), Err(NodeResourceError::InvalidLimits));
    }
    let node = NodeAdmission::prepare(config(), lower).unwrap();
    let (bytes, cells) = node.remaining_registry_limits().unwrap();
    assert!(bytes < lower.registry_bytes);
    assert_eq!(cells, 2);
    assert_eq!(node.metrics()["baselineReservedBytes"], NODE_BASELINE_BYTES);
    assert_eq!(
        node.reserve_registry_mapping(4096, 3).err(),
        Some(NodeResourceError::InvalidRegistryReservation)
    );
    assert_eq!(
        NodeAdmission::prepare(config(), hard).err(),
        Some(NodeResourceError::BootstrapMismatch)
    );
    let mut other = config();
    other.workers[0] += 1;
    assert_eq!(
        NodeAdmission::prepare(other, lower).err(),
        Some(NodeResourceError::BootstrapMismatch)
    );
    assert!(std::ptr::eq(
        node,
        NodeAdmission::prepare(config(), lower).unwrap()
    ));
}

#[test]
fn invalid_first_limits_latch_without_native_or_heap_allocation() {
    if !isolated("invalid_first_limits_latch_without_native_or_heap_allocation") {
        return;
    }
    let bad = NodeLimits {
        cancel_slots: MAX_CANCEL_SLOTS + 1,
        ..NodeLimits::default()
    };
    let (result, operations, bytes) =
        crate::allocation_probe::measure(|| NodeAdmission::prepare(config(), bad));
    assert_eq!(result.err(), Some(NodeResourceError::InvalidLimits));
    assert_eq!((operations, bytes), (0, 0));
    assert_eq!(
        NodeAdmission::prepare(config(), NodeLimits::default()).err(),
        Some(NodeResourceError::InvalidLimits)
    );
}

#[test]
fn exact_real_pool_mapping_global_static_and_caller_layouts_zero_arc_allocation() {
    if !isolated("exact_real_pool_mapping_global_static_and_caller_layouts_zero_arc_allocation") {
        return;
    }
    let layout = AllocationLayout::native().unwrap();
    assert_eq!(layout.page_bytes, 4096);
    assert_eq!(layout.pool_layout, Layout::new::<Pool>());
    assert_eq!(layout.control_layout, Layout::new::<Control>());
    assert_eq!(layout.mapping_layout, Layout::new::<NativeMapping>());
    assert_eq!(
        layout.mapped_bytes,
        round_pages(size_of::<NativeMapping>(), layout.page_bytes).unwrap()
    );
    assert_eq!(layout.node_handle_layout, Layout::new::<NodeAdmission>());
    assert_eq!(layout.admission_handle_layout, Layout::new::<Owner>());
    assert_eq!(layout.strong_input_layout, Layout::new::<StrongInput>());
    assert_eq!(
        layout.associated_lease_layout,
        Layout::new::<BaselineLease>()
    );
    let global = layout.bootstrap_region;
    assert_eq!(global.address, std::ptr::from_ref(&GLOBAL).addr());
    assert_eq!(global.layout, Layout::new::<Bootstrap>());
    assert_eq!(global.page_start, global.address & !(layout.page_bytes - 1));
    assert_eq!(global.page_end - global.page_start, global.page_bytes);
    assert_eq!(
        global.page_bytes,
        region_page_bytes(global.address, global.layout.size(), layout.page_bytes).unwrap()
    );
    let (node, operations, bytes) = crate::allocation_probe::measure(node);
    // Actual Pool constructor BY VALUE into the real mmap, not a fake allocator
    // count for a toy pool. The global pointer/ledger are actual native objects.
    assert_eq!((operations, bytes), (0, 0));
    let mapped = std::ptr::from_ref(node.owner).addr();
    let pool = node.admission();
    assert!(matches!(pool, Owner::NativeStatic(_)));
    assert_eq!(std::ptr::from_ref(&*pool).addr(), mapped);
    assert!(
        std::ptr::from_ref(&node.owner.control).addr() + layout.control_layout.size()
            <= mapped + layout.mapped_bytes
    );
    assert!(global.address <= std::ptr::from_ref(node).addr());
    assert!(
        std::ptr::from_ref(node).addr() + size_of::<NodeAdmission>()
            <= global.address + global.layout.size()
    );
    assert_eq!(
        node.remaining_registry_limits().unwrap(),
        (
            NODE_BASELINE_BYTES - layout.mapped_bytes - global.page_bytes,
            MAX_REGISTRY_CELLS
        )
    );
    eprintln!(
        "native mapped layout: Pool={}/{} Control={}/{} mapping={}/{} mapped={} NodeInline={}/{} OwnerInline={}/{} StrongInput={}/{} SourceLease={}/{} GLOBALaddr={:#x} GLOBAL={}/{} GLOBALpageStart={:#x} GLOBALpages={} mapaddr={:#x}",
        layout.pool_layout.size(),
        layout.pool_layout.align(),
        layout.control_layout.size(),
        layout.control_layout.align(),
        layout.mapping_layout.size(),
        layout.mapping_layout.align(),
        layout.mapped_bytes,
        layout.node_handle_layout.size(),
        layout.node_handle_layout.align(),
        layout.admission_handle_layout.size(),
        layout.admission_handle_layout.align(),
        layout.strong_input_layout.size(),
        layout.strong_input_layout.align(),
        layout.associated_lease_layout.size(),
        layout.associated_lease_layout.align(),
        global.address,
        global.layout.size(),
        global.layout.align(),
        global.page_start,
        global.page_bytes,
        mapped
    );
}

#[test]
fn concurrent_startup_attempts_share_one_real_cold_native_owner() {
    if !isolated("concurrent_startup_attempts_share_one_real_cold_native_owner") {
        return;
    }
    let barrier = std::sync::Barrier::new(4);
    let addresses = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    let (node, operations, bytes) = crate::allocation_probe::measure(|| {
                        NodeAdmission::prepare(config(), NodeLimits::default()).unwrap()
                    });
                    assert_eq!((operations, bytes), (0, 0));
                    std::ptr::from_ref(node.owner).addr()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(addresses.iter().all(|address| *address == addresses[0]));
    assert_eq!(
        std::ptr::from_ref(NodeAdmission::global().unwrap().owner).addr(),
        addresses[0]
    );
}

#[test]
fn reservation_overflow_and_bad_source_layouts_leave_actual_ledger_unchanged() {
    if !isolated("reservation_overflow_and_bad_source_layouts_leave_actual_ledger_unchanged") {
        return;
    }
    let node = node();
    let before = node.remaining_registry_limits().unwrap();
    for (bytes, cells) in [(0, 1), (4095, 1), (4096, 0), (4096, MAX_REGISTRY_CELLS + 1)] {
        assert_eq!(
            node.reserve_registry_mapping(bytes, cells).err(),
            Some(NodeResourceError::InvalidRegistryReservation)
        );
    }
    assert_eq!(
        node.reserve_native_constant(0).err(),
        Some(NodeResourceError::InvalidRegistryReservation)
    );
    assert_eq!(
        node.reserve_native_constant(usize::MAX).err(),
        Some(NodeResourceError::BaselineExhausted)
    );
    assert_eq!(node.remaining_registry_limits().unwrap(), before);
    let ticket = node.reserve_native_constant(4096).unwrap();
    assert_eq!(
        node.reserve_native_constant(usize::MAX).err(),
        Some(NodeResourceError::LayoutOverflow)
    );
    assert_eq!(node.remaining_registry_limits().unwrap().0, before.0 - 4096);
    drop(ticket);
    assert_eq!(node.remaining_registry_limits().unwrap().0, before.0 - 4096);
}

#[test]
fn actual_mapping_pretouched_and_remains_after_every_caller_drop() {
    if !isolated("actual_mapping_pretouched_and_remains_after_every_caller_drop") {
        return;
    }
    let (pointer, layout) = {
        let node = node().try_clone().unwrap();
        let pool = node.admission();
        assert!(pool.ptr_eq(&node.admission()));
        let pointer = std::ptr::from_ref(node.owner).cast::<libc::c_void>();
        (pointer, node.allocation_layout())
    };
    let mut resident = [0u8; 8];
    assert!(layout.mapped_bytes / layout.page_bytes <= resident.len());
    assert_eq!(
        unsafe {
            libc::mincore(
                pointer.cast_mut(),
                layout.mapped_bytes,
                resident.as_mut_ptr(),
            )
        },
        0
    );
    for page in &resident[..layout.mapped_bytes / layout.page_bytes] {
        assert_eq!(page & 1, 1);
    }
    let node = NodeAdmission::global().unwrap();
    assert_eq!(
        std::ptr::from_ref(node.owner).cast::<libc::c_void>(),
        pointer
    );
    assert_eq!(
        node.admission().metrics()["classes"][0]["memoryBudgetBytes"],
        config().per_job
    );
    assert_eq!(node.metrics()["nativePhysicalAggregate"], "HOLD");
}

#[test]
fn actual_region_offsets_and_layout_overflows_refuse() {
    assert_eq!(region_page_bytes(4096, 4096, 4096), Ok(4096));
    assert_eq!(region_page_bytes(4097, 4096, 4096), Ok(8192));
    assert_eq!(region_page_bytes(4096 + 4095, 1, 4096), Ok(4096));
    for (address, bytes, page) in [
        (usize::MAX, 1, 4096),
        (0, usize::MAX, 4096),
        (0, 1, 0),
        (0, 1, 3),
        (0, 0, 4096),
    ] {
        assert_eq!(
            region_page_bytes(address, bytes, page),
            Err(NodeResourceError::LayoutOverflow)
        );
    }
    assert_eq!(
        round_pages(usize::MAX, 4096),
        Err(NodeResourceError::LayoutOverflow)
    );
}

#[test]
fn handles_and_leases_share_actual_permanent_owner_without_allocations_or_refunds() {
    if !isolated("handles_and_leases_share_actual_permanent_owner_without_allocations_or_refunds") {
        return;
    }
    let node = node();
    let (other, operations, bytes) = crate::allocation_probe::measure(|| node.try_clone().unwrap());
    assert_eq!((operations, bytes), (0, 0));
    assert!(std::ptr::eq(node.owner, other.owner));
    let (pool, operations, bytes) = crate::allocation_probe::measure(|| other.admission());
    assert_eq!((operations, bytes), (0, 0));
    assert!(pool.ptr_eq(&node.admission()));
    let (before, _) = node.remaining_registry_limits().unwrap();
    let (ticket, operations, bytes) =
        crate::allocation_probe::measure(|| other.reserve_native_constant(4096).unwrap());
    assert_eq!((operations, bytes), (0, 0));
    assert!(ticket.admission().ptr_eq(&node.admission()));
    assert!(std::ptr::eq(ticket.owner, node.owner));
    assert!(!ticket.is_registry_mapping());
    assert_eq!(ticket.allocation_layout(), node.allocation_layout());
    drop(ticket);
    assert_eq!(node.metrics()["nativeConstantReservedBytes"], 4096);
    assert_eq!(node.remaining_registry_limits().unwrap().0, before - 4096);
}

#[tokio::test]
async fn real_pool_fifo_shared_partition_lanes_and_control_deployment_capacity() {
    if !isolated("real_pool_fifo_shared_partition_lanes_and_control_deployment_capacity") {
        return;
    }
    let node = node();
    let other = node.try_clone().unwrap();
    let one = node.admission();
    let two = other.admission();
    let cold = other.try_clone().unwrap().admission();
    let warm = cold.clone();
    for handle in [&two, &cold, &warm] {
        assert!(one.ptr_eq(handle));
    }
    let first = one
        .acquire("busy/root".into(), Class::User, 100)
        .await
        .unwrap();
    let mut a = Box::pin(two.acquire("a".into(), Class::User, 100));
    let mut a2 = Box::pin(cold.acquire("a".into(), Class::User, 100));
    let mut b = Box::pin(warm.acquire("b".into(), Class::User, 100));
    assert!(matches!(futures_util::poll!(&mut a), Poll::Pending));
    assert!(matches!(futures_util::poll!(&mut a2), Poll::Pending));
    assert!(matches!(futures_util::poll!(&mut b), Poll::Pending));
    let control = cold
        .acquire("partition/control".into(), Class::Control, 100)
        .await
        .unwrap();
    let deployment = warm
        .acquire("partition/deployment".into(), Class::Deployment, 100)
        .await
        .unwrap();
    for i in 0..3 {
        assert_eq!(one.metrics()["classes"][i]["active"], 1);
    }
    drop(first);
    let a = a.await.unwrap();
    assert!(matches!(futures_util::poll!(&mut b), Poll::Pending));
    drop(a);
    let b = b.await.unwrap();
    assert!(matches!(futures_util::poll!(&mut a2), Poll::Pending));
    drop(b);
    drop(a2.await.unwrap());
    drop(control);
    drop(deployment);
    for i in 0..3 {
        assert_eq!(one.metrics()["classes"][i]["active"], 0);
    }
    assert_eq!(one.metrics()["classes"][0]["retainedInputBytes"], 0);
    // Actual admission lanes, NOT two physical Store/router/native SQL proof.
}

#[test]
fn strong_metadata_lease_keeps_native_pool_and_charge_until_final_owner_drop() {
    if !isolated("strong_metadata_lease_keeps_native_pool_and_charge_until_final_owner_drop") {
        return;
    }
    let pool = node().admission();
    let (retained, operations, bytes) =
        crate::allocation_probe::measure(|| pool.retain_strong(Class::User, 777).unwrap());
    assert_eq!((operations, bytes), (0, 0));
    // Native writer metadata can Arc its Basis; this tests the REAL opaque
    // retained charge, not a fake Basis/Consensus constructor.
    let metadata = std::sync::Arc::new(retained);
    let queued = metadata.clone();
    drop(pool);
    drop(metadata);
    let pool = NodeAdmission::global().unwrap().admission();
    assert_eq!(pool.metrics()["classes"][0]["retainedInputBytes"], 777);
    drop(queued);
    assert_eq!(pool.metrics()["classes"][0]["retainedInputBytes"], 0);
    assert!(matches!(pool, Owner::NativeStatic(_)));
}

#[test]
fn constants_and_single_source_mapping_share_total_without_reset_or_fake_cleanup_credit() {
    if !isolated(
        "constants_and_single_source_mapping_share_total_without_reset_or_fake_cleanup_credit",
    ) {
        return;
    }
    let node = node();
    let (before, cells) = node.remaining_registry_limits().unwrap();
    let native = node.reserve_native_constant(3 * 4096).unwrap();
    assert_eq!(
        node.remaining_registry_limits().unwrap(),
        (before - 3 * 4096, cells)
    );
    let available = node.remaining_registry_limits().unwrap().0;
    assert!(available.is_multiple_of(4096));
    assert_eq!(
        node.reserve_registry_mapping(available + 1, cells).err(),
        Some(NodeResourceError::InvalidRegistryReservation)
    );
    let (result, operations, bytes) =
        crate::allocation_probe::measure(|| node.reserve_registry_mapping(available + 4096, cells));
    assert_eq!(result.err(), Some(NodeResourceError::BaselineExhausted));
    assert_eq!((operations, bytes), (0, 0));
    let ticket = node.reserve_registry_mapping(available, cells).unwrap();
    assert_eq!(ticket.reserved_bytes(), available);
    assert_eq!(ticket.reserved_cells(), cells);
    assert!(ticket.is_registry_mapping());
    assert_eq!(
        node.reserve_registry_mapping(4096, 1).err(),
        Some(NodeResourceError::RegistryAlreadyIssued)
    );
    assert_eq!(
        node.reserve_native_constant(1).err(),
        Some(NodeResourceError::BaselineExhausted)
    );
    drop(ticket);
    drop(native);
    // Untyped cleanup is NOT a refund. Source cap can never be recreated.
    assert_eq!(node.metrics()["registryMappedReservedBytes"], available);
    assert_eq!(node.metrics()["registryReservedCells"], cells);
    assert_eq!(node.metrics()["nativeConstantReservedBytes"], 3 * 4096);
    assert_eq!(
        node.reserve_registry_mapping(4096, 1).err(),
        Some(NodeResourceError::RegistryAlreadyIssued)
    );
    assert_eq!(
        node.remaining_registry_limits(),
        Err(NodeResourceError::RegistryAlreadyIssued)
    );
}

#[test]
fn overflow_and_too_small_native_limits_preflight_refuse() {
    if !isolated("overflow_and_too_small_native_limits_preflight_refuse") {
        return;
    }
    // Pure config preflight; multiple invalid configs do NOT reset GLOBAL.
    for bad in [
        AdmissionConfig {
            per_job: 0,
            ..config()
        },
        AdmissionConfig {
            workers: [0, 1, 1],
            ..config()
        },
        AdmissionConfig {
            input: [0, 4096, 4096],
            ..config()
        },
        AdmissionConfig {
            memory: [usize::MAX; 3],
            per_job: usize::MAX,
            ..config()
        },
        AdmissionConfig {
            memory: [
                config().memory[0] - 1,
                config().memory[1],
                config().memory[2],
            ],
            ..config()
        },
    ] {
        assert!(bad.carved().is_err());
    }
    let limits = NodeLimits {
        registry_bytes: 1,
        ..NodeLimits::default()
    };
    let (result, operations, bytes) =
        crate::allocation_probe::measure(|| NodeAdmission::prepare(config(), limits));
    assert_eq!(result.err(), Some(NodeResourceError::BaselineExhausted));
    assert_eq!((operations, bytes), (0, 0));
    assert_eq!(
        NodeAdmission::prepare(config(), NodeLimits::default()).err(),
        Some(NodeResourceError::BaselineExhausted)
    );
}

#[test]
fn poisoned_metrics_are_unknown_not_zero_and_do_not_admit_or_credit() {
    if !isolated("poisoned_metrics_are_unknown_not_zero_and_do_not_admit_or_credit") {
        return;
    }
    let node = node();
    let ticket = node.reserve_native_constant(4096).unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _lock = node.owner.control.accounting.lock().unwrap();
        panic!("intentional ledger poison");
    }));
    assert_eq!(
        node.metrics()["nativeConstantReservedBytes"],
        serde_json::Value::Null
    );
    assert_eq!(
        node.metrics()["registryMappedReservedBytes"],
        serde_json::Value::Null
    );
    assert_eq!(
        node.reserve_registry_mapping(4096, 1).err(),
        Some(NodeResourceError::Poisoned)
    );
    assert_eq!(
        node.remaining_registry_limits(),
        Err(NodeResourceError::Poisoned)
    );
    drop(ticket);
    let poisoned = node
        .owner
        .control
        .accounting
        .lock()
        .err()
        .unwrap()
        .into_inner();
    assert_eq!(poisoned.native_constant_bytes, 4096);
}

#[test]
fn native_handles_and_inline_leases_are_send_sync_static() {
    fn require<T: Send + Sync + 'static>() {}
    require::<NodeAdmission>();
    require::<Owner>();
    require::<StrongInput>();
    require::<BaselineLease>();
}
