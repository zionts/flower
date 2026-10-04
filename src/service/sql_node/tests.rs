use super::*;
use crate::service::admission::Class;
use std::{mem::size_of, task::Poll};

fn config() -> AdmissionConfig {
    // Keep the actual 432 MiB SQL blanket job contract; no cheap terminal job.
    let per_job = 432 * 1024 * 1024;
    AdmissionConfig {
        workers: [2, 1, 1],
        memory: [per_job + NODE_BASELINE_BYTES, per_job, per_job],
        input: [4096, 4096, 4096],
        per_job,
    }
}
fn node() -> NodeAdmission {
    NodeAdmission::prepare(config(), NodeLimits::default()).unwrap()
}

#[test]
fn one_worker_default_refused_before_native_or_heap_allocation() {
    let mut config = config();
    config.workers[0] = 1;
    config.memory[0] = config.per_job;
    let (result, operations, bytes) =
        crate::allocation_probe::measure(|| NodeAdmission::prepare(config, NodeLimits::default()));
    assert_eq!((operations, bytes), (0, 0));
    let error = result.err().unwrap();
    assert_eq!(
        error,
        NodeResourceError::InsufficientUserMemory {
            configured: config.per_job,
            per_job: config.per_job
        }
    );
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("FLOWER_PREPARATION_MEMORY_BYTES=452984832"));
    assert!(diagnostic.contains("16777216-byte"));
    assert!(diagnostic.contains("one-worker default is insufficient"));
    let too_small = AdmissionConfig {
        memory: [
            config.per_job + NODE_BASELINE_BYTES - 1,
            config.per_job,
            config.per_job,
        ],
        ..config
    };
    assert_eq!(
        NodeAdmission::prepare(too_small, NodeLimits::default()).err(),
        Some(NodeResourceError::InsufficientUserMemory {
            configured: too_small.memory[0],
            per_job: config.per_job
        })
    );
}

#[test]
fn exact_minimum_carves_user_only_without_capacity_or_default_rewrite() {
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
    assert_eq!(metrics["allocatorBacking"], "HOLD");
    assert!(metrics["construction"].as_str().unwrap().contains("HOLD"));
    for (i, bytes) in carved.memory.into_iter().enumerate() {
        assert_eq!(
            node.admission().metrics()["classes"][i]["memoryBudgetBytes"],
            bytes
        );
    }
}

#[test]
fn hard_limits_can_only_be_lowered_before_construction() {
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
        let (result, operations, bytes) =
            crate::allocation_probe::measure(|| NodeAdmission::prepare(config(), invalid));
        assert_eq!(result.err(), Some(NodeResourceError::InvalidLimits));
        assert_eq!((operations, bytes), (0, 0));
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
    assert_eq!(node.remaining_registry_limits().unwrap().1, 2);
}

#[test]
fn exact_native_ledger_inline_lease_and_real_arc_allocation_layout() {
    let layout = AllocationLayout::native().unwrap();
    assert_eq!(layout.page_bytes, 4096);
    assert_eq!(layout.control_mapped_bytes, 4096);
    assert_eq!(layout.control_layout, Layout::new::<Control>());
    assert_eq!(
        layout.associated_lease_layout,
        Layout::new::<BaselineLease>()
    );
    assert_eq!(
        layout.associated_lease_layout.size(),
        size_of::<BaselineLease>()
    );
    let (node, operations, bytes) = crate::allocation_probe::measure(node);
    // REAL Pool::with_deployment, not a mock pool/fabricated allocator count.
    assert_eq!(operations, 1);
    assert_eq!(bytes, layout.admission_arc_requested_layout.size());
    assert_eq!(node.metrics()["admissionArcRequestedBytes"], bytes);
    assert_eq!(
        node.remaining_registry_limits().unwrap(),
        (
            NODE_BASELINE_BYTES - layout.control_mapped_bytes - bytes,
            MAX_REGISTRY_CELLS
        )
    );
    eprintln!(
        "native node layout: control={} align={} map={} PoolArcRequested={} align={} sourceInlineLease={} align={}",
        layout.control_layout.size(),
        layout.control_layout.align(),
        layout.control_mapped_bytes,
        layout.admission_arc_requested_layout.size(),
        layout.admission_arc_requested_layout.align(),
        layout.associated_lease_layout.size(),
        layout.associated_lease_layout.align()
    );
}

#[test]
fn actual_mapping_is_written_resident_not_an_mlock_or_kernel_proof() {
    let node = node();
    let mut resident = [0u8; 1];
    assert_eq!(
        unsafe {
            libc::mincore(
                node.owner.0.as_ptr().cast(),
                node.owner.control().control_mapped_bytes,
                resident.as_mut_ptr(),
            )
        },
        0
    );
    assert_eq!(resident[0] & 1, 1);
    assert_eq!(node.metrics()["allocatorBacking"], "HOLD");
}

#[test]
fn actual_region_offsets_and_all_layout_overflows_refuse() {
    assert_eq!(region_page_bytes(4096, 4096, 4096), Ok(4096));
    assert_eq!(region_page_bytes(4097, 4096, 4096), Ok(8192));
    assert_eq!(region_page_bytes(4096 + 4095, 1, 4096), Ok(4096));
    // Arithmetic only: the cancellation owner's actual static address is HOLD.
    assert_eq!(region_page_bytes(4096, 38_944, 4096), Ok(40_960));
    assert_eq!(region_page_bytes(4096 + 4088, 38_944, 4096), Ok(45_056));
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
fn handles_share_real_baseline_and_admission_without_heap_allocations() {
    let node = node();
    let (other, operations, bytes) = crate::allocation_probe::measure(|| node.try_clone().unwrap());
    assert_eq!((operations, bytes), (0, 0));
    assert_eq!(node.owner.0, other.owner.0);
    assert!(Arc::ptr_eq(&node.admission(), &other.admission()));
    let (ticket, operations, bytes) =
        crate::allocation_probe::measure(|| other.reserve_native_constant(4096).unwrap());
    assert_eq!((operations, bytes), (0, 0));
    assert!(Arc::ptr_eq(&ticket.admission, &node.admission()));
    assert_eq!(ticket.owner.0, node.owner.0);
    assert_eq!(node.metrics()["nativeConstantReservedBytes"], 4096);
    drop(ticket);
    assert_eq!(node.metrics()["nativeConstantReservedBytes"], 0);
}

#[tokio::test]
async fn two_handles_cold_warm_partition_lanes_share_capacity_and_fair_controls() {
    let node = node();
    let replica_two = node.try_clone().unwrap();
    let partition_cold = replica_two.try_clone().unwrap();
    let partition_warm = partition_cold.try_clone().unwrap();
    let one = node.admission();
    let two = replica_two.admission();
    let cold = partition_cold.admission();
    let warm = partition_warm.admission();
    for handle in [&two, &cold, &warm] {
        assert!(Arc::ptr_eq(&one, handle));
    }
    let first = one
        .acquire("replica-one/root".into(), Class::User, 100)
        .await
        .unwrap();
    let mut next = Box::pin(two.acquire("replica-two/root".into(), Class::User, 100));
    let mut later = Box::pin(cold.acquire("replica-two/partition".into(), Class::User, 100));
    assert!(matches!(futures_util::poll!(&mut next), Poll::Pending));
    assert!(matches!(futures_util::poll!(&mut later), Poll::Pending));
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
    let next = next.await.unwrap();
    assert!(matches!(futures_util::poll!(&mut later), Poll::Pending));
    drop(next);
    drop(later.await.unwrap());
    drop(control);
    drop(deployment);
    for i in 0..3 {
        assert_eq!(one.metrics()["classes"][i]["active"], 0);
    }
    // This admission-lane test does NOT construct two physical Store/Consensus
    // instances or a serving router. Their mandatory resource APIs are HOLD.
}

#[test]
fn constants_and_one_source_mapping_share_total_without_second_pool_or_reset() {
    let node = node();
    let (before, cells) = node.remaining_registry_limits().unwrap();
    let native = node.reserve_native_constant(3 * 4096).unwrap();
    assert_eq!(
        node.remaining_registry_limits().unwrap(),
        (before - 3 * 4096, cells)
    );
    let unrounded = node.remaining_registry_limits().unwrap().0;
    let available = unrounded / 4096 * 4096;
    let tail = unrounded - available;
    let tail_ticket = (tail > 0).then(|| node.reserve_native_constant(tail).unwrap());
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
    assert_eq!(node.metrics()["registryMappedReservedBytes"], available);
    assert_eq!(
        node.reserve_registry_mapping(4096, 1).err(),
        Some(NodeResourceError::RegistryAlreadyIssued)
    );
    assert_eq!(
        node.reserve_native_constant(1).err(),
        Some(NodeResourceError::BaselineExhausted)
    );
    drop(ticket);
    assert_eq!(node.metrics()["registryMappedReservedBytes"], 0);
    assert_eq!(node.metrics()["registryReservedCells"], 0);
    assert_eq!(
        node.reserve_registry_mapping(4096, 1).err(),
        Some(NodeResourceError::RegistryAlreadyIssued)
    );
    assert_eq!(
        node.remaining_registry_limits(),
        Err(NodeResourceError::RegistryAlreadyIssued)
    );
    drop(tail_ticket);
    drop(native);
    assert_eq!(node.metrics()["baselineReservedBytes"], NODE_BASELINE_BYTES);
}

#[test]
fn native_mapping_unmaps_before_ticket_and_baseline_final_drop() {
    struct ActualMapping {
        pointer: NonNull<libc::c_void>,
        bytes: usize,
        ticket: BaselineLease,
    }
    impl Drop for ActualMapping {
        fn drop(&mut self) {
            assert_eq!(
                unsafe { libc::munmap(self.pointer.as_ptr(), self.bytes) },
                0
            );
            // Final cleanup still holds the prepaid charge after actual unmap.
            assert_eq!(
                self.ticket
                    .owner
                    .control()
                    .accounting
                    .lock()
                    .unwrap()
                    .registry_bytes,
                self.bytes
            );
            assert_eq!(Arc::strong_count(&self.ticket.admission), 1);
        }
    }
    let node = node();
    let ticket = node.reserve_registry_mapping(4096, 1).unwrap();
    let ledger = node.owner.0.as_ptr().cast::<libc::c_void>();
    let ledger_bytes = node.owner.control().control_mapped_bytes;
    let pointer = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(pointer, libc::MAP_FAILED);
    let pointer = NonNull::new(pointer).unwrap();
    unsafe {
        std::ptr::write_volatile(pointer.as_ptr().cast::<u8>(), 1);
    }
    let retained = ActualMapping {
        pointer,
        bytes: 4096,
        ticket,
    };
    drop(node);
    let mut resident = [0u8; 1];
    assert_eq!(
        unsafe { libc::mincore(ledger, ledger_bytes, resident.as_mut_ptr()) },
        0
    );
    assert_eq!(
        retained
            .ticket
            .owner
            .control()
            .owners
            .load(Ordering::Acquire),
        1
    );
    assert_eq!(
        retained.ticket.admission.metrics()["classes"][0]["memoryBudgetBytes"],
        config().per_job
    );
    drop(retained);
    // Run serially: no new mappings intervene between final Drop and mincore.
    assert_eq!(
        unsafe { libc::mincore(pointer.as_ptr(), 4096, resident.as_mut_ptr()) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOMEM)
    );
    assert_eq!(
        unsafe { libc::mincore(ledger, ledger_bytes, resident.as_mut_ptr()) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOMEM)
    );
}

#[test]
fn overflow_and_too_small_native_limits_refuse_before_allocating() {
    for config in [
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
    ] {
        let (result, operations, bytes) = crate::allocation_probe::measure(|| {
            NodeAdmission::prepare(config, NodeLimits::default())
        });
        assert!(result.is_err());
        assert_eq!((operations, bytes), (0, 0));
    }
    let limits = NodeLimits {
        registry_bytes: 1,
        ..NodeLimits::default()
    };
    let (result, operations, bytes) =
        crate::allocation_probe::measure(|| NodeAdmission::prepare(config(), limits));
    assert_eq!(result.err(), Some(NodeResourceError::BaselineExhausted));
    assert_eq!((operations, bytes), (0, 0));
    let node = node();
    assert_eq!(
        node.reserve_native_constant(usize::MAX).err(),
        Some(NodeResourceError::BaselineExhausted)
    );
    let a = node.reserve_native_constant(4096).unwrap();
    assert_eq!(
        node.reserve_native_constant(usize::MAX).err(),
        Some(NodeResourceError::LayoutOverflow)
    );
    drop(a);
}

#[test]
fn poisoned_metrics_are_unknown_not_zero_and_do_not_admit_or_credit() {
    let node = node();
    let ticket = node.reserve_native_constant(4096).unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _lock = node.owner.control().accounting.lock().unwrap();
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
        .control()
        .accounting
        .lock()
        .err()
        .unwrap()
        .into_inner();
    assert_eq!(poisoned.native_constant_bytes, 4096);
}

#[test]
fn native_owner_and_inline_lease_are_send_sync_static() {
    fn require<T: Send + Sync + 'static>() {}
    require::<NodeAdmission>();
    require::<BaselineLease>();
}
