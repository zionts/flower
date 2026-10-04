//! Isolated lab diagnostic ELF, never the serving Flower constructor.
#![allow(dead_code)]
mod sqlite {
    include!(concat!(env!("OUT_DIR"), "/error.rs"));
}
#[path = "../../sql_control.rs"]
mod sql_control;
#[path = "../../sql_worker.rs"]
mod sql_worker;
use sql_worker::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
#[cfg(feature = "mimalloc-probe")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
static SLOT: AtomicBool = AtomicBool::new(false);
static RELEASED: AtomicBool = AtomicBool::new(false);
struct LabOnlyLease;
// UNSAFE LAB ATTESTATION ONLY, no real node/job/physical/native backing owner.
unsafe impl NativeLease for LabOnlyLease {
    fn mapping_ids(&self) -> [u64; 2] {
        [1, 2]
    }
}
impl Drop for LabOnlyLease {
    fn drop(&mut self) {
        assert!(SLOT.swap(false, Ordering::SeqCst));
        RELEASED.store(true, Ordering::SeqCst);
    }
}
struct LabOnlyOwner;
unsafe impl NativeOwner for LabOnlyOwner {
    type Lease = LabOnlyLease;
    fn immutable_worker_ceiling(&self) -> usize {
        1
    }
    fn native_gate(&self, _: &WorkerLayout) -> Result<(), Hold> {
        Ok(())
    }
    fn admit(
        &self,
        _: &WorkerLayout,
        _: &sql_control::JobControl,
    ) -> Result<Self::Lease, WorkerError> {
        if SLOT.swap(true, Ordering::SeqCst) {
            return Err(WorkerError::Busy);
        }
        Ok(LabOnlyLease)
    }
}
struct NoSource;
unsafe impl TrustedCaptureTask for NoSource {
    fn run(
        self,
        original: &mut sql_control::JobControl,
        _: StackExtentReady,
    ) -> Result<(), WorkerError> {
        original.check().map_err(Into::into)
    }
}
#[repr(C)]
#[derive(Default)]
struct Counts {
    calls: [u64; 7],
    requested_bytes: u64,
    requests: [u64; 16],
}
fn main() {
    // Resolve diagnostic symbols BEFORE measurement and before pthread_create.
    // No std thread, Tokio handle, source/Consensus/fence or guest is created.
    let begin = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"flower_worker_probe_begin".as_ptr()) };
    let read = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"flower_worker_probe_read".as_ptr()) };
    let end = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"flower_worker_probe_end".as_ptr()) };
    if begin.is_null() || read.is_null() || end.is_null() {
        eprintln!("code=DIAGNOSTIC_INTERPOSER_REQUIRED");
        std::process::exit(2);
    }
    let begin = unsafe { std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn()>(begin) };
    let read = unsafe {
        std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(*mut Counts)>(read)
    };
    let end = unsafe { std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn()>(end) };
    let owner = LabOnlyOwner;
    let factory = WorkerFactory::new(&owner).unwrap();
    let spec = StackSpec {
        usable_bytes: 2 * 1024 * 1024,
    };
    let layout = factory.layout::<NoSource>(spec).unwrap();
    let original =
        sql_control::JobControl::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false)))
            .unwrap();
    let mut startup = Counts::default();
    unsafe {
        begin();
    }
    let mut worker = factory
        .start::<NoSource>(spec, original, WorkerBootstrap::InspectOwnedStack)
        .unwrap();
    unsafe {
        read(&mut startup);
        end();
    }
    let mut joined = Counts::default();
    unsafe {
        begin();
    }
    worker
        .source_enrollment()
        .unwrap()
        .original
        .check()
        .unwrap();
    worker.submit(NoSource).unwrap();
    let completion = worker.join().unwrap();
    unsafe {
        read(&mut joined);
        end();
    }
    assert_eq!(completion.callback, Ok(()));
    assert!(RELEASED.load(Ordering::SeqCst));
    println!(
        "code=COLD_ELF_STARTUP_OBSERVATION calls={:?} requested_bytes={}",
        startup.calls, startup.requested_bytes
    );
    let sample_count =
        (startup.calls[..6].iter().sum::<u64>() as usize).min(startup.requests.len());
    println!(
        "code=COLD_ELF_STARTUP_REQUEST_BYTES samples={:?}",
        &startup.requests[..sample_count]
    );
    println!(
        "code=COLD_ELF_JOIN_OBSERVATION calls={:?} requested_bytes={}",
        joined.calls, joined.requested_bytes
    );
    println!(
        "code=EXACT_LAYOUT page_bytes={} stack_bytes={} guard_each_bytes={} stack_map_bytes={} control_layout_bytes={} control_align={} control_map_bytes={} task_bytes={} lease_bytes={} handle_bytes={} explicit_maps_bytes={}",
        layout.page_bytes,
        layout.stack_bytes,
        layout.guard_bytes_each,
        layout.stack_mapping_bytes,
        layout.control_layout.size(),
        layout.control_layout.align(),
        layout.control_mapping_bytes,
        layout.task_layout.size(),
        layout.lease_layout.size(),
        layout.caller_handle_layout.size(),
        layout.explicit_mapping_bytes
    );
    println!("code=WHOLE_NATIVE_TLS_KERNEL_ASYNC_SOURCE_HOST_HOLD");
}
