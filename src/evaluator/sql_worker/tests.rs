//! Isolated fixture proofs only. TestOwner is NOT a production admission proof;
//! SourceOwned is a dummy epoch/drop owner, NOT Consensus/source-GC verification.
use super::*;
use std::{
    sync::{
        Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const SELECTED_TEST_STACK_BYTES: usize = 2 * 1024 * 1024;
#[derive(Default)]
struct Book {
    occupied: AtomicBool,
    issued: AtomicUsize,
    released: AtomicUsize,
    source_created: AtomicUsize,
    source_dropped: AtomicUsize,
    events: Mutex<Vec<NativeEvent>>,
}
struct TestOwner {
    book: Arc<Book>,
    gate: Option<Hold>,
}
impl TestOwner {
    fn fixture() -> Self {
        Self {
            book: Arc::new(Book {
                events: Mutex::new(Vec::with_capacity(128)),
                ..Book::default()
            }),
            gate: None,
        }
    }
    fn events(&self) -> Vec<NativeEvent> {
        self.book.events.lock().unwrap().clone()
    }
}
struct TestLease {
    book: Arc<Book>,
    ids: [u64; 2],
}
// TEST ATTESTATION ONLY. Allocator/TLS/kernel/physical admission is unknown.
unsafe impl NativeLease for TestLease {
    fn mapping_ids(&self) -> [u64; 2] {
        self.ids
    }
    fn observe(&self, event: NativeEvent) {
        self.book.events.lock().unwrap().push(event);
    }
}
impl Drop for TestLease {
    fn drop(&mut self) {
        self.book.released.fetch_add(1, Ordering::SeqCst);
        assert!(self.book.occupied.swap(false, Ordering::SeqCst));
    }
}
unsafe impl NativeOwner for TestOwner {
    type Lease = TestLease;
    fn immutable_worker_ceiling(&self) -> usize {
        1
    }
    fn native_gate(&self, _layout: &WorkerLayout) -> Result<(), Hold> {
        self.gate.map_or(Ok(()), Err)
    }
    fn admit(
        &self,
        _layout: &WorkerLayout,
        original: &JobControl,
    ) -> Result<TestLease, WorkerError> {
        assert!(original.deadline() > original.admitted());
        if self.book.occupied.swap(true, Ordering::SeqCst) {
            return Err(WorkerError::Busy);
        }
        let count = self.book.issued.fetch_add(1, Ordering::SeqCst) as u64;
        Ok(TestLease {
            book: self.book.clone(),
            ids: [count * 2 + 1, count * 2 + 2],
        })
    }
}
fn job() -> JobControl {
    JobControl::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false))).unwrap()
}
fn spec() -> StackSpec {
    StackSpec {
        usable_bytes: SELECTED_TEST_STACK_BYTES,
    }
}
struct NoSource;
unsafe impl TrustedCaptureTask for NoSource {
    fn run(self, original: &mut JobControl, _: StackExtentReady) -> Result<(), WorkerError> {
        original.check().map_err(Into::into)
    }
}
fn start<T: TrustedCaptureTask>(
    owner: &TestOwner,
    original: JobControl,
) -> NativeThread<TestLease, T> {
    WorkerFactory::new(owner)
        .unwrap()
        .start(spec(), original, WorkerBootstrap::InspectOwnedStack)
        .unwrap()
}
#[test]
fn layout_is_actual_page_rounded_and_task_lease_are_inline() {
    let owner = TestOwner::fixture();
    let factory = WorkerFactory::new(&owner).unwrap();
    let layout = factory
        .layout::<NoSource>(StackSpec {
            usable_bytes: SELECTED_TEST_STACK_BYTES + 1,
        })
        .unwrap();
    assert_eq!(layout.task_layout, Layout::new::<NoSource>());
    assert_eq!(layout.lease_layout, Layout::new::<TestLease>());
    assert_eq!(
        layout.caller_handle_layout,
        Layout::new::<NativeThread<TestLease, NoSource>>()
    );
    assert_eq!(
        layout.stack_bytes,
        SELECTED_TEST_STACK_BYTES + layout.page_bytes
    );
    assert_eq!(
        layout.stack_mapping_bytes,
        layout.stack_bytes + 2 * layout.page_bytes
    );
    assert_eq!(
        layout.control_mapping_bytes,
        WorkerLayout::round_pages(layout.control_layout.size(), layout.page_bytes).unwrap()
    );
    assert_eq!(
        layout.explicit_mapping_bytes,
        layout.control_mapping_bytes + layout.stack_mapping_bytes
    );
    assert_eq!(layout.control_mapping_bytes % layout.page_bytes, 0);
    assert_eq!(layout.stack_bytes % layout.page_bytes, 0);
}
#[test]
fn zero_small_overflow_and_bad_page_refuse_before_native_start() {
    let owner = TestOwner::fixture();
    let factory = WorkerFactory::new(&owner).unwrap();
    for n in [0, 1, libc::PTHREAD_STACK_MIN - 1] {
        assert!(
            factory
                .layout::<NoSource>(StackSpec { usable_bytes: n })
                .is_err()
        );
    }
    assert!(matches!(
        factory.layout::<NoSource>(StackSpec {
            usable_bytes: usize::MAX
        }),
        Err(WorkerError::Overflow)
    ));
    assert_eq!(
        WorkerLayout::round_pages(1, 0),
        Err(WorkerError::InvalidLayout)
    );
    assert_eq!(
        WorkerLayout::round_pages(1, 3),
        Err(WorkerError::InvalidLayout)
    );
    assert_eq!(owner.book.issued.load(Ordering::SeqCst), 0);
}
#[test]
fn unknown_native_gate_refuses_before_admission_mapping_and_source() {
    for hold in [
        Hold::NativeOwnerNotInstalled,
        Hold::NativeTlsDtv,
        Hold::AllocatorBacking,
        Hold::KernelThread,
        Hold::AsyncFenceRuntime,
        Hold::SourceCallgraph,
        Hold::WholeHostPhysical,
    ] {
        let mut owner = TestOwner::fixture();
        owner.gate = Some(hold);
        assert!(
            matches!(WorkerFactory::new(&owner).unwrap().start::<NoSource>(spec(), job(), WorkerBootstrap::InspectOwnedStack), Err(WorkerError::Hold(actual)) if actual == hold)
        );
        assert_eq!(owner.book.issued.load(Ordering::SeqCst), 0);
        assert!(owner.events().is_empty());
        assert_eq!(owner.book.source_created.load(Ordering::SeqCst), 0);
    }
}
struct WrongCeiling;
unsafe impl NativeOwner for WrongCeiling {
    type Lease = TestLease;
    fn immutable_worker_ceiling(&self) -> usize {
        2
    }
    fn admit(&self, _: &WorkerLayout, _: &JobControl) -> Result<TestLease, WorkerError> {
        unreachable!()
    }
}
#[test]
fn owner_must_supply_immutable_exact_one_worker_ceiling() {
    assert!(matches!(
        WorkerFactory::new(&WrongCeiling),
        Err(WorkerError::InvalidLayout)
    ));
}
#[test]
fn actual_pthread_extent_readiness_and_permissions_precede_any_task() {
    let owner = TestOwner::fixture();
    let thread = start::<NoSource>(&owner, job());
    let extent = thread.stack_extent_ready().unwrap();
    assert_eq!(extent.stack_bytes, SELECTED_TEST_STACK_BYTES);
    assert_eq!(extent.native_reported_guard_bytes, 0);
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    fn permission(maps: &str, address: usize) -> &str {
        maps.lines()
            .find_map(|line| {
                let mut parts = line.split_whitespace();
                let mut range = parts.next()?.split('-');
                let start = usize::from_str_radix(range.next()?, 16).ok()?;
                let end = usize::from_str_radix(range.next()?, 16).ok()?;
                (address >= start && address < end).then(|| parts.next().unwrap())
            })
            .unwrap()
    }
    assert_eq!(permission(&maps, extent.stack_address - 1), "---p");
    assert_eq!(permission(&maps, extent.stack_address), "rw-p");
    assert_eq!(
        permission(&maps, extent.stack_address + extent.stack_bytes),
        "---p"
    );
    assert_eq!(owner.book.source_created.load(Ordering::SeqCst), 0);
    assert!(
        owner
            .events()
            .iter()
            .any(|e| matches!(e, NativeEvent::StackReady { .. }))
    );
    let completion = thread.join().unwrap();
    assert_eq!(completion.callback, Ok(()));
    assert_eq!(owner.book.released.load(Ordering::SeqCst), 1);
}
#[test]
fn second_factory_same_node_cannot_reset_one_worker_slot() {
    let owner = TestOwner::fixture();
    let thread = start::<NoSource>(&owner, job());
    let second = WorkerFactory::new(&owner).unwrap().start::<NoSource>(
        spec(),
        job(),
        WorkerBootstrap::InspectOwnedStack,
    );
    assert!(matches!(second, Err(WorkerError::Busy)));
    assert_eq!(owner.book.issued.load(Ordering::SeqCst), 1);
    thread.join().unwrap();
    let next = start::<NoSource>(&owner, job());
    next.join().unwrap();
    assert_eq!(owner.book.issued.load(Ordering::SeqCst), 2);
    assert_eq!(owner.book.released.load(Ordering::SeqCst), 2);
}
struct SourceOwned {
    book: Arc<Book>,
    epoch: u64,
}
impl SourceOwned {
    fn enroll(book: &Arc<Book>, permit: &mut SourceEnrollment<'_>) -> Self {
        permit.original.check().unwrap();
        assert!(
            book.events
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, NativeEvent::StackReady { .. }))
        );
        book.source_created.fetch_add(1, Ordering::SeqCst);
        Self {
            book: book.clone(),
            epoch: 7,
        }
    }
}
impl Drop for SourceOwned {
    fn drop(&mut self) {
        self.book.source_dropped.fetch_add(1, Ordering::SeqCst);
    }
}
struct CaptureTask {
    source: SourceOwned,
    admitted: Instant,
    deadline: Instant,
    cancel_address: usize,
}
unsafe impl TrustedCaptureTask for CaptureTask {
    fn run(self, original: &mut JobControl, _: StackExtentReady) -> Result<(), WorkerError> {
        assert_eq!(self.source.epoch, 7);
        assert_eq!(original.admitted(), self.admitted);
        assert_eq!(original.deadline(), self.deadline);
        assert_eq!(
            Arc::as_ptr(original.cancellation()) as usize,
            self.cancel_address
        );
        for _phase in ["source", "certificate", "identity", "copy", "controller"] {
            original.check()?;
        }
        Ok(())
    }
}
#[test]
fn dummy_owned_source_is_enrolled_only_after_ready_and_uses_original_control() {
    let owner = TestOwner::fixture();
    let original = job();
    let admitted = original.admitted();
    let deadline = original.deadline();
    let cancel_address = Arc::as_ptr(original.cancellation()) as usize;
    let mut worker = start::<CaptureTask>(&owner, original);
    assert_eq!(owner.book.source_created.load(Ordering::SeqCst), 0);
    let source = SourceOwned::enroll(&owner.book, &mut worker.source_enrollment().unwrap());
    worker
        .submit(CaptureTask {
            source,
            admitted,
            deadline,
            cancel_address,
        })
        .unwrap();
    assert_eq!(worker.join().unwrap().callback, Ok(()));
    assert_eq!(owner.book.source_created.load(Ordering::SeqCst), 1);
    assert_eq!(owner.book.source_dropped.load(Ordering::SeqCst), 1);
    assert_cleanup_order(&owner.events());
}
fn assert_cleanup_order(events: &[NativeEvent]) {
    let joined = events
        .iter()
        .position(|e| *e == NativeEvent::Joined)
        .unwrap();
    let mut mapped = 0;
    let mut unmapped = 0;
    for event in events {
        if let NativeEvent::Mapped {
            id,
            kind,
            address,
            bytes,
        } = *event
        {
            mapped += 1;
            let released = events
                .iter()
                .position(|e| {
                    *e == NativeEvent::Unmapped {
                        id,
                        kind,
                        address,
                        bytes,
                    }
                })
                .unwrap();
            assert!(
                joined < released,
                "actual same mapping-ID unmap must follow native join"
            );
        }
        if matches!(event, NativeEvent::Unmapped { .. }) {
            unmapped += 1;
        }
    }
    assert_eq!(mapped, 2);
    assert_eq!(unmapped, 2);
    if let Some(cleaned) = events
        .iter()
        .position(|e| *e == NativeEvent::CallbackCleaned)
    {
        assert!(cleaned < joined);
    }
}
#[derive(Default)]
struct Blocker {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}
impl Blocker {
    fn entered(&self) {
        let mut state = self.state.lock().unwrap();
        while !state.0 {
            state = self.changed.wait(state).unwrap();
        }
    }
    fn unblock(&self) {
        let mut state = self.state.lock().unwrap();
        state.1 = true;
        self.changed.notify_all();
    }
}
struct BlockedTask {
    source: SourceOwned,
    blocker: Arc<Blocker>,
    tls: bool,
}
unsafe impl TrustedCaptureTask for BlockedTask {
    fn run(self, original: &mut JobControl, _: StackExtentReady) -> Result<(), WorkerError> {
        assert_eq!(self.source.epoch, 7);
        if self.tls {
            EXIT_BARRIER.with(|slot| *slot.0.borrow_mut() = Some(self.blocker.clone()));
            return Ok(());
        }
        let mut state = self.blocker.state.lock().unwrap();
        state.0 = true;
        self.blocker.changed.notify_all();
        while !state.1 {
            state = self.blocker.changed.wait(state).unwrap();
        }
        original.check()?;
        Ok(())
    }
}
fn blocked(
    owner: &TestOwner,
    blocker: &Arc<Blocker>,
    tls: bool,
) -> NativeThread<TestLease, BlockedTask> {
    let mut worker = start::<BlockedTask>(owner, job());
    let source = SourceOwned::enroll(&owner.book, &mut worker.source_enrollment().unwrap());
    worker
        .submit(BlockedTask {
            source,
            blocker: blocker.clone(),
            tls,
        })
        .unwrap();
    worker
}
#[test]
fn cancellation_while_blocked_keeps_lease_and_native_stack_until_join_unmap() {
    let owner = TestOwner::fixture();
    let blocker = Arc::new(Blocker::default());
    let worker = blocked(&owner, &blocker, false);
    blocker.entered();
    worker.request_cancel();
    assert_eq!(owner.book.released.load(Ordering::SeqCst), 0);
    assert_eq!(owner.book.source_dropped.load(Ordering::SeqCst), 0);
    assert!(owner.book.occupied.load(Ordering::SeqCst));
    blocker.unblock();
    let result = worker.join().unwrap();
    assert_eq!(result.callback, Err(WorkerError::Job(SqlError::Cancelled)));
    assert_cleanup_order(&owner.events());
    assert_eq!(owner.book.released.load(Ordering::SeqCst), 1);
}
#[test]
fn requester_drop_while_callback_blocked_cannot_release_admission_early() {
    let owner = TestOwner::fixture();
    let blocker = Arc::new(Blocker::default());
    let worker = blocked(&owner, &blocker, false);
    blocker.entered();
    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel(0); // TEST synchronization only, not factory storage.
        let dropping = scope.spawn(move || {
            tx.send(()).unwrap();
            drop(worker);
        });
        rx.recv().unwrap();
        assert_eq!(owner.book.released.load(Ordering::SeqCst), 0);
        assert!(
            !owner
                .events()
                .iter()
                .any(|e| matches!(e, NativeEvent::Unmapped { .. }))
        );
        blocker.unblock();
        dropping.join().unwrap();
    });
    assert_cleanup_order(&owner.events());
    assert_eq!(owner.book.released.load(Ordering::SeqCst), 1);
}
struct ExitBarrier(std::cell::RefCell<Option<Arc<Blocker>>>);
impl Drop for ExitBarrier {
    fn drop(&mut self) {
        if let Some(blocker) = self.0.get_mut().take() {
            let mut state = blocker.state.lock().unwrap();
            state.0 = true;
            blocker.changed.notify_all();
            while !state.1 {
                state = blocker.changed.wait(state).unwrap();
            }
        }
    }
}
std::thread_local! { static EXIT_BARRIER: ExitBarrier = const { ExitBarrier(std::cell::RefCell::new(None)) }; }
#[test]
fn native_tls_destructor_blocks_credit_even_after_source_callback_cleanup() {
    let owner = TestOwner::fixture();
    let blocker = Arc::new(Blocker::default());
    let worker = blocked(&owner, &blocker, true);
    blocker.entered();
    assert_eq!(owner.book.source_dropped.load(Ordering::SeqCst), 1);
    assert!(owner.events().contains(&NativeEvent::CallbackCleaned));
    assert_eq!(owner.book.released.load(Ordering::SeqCst), 0);
    assert!(!owner.events().contains(&NativeEvent::Joined));
    blocker.unblock();
    worker.join().unwrap();
    assert_cleanup_order(&owner.events());
}
#[test]
fn cancellation_before_first_fence_refuses_constructor_and_source_enrollment() {
    let owner = TestOwner::fixture();
    let original = job();
    original.cancellation().store(true, Ordering::Release);
    assert!(matches!(
        WorkerFactory::new(&owner).unwrap().start::<NoSource>(
            spec(),
            original,
            WorkerBootstrap::InspectOwnedStack
        ),
        Err(WorkerError::Job(SqlError::Cancelled))
    ));
    assert_eq!(owner.book.issued.load(Ordering::SeqCst), 0);
    let mut worker = start::<NoSource>(&owner, job());
    worker.request_cancel();
    assert!(matches!(
        worker.source_enrollment(),
        Err(WorkerError::Job(SqlError::Cancelled))
    ));
    assert!(matches!(
        worker.submit(NoSource),
        Err(WorkerError::Job(SqlError::Cancelled))
    ));
    drop(worker);
    assert_eq!(owner.book.source_created.load(Ordering::SeqCst), 0);
}
struct PanicTask {
    source: SourceOwned,
}
unsafe impl TrustedCaptureTask for PanicTask {
    fn run(self, _: &mut JobControl, _: StackExtentReady) -> Result<(), WorkerError> {
        assert_eq!(self.source.epoch, 7);
        panic!("native fixture panic");
    }
}
#[test]
fn callback_panic_cleans_owned_source_then_joins_then_unmaps() {
    let owner = TestOwner::fixture();
    let mut worker = start::<PanicTask>(&owner, job());
    let source = SourceOwned::enroll(&owner.book, &mut worker.source_enrollment().unwrap());
    worker.submit(PanicTask { source }).unwrap();
    assert_eq!(
        worker.join().unwrap().callback,
        Err(WorkerError::NativePanic)
    );
    assert_eq!(owner.book.source_dropped.load(Ordering::SeqCst), 1);
    assert_cleanup_order(&owner.events());
}
struct FaultTask {
    mode: u8,
}
unsafe impl TrustedCaptureTask for FaultTask {
    fn run(self, _: &mut JobControl, extent: StackExtentReady) -> Result<(), WorkerError> {
        if self.mode == 1 {
            unsafe {
                (extent.stack_address as *mut u8).sub(1).write_volatile(7);
            }
        } else {
            consume_stack(1);
        }
        Ok(())
    }
}
#[inline(never)]
fn consume_stack(depth: u64) -> u64 {
    let mut page = [0u8; 8192];
    for i in (0..page.len()).step_by(4096) {
        unsafe {
            page.as_mut_ptr().add(i).write_volatile(depth as u8);
        }
    }
    let next = std::hint::black_box(depth + 1);
    if std::hint::black_box(next) < u64::MAX {
        let result = consume_stack(next);
        std::hint::black_box(&page);
        result
    } else {
        depth
    }
}
#[test]
fn child_guard_fault_entry() {
    let Ok(mode) = std::env::var("FLOWER_SQL_WORKER_FAULT_FIXTURE") else {
        return;
    };
    // Fault children must not leave process/environment/TLS core images on
    // shared disk. This changes ONLY this disposable child, never host limits
    // or the factory/serving constructor, and does not change stack admission.
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
    let owner = TestOwner::fixture();
    let mut worker = start::<FaultTask>(&owner, job());
    worker
        .submit(FaultTask {
            mode: mode.parse().unwrap(),
        })
        .unwrap();
    let _ = worker.join();
    panic!("bounded stack fault unexpectedly returned");
}
#[test]
fn actual_guard_and_recursive_growth_fault_in_isolated_child_only() {
    use std::os::unix::process::ExitStatusExt;
    for mode in ["1", "2"] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sql_worker::tests::child_guard_fault_entry",
                "--nocapture",
            ])
            .env("FLOWER_SQL_WORKER_FAULT_FIXTURE", mode)
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGSEGV));
    }
}
#[test]
fn child_mapping_reuse_entry() {
    if std::env::var("FLOWER_SQL_WORKER_MAP_REUSE_FIXTURE")
        .ok()
        .as_deref()
        != Some("1")
    {
        return;
    }
    let owner = TestOwner::fixture();
    let worker = start::<NoSource>(&owner, job());
    worker.join().unwrap();
    let events = owner.events();
    assert_cleanup_order(&events);
    for event in events {
        if let NativeEvent::Unmapped { address, bytes, .. } = event {
            let result = unsafe {
                libc::mmap(
                    address as *mut _,
                    bytes,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            assert_eq!(
                result as usize, address,
                "test retains mapping ID proof independently of later address reuse"
            );
            assert_eq!(unsafe { libc::munmap(result, bytes) }, 0);
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
struct Counts {
    calls: [u64; 7],
    requested_bytes: u64,
    requests: [u64; 16],
}
struct Diagnostics {
    begin: unsafe extern "C" fn(),
    read: unsafe extern "C" fn(*mut Counts),
    end: unsafe extern "C" fn(),
}
impl Diagnostics {
    fn load() -> Option<Self> {
        unsafe {
            let begin = libc::dlsym(libc::RTLD_DEFAULT, c"flower_worker_probe_begin".as_ptr());
            let read = libc::dlsym(libc::RTLD_DEFAULT, c"flower_worker_probe_read".as_ptr());
            let end = libc::dlsym(libc::RTLD_DEFAULT, c"flower_worker_probe_end".as_ptr());
            if begin.is_null() || read.is_null() || end.is_null() {
                return None;
            }
            Some(Self {
                begin: std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn()>(begin),
                read: std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(*mut Counts)>(
                    read,
                ),
                end: std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn()>(end),
            })
        }
    }
    fn counts(&self) -> Counts {
        let mut result = Counts::default();
        unsafe {
            (self.read)(&mut result);
        }
        result
    }
}
#[test]
fn native_startup_diagnostics_are_observations_not_whole_native_proof() {
    let Some(probe) = Diagnostics::load() else {
        return;
    };
    let owner = TestOwner::fixture();
    let original = job();
    unsafe {
        (probe.begin)();
    }
    let mut worker = start::<NoSource>(&owner, original);
    let startup = probe.counts();
    unsafe {
        (probe.end)();
    }
    // The separate post-Ready NoSource callback probe is source-free and is NOT
    // code/cert/JSON-depth/capture/Tokio whole-stack proof.
    unsafe {
        (probe.begin)();
    }
    worker
        .source_enrollment()
        .unwrap()
        .original
        .check()
        .unwrap();
    worker.submit(NoSource).unwrap();
    let completion = worker.join().unwrap();
    let completion_counts = probe.counts();
    unsafe {
        (probe.end)();
    }
    assert_eq!(completion.callback, Ok(()));
    eprintln!(
        "code=STARTUP_OBSERVATION calls={:?} requested_bytes={} code=JOIN_OBSERVATION calls={:?} requested_bytes={}",
        startup.calls,
        startup.requested_bytes,
        completion_counts.calls,
        completion_counts.requested_bytes
    );
    assert!(
        startup.calls[1] > 0 || startup.calls[2] > 0 || startup.calls[0] > 0,
        "native TLS/getattr must not be represented as zero allocations"
    );
    assert_eq!(
        completion_counts.calls[..6].iter().sum::<u64>(),
        0,
        "only the actual dummy post-Ready callback; not source or async machinery"
    );
}

#[repr(align(8192))]
struct OverAligned;
unsafe impl TrustedCaptureTask for OverAligned {
    fn run(self, _: &mut JobControl, _: StackExtentReady) -> Result<(), WorkerError> {
        Ok(())
    }
}
#[test]
fn inline_control_alignment_must_fit_actual_native_page() {
    let owner = TestOwner::fixture();
    let factory = WorkerFactory::new(&owner).unwrap();
    let page = factory.layout::<NoSource>(spec()).unwrap().page_bytes;
    if page < std::mem::align_of::<OverAligned>() {
        assert!(matches!(
            factory.layout::<OverAligned>(spec()),
            Err(WorkerError::InvalidLayout)
        ));
    }
    assert_eq!(owner.book.issued.load(Ordering::SeqCst), 0);
}
#[test]
fn actual_impossible_native_mapping_refusal_returns_only_its_unused_lease() {
    let owner = TestOwner::fixture();
    let factory = WorkerFactory::new(&owner).unwrap();
    let error = factory.start::<NoSource>(
        StackSpec {
            usable_bytes: (isize::MAX as usize) - 65536,
        },
        job(),
        WorkerBootstrap::InspectOwnedStack,
    );
    assert!(matches!(error, Err(WorkerError::MappingFailed)));
    assert_eq!(owner.book.issued.load(Ordering::SeqCst), 1);
    assert_eq!(owner.book.released.load(Ordering::SeqCst), 1);
    assert!(owner.events().is_empty());
}
fn fault_injection() -> Option<unsafe extern "C" fn(u32)> {
    let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"flower_worker_probe_fault".as_ptr()) };
    if pointer.is_null() {
        return None;
    }
    Some(unsafe { std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(u32)>(pointer) })
}
#[test]
fn child_native_failure_entry() {
    let Ok(mode) = std::env::var("FLOWER_SQL_WORKER_NATIVE_FAILURE_FIXTURE") else {
        return;
    };
    let mode: u32 = mode.parse().unwrap();
    let fault = fault_injection().expect("isolated native fault interposer");
    let owner = TestOwner::fixture();
    unsafe {
        fault(mode);
    }
    if matches!(mode, 3 | 4) {
        let worker = start::<NoSource>(&owner, job());
        let result = worker.join();
        if mode == 3 {
            assert!(matches!(result, Err(WorkerError::Join(libc::EINVAL))));
        } else {
            assert!(matches!(result, Err(WorkerError::Unmap(libc::EBUSY))));
        }
    } else {
        let result = WorkerFactory::new(&owner).unwrap().start::<NoSource>(
            spec(),
            job(),
            WorkerBootstrap::InspectOwnedStack,
        );
        match mode {
            1 => assert!(matches!(result, Err(WorkerError::Create(libc::EAGAIN)))),
            2 => assert!(matches!(result, Err(WorkerError::StackMismatch))),
            5 | 6 => assert!(matches!(result, Err(WorkerError::ProtectionFailed))),
            _ => panic!("closed native failure fixture"),
        }
    }
    let events = owner.events();
    assert_eq!(owner.book.issued.load(Ordering::SeqCst), 1);
    assert_eq!(owner.book.source_created.load(Ordering::SeqCst), 0);
    if matches!(mode, 3 | 4 | 6) {
        assert_eq!(
            owner.book.released.load(Ordering::SeqCst),
            0,
            "uncertain native cleanup MUST leak strong ticket"
        );
        assert!(owner.book.occupied.load(Ordering::SeqCst));
        assert!(events.contains(&NativeEvent::CleanupUncertain));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, NativeEvent::Unmapped { .. }))
        );
    } else {
        assert_eq!(owner.book.released.load(Ordering::SeqCst), 1);
        let mapped = events
            .iter()
            .filter(|e| matches!(e, NativeEvent::Mapped { .. }))
            .count();
        let unmapped = events
            .iter()
            .filter(|e| matches!(e, NativeEvent::Unmapped { .. }))
            .count();
        assert_eq!(mapped, unmapped);
        assert!(mapped > 0);
        if mode == 2 {
            assert_cleanup_order(&events);
        }
    }
    // No reset/free/reuse claim for intentionally leaked mappings/tickets. They
    // live until this ISOLATED child's OS teardown, never the serving daemon.
    unsafe {
        fault(0);
    }
}
#[test]
fn injected_native_failures_keep_partial_maps_and_uncertain_join_unmap_tickets() {
    if fault_injection().is_none() {
        return;
    }
    for mode in [1, 2, 3, 4, 5, 6] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sql_worker::tests::child_native_failure_entry",
                "--nocapture",
            ])
            .env("FLOWER_SQL_WORKER_NATIVE_FAILURE_FIXTURE", mode.to_string())
            .status()
            .unwrap();
        assert!(status.success(), "isolated native failure code={mode}");
    }
}

#[test]
fn unmapped_original_mapping_ids_can_be_reused_without_faking_a_free_by_va() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sql_worker::tests::child_mapping_reuse_entry",
            "--nocapture",
        ])
        .env("FLOWER_SQL_WORKER_MAP_REUSE_FIXTURE", "1")
        .status()
        .unwrap();
    assert!(status.success());
}
struct RenewTask;
unsafe impl TrustedCaptureTask for RenewTask {
    fn run(self, original: &mut JobControl, _: StackExtentReady) -> Result<(), WorkerError> {
        *original = JobControl::new(Duration::from_secs(10), original.cancellation().clone())?;
        Ok(())
    }
}
#[test]
fn replacing_original_control_during_enrollment_or_callback_is_sticky_refusal() {
    let owner = TestOwner::fixture();
    let mut worker = start::<NoSource>(&owner, job());
    {
        let enrollment = worker.source_enrollment().unwrap();
        *enrollment.original = JobControl::new(
            Duration::from_secs(10),
            enrollment.original.cancellation().clone(),
        )
        .unwrap();
    }
    assert!(matches!(
        worker.submit(NoSource),
        Err(WorkerError::InvalidState)
    ));
    assert!(matches!(
        worker.source_enrollment(),
        Err(WorkerError::InvalidState)
    ));
    drop(worker);
    let mut worker = start::<RenewTask>(&owner, job());
    worker.submit(RenewTask).unwrap();
    assert_eq!(
        worker.join().unwrap().callback,
        Err(WorkerError::InvalidState)
    );
    assert_eq!(owner.book.source_created.load(Ordering::SeqCst), 0);
}
