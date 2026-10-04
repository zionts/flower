use super::*;
use std::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    ptr::NonNull,
    sync::atomic::{AtomicU32, Ordering},
    time::Instant,
};

const BOOTING: u32 = 0;
const READY: u32 = 1;
const SUBMITTED: u32 = 2;
const STOP: u32 = 3;
const RUNNING: u32 = 4;
const RETURNED: u32 = 5;
const BOOT_FAILED: u32 = 6;

#[derive(Clone, Copy)]
struct OriginalIdentity {
    admitted: Instant,
    deadline: Instant,
    cancellation_address: usize,
}
impl OriginalIdentity {
    fn of(original: &JobControl) -> Self {
        Self {
            admitted: original.admitted(),
            deadline: original.deadline(),
            cancellation_address: Arc::as_ptr(original.cancellation()) as usize,
        }
    }
    fn check(self, original: &JobControl) -> Result<(), WorkerError> {
        if original.admitted() != self.admitted
            || original.deadline() != self.deadline
            || Arc::as_ptr(original.cancellation()) as usize != self.cancellation_address
        {
            return Err(WorkerError::InvalidState);
        }
        Ok(())
    }
}
struct State<L, T> {
    phase: AtomicU32,
    original: UnsafeCell<Option<JobControl>>,
    lease: UnsafeCell<MaybeUninit<L>>,
    task: UnsafeCell<MaybeUninit<T>>,
    task_present: UnsafeCell<bool>,
    result: UnsafeCell<Option<Result<(), WorkerError>>>,
    extent: UnsafeCell<StackExtentReady>,
    bootstrap: WorkerBootstrap,
    identity: OriginalIdentity,
    identity_failed: AtomicBool,
}
// Only the phase-acquire/release protocol transfers exclusive ownership of the
// job/task/result cells. The lease observer itself must be thread-safe.
unsafe impl<L: NativeLease + Sync, T: TrustedCaptureTask> Sync for State<L, T> {}
impl<L: NativeLease, T> State<L, T> {
    fn check_identity(&self, original: &JobControl) -> Result<(), WorkerError> {
        if self.identity_failed.load(Ordering::Acquire) {
            return Err(WorkerError::InvalidState);
        }
        if self.identity.check(original).is_err() {
            self.identity_failed.store(true, Ordering::Release);
            return Err(WorkerError::InvalidState);
        }
        Ok(())
    }
    fn lease(&self) -> &L {
        unsafe { (&*self.lease.get()).assume_init_ref() }
    }
    fn observe(&self, event: NativeEvent) {
        self.lease().observe(event);
    }
    fn publish(&self, phase: u32) {
        self.phase.store(phase, Ordering::Release);
        wake(&self.phase);
    }
}

pub(crate) struct WorkerFactory<'a, N: NativeOwner> {
    owner: &'a N,
}
impl<'a, N: NativeOwner> WorkerFactory<'a, N> {
    pub(crate) fn new(owner: &'a N) -> Result<Self, WorkerError> {
        platform_gate()?;
        if owner.immutable_worker_ceiling() != APPROVED_WORKER_CEILING {
            return Err(WorkerError::InvalidLayout);
        }
        Ok(Self { owner })
    }
    pub(crate) fn layout<T: TrustedCaptureTask>(
        &self,
        spec: StackSpec,
    ) -> Result<WorkerLayout, WorkerError> {
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|p| p.is_power_of_two())
            .ok_or(WorkerError::UnsupportedPlatform)?;
        let control = Layout::new::<State<N::Lease, T>>();
        if control.align() > page || spec.usable_bytes < libc::PTHREAD_STACK_MIN {
            return Err(WorkerError::InvalidLayout);
        }
        let stack_bytes = WorkerLayout::round_pages(spec.usable_bytes, page)?;
        let stack_mapping_bytes = page
            .checked_mul(2)
            .and_then(|g| g.checked_add(stack_bytes))
            .ok_or(WorkerError::Overflow)?;
        let control_mapping_bytes = WorkerLayout::round_pages(control.size(), page)?;
        let explicit_mapping_bytes = stack_mapping_bytes
            .checked_add(control_mapping_bytes)
            .ok_or(WorkerError::Overflow)?;
        Ok(WorkerLayout {
            page_bytes: page,
            stack_bytes,
            guard_bytes_each: page,
            stack_mapping_bytes,
            control_layout: control,
            control_mapping_bytes,
            task_layout: Layout::new::<T>(),
            lease_layout: Layout::new::<N::Lease>(),
            caller_handle_layout: Layout::new::<NativeThread<N::Lease, T>>(),
            explicit_mapping_bytes,
        })
    }
    /// Source-free construction. Unknown native admission refuses before ANY
    /// mmap/pthread/native bootstrap allocation. No pool or fallback is created.
    pub(crate) fn start<T: TrustedCaptureTask>(
        &self,
        spec: StackSpec,
        mut original: JobControl,
        bootstrap: WorkerBootstrap,
    ) -> Result<NativeThread<N::Lease, T>, WorkerError> {
        original.check()?;
        let layout = self.layout::<T>(spec)?;
        self.owner.native_gate(&layout).map_err(WorkerError::Hold)?;
        original.check()?;
        let lease = self.owner.admit(&layout, &original)?;
        // Admission owns ALL cleanup failures from this point onward.
        let ids = lease.mapping_ids();
        if ids[0] == 0 || ids[1] == 0 || ids[0] == ids[1] {
            // The admitted lease may release the original job/node credit.
            // Drop its original control owner BEFORE the lease can do so.
            drop(original);
            return Err(WorkerError::InvalidLayout);
        }
        let cancel = original_cancellation(&original);
        let mut stack =
            match Mapping::new(layout.stack_mapping_bytes, ids[0], MapKind::StackAndGuards) {
                Ok(map) => map,
                Err(error) => {
                    drop(original);
                    drop(cancel);
                    if matches!(error, WorkerError::Unmap(_)) {
                        std::mem::forget(lease);
                    }
                    return Err(error);
                }
            };
        lease.observe(stack.mapped_event());
        if let Err(error) = stack.protect(layout.page_bytes, layout.stack_bytes) {
            drop(original);
            drop(cancel);
            cleanup_partial(&mut stack, None, lease);
            return Err(error);
        }
        if let Err(error) = stack.touch(
            layout.page_bytes,
            layout.stack_bytes,
            layout.page_bytes,
            &mut original,
        ) {
            drop(original);
            drop(cancel);
            cleanup_partial(&mut stack, None, lease);
            return Err(error);
        }
        let mut control = match Mapping::new(
            layout.control_mapping_bytes,
            ids[1],
            MapKind::ControlAndTask,
        ) {
            Ok(map) => map,
            Err(error) => {
                drop(original);
                drop(cancel);
                if matches!(error, WorkerError::Unmap(_)) {
                    let _ = stack.release();
                    std::mem::forget(lease);
                } else {
                    cleanup_partial(&mut stack, None, lease);
                }
                return Err(error);
            }
        };
        lease.observe(control.mapped_event());
        if let Err(error) = control
            .protect(0, layout.control_mapping_bytes)
            .and_then(|()| {
                control.touch(
                    0,
                    layout.control_mapping_bytes,
                    layout.page_bytes,
                    &mut original,
                )
            })
        {
            drop(original);
            drop(cancel);
            cleanup_partial(&mut stack, Some(&mut control), lease);
            return Err(error);
        }
        let extent = StackExtentReady {
            stack_mapping_id: ids[0],
            stack_address: stack.address() + layout.page_bytes,
            stack_bytes: layout.stack_bytes,
            native_reported_guard_bytes: 0,
            owned_guard_bytes_each: layout.page_bytes,
            stack_mapping_bytes: layout.stack_mapping_bytes,
            control_mapping_id: ids[1],
        };
        let identity = OriginalIdentity::of(&original);
        let state = control.base.cast::<State<N::Lease, T>>();
        // Initialize fields in place; no whole task/control temporary on caller
        // stack. T is still UNINITIALIZED and cannot contain source refs.
        unsafe {
            let p = state.as_ptr();
            std::ptr::addr_of_mut!((*p).phase).write(AtomicU32::new(BOOTING));
            std::ptr::addr_of_mut!((*p).original).write(UnsafeCell::new(Some(original)));
            std::ptr::addr_of_mut!((*p).lease).write(UnsafeCell::new(MaybeUninit::new(lease)));
            // The map is initialized bytes but deliberately NOT a valid T.
            std::ptr::addr_of_mut!((*p).task_present).write(UnsafeCell::new(false));
            std::ptr::addr_of_mut!((*p).result).write(UnsafeCell::new(None));
            std::ptr::addr_of_mut!((*p).extent).write(UnsafeCell::new(extent));
            std::ptr::addr_of_mut!((*p).bootstrap).write(bootstrap);
            std::ptr::addr_of_mut!((*p).identity).write(identity);
            std::ptr::addr_of_mut!((*p).identity_failed).write(AtomicBool::new(false));
        }
        let mut worker = NativeThread {
            state,
            stack,
            control,
            thread: None,
            cancel: Some(cancel),
            ready: false,
            cleaned: false,
        };
        let mut attr = MaybeUninit::<libc::pthread_attr_t>::uninit();
        let rc = unsafe { libc::pthread_attr_init(attr.as_mut_ptr()) };
        if rc != 0 {
            return Err(WorkerError::Attributes(rc));
        }
        let mut attr = unsafe { attr.assume_init() };
        let rc = unsafe { libc::pthread_attr_setguardsize(&mut attr, 0) };
        let rc = if rc == 0 {
            unsafe {
                libc::pthread_attr_setstack(
                    &mut attr,
                    extent.stack_address as *mut libc::c_void,
                    extent.stack_bytes,
                )
            }
        } else {
            rc
        };
        if rc != 0 {
            let destroy = unsafe { libc::pthread_attr_destroy(&mut attr) };
            if destroy != 0 {
                worker.abandon();
            }
            return Err(WorkerError::Attributes(rc));
        }
        let mut thread = MaybeUninit::<libc::pthread_t>::uninit();
        let rc = unsafe {
            libc::pthread_create(
                thread.as_mut_ptr(),
                &attr,
                entry::<N::Lease, T>,
                state.as_ptr().cast(),
            )
        };
        if rc == 0 {
            worker.thread = Some(unsafe { thread.assume_init() });
        }
        let destroy = unsafe { libc::pthread_attr_destroy(&mut attr) };
        if destroy != 0 {
            // Attribute-owner cleanup is uncertain. Retain capacity AND native
            // mappings even if create failed. Never invent a cleanup success.
            worker.stop_and_join_without_credit();
            worker.abandon();
            return Err(WorkerError::AttributeCleanup(destroy));
        }
        if rc != 0 {
            return Err(WorkerError::Create(rc));
        }
        worker.wait_ready()?;
        worker.ready = true;
        Ok(worker)
    }
}

/// Owns the actual pthread, mappings and inline original-job lease. Drop joins
/// synchronously; aborting an async requester cannot detach/return this credit.
/// The parent must run this lifecycle in its already admitted native controller,
/// NOT create an unaccounted Tokio blocking pool/reaper to hide Drop latency.
pub(crate) struct NativeThread<L: NativeLease, T: TrustedCaptureTask> {
    state: NonNull<State<L, T>>,
    stack: Mapping,
    control: Mapping,
    thread: Option<libc::pthread_t>,
    cancel: Option<Arc<AtomicBool>>,
    ready: bool,
    cleaned: bool,
}
unsafe impl<L: NativeLease, T: TrustedCaptureTask> Send for NativeThread<L, T> {}
impl<L: NativeLease, T: TrustedCaptureTask> NativeThread<L, T> {
    fn state(&self) -> &State<L, T> {
        unsafe { self.state.as_ref() }
    }
    fn wait_ready(&self) -> Result<(), WorkerError> {
        loop {
            let phase = self.state().phase.load(Ordering::Acquire);
            match phase {
                READY => return Ok(()),
                BOOT_FAILED | RETURNED => {
                    return unsafe {
                        (*self.state().result.get()).unwrap_or(Err(WorkerError::InvalidState))
                    };
                }
                BOOTING => {
                    // Only parent accesses the original until Ready/submission.
                    let job = unsafe {
                        (&mut *self.state().original.get())
                            .as_mut()
                            .ok_or(WorkerError::InvalidState)?
                    };
                    self.state().check_identity(job)?;
                    job.check()?;
                    let duration = job.deadline().saturating_duration_since(Instant::now());
                    let timeout = libc::timespec {
                        tv_sec: duration.as_secs() as libc::time_t,
                        tv_nsec: duration.subsec_nanos().into(),
                    };
                    wait(&self.state().phase, phase, Some(&timeout))?;
                }
                _ => return Err(WorkerError::InvalidState),
            }
        }
    }
    pub(crate) fn stack_extent_ready(&self) -> Result<StackExtentReady, WorkerError> {
        if !self.ready || self.state().phase.load(Ordering::Acquire) != READY {
            return Err(WorkerError::InvalidState);
        }
        Ok(unsafe { *self.state().extent.get() })
    }
    /// Source refs can be enrolled only through this post-Ready boundary. It
    /// lends the ORIGINAL control; no new JobControl/retry/cancellation Arc.
    pub(crate) fn source_enrollment(&mut self) -> Result<SourceEnrollment<'_>, WorkerError> {
        let extent = self.stack_extent_ready()?;
        let original = unsafe {
            (&mut *self.state().original.get())
                .as_mut()
                .ok_or(WorkerError::InvalidState)?
        };
        self.state().check_identity(original)?;
        original.check()?;
        Ok(SourceEnrollment {
            extent,
            original,
            _private: PhantomData,
        })
    }
    pub(crate) fn submit(&mut self, task: T) -> Result<(), WorkerError> {
        self.stack_extent_ready()?;
        let state = self.state();
        let original = unsafe {
            (&mut *state.original.get())
                .as_mut()
                .ok_or(WorkerError::InvalidState)?
        };
        state.check_identity(original)?;
        original.check()?;
        unsafe {
            (*state.task.get()).write(task);
            *state.task_present.get() = true;
        }
        state.publish(SUBMITTED);
        Ok(())
    }
    pub(crate) fn request_cancel(&self) {
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Release);
        }
    }
    pub(crate) fn join(mut self) -> Result<Completion, WorkerError> {
        self.stop_if_unsubmitted();
        self.join_native()?;
        let state = self.state();
        let extent = unsafe { *state.extent.get() };
        let callback = unsafe { (*state.result.get()).unwrap_or(Err(WorkerError::InvalidState)) };
        self.cleanup()?;
        Ok(Completion { callback, extent })
    }
    fn stop_if_unsubmitted(&self) {
        let phase = &self.state().phase;
        // BOOTING may still finish its source-free inspection; entry then
        // preserves STOP instead of enrolling a task. No source data exists.
        let mut current = phase.load(Ordering::Acquire);
        while matches!(current, BOOTING | READY) {
            match phase.compare_exchange(current, STOP, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    wake(phase);
                    break;
                }
                Err(now) => current = now,
            }
        }
    }
    fn join_native(&mut self) -> Result<(), WorkerError> {
        if let Some(thread) = self.thread {
            let rc = unsafe { libc::pthread_join(thread, std::ptr::null_mut()) };
            if rc != 0 {
                self.state().observe(NativeEvent::CleanupUncertain);
                self.abandon();
                return Err(WorkerError::Join(rc));
            }
            self.thread = None;
            self.state().observe(NativeEvent::Joined);
        }
        Ok(())
    }
    fn cleanup(&mut self) -> Result<(), WorkerError> {
        // No callback, source ref or native TLS destructor can still execute.
        let state = self.state();
        if unsafe {
            matches!(
                *state.result.get(),
                Some(Err(WorkerError::AttributeCleanup(_)))
            )
        } {
            state.observe(NativeEvent::CleanupUncertain);
            self.abandon();
            return Err(WorkerError::InvalidState);
        }
        unsafe {
            if *state.task_present.get() {
                (*state.task.get()).assume_init_drop();
                *state.task_present.get() = false;
            }
            drop((&mut *state.original.get()).take());
        }
        // Release this worker's final original cancellation handle BEFORE any
        // lease credit. External cancellation owners require their own strong
        // prepaid lifetime; this factory does not certify those owners.
        drop(self.cancel.take());
        // Move the strong ticket into the cleanup frame before unmapping its
        // old inline slot. Drop it ONLY after both actual successful munmaps.
        let lease = unsafe { (*self.state().lease.get()).assume_init_read() };
        let stack = self.stack.release().map(|event| lease.observe(event));
        let control = self.control.release().map(|event| lease.observe(event));
        self.cleaned = true;
        if let Err(error) = stack.and(control) {
            lease.observe(NativeEvent::CleanupUncertain);
            std::mem::forget(lease);
            return Err(error);
        }
        drop(lease);
        Ok(())
    }
    fn abandon(&mut self) {
        self.cleaned = true;
    }
    fn stop_and_join_without_credit(&mut self) {
        self.stop_if_unsubmitted();
        let _ = self.join_native();
    }
}
impl<L: NativeLease, T: TrustedCaptureTask> Drop for NativeThread<L, T> {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        self.request_cancel();
        self.stop_if_unsubmitted();
        if self.join_native().is_ok() {
            let _ = self.cleanup();
        }
    }
}

extern "C" fn entry<L: NativeLease, T: TrustedCaptureTask>(
    raw: *mut libc::c_void,
) -> *mut libc::c_void {
    let state = unsafe { &*raw.cast::<State<L, T>>() };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker_body(state)))
        .unwrap_or(Err(WorkerError::NativePanic));
    unsafe {
        *state.result.get() = Some(outcome);
    }
    let phase = if matches!(state.phase.load(Ordering::Acquire), BOOTING) {
        BOOT_FAILED
    } else {
        RETURNED
    };
    state.publish(phase);
    std::ptr::null_mut()
}
fn worker_body<L: NativeLease, T: TrustedCaptureTask>(
    state: &State<L, T>,
) -> Result<(), WorkerError> {
    match state.bootstrap {
        WorkerBootstrap::InspectOwnedStack => verify_stack(unsafe { *state.extent.get() })?,
    }
    state.observe(NativeEvent::StackReady {
        stack_id: unsafe { (*state.extent.get()).stack_mapping_id },
    });
    if state
        .phase
        .compare_exchange(BOOTING, READY, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        wake(&state.phase);
    }
    loop {
        match state.phase.load(Ordering::Acquire) {
            READY => wait(&state.phase, READY, None)?,
            STOP => return Ok(()),
            SUBMITTED => break,
            _ => return Err(WorkerError::InvalidState),
        }
    }
    state.phase.store(RUNNING, Ordering::Release);
    // Ownership transfer is release SUBMITTED -> acquire above; source cleanup
    // happens inside catch_unwind and before thread return/TLS destruction.
    let task = unsafe {
        *state.task_present.get() = false;
        (*state.task.get()).assume_init_read()
    };
    let original = unsafe {
        (&mut *state.original.get())
            .as_mut()
            .ok_or(WorkerError::InvalidState)?
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.check_identity(original)?;
        original.check()?;
        state.observe(NativeEvent::CallbackStarted);
        let result = task.run(original, unsafe { *state.extent.get() });
        state.check_identity(original)?;
        original.check()?;
        result
    }))
    .unwrap_or(Err(WorkerError::NativePanic));
    state.observe(NativeEvent::CallbackCleaned);
    result
}
fn verify_stack(expected: StackExtentReady) -> Result<(), WorkerError> {
    let mut attr = MaybeUninit::<libc::pthread_attr_t>::uninit();
    let rc = unsafe { libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr()) };
    if rc != 0 {
        return Err(WorkerError::Attributes(rc));
    }
    let mut attr = unsafe { attr.assume_init() };
    let mut address = std::ptr::null_mut();
    let mut bytes = 0;
    let mut guard = 0;
    let first = unsafe { libc::pthread_attr_getstack(&attr, &mut address, &mut bytes) };
    let second = unsafe { libc::pthread_attr_getguardsize(&attr, &mut guard) };
    let destroy = unsafe { libc::pthread_attr_destroy(&mut attr) };
    if destroy != 0 {
        return Err(WorkerError::AttributeCleanup(destroy));
    }
    if first != 0 || second != 0 {
        return Err(WorkerError::Attributes(if first != 0 {
            first
        } else {
            second
        }));
    }
    let local = 0u8;
    let sp = (&local as *const u8) as usize;
    if address as usize != expected.stack_address
        || bytes != expected.stack_bytes
        || guard != 0
        || sp < expected.stack_address
        || sp
            >= expected
                .stack_address
                .checked_add(expected.stack_bytes)
                .ok_or(WorkerError::Overflow)?
    {
        return Err(WorkerError::StackMismatch);
    }
    Ok(())
}

struct Mapping {
    base: NonNull<u8>,
    bytes: usize,
    id: u64,
    kind: MapKind,
}
impl Mapping {
    fn new(bytes: usize, id: u64, kind: MapKind) -> Result<Self, WorkerError> {
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(WorkerError::MappingFailed);
        }
        let Some(base) = NonNull::new(raw.cast()) else {
            // Linux normally disallows address0 mappings; raw0 is nevertheless
            // valid mmap success. Never lose a grant before cleanup certainty.
            let rc = unsafe { libc::munmap(raw, bytes) };
            if rc != 0 {
                return Err(WorkerError::Unmap(errno()));
            }
            return Err(WorkerError::MappingFailed);
        };
        Ok(Self {
            base,
            bytes,
            id,
            kind,
        })
    }
    fn address(&self) -> usize {
        self.base.as_ptr() as usize
    }
    fn mapped_event(&self) -> NativeEvent {
        NativeEvent::Mapped {
            id: self.id,
            kind: self.kind,
            address: self.address(),
            bytes: self.bytes,
        }
    }
    fn protect(&mut self, offset: usize, bytes: usize) -> Result<(), WorkerError> {
        if unsafe {
            libc::mprotect(
                self.base.as_ptr().add(offset).cast(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        } != 0
        {
            return Err(WorkerError::ProtectionFailed);
        }
        Ok(())
    }
    fn touch(
        &mut self,
        offset: usize,
        bytes: usize,
        page: usize,
        original: &mut JobControl,
    ) -> Result<(), WorkerError> {
        for i in (offset..offset + bytes).step_by(page) {
            original.check()?;
            unsafe {
                self.base.as_ptr().add(i).write_volatile(0);
            }
        }
        original.check()?;
        Ok(())
    }
    fn release(&mut self) -> Result<NativeEvent, WorkerError> {
        if unsafe { libc::munmap(self.base.as_ptr().cast(), self.bytes) } != 0 {
            return Err(WorkerError::Unmap(errno()));
        }
        Ok(NativeEvent::Unmapped {
            id: self.id,
            kind: self.kind,
            address: self.address(),
            bytes: self.bytes,
        })
    }
}
fn cleanup_partial<L: NativeLease>(stack: &mut Mapping, control: Option<&mut Mapping>, lease: L) {
    let first = stack.release().map(|event| lease.observe(event));
    let second = control.map_or(Ok(()), |control| {
        control.release().map(|event| lease.observe(event))
    });
    if first.and(second).is_err() {
        lease.observe(NativeEvent::CleanupUncertain);
        std::mem::forget(lease);
    }
}
fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}
fn wake(word: &AtomicU32) {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word.as_ptr(),
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            i32::MAX,
        );
    }
}
fn wait(
    word: &AtomicU32,
    expected: u32,
    timeout: Option<&libc::timespec>,
) -> Result<(), WorkerError> {
    let raw = timeout.map_or(std::ptr::null(), |value| value as *const _);
    let rc = unsafe {
        libc::syscall(
            libc::SYS_futex,
            word.as_ptr(),
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected,
            raw,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    match errno() {
        libc::EINTR | libc::EAGAIN | libc::ETIMEDOUT => Ok(()),
        error => Err(WorkerError::Wait(error)),
    }
}
