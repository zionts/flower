use super::sqlite::{QueryOptions, SqlCell};
use super::*;
use crate::allocation_probe::measure;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Rust's test harness omits the crate segment. Derive the remaining real
/// ancestry so the SAME fixture runs in Root and standalone component crates.
fn current_test_filter(function: &str) -> String {
    let (_, module) = module_path!().split_once("::").unwrap();
    format!("{module}::{function}")
}

#[derive(Clone, Copy)]
struct CloseState {
    active: bool,
    identities: [FileIdentity; 6],
    count: [u16; 6],
    failed: bool,
    ticket_dropped: bool,
}
impl CloseState {
    const EMPTY: Self = Self {
        active: false,
        identities: [FileIdentity {
            device: 0,
            inode: 0,
            bytes: 0,
        }; 6],
        count: [0; 6],
        failed: false,
        ticket_dropped: false,
    };
}
thread_local! { static NO_REFUND: Cell<bool> = const { Cell::new(false) }; static CLOSES: Cell<CloseState> = const { Cell::new(CloseState::EMPTY) }; }
pub(super) fn closed(identity: Option<FileIdentity>, result: i32) {
    CLOSES.with(|state| {
        let mut value = state.get();
        if !value.active {
            return;
        }
        value.failed |= result != 0;
        if let Some(identity) = identity {
            for index in 0..6 {
                if identity == value.identities[index] {
                    value.count[index] += 1;
                }
            }
        }
        state.set(value);
    });
}
struct ComponentTicket;
impl Drop for ComponentTicket {
    fn drop(&mut self) {
        if NO_REFUND.with(Cell::get) {
            unsafe { libc::write(libc::STDOUT_FILENO, b"TICKET-REFUNDED".as_ptr().cast(), 15) };
        }
        CLOSES.with(|state| {
            let mut value = state.get();
            if value.active {
                assert!(!value.failed);
                assert!(
                    value.count.iter().all(|count| *count >= 1),
                    "credit refunded before all file owners closed"
                );
                value.ticket_dropped = true;
                state.set(value);
            }
        });
    }
}
struct CloseObservation;
impl CloseObservation {
    fn begin(files: &[FrameFile; 6]) -> Self {
        let identities = std::array::from_fn(|index| files[index].identity().unwrap());
        CLOSES.with(|state| {
            assert!(!state.get().active);
            state.set(CloseState {
                active: true,
                identities,
                ..CloseState::EMPTY
            });
        });
        Self
    }
    fn state(&self) -> CloseState {
        CLOSES.with(Cell::get)
    }
}
impl Drop for CloseObservation {
    fn drop(&mut self) {
        CLOSES.with(|state| state.set(CloseState::EMPTY));
    }
}
fn limits() -> FrameLimits {
    FrameLimits {
        raw_bytes: 4096,
        support_bytes: 4096,
        decoded_bytes: 4096,
        nodes: 128,
        documents: 8,
        keys: 8,
        key_bytes: 4096,
        tables: 4,
        columns: 16,
        rows: 16,
        cells: 64,
        text_bytes: 4096,
        provenance_bytes: 4096,
        parse_work: 1024 * 1024,
    }
}
fn column(name: &str, kind: ColumnKind) -> FrameColumn<'_> {
    FrameColumn {
        name,
        kind,
        nullable: false,
        logical_type: None,
        unit: None,
        equality: false,
    }
}
fn prepare(limits: FrameLimits, control: &FrameControl<'_>) -> PreparedFrame<ComponentTicket> {
    let plan = PreparationPlan::for_limits(limits).unwrap();
    // COMPONENT-ONLY marker! It tests ownership order, not kernel/physical or
    // native USER/node admission. There is deliberately no production issuer.
    unsafe { PreparationLease::from_precharged_owner(ComponentTicket, plan) }
        .prepare(limits, control)
        .unwrap()
}
fn control(cancelled: &AtomicBool) -> FrameControl<'_> {
    FrameControl::new(cancelled, Instant::now() + Duration::from_secs(60))
}
fn fixture(control: &FrameControl<'_>) -> PreparedFrame<ComponentTicket> {
    let mut prepared = prepare(limits(), control);
    let table = prepared
        .add_table(
            "visible",
            &[
                column("id", ColumnKind::Integer),
                column("text", ColumnKind::Text),
                column("real", ColumnKind::Real),
            ],
        )
        .unwrap();
    prepared
        .insert_row(
            table,
            &[
                FrameCell::Integer(3),
                FrameCell::Text("Ada\0😀"),
                FrameCell::Real(1.25),
            ],
            control,
        )
        .unwrap();
    prepared
        .insert_row(
            table,
            &[
                FrameCell::Integer(7),
                FrameCell::Text("Grace"),
                FrameCell::Real(2.75),
            ],
            control,
        )
        .unwrap();
    let hidden = br#"{"hidden":"NEVER-EXPORT-RAW","readable":false}"#;
    let id = prepared.reserve_json(JsonBank::Raw, hidden.len()).unwrap();
    prepared.append_json_chunk(id, hidden).unwrap();
    prepared.finish_json(id, control).unwrap();
    let id = prepared
        .reserve_json(JsonBank::Support, hidden.len())
        .unwrap();
    prepared.append_json_chunk(id, hidden).unwrap();
    prepared.finish_json(id, control).unwrap();
    prepared.retain_key("NEVER-EXPORT-KEY").unwrap();
    prepared
        .append_provenance(b"NEVER-EXPORT-PROVENANCE")
        .unwrap();
    prepared
}
fn duplicate_bank(exported: &ExportedFrame<ComponentTicket>) -> [Option<FrameFile>; 7] {
    std::array::from_fn(|index| {
        if index == 6 {
            None
        } else {
            let fd = unsafe { libc::fcntl(exported.files[index].fd, libc::F_DUPFD_CLOEXEC, 0) };
            assert!(fd >= 0);
            Some(unsafe { FrameFile::from_owned_fd(fd) })
        }
    })
}
fn bytes(file: &FrameFile) -> Vec<u8> {
    let size = file.identity().unwrap().bytes as usize;
    let mut bytes = vec![0; size];
    assert_eq!(
        unsafe { libc::pread(file.fd, bytes.as_mut_ptr().cast(), size, 0) },
        size as isize
    );
    bytes
}
fn region<T: Copy>(slab: &Slab<T>) -> super::super::mapping_tests::Region {
    slab.region()
}

#[test]
fn cold_prepare_seal_consume_validate_views_and_cleanup_use_zero_rust_heap() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let (prepared, count, bytes) = measure(|| prepare(limits(), &control));
    assert_eq!((count, bytes), (0, 0));
    let (exported, count, bytes) = measure(|| prepared.seal(&control));
    assert_eq!((count, bytes), (0, 0));
    let exported = exported.unwrap();
    let observe = CloseObservation::begin(&exported.files);
    let (readonly, count, bytes) = measure(|| exported.adopt(&control));
    assert_eq!((count, bytes), (0, 0));
    let readonly = readonly.unwrap();
    let ((), count, bytes) = measure(|| {
        assert_eq!(readonly.table_count(), 0);
        drop(readonly);
    });
    assert_eq!((count, bytes), (0, 0));
    assert!(observe.state().ticket_dropped);
}

#[test]
fn production_builder_export_ro_same_files_source_sqlite_count_sum_and_typed_text() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let prepared = fixture(&control);
    let old = [
        region(&prepared.typed.text),
        region(&prepared.typed.tables),
        region(&prepared.typed.columns),
        region(&prepared.typed.rows),
        region(&prepared.typed.cells),
        region(&prepared.typed.row_order),
    ];
    let map_observer = super::super::mapping_tests::Observation::begin();
    let exported = prepared.seal(&control).unwrap();
    let (releases, count) = map_observer.releases();
    for owner in old {
        assert!(
            releases[..count]
                .iter()
                .any(|release| release.region == owner && release.result == 0)
        );
    }
    assert_eq!(exported.parent_provenance(), b"NEVER-EXPORT-PROVENANCE");
    for file in &exported.files {
        let payload = bytes(file);
        for sentinel in [
            b"NEVER-EXPORT-RAW".as_slice(),
            b"NEVER-EXPORT-KEY",
            b"NEVER-EXPORT-PROVENANCE",
        ] {
            assert!(
                !payload
                    .windows(sentinel.len())
                    .any(|slice| slice == sentinel)
            );
        }
    }
    let descriptor = exported.descriptor();
    let fds = exported.descriptors();
    let observe = CloseObservation::begin(&exported.files);
    let mut readonly = exported.adopt(&control).unwrap();
    for (index, fd) in fds.iter().enumerate() {
        let borrowed = std::mem::ManuallyDrop::new(FrameFile { fd: *fd });
        assert_eq!(borrowed.identity().unwrap(), descriptor.files[index]);
    }
    let tables = readonly.native_tables(8192).unwrap();
    let result = sqlite::execute(
        "SELECT COUNT(*), SUM(id), SUM(real) FROM visible",
        &[],
        &tables,
        &mut readonly,
        QueryOptions::default(),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(
        result.rows,
        [vec![
            SqlCell::Integer(2),
            SqlCell::Integer(10),
            SqlCell::Real(4.0)
        ]]
    );
    assert!(!result.truncated);
    let result = sqlite::execute(
        "SELECT text FROM visible ORDER BY id",
        &[],
        &tables,
        &mut readonly,
        QueryOptions::default(),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(
        result.rows,
        [
            vec![SqlCell::Text("Ada\0😀".to_owned())],
            vec![SqlCell::Text("Grace".to_owned())]
        ]
    );
    assert!(!result.truncated);
    let ((), count, bytes) = measure(|| {
        assert_eq!(readonly.table(0).unwrap().name, "visible");
        assert_eq!(readonly.column(0, 1).unwrap().kind, ColumnKind::Text);
        drop(readonly);
    });
    assert_eq!((count, bytes), (0, 0));
    assert!(observe.state().ticket_dropped);
}

#[test]
fn kernel_seals_refuse_pwrite_grow_shrink_rw_shared_and_protect_promotions() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let exported = fixture(&control).seal(&control).unwrap();
    for file in &exported.files {
        assert_eq!(unsafe { libc::fcntl(file.fd, libc::F_GET_SEALS) }, SEALS);
        let before = file.identity().unwrap();
        // Reopen RW only for adversarial kernel probes; it is NOT an export FD.
        let path = format!("/proc/self/fd/{}\0", file.fd);
        let fd = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        let probe = unsafe { FrameFile::from_owned_fd(fd) };
        assert_eq!(unsafe { libc::pwrite(fd, b"x".as_ptr().cast(), 1, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        for len in [before.bytes + 4096, before.bytes - 1] {
            assert_eq!(unsafe { libc::ftruncate(fd, len as libc::off_t) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        }
        assert_eq!(
            unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    before.bytes as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            },
            libc::MAP_FAILED
        );
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                before.bytes as usize,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.fd,
                0,
            )
        };
        assert_ne!(map, libc::MAP_FAILED);
        assert_eq!(
            unsafe {
                libc::mprotect(
                    map,
                    before.bytes as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            },
            -1
        );
        assert_eq!(unsafe { libc::munmap(map, before.bytes as usize) }, 0);
        assert_eq!(probe.identity().unwrap(), before);
    }
}

#[test]
fn actual_hidden_shared_writer_blocks_write_seal_until_unmapped() {
    let file = FrameFile::create(4096).unwrap();
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.fd,
            0,
        )
    };
    assert_ne!(map, libc::MAP_FAILED);
    assert_eq!(
        unsafe { libc::fcntl(file.fd, libc::F_ADD_SEALS, SEALS) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBUSY)
    );
    assert_eq!(unsafe { libc::munmap(map, 4096) }, 0);
    assert_eq!(unsafe { libc::fcntl(file.fd, libc::F_ADD_SEALS, SEALS) }, 0);
    assert_eq!(unsafe { libc::fcntl(file.fd, libc::F_GET_SEALS) }, SEALS);
}

#[test]
fn exact_readonly_map_shared_file_offset_and_fd_identity() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let exported = fixture(&control).seal(&control).unwrap();
    let descriptor = exported.descriptor();
    let readonly = exported.adopt(&control).unwrap();
    let regions = [
        region(&readonly.typed.text),
        region(&readonly.typed.tables),
        region(&readonly.typed.columns),
        region(&readonly.typed.rows),
        region(&readonly.typed.cells),
        region(&readonly.typed.row_order),
    ];
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    for (index, region) in regions.iter().enumerate() {
        let line = maps
            .lines()
            .find(|line| {
                let range = line.split_whitespace().next().unwrap();
                let (start, end) = range.split_once('-').unwrap();
                usize::from_str_radix(start, 16).unwrap() == region.address
                    && usize::from_str_radix(end, 16).unwrap() == region.address + region.bytes
            })
            .expect("exact actual owned VMA");
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields[1], "r--s");
        assert_eq!(fields[2], "00000000");
        assert_eq!(
            fields[4].parse::<u64>().unwrap(),
            descriptor.files[index].inode
        );
    }
}

#[test]
fn receive_missing_duplicate_extra_foreign_writable_unsealed_truncated_all_whole_refuse_zero_heap()
{
    for case in 0..7 {
        let cancelled = AtomicBool::new(false);
        let control = control(&cancelled);
        let exported = fixture(&control).seal(&control).unwrap();
        let mut bank = duplicate_bank(&exported);
        match case {
            0 => {
                bank[2] = None;
            }
            1 => {
                let fd = unsafe { libc::fcntl(exported.files[0].fd, libc::F_DUPFD_CLOEXEC, 0) };
                bank[1] = Some(unsafe { FrameFile::from_owned_fd(fd) });
            }
            2 => {
                let fd = unsafe { libc::fcntl(exported.files[0].fd, libc::F_DUPFD_CLOEXEC, 0) };
                bank[6] = Some(unsafe { FrameFile::from_owned_fd(fd) });
            }
            3 => {
                bank[0] = Some(FrameFile::create(4096).unwrap().seal_readonly().unwrap());
            }
            4 => {
                let path = format!("/proc/self/fd/{}\0", exported.files[0].fd);
                let fd =
                    unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR | libc::O_CLOEXEC) };
                assert!(fd >= 0);
                bank[0] = Some(unsafe { FrameFile::from_owned_fd(fd) });
            }
            5 => {
                bank[0] = Some(FrameFile::create(4096).unwrap());
            }
            6 => {
                bank[0] = Some(FrameFile::create(1).unwrap().seal_readonly().unwrap());
            }
            _ => unreachable!(),
        }
        let observe = CloseObservation::begin(&exported.files);
        let (result, count, bytes) = measure(|| exported.adopt_received(bank, &control));
        assert!(matches!(result, Err(FrameError::Invalid)), "case {case}");
        assert_eq!((count, bytes), (0, 0));
        assert!(observe.state().ticket_dropped);
    }
}

#[test]
fn hostile_header_full_bounds_refs_types_nan_utf8_row_alias_and_tail_whole_refuse() {
    for case in 0..13 {
        let cancelled = AtomicBool::new(false);
        let control = control(&cancelled);
        let mut prepared = fixture(&control);
        match case {
            0 => prepared.typed.cells[0].tag = 99,
            1 => prepared.typed.columns[0].kind = 255,
            2 => prepared.typed.columns[0].flags = 255,
            3 => prepared.typed.tables[0].name.start = u32::MAX,
            4 => prepared.typed.rows[0].start = u32::MAX,
            5 => prepared.typed.cells[2].payload = f64::NAN.to_bits(),
            6 => prepared.typed.text[0] = 255,
            7 => prepared.typed.cells[1].payload = u64::MAX,
            8 => prepared.typed.columns[0].reserved[0] = 1,
            9 => {
                let tail = prepared.typed.text_len;
                prepared.typed.text[tail] = b'x';
            }
            10..=12 => (),
            _ => unreachable!(),
        }
        let mut exported = prepared.seal(&control).unwrap();
        match case {
            10 => exported.descriptor.magic = 0,
            11 => exported.descriptor.counts[4] = u32::MAX,
            12 => exported.descriptor.files[0].inode ^= 1,
            _ => (),
        }
        let observe = CloseObservation::begin(&exported.files);
        let maps = super::super::mapping_tests::Observation::begin();
        let (result, count, bytes) = measure(|| exported.adopt(&control));
        assert!(matches!(result, Err(FrameError::Invalid)), "case {case}");
        assert_eq!((count, bytes), (0, 0));
        assert!(observe.state().ticket_dropped);
        assert!(
            maps.releases().0[..maps.releases().1]
                .iter()
                .all(|release| release.result == 0)
        );
    }
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut exported = fixture(&control).seal(&control).unwrap();
    // Row order is generated at builder seal, so corrupt it in an independent
    // attacker-owned sealed object, then prove descriptor identity refusal.
    let attacker = FrameFile::create(4096).unwrap();
    assert_eq!(
        unsafe { libc::pwrite(attacker.fd, [0u32, 0u32].as_ptr().cast(), 8, 0) },
        8
    );
    exported.files[5] = attacker.seal_readonly().unwrap();
    // Supply its real authoritative identity, so this reaches row-order
    // content validation rather than merely the foreign-object check.
    exported.descriptor.files[5] = exported.files[5].identity().unwrap();
    assert!(matches!(exported.adopt(&control), Err(FrameError::Invalid)));
}

#[test]
fn cumulative_original_work_not_reset_and_cancel_deadline_cleanup_order() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut prepared = fixture(&control);
    prepared.capture.budget = Budget::new(3);
    assert!(matches!(
        prepared.seal(&control),
        Err(FrameError::WorkLimit)
    ));
    let exported = fixture(&control).seal(&control).unwrap();
    let remaining = exported.budget.remaining_work();
    let readonly = exported.adopt(&control).unwrap();
    assert!(readonly.budget.remaining_work() < remaining);
    drop(readonly);
    let exported = fixture(&control).seal(&control).unwrap();
    let observe = CloseObservation::begin(&exported.files);
    cancelled.store(true, Ordering::Release);
    let (result, count, bytes) = measure(|| exported.adopt(&control));
    assert!(matches!(result, Err(FrameError::Cancelled)));
    assert_eq!((count, bytes), (0, 0));
    assert!(observe.state().ticket_dropped);
    drop(observe);
    cancelled.store(false, Ordering::Release);
    let exported = fixture(&control).seal(&control).unwrap();
    let observe = CloseObservation::begin(&exported.files);
    let expired = FrameControl::new(&cancelled, Instant::now());
    assert!(matches!(
        exported.adopt(&expired),
        Err(FrameError::Deadline)
    ));
    assert!(observe.state().ticket_dropped);
}

#[test]
fn maximum_20k_64_columns_1point28m_cells_8m_text_same_page_count_sum_refuses_whole() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let plan = PreparationPlan::for_limits(FrameLimits::default()).unwrap();
    assert_eq!(plan.typed_file_count, 6);
    assert_eq!(plan.peak_owned_fd_count, 13);
    assert!(plan.constructing_mapping_bytes + plan.control_allowance_bytes <= MAX_FRAME_BYTES);
    let mut prepared = prepare(FrameLimits::default(), &control);
    // Text is filled to the exact 8MiB boundary, including schema text.
    let names: Vec<String> = (0..64).map(|index| format!("c{index}")).collect();
    let columns: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            column(
                name,
                if index == 63 {
                    ColumnKind::Text
                } else {
                    ColumnKind::Integer
                },
            )
        })
        .collect();
    let table = prepared.add_table("maximal", &columns).unwrap();
    let available = MAX_TEXT_BYTES - prepared.typed.text_len;
    let text = [b'x'; 420];
    let mut cells = [FrameCell::Integer(1); 64];
    let average = available / 20_000;
    let remainder = available % 20_000;
    for row in 0..20_000 {
        let len = average + usize::from(row < remainder);
        cells[63] = FrameCell::Text(std::str::from_utf8(&text[..len]).unwrap());
        prepared.insert_row(table, &cells, &control).unwrap();
    }
    assert_eq!(prepared.typed.cell_len, 1_280_000);
    assert_eq!(prepared.typed.text_len, 8 * 1024 * 1024);
    let exported = prepared.seal(&control).unwrap();
    let mut readonly = exported.adopt(&control).unwrap();
    let tables = readonly.native_tables(8192).unwrap();
    let count = sqlite::execute(
        "SELECT COUNT(*) FROM maximal",
        &[],
        &tables,
        &mut readonly,
        QueryOptions::default(),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(count.rows, [vec![SqlCell::Integer(20_000)]]);
    assert!(!count.truncated);
    for query in [
        "SELECT SUM(c0) FROM maximal",
        "SELECT SUM(c0), MIN(c1), MAX(c2) FROM maximal",
    ] {
        assert_eq!(
            sqlite::execute(
                query,
                &[],
                &tables,
                &mut readonly,
                QueryOptions::default(),
                &mut || Ok(())
            ),
            Err(SqlError::WorkLimit)
        );
    }
}

#[test]
fn native_partial_mapping_failure_cleans_real_maps_and_fds_before_ticket_refund() {
    use std::process::Command;
    const CHILD: &str = "SQL_FRAME_PARTIAL_MMAP_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let filter = current_test_filter(
            "native_partial_mapping_failure_cleans_real_maps_and_fds_before_ticket_refund",
        );
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &filter, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output
                .stderr
                .windows(b"ACTUAL-PARTIAL-MAP-CHILD".len())
                .any(|bytes| bytes == b"ACTUAL-PARTIAL-MAP-CHILD"),
            "a zero-test child is not a native partial-map cleanup witness"
        );
        return;
    }
    eprintln!("ACTUAL-PARTIAL-MAP-CHILD");
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let exported = fixture(&control).seal(&control).unwrap();
    let close = CloseObservation::begin(&exported.files);
    let maps = super::super::mapping_tests::Observation::begin();
    let pages = {
        let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
        statm
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let mut original = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_AS, original.as_mut_ptr()) },
        0
    );
    let original = unsafe { original.assume_init() };
    let limit = libc::rlimit {
        rlim_cur: pages * page + page,
        rlim_max: original.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) }, 0);
    // Real kernel ENOMEM: one 4096-byte text map fits; the next map cannot.
    let result = exported.adopt(&control);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &original) }, 0);
    assert!(matches!(result, Err(FrameError::Capacity)));
    let (releases, count) = maps.releases();
    assert_eq!(
        count, 2,
        "one successful RO map + private parent provenance"
    );
    assert!(releases[..count].iter().all(|release| release.result == 0));
    assert!(close.state().ticket_dropped);
}

#[test]
fn native_close_uncertainty_and_hidden_writer_failstop_without_credit_refund() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    const CHILD: &str = "SQL_FRAME_FATAL_CHILD";
    if let Some(case) = std::env::var_os(CHILD) {
        eprintln!("ACTUAL-CLOSE-UNCERTAINTY-CHILD");
        let core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) }, 0);
        NO_REFUND.with(|flag| flag.set(true));
        let cancelled = AtomicBool::new(false);
        let control = control(&cancelled);
        if case == "close" {
            let exported = fixture(&control).seal(&control).unwrap();
            assert_eq!(unsafe { libc::close(exported.files[0].fd) }, 0);
            // Actual EBADF on owning close, NOT a simulated failure hook.
            drop(exported);
        } else {
            let _lease = unsafe {
                PreparationLease::from_precharged_owner(
                    ComponentTicket,
                    PreparationPlan::for_limits(limits()).unwrap(),
                )
            };
            let file = FrameFile::create(4096).unwrap();
            let map = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    file.fd,
                    0,
                )
            };
            assert_ne!(map, libc::MAP_FAILED);
            // Production sealing refuses actual EBUSY with a hidden writer,
            // before any lease destructor can falsely refund its live pages.
            let _ = file.seal_readonly();
        }
        panic!("cleanup uncertainty returned instead of retaining until reap");
    }
    for case in ["close", "writer"] {
        let filter = current_test_filter(
            "native_close_uncertainty_and_hidden_writer_failstop_without_credit_refund",
        );
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &filter, "--nocapture"])
            .env(CHILD, case)
            .env("SQL_FRAME_EXPECT_NO_REFUND", "1")
            .output()
            .unwrap();
        assert_eq!(output.status.signal(), Some(libc::SIGABRT));
        assert!(
            output
                .stderr
                .windows(b"ACTUAL-CLOSE-UNCERTAINTY-CHILD".len())
                .any(|bytes| bytes == b"ACTUAL-CLOSE-UNCERTAINTY-CHILD"),
            "a zero-test child is not an actual native fail-stop witness"
        );
        assert!(
            !output
                .stdout
                .windows(b"TICKET-REFUNDED".len())
                .any(|bytes| bytes == b"TICKET-REFUNDED")
        );
    }
}

#[test]
fn exact_layout_sizes_report_without_physical_or_allocator_backing_claim() {
    let plan = PreparationPlan::for_limits(FrameLimits::default()).unwrap();
    eprintln!(
        "component PLAN {:?}; Lease<()> {}; Prepared<()> {}; Exported<()> {}; ReadOnly<()> {}; Pending<()> {}; GLOBALS=none (test TLS excluded)",
        plan,
        size_of::<PreparationLease<()>>(),
        size_of::<PreparedFrame<()>>(),
        size_of::<ExportedFrame<()>>(),
        size_of::<ReadOnlyFrame<()>>(),
        size_of::<PendingAdoption<()>>()
    );
    assert_eq!(plan.descriptor_bytes, 208);
    assert_eq!(plan.file_owner_bank_bytes, 24);
    assert_eq!(plan.validation_local_bytes, 316);
    assert_eq!(plan.control_allowance_bytes, 65536);
    assert!(size_of::<PendingAdoption<()>>() < CONTROL_BYTES);
}

#[test]
fn received_readonly_fd_bank_adopts_same_objects_and_last_owner_drops_before_ticket() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let exported = fixture(&control).seal(&control).unwrap();
    let bank = duplicate_bank(&exported);
    let close = CloseObservation::begin(&exported.files);
    let (readonly, count, bytes) = measure(|| exported.adopt_received(bank, &control));
    assert_eq!((count, bytes), (0, 0));
    let mut readonly = readonly.unwrap();
    assert_eq!(
        close.state().count,
        [1; 6],
        "authoritative originals closed only after complete adoption"
    );
    assert!(
        !close.state().ticket_dropped,
        "recipient owners still hold SAME backing"
    );
    let tables = readonly.native_tables(8192).unwrap();
    let result = sqlite::execute(
        "SELECT COUNT(*), SUM(id) FROM visible",
        &[],
        &tables,
        &mut readonly,
        QueryOptions::default(),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(
        result.rows,
        [vec![SqlCell::Integer(2), SqlCell::Integer(10)]]
    );
    drop(readonly);
    assert_eq!(close.state().count, [2; 6]);
    assert!(close.state().ticket_dropped);
}
