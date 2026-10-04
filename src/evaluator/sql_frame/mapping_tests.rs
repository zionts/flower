//! Test-only fixed mapping-owner lifecycle observer; never production state.
//! Address residency cannot identify a released mapping: another test/thread
//! can immediately reuse its VA. IDs distinguish exact owners and record the
//! real munmap result, without an allocator or a process-global test lock.
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Region {
    pub id: u64,
    pub address: usize,
    pub bytes: usize,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Release {
    pub region: Region,
    pub result: i32,
    pub errno: i32,
}
#[derive(Clone, Copy)]
struct State {
    active: bool,
    len: usize,
    overflow: bool,
    releases: [Release; 32],
}
impl State {
    const EMPTY: Self = Self {
        active: false,
        len: 0,
        overflow: false,
        releases: [Release {
            region: Region {
                id: 0,
                address: 0,
                bytes: 0,
            },
            result: 0,
            errno: 0,
        }; 32],
    };
}
thread_local! {
    static STATE: Cell<State> = const { Cell::new(State::EMPTY) };
}
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
pub(super) fn next_id() -> u64 {
    NEXT_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("test mapping identity exhausted")
}
pub(super) fn released(region: Region, result: i32) {
    STATE.with(|state| {
        let mut current = state.get();
        if !current.active {
            return;
        }
        let errno = if result == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        };
        if current.len == current.releases.len() {
            current.overflow = true;
        } else {
            current.releases[current.len] = Release {
                region,
                result,
                errno,
            };
            current.len += 1;
        }
        state.set(current);
    });
}
pub(super) struct Observation;
impl Observation {
    pub fn begin() -> Self {
        STATE.with(|state| {
            assert!(!state.get().active, "nested mapping lifecycle observation");
            state.set(State {
                active: true,
                ..State::EMPTY
            });
        });
        Self
    }
    pub fn releases(&self) -> ([Release; 32], usize) {
        STATE.with(|state| {
            let current = state.get();
            assert!(!current.overflow, "mapping lifecycle evidence overflow");
            (current.releases, current.len)
        })
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        STATE.with(|state| state.set(State::EMPTY));
    }
}
