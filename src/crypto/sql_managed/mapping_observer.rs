//! Test-only exact mapping-owner/syscall evidence, not VA residency inference.
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
#[derive(Clone, Copy, Default, Debug)]
pub(in super::super) struct Release {
    pub id: u64,
    pub address: usize,
    pub bytes: usize,
    pub erased: bool,
    pub result: i32,
}
#[derive(Clone, Copy)]
struct State {
    active: bool,
    attempts: usize,
    len: usize,
    overflow: bool,
    releases: [Release; 16],
    fail_next: bool,
}
impl State {
    const EMPTY: Self = Self {
        active: false,
        attempts: 0,
        len: 0,
        overflow: false,
        releases: [Release {
            id: 0,
            address: 0,
            bytes: 0,
            erased: false,
            result: 0,
        }; 16],
        fail_next: false,
    };
}
thread_local! { static STATE: Cell<State> = const { Cell::new(State::EMPTY) }; }
static ID: AtomicU64 = AtomicU64::new(1);
pub(super) fn next_id() -> u64 {
    ID.fetch_add(1, Ordering::Relaxed)
}
pub(super) fn mapping_attempt() {
    STATE.with(|state| {
        let mut s = state.get();
        if s.active {
            s.attempts += 1;
        }
        state.set(s);
    });
}
pub(super) fn fail_unmap() -> bool {
    STATE.with(|state| {
        let mut s = state.get();
        let fail = s.fail_next;
        s.fail_next = false;
        state.set(s);
        fail
    })
}
pub(super) fn released(release: Release) {
    STATE.with(|state| {
        let mut s = state.get();
        if s.active {
            if s.len == s.releases.len() {
                s.overflow = true;
            } else {
                s.releases[s.len] = release;
                s.len += 1;
            }
        }
        state.set(s);
    });
}
pub(in super::super) struct Observation;
impl Observation {
    pub fn begin() -> Self {
        STATE.with(|state| {
            assert!(!state.get().active);
            state.set(State {
                active: true,
                ..State::EMPTY
            });
        });
        Self
    }
    pub fn attempts(&self) -> usize {
        STATE.with(|state| state.get().attempts)
    }
    pub fn releases(&self) -> ([Release; 16], usize) {
        STATE.with(|state| {
            let s = state.get();
            assert!(!s.overflow);
            (s.releases, s.len)
        })
    }
    /// Fault injection changes the actual munmap syscall address to unaligned,
    /// producing real EINVAL while the exact original map remains locked.
    pub fn fail_next_unmap(&self) {
        STATE.with(|state| {
            let mut s = state.get();
            s.fail_next = true;
            state.set(s);
        });
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        STATE.with(|state| state.set(State::EMPTY));
    }
}
