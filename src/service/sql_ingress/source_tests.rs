//! Additional source/payload ownership probes; diagnostics are counts only.
use super::*;
use crate::allocation_probe;
use std::sync::Arc;
use std::time::Duration;
static NEVER: AtomicBool = AtomicBool::new(false);

#[test]
fn borrowed_raw_value_is_not_a_prepaid_depth_or_allocation_bound() {
    // Pinned serde_json's RawValue scanner uses its scratch Vec as a container
    // stack. Merely choosing a borrowed result does not make ingress quota-first.
    // This is an alternative-parser positive control, not the actual Value path.
    let success = format!("{}0{}", "[".repeat(1024), "]".repeat(1024));
    let malformed = format!("{}invalid", "[".repeat(1024));
    for (body, okay) in [(success.as_bytes(), true), (malformed.as_bytes(), false)] {
        let (result, n, bytes) = allocation_probe::measure(|| {
            serde_json::from_slice::<&serde_json::value::RawValue>(body)
        });
        assert_eq!(result.is_ok(), okay);
        assert!(n > 0 && bytes >= 1024);
        println!(
            "borrowed_raw_value_positive_control: success={} input_bytes={} allocation_operations={} cumulative_requested_bytes={}",
            okay,
            body.len(),
            n,
            bytes
        );
    }
}

struct RetainedBody {
    raw: Vec<u8>,
    released: Arc<AtomicBool>,
}
impl AsRef<[u8]> for RetainedBody {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}
impl Drop for RetainedBody {
    fn drop(&mut self) {
        self.released.store(true, Ordering::Release);
    }
}

struct StopInReserve(AtomicUsize);
impl Check for StopInReserve {
    fn check(&self) -> Result<(), Error> {
        if self.0.fetch_add(1, Ordering::Relaxed) == 2 {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
}
#[test]
fn deadline_between_slot_and_byte_admission_returns_provisional_slot() {
    let pool = Pool::new(8 * 1024 * 1024, 4);
    let stop = StopInReserve(AtomicUsize::new(0));
    let (result, n, bytes) =
        allocation_probe::measure(|| Preflight::new(&pool, Limits::default(), &stop));
    assert_eq!(result.err(), Some(Error::Deadline));
    assert_eq!((n, bytes), (0, 0));
    assert_eq!(pool.retained(), (0, 0));
}
#[test]
fn actual_bytes_owner_retains_original_body_through_header_borrow() {
    // Mirrors ingress's Bytes::from_owner(Buffered{Vec,_retained:Arc<Input>}).
    // The production ingress owns its real admission lease; this test observes
    // lifetime/drop only and does not pretend to acquire that private pool.
    let released = Arc::new(AtomicBool::new(false));
    let original = axum::body::Bytes::from_owner(RetainedBody {
        raw: br#"{"name":"native","args":{"raw":"retained"},"credentials":"jwt"}"#.to_vec(),
        released: released.clone(),
    });
    let body = original.clone();
    drop(original);
    assert!(!released.load(Ordering::Acquire));
    let pool = Pool::new(8 * 1024 * 1024, 4);
    let check = Control::new(Instant::now() + Duration::from_secs(30), &NEVER);
    let mut scratch = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let (result, n, bytes) =
        allocation_probe::measure(|| scratch.parse(body.as_ref(), Transport::Query, &check));
    assert_eq!((n, bytes), (0, 0));
    let header = result.unwrap();
    drop(scratch);
    assert_eq!(pool.bytes.load(Ordering::Acquire), 0);
    assert!(!released.load(Ordering::Acquire));
    assert_eq!(header.args_json(), br#"{"raw":"retained"}"#);
    // All header borrows have ended before this Drop. A header cannot be used
    // after body Drop in safe Rust; no borrowed source pointer is stored in maps.
    drop(body);
    assert!(released.load(Ordering::Acquire));
}
