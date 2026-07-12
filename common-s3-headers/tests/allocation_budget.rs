// allocation_budget.rs — regression guard for the presign hot path's allocation
// count.
//
// The SigV4 signing key is stable for a UTC day per (region, service); callers
// that cache it (e.g. jsonlog's SigningKeyCache) use `presign_get_with_key` to
// skip the 4-stage HMAC key derivation. This single test asserts:
//   1. `presign_get_with_key` allocates strictly fewer times than the full
//      `presign_get` (which re-derives the key) — the cache must pay off.
//   2. `presign_get_with_key` stays within a fixed budget, so a regression that
//      adds allocations to the hot path is caught.
//
// It is a single test in its own integration-test binary so the
// `#[global_allocator]` does not collide with anything else and the count is
// measured as a clean delta around one call (no parallel-test pollution).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use common_s3_headers::aws_math::get_signature_key;
use common_s3_headers::{presign_get, presign_get_with_key, S3DateTime};
use time::OffsetDateTime;
use url::Url;

struct Counting;

static COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNT.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn count_allocations<F: FnOnce()>(f: F) -> usize {
    COUNT.store(0, Ordering::SeqCst);
    f();
    COUNT.load(Ordering::SeqCst)
}

#[test]
fn presign_allocation_budget() {
    let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
    let datetime = OffsetDateTime::from_unix_timestamp(0).unwrap();
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    // Full path: derives the signing key on every call.
    let full = count_allocations(|| {
        let _ = presign_get(
            &url,
            "AKIAIOSFODNN7EXAMPLE",
            secret,
            "us-east-1",
            "s3",
            S3DateTime::UnixTimestamp(datetime.unix_timestamp()),
            3600,
        );
    });

    // Cached-key path: the key is supplied, skipping the 4-stage HMAC chain.
    let key = get_signature_key(&datetime, secret, "us-east-1", "s3");
    let steady = count_allocations(|| {
        let _ = presign_get_with_key(
            &url,
            "AKIAIOSFODNN7EXAMPLE",
            "us-east-1",
            "s3",
            datetime,
            3600,
            &key,
        );
    });

    assert!(
        steady < full,
        "cached-key presign ({steady} allocs) must allocate less than full presign ({full} allocs)"
    );

    // Budget guard: the steady-state presign must stay lean. If a change pushes
    // this above the budget, investigate before raising it. (Measured baseline:
    // ~32 allocations; the small margin absorbs run-to-run variance.)
    const STEADY_BUDGET: usize = 35;
    assert!(
        steady <= STEADY_BUDGET,
        "presign_get_with_key allocated {steady} times, exceeding the {STEADY_BUDGET}-allocation budget"
    );
}
