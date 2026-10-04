# Reproduce finite-profile SQL managed crypto checks

All manifests/build outputs are **external to Flower**, in a unique directory owned by the current session. Do not share/erase parent targets, dependency registries or `/cache`. The harness reads **current actual** frame/SQLite/root allocation-probe modules and extracts current ordinary AES/AAD/mount helper bodies into its **test-only reference**. No serving activation, parent Cargo/import change, credentials, environment dump, live key or source payload is required.

## Exact independent manifest

Choose an unused `H=/workspace/sql-managed-profile-UNIQUE` (this run used `/workspace/sql-managed-profile-yom3`). Put this in `$H/Cargo.toml`:

```toml
[package]
name = "sql-managed-harness"
version = "0.0.0"
edition = "2024"
build = "/workspace/flower/src/crypto/sql_managed/build_harness.rs"
[lib]
path = "/workspace/flower/src/crypto/sql_managed/harness.rs"
[dependencies]
libc = "=0.2.189"
libsqlite3-sys = { version = "=0.38.2", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
aws-lc-rs = "=1.18.1"
ed25519-dalek = "=3.0.0"
sha2 = "=0.11.0"
zeroize = "=1.9.0"
base64 = "=0.23.1"
anyhow = "=1.0.102"
aes-gcm = { version = "=0.10.3", default-features = false, features = ["aes", "zeroize"] }
aes = { version = "=0.8.4", default-features = false, features = ["zeroize"] }
ghash = { version = "=0.5.1", default-features = false, features = ["zeroize"] }
polyval = { version = "=0.6.2", default-features = false, features = ["zeroize"] }
```

Copy `Harness.Cargo.lock` from this subtree to `$H/Cargo.lock`. Its exact resolution/checksums, not unconstrained latest releases, define the observation. All checks below use `--locked --offline`, **two build jobs**, no incremental compilation and **no shared compiler cache** (`RUSTC_WRAPPER=`). Reference-only AWS-LC/serde/base64/anyhow do not become production loader APIs.

```sh
cc -shared -fPIC -O2 -Wall -Wextra -Werror \
  /workspace/flower/src/crypto/sql_managed/native_probe.c -o "$H/native-probe.so"
cd "$H"
export RUSTC_WRAPPER= CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
export SQL_MANAGED_NATIVE_PROBE=1 LD_PRELOAD="$H/native-probe.so"
export CARGO_TARGET_DIR="$H/target"
cargo test --locked --offline --lib -- --test-threads=1
cargo clippy --locked --offline --all-targets -- -D warnings
rustfmt --edition 2024 --config skip_children=true --check \
  /workspace/flower/src/crypto/sql_managed.rs \
  /workspace/flower/src/crypto/sql_managed/*.rs
```

**Current normal result:113/113 PASS**, including the real current frame mapping-address-reuse observer and actual root allocator positive/unwind test. Exact groups:47 managed,18 profile,29 current frame,18 SQLite,1 root allocator. The earlier87 count is historical and NOT this revision's evidence. Profile helper-entry test returns without its selector in the outer suite, but is substantively invoked by four independent fork/exec regressions; do not add those child1-test summaries again to the outer113 count.

The four real child-process tests lower limits only—never raise/privilege-waive them—and prove:64KiB soft+hard refusal before any mapping/private read; exact143360 soft+hard one-capsule success/second-loan refusal/startup singleton; post-startup lower64KiB partial-lock failure and complete wipe/unmap; and an injected **actual munmap(EINVAL)** retaining fatal strong-owner/credit HOLD. The last fault changes the syscall pointer to an unaligned address; fixture-only later kernel cleanup does NOT return held credit. Invalid/infinite/overflow/unknown-other-owner cases, explicit nonzero other locks, software-cap lowering, native/original-Control mismatch, cancellation/deadline/partial construction/unwind, cross-thread drop/concurrent loan, outer-handle lifetime, unique-Control identity versus address reuse and reset-without-credit-release are independently covered.

## No-warm-up actual native C + Rust observations

Run **each filter as a separate fresh process**, not after another RustCrypto test:

```sh
cargo test --locked --offline --lib \
  profile_owned_mount_cold_ticket_mapping_aes_jwt_and_drop_zero_c_zero_rust \
  -- --test-threads=1 --nocapture
cargo test --locked --offline --lib \
  fresh_thread_schedule_init_success_and_errors_allocate_zero_native_and_rust \
  -- --test-threads=1 --nocapture
```

Both configure a2MiB stack **before spawn** and verify actual pthread extent2097152 before observation. Each has five fresh-thread cases: load/sign, load/verify, bad wrap tag, bad material tag after DEK initialization, wrong wrapping key. Both first AES schedules are constructed inside observation without RustCrypto warm-up. The **new strict profile filter also observes ticket claim, all five mandatory locked/DONTDUMP mappings, owned mount destination after the trusted Grant, real AES/JWT work, typed Drop and all actual unmaps**: every case0C/0Rust calls/0Rust bytes. Startup profile allocation, parser allocation and thread creation/native/kernel/TLS metadata are outside this component observation and remain separately admitted parent terms. The legacy filter retains compatibility fixtures, including its extra caller-owned locked mount page outside the Workspace ledger; it is not a production numeric-constructor bypass.

**Selector AND preload are mandatory.** Without them native tests intentionally return unobserved; that is NOT a native allocator proof. The Linux/glibc C probe covers malloc/calloc/realloc/reallocarray and aligned allocation families through `__libc_*` forwarding. The positive control must report **5C/0Rust**, using volatile indirect C calls so optimized malloc elision cannot invalidate the counter test. The imported actual root Rust probe separately proves3allocation operations/128requested bytes and unwind reset. No all-libc/macOS claim.

## Forced software and optimized release

With the exported environment above, run each command separately; targets stay unique:

```sh
RUSTFLAGS='--cfg aes_force_soft --cfg polyval_force_soft' \
CARGO_TARGET_DIR="$H/target-soft" \
  cargo test --locked --offline --lib mounted_tests -- --test-threads=1 --nocapture
RUSTFLAGS='--cfg aes_force_soft --cfg polyval_force_soft' \
CARGO_TARGET_DIR="$H/target-soft" \
  cargo test --locked --offline --lib profile::tests -- --test-threads=1 --nocapture
# Repeat BOTH fresh-process filters with these same RUSTFLAGS/target-soft settings.

CARGO_TARGET_DIR="$H/target-release" \
  cargo test --release --locked --offline --lib mounted_tests -- --test-threads=1 --nocapture
CARGO_TARGET_DIR="$H/target-release" \
  cargo test --release --locked --offline --lib profile::tests -- --test-threads=1 --nocapture
# Repeat BOTH fresh-process filters with --release and target-release.
```

Focused counts are **15 mounted +18 profile =33**, not the historical11. Current forced-software33/33 and both separate cold filters PASS. Current optimized release33/33 and both separate cold filters PASS; the initial release compilation worker interruption was resumed, never counted as a completed check. Expected test-only unwind panic messages are caught; they print fixed fixture text and never keys/JWT/source payloads.

Exact dependency feature evidence (repeat against the integrated parent manifest too):

```sh
cargo tree --locked --offline -e features -i aes
cargo tree --locked --offline -e features -i ghash
cargo tree --locked --offline -e features -i polyval
cargo tree --locked --offline -e features -p aes-gcm
```

Pinned POLYVAL autodetect's missing Drop still mandates the full dead-owner mapped scrub; do not infer a newer fix into0.10.3 from issue closure. The unmodified AES0.8.4 upstream round-key test1/1 PASS is preserved **historical unchanged-dependency** evidence, not a rerun of this new profile. To repeat it, use an independent source copy and target, never patch/remove registry/cache/parent trees:

```sh
CARGO_TARGET_DIR="$H/target-upstream-aes" \
  cargo test --manifest-path "$H/upstream-aes/Cargo.toml" \
  --no-default-features --features zeroize zeroize_works -- --nocapture
```

## Non-test signature/layout and honest admission boundary

This run additionally compiled and executed a production-only external `layout.rs` entry point at `$H/layout.rs`, with direct current module imports and a compile-checked `Workspace::new(profile.claim(original)?, native, original)` signature. Its modules/entry point are `cfg(not(test))` (empty cfg(test) main), so clippy's all-targets test build cannot accidentally substitute the numeric fixture overload. The retained `$H/Cargo.toml` registers that bin; `cargo run --locked --offline --bin layout` repeats the scalar measurement on its actual selected/pthread-verified2MiB fixture thread.

Measured production (non-test) layout:143360 locked maps; Workspace528 +original Control88 =616owner bytes; profile allocation232 +handle8 +global atomics9 =249control bytes; each slot atomic8bytes. Capsule software with the verified2097152fixture stack and zero excluded other-native term=2241128; initial one-profile total=2241377. Test-only per-map observer IDs add40Workspace bytes (fixture owner sum656, profile total2241417); do not use test owner layout as the production ledger. See PROFILE.md for exact owner formulas, OS/software/slot requirements and startup operator recipes. None of these numbers proves allocator backing/guard/TLS/signal/Grant/parser/guest/kernel/whole-process ownership or source/controller certification.

Only after all commands exit, verify the frozen owned-source hashes and remove **this session's finished** `target`, `target-soft`, `target-release` (and optional own upstream target). Keep the external manifest/lock/layout/references if the parent needs them. Never remove `/workspace/flower/target`, peers' targets, `/cache`, or stop peer/parent servers. This child started no service and performed no configuration/resource increase/commit/push/PR/activation.

## Foundation exact-inventory reconciliation (October 4, 2026)

The durable runner `/workspace/reports/run-managed-profile-audit-v1.sh` repeated
the exact frozen native test inventory and all normal native-interposed checks.
The total **113/113** was correct; the old subgroup labels were not: the actual
test list is **47 managed +18 profile +29 frame +18 SQLite +1 root allocator**.
The completed native run, both separate fresh-process cold selectors, strict
all-target Clippy, and before/after owned/stable-input hashes all passed. This
repeat used the unchanged runtime sources and actual native interposer; it is
still component evidence, not source/controller/whole-node/serving readiness.
