#!/usr/bin/env bash
# Run from the Flower checkout root. ISOLATED lab only; never serving daemon.
set -euo pipefail
harness=src/evaluator/sql_worker/harness
manifest="$harness/Cargo.toml"
target=/workspace/sql-worker-kkqabc3nkirfazq6-target
probe=/workspace/sql-worker-kkqabc3nkirfazq6-probe.so
cc -O2 -shared -fPIC -std=c11 -Wall -Wextra -Werror "$harness/probe.c" -ldl -o "$probe"
cargo fmt --manifest-path "$manifest" --check
for allocator in system mimalloc; do
    features=()
    if [[ "$allocator" == mimalloc ]]; then features=(--features mimalloc-probe); fi
    echo "code=ALLOCATOR_SUITE name=$allocator"
    cargo clippy --offline --locked --manifest-path "$manifest" --target-dir "$target" -j 2 "${features[@]}" --all-targets -- -D warnings
    # Native startup diagnostics share one fixed counter window; run serial.
    env LD_PRELOAD="$probe" cargo test --offline --locked --manifest-path "$manifest" --target-dir "$target" -j 2 "${features[@]}" -- --test-threads=1 --nocapture
    # Uninstrumented concurrent regressions; optional interposer-only cases do
    # not execute here. The serial run above executes the real diagnostics.
    cargo test --offline --locked --manifest-path "$manifest" --target-dir "$target" -j 2 "${features[@]}" -- --test-threads=2
    env LD_PRELOAD="$probe" cargo test --release --offline --locked --manifest-path "$manifest" --target-dir "$target" -j 2 "${features[@]}" -- --test-threads=1 --nocapture
    cargo build --release --offline --locked --manifest-path "$manifest" --target-dir "$target" -j 2 "${features[@]}" --bin native-worker-diagnostic
    env LD_PRELOAD="$probe" "$target/release/native-worker-diagnostic"
done
# Deliberately no automatic rm: inspect successful status, then remove ONLY the
# unique target/probe above. Do not touch shared targets, caches or other owners.
