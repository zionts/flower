#!/usr/bin/env bash
# Isolated concat-argument allocation observer; needs the parent's built rlibs.
set -euo pipefail
cd "$(dirname "$0")/../../.."
out="${TMPDIR:-/tmp}/flower-sql-arguments-${USER:-test}-$$"
trap 'rm -f "$out"' EXIT
one() { local paths=(target/debug/deps/lib"$1"-*.rlib); [[ -f "${paths[0]}" ]] || { echo "missing existing $1 rlib; build Flower first" >&2; exit 1; }; printf '%s' "${paths[0]}"; }
rustc --edition=2024 --test src/evaluator/sql_bridge/arguments_allocator_harness.rs -o "$out" -L dependency=target/debug/deps \
    --extern "libc=$(one libc)" --extern "ryu_js=$(one ryu_js)" \
    --extern "serde_json=$(one serde_json)" --extern "rustc_hash=$(one rustc_hash)"
"$out" --test-threads=1 "$@"
