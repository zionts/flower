#!/usr/bin/env bash
# Isolated current-pinned-source harness. No shared target/resources/servers.
set -euo pipefail
cd "$(dirname "$0")/../../.."
build=$(mktemp -d "${TMPDIR:-/tmp}/flower-sql-ingress-3dyrmki6.XXXXXX")
trap 'rm -rf "$build"' EXIT
python3 src/service/sql_ingress/reference.py "$build"
mapfile -t externs < "$build/externs"
CARGO_INCREMENTAL=0 SQL_INGRESS_REFERENCE="$build/reference.rs" rustc --edition=2024 -C "opt-level=${SQL_INGRESS_OPT_LEVEL:-0}" --test src/service/sql_ingress/harness.rs -o "$build/tests" \
    -L dependency=target/debug/deps "${externs[@]}"
"$build/tests" --test-threads=2 "$@"
