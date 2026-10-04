#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
build=$(mktemp -d "${TMPDIR:-/tmp}/flower-sql-ingress-clippy-3dyrmki6.XXXXXX")
trap 'rm -rf "$build"' EXIT
python3 src/service/sql_ingress/reference.py "$build"
mapfile -t externs < "$build/externs"
CARGO_INCREMENTAL=0 SQL_INGRESS_REFERENCE="$build/reference.rs" clippy-driver --edition=2024 --test src/service/sql_ingress/harness.rs -o "$build/tests" \
    -L dependency=target/debug/deps "${externs[@]}" -D warnings
