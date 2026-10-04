#!/usr/bin/env python3
"""Prepare actual-source reference before any allocator observation.

Never changes evaluator/schema/root Cargo. The generated isolated module embeds
verbatim current HttpMethod/TerminalMethod serde+validation and registry build;
it is not an independently guessed reference schema. Original files are hashed.
"""
from pathlib import Path
import hashlib
import sys

root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1])
evaluator_path = root / 'src/evaluator.rs'
sql_path = root / 'src/evaluator/sql.rs'
registry_path = root / 'src/evaluator/sql_registry.rs'
evaluator = evaluator_path.read_text()
sql = sql_path.read_text()

def between(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin)]

http = between(evaluator, '#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]\n#[serde(rename_all = "lowercase")]\npub enum MethodKind', '#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]\n#[serde(deny_unknown_fields, rename_all = "camelCase")]\npub struct MaintenanceMethod')
terminal = between(sql, '#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]\n#[serde(deny_unknown_fields, rename_all = "camelCase")]\npub(crate) struct TerminalMethod', '#[cfg(test)]\n#[path = "sql/metadata_tests.rs"]')
identifier = between(sql, 'pub(crate) fn identifier', 'fn text(')
reference = 'use serde::{Deserialize, Serialize};\nuse std::collections::BTreeMap;\n' + http
reference += '\npub(crate) mod sql {\nuse serde::{Deserialize, Serialize};\nuse std::collections::BTreeSet;\n' + identifier + terminal + '\n}\n'
reference += '#[path = ' + repr(str(registry_path)).replace("'", '"') + ']\nmod sql_registry;\n'
reference += '''
pub(crate) fn registry(methods: &BTreeMap<String, HttpMethod>) -> anyhow::Result<serde_json::Value> {
    for method in methods.values() {
        if let Some(terminal) = &method.terminal { terminal.validate().map_err(anyhow::Error::msg)?; }
    }
    sql_registry::build(methods)
}
'''
(out / 'reference.rs').write_text(reference)
for path in [evaluator_path, sql_path, registry_path, root / 'Cargo.lock']:
    print(f'reference sha256={hashlib.sha256(path.read_bytes()).hexdigest()} path={path.relative_to(root)}')

# Explicit versions and dependency-source roots, rather than an arbitrary first
# glob of potentially stale/incompatible rlibs. These are current root-lock pins.
import tomllib
lock = tomllib.loads((root / 'Cargo.lock').read_text())
packages = {p['name']: p['version'] for p in lock['package']}
chosen = {
    'libc': 'cfc6bd596224c782',
    'serde': '6359ce932656ff86',
    'serde_json': '64bf0901f36ff9e8',
    'axum': '615ebcd1fa6ac256',
    'anyhow': '95160b83a69d28f1',
}
externs = []
for name, stamp in chosen.items():
    rlib = root / f'target/debug/deps/lib{name}-{stamp}.rlib'
    dep = root / f'target/debug/deps/{name}-{stamp}.d'
    if not rlib.is_file() or not dep.is_file():
        raise SystemExit(f'Missing pinned artifact {name}; ask parent to build current dependencies')
    expected = f'/{name}-{packages[name]}/src/'
    if expected not in dep.read_text():
        raise SystemExit(f'{name} artifact does not match actual Cargo.lock {packages[name]}')
    print(f'artifact sha256={hashlib.sha256(rlib.read_bytes()).hexdigest()} package={name}@{packages[name]} stamp={stamp}')
    externs.extend(['--extern', f'{name}={rlib}'])
(out / 'externs').write_text('\n'.join(externs))
