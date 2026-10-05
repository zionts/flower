import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { accumulator, addLine, families, finish, parseArgs, parseLine } from './conflict-diagnostics.mjs';

function report(overrides = {}) {
  return {
    version: 1, diagnostic_only: true, claim: 'not_safe_repairability', event: 1,
    event_limit: 1000, event_limit_reached: false, check_limit: 4096,
    checks_inspected: 9, dependency_checks_total: 2, dependency_checks_inspected: 2,
    truncated: false, window_marker_unavailable: false, ignoring_all_cell_versions_upper_bound: 'yes',
    mismatches: { ...Object.fromEntries(families.map((name) => [name, 0])), cell_record: 1 },
    names: [{ name: 'org.spend', source_record: 0, cell_record: 1, marker: 0, window: 0 }],
    ...overrides,
  };
}
const line = (value) => `DEBUG flower::conflicts: flower_conflict_diagnostic ${JSON.stringify(value)}`;
const truncated = () => report({ truncated: true, ignoring_all_cell_versions_upper_bound: 'unknown',
  check_limit: 8, checks_inspected: 8, dependency_checks_inspected: 1 });
// Matches a disposable log captured from the installed process-compose v1.110.0.
const wrapped = (message, overrides = {}) => JSON.stringify({ level: 'info', process: 'flower', replica: 0, message, ...overrides });
const script = fileURLToPath(new URL('./conflict-diagnostics.mjs', import.meta.url));
const cli = (input, args = []) => spawnSync(process.execPath, [script, ...args], { input, encoding: 'utf8' });

// The original six observable contracts, with realistic bounded/target fixtures.
test('reads bounded multi-family records; never mistakes a truncated cell prefix for cell-only', () => {
  const summary = accumulator(['org.spend']);
  addLine(summary, 'unrelated server output');
  addLine(summary, line(report()));
  addLine(summary, line(report({ mismatches: { ...report().mismatches, source_record: 1 }, ignoring_all_cell_versions_upper_bound: 'no' })));
  addLine(summary, line(truncated()));
  const result = finish(summary);
  assert.equal(result.certificate_failures_observed, 3);
  assert.equal(result.complete_scans, 2);
  assert.equal(result.truncated_scans, 1);
  assert.deepEqual(result.ignoring_all_cell_versions, { yes: 1, no: 1, unknown: 1 });
  assert.equal(result.possible_fraction_upper_bound_in_observed_sample, 2 / 3);
  assert.equal(result.complete_yes_fraction_in_observed_sample, 1 / 3);
  assert.equal(result.mismatch_counts.cell_record, 3);
  assert.equal(result.candidates_with_mismatch.source_record, 1);
  assert.equal(result.names[0].mismatch_counts.cell_record, 3);
});

test('malformed and contradictory diagnostics are counted, never emitted verbatim', () => {
  const summary = accumulator();
  addLine(summary, 'flower_conflict_diagnostic secret-credential');
  addLine(summary, line(report({ truncated: true })));
  addLine(summary, line(report({ ignoring_all_cell_versions_upper_bound: 'no' })));
  addLine(summary, line(report({ names: [{ ...report().names[0], name: 'raw:session-key' }] })));
  assert.equal(summary.malformed_records, 4);
  assert.equal(summary.certificate_failures_observed, 0);
  assert.equal(finish(summary).possible_fraction_upper_bound_in_observed_sample, null);
  assert.equal(JSON.stringify(summary).includes('credential'), false);
});

test('parser output is bounded by its own configured names, not changing input labels', () => {
  const allowed = Array.from({ length: 16 }, (_, n) => `name${n}`);
  const summary = accumulator(allowed);
  for (let n = 0; n < 17; n++) {
    addLine(summary, line(report({ names: [{ ...report().names[0], name: `name${n}` }] })));
  }
  assert.deepEqual(summary.names.map((name) => name.name), allowed);
  assert.equal(summary.names.every((name) => name.mismatch_counts.cell_record === 1), true);
  assert.equal(summary.certificate_failures_observed, 17);
  assert.equal(summary.mismatch_counts.cell_record, 17);
  assert.equal(JSON.stringify(summary).includes('name16'), false);
});

test('event-cap marker survives readout; unknown stays unknown', () => {
  const summary = accumulator();
  addLine(summary, line(report({ event: 1000, event_limit_reached: true })));
  assert.equal(summary.event_limits_reached, 1);
  assert.throws(() => parseLine(line(report({ check_limit: 65537 }))));
  assert.throws(() => parseLine(line(report({ names: Array(17).fill(report().names[0]) }))));
});

test('accepts normal fmt ANSI decoration without emitting it', () => {
  const summary = accumulator();
  addLine(summary, `\x1b[34m${line(report())}\x1b[0m`);
  assert.equal(summary.certificate_failures_observed, 1);
  assert.equal(summary.malformed_records, 0);
});

test('unavailable marker locks are reported as incomplete, not cell-only', () => {
  const summary = accumulator();
  addLine(summary, line(report({ truncated: true, window_marker_unavailable: true,
    ignoring_all_cell_versions_upper_bound: 'unknown' })));
  assert.equal(summary.unavailable_window_marker_scans, 1);
  assert.equal(summary.ignoring_all_cell_versions.yes, 0);
  assert.equal(summary.ignoring_all_cell_versions.unknown, 1);
});

test('complete scans must inspect every dependency and all seven state predicates', () => {
  for (const value of [
    report({ dependency_checks_inspected: 0, mismatches: { ...report().mismatches, cell_record: 0 }, names: [] }),
    report({ dependency_checks_total: 65536, dependency_checks_inspected: 65536 }),
    report({ checks_inspected: 8 }),
    report({ checks_inspected: 6, dependency_checks_total: 0, dependency_checks_inspected: 0,
      mismatches: { ...report().mismatches, cell_record: 0 }, names: [] }),
  ]) {
    assert.throws(() => parseLine(line(value)));
    const summary = accumulator(['org.spend']);
    addLine(summary, line(value));
    assert.equal(summary.malformed_records, 1);
    assert.equal(summary.complete_scans, 0);
    assert.equal(summary.ignoring_all_cell_versions.yes, 0);
    assert.equal(summary.mismatch_counts.cell_record, 0);
    assert.equal(summary.names[0].mismatch_counts.cell_record, 0);
  }
});

test('seven structural counters are booleans and cannot precede their inspection', () => {
  for (const family of families.slice(5)) {
    assert.throws(() => parseLine(line(report({
      mismatches: { ...report().mismatches, [family]: 9 }, ignoring_all_cell_versions_upper_bound: 'no',
    }))));
    assert.equal(parseLine(line(report({
      mismatches: { ...report().mismatches, [family]: 1 }, ignoring_all_cell_versions_upper_bound: 'no',
    }))).mismatches[family], 1);
  }
  assert.throws(() => parseLine(line(report({ ...truncated(), check_limit: 1, checks_inspected: 1,
    dependency_checks_inspected: 0, mismatches: { ...report().mismatches, cell_record: 0, graph_shape: 1 }, names: [] }))));
});

test('failed stamp families cannot together exceed inspected dependencies', () => {
  const summary = accumulator();
  addLine(summary, line(report({ mismatches: { ...report().mismatches, source_record: 1, marker: 1 },
    ignoring_all_cell_versions_upper_bound: 'no' })));
  assert.equal(summary.malformed_records, 1);
  assert.equal(summary.certificate_failures_observed, 0);
});

test('disjoint named totals cannot exceed any generic family, even for unconfigured names', () => {
  for (const family of ['source_record', 'cell_record', 'marker', 'window']) {
    const counters = { source_record: 0, cell_record: 0, marker: 0, window: 0, [family]: 1 };
    const value = report({ mismatches: { ...Object.fromEntries(families.map((name) => [name, 0])), [family]: 1 },
      ignoring_all_cell_versions_upper_bound: family === 'cell_record' ? 'yes' : 'no',
      names: [{ name: 'org.spend', ...counters }, { name: 'other.allowed', ...counters }] });
    assert.throws(() => parseLine(line(value)));
    const summary = accumulator();
    addLine(summary, line(value));
    assert.equal(summary.malformed_records, 1);
    assert.equal(summary.certificate_failures_observed, 0);
  }
});

test('actual process-compose JSON wrapping a timestamped ANSI fmt record is accepted', () => {
  const message = `\x1b[2m2026-10-05T04:56:42.123456Z\x1b[0m \x1b[34mDEBUG\x1b[0m \x1b[2mflower::conflicts:\x1b[0m flower_conflict_diagnostic ${JSON.stringify(report())}`;
  const result = cli(wrapped(message), ['--names', 'org.spend']);
  assert.equal(result.status, 0, result.stderr);
  const summary = JSON.parse(result.stdout);
  assert.equal(summary.capture_valid, true);
  assert.equal(summary.certificate_failures_observed, 1);
  assert.equal(summary.names[0].mismatch_counts.cell_record, 1);
  assert.equal(result.stdout.includes('DEBUG'), false);
  assert.equal(result.stdout.includes('\\u001b'), false);
});

test('unrelated application text carrying the marker cannot supply labels or valid counts', () => {
  const payload = line(report({ names: [{ ...report().names[0], name: 'customer-secret' }] }));
  for (const input of [
    `DEBUG flower::application: ${payload}`,
    wrapped(`DEBUG flower::application: user text ${payload}`),
    wrapped(payload, { process: 'gateway' }),
    wrapped(`INFO flower::conflicts: user text ${payload}`),
    `unrelated user text ${payload}`,
  ]) {
    const result = cli(input, ['--names', 'org.spend']);
    assert.equal(result.status, 1);
    const summary = JSON.parse(result.stdout);
    assert.equal(summary.malformed_records, 1);
    assert.equal(summary.certificate_failures_observed, 0);
    assert.equal(summary.possible_fraction_upper_bound_in_observed_sample, null);
    assert.equal(result.stdout.includes('customer-secret'), false);
    assert.equal(result.stderr.includes('customer-secret'), false);
  }
});

test('missing targets and unknown marker-bearing formats are counted as malformed', () => {
  for (const input of [
    `flower_conflict_diagnostic ${JSON.stringify(report())}`,
    JSON.stringify(report()), // No marker and no diagnostic target: not a record.
    JSON.stringify({ message: line(report()) }),
    JSON.stringify({ level: 'info', process: 'flower', message: line(report()) }),
    JSON.stringify({ target: 'flower::conflicts', message: line(report()) }),
    wrapped(line(report()), { level: 'debug' }),
    wrapped(line(report()), { replica: -1 }),
    wrapped('ordinary application text', { user_field: line(report()) }),
    wrapped(`flower_conflict_diagnostic ${JSON.stringify(report())}`),
  ]) {
    const summary = accumulator();
    addLine(summary, input);
    assert.equal(summary.certificate_failures_observed, 0);
    assert.equal(summary.malformed_records, input === JSON.stringify(report()) ? 0 : 1);
  }
});

test('labels default to none and an independent allowlist never drops generic counts', () => {
  const value = report({ names: [{ ...report().names[0], name: 'input-only-secret' }] });
  const anonymous = cli(line(value));
  assert.equal(anonymous.status, 0);
  assert.deepEqual(JSON.parse(anonymous.stdout).names, []);
  assert.equal(anonymous.stdout.includes('input-only-secret'), false);
  const configured = cli(line(value), ['--names', 'org.spend']);
  assert.equal(configured.status, 0);
  const summary = JSON.parse(configured.stdout);
  assert.equal(summary.mismatch_counts.cell_record, 1);
  assert.equal(summary.names[0].name, 'org.spend');
  assert.equal(summary.names[0].mismatch_counts.cell_record, 0);
  assert.equal(configured.stdout.includes('input-only-secret'), false);
});

test('damaged mixed captures retain validated counts but publish no partial positive bounds', () => {
  const result = cli(`${line(report())}\n${line(report({ dependency_checks_inspected: 0 }))}\n`);
  assert.equal(result.status, 1);
  const summary = JSON.parse(result.stdout);
  assert.equal(summary.certificate_failures_observed, 1);
  assert.equal(summary.mismatch_counts.cell_record, 1);
  assert.equal(summary.malformed_records, 1);
  assert.equal(summary.capture_valid, false);
  assert.equal(summary.possible_fraction_upper_bound_in_observed_sample, null);
  assert.equal(summary.complete_yes_fraction_in_observed_sample, null);
});

test('known CLI flags enforce bounded distinct ASCII names and fail closed without raw errors', () => {
  const names = Array.from({ length: 16 }, (_, n) => `n${n}`);
  assert.deepEqual(parseArgs(['--names', names.join(','), '--', '-capture.log']),
    { names, paths: ['-capture.log'], help: false });
  assert.equal(parseArgs(['--names', 'a'.repeat(64)]).names[0].length, 64);
  assert.deepEqual(parseArgs(['--names', '', '-']).names, []);
  for (const args of [
    ['--names'], ['--names', 'secret:credential'], ['--names', 'secret,secret'],
    ['--names', 'secret,,other'], ['--names', 'a'.repeat(65)],
    ['--names', `${names.join(',')},extra`], ['--names', 'é'],
    ['--names', 'secret\ncredential'], ['--names', 'secret\x1b[31m'],
    ['--names', 'org.spend', '--names', 'other'], ['--secret-credential'],
    ['--names', 'a'.repeat(1041)],
  ]) {
    const result = cli(line(report()), args);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'Could not read diagnostics (configuration/input details withheld)\n');
  }
  assert.throws(() => accumulator(Array(17).fill('secret')));
  assert.throws(() => accumulator(['secret', 'secret']));
  assert.throws(() => accumulator(['secret:credential']));
});

test('raw malformed JSON, oversized records and unreadable paths never echo supplied contents', () => {
  for (const input of [
    'DEBUG flower::conflicts: flower_conflict_diagnostic secret-credential',
    wrapped('DEBUG flower::conflicts: flower_conflict_diagnostic secret-credential'),
    wrapped(`${line(report())}${'secret-credential'.repeat(2000)}`),
    '{"message":"flower_conflict_diagnostic secret-credential',
    line(null),
  ]) {
    const result = cli(input);
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stdout).malformed_records, 1);
    assert.equal(`${result.stdout}${result.stderr}`.includes('secret-credential'), false);
    assert.throws(() => parseLine(input), /invalid diagnostic record \(details withheld\)/);
  }
  const missing = cli('', ['/nonexistent/secret-credential/conflicts.log']);
  assert.equal(missing.status, 1);
  assert.equal(missing.stdout, '');
  assert.equal(missing.stderr, 'Could not read diagnostics (configuration/input details withheld)\n');
});

test('complete and truncated boundary fixtures match the emitter inspection order', () => {
  assert.equal(parseLine(line(report({ check_limit: 9 }))).truncated, false);
  const stateOnly = report({ check_limit: 7, checks_inspected: 7, dependency_checks_total: 0,
    dependency_checks_inspected: 0, mismatches: { ...report().mismatches, cell_record: 0 }, names: [] });
  assert.equal(parseLine(line(stateOnly)).truncated, false);
  const early = { ...stateOnly, truncated: true, check_limit: 1, checks_inspected: 1,
    ignoring_all_cell_versions_upper_bound: 'unknown' };
  assert.equal(parseLine(line(early)).truncated, true);
  assert.throws(() => parseLine(line({ ...early, check_limit: 4096 })));
  assert.throws(() => parseLine(line({ ...early, window_marker_unavailable: true })));
});
