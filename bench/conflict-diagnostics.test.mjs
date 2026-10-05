import assert from 'node:assert/strict';
import test from 'node:test';
import { accumulator, addLine, families, finish, parseLine } from './conflict-diagnostics.mjs';

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

test('reads bounded multi-family records; never mistakes a truncated cell prefix for cell-only', () => {
  const summary = accumulator();
  addLine(summary, 'unrelated server output');
  addLine(summary, line(report()));
  addLine(summary, line(report({ mismatches: { ...report().mismatches, source_record: 1 }, ignoring_all_cell_versions_upper_bound: 'no' })));
  addLine(summary, line(report({ truncated: true, ignoring_all_cell_versions_upper_bound: 'unknown', dependency_checks_inspected: 1 })));
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

test('parser output has a bounded name set and reports config changes that exceed it', () => {
  const summary = accumulator();
  for (let n = 0; n < 17; n++) {
    addLine(summary, line(report({ names: [{ ...report().names[0], name: `name${n}` }] })));
  }
  assert.equal(summary.names.length, 16);
  assert.equal(summary.names_truncated, true);
  assert.equal(summary.certificate_failures_observed, 17);
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
