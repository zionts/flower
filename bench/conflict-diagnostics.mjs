#!/usr/bin/env node
// Read only the dedicated bounded records. Never print rejected lines or fields.
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { stripVTControlCharacters } from 'node:util';

export const families = [
  'source_record', 'cell_record', 'other_record', 'marker', 'window',
  'invalid_depth', 'invalid_source_ids', 'invalid_graph_pointer',
  'invalid_reactive_index', 'invalid_clock', 'graph_shape', 'clock_bound',
];
const namedFamilies = ['source_record', 'cell_record', 'marker', 'window'];
const marker = 'flower_conflict_diagnostic ';
const empty = (keys) => Object.fromEntries(keys.map((key) => [key, 0]));
const count = (n, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(n) && n >= 0 && n <= max;

export function parseLine(line) {
  // The ordinary fmt subscriber may color DEBUG/target/message output.
  line = stripVTControlCharacters(line);
  const start = line.indexOf(marker);
  if (start < 0) return null;
  if (line.length > 16384) throw new Error('oversized diagnostic record');
  const value = JSON.parse(line.slice(start + marker.length));
  if (value.version !== 1 || value.diagnostic_only !== true || value.claim !== 'not_safe_repairability'
      || !count(value.event, 10000) || value.event < 1
      || !count(value.event_limit, 10000) || value.event > value.event_limit
      || value.event_limit_reached !== (value.event === value.event_limit)
      || !count(value.check_limit, 65536) || value.check_limit < 1
      || !count(value.checks_inspected, value.check_limit)
      || !count(value.dependency_checks_total)
      || !count(value.dependency_checks_inspected, value.dependency_checks_total)
      || typeof value.truncated !== 'boolean'
      || typeof value.window_marker_unavailable !== 'boolean'
      || (value.window_marker_unavailable && !value.truncated)
      || !['yes', 'no', 'unknown'].includes(value.ignoring_all_cell_versions_upper_bound)
      || value.truncated !== (value.ignoring_all_cell_versions_upper_bound === 'unknown')
      || !families.every((key) => count(value.mismatches?.[key], value.checks_inspected))
      || !Array.isArray(value.names) || value.names.length > 16
      || !value.names.every((name) => typeof name.name === 'string' && /^[A-Za-z0-9._-]{1,64}$/.test(name.name)
        && namedFamilies.every((key) => count(name[key], value.mismatches[key])))
      || new Set(value.names.map((name) => name.name)).size !== value.names.length) {
    throw new Error('invalid diagnostic record');
  }
  const nonCell = families.filter((key) => key !== 'cell_record').reduce((sum, key) => sum + value.mismatches[key], 0);
  if (!value.truncated && (value.ignoring_all_cell_versions_upper_bound === 'yes') !== (nonCell === 0)) {
    throw new Error('inconsistent counterfactual');
  }
  return value;
}

export function accumulator() {
  return {
    diagnostic_only: true,
    claim: 'not_safe_repairability',
    certificate_failures_observed: 0,
    complete_scans: 0,
    truncated_scans: 0,
    unavailable_window_marker_scans: 0,
    event_limits_reached: 0,
    malformed_records: 0,
    mismatch_counts: empty(families),
    candidates_with_mismatch: empty(families),
    ignoring_all_cell_versions: { yes: 0, no: 0, unknown: 0 },
    names: [],
    names_truncated: false,
  };
}
export function addLine(summary, line) {
  let report;
  try { report = parseLine(line); }
  catch { summary.malformed_records++; return; }
  if (!report) return;
  summary.certificate_failures_observed++;
  summary[report.truncated ? 'truncated_scans' : 'complete_scans']++;
  if (report.event_limit_reached) summary.event_limits_reached++;
  if (report.window_marker_unavailable) summary.unavailable_window_marker_scans++;
  summary.ignoring_all_cell_versions[report.ignoring_all_cell_versions_upper_bound]++;
  for (const family of families) {
    summary.mismatch_counts[family] += report.mismatches[family];
    if (report.mismatches[family]) summary.candidates_with_mismatch[family]++;
  }
  for (const entry of report.names) {
    let named = summary.names.find((name) => name.name === entry.name);
    if (!named) {
      if (summary.names.length === 16) { summary.names_truncated = true; continue; }
      named = { name: entry.name, mismatch_counts: empty(namedFamilies), candidates_with_mismatch: empty(namedFamilies) };
      summary.names.push(named);
    }
    for (const family of namedFamilies) {
      named.mismatch_counts[family] += entry[family];
      if (entry[family]) named.candidates_with_mismatch[family]++;
    }
  }
}
export function finish(summary) {
  const { yes, unknown } = summary.ignoring_all_cell_versions;
  return {
    ...summary,
    // Unknowns stay possible, not classified as cell-only. This is only a bound
    // within the captured, selected diagnostic sample, never a throughput gain.
    possible_fraction_upper_bound_in_observed_sample: summary.certificate_failures_observed
      ? (yes + unknown) / summary.certificate_failures_observed : null,
    complete_yes_fraction_in_observed_sample: summary.certificate_failures_observed
      ? yes / summary.certificate_failures_observed : null,
  };
}
async function main() {
  const paths = process.argv.slice(2);
  const summary = accumulator();
  for (const path of paths.length ? paths : ['-']) {
    const lines = createInterface({ input: path === '-' ? process.stdin : createReadStream(path), crlfDelay: Infinity });
    for await (const line of lines) addLine(summary, line);
  }
  console.log(JSON.stringify(finish(summary), null, 2));
  if (summary.malformed_records) process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { console.error('Could not read diagnostic input (input details withheld)'); process.exitCode = 1; });
}
