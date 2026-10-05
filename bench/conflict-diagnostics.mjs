#!/usr/bin/env node
// Read only the dedicated bounded records. Never print rejected lines or fields.
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { stripVTControlCharacters } from 'node:util';

const stampFamilies = ['source_record', 'cell_record', 'other_record', 'marker', 'window'];
const structuralFamilies = [
  'invalid_depth', 'invalid_source_ids', 'invalid_graph_pointer',
  'invalid_reactive_index', 'invalid_clock', 'graph_shape', 'clock_bound',
];
export const families = [...stampFamilies, ...structuralFamilies];
const namedFamilies = ['source_record', 'cell_record', 'marker', 'window'];
const marker = 'flower_conflict_diagnostic';
const maxNames = 16;
const maxNameBytes = 64;
const maxRecordBytes = 16384;
const namePattern = /^[A-Za-z0-9._-]{1,64}$/;
// The emitter has parent: None: no span text may precede its dedicated target.
const recordPattern = /^(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z[ \t]+)?DEBUG[ \t]+flower::conflicts:[ \t]+flower_conflict_diagnostic (.+)$/;
const empty = (keys) => Object.fromEntries(keys.map((key) => [key, 0]));
const count = (n, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(n) && n >= 0 && n <= max;
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const invalidRecord = () => new Error('invalid diagnostic record (details withheld)');
const invalidConfig = () => new Error('invalid parser configuration (details withheld)');
function decodeRecord(text) {
  try { return JSON.parse(text); }
  catch { throw invalidRecord(); }
}

export function parseLine(line) {
  let message = stripVTControlCharacters(line);
  if (message.startsWith('{')) {
    // process-compose v1.110 writes the process's fmt output as an escaped JSON
    // message. Decode before stripping its ANSI controls; a marker search in the
    // outer JSON is not proof of the inner tracing target.
    let wrapper;
    try { wrapper = JSON.parse(message); }
    catch {
      if (message.includes(marker)) throw invalidRecord();
      return null;
    }
    const inner = object(wrapper) && typeof wrapper.message === 'string'
      ? stripVTControlCharacters(wrapper.message) : '';
    if (!inner.includes(marker) && !message.includes(marker)) return null;
    if (!inner.includes(marker) || !object(wrapper) || wrapper.level !== 'info' || wrapper.process !== 'flower'
        || !count(wrapper.replica) || typeof wrapper.message !== 'string') throw invalidRecord();
    message = inner;
  }
  if (!message.includes(marker)) return null;
  if (Buffer.byteLength(line, 'utf8') > maxRecordBytes) throw invalidRecord();
  const match = recordPattern.exec(message);
  if (!match) throw invalidRecord();
  const value = decodeRecord(match[1]);
  if (!object(value) || value.version !== 1 || value.diagnostic_only !== true || value.claim !== 'not_safe_repairability'
      || !count(value.event, 10000) || value.event < 1
      || !count(value.event_limit, 10000) || value.event > value.event_limit
      || value.event_limit_reached !== (value.event === value.event_limit)
      || !count(value.check_limit, 65536) || value.check_limit < 1
      || !count(value.checks_inspected, value.check_limit) || value.checks_inspected < 1
      || !count(value.dependency_checks_total)
      || !count(value.dependency_checks_inspected, value.dependency_checks_total)
      || value.dependency_checks_inspected > value.checks_inspected
      || typeof value.truncated !== 'boolean'
      || (!value.truncated && (value.dependency_checks_inspected !== value.dependency_checks_total || value.checks_inspected < 7))
      // All seven state predicates precede dependency stamps, even on failure.
      || value.dependency_checks_inspected + Math.min(7, value.checks_inspected) > value.checks_inspected
      || typeof value.window_marker_unavailable !== 'boolean'
      || (value.window_marker_unavailable && (!value.truncated || !value.dependency_checks_inspected))
      || (value.truncated && !value.window_marker_unavailable && value.checks_inspected !== value.check_limit)
      || !['yes', 'no', 'unknown'].includes(value.ignoring_all_cell_versions_upper_bound)
      || value.truncated !== (value.ignoring_all_cell_versions_upper_bound === 'unknown')
      || !object(value.mismatches)
      || !stampFamilies.every((key) => count(value.mismatches[key], value.dependency_checks_inspected))
      || !structuralFamilies.every((key, index) => count(value.mismatches[key], value.checks_inspected > index ? 1 : 0))
      || stampFamilies.reduce((sum, key) => sum + value.mismatches[key], 0) > value.dependency_checks_inspected
      || !Array.isArray(value.names) || value.names.length > maxNames
      || !value.names.every((name) => object(name) && typeof name.name === 'string' && namePattern.test(name.name)
        && namedFamilies.every((key) => count(name[key], value.mismatches[key])))
      || new Set(value.names.map((name) => name.name)).size !== value.names.length
      || !namedFamilies.every((key) => value.names.reduce((sum, name) => sum + name[key], 0) <= value.mismatches[key])) {
    throw invalidRecord();
  }
  const nonCell = families.filter((key) => key !== 'cell_record').reduce((sum, key) => sum + value.mismatches[key], 0);
  if (!value.truncated && (value.ignoring_all_cell_versions_upper_bound === 'yes') !== (nonCell === 0)) {
    throw invalidRecord();
  }
  return value;
}

function validateNames(names) {
  if (!Array.isArray(names) || names.length > maxNames
      || !names.every((name) => typeof name === 'string' && namePattern.test(name))
      || new Set(names).size !== names.length) throw invalidConfig();
  return names;
}
export function parseArgs(args) {
  const paths = [];
  let names = [];
  let namesSeen = false;
  let help = false;
  let options = true;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (options && arg === '--') { options = false; continue; }
    if (options && arg === '--names') {
      if (namesSeen) throw invalidConfig();
      namesSeen = true;
      const text = args[++index];
      if (typeof text !== 'string' || text.length > maxNames * (maxNameBytes + 1)) throw invalidConfig();
      names = validateNames(text === '' ? [] : text.split(','));
    } else if (options && (arg === '--help' || arg === '-h')) {
      help = true;
    } else if (options && arg.startsWith('-') && arg !== '-') {
      throw invalidConfig();
    } else {
      paths.push(arg);
    }
  }
  return { paths, names, help };
}
export function accumulator(names = []) {
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
    // Labels originate only from independently supplied parser configuration.
    names: validateNames(names).map((name) => ({
      name, mismatch_counts: empty(namedFamilies), candidates_with_mismatch: empty(namedFamilies),
    })),
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
  for (const named of summary.names) {
    const entry = report.names.find((name) => name.name === named.name);
    if (!entry) continue;
    for (const family of namedFamilies) {
      named.mismatch_counts[family] += entry[family];
      if (entry[family]) named.candidates_with_mismatch[family]++;
    }
  }
}
export function finish(summary) {
  const { yes, unknown } = summary.ignoring_all_cell_versions;
  const captureValid = summary.malformed_records === 0;
  const hasValidSample = captureValid && summary.certificate_failures_observed > 0;
  return {
    ...summary,
    capture_valid: captureValid,
    // Keep counts from individually valid records, but never publish a bound
    // from a damaged capture. Unknowns remain possible, not cell-only.
    possible_fraction_upper_bound_in_observed_sample: hasValidSample
      ? (yes + unknown) / summary.certificate_failures_observed : null,
    complete_yes_fraction_in_observed_sample: hasValidSample
      ? yes / summary.certificate_failures_observed : null,
  };
}
async function main() {
  const { paths, names, help } = parseArgs(process.argv.slice(2));
  if (help) {
    console.log('Usage: node bench/conflict-diagnostics.mjs [--names NAME,...] [--] [FILE ...]\n'
      + 'Read dedicated flower::conflicts fmt records or process-compose flower JSON logs.\n'
      + 'No FILE (or FILE -) reads stdin. Labels default to none; at most 16 distinct 1-64 ASCII names.\n'
      + 'Malformed/rejected records invalidate both sample ratios and cause a nonzero exit.\n'
      + 'Diagnostic-only upper bound, never safe repairability or a throughput gain.');
    return;
  }
  const summary = accumulator(names);
  for (const path of paths.length ? paths : ['-']) {
    const lines = createInterface({ input: path === '-' ? process.stdin : createReadStream(path), crlfDelay: Infinity });
    for await (const line of lines) addLine(summary, line);
  }
  console.log(JSON.stringify(finish(summary), null, 2));
  if (summary.malformed_records) process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { console.error('Could not read diagnostics (configuration/input details withheld)'); process.exitCode = 1; });
}
