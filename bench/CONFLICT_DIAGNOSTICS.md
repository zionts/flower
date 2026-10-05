# Speculative certificate conflict diagnostics (prototype)

**Production default: off. Diagnostic-only; never use this to accept, repair, or
skip re-executing a candidate.** This observes the certificate portion of an
already rejected speculative candidate, not all reasons a candidate can fail.
It does not change commit order, aggregate evaluation, admission/budgets,
retention, authorization, or certificate acceptance.

The ordinary validator still short-circuits in its original order. When it
returns false, this optional second pass examines **all certificate dependencies
within a separate diagnostic inspection limit**, even after a mismatch. This
corrects first-failed-key attribution: `cell:` sorting before `source:` must not
make a candidate with both conflicts look cell-only. Window comparison shares
the ordinary version-equality helper, but diagnostics **never adopt a marker**.
An unchanged index marker makes its window valid without a walk; a changed
marker is not itself a failed window if the window's entry versions still match.

## Enable for a finite local investigation

Restart the benchmark server with these environment variables (configuration is
read once, on the first rejected certificate):

```sh
FLOWER_CONFLICT_DIAGNOSTICS=1 \
FLOWER_CONFLICT_DIAGNOSTICS_NAMES=org.spend,org.dailySpend,hourTotals,scopeSpend,chargeTotals \
FLOWER_CONFLICT_DIAGNOSTICS_MAX_CHECKS=4096 \
FLOWER_CONFLICT_DIAGNOSTICS_MAX_EVENTS=1000 \
RUST_LOG=warn,flower::conflicts=debug \
  target/release/flower ... >flower-conflicts.log 2>&1
node bench/conflict-diagnostics.mjs flower-conflicts.log
# Or: node bench/conflict-diagnostics.mjs <flower-conflicts.log
```

The example names are **operator-supplied examples**, not schema-specific logic
in Flower. Choose only static collection/definition names approved for logs,
never a name containing a customer identifier or other secret. Matching uses
exact first identity components, not substring matches; names with `.` are not
implicitly namespaces. The same allowed name can label both source and cell
counters, distinguished by family. Index-window attribution uses the index's
collection, not the fields, query, bounds, or row keys. Unconfigured names and
unrecognized record kinds remain in generic counters.

| Configuration | Default | Allowed bound |
| --- | --- | --- |
| `FLOWER_CONFLICT_DIAGNOSTICS` | unset/off | Only exact `1` enables |
| `FLOWER_CONFLICT_DIAGNOSTICS_NAMES` | empty (generic counters only) | At most 16 distinct names, each 1–64 ASCII letters/digits/`.`/`_`/`-`, comma-separated |
| `FLOWER_CONFLICT_DIAGNOSTICS_MAX_CHECKS` | 4096 | 1–65,536 |
| `FLOWER_CONFLICT_DIAGNOSTICS_MAX_EVENTS` | 1000 | 1–10,000, process-wide across all partitions |

Invalid configuration disables diagnostics, without echoing its contents. Both
the flag and the dedicated DEBUG log filter are required. The enabled path
reserves an event slot **before** scanning. After the finite event allowance is
used, subsequent conflicts are not scanned or logged. The last allowed event
has `event_limit_reached: true`; this is not a count of subsequent omissions.
No recurring diagnostic task, public API, metric-label series, or retained
per-request diagnostic state is added. Disabling the flag leaves only the
cached disabled-config check on rejected certificates; successful validation
does not visit diagnostic code. Restart without the flag after investigation.

## What a record means

Each line includes `flower_conflict_diagnostic ` followed by a JSON record:

- `version: 1`, `diagnostic_only: true`, `claim: "not_safe_repairability"`.
- Fixed-cardinality mismatch counters: `source_record`, `cell_record`,
  `other_record`, `marker`, `window`, `invalid_depth`, `invalid_source_ids`,
  `invalid_graph_pointer`, `invalid_reactive_index`, `invalid_clock`,
  `graph_shape`, and `clock_bound`. These count failed **checks**, not writes,
  unique rows, requests, or repair operations. One failure can have multiple
  families. An invalid stored clock fails both clock predicates.
- Optional `names`: only configured names, with source/cell/marker/window
  mismatch counts. Names are never copied from a raw key into output.
- The total/inspected dependency-check counts, inspected-work count, limits,
  process-local event ordinal, and `truncated`.
- `ignoring_all_cell_versions_upper_bound`: `yes`, `no`, or `unknown`.

The inspection limit charges each of the seven state/graph/clock predicates,
each dependency stamp, and every index-window iterator `next()` (including its
final absence check). A failed window needs only the first differing entry;
other stamps are still inspected. An unchanged window can consume the budget,
so entry walks share the same limit. A partially inspected window, unvisited
dependency, or unvisited state predicate sets `truncated: true` and makes the
counterfactual **unknown**, even if every observed mismatch was a cell. Reaching
the limit exactly after the last required comparison is complete, not truncated.
A contended or poisoned window-marker mutex is not waited on: it also makes
the scan incomplete, with `window_marker_unavailable: true`. Counts in
truncated records are lower bounds. The limit bounds logical checks
and output, not hard wall time or underlying storage page/iterator work. This
adds real diagnostic overhead; use a separate run from performance timing.

### Counterfactual upper bound, NOT safe repairability

`yes` means a **complete** scan found no failing predicate other than cell
record-version checks. If **all** those checks were magically ignored, the
certificate would pass. It does **not** distinguish aggregate write-base
conflicts from genuine reads of cell outcomes. A method returning a stale cell
value can produce `yes` and still absolutely require re-execution. This is not
an “aggregate-only”, commutativity, delta-repair, or correctness claim.

`no` means a complete scan found at least one non-cell failure. `unknown` means
the scan was incomplete. Later candidate gates (authorization/principal,
receipts, CAS, transaction locks, fingerprint, capacity, etc.) are outside this
certificate-only counterfactual. Consequently even `yes` is merely an upper
bound on candidates that a hypothetical change might help, not expected reuse
or throughput improvement.

## Readout and confidentiality

The parser reports complete/truncated records, all failed-family counts and
per-family candidate counts, allowed names, event-cap markers, and the three
counterfactual classes. Its
`possible_fraction_upper_bound_in_observed_sample = (yes + unknown) / observed`
keeps unknowns possible, **never** reclassifies them as cell-only. The separate
`complete_yes_fraction_in_observed_sample = yes / observed` counts only complete
positives. Empty samples report `null`, not a fabricated zero. Both ratios are
about this selected observed sample, **not all speculative failures** or any
population confidence bound. The allowance selects the first logged failures;
the adaptive speculation policy, process restarts, logging loss, and diagnostic
overhead also bias the sample. Compare against existing speculation telemetry
separately. Do not merge duplicate captures as independent events.

The parser retains at most 16 distinct configured names across input files;
`names_truncated` flags config changes exceeding that cap while generic counts
remain available. Malformed records are counted, never printed, and cause a
nonzero exit status. They are not silently counted as complete negatives or
positives; do not interpret ratios from a damaged capture as a valid bound.

The dedicated event has no parent request span and contains no raw keys,
collection arguments, row values, org/session/request IDs, principals,
credentials, exception strings, or method names. Method names are deliberately
omitted: existing telemetry permits resolved names only in sampled traces,
not this independent debug log. This event is not an OTLP span. Other enabled
logging is outside this diagnostic's confidentiality contract.

## Targeted checks

```sh
cargo test -p flower --lib 'dependencies::' -- --test-threads=2
cargo test -p flower --lib speculative_candidates_recheck_order_principal_receipts_cas_and_transaction_locks
# Separate processes; leave the three tuning variables unset for these fixtures.
FLOWER_CONFLICT_DIAGNOSTICS=0 cargo test -p flower --lib conflict_diagnostics_observe_rejection
FLOWER_CONFLICT_DIAGNOSTICS=1 cargo test -p flower --lib conflict_diagnostics_observe_rejection
node --test bench/conflict-diagnostics.test.mjs
```

The native fixtures cover simultaneous cell/source/other failures, cell-first
ordering, a genuine stale cell read, window marker changes/unchanged contents,
all structural/clock predicates, bounded entry walks, complete vs truncated
scans, finite config/event limits, emitted-field confidentiality, and unchanged
validation results before and after diagnosis. Existing writer and dependency
fixtures still exercise the ordinary acceptance path. The writer integration
fixture checks the actual flag-gated log and unchanged candidate rejection,
response, write patch, and expected revision in separate off/on processes.
