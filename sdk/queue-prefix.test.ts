// Current approved bounded-prefix semantics through the actual ordinary SDK and
// reference-engine synchronous mutations. NOT Node SQL emulation or native proof.
import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalJson, define, FlowerError, mutation } from "./index.ts";
import type { Json, MutationContext } from "./index.ts";
import { queue } from "./temporal.ts";
import { testDatabase } from "./testing.ts";
import app from "./queue-prefix-native.fixture.ts";

const worker = { credentials: "worker" }, reader = { credentials: "reader" };
const failure = (run: () => unknown, message?: RegExp) => assert.throws(run, (error: unknown) =>
  error instanceof FlowerError && error.failure?.code === "EVALUATION_BUDGET" && (!message || message.test(error.message)));
const originalBytes = (rows: { value: unknown }[]) => rows.reduce((bytes, row) => bytes + Buffer.byteLength(canonicalJson(row.value as Json)), 0);
const raw = (db: Awaited<ReturnType<typeof fresh>>, id: string): any => db.query("row", id, worker);
const book = (db: Awaited<ReturnType<typeof fresh>>) => db.query("bookkeeping", null, worker);
const seed = (db: Awaited<ReturnType<typeof fresh>>, input: Json) => db.mutate("seed", input, worker);
const take = (db: Awaited<ReturnType<typeof fresh>>, input: Json = {}) => db.mutate("take", input, reader);
const fresh = () => testDatabase(app);

function quarantine(stored: any, original: any, now: number): void {
  assert.deepEqual(stored, { ...original, state: "failed", availableAt: null, queued: null, lease: null,
    leaseExpiresAt: null, updatedAt: now, outboundQuarantine: original });
  assert.deepEqual(stored.payload, original.payload);
  assert.equal(stored.attempts, original.attempts);
}

async function drain(rich: boolean) {
  const db = await fresh(), ids = Array.from({ length: 64 }, (_, index) => rich ? `unknown-${index.toString().padStart(2, "0")}` : `u${index}`);
  seed(db, { ids, ...(rich ? { rich: true } : { compact: true }) });
  seed(db, { ids: ["ordinary"] });
  const originals = new Map(ids.map((id) => [id, raw(db, id)]));
  if (rich) assert.equal(originalBytes([...originals.values()].map((value) => ({ value }))), 48_566,
    "exact BE constructor trace: all unknown body, metadata, result/error and job extra fields retained");
  const ordinary = raw(db, "ordinary"), counters = book(db);
  const admitted: string[] = [], prefixCounts: number[] = [];
  let granted = false;
  for (let call = 0; call < 65 && !granted; ++call) {
    const before = new Map(ids.map((id) => [id, canonicalJson(raw(db, id))]));
    const result = take(db, { max: 64, principal: "reader" });
    assert.equal(result.checked, true);
    assert.ok(result.calls > 0 && result.calls <= 64);
    const seen = result.observed.map((entry) => entry.id);
    const consideredUnknown = seen.filter((id) => id !== "ordinary");
    prefixCounts.push(consideredUnknown.length);
    assert.ok(consideredUnknown.length > 0 || admitted.length === 64);
    for (const id of consideredUnknown) {
      assert.ok(!admitted.includes(id), "completed quarantine is never visited again");
      admitted.push(id);
      quarantine(raw(db, id), originals.get(id), db.now);
    }
    for (const id of ids.filter((id) => !consideredUnknown.includes(id))) {
      assert.equal(canonicalJson(raw(db, id)), before.get(id), "every unconsidered job remains byte-exact");
    }
    if (result.claims.length === 0) {
      assert.ok(!seen.includes("ordinary"), "no callback/touch on candidate 65 before a real eligible grant");
      assert.deepEqual(raw(db, "ordinary"), ordinary);
      assert.deepEqual(book(db), counters, "all quarantine prefixes spend no fencing, turn, group or line writes");
    } else {
      assert.equal(admitted.length, 64, "all originals completed before ordinary is considered");
      assert.deepEqual(result.claims.map((claim) => [claim.id, claim.token, claim.attempt]), [["ordinary", 1, 1]]);
      assert.equal(raw(db, "ordinary").attempts, 1);
      granted = true;
    }
  }
  assert.ok(granted, "finite repeated actual synchronous mutations reach ordinary eligible work");
  assert.equal(admitted.length, 64);
  for (const id of ids) quarantine(raw(db, id), originals.get(id), db.now);
  if (rich) assert.ok(prefixCounts.length > 1 && prefixCounts[0] < 64,
    "64 is an upper bound; no quota raise, refund/reset, fixture/body reduction or partial fake claim");
  return prefixCounts;
}

test("exact 48566-byte metadata-rich 64 originals commit bounded prefixes, then ordinary gets token 1/attempt 1", async () => {
  const prefixes = await drain(true);
  console.info(`QUEUE_PREFIX_RICH64: completed-prefix counts ${prefixes.join(",")}; originals 48566 bytes`);
});

test("64 compact originals also obey an upper bound, not a promise to process all 64 in one allowance", async () => {
  await drain(false);
});

test("max 0 executes no callback or row/lease write, and max 1 leaves the next row byte-exact", async () => {
  const db = await fresh(); seed(db, { ids: ["a", "b"] });
  const before = canonicalJson(db.data);
  assert.deepEqual(take(db, { max: 0 }).claims, []);
  assert.equal(canonicalJson(db.data), before);
  const b = canonicalJson(raw(db, "b")), result = take(db, { mode: "accept", max: 1 });
  assert.equal(result.calls, 1);
  assert.deepEqual(result.claims.map((claim) => [claim.id, claim.token, claim.attempt]), [["a", 1, 1]]);
  assert.equal(canonicalJson(raw(db, "b")), b);
});

test("max 64 never visits a 65th candidate; direct no-admit max 65 is unchanged", async () => {
  const db = await fresh(); seed(db, { ids: Array.from({ length: 65 }, (_, index) => `s${index.toString().padStart(2, "0")}`) });
  const last = canonicalJson(raw(db, "s64"));
  const result = take(db, { mode: "accept", max: 64 });
  assert.equal(result.calls, 64);
  assert.equal(result.claims.length, 64);
  assert.equal(canonicalJson(raw(db, "s64")), last);
  assert.throws(() => take(db, { max: 65 }), /max is at most 64/);
  const direct = await fresh(); seed(direct, { ids: Array.from({ length: 65 }, (_, index) => String(index)) });
  assert.equal(direct.mutate("direct", { max: 65 }, reader).length, 65);
});

test("a first candidate cannot invoke admission until both copies AND the unchanged comparison fit", async () => {
  let callbacks = 0;
  const work = queue("upfrontComparison");
  const db = await testDatabase(define({ uses: [work], http: {
    seed: mutation("seed", (ctx) => { work.enqueue(ctx, "first", { text: "x".repeat(14_400) }); return null; }),
    take: mutation("take", (ctx) => work.claimMany(ctx, "new-worker", { admit: () => { ++callbacks; return true; } })),
  } }));
  db.mutate("seed"); const before = canonicalJson(db.data), revision = db.revision;
  failure(() => db.mutate("take"), /Queue admission snapshot/);
  assert.equal(callbacks, 0, "old prepare could enter callback then fail its unreserved current-side comparison");
  assert.equal(canonicalJson(db.data), before);
  assert.equal(db.revision, revision);
});

test("late oversized candidate stops after a completed quarantine; next call fails first and never loops empty-success", async () => {
  const db = await fresh(); seed(db, { ids: ["a"], rich: true }); seed(db, { ids: ["oversized"], text: 25_000 });
  const a = raw(db, "a"), oversized = canonicalJson(raw(db, "oversized")), counters = book(db);
  const result = take(db);
  assert.equal(result.calls, 1);
  assert.deepEqual(result.claims, []);
  quarantine(raw(db, "a"), a, db.now);
  assert.equal(canonicalJson(raw(db, "oversized")), oversized);
  assert.deepEqual(book(db), counters);
  const prefix = canonicalJson(db.data), revision = db.revision;
  failure(() => take(db), /Queue admission snapshot/);
  assert.equal(canonicalJson(db.data), prefix);
  assert.equal(db.revision, revision);
});

test("late oversized boundary returns only a real granted prefix and leaves all later rows untouched", async () => {
  const db = await fresh(); seed(db, { ids: ["accepted"], priority: -2 });
  seed(db, { ids: ["oversized"], text: 25_000 }); seed(db, { ids: ["tail"], priority: 1 });
  const oversized = canonicalJson(raw(db, "oversized")), tail = canonicalJson(raw(db, "tail"));
  const result = take(db, { mode: "mixed" });
  assert.equal(result.calls, 1);
  assert.deepEqual(result.claims.map((claim) => [claim.id, claim.token, claim.attempt]), [["accepted", 1, 1]]);
  assert.equal(raw(db, "accepted").lease.token, 1);
  assert.equal(raw(db, "accepted").attempts, 1);
  assert.equal(canonicalJson(raw(db, "oversized")), oversized);
  assert.equal(canonicalJson(raw(db, "tail")), tail);
});

test("REAL reference guest host-operation failure after a completed prefix rolls back the WHOLE mutation", async () => {
  const db = await fresh(); seed(db, { ids: ["a", "b"] });
  const before = canonicalJson(db.data), revision = db.revision;
  failure(() => take(db, { mode: "hostFailure" }), /Method operation budget exceeds 100000/);
  assert.equal(canonicalJson(db.data), before, "earlier successful quarantine does not survive real guest failure");
  assert.equal(db.revision, revision);
});

test("a callback EVALUATION_BUDGET-shaped exception is not the private prospective boundary", async () => {
  const db = await fresh(); seed(db, { ids: ["a", "b"] });
  const before = canonicalJson(db.data);
  failure(() => take(db, { mode: "callbackFailure" }), /callback resource-shaped failure/);
  assert.equal(canonicalJson(db.data), before);
});

test("unchanged false cancels without tokens; accepted payload-only replacements stay pending and are not overwritten", async () => {
  const refused = await fresh(); seed(refused, { ids: ["a", "b"] }); const counters = book(refused);
  assert.equal(take(refused, { mode: "false" }).calls, 2);
  assert.deepEqual(refused.query("rows", null, worker), []);
  assert.deepEqual(book(refused), counters);
  const replaced = await fresh(); seed(replaced, { ids: ["a", "b"] }); const originalCounters = book(replaced);
  const result = take(replaced, { mode: "payload", replacementSize: 10 });
  assert.equal(result.calls, 2); assert.deepEqual(result.claims, []);
  for (const id of ["a", "b"]) {
    assert.equal(raw(replaced, id).state, "pending"); assert.equal(raw(replaced, id).attempts, 0);
    assert.deepEqual(raw(replaced, id).payload, { text: "r".repeat(10) }); assert.equal(raw(replaced, id).lease, null);
  }
  assert.deepEqual(book(replaced), originalCounters);
});

test("shrinking replacements do not refund unused prepaid comparison work or reset the cumulative allowance", async () => {
  const db = await fresh(); seed(db, { ids: ["a", "b", "c"], text: 6_800 });
  const c = canonicalJson(raw(db, "c")), counters = book(db);
  const result = take(db, { mode: "shrink" });
  assert.equal(result.calls, 2, "unused candidate credit is held/burned, never returned for candidate three");
  assert.deepEqual(result.claims, []);
  assert.deepEqual(raw(db, "a").payload, { text: "r" }); assert.deepEqual(raw(db, "b").payload, { text: "r" });
  assert.equal(canonicalJson(raw(db, "c")), c);
  assert.deepEqual(book(db), counters);
});

test("larger payload-only replacement can exhaust original shared remainder and fails whole, never prefix-success", async () => {
  const db = await fresh(); seed(db, { ids: ["a"] }); const before = canonicalJson(db.data);
  failure(() => take(db, { mode: "payload", replacementSize: 70_000 }), /Queue admission snapshot/);
  assert.equal(canonicalJson(db.data), before);
});

test("larger post-callback comparison failure after a completed quarantine still rolls back the whole mutation", async () => {
  const db = await fresh(); seed(db, { ids: ["a", "b"] }); const before = canonicalJson(db.data), revision = db.revision;
  failure(() => take(db, { mode: "growLate", replacementSize: 70_000 }), /Queue admission snapshot/);
  assert.equal(canonicalJson(db.data), before);
  assert.equal(db.revision, revision);
});

test("callback deletions/reentry are preserved and cannot grant stale proposed tokens", async () => {
  const deleted = await fresh(); seed(deleted, { ids: ["a", "b"] }); const counters = book(deleted);
  assert.deepEqual(take(deleted, { mode: "delete" }).claims, []);
  assert.deepEqual(deleted.query("rows", null, worker), []); assert.deepEqual(book(deleted), counters);
  const reentrant = await fresh(); seed(reentrant, { ids: ["a", "b"] });
  assert.deepEqual(take(reentrant, { mode: "reenter" }).claims, []);
  assert.equal(raw(reentrant, "a").lease.owner, "reentrant"); assert.equal(raw(reentrant, "b").lease.owner, "reentrant");
});

test("prefix callbacks remain outside definer with their actual principal and ACL", async () => {
  const db = await fresh(); db.mutate("protect", null, worker); seed(db, { ids: ["a", "b"], text: 12_000 });
  const b = canonicalJson(raw(db, "b")), counters = book(db);
  const result = take(db, { mode: "boundary", principal: "reader" });
  assert.equal(result.calls, 1); assert.deepEqual(result.claims, []);
  assert.equal(raw(db, "a").state, "failed"); assert.equal(canonicalJson(raw(db, "b")), b);
  assert.deepEqual(book(db), counters);
});

test("delayed/expired raw schedule, attempt, lease and unknown old marker survive exact quarantine", async () => {
  const delayed = await fresh(); seed(delayed, { ids: ["delayed"], rich: true, delayMs: 10, marker: true });
  const original = raw(delayed, "delayed"), counters = book(delayed); delayed.now += 10;
  assert.deepEqual(take(delayed).claims, []); quarantine(raw(delayed, "delayed"), original, delayed.now);
  assert.deepEqual(book(delayed), counters);
  assert.equal(raw(delayed, "delayed").outboundQuarantine.outboundQuarantine.original, "UNTRUSTED_OLD_MARKER_CANARY");
  const expired = await fresh(); seed(expired, { ids: ["expired"], rich: true }); expired.mutate("lease", null, worker);
  const leased = raw(expired, "expired"), oldCounters = book(expired); expired.now += 10;
  const result = take(expired); assert.equal(result.observed[0].state, "leased"); assert.equal(result.observed[0].attempts, 1);
  quarantine(raw(expired, "expired"), leased, expired.now); assert.deepEqual(book(expired), oldCounters);
});

test("finite JSON UTF16, dense arrays and authentic __proto__ fields preserve bytes and independent frozen trees", async () => {
  const db = await fresh(); seed(db, { ids: ["special"] });
  const special = JSON.parse('{"__proto__":{"nested":["😀\\u0001é"]},"numbers":[0,-1.5,1e308],"constructor":{"value":1}}');
  db.mutate("patch", { id: "special", patch: { payload: special } }, worker);
  const original = raw(db, "special"), result = take(db, { mode: "accept", max: 1 });
  assert.equal(result.checked, true); assert.deepEqual(result.claims[0].payload, special);
  assert.deepEqual(raw(db, "special").payload, original.payload);
});


test("detached frozen previous survives the call but the actual captured mutation context expires", async () => {
  let context: MutationContext | undefined, saved: unknown;
  const work = queue("prefixLifetime");
  const db = await testDatabase(define({ uses: [work], http: {
    seed: mutation("seed", (ctx) => { work.enqueue(ctx, "a", { nested: ["original"] }); return null; }),
    take: mutation("take", (ctx) => work.claimMany(ctx, "new-worker", { admit: (_claim, previous) => {
      context = ctx; saved = previous; return false;
    } })),
  } }));
  db.mutate("seed"); assert.deepEqual(db.mutate("take"), []);
  assert.ok(Object.isFrozen(saved));
  assert.deepEqual((saved as { payload: unknown }).payload, { nested: ["original"] });
  assert.throws(() => context!.get(work.records, ["", "a"]), (error: unknown) => (error as { code?: string }).code === "INVALID_CONTEXT");
});


test("actual esbuild native fixture also executes prefix and genuine guest rollback through bundled SDK contexts", async () => {
  const db = await testDatabase<typeof app>(new URL("queue-prefix-native.fixture.ts", import.meta.url).pathname);
  seed(db, { ids: ["a", "b"], text: 12_000 });
  const b = canonicalJson(raw(db, "b")), counters = book(db);
  const first = take(db);
  assert.equal(first.calls, 1); assert.deepEqual(first.claims, []);
  assert.equal(raw(db, "a").state, "failed"); assert.equal(canonicalJson(raw(db, "b")), b); assert.deepEqual(book(db), counters);
  seed(db, { ids: ["c"] }); const before = canonicalJson(db.data);
  failure(() => take(db, { mode: "hostFailure" }), /Method operation budget exceeds 100000/);
  assert.equal(canonicalJson(db.data), before);
});
