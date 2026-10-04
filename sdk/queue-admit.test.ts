// Ordinary queue SDK contracts through the real Node testDatabase. These are
// NOT SQL-serving, native-controller, authorization-provenance or Wasmtime proof.
import assert from "node:assert/strict";
import { test } from "node:test";
import { define, FlowerError, mutation, query, v } from "./index.ts";
import type { Json, MutationContext } from "./index.ts";
import { queue } from "./temporal.ts";
import type { Claim, ClaimOptions, Job, Queue } from "./temporal.ts";
import { testDatabase } from "./testing.ts";

type Payload = { pointer: { id: string }; nested: { items: { text: string }[] } };
type Result = { details: { values: number[] } };
type Previous = Parameters<NonNullable<ClaimOptions<Payload, Result>["admit"]>>[1];
const payload = (id = "authentic"): Payload => ({ pointer: { id }, nested: { items: [{ text: "original" }] } });
const originalKey = (claim: Claim<Payload>): [string, string] => [claim.scope, claim.id];

function frozen(value: unknown): void {
  if (value === null || typeof value !== "object") return;
  assert.ok(Object.isFrozen(value));
  for (const item of Object.values(value)) frozen(item);
}
function budgetFailure(run: () => unknown): void {
  assert.throws(run, (error: unknown) => error instanceof FlowerError && error.failure?.code === "EVALUATION_BUDGET");
}

function fixture(admit: (ctx: MutationContext, work: Queue<Payload, Result>, claim: Claim<Payload>, previous: Previous) => boolean) {
  const work = queue<Payload, Result>("admission", { lease: { defaultMs: 10 }, retry: { maxAttempts: 3 } });
  const db = testDatabase(define({
    uses: [work],
    http: {
      ...work.http("work", { methods: ["enqueue", "claim", "get"] }),
      stored: query("stored", { args: v.string() }, (ctx, id) => ctx.get(work.records, ["", id])),
      all: query("all", (ctx) => ctx.scan(work.records)),
      bookkeeping: query("bookkeeping", (ctx) => work.collections.filter((entry) => entry !== work.records)
        .map((entry) => ({ name: entry.name, rows: ctx.scan(entry) }))),
      patch: mutation("patch", { args: v.object({ id: v.string(), patch: v.json() }) }, (ctx, input) => {
        const key: [string, string] = ["", input.id];
        const current = ctx.get(work.records, key)!;
        ctx.set(work.records, key, { ...current, ...input.patch as object });
        return null;
      }),
      take: mutation("take", { args: v.nullable(v.object({ max: v.optional(v.int()), waitMs: v.optional(v.int()) })) }, (ctx, options) =>
        work.claimMany(ctx, "new-worker", { ...options, admit: (claim, previous) => admit(ctx, work, claim, previous) })),
    },
  }));
  return db;
}

test("admission sees the exact raw delayed job before promotion, attempts, fencing or turn writes", async () => {
  let expected: Job<Payload, Result>;
  let previousSeen: Previous;
  const db = await fixture((ctx, work, claim, previous) => {
    assert.deepEqual(previous, expected);
    assert.deepEqual(ctx.get(work.records, originalKey(claim)), expected);
    assert.equal(previous.queued, "later");
    assert.equal(previous.availableAt, expected.availableAt);
    assert.equal(previous.attempts, 0);
    frozen(previous);
    assert.throws(() => { (previous.error as { detail: string[] }).detail[0] = "forged"; }, TypeError);
    assert.equal(claim.attempt, 1);
    assert.equal(claim.token, 1);
    for (const entry of work.collections.filter((entry) => entry.name === "$flower.fencing")) assert.deepEqual(ctx.scan(entry), []);
    previousSeen = previous;
    return true;
  });
  db.mutate("work.enqueue", { id: "delayed", payload: payload(), delayMs: 10 });
  db.mutate("patch", { id: "delayed", patch: { result: { details: { values: [1, 2] } }, error: { detail: ["stored"] } } });
  expected = db.query("stored", "delayed")!;
  db.now += 10;
  const [claim] = db.mutate("take");
  assert.equal(claim.id, "delayed");
  assert.equal(db.query("stored", "delayed")!.attempts, 1);
  assert.deepEqual(previousSeen!, expected);
});

test("raw expired leases, original schedule, attempt, result and error survive admission without reconstruction", async () => {
  let expected: Job<Payload, Result>;
  const db = await fixture((ctx, work, claim, previous) => {
    assert.deepEqual(previous, expected);
    assert.equal(previous.state, "leased");
    assert.equal(previous.availableAt, null);
    assert.equal(previous.leaseExpiresAt, 1_000_010);
    assert.deepEqual(previous.lease, { owner: "old-worker", token: 1, expiresAt: 1_000_010 });
    assert.equal(previous.attempts, 1);
    assert.equal(previous.updatedAt, 1_000_000);
    assert.equal(previous.error, null);
    assert.deepEqual(ctx.get(work.records, originalKey(claim)), expected);
    frozen(previous);
    assert.throws(() => { (previous.lease as { owner: string }).owner = "forged"; }, TypeError);
    assert.notEqual(previous.lease, ctx.get(work.records, originalKey(claim))!.lease);
    assert.equal(claim.attempt, 2);
    assert.equal(claim.token, 2);
    return true;
  });
  db.mutate("work.enqueue", { id: "expired", payload: payload() });
  db.mutate("work.claim", { owner: "old-worker" });
  expected = db.query("stored", "expired")!;
  db.now += 10;
  const [claim] = db.mutate("take");
  assert.equal(claim.attempt, 2);
  const leased = db.query("stored", "expired")!;
  assert.deepEqual(leased.error, { code: "LEASE_EXPIRED", message: "Worker lease expired", at: 1_000_010 });
});

test("every nested previous and proposed value is detached and frozen, with no records or claimed aliases", async () => {
  let previousSeen: Previous;
  let proposedSeen: Claim<Payload>;
  const db = await fixture((ctx, work, claim, previous) => {
    previousSeen = previous;
    proposedSeen = claim;
    const stored = ctx.get(work.records, originalKey(claim))!;
    frozen(previous);
    frozen(claim);
    assert.notEqual(previous, stored);
    assert.notEqual(previous.payload, stored.payload);
    assert.notEqual(previous.payload.nested.items, stored.payload.nested.items);
    assert.notEqual(previous.result, stored.result);
    assert.notEqual(previous.payload, claim.payload);
    assert.notEqual(previous.payload.nested.items, claim.payload.nested.items);
    assert.throws(() => { (previous.payload.pointer as { id: string }).id = "forged"; }, TypeError);
    assert.throws(() => { (previous.payload.nested.items as { text: string }[]).push({ text: "forged" }); }, TypeError);
    assert.throws(() => { (previous.result!.details.values as number[])[0] = 99; }, TypeError);
    assert.throws(() => { (claim as { token: number }).token = 99; }, TypeError);
    assert.throws(() => { claim.payload.nested.items[0].text = "forged"; }, TypeError);
    assert.deepEqual(ctx.get(work.records, originalKey(claim)), stored);
    return true;
  });
  db.mutate("work.enqueue", { id: "nested", payload: payload() });
  db.mutate("patch", { id: "nested", patch: { result: { details: { values: [1] } } } });
  const [claimed] = db.mutate("take");
  const stored = db.query("stored", "nested")!;
  assert.equal(stored.payload.pointer.id, "authentic");
  assert.equal(stored.payload.nested.items[0].text, "original");
  assert.deepEqual(stored.result, { details: { values: [1] } });
  assert.deepEqual(claimed, proposedSeen!);
  assert.notEqual(previousSeen!.payload, claimed.payload);
});

test("pointer tamper refusal preserves an application's quarantine and exact original row without any lease counters", async () => {
  let expected: Job<Payload, Result>;
  const db = await fixture((ctx, work, claim, previous) => {
    assert.deepEqual(previous, expected);
    assert.equal(previous.payload.pointer.id, "tampered-pointer");
    // The SDK does not authenticate this application's marker or grant a new
    // quarantine capability. Parent/backend authorization is a separate gate.
    ctx.set(work.records, originalKey(claim), {
      ...ctx.get(work.records, originalKey(claim))!, state: "failed", availableAt: null, queued: null,
      error: { code: "APPLICATION_QUARANTINE", original: previous as unknown as Json },
    });
    return false;
  });
  db.mutate("work.enqueue", { id: "quarantined", payload: payload("tampered-pointer"), group: "group", delayMs: 10 });
  expected = db.query("stored", "quarantined")!;
  const before = db.query("bookkeeping");
  db.now += 10;
  assert.deepEqual(db.mutate("take"), []);
  const quarantined = db.query("stored", "quarantined")!;
  assert.equal(quarantined.state, "failed");
  assert.equal(quarantined.lease, null);
  assert.equal(quarantined.attempts, 0);
  assert.deepEqual((quarantined.error as { original: Json }).original, expected);
  assert.deepEqual(db.query("bookkeeping"), before);
});

test("unchanged refusals cancel without attempts, fencing or turns, and the next accepted job gets the first token", async () => {
  const seen: { id: string; token: number; attempts: number }[] = [];
  const db = await fixture((_ctx, _work, claim, previous) => {
    seen.push({ id: claim.id, token: claim.token, attempts: previous.attempts });
    return claim.id === "accepted";
  });
  db.mutate("work.enqueue", { id: "refused", payload: payload(), priority: -1, group: "only" });
  db.mutate("work.enqueue", { id: "accepted", payload: payload() });
  const before = db.query("bookkeeping");
  const [claim] = db.mutate("take");
  assert.deepEqual(seen, [{ id: "refused", token: 1, attempts: 0 }, { id: "accepted", token: 1, attempts: 0 }]);
  assert.equal(claim.token, 1);
  assert.equal(db.query("stored", "refused"), null);
  const after = db.query("bookkeeping");
  assert.deepEqual(after.find((entry) => entry.name === "$flower.turns")!.rows.filter((row) => row.key.includes("-1")),
    before.find((entry) => entry.name === "$flower.turns")!.rows.filter((row) => row.key.includes("-1")));
});

test("all refused delayed jobs leave unrelated promotions, fencing, group turns and line untouched", async () => {
  const db = await fixture(() => false);
  db.mutate("work.enqueue", { id: "refused", payload: payload(), group: "g", delayMs: 10 });
  db.mutate("work.enqueue", { id: "not-due", payload: payload(), group: "g", delayMs: 20 });
  const before = db.query("bookkeeping");
  const unrelated = db.query("stored", "not-due");
  db.now += 10;
  assert.deepEqual(db.mutate("take"), []);
  assert.equal(db.query("stored", "refused"), null);
  assert.deepEqual(db.query("stored", "not-due"), unrelated);
  assert.deepEqual(db.query("bookkeeping"), before);
});

test("admission preserves the ordinary once-per-call line overtake when several jobs are accepted", async () => {
  const db = await fixture(() => true);
  db.mutate("work.claim", { owner: "stuck-a", max: 1, waitMs: 10_000 });
  db.mutate("work.claim", { owner: "stuck-b", max: 1, waitMs: 10_000 });
  db.mutate("work.enqueue", { id: "a", payload: payload() });
  db.mutate("work.enqueue", { id: "b", payload: payload() });
  db.now += 1_000; // the documented queue turn, not a wall-clock timing waiver
  assert.deepEqual(db.mutate("take", { max: 2 }).map((claim) => claim.id), ["a", "b"]);
  const line = db.query("bookkeeping").find((entry) => entry.name === "admission.line")!;
  assert.deepEqual(line.rows.map((row) => (row.value as { owner: string }).owner), ["stuck-b"]);
});

test("callback-written pending replacements are not repeatedly selected or overwritten, even if admitted", async () => {
  const seen: string[] = [];
  const db = await fixture((ctx, work, claim) => {
    seen.push(claim.id);
    if (claim.id === "replace") {
      ctx.set(work.records, originalKey(claim), { ...ctx.get(work.records, originalKey(claim))!, payload: payload("replacement") });
    }
    return true;
  });
  db.mutate("work.enqueue", { id: "replace", payload: payload(), priority: -1 });
  db.mutate("work.enqueue", { id: "next", payload: payload() });
  assert.deepEqual(db.mutate("take", { max: 2 }).map((claim) => claim.id), ["next"]);
  assert.deepEqual(seen, ["replace", "next"]);
  const replaced = db.query("stored", "replace")!;
  assert.equal(replaced.payload.pointer.id, "replacement");
  assert.equal(replaced.state, "pending");
  assert.equal(replaced.attempts, 0);
  assert.equal(db.query("stored", "next")!.lease!.token, 1);
});

test("callback deletion stays deleted and does not spend a lease token", async () => {
  const db = await fixture((ctx, work, claim) => { ctx.delete(work.records, originalKey(claim)); return true; });
  db.mutate("work.enqueue", { id: "deleted", payload: payload() });
  const before = db.query("bookkeeping");
  assert.deepEqual(db.mutate("take"), []);
  assert.equal(db.query("stored", "deleted"), null);
  assert.deepEqual(db.query("bookkeeping"), before);
});

test("reentrant admission cannot issue its stale proposed fencing token", async () => {
  const db = await fixture((ctx, work) => { work.claim(ctx, "reentrant"); return true; });
  db.mutate("work.enqueue", { id: "a", payload: payload() });
  db.mutate("work.enqueue", { id: "b", payload: payload() });
  assert.deepEqual(db.mutate("take"), []);
  assert.equal(db.query("stored", "a")!.lease!.owner, "reentrant");
  assert.equal(db.query("stored", "b")!.lease!.owner, "reentrant");
});

test("huge raw JSON refuses before any detached snapshot or callback, and leaves all rows and counters unchanged", async () => {
  let calls = 0;
  const db = await fixture(() => { ++calls; return true; });
  db.mutate("work.enqueue", { id: "huge", payload: { pointer: { id: "x" }, nested: { items: [{ text: "x".repeat(100_001) }] } } });
  const before = db.query("all");
  const bookkeeping = db.query("bookkeeping");
  budgetFailure(() => db.mutate("take"));
  assert.equal(calls, 0);
  assert.deepEqual(db.query("all"), before);
  assert.deepEqual(db.query("bookkeeping"), bookkeeping);
});

test("shared snapshot work does not reset between candidates and a whole failed call rolls back earlier cancellations", async () => {
  let calls = 0;
  const db = await fixture(() => { ++calls; return false; });
  for (const id of ["a", "b"]) {
    db.mutate("work.enqueue", { id, payload: { pointer: { id }, nested: { items: [{ text: "x".repeat(12_000) }] } } });
  }
  const before = db.query("all");
  const bookkeeping = db.query("bookkeeping");
  budgetFailure(() => db.mutate("take"));
  assert.equal(calls, 1);
  assert.deepEqual(db.query("all"), before);
  assert.deepEqual(db.query("bookkeeping"), bookkeeping);
});

test("dense huge arrays are preflight-refused without handing out a partial claim", async () => {
  let calls = 0;
  const db = await fixture(() => { ++calls; return true; });
  db.mutate("work.enqueue", { id: "array", payload: { pointer: { id: "x" }, nested: { items: Array.from({ length: 15_000 }, () => ({ text: "x" })) } } });
  const original = db.query("stored", "array");
  budgetFailure(() => db.mutate("take"));
  assert.equal(calls, 0);
  assert.deepEqual(db.query("stored", "array"), original);
});

test("deep durable JSON stays bounded and frozen; invalid method-envelope depth never produces a snapshot", async () => {
  let calls = 0;
  const db = await fixture((_ctx, _work, _claim, previous) => { ++calls; frozen(previous); return true; });
  let deep: Json = "leaf";
  // Leave room for the actual ordinary call/record wrappers in the existing
  // depth-128 budget; do not raise that budget to make the fixture pass.
  for (let level = 0; level < 110; ++level) deep = { n: deep };
  db.mutate("work.enqueue", { id: "deep", payload: deep as never });
  assert.equal(db.mutate("take")[0].id, "deep");
  assert.equal(calls, 1);
  // Invalid durable JSON is refused by the actual ordinary runtime, not a fake
  // raw/native original. The SDK never fabricates a snapshot for it.
  for (let level = 0; level < 15; ++level) deep = { n: deep };
  assert.throws(() => db.mutate("work.enqueue", { id: "too-deep", payload: deep as never }), /nesting|depth|128/i);
  assert.equal(db.query("stored", "too-deep"), null);
  assert.equal(calls, 1);
});

test("native JSON __proto__ payload fields stay data and are deeply frozen", async () => {
  const special = JSON.parse('{"__proto__":{"nested":["authentic"]},"constructor":{"value":1}}');
  const db = await fixture((_ctx, _work, claim, previous) => {
    assert.equal(Object.getPrototypeOf(previous.payload), Object.prototype);
    assert.ok(Object.hasOwn(previous.payload, "__proto__"));
    assert.deepEqual(previous.payload, special);
    frozen(previous);
    assert.notEqual(previous.payload, claim.payload);
    return true;
  });
  db.mutate("work.enqueue", { id: "proto", payload: special });
  assert.deepEqual(db.mutate("take")[0].payload, special);
});

test("a raw identity mismatch is visible for quarantine; acceptance cannot lease a different row by its pointer", async () => {
  const db = await fixture((_ctx, _work, claim, previous) => {
    assert.equal(claim.id, "actual-key");
    assert.equal(previous.id, "other-row-pointer");
    return true;
  });
  db.mutate("work.enqueue", { id: "actual-key", payload: payload() });
  db.mutate("patch", { id: "actual-key", patch: { id: "other-row-pointer" } });
  const before = db.query("bookkeeping");
  assert.throws(() => db.mutate("take"), (error: unknown) => error instanceof FlowerError && error.failure?.code === "INVALID_JOB");
  assert.equal(db.query("stored", "actual-key")!.attempts, 0);
  assert.equal(db.query("stored", "other-row-pointer"), null);
  assert.deepEqual(db.query("bookkeeping"), before);
});

test("admission uses the existing 64-candidate bound, not an unbounded false loop or extra capacity", async () => {
  let calls = 0;
  const db = await fixture(() => { ++calls; return false; });
  for (let index = 0; index < 65; ++index) db.mutate("work.enqueue", { id: String(index).padStart(2, "0"), payload: payload() });
  assert.deepEqual(db.mutate("take"), []);
  assert.equal(calls, 64);
  assert.equal(db.query("all").length, 1);
  assert.throws(() => db.mutate("take", { max: 65 }), /max is at most 64/);
});

test("legacy one-argument admission is valid and a new adopter explicitly refuses a missing previous", async () => {
  const legacy: NonNullable<ClaimOptions<Payload, Result>["admit"]> = (claim) => claim.payload.pointer.id === "authentic";
  const db = await fixture((_ctx, _work, claim, previous) => legacy(claim, previous));
  db.mutate("work.enqueue", { id: "legacy", payload: payload() });
  assert.equal(db.mutate("take")[0].id, "legacy");
  const adopter: NonNullable<ClaimOptions<Payload, Result>["admit"]> = (_claim, previous) => {
    if (previous === undefined) throw new Error("actual previous job required");
    return previous.payload.pointer.id === "authentic";
  };
  assert.throws(() => adopter({} as Claim<Payload>, undefined as never), /actual previous job required/);
});

// Compile-time deep readonly/R propagation, without executing invalid mutation.
function readonlyContract(previous: Previous): void {
  // @ts-expect-error admission does not hand out mutable nested payloads
  previous.payload.pointer.id = "x";
  // @ts-expect-error result generic is preserved and nested arrays are readonly
  previous.result!.details.values.push(1);
  // @ts-expect-error an original lease is not mutable
  previous.lease!.owner = "x";
}
void readonlyContract;


test("64 refused candidates yield bounded progress and a subsequent call takes later eligible work", async () => {
  const seen: string[] = [];
  const db = await fixture((_ctx, _work, claim) => { seen.push(claim.id); return claim.id === "eligible"; });
  for (let index = 0; index < 64; ++index) db.mutate("work.enqueue", { id: `rejected-${index}`, payload: payload(), priority: -1 });
  db.mutate("work.enqueue", { id: "eligible", payload: payload() });
  const counters = db.query("bookkeeping");
  assert.deepEqual(db.mutate("take"), []);
  assert.equal(seen.length, 64);
  assert.deepEqual(db.query("bookkeeping"), counters);
  assert.equal(db.query("stored", "eligible")!.attempts, 0);
  const [claim] = db.mutate("take");
  assert.equal(claim.id, "eligible");
  assert.equal(claim.token, 1);
  assert.equal(claim.attempt, 1);
});

test("64 callback quarantines preserve exact originals and subsequent eligible work without lease writes", async () => {
  const originals = new Map<string, Job<Payload, Result>>();
  const db = await fixture((ctx, work, claim, previous) => {
    if (claim.id === "eligible") return true;
    assert.deepEqual(previous, originals.get(claim.id));
    ctx.set(work.records, originalKey(claim), {
      ...ctx.get(work.records, originalKey(claim))!, state: "failed", availableAt: null, queued: null,
      error: { code: "APPLICATION_QUARANTINE", original: previous as unknown as Json },
    });
    return false;
  });
  for (let index = 0; index < 64; ++index) {
    const id = `quarantine-${index}`;
    db.mutate("work.enqueue", { id, payload: payload(id), priority: -1, group: "blocked" });
    originals.set(id, db.query("stored", id)!);
  }
  db.mutate("work.enqueue", { id: "eligible", payload: payload() });
  const counters = db.query("bookkeeping");
  assert.deepEqual(db.mutate("take"), []);
  assert.deepEqual(db.query("bookkeeping"), counters);
  for (const [id, original] of originals) {
    const row = db.query("stored", id)!;
    assert.equal(row.state, "failed");
    assert.equal(row.attempts, original.attempts);
    assert.equal(row.lease, null);
    assert.deepEqual((row.error as { original: Json }).original, original);
  }
  const [claim] = db.mutate("take");
  assert.equal(claim.id, "eligible");
  assert.equal(claim.token, 1);
});

test("ordinary direct no-admit calls retain their uncapped max contract", async () => {
  const work = queue<Payload>("ordinary-unbounded-max");
  const db = await testDatabase(define({ uses: [work], http: {
    ...work.http("work", { methods: ["enqueue"] }),
    take: mutation("take", (ctx) => work.claimMany(ctx, "ordinary", { max: 65 })),
  } }));
  for (let index = 0; index < 65; ++index) db.mutate("work.enqueue", { id: String(index), payload: payload() });
  assert.equal(db.mutate("take").length, 65);
});
