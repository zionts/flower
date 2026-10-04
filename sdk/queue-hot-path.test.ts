import assert from "node:assert/strict";
import { test } from "node:test";
import { define, fail, FlowerError, mutation, query, v } from "./index.ts";
import type { HistoryIdentity, Json, MutationContext } from "./index.ts";
import { canonicalJson } from "./json.ts";
import { queue } from "./temporal.ts";
import type { LeaseIdentity, QueueWaiter } from "./temporal.ts";
import { testDatabase } from "./testing.ts";

const jobs = queue("hotJobs", { lease: { defaultMs: 100 }, result: v.object({ ok: v.boolean() }) });
const identity = v.object({
  id: v.string(), owner: v.string(), token: v.int(),
  history: v.optional(v.object({ database: v.string(), incarnation: v.string() })),
});
const app = define({
  uses: [jobs],
  http: {
    ...jobs.http("jobs", { methods: ["enqueue", "claim", "renew", "complete", "fail", "release", "get", "stats"] }),
    ...jobs.http("tenant", { methods: ["enqueue", "claim", "get", "ready"], scope: "argument" }),
    finish: mutation("finish", { args: identity }, (ctx, lease) => { jobs.finish(ctx, lease); return null; }),
    finishIn: mutation("finishIn", { args: v.object({ scope: v.string(), lease: identity }) }, (ctx, { scope, lease }) => {
      jobs.scope(scope).finish(ctx, lease);
      return null;
    }),
    finishAndFail: mutation("finishAndFail", { args: identity }, (ctx, lease) => {
      jobs.finish(ctx, lease);
      fail("AFTER_FINISH", "Roll the deletion back");
    }),
    line: query("line", (ctx) => ctx.scan(jobs.line).map((row) => row.value)),
  },
});

function lost(run: () => unknown): void {
  assert.throws(run, (error: unknown) => error instanceof FlowerError && error.failure?.code === "LEASE_LOST");
}

const leaseOf = ({ id, owner, token, history }: LeaseIdentity): LeaseIdentity =>
  ({ id, owner, token, ...(history === undefined ? {} : { history }) });

test("finish deletes without a result, and replaying its request does not delete a replacement", async () => {
  const db = await testDatabase(app);
  db.mutate("jobs.enqueue", { id: "one", payload: { n: 1 } });
  const first = db.mutate("jobs.claim", { owner: "w" })!;
  const lease = leaseOf(first);
  assert.equal(db.mutate("finish", lease, { requestId: "finished-one" }), null);
  assert.equal(db.query("jobs.get", { id: "one" }), null);
  assert.deepEqual(db.query("jobs.stats"), {
    ready: false, oldestReadyAt: null, nextAvailableAt: null, readyCount: 0, leasedCount: 0, delayedCount: 0,
  });
  lost(() => db.mutate("finish", lease));
  // No replace option is needed, and the fencing counter must survive deletion.
  db.mutate("jobs.enqueue", { id: "one", payload: { n: 2 } });
  const second = db.mutate("jobs.claim", { owner: "w" })!;
  assert.ok(second.token > first.token);
  const before = db.data;
  assert.equal(db.mutate("finish", lease, { requestId: "finished-one" }), null);
  assert.deepEqual(db.data, before, "request-id replay returns the old receipt without executing finish again");
  lost(() => db.mutate("finish", lease));
  assert.deepEqual(db.data, before);
  assert.equal(db.mutate("finish", leaseOf(second)), null);
});

test("finish rejects wrong owners, tokens, non-leased jobs and expiry, before or after maintenance", async () => {
  const db = await testDatabase(app);
  db.mutate("jobs.enqueue", { id: "one", payload: null });
  const lease = leaseOf(db.mutate("jobs.claim", { owner: "w" })!);
  const before = db.data;
  lost(() => db.mutate("finish", { ...lease, owner: "other" }));
  lost(() => db.mutate("finish", { ...lease, token: lease.token + 1 }));
  lost(() => db.mutate("finish", { ...lease, id: "missing" }));
  assert.deepEqual(db.data, before);
  db.now += 100;
  lost(() => db.mutate("finish", lease));
  assert.deepEqual(db.data, before, "an expired but unswept lease is not deleted");
  db.maintain();
  const expired = db.data;
  lost(() => db.mutate("finish", lease));
  assert.deepEqual(db.data, expired);
  const current = leaseOf(db.mutate("jobs.claim", { owner: "w" })!);
  lost(() => db.mutate("finish", lease));
  assert.equal(db.mutate("finish", current), null);

  for (const state of ["pending", "completed", "failed", "released"] as const) {
    db.mutate("jobs.enqueue", { id: state, payload: null });
    let identity: LeaseIdentity = { id: state, owner: "w", token: 1 };
    if (state !== "pending") {
      identity = leaseOf(db.mutate("jobs.claim", { owner: "w" })!);
      if (state === "completed") db.mutate("jobs.complete", { ...identity, result: { ok: true } });
      if (state === "failed") db.mutate("jobs.fail", { ...identity, error: null, retry: false });
      if (state === "released") db.mutate("jobs.release", identity);
    }
    const before = db.data;
    lost(() => db.mutate("finish", identity));
    assert.deepEqual(db.data, before, state);
    // Keep subsequent iterations from claiming this pending job.
    if (state === "pending" || state === "released") {
      db.mutate("finish", leaseOf(db.mutate("jobs.claim", { owner: "w" })!));
    }
  }
});

test("finish uses the stored renewed expiry and rolls back with the enclosing mutation", async () => {
  const db = await testDatabase(app);
  db.mutate("jobs.enqueue", { id: "one", payload: null });
  const original = leaseOf(db.mutate("jobs.claim", { owner: "w" })!);
  db.now += 50;
  db.mutate("jobs.renew", { leases: [original], leaseMs: 100 });
  db.now += 50;
  const before = db.data;
  assert.throws(() => db.mutate("finishAndFail", original), (error: unknown) =>
    error instanceof FlowerError && error.failure?.code === "AFTER_FINISH");
  assert.deepEqual(db.data, before);
  db.now += 49;
  assert.equal(db.mutate("finish", original), null, "the current stored lease, not the original claim's expiry, governs finish");
});

test("finish fences both the supplied and stored lease to the current history", async () => {
  const db = await testDatabase(app);
  const setHistory = (history: HistoryIdentity) => {
    (db as unknown as { stores: Map<string, { data: Record<string, Json> }> }).stores.get("")!.data["$flower.retention"] = { ...history };
  };
  db.mutate("jobs.enqueue", { id: "one", payload: null });
  const unbound = leaseOf(db.mutate("jobs.claim", { owner: "w" })!);
  const original = { database: "a".repeat(32), incarnation: "b".repeat(32) };
  setHistory(original);
  lost(() => db.mutate("finish", unbound));
  lost(() => db.mutate("finish", { ...unbound, history: original }));
  db.now += 100;
  const old = leaseOf(db.mutate("jobs.claim", { owner: "w" })!);
  lost(() => db.mutate("finish", { id: old.id, owner: old.owner, token: old.token }));
  lost(() => db.mutate("finish", { ...old, history: { ...original, database: "d".repeat(32) } }));
  const restored = { ...original, incarnation: "c".repeat(32) };
  setHistory(restored);
  const before = db.data;
  lost(() => db.mutate("finish", old));
  lost(() => db.mutate("finish", { ...old, history: restored }));
  assert.deepEqual(db.data, before, "forging the current history cannot revive a stored old-history lease");
  db.now += 100;
  const current = leaseOf(db.mutate("jobs.claim", { owner: "w" })!);
  lost(() => db.mutate("finish", { ...current, history: original }));
  assert.equal(db.mutate("finish", current), null);
});

test("finish acts only in its selected scope, including when job IDs and lease tokens coincide", async () => {
  const db = await testDatabase(app);
  db.mutate("jobs.enqueue", { id: "one", payload: "default" });
  const root = leaseOf(db.mutate("jobs.claim", { owner: "w" })!);
  for (const scope of ["a", "b"]) db.mutate("tenant.enqueue", { scope, id: "one", payload: scope });
  const a = leaseOf(db.mutate("tenant.claim", { scope: "a", owner: "w" })!);
  const b = leaseOf(db.mutate("tenant.claim", { scope: "b", owner: "w" })!);
  assert.deepEqual(a, b, "the view chooses the scope; a LeaseIdentity itself has none");
  lost(() => db.mutate("finishIn", { scope: "missing", lease: a }));
  db.mutate("finishIn", { scope: "a", lease: a });
  lost(() => db.mutate("finishIn", { scope: "a", lease: a }));
  assert.equal(db.query("tenant.get", { scope: "a", id: "one" }), null);
  assert.equal(db.query("tenant.get", { scope: "b", id: "one" })!.state, "leased");
  assert.equal(db.query("jobs.get", { id: "one" })!.state, "leased");
  db.mutate("finish", root);
  db.mutate("finishIn", { scope: "b", lease: b });
});

/** A source-operation spy for the empty-queue path; real indexed behavior is exercised below. */
function emptyContext() {
  const rows = new Map<string, unknown>();
  const calls: string[] = [];
  const state = { now: 1_000_000 };
  const rowKey = (collection: { name: string }, key: unknown) => canonicalJson([collection.name, key] as Json);
  const ctx = {
    clock: () => state.now, history: () => null, changesAt: () => {},
    get(collection: { name: string }, key: unknown) { calls.push(`get ${collection.name}`); return rows.get(rowKey(collection, key)) ?? null; },
    set(collection: { name: string }, key: unknown, value: unknown) { calls.push(`set ${collection.name}`); rows.set(rowKey(collection, key), value); },
    delete(collection: { name: string }, key: unknown) { calls.push(`delete ${collection.name}`); rows.delete(rowKey(collection, key)); },
    range: () => ({ rows: [], cursor: null }),
  } as unknown as MutationContext;
  return { ctx, calls, state };
}

test("finish reads once and deletes once without serializing a completed job", async () => {
  const db = await testDatabase(app);
  db.mutate("jobs.enqueue", { id: "one", payload: null });
  const lease = db.mutate("jobs.claim", { owner: "w" })!;
  const { ctx, calls } = emptyContext();
  ctx.set(jobs.records, ["", "one"], db.query("jobs.get", { id: "one" })!);
  calls.length = 0;
  assert.equal(jobs.finish(ctx, lease), undefined);
  assert.deepEqual(calls, ["get hotJobs", "delete hotJobs"]);
  for (const token of [0, -1, 1.5, NaN]) assert.throws(() => jobs.finish(ctx, { ...lease, token }), /Lease token/);
  assert.throws(() => jobs.finish(ctx, { ...lease, id: "" }), /Job ID/);
});

test("empty waiting polls skip writes until three quarters of the wait remains, including the admit path", () => {
  for (const admit of [undefined, () => true]) {
    const { ctx, calls, state } = emptyContext();
    const poll = () => jobs.claimMany(ctx, "w", { max: 2, waitMs: 100, ...(admit ? { admit } : {}) });
    assert.deepEqual(poll(), []);
    const initial = ctx.get(jobs.line, ["", "w"])!;
    assert.deepEqual(initial, { scope: "", owner: "w", room: 2, since: 1_000_000, expiresAt: 1_000_100 });
    calls.length = 0;
    for (const delta of [0, 1, 12, 24]) {
      state.now = 1_000_000 + delta;
      assert.deepEqual(poll(), []);
      assert.deepEqual(ctx.get(jobs.line, ["", "w"]), initial);
    }
    assert.equal(calls.some((call) => /^(set|delete) /.test(call)), false, "fresh polls perform no writes at all");
    state.now = 1_000_025;
    calls.length = 0;
    poll();
    assert.deepEqual(calls.filter((call) => call.startsWith("set ")), ["set hotJobs.line"]);
    assert.deepEqual(ctx.get(jobs.line, ["", "w"]), { ...initial, expiresAt: 1_000_125 });
    state.now = 1_000_125;
    poll();
    assert.deepEqual(ctx.get(jobs.line, ["", "w"]), { ...initial, since: 1_000_125, expiresAt: 1_000_225 }, "an expired place rejoins at the back");
  }
});

test("quarter-wait refresh boundaries keep half-wait headroom for small and odd durations", () => {
  for (const waitMs of [1, 2, 3, 4, 5, 6, 7, 8, 9, 60_000]) {
    for (const elapsed of new Set([0, Math.floor(waitMs / 4), Math.ceil(waitMs / 4), Math.floor(waitMs / 2), waitMs - 1, waitMs])) {
      for (const admit of [undefined, () => true]) {
        const { ctx, calls, state } = emptyContext();
        const initial = state.now;
        const poll = () => jobs.claimMany(ctx, "w", { waitMs, ...(admit ? { admit } : {}) });
        poll();
        state.now += elapsed;
        calls.length = 0;
        poll();
        const refreshed = elapsed * 4 >= waitMs;
        const spot = ctx.get(jobs.line, ["", "w"])!;
        const label = `waitMs=${waitMs}, elapsed=${elapsed}, admit=${admit !== undefined}`;
        assert.deepEqual(calls.filter((call) => call.startsWith("set ")), refreshed ? ["set hotJobs.line"] : [], label);
        assert.equal(spot.expiresAt, initial + waitMs + (refreshed ? elapsed : 0), label);
        assert.equal(spot.since, elapsed < waitMs ? initial : state.now, label);
        assert.ok(spot.expiresAt - state.now - Math.floor(waitMs / 2) > waitMs / 4, label);
      }
    }
  }
});

test("waiting polls record changed room, shorter deadlines, departures and one-millisecond waits", () => {
  const { ctx, calls, state } = emptyContext();
  const spot = () => ctx.get(jobs.line, ["", "w"]);
  jobs.claimMany(ctx, "w", { max: 2, waitMs: 100 });
  for (const room of [3, 1]) {
    state.now++;
    jobs.claimMany(ctx, "w", { max: room, waitMs: 100 });
    assert.deepEqual(spot(), { scope: "", owner: "w", room, since: 1_000_000, expiresAt: state.now + 100 });
  }
  jobs.claimMany(ctx, "w", { max: 1, waitMs: 10 });
  assert.equal(spot()!.expiresAt, state.now + 10, "a shorter wait takes effect immediately");
  jobs.claimMany(ctx, "w", { max: 1, waitMs: 100 });
  assert.equal(spot()!.expiresAt, state.now + 100, "less than three quarters of the requested wait remaining triggers an extension");
  calls.length = 0;
  jobs.claimMany(ctx, "w");
  assert.equal(calls.some((call) => /^(set|delete) /.test(call)), false, "omitting waitMs leaves the line alone");
  for (const options of [{ max: 0, waitMs: 100 }, { max: 1, waitMs: 0 }]) {
    jobs.claimMany(ctx, "w", options);
    assert.equal(spot(), null);
    jobs.claimMany(ctx, "w", { waitMs: 100 });
  }
  jobs.claimMany(ctx, "w", { waitMs: 1 });
  assert.equal(spot()!.expiresAt, state.now + 1);
  calls.length = 0;
  jobs.claimMany(ctx, "w", { waitMs: 1 });
  assert.equal(calls.some((call) => call.startsWith("set ")), false);
  state.now++;
  jobs.claimMany(ctx, "w", { waitMs: 1 });
  assert.equal(spot()!.since, state.now);
});

test("coalesced line refreshes preserve scoped places, partial claims and actual expiry", async () => {
  const db = await testDatabase(app);
  const poll = (scope: string, owner: string, max = 2) => db.mutate("tenant.claim", { scope, owner, max, waitMs: 100 });
  const line = (scope: string, owner: string): QueueWaiter | undefined => db.query("line").find((row) => row.scope === scope && row.owner === owner);
  poll("a", "w");
  db.now += 1;
  poll("a", "second");
  poll("b", "w");
  const a = line("a", "w")!;
  const b = line("b", "w")!;
  db.now += 23;
  poll("a", "w");
  assert.deepEqual(line("a", "w"), a);
  assert.deepEqual(line("b", "w"), b);
  db.mutate("tenant.enqueue", { scope: "a", id: "one", payload: null });
  const first = poll("a", "w")!;
  assert.equal(first.id, "one", "a fresh line never prevents claiming new work");
  assert.deepEqual(line("a", "w"), { ...a, room: 1, expiresAt: db.now + 100 });
  db.mutate("finishIn", { scope: "a", lease: leaseOf(first) });
  db.mutate("tenant.enqueue", { scope: "a", id: "two", payload: null });
  const second = poll("a", "w", 1)!;
  assert.equal(second.id, "two");
  assert.equal(line("a", "w"), undefined, "a full claim leaves even a fresh place");
  db.mutate("finishIn", { scope: "a", lease: leaseOf(second) });
  db.now = 1_000_101;
  db.maintain();
  assert.deepEqual(db.query("line"), [], "unrefreshed places expire at their stored deadlines");
});

test("a coalesced waiter expires for readiness without maintenance, and half-interval refreshes keep its place", async () => {
  const db = await testDatabase(app);
  const poll = (owner: string) => db.mutate("tenant.claim", { scope: "a", owner, waitMs: 100 });
  const ready = (owner: string) => db.query("tenant.ready", { scope: "a", owner });
  poll("first");
  db.now++;
  poll("second");
  db.now += 23;
  poll("first");
  db.now += 75;
  db.mutate("tenant.enqueue", { scope: "a", id: "one", payload: null });
  assert.deepEqual([ready("first"), ready("second")], [true, false]);
  db.now++;
  assert.deepEqual([ready("first"), ready("second")], [false, true], "the first place expires at its stored deadline without a sweep");
  const claim = poll("second")!;
  db.mutate("finishIn", { scope: "a", lease: leaseOf(claim) });
  poll("first");
  for (let i = 0; i < 6; i++) {
    db.now += 24;
    poll("first");
    db.now += 26;
    poll("first");
    db.maintain();
    assert.deepEqual(db.query("line"), [{ scope: "a", owner: "first", room: 1, since: 1_000_100, expiresAt: db.now + 100 }]);
  }
});
