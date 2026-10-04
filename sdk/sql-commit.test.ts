import assert from "node:assert/strict";
import test from "node:test";
import { collection, define, mutation, query, v } from "./index.ts";
import { testDatabase } from "./testing.ts";

// These are trusted-declaration model tests, NOT native ordered-commit proof.
// The real queued/core/fsync tests run in Flower's Rust service/consensus suite.
test("mutation commit deadlines are safe, sticky, min-only and fail before effects", async () => {
  const rows = collection("commit-guard-model", v.string());
  const completion = mutation("completion", { args: v.array(v.json()) }, (ctx, deadlines) => {
    ctx.set(rows, "secret", "not-durable-until-admitted");
    for (const deadline of deadlines) {
      try { ctx.requireCommitBefore(deadline as number); } catch { /* cannot swallow a native fatal */ }
    }
    return null;
  });
  const app = define({ http: { completion } });
  const model = await testDatabase(app, { now: 1000 });
  for (const deadlines of [[1000], [999, 9000], [null], [-1], [1.5], [Number.MAX_SAFE_INTEGER + 1]]) {
    assert.throws(() => model.mutate("completion", deadlines), (error: any) =>
      error.code === "EVALUATION_FAILED" && ["INVALID_VALUE", "SQL_COMMIT_EXPIRED"].includes(error.failure.code));
    assert.equal(model.revision, 0);
    assert.deepEqual(model.data, {});
  }
  model.mutate("completion", [1100, 9000]);
  assert.equal(model.revision, 1);
});

test("there is no missing-host guard shim or read-context capability", async () => {
  const complete = mutation("complete", (ctx) => { ctx.requireCommitBefore(2000); return null; });
  const inspect = query("inspect", (ctx) => {
    // @ts-expect-error QueryContext has no mutation-only attenuation primitive.
    const guard = ctx.requireCommitBefore;
    return typeof guard;
  });
  const app = define({ http: { complete, inspect } });
  const host = { now: () => 1000, clock: () => 1000, changesAt: () => null, principal: () => null, history: () => null, set: () => null };
  assert.throws(() => (app.definitions.complete as any).compute(host, null), /requireCommitBefore/);
  assert.equal((app.definitions.inspect as any).compute(host, null), "undefined");
});
