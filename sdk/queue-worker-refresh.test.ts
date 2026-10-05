import assert from "node:assert/strict";
import { test } from "node:test";
import { FlowerClient, type FlowerFetch } from "./client.ts";
import { define, query } from "./index.ts";
import { queue } from "./temporal.ts";
import { testDatabase } from "./testing.ts";
import { runQueueWorker } from "./worker.ts";

const jobs = queue("refreshJobs");
const app = define({
  uses: [jobs],
  http: {
    ...jobs.http("jobs", { methods: ["enqueue", "claim", "complete", "ready"] }),
    line: query("line", (ctx) => ctx.scan(jobs.line).map((row) => row.value)),
  },
});

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

test("a worker keeps its place after an early empty readiness race and a delayed half-interval refresh", async (t) => {
  const initial = 1_000_000;
  const db = await testDatabase(app, { now: initial });
  t.mock.timers.enable({ apis: ["Date", "setTimeout", "setInterval"], now: initial });
  // Native AbortSignal.timeout does not use mock timers. Keep the worker's real
  // choice of delay, but drive its deadline with the same clock as the database.
  t.mock.method(AbortSignal, "timeout", (ms: number) => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(new DOMException("Timed out", "TimeoutError")), ms);
    return controller.signal;
  });
  const advance = (ms: number) => { db.advance(ms); t.mock.timers.tick(ms); };
  const watches = [deferred(), deferred(), deferred()];
  const watchTimes: number[] = [];
  const claimTimes: Array<{ sent: number; arrived: number }> = [];
  const refreshSent = deferred(), deliverRefresh = deferred();
  let claims = 0;
  const fetch: FlowerFetch = async (url, init) => {
    const call = JSON.parse(init.body);
    if (call.name === "jobs.claim" && call.args.max !== 0) {
      const sent = Date.now() - initial;
      if (++claims === 2) {
        // The watch really saw work, but a competing claimant takes it before
        // this worker's request reaches the server: the early claim is empty.
        const raced = db.mutate("jobs.claim", { owner: "racer" })!;
        assert.equal(raced.id, "race");
        db.mutate("jobs.complete", { id: raced.id, owner: raced.owner, token: raced.token, result: null });
      } else if (claims === 3) {
        refreshSent.resolve();
        await deliverRefresh.promise;
      }
      claimTimes.push({ sent, arrived: Date.now() - initial });
    }
    const reply = await db.fetch(url, init);
    if (url.endsWith("/v1/watch")) {
      const index = watchTimes.length;
      watchTimes.push(Date.now() - initial);
      watches[index]?.resolve();
    }
    return reply;
  };
  const client = new FlowerClient<typeof app>("http://flower.test", { fetch });
  const stop = new AbortController();
  const worked: string[] = [];
  const done = runQueueWorker(client, {
    queue: "jobs", owner: "first", signal: stop.signal,
    wait: true, waitMs: 60_000, concurrency: 1, renew: false,
    health: () => ({ load: 0, reason: "idle" }),
    work: (claim) => { worked.push(claim.id); return null; },
  });
  try {
    await watches[0].promise;
    assert.deepEqual(db.query("line"), [{ scope: "", owner: "first", room: 1, since: initial, expiresAt: initial + 60_000 }]);
    advance(10_000);
    db.mutate("jobs.claim", { owner: "later", waitMs: 60_000 });
    advance(19_999);
    db.mutate("jobs.enqueue", { id: "race", payload: null });
    await watches[1].promise;
    assert.deepEqual(worked, [], "the readiness race left the worker's early claim empty");

    // The actual worker starts a new 30 s watch AFTER that empty response.
    advance(30_000);
    await refreshSent.promise;
    advance(2); // a small dispatch/transport delay before the refresh arrives
    deliverRefresh.resolve();
    await watches[2].promise;
    assert.deepEqual(watchTimes, [0, 29_999, 60_001]);
    assert.deepEqual(claimTimes, [
      { sent: 0, arrived: 0 },
      { sent: 29_999, arrived: 29_999 },
      { sent: 59_999, arrived: 60_001 },
    ]);
    assert.deepEqual(worked, []);
    db.mutate("jobs.enqueue", { id: "next", payload: null });
    assert.deepEqual({
      since: db.query("line").find((row) => row.owner === "first")!.since,
      firstReady: db.query("jobs.ready", { owner: "first" }),
      laterReady: db.query("jobs.ready", { owner: "later" }),
    }, { since: initial, firstReady: true, laterReady: false }, "an early empty poll must leave headroom for the worker's next half-wait sleep and transport delay");
  } finally {
    stop.abort();
    deliverRefresh.resolve();
    await done;
  }
});
