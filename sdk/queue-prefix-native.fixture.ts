// Actual define/WeakMap SDK context fixture for ordinary native qualification.
// Node execution is NOT Wasmtime, SQL, JWT, source/controller or resource proof.
// Rich constructor trace copied without body changes from the BE code-only witness
// c16e1799e636a816c8e268a3375f47ce52fbaa946fe0fd08dec95786e3d8b9af.
import { canonicalJson, collection, define, mutation, query, v } from "./index.ts";
import type { Json } from "./index.ts";
import { queue } from "./temporal.ts";

const work = queue<Json, Json>("queuePrefix", { lease: { defaultMs: 10 }, retry: { maxAttempts: 3 } });
const scoped = work.scope("slack");
const protectedRows = collection("queuePrefixProtected", v.object({ owner: v.string() }))
  .access(({ principal }) => {
    const worker = principal.claim("role").eq("worker");
    return { read: worker, insert: worker, update: worker, delete: worker };
  });
function check(condition: boolean): void {
  if (!condition) throw Object.assign(new Error("QUEUE_PREFIX_CHECK"), { code: "QUEUE_PREFIX_CHECK" });
}
function frozen(value: unknown): boolean {
  return value === null || typeof value !== "object" || Object.isFrozen(value) && Object.values(value).every(frozen);
}
const target = { org: "acme", surface: "slack", thread: "T1/C1/1700000000.000100",
  meta: { team: "T1", channel: "C1", thread: "1700000000.000100" } };
type Seed = { ids: string[]; rich?: boolean; compact?: boolean; text?: number; delayMs?: number; priority?: number; marker?: boolean };
type Take = { mode?: string; max?: number; waitMs?: number; replacementSize?: number; principal?: string; faultAt?: number };

export default define({
  uses: [work], collections: [protectedRows],
  auth: { default: "public", authenticate: (_ctx, credentials) => credentials === "worker"
    ? { subject: "fixture-worker", claims: { role: "worker" } } : { subject: "reader" } },
  http: {
    seed: mutation("queuePrefix.seed", { args: v.json() }, (ctx, input) => {
      const args = input as unknown as Seed;
      for (const id of args.ids) {
        const payload: Json = args.rich ? { ...target, session: "s", seq: 0,
          message: { kind: "post", text: "UNKNOWN_BODY_CANARY", files: [{ name: "original.txt", mediaType: "text/plain", url: "https://example.test/original" }] }, marks: null,
          nativeOnly: { nested: ["UNKNOWN_PRIVATE_PAYLOAD_CANARY", { original: true }] },
        } : args.compact ? { org: "acme", surface: "slack", thread: "u", meta: null, session: "s", seq: 0,
          message: { kind: "post", text: "U" }, marks: null } : { text: "x".repeat(args.text ?? 1) };
        const row = scoped.enqueue(ctx, id, payload, { delayMs: args.delayMs ?? 0,
          priority: args.priority ?? (args.rich || args.compact ? -2 : 0),
          ...(args.rich ? { group: "unknown-group" } : args.compact ? { group: "g" } : {}),
        });
        if (args.rich) {
          const stored = { ...row,
            result: { original: [1, "result"] }, error: { original: ["error", null] },
            nativeOnly: { original: "UNKNOWN_PRIVATE_JOB_CANARY" },
            ...(args.marker ? { outboundQuarantine: { original: "UNTRUSTED_OLD_MARKER_CANARY" } } : {}),
          };
          ctx.set(work.records, [row.scope, row.id], stored);
        }
      }
      return null;
    }),
    protect: mutation("queuePrefix.protect", (ctx) => { ctx.set(protectedRows, "unrelated", { owner: "fixture-worker" }); return null; }),
    row: query("queuePrefix.row", { args: v.string() }, (ctx, id) => ctx.get(work.records, ["slack", id])),
    rows: query("queuePrefix.rows", (ctx) => ctx.scan(work.records)),
    bookkeeping: query("queuePrefix.bookkeeping", (ctx) => work.collections.filter((entry) => entry !== work.records)
      .map((entry) => ({ name: entry.name, rows: ctx.scan(entry) }))),
    patch: mutation("queuePrefix.patch", { args: v.json() }, (ctx, input) => {
      const args = input as unknown as { id: string; patch: Json };
      const key: [string, string] = ["slack", args.id];
      ctx.set(work.records, key, { ...ctx.get(work.records, key)!, ...args.patch as object }); return null;
    }),
    lease: mutation("queuePrefix.lease", (ctx) => scoped.claim(ctx, "original-worker")),
    take: mutation("queuePrefix.take", { args: v.json() }, (ctx, input) => {
      const args = input as unknown as Take;
      let calls = 0;
      const observed: { id: string; token: number; attempt: number; state: string; attempts: number }[] = [];
      const claims = scoped.claimMany(ctx, "new-worker", { max: args.max ?? 64,
        ...(args.waitMs === undefined ? {} : { waitMs: args.waitMs }), admit: (claim, previous) => {
          ++calls;
          check(Object.isFrozen(ctx) && !("definer" in ctx));
          check(frozen(previous) && frozen(claim) && previous !== claim as unknown && previous.payload !== claim.payload);
          if (args.principal !== undefined) check(ctx.principal()?.subject === args.principal);
          const key: [string, string] = [claim.scope, claim.id], current = ctx.get(work.records, key)!;
          check(canonicalJson(current) === canonicalJson(previous as unknown as Json));
          observed.push({ id: claim.id, token: claim.token, attempt: claim.attempt, state: previous.state, attempts: previous.attempts });
          const mode = args.mode ?? "quarantine";
          if (mode === "hostFailure" && calls === (args.faultAt ?? 2)) {
            // REAL guest host-operation allowance, not a manufactured error code.
            for (let index = 0; index < 100_001; ++index) ctx.history();
            check(false);
          }
          if (mode === "callbackFailure" && calls === (args.faultAt ?? 2)) {
            throw Object.assign(new Error("callback resource-shaped failure"), { code: "EVALUATION_BUDGET" });
          }
          if (mode === "accept" || mode === "mixed" && claim.id === "accepted" || claim.id === "ordinary") return true;
          if (mode === "false") return false;
          if (mode === "delete") { ctx.delete(work.records, key); return true; }
          if (mode === "reenter") { scoped.claim(ctx, "reentrant"); return true; }
          if (mode === "boundary") {
            check(ctx.get(protectedRows, "unrelated") === null);
            let denied = false;
            try { ctx.set(protectedRows, "unrelated", { owner: "reader" }); }
            catch (error) { denied = (error as { code?: string }).code === "ACCESS_DENIED"; }
            check(denied);
          }
          if (mode === "payload" || mode === "shrink" || mode === "growLate" && calls === (args.faultAt ?? 2)) {
            ctx.set(work.records, key, { ...current, payload: { text: "r".repeat(args.replacementSize ?? 1) } }); return true;
          }
          const quarantine = { ...current, state: "failed" as const, availableAt: null, queued: null, lease: null,
            leaseExpiresAt: null, updatedAt: ctx.now(), outboundQuarantine: previous as unknown as Json };
          ctx.set(work.records, key, quarantine);
          return false;
        } });
      // A prospective boundary also passes through definer's finally-unlift.
      if (args.mode === "boundary") check(ctx.get(protectedRows, "unrelated") === null);
      return { calls, observed, claims, checked: true };
    }),
    direct: mutation("queuePrefix.direct", { args: v.json() }, (ctx, input) => scoped.claimMany(ctx, "ordinary", input as unknown as { max: number })),
  },
});
