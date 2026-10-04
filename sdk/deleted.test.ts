import assert from "node:assert/strict";
import test from "node:test";
import {
  aggregate, collection, component, define, derive, fail, FlowerError, mutation, query, retainDeleted, trigger, v,
} from "./index.ts";
import type { Change, Collection, DeletedRow, DeleteOptions, Json, MutationContext } from "./index.ts";
import { testDatabase } from "./testing.ts";

type Value = { group: string; amount: number };
type Operation = { op: "set" | "delete"; key: [string, number]; value?: Value; options?: DeleteOptions; fresh?: boolean; raw?: boolean };
const tuple = v.tuple([v.string(), v.int()]);

async function fixture(options: { reject?: boolean; loop?: boolean } = {}) {
  const rows = collection<Value>("rows").key(tuple).index("group", ["group"]);
  const archive = collection<DeletedRow<Value, [string, number]>[]>("archive");
  const changes = collection<Change<Value, [string, number]>[]>("changes");
  const total = aggregate("total", {
    source: rows, index: "group", initial: () => 0,
    add: (value, row) => value + row.amount, remove: (value, row) => value - row.amount,
  });
  const retained = retainDeleted("retain", rows, (ctx, deleted) => {
    ctx.set(archive, "all", [...(ctx.get(archive, "all") ?? []), deleted]);
    if (options.reject) fail("RETENTION_FAILED", "cannot retain");
    if (options.loop) { ctx.set(rows, deleted.key, deleted.value); ctx.delete(rows, deleted.key); }
  });
  const record = trigger("record", rows, (ctx, change) => {
    ctx.set(changes, "all", [...(ctx.get(changes, "all") ?? []), change]);
  });
  const app = define({ uses: [component({ triggers: [retained, record], definitions: [total] })], http: {
    apply: mutation("apply", (ctx, ops: Operation[]) => {
      for (const op of ops) {
        const source = op.fresh ? collection<Value>("rows").key(tuple) : rows;
        if (op.op === "set") ctx.set(source, op.key, op.value!);
        else if (op.raw) ctx.delete(collection<Value>("rows"), JSON.stringify(op.key), op.options);
        else ctx.delete(source, op.key, op.options);
      }
      return null;
    }),
    abort: mutation("abort", (ctx) => { ctx.delete(rows, ["a", 1]); fail("ABORT", "abort before settlement"); }),
    view: query("view", (ctx) => ({
      rows: ctx.scan(rows), matches: ctx.query(rows.by("group").eq("g")),
      page: ctx.range(rows.by("group").range({ prefix: ["g"], limit: 10 })),
      total: ctx.get(total, "g"), archive: ctx.get(archive, "all") ?? [], changes: ctx.get(changes, "all") ?? [],
    })),
  } });
  return testDatabase(app, { now: 1234 });
}
const put = (key: [string, number], amount: number): Operation => ({ op: "set", key, value: { group: "g", amount } });
const drop = (key: [string, number], options?: DeleteOptions): Operation => ({ op: "delete", key, ...(options ? { options } : {}) });
const code = (expected: string) => (error: unknown) => error instanceof FlowerError && error.failure?.code === expected;

test("retention captures the final deleted value and decoded key, while all active views see absence", async () => {
  const db = await fixture();
  db.mutate("apply", [put(["a", 1], 2)]);
  db.advance(20);
  db.mutate("apply", [put(["a", 1], 9), { ...drop(["a", 1]), fresh: true }]);
  const view = db.query("view");
  assert.deepEqual(view.archive, [{ collection: "rows", key: ["a", 1], value: { group: "g", amount: 9 }, deletedAt: 1254 }]);
  assert.deepEqual(view.rows, []);
  assert.deepEqual(view.matches, []);
  assert.deepEqual(view.page, { rows: [], cursor: null });
  assert.equal(view.total, 0);
  assert.deepEqual(view.changes.at(-1), { key: ["a", 1], before: { group: "g", amount: 2 }, after: null });
});

test("name-only references with encoded JSON keys cannot bypass retention or change typed trigger keys", async () => {
  const db = await fixture(); db.mutate("apply", [put(["a", 1], 2)]);
  db.mutate("apply", [{ ...drop(["a", 1]), raw: true }]);
  const view = db.query("view");
  assert.deepEqual(view.archive[0].key, ["a", 1]);
  assert.deepEqual(view.changes.at(-1)?.key, ["a", 1]);
  assert.deepEqual(view.rows, []);
});

test("every effective deletion is retained despite recreation, unchanged net state, or transient insertion", async () => {
  const db = await fixture();
  db.mutate("apply", [put(["a", 1], 2)]);
  db.mutate("apply", [drop(["a", 1]), put(["a", 1], 2), drop(["a", 1]), put(["a", 1], 8), put(["b", 2], 3), drop(["b", 2])]);
  let view = db.query("view");
  assert.deepEqual(view.archive.map((row) => [row.key, row.value.amount]), [[["a", 1], 2], [["a", 1], 2], [["b", 2], 3]]);
  assert.deepEqual(view.changes.at(-1), { key: ["a", 1], before: { group: "g", amount: 2 }, after: { group: "g", amount: 8 } });
  assert.equal(view.total, 8);
  const count = view.changes.length;
  db.mutate("apply", [drop(["a", 1]), put(["a", 1], 8)]);
  view = db.query("view");
  assert.equal(view.changes.length, count, "ordinary triggers still suppress unchanged net rows");
  assert.equal(view.archive.length, 4);
  assert.equal(view.total, 8);
});

test("missing deletes and duplicate missing deletes retain nothing; permanent affects only its effective deletion", async () => {
  const db = await fixture();
  db.mutate("apply", [drop(["none", 0]), drop(["none", 0], { permanent: true })]);
  assert.deepEqual(db.query("view").archive, []);
  db.mutate("apply", [put(["a", 1], 1), drop(["a", 1], { permanent: true }), put(["a", 1], 2), drop(["a", 1]), drop(["a", 1], { permanent: true })]);
  assert.deepEqual(db.query("view").archive.map((row) => row.value.amount), [2]);
  db.mutate("apply", [put(["a", 1], 3), drop(["a", 1], { permanent: false })]);
  assert.deepEqual(db.query("view").archive.map((row) => row.value.amount), [2, 3]);
});

test("retention and deletion roll back on method or retention failure; retention loops are bounded", async () => {
  const db = await fixture({ reject: true });
  db.mutate("apply", [put(["a", 1], 2)]);
  const before = db.data;
  assert.throws(() => db.mutate("abort"), code("ABORT"));
  assert.deepEqual(db.data, before);
  assert.throws(() => db.mutate("apply", [drop(["a", 1])]), code("RETENTION_FAILED"));
  assert.deepEqual(db.data, before);
  const looping = await fixture({ loop: true });
  looping.mutate("apply", [put(["a", 1], 2)]);
  const original = looping.data;
  assert.throws(() => looping.mutate("apply", [drop(["a", 1])]), code("TRIGGER_LOOP"));
  assert.deepEqual(looping.data, original);
});

test("deletions caused by ordinary trigger writes retain their final payload and participate in settlement", async () => {
  const rows = collection<{ n: number }>("rows");
  const archive = collection<DeletedRow<{ n: number }, string>[]>("archive");
  const db = await testDatabase(define({ triggers: [
    trigger("removeUpdated", rows, (ctx, change) => {
      if (change.after?.n === 2) { ctx.set(rows, change.key, { n: 3 }); ctx.delete(rows, change.key); }
    }),
    retainDeleted("retain", rows, (ctx, event) => ctx.set(archive, "all", [...(ctx.get(archive, "all") ?? []), event])),
  ], http: {
    put: mutation("put", (ctx, n: number) => { ctx.set(rows, "a", { n }); return null; }),
    view: query("view", (ctx) => ({ row: ctx.get(rows, "a"), archive: ctx.get(archive, "all") ?? [] })),
  } }));
  db.mutate("put", 1); db.mutate("put", 2, { requestId: "remove" }); db.mutate("put", 2, { requestId: "remove" });
  assert.deepEqual(db.query("view"), { row: null, archive: [{ collection: "rows", key: "a", value: { n: 3 }, deletedAt: 1_000_000 }] });
});

test("retention-only hooks run without ordinary triggers and retain stored nulls, not missing rows", async () => {
  const rows = collection<Json>("plain");
  const archive = collection<DeletedRow<Json, string>[]>("archive");
  const db = await testDatabase(define({ collections: [archive], triggers: [retainDeleted("retain", rows, (ctx, deleted) => {
    ctx.set(archive, "all", [...(ctx.get(archive, "all") ?? []), deleted]);
  })], http: {
    put: mutation("put", (ctx, value: Json) => { ctx.set(rows, "x", value); return null; }),
    drop: mutation("drop", (ctx) => { ctx.delete(collection<Json>("plain"), "x"); return null; }),
    view: query("view", (ctx) => ({ rows: ctx.scan(rows), archive: ctx.get(archive, "all") ?? [] })),
  } }));
  db.mutate("drop");
  assert.deepEqual(db.query("view").archive, []);
  db.mutate("put", null);
  db.mutate("drop");
  db.mutate("drop");
  assert.deepEqual(db.query("view"), { rows: [], archive: [{ collection: "plain", key: "x", value: null, deletedAt: 1_000_000 }] });
});

async function cascadeFixture(extraTrigger = false, retainParents = true) {
  const parents = collection<{ name: string }>("parents");
  const children = collection<{ parent: string }>("children").references(parents, "parent", { onDelete: "cascade" });
  const leaves = collection<{ child: string }>("leaves").references(children, "child", { onDelete: "cascade" });
  const detached = collection<{ parent: string | null }>("detached").references(parents, "parent", { onDelete: "setNull" });
  const archive = collection<DeletedRow<Json, string>[]>("archive");
  const append = (ctx: MutationContext, event: DeletedRow<any, any>) => ctx.set(archive, "all", [...(ctx.get(archive, "all") ?? []), event]);
  const all = { parents, children, leaves, detached };
  return testDatabase(define({ collections: Object.values(all), triggers: [
    ...Object.values(all).filter((source) => retainParents || source.name !== "parents").map((source) => retainDeleted(`retain:${source.name}`, source as Collection<Json>, append)),
    ...(extraTrigger ? [trigger("observe", parents, () => {})] : []),
  ], http: {
    seed: mutation("seed", (ctx) => {
      ctx.set(parents, "p", { name: "Parent" }); ctx.set(children, "c", { parent: "p" });
      ctx.set(leaves, "l", { child: "c" }); ctx.set(detached, "d", { parent: "p" }); return null;
    }),
    drop: mutation("drop", (ctx, options: DeleteOptions | null) => { ctx.delete(parents, "p", options ?? undefined); ctx.delete(parents, "p"); return null; }),
    replaceDrop: mutation("replaceDrop", (ctx, permanent: boolean) => {
      ctx.delete(parents, "p", { permanent: !permanent }); ctx.set(parents, "p", { name: "New" });
      ctx.delete(parents, "p", { permanent }); return null;
    }),
    recreate: mutation("recreate", (ctx) => { ctx.delete(parents, "p"); ctx.set(parents, "p", { name: "Recreated" }); return null; }),
    view: query("view", (ctx) => ({ parents: ctx.scan(parents), children: ctx.scan(children), leaves: ctx.scan(leaves), detached: ctx.scan(detached), archive: ctx.get(archive, "all") ?? [] })),
  } }));
}

for (const mixed of [false, true]) test(`normal/permanent deletion propagates through multi-level FK cascades (${mixed ? "mixed" : "existence-only"} triggers)`, async () => {
  for (const permanent of [false, true]) {
    const db = await cascadeFixture(mixed);
    db.mutate("seed"); db.mutate("drop", { permanent });
    const view = db.query("view");
    assert.deepEqual(view.parents, []); assert.deepEqual(view.children, []); assert.deepEqual(view.leaves, []);
    assert.deepEqual(view.detached, [{ key: "d", value: { parent: null } }]);
    assert.deepEqual(view.archive.map((row) => row.collection).sort(), permanent ? [] : ["children", "leaves", "parents"]);
  }
});

test("permanent cascade propagates even when the deleted parent has no retention hook", async () => {
  const db = await cascadeFixture(false, false); db.mutate("seed"); db.mutate("drop", { permanent: true });
  const view = db.query("view");
  assert.deepEqual(view.children, []); assert.deepEqual(view.leaves, []); assert.deepEqual(view.archive, []);
});

test("FK cascade uses the last effective deletion's permanence and ignores later no-op deletes", async () => {
  for (const permanent of [false, true]) {
    const db = await cascadeFixture(); db.mutate("seed"); db.mutate("replaceDrop", permanent);
    const archived = db.query("view").archive;
    assert.deepEqual(archived.map((row) => row.collection).sort(), permanent ? ["parents"] : ["children", "leaves", "parents"]);
    assert.deepEqual(archived.find((row) => row.collection === "parents")?.value, { name: permanent ? "Parent" : "New" });
  }
  const recreated = await cascadeFixture(); recreated.mutate("seed"); recreated.mutate("recreate");
  const view = recreated.query("view");
  assert.equal(view.children.length, 1, "recreated parent does not cascade, matching existing FK semantics");
  assert.equal(view.leaves.length, 1);
  assert.deepEqual(view.archive.map((row) => row.collection), ["parents"]);
});

test("a JSON-key parent deleted by a name-only reference still cascades and propagates permanence", async () => {
  for (const permanent of [false, true]) {
    const parents = collection<Json>("parents").key(tuple);
    const children = collection<{ parent: string; n: number }>("children").references(parents, ["parent", "n"], { onDelete: "cascade" });
    const archive = collection<Json[]>("archive");
    const retain = (ctx: MutationContext, row: DeletedRow<any, any>) => ctx.set(archive, "all", [...(ctx.get(archive, "all") ?? []), row as unknown as Json]);
    const db = await testDatabase(define({ collections: [children], triggers: [retainDeleted("p", parents, retain), retainDeleted("c", children, retain)], http: {
      seed: mutation("seed", (ctx) => { ctx.set(parents, ["p", 1], {}); ctx.set(children, "c", { parent: "p", n: 1 }); return null; }),
      drop: mutation("drop", (ctx) => { ctx.delete(collection<Json>("parents"), JSON.stringify(["p", 1]), { permanent }); return null; }),
      view: query("view", (ctx) => ({ parents: ctx.scan(parents), children: ctx.scan(children), archive: ctx.get(archive, "all") ?? [] })),
    } }));
    db.mutate("seed"); db.mutate("drop");
    const view = db.query("view");
    assert.deepEqual(view.parents, []); assert.deepEqual(view.children, []);
    assert.equal(view.archive.length, permanent ? 0 : 2);
  }
});

test("each trigger decodes its own source key when a name-only observer precedes tuple FK cascades", async () => {
  for (const permanent of [false, true]) for (const raw of [false, true]) for (const retainedParent of [false, true]) {
    const parents = collection<Json>("parents").key(tuple);
    const children = collection<{ parent: string; n: number }>("children").references(parents, ["parent", "n"], { onDelete: "cascade" });
    const archive = collection<Json[]>("archive"), observed = collection<Json[]>("observed");
    const retain = (ctx: MutationContext, row: DeletedRow<any, any>) => ctx.set(archive, "all", [...(ctx.get(archive, "all") ?? []), row as unknown as Json]);
    const record = (ctx: MutationContext, kind: string, key: Json) => ctx.set(observed, "all", [...(ctx.get(observed, "all") ?? []), { kind, key }]);
    const db = await testDatabase(define({ collections: [children], triggers: [
      trigger("rawObserver", collection<Json>("parents"), (ctx, change) => record(ctx, "raw", change.key)),
      trigger("typedObserver", parents, (ctx, change) => record(ctx, "typed", change.key)),
      ...(retainedParent ? [retainDeleted("p", parents, retain)] : []), retainDeleted("c", children, retain),
    ], http: {
      seed: mutation("seed", (ctx) => { ctx.set(parents, ["p", 1], {}); ctx.set(children, "c", { parent: "p", n: 1 }); return null; }),
      drop: mutation("drop", (ctx) => {
        if (raw) ctx.delete(collection<Json>("parents"), JSON.stringify(["p", 1]), { permanent });
        else ctx.delete(parents, ["p", 1], { permanent });
        return null;
      }),
      view: query("view", (ctx) => ({ parents: ctx.scan(parents), children: ctx.scan(children), archive: ctx.get(archive, "all") ?? [], observed: ctx.get(observed, "all") ?? [] })),
    } }));
    db.mutate("seed"); db.mutate("drop");
    const view = db.query("view");
    assert.deepEqual(view.parents, []); assert.deepEqual(view.children, []);
    assert.deepEqual(view.observed, [
      { kind: "raw", key: JSON.stringify(["p", 1]) }, { kind: "typed", key: ["p", 1] },
      { kind: "raw", key: JSON.stringify(["p", 1]) }, { kind: "typed", key: ["p", 1] },
    ]);
    assert.deepEqual(view.archive.map((row: any) => row.collection).sort(), permanent ? [] : retainedParent ? ["children", "parents"] : ["children"]);
  }
});

test("retention does not satisfy restrict FKs, and permanent deletion does not bypass them", async () => {
  const parents = collection<Json>("parents");
  const children = collection<{ parent: string }>("children").references(parents, "parent");
  const archive = collection<Json[]>("archive");
  const db = await testDatabase(define({ collections: [children], triggers: [retainDeleted("retain", parents, (ctx, row) => {
    ctx.set(archive, "all", [...(ctx.get(archive, "all") ?? []), row as unknown as Json]);
  })], http: {
    seed: mutation("seed", (ctx) => { ctx.set(parents, "p", {}); ctx.set(children, "c", { parent: "p" }); return null; }),
    drop: mutation("drop", (ctx, options: DeleteOptions | null) => { ctx.delete(parents, "p", options ?? undefined); return null; }),
  } }));
  db.mutate("seed"); const before = db.data;
  for (const options of [null, { permanent: true }]) {
    assert.throws(() => db.mutate("drop", options), code("FOREIGN_KEY_VIOLATION"));
    assert.deepEqual(db.data, before);
  }
});

test("caller deletes remain checked, while retention gets full final hidden fields and can write hidden archives", async () => {
  type Doc = { owner: string; text: string; secret?: string; locked?: boolean };
  const docs = collection<Doc>("docs").access(({ principal, row, next, any, not }) => {
    const admin = principal.subject.eq("root"); const owner = row("owner").eq(principal.subject);
    return { read: any(admin, owner), insert: admin, update: any(admin, owner), delete: any(admin, owner.and(not(row("locked").eq(true)))),
      fields: { secret: { read: admin, write: admin } } };
  });
  const archive = collection<(DeletedRow<Doc, string> & { principal: string | null })[]>("archive").access(({ principal }) => ({ read: principal.subject.eq("root"), write: false }));
  const hook = retainDeleted("retain", docs, (ctx, row) => {
    ctx.set(archive, "all", [...(ctx.get(archive, "all") ?? []), { ...row, principal: ctx.principal()?.subject ?? null }]);
  });
  const db = await testDatabase(define({ collections: [archive], triggers: [hook], auth: {
    authenticate: (_ctx, credentials) => typeof credentials === "string" ? { subject: credentials } : null,
  }, http: {
    seed: mutation("seed", (ctx) => {
      ctx.set(docs, "a", { owner: "alice", text: "old", secret: "hidden" });
      ctx.set(docs, "locked", { owner: "alice", text: "locked", secret: "kept", locked: true }); return null;
    }),
    editDrop: mutation("editDrop", (ctx) => { ctx.set(docs, "a", { ...ctx.get(docs, "a")!, text: "final" }); ctx.delete(collection<Doc>("docs"), "a"); return ctx.get(archive, "all"); }),
    drop: mutation("drop", (ctx, { key, permanent }: { key: string; permanent?: boolean }) => { ctx.delete(docs, key, { permanent }); return null; }),
    view: query("view", (ctx) => ({ docs: ctx.scan(docs), archive: ctx.get(archive, "all") ?? [] })),
  } }));
  const as = (credentials: string) => ({ credentials });
  db.mutate("seed", null, as("root")); const before = db.data;
  for (const permanent of [false, true]) {
    db.mutate("drop", { key: "a", permanent }, as("bob"));
    db.mutate("drop", { key: "missing", permanent }, as("alice"));
    assert.throws(() => db.mutate("drop", { key: "locked", permanent }, as("alice")), code("ACCESS_DENIED"));
    assert.deepEqual(db.data, before);
  }
  assert.equal(db.mutate("editDrop", null, as("alice")), null, "caller cannot read the archive or keep definer rights");
  assert.deepEqual(db.query("view", null, as("alice")).archive, []);
  assert.deepEqual(db.query("view", null, as("root")).archive, [{ collection: "docs", key: "a", value: { owner: "alice", text: "final", secret: "hidden" }, deletedAt: 1_000_000, principal: "alice" }]);
});

test("retention can coexist with materialization existence bookkeeping", async () => {
  const rows = collection<{ n: number }>("rows");
  const archive = collection<Json[]>("archive");
  const computed = derive("computed", (ctx, key: string) => ctx.get(rows, key)?.n ?? 0, { materialize: { each: rows } });
  const db = await testDatabase(define({ definitions: [computed], triggers: [retainDeleted("retain", rows, (ctx, deleted) => {
    ctx.set(archive, "all", [...(ctx.get(archive, "all") ?? []), deleted as unknown as Json]);
  })], http: {
    apply: mutation("apply", (ctx) => { ctx.set(rows, "a", { n: 2 }); ctx.delete(rows, "a"); return null; }),
    archived: query("archived", (ctx) => ctx.get(archive, "all") ?? []),
  } }));
  db.mutate("apply");
  assert.equal(db.query("archived").length, 1);
});

test("retention declarations reject duplicate hooks and malformed options", async () => {
  const rows = collection<Json>("rows");
  const hook = retainDeleted("one", rows, () => {});
  assert.throws(() => define({ triggers: [hook, hook] }), /Duplicate trigger/);
  assert.throws(() => define({ triggers: [hook, retainDeleted("two", collection<Json>("rows"), () => {})] }), /Duplicate retention.*rows/);
  assert.throws(() => retainDeleted("one", rows, null as any), /retain function/);
  assert.throws(() => retainDeleted("one", {} as any, () => {}), /collection/);
  const db = await testDatabase(define({ triggers: [hook], http: {
    drop: mutation("drop", (ctx, options: any) => { ctx.delete(rows, "a", options); return null; }),
  } }));
  for (const options of [{ permanent: 1 }, { typo: true }, null, []]) assert.throws(() => db.mutate("drop", options));
});

test("delete admission and caller-supplied getters never run elevated, including permanent options", () => {
  const rows = collection<Json>("rows").access({ read: true, write: true });
  const archive = collection<Json>("archive").access({ read: false, write: false });
  let depth = 0;
  const seen: number[] = [];
  const deletes: number[] = [];
  const writes: number[] = [];
  const data = new Map<string, Json>([["rows/a", { secret: "complete" }]]);
  const host = {
    get: (reference: any, key: string) => data.get(`${reference.name}/${key}`) ?? null,
    scan: () => [], now: () => 123, principal: () => ({ subject: "alice" }),
    delete: (reference: any, key: string) => { deletes.push(depth); data.delete(`${reference.name}/${key}`); },
    set: (reference: any, key: string, value: Json) => { writes.push(depth); data.set(`${reference.name}/${key}`, value); },
  };
  const reference = new Proxy(rows, { get(target, property, receiver) { seen.push(depth); return Reflect.get(target, property, receiver); } });
  const options = { get permanent() { seen.push(depth); return false; } };
  const app = define({ collections: [archive], triggers: [retainDeleted("retain", rows, (ctx, event) => {
    ctx.set(archive, "a", event as unknown as Json);
  })], http: { drop: mutation("drop", (ctx) => { ctx.delete(reference, "a", options); return depth; }) } });
  assert.equal((app.definitions.drop as any).compute(host, null, (on: boolean) => { depth += on ? 1 : -1; }), 0);
  assert.deepEqual(deletes, [0]); assert.deepEqual(writes, [1]);
  assert.ok(seen.length > 0); assert.ok(seen.every((at) => at === 0)); assert.equal(depth, 0);
  assert.deepEqual(data.get("archive/a"), { collection: "rows", key: "a", value: { secret: "complete" }, deletedAt: 123 });
});
