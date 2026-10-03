// E2E_FLOWER_BIN=target/release/flower node tests/e2e-deleted.mjs
// SDK retention against the real Rust/QuickJS engine: full payloads under definer rights,
// caller delete admission, cascades, permanent bypass, indexes/aggregates and rollback.
import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { LocalCluster } from "../bench/cluster.mjs";
import { buildBundle } from "../sdk/bundle.ts";
import { FlowerAdmin, FlowerClient } from "../sdk/index.ts";
import { createHttp2Transport } from "../sdk/http2.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
let cluster;
const transport = createHttp2Transport({ requestTimeoutMs: 20_000 });
const as = (credentials) => new FlowerClient(cluster.leader.url, { fetch: transport.fetch, credentials });
let sequence = 0;
const mutate = (client, alias, args = null) => client.mutate(alias, args, { requestId: `deleted-${++sequence}`, signal: AbortSignal.timeout(20_000) });
const view = async (client) => (await client.query("view")).value;
const code = (expected) => (error) => { assert.equal(error.failure?.code, expected, error.message); return true; };

const source = `import { aggregate, collection, define, fail, mutation, query, retainDeleted, trigger, v, type DeletedRow, type Json } from ${JSON.stringify(join(root, "sdk/index.ts"))};
type Parent = { owner: string; group: string; amount: number; secret?: string; locked?: boolean };
const parents = collection<Parent>("parents").index("group", ["group"]).access(({principal, row, next, any, not}) => {
  const admin = principal.subject.eq("root");
  const owner = row("owner").eq(principal.subject);
  return { read: any(admin, owner), insert: admin, update: any(admin, owner),
    delete: any(admin, owner.and(not(row("locked").eq(true)))), fields: {secret: {read: admin, write: admin}} };
});
const children = collection<{parent: string; secret: string}>("children").references(parents, "parent", {onDelete: "cascade"})
  .access(({principal}) => ({read: principal.subject.eq("root"), write: principal.subject.eq("root")}));
const leaves = collection<{secret: string}>("leaves").key(v.tuple([v.string(), v.int()])).references(children, {key: 1}, {onDelete: "cascade"})
  .access(({principal}) => ({read: principal.subject.eq("root"), write: principal.subject.eq("root")}));
const restricted = collection<{parent: string}>("restricted").references(parents, "parent");
const nullable = collection<Json>("nullable");
const archive = collection<(DeletedRow<Json, Json> & {by: string|null})[]>("archive")
  .access(({principal}) => ({read: principal.subject.eq("root"), write: false}));
const tupleParents = collection<Json>("tupleParents").key(v.tuple([v.string(), v.int()]));
const tupleChildren = collection<{parent: string; n: number}>("tupleChildren").references(tupleParents, ["parent", "n"], {onDelete: "cascade"});
const tupleArchive = collection<Json[]>("tupleArchive");
const tupleObserved = collection<Json[]>("tupleObserved");
const changes = collection<Json[]>("changes").access(({principal}) => ({read: principal.subject.eq("root"), write: false}));
const total = aggregate("total", {source: parents, index: "group", initial: () => 0,
  add: (n, row) => n + row.amount, remove: (n, row) => n - row.amount});
const retain = (ctx: any, row: any) => {
  ctx.set(archive, "all", [...(ctx.get(archive, "all") ?? []), {...row, by: ctx.principal()?.subject ?? null}]);
  if (row.value?.secret === "retention-fails") fail("RETENTION_FAILED", "retention rejected");
};
export default define({collections: [parents, children, leaves, restricted, nullable, archive, changes, tupleChildren], definitions: [total],
  triggers: [
    trigger("observe:rawTuple", collection<Json>("tupleParents"), (ctx, change) => ctx.set(tupleObserved, "all", [...(ctx.get(tupleObserved, "all") ?? []), {kind: "raw", key: change.key}])),
    trigger("observe:typedTuple", tupleParents, (ctx, change) => ctx.set(tupleObserved, "all", [...(ctx.get(tupleObserved, "all") ?? []), {kind: "typed", key: change.key}])),
    ...[tupleParents, tupleChildren].map((source) => retainDeleted("retain:" + source.name, source, (ctx, row) => ctx.set(tupleArchive, "all", [...(ctx.get(tupleArchive, "all") ?? []), row as any]))),
    retainDeleted("retain:parents", parents, retain), retainDeleted("retain:children", children, retain),
    retainDeleted("retain:leaves", leaves, retain), retainDeleted("retain:nullable", nullable, retain),
    trigger("observe", parents, (ctx, change) => ctx.set(changes, "all", [...(ctx.get(changes, "all") ?? []), change as any]))],
  auth: {authenticate: (_ctx, credentials) => typeof credentials === "string" ? {subject: credentials} : null}, http: {
    seed: mutation("seed", (ctx) => {
      for (const key of ["normal", "permanent", "restricted", "locked", "replace", "rollback", "retention-fails"]) {
        ctx.set(parents, key, {owner: "alice", group: "g", amount: 1, secret: key === "retention-fails" ? key : "parent-secret", ...(key === "locked" ? {locked: true} : {})});
        ctx.set(children, key + ":child", {parent: key, secret: "child-secret"});
        ctx.set(leaves, [key + ":child", 1], {secret: "leaf-secret"});
      }
      ctx.set(restricted, "r", {parent: "restricted"}); ctx.set(nullable, "null", null); return null;
    }),
    drop: mutation("drop", (ctx, {key, permanent}: {key: string; permanent?: boolean}) => {ctx.delete(collection<Parent>("parents"), key, {permanent}); return null;}),
    editDrop: mutation("editDrop", (ctx, key: string) => {ctx.set(parents, key, {...ctx.get(parents, key)!, amount: 99}); ctx.delete(parents, key); return ctx.get(archive, "all");}),
    recreate: mutation("recreate", (ctx, key: string) => {const row = ctx.get(parents, key)!; ctx.delete(parents, key); ctx.set(parents, key, row); return null;}),
    abort: mutation("abort", (ctx) => {ctx.delete(parents, "rollback"); fail("ABORT", "abort before settlement");}),
    nullDrop: mutation("nullDrop", (ctx) => {ctx.delete(nullable, "null"); return null;}),
    seedTuple: mutation("seedTuple", (ctx) => {ctx.set(tupleParents, ["p", 1], {}); ctx.set(tupleChildren, "c", {parent: "p", n: 1}); return null;}),
    dropTuple: mutation("dropTuple", (ctx, permanent: boolean) => {ctx.delete(collection<Json>("tupleParents"), JSON.stringify(["p", 1]), {permanent}); return null;}),
    viewTuple: query("viewTuple", (ctx) => ({parents: ctx.scan(tupleParents), children: ctx.scan(tupleChildren), archive: ctx.get(tupleArchive, "all") ?? [], observed: ctx.get(tupleObserved, "all") ?? []})),
    view: query("view", (ctx) => ({parents: ctx.scan(parents), children: ctx.scan(children), leaves: ctx.scan(leaves),
      matches: ctx.query(parents.by("group").eq("g")), page: ctx.range(parents.by("group").range({prefix: ["g"], limit: 20})),
      total: ctx.get(total, "g"), archive: ctx.get(archive, "all") ?? [], changes: ctx.get(changes, "all") ?? [], nullable: ctx.scan(nullable)})),
  }});`;

for (const initialization of ["per-invocation", "static"]) {
  cluster = new LocalCluster({ nodes: 1, binary: process.env.E2E_FLOWER_BIN ?? join(root, "target/release/flower") });
  try {
    await cluster.start();
    const fixture = join(cluster.directory, "deleted.ts");
    await writeFile(fixture, source);
    const admin = new FlowerAdmin(cluster.leader.url, { adminToken: cluster.adminToken, fetch: transport.fetch });
    const rootUser = as("root"), alice = as("alice"), bob = as("bob");
    await admin.deploy(await buildBundle(fixture, { initialization }), { requestId: `deleted-${initialization}` });
    await mutate(rootUser, "seed");
    let current = await view(rootUser);
    assert.equal(current.total, 7);
    const original = current;
    for (const permanent of [false, true]) {
      await mutate(bob, "drop", { key: "normal", permanent });
      await mutate(alice, "drop", { key: "missing", permanent });
      await assert.rejects(mutate(alice, "drop", { key: "locked", permanent }), code("ACCESS_DENIED"));
      await assert.rejects(mutate(alice, "drop", { key: "restricted", permanent }), code("FOREIGN_KEY_VIOLATION"));
      assert.deepEqual(await view(rootUser), original);
    }
    await assert.rejects(mutate(alice, "abort"), code("ABORT"));
    await assert.rejects(mutate(alice, "drop", { key: "retention-fails" }), code("RETENTION_FAILED"));
    assert.deepEqual(await view(rootUser), original);
    assert.equal((await mutate(alice, "editDrop", "normal")).value, null, "caller stays unable to read the hidden archive");
    current = await view(rootUser);
    assert.equal(current.total, 6, "aggregate removes original amount, not the final deleted amount");
    assert.ok(current.parents.every((row) => row.key !== "normal"));
    assert.ok(current.matches.every((row) => row.amount !== 99));
    assert.ok(current.page.rows.every((row) => row.key !== "normal"));
    assert.ok(current.children.every((row) => row.value.parent !== "normal"));
    assert.ok(current.leaves.every((row) => row.key[0] !== "normal:child"));
    assert.deepEqual(current.archive.map((row) => row.collection).sort(), ["children", "leaves", "parents"]);
    const parent = current.archive.find((row) => row.collection === "parents");
    assert.deepEqual(parent.value, { owner: "alice", group: "g", amount: 99, secret: "parent-secret" });
    assert.equal(parent.key, "normal"); assert.equal(parent.by, "alice");
    assert.ok(Number.isSafeInteger(parent.deletedAt) && parent.deletedAt > 0);
    assert.deepEqual(current.archive.find((row) => row.collection === "leaves").key, ["normal:child", 1]);
    assert.equal(current.archive.find((row) => row.collection === "children").value.secret, "child-secret");
    assert.deepEqual((await view(alice)).archive, []);
    assert.deepEqual(current.changes.at(-1).before.amount, 1);
    assert.equal(current.changes.at(-1).after, null);
    const retainedCount = current.archive.length;
    await mutate(alice, "drop", { key: "permanent", permanent: true });
    current = await view(rootUser);
    assert.equal(current.archive.length, retainedCount);
    assert.equal(current.total, 5);
    assert.ok(current.children.every((row) => row.value.parent !== "permanent"));
    assert.ok(current.leaves.every((row) => row.key[0] !== "permanent:child"));
    const changedCount = current.changes.length;
    await mutate(rootUser, "recreate", "replace");
    current = await view(rootUser);
    assert.equal(current.archive.length, retainedCount + 1);
    assert.equal(current.changes.length, changedCount, "unchanged net state fires no ordinary trigger");
    assert.equal(current.total, 5);
    assert.ok(current.children.some((row) => row.value.parent === "replace"));
    await mutate(alice, "nullDrop"); await mutate(alice, "nullDrop");
    current = await view(rootUser);
    assert.deepEqual(current.nullable, []);
    assert.equal(current.archive.length, retainedCount + 2);
    assert.equal(current.archive.at(-1).value, null);
    for (const permanent of [false, true]) {
      await mutate(rootUser, "seedTuple"); await mutate(rootUser, "dropTuple", permanent);
      const tupleView = (await rootUser.query("viewTuple")).value;
      assert.deepEqual(tupleView.parents, []); assert.deepEqual(tupleView.children, []);
      assert.equal(tupleView.archive.length, 2, "only the normal tuple cascade is retained");
      assert.deepEqual(tupleView.observed.slice(-2), [{kind: "raw", key: JSON.stringify(["p", 1])}, {kind: "typed", key: ["p", 1]}]);
    }
    console.log(`PASS (${initialization}): real engine deletion retention, full hidden final payloads, decoded keys, unchanged net triggers/aggregates, caller admission, rollback, null rows and permanent FK cascade bypass`);
  } catch (error) {
    console.error(error);
    console.error(cluster.logTails());
    process.exitCode = 1;
  } finally {
    await cluster.close();
  }
}
transport.close();
