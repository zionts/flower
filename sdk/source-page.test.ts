import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson, collection, define, derive, FlowerError, mutation, query, v } from "./index.ts";
import type { Context, Json, RangePage, ScanPageOptions } from "./index.ts";
import { enforceAccess } from "./access.ts";
import { testDatabase } from "./testing.ts";

const sourceId = (name: string, key: string) => "source:" + canonicalJson([name, key]);
const cursorAt = (name: string, key: string) => canonicalJson({ version: 1, scope: canonicalJson(["sourcePage", name]), last: sourceId(name, key) });
const optionsSchema = v.object({ limit: v.int(), after: v.optional(v.string()) });
const host = { now: () => 0, clock: () => 0, changesAt: () => null, history: () => null, principal: () => null, get: () => null, scan: () => [], query: () => [], range: () => ({ rows: [], cursor: null }) };

function computePage(options: ScanPageOptions, range = host.range) {
  const rows = collection("rows");
  const app = define({ http: { page: query("page", (ctx) => ctx.scanPage(rows, options)) } });
  return (app.definitions.page as any).compute({ ...host, range }, null);
}

test("scanPage validates and freezes a sourcePage reference for the existing range host", () => {
  const options = { limit: 2, after: "opaque-cursor" };
  let sent: any;
  const result = computePage(options, ((reference: any) => {
    sent = reference;
    return { rows: [{ key: "a", value: null }], cursor: null };
  }) as typeof host.range);
  options.limit = 99;
  assert.deepEqual(sent, { kind: "sourcePage", collection: "rows", options: { limit: 2, after: "opaque-cursor" } });
  assert.ok(Object.isFrozen(sent) && Object.isFrozen(sent.options));
  assert.deepEqual(result, { rows: [{ key: "a", value: null }], cursor: null });
  assert.deepEqual(computePage(Object.assign(Object.create(null), { limit: Number.MAX_SAFE_INTEGER })), { rows: [], cursor: null });

  let read = false;
  const getter = { get limit() { read = true; return 1; } };
  const hidden = Object.defineProperty({ limit: 1 }, "after", { value: "hidden", enumerable: false });
  const invalid = [undefined, null, [], {}, 1, { limit: 0 }, { limit: -1 }, { limit: 0.5 }, { limit: NaN }, { limit: Infinity },
    { limit: Number.MAX_SAFE_INTEGER + 1 }, { limit: "1" }, { limit: 1, after: undefined }, { limit: 1, after: null },
    { limit: 1, offset: 0 }, { limit: 1, reverse: false }, { limit: 1, prefix: [] }, { limit: 1, index: "x" },
    { limit: 1, [Symbol("secret")]: true }, getter, hidden, Object.create({ limit: 1 }), new (class { limit = 1; })()];
  for (const input of invalid) {
    assert.throws(() => computePage(input as ScanPageOptions, () => { assert.fail("invalid options reached the host"); }), TypeError);
  }
  assert.equal(read, false, "validation never invokes accessors");
});

test("scanPage retains the normal context authority and declaration guard", () => {
  const guarded = collection("guarded").access({ read: true });
  const read = query("read", (ctx) => ctx.scanPage(guarded, { limit: 1 }));
  const undeclared = define({ http: { read } });
  assert.throws(() => (undeclared.definitions.read as any).compute(host, null), /declares access/);
  const referenced = collection("referenced").references(collection("target"), "target");
  const unlisted = define({ http: { read: query("read", (ctx) => ctx.scanPage(referenced, { limit: 1 })) } });
  assert.throws(() => (unlisted.definitions.read as any).compute(host, null), /declares references/);
  const app = define({ collections: [guarded], http: {
    read: query("read", (ctx) => {
      assert.equal(typeof (ctx as any).definer, "undefined");
      assert.equal(typeof (ctx as any).host, "undefined");
      assert.ok(Object.isFrozen(ctx));
      assert.equal(typeof ctx.scanPage, "function");
      return ctx.scanPage(guarded, { limit: 1 });
    }),
    write: mutation("write", (ctx) => ctx.scanPage(guarded, { limit: 1 })),
  } });
  const ordinary = { ...host, definer: () => assert.fail("scanPage elevated authority"), range: (ref: any) => {
    assert.equal(ref.collection, "guarded"); return { rows: [], cursor: null };
  } };
  assert.deepEqual((app.definitions.read as any).compute(ordinary, null), { rows: [], cursor: null });
  assert.deepEqual((app.definitions.write as any).compute(ordinary, null, () => assert.fail("scanPage elevated authority")), { rows: [], cursor: null });
});

test("scanPage pages typed tuple keys and every value without an index", async () => {
  const keySchema = v.tuple([v.string(), v.int()]);
  const rows = collection("typed").key(keySchema);
  const app = define({ http: {
    put: mutation("put", { args: v.object({ key: keySchema, value: v.json() }) }, (ctx, { key, value }) => { ctx.set(rows, key, value); return null; }),
    page: query("page", { args: optionsSchema }, (ctx, options) => {
      const page: RangePage<Json, [string, number]> = ctx.scanPage(rows, options);
      return page;
    }),
  } });
  const db = await testDatabase(app);
  const values: Json[] = [null, 7, false, "text", [], {}, { missingIndexedField: true }];
  const keys: [string, number][] = [["🌺", 2], ["\ue000", 1], ['"', 4], ["/", 3], ["\n", 9], ["\\", 8], ["a", 10]];
  for (let i = 0; i < keys.length; i++) db.mutate("put", { key: keys[i], value: values[i] });
  const expected = keys.map((key, i) => ({ key, value: values[i] })).sort((a, b) => Buffer.compare(
    Buffer.from(sourceId(rows.name, canonicalJson(a.key))), Buffer.from(sourceId(rows.name, canonicalJson(b.key)))));
  const found: typeof expected = [];
  let after: string | undefined;
  do {
    const page = db.query("page", { limit: 2, ...(after === undefined ? {} : { after }) });
    found.push(...page.rows);
    if (page.cursor) assert.equal(page.cursor, cursorAt(rows.name, canonicalJson(page.rows.at(-1)!.key)));
    after = page.cursor ?? undefined;
  } while (after !== undefined);
  assert.deepEqual(found, expected);
  assert.deepEqual(db.query("page", { limit: Number.MAX_SAFE_INTEGER }).rows, expected);

  function typing(ctx: Context) {
    const options: ScanPageOptions = { limit: 1 };
    const page: RangePage<Json, [string, number]> = ctx.scanPage(rows, options);
    // @ts-expect-error limit is required
    ctx.scanPage(rows, {});
    // @ts-expect-error source pages do not take offsets
    ctx.scanPage(rows, { limit: 1, offset: 0 });
    return page;
  }
  void typing;
});

test("scanPage physical source order differs from logical UTF-16 order and survives deleted cursors", async () => {
  const rows = collection("physical/🌺\n");
  const view = derive("view", (ctx) => ctx.scanPage(rows, { limit: 2 }));
  const app = define({ definitions: [view], http: {
    seed: mutation("seed", (ctx) => {
      for (const key of ["🌺", "\ue000", '"', "\\", "/", "\n", "\u0000", "a", ""]) ctx.set(rows, key, null);
      return null;
    }),
    page: query("page", { args: optionsSchema }, (ctx, options) => ctx.scanPage(rows, options)),
    scan: query("scan", (ctx) => ctx.scan(rows)),
    change: mutation("change", { args: v.string() }, (ctx, after) => {
      const first = ctx.scanPage(rows, { limit: 2 });
      const deleted = first.rows.at(-1)!.key;
      ctx.delete(rows, deleted);
      ctx.set(rows, "z", { pending: true });
      const next = ctx.scanPage(rows, { limit: 99, after });
      return { next, view: ctx.get(view) };
    }),
  } });
  const db = await testDatabase(app);
  db.mutate("seed");
  const first = db.query("page", { limit: 2 });
  const all = db.query("page", { limit: 99 }).rows;
  const physical = all.map((row) => row.key);
  assert.deepEqual(physical, [...physical].sort((a, b) => Buffer.compare(Buffer.from(sourceId(rows.name, a)), Buffer.from(sourceId(rows.name, b)))));
  assert.notDeepEqual(physical, db.query("scan").map((row) => row.key));
  assert.ok(physical.indexOf("\ue000") < physical.indexOf("🌺"));
  const changed = db.mutate("change", first.cursor!);
  assert.deepEqual(changed.next.rows.map((row) => row.key), [...physical.slice(2), "z"].sort((a, b) => Buffer.compare(Buffer.from(sourceId(rows.name, a)), Buffer.from(sourceId(rows.name, b)))));
  assert.equal(changed.next.cursor, null);
  assert.deepEqual(changed.view, db.query("page", { limit: 2 }));
  assert.deepEqual(db.query("page", { limit: 1, after: cursorAt(rows.name, "\u{10ffff}") }), { rows: [], cursor: null });

  const good = JSON.parse(first.cursor!);
  const invalid = ["", "not-json", "null", "[]", "{}", canonicalJson({ ...good, version: 2 }),
    canonicalJson({ ...good, extra: true }), canonicalJson({ ...good, scope: canonicalJson(["sourcePage", "other"]) }),
    canonicalJson({ ...good, last: sourceId("other", "a") }), canonicalJson({ ...good, last: 'source:["x"]' }),
    canonicalJson({ ...good, last: "source:" + JSON.stringify([rows.name, 1]) }),
    canonicalJson({ ...good, last: "source: " + canonicalJson([rows.name, "a"]) }),
    canonicalJson({ ...good, last: sourceId(rows.name, "\ud800") }), first.cursor! + " "];
  for (const after of invalid) assert.throws(() => db.query("page", { limit: 1, after }), (error: unknown) =>
    error instanceof FlowerError && error.failure?.code === "INVALID_REFERENCE", after);
});

test("scanPage ACL fills hidden prefixes/middles/suffixes and never exposes hidden keys or fields", async () => {
  const rows = collection<{ owner: string; secret: string }>("private").access(({ principal, row }) => {
    const operator = principal.subject.eq("operator");
    return { read: operator.or(row("owner").eq(principal.subject)), write: operator, fields: { secret: { read: operator } } };
  });
  const keys = ["00-hidden", "01-hidden", "02-visible", "03-hidden", "04-visible", "05-hidden", "06-hidden", "07-visible", "08-hidden", "09-hidden"];
  const app = define({ collections: [rows], auth: { authenticate: (_ctx, credentials) => typeof credentials === "string" ? { subject: credentials } : null, default: "public" }, http: {
    seed: mutation("seed", (ctx) => { for (const key of keys) ctx.set(rows, key, { owner: key.includes("visible") ? "alice" : "bob", secret: key + "-secret" }); return null; }),
    page: query("page", { args: optionsSchema }, (ctx, options) => ctx.scanPage(rows, options)),
    remove: mutation("remove", { args: v.string() }, (ctx, key) => { ctx.delete(rows, key); return null; }),
  } });
  const db = await testDatabase(app);
  db.mutate("seed", null, { credentials: "operator" });
  const first = db.query("page", { limit: 2 }, { credentials: "alice" });
  assert.deepEqual(first.rows, [{ key: "02-visible", value: { owner: "alice" } }, { key: "04-visible", value: { owner: "alice" } }]);
  assert.equal(first.cursor, cursorAt(rows.name, "04-visible"));
  assert.equal(first.cursor!.includes("hidden"), false);
  assert.equal(JSON.stringify(first).includes("secret"), false);
  db.mutate("remove", "04-visible", { credentials: "operator" });
  assert.deepEqual(db.query("page", { limit: 2, after: first.cursor! }, { credentials: "alice" }), { rows: [{ key: "07-visible", value: { owner: "alice" } }], cursor: null });
  assert.deepEqual(db.query("page", { limit: 1 }, { credentials: "nobody" }), { rows: [], cursor: null });
  const operator = db.query("page", { limit: 99 }, { credentials: "operator" });
  assert.equal(operator.rows.length, keys.length - 1);
  assert.ok(operator.rows.every((row) => row.value.secret === row.key + "-secret"));
  assert.equal(operator.cursor, null);
});

test("source-page ACL wrapper keeps bounded raw requests, all JSON values, and raw errors", () => {
  const rows = collection("guarded").access(({ key }) => ({ read: key.ne("hidden"), fields: { secret: { read: false } } }));
  const app = define({ collections: [rows] });
  const calls: any[] = [];
  const input = [{ key: "a", value: null }, { key: "b", value: 3 }, { key: "hidden", value: { secret: "hidden" } }, { key: "z", value: { secret: "private", public: true } }];
  const raw = { ...host, range: (reference: any) => {
    calls.push(reference);
    const after = reference.options.after === undefined ? -1 : input.findIndex((row) => sourceId(rows.name, row.key) === JSON.parse(reference.options.after).last);
    const page = input.slice(after + 1, after + 1 + reference.options.limit);
    return { rows: page, cursor: after + 1 + page.length < input.length ? cursorAt(rows.name, page.at(-1)!.key) : null };
  } };
  const enforced = enforceAccess(raw, app.collections!, { subject: "alice" });
  const reference = { kind: "sourcePage", collection: rows.name, options: { limit: 1 } };
  assert.deepEqual(enforced.host.range(reference), { rows: [{ key: "a", value: null }], cursor: cursorAt(rows.name, "a") });
  assert.equal(calls.length, 2);
  assert.ok(calls.every((call) => call.options.limit === 1));
  calls.length = 0;
  assert.deepEqual(enforced.host.range({ ...reference, options: { limit: Number.MAX_SAFE_INTEGER } }), {
    rows: [{ key: "a", value: null }, { key: "b", value: 3 }, { key: "z", value: { public: true } }], cursor: null,
  });
  assert.equal(calls[0].options.limit, Number.MAX_SAFE_INTEGER);
  const failure = Object.assign(new Error("original failure"), { code: "EVALUATION_BUDGET" });
  let count = 0;
  const broken = enforceAccess({ ...host, range: () => {
    if (++count === 2) throw failure;
    return { rows: [input[0]], cursor: cursorAt(rows.name, "a") };
  } }, app.collections!, { subject: "alice" });
  assert.throws(() => broken.host.range(reference), (error) => error === failure);
  assert.equal(enforced.depth(), 0);
});

test("scanPage works from an isolated bundled application with typed keys and field ACLs", async () => {
  const directory = await mkdtemp(join(tmpdir(), "flower-source-page-"));
  try {
    const entry = join(directory, "app.ts");
    const sdk = fileURLToPath(new URL("./index.ts", import.meta.url));
    await writeFile(entry, `
      import { collection, define, mutation, query, v } from ${JSON.stringify(sdk)};
      const rows = collection("bundled").key(v.tuple([v.string(), v.int()]))
        .access(({ principal }) => ({ read: true, write: true, fields: { secret: { read: principal.subject.eq("operator") } } }));
      export default define({ collections: [rows], auth: {
        authenticate: (_ctx, credentials) => typeof credentials === "string" ? { subject: credentials } : null,
        default: "public",
      }, http: {
        seed: mutation("seed", (ctx) => { ctx.set(rows, ["🌺", 1], null); ctx.set(rows, ["\\ue000", 2], { secret: "hidden", public: true }); return null; }),
        page: query("page", { args: v.object({ after: v.optional(v.string()) }) }, (ctx, options) => ctx.scanPage(rows, { limit: 1, ...options })),
      } });
    `);
    const db = await testDatabase(entry);
    db.mutate("seed", null, { credentials: "operator" });
    const first = db.query("page", {}) as unknown as RangePage<Json, [string, number]>;
    assert.deepEqual(first.rows, [{ key: ["\ue000", 2], value: { public: true } }]);
    assert.equal(first.cursor, cursorAt("bundled", canonicalJson(["\ue000", 2])));
    const second = db.query("page", { after: first.cursor! });
    assert.deepEqual(second, { rows: [{ key: ["🌺", 1], value: null }], cursor: null });
  } finally { await rm(directory, { recursive: true, force: true }); }
});
