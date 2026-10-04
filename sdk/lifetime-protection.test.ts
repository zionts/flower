import assert from "node:assert/strict";
import { test } from "node:test";
import { collection, define, v } from "./index.ts";
import type { Collection } from "./index.ts";
import { collectionInfo } from "./core.ts";
import { collectionManifest } from "./indexing.ts";

const plain = <T>(value: T): T => JSON.parse(JSON.stringify(value));

test("protectLifetime emits only the closed declared-source manifest literal", () => {
  const original = collection("arbitraryPhysicalSource");
  const protectedSource = original.protectLifetime();
  assert.notEqual(protectedSource, original);
  assert.equal(Object.isFrozen(protectedSource), true);
  assert.equal(Object.hasOwn(protectedSource, "nativeLifetime"), false);
  assert.equal(collectionInfo(original)?.nativeLifetime, undefined);
  assert.equal(collectionInfo(protectedSource)?.nativeLifetime, "protected");
  assert.deepEqual(plain(define({ collections: [protectedSource], http: {} }).collections), [
    { name: original.name, indexes: {}, nativeLifetime: "protected" },
  ]);
  assert.deepEqual(plain(collectionManifest([original])), [{ name: original.name, indexes: {} }]);
});

test("all typed collection builder clones retain lifetime, key, value, indexes, access and references", () => {
  const value = v.object({ owner: v.string(), target: v.string(), cents: v.int() });
  const key = v.tuple([v.string(), v.int()]);
  const target = collection("targets");
  const protectedSource = collection("ledger", value).protectLifetime()
    .key(key).index("byOwner", ["owner"]).access({ read: true, write: false })
    .references(target, "target");
  type Value = { owner: string; target: string; cents: number };
  const typed: Collection<Value, [string, number], { readonly byOwner: readonly ["owner"] }> = protectedSource;
  assert.deepEqual(typed.by("byOwner").eq("ann").fields, ["owner"]);
  const info = collectionInfo(typed)!;
  assert.equal(info.nativeLifetime, "protected");
  assert.deepEqual(info.key!.parse(["ann", 1]), ["ann", 1]);
  assert.deepEqual(info.value!.parse({ owner: "ann", target: "t", cents: 1 }), { owner: "ann", target: "t", cents: 1 });
  assert.throws(() => info.key!.parse("wrong"));
  assert.throws(() => info.value!.parse({ owner: "ann", target: "t", cents: "wrong" }));
  assert.deepEqual(plain(collectionManifest([typed])), [{
    name: "ledger", indexes: { byOwner: ["owner"] },
    access: { read: { const: true }, insert: { const: false }, update: { const: false }, delete: { const: false } },
    references: [{ target: "targets", fields: ["target"] }], nativeLifetime: "protected",
  }]);
  const protectedLast = collection("ledger", value).key(key).index("byOwner", ["owner"])
    .access({ read: true, write: false }).references(target, "target").protectLifetime();
  assert.deepEqual(plain(collectionManifest([protectedLast])), plain(collectionManifest([typed])));
});

test("protection is idempotent and preserves existing declarations", () => {
  const source = collection<{ n: number }>("custom").index("byN", ["n"]).protectLifetime();
  assert.deepEqual(plain(collectionManifest([source, source.protectLifetime()])), [
    { name: "custom", indexes: { byN: ["n"] }, nativeLifetime: "protected" },
  ]);
});

test("same-name protected and undeclared lifetime cannot silently merge in either order", () => {
  const plainSource = collection("custom");
  const protectedSource = plainSource.protectLifetime();
  for (const references of [[plainSource, protectedSource], [protectedSource, plainSource]]) {
    assert.throws(() => collectionManifest(references), /different native lifetime protection/);
    assert.throws(() => define({ collections: references, http: {} }), /different native lifetime protection/);
  }
});

test("existing duplicate index, access and reference conflicts still reject protected declarations", () => {
  const source = collection<{ n: number; target: string }>("custom").protectLifetime();
  assert.throws(() => collectionManifest([source, source.index("byN", ["n"])]), /different indexes/);
  assert.throws(() => collectionManifest([
    source.access({ read: true }), source.access({ read: false }),
  ]), /different access/);
  assert.throws(() => collectionManifest([
    source.references(collection("a"), "target"), source.references(collection("b"), "target"),
  ]), /different references/);
});

test("name-only caller references cannot inject the declaration through properties or a getter", () => {
  for (const nativeLifetime of ["protected", "unprotected", false, true, null, 1, {}, undefined]) {
    const raw = { kind: "collection", name: "custom", indexes: {}, nativeLifetime } as unknown as Collection;
    assert.throws(() => collectionManifest([raw]), /requires collection.protectLifetime/);
  }
  let called = false;
  const getter = { kind: "collection", name: "custom", indexes: {}, get nativeLifetime() { called = true; return "protected"; } } as unknown as Collection;
  assert.throws(() => collectionManifest([getter]), /requires collection.protectLifetime/);
  assert.equal(called, false);
  const inherited = Object.assign(Object.create({ nativeLifetime: "protected" }), { kind: "collection", name: "custom", indexes: {} }) as Collection;
  assert.throws(() => collectionManifest([inherited]), /requires collection.protectLifetime/);
  assert.deepEqual(plain(collectionManifest([{ kind: "collection", name: "custom", indexes: {} } as unknown as Collection])), [
    { name: "custom", indexes: {} },
  ]);
});

test("builder has no opt-out arguments and cannot bless a forged receiver", () => {
  const source = collection("custom");
  for (const argument of [undefined, null, false, true, "protected", "unprotected", {}]) {
    assert.throws(() => (source.protectLifetime as Function)(argument), /no arguments/);
  }
  assert.throws(() => source.protectLifetime.call({ kind: "collection", name: "custom", indexes: {} } as unknown as Collection), /declared collection/);
  assert.equal("unprotectLifetime" in source, false);
  if (false) {
    // @ts-expect-error The closed builder takes no arguments.
    source.protectLifetime(false);
    // @ts-expect-error There is no opt-out builder.
    source.unprotectLifetime();
  }
});

test("protection neither grants access nor guesses SQL or business collection names", () => {
  const names = ["sqlCustodies", "nativeBlobReceipts", "nativeSealReceipts", "modelCustodies", "ordinary"];
  const unprotected = define({ collections: names.map((name) => collection(name)), http: {} });
  assert.equal(unprotected.sql, undefined);
  assert.ok(unprotected.collections!.every((entry) => !Object.hasOwn(entry, "nativeLifetime")));
  const protectedSource = define({ collections: [collection("not_a_sql_name").protectLifetime()], http: {} });
  assert.equal(protectedSource.sql, undefined);
  assert.equal(Object.hasOwn(protectedSource.collections![0], "access"), false);
});
