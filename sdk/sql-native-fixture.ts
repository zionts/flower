// Real-server SQL conformance fixture. Deliberately not imported by Node testDatabase.
// Test credentials are accepted only by this disposable application's authenticator.
import {
  collection, define, derive, fail, mutation, query, sqlCatalog, sqlTable, v,
  type Collection, type Json, type QueryContext, type SqlColumn,
  type SqlIndex, type SqlProviderContext, type SqlProviderInput, type SqlTable,
} from "./index.ts";

type Owned = { owner: string };
type Customer = Owned & { name: string; secret?: string; nullable?: string | null; profile: Json };
type Order = Owned & { customer: string; nanodollars: string; status: string };
type Session = Owned & { tasks: { id: string; title: string; done: boolean }[] };
type Organization = Owned & { title: string };
type Scope = Owned & { org: string; title: string };
type BudgetRow = Owned & { payload: string };

const customers = collection<Customer>("fixture.private.customers")
  .index("name", ["name"]).index("secret", ["secret"])
  .access(({ principal, row }) => ({
    read: row("owner").eq(principal.subject).or(principal.claim("role").eq("root")),
    write: principal.claim("role").eq("root"),
    fields: { secret: { read: principal.claim("role").eq("root") } },
  }));
const orders = collection<Order>("fixture.private.orders").index("customer", ["customer"])
  .access(({ principal, row }) => ({
    read: row("owner").eq(principal.subject).or(principal.claim("role").eq("root")),
    write: principal.claim("role").eq("root"),
  }));
const sessions = collection<Session>("fixture.private.sessions").access(({ principal, row }) => ({
  read: row("owner").eq(principal.subject), write: principal.claim("role").eq("root"),
}));
const organizations = collection<Organization>("fixture.private.organizations").access(({ principal, row }) => ({
  read: row("owner").eq(principal.subject), write: principal.claim("role").eq("root"),
}));
const scopes = collection<Scope>("fixture.private.scopes").access(({ principal, row }) => ({
  read: row("owner").eq(principal.subject), write: principal.claim("role").eq("root"),
}));
const budgetRows = collection<BudgetRow>("fixture.private.budget").access(({ principal, row }) => ({
  read: row("owner").eq(principal.subject), write: principal.claim("role").eq("root"),
}));
const vault = collection<{ secret: string }>("fixture.unauthorized.vault").access(({ principal }) => ({
  read: principal.claim("role").eq("root"), write: principal.claim("role").eq("root"),
}));
const privileged = derive("fixture.privileged.total", (ctx) => ctx.scan(vault).length, { access: true });
const customerColumns: readonly SqlColumn[] = [
  { name: "id", type: "text", sourceKey: true },
  { name: "name", type: "text", sourceField: "name" },
  { name: "secret", type: "text", sourceField: "secret", nullable: true },
  { name: "nullable", type: "text", sourceField: "nullable", nullable: true },
  { name: "profile_json", type: "text", logicalType: "json" },
  { name: "authority_context", type: "text", logicalType: "json" },
];
function customerTable(name: string, indexes: readonly SqlIndex[]): SqlTable {
  return sqlTable({
    name, source: customers, columns: customerColumns, indexes,
    grain: "One visible customer", coverage: "Private rows and protected fields are filtered before SQL",
    project: (_ctx, batch) => ({
      rows: batch.rows.map((row, sourceRow) => ({ sourceRow, cells: [
        // Lies prove the native source mappings override projector output, including redacted fields.
        { text: "FORGED_SOURCE_KEY" }, { text: "FORGED_NAME" }, { text: "FORGED_SECRET" }, { text: "FORGED_NULL" },
        { text: JSON.stringify(row.value.profile) }, { text: JSON.stringify(batch.purpose) },
      ] })),
      provenance: [{ internalOnly: "INTERNAL_PROVENANCE_CANARY", source: customers.name }],
    }),
  });
}
const visibleCustomers = customerTable("customers", [{ name: "name", columns: ["name"] }, { name: "secret", columns: ["secret"] }]);
const scanCustomers = customerTable("customers_scan", []);
const visibleOrders = sqlTable({
  name: "orders", source: orders,
  columns: [
    { name: "id", type: "text", sourceKey: true },
    { name: "customer_id", type: "text", sourceField: "customer" },
    { name: "nanodollars", type: "integer", sourceField: "nanodollars", logicalType: "money", unit: "nanodollars" },
    { name: "status", type: "text", sourceField: "status" },
  ], indexes: [{ name: "customer", columns: ["customer_id"] }],
  project: (_ctx, batch) => ({ rows: batch.rows.map((_row, sourceRow) => ({ sourceRow, cells: [null, null, null, null] })) }),
});
const tasks = sqlTable({
  name: "tasks", source: sessions,
  columns: [{ name: "session_id", type: "text", sourceKey: true }, { name: "id", type: "text" }, { name: "title", type: "text" }, { name: "done", type: "integer" }],
  grain: "One task expanded from a visible session",
  project: (_ctx, batch) => ({ rows: batch.rows.flatMap((row, sourceRow) => (row.value as Session).tasks.map((task) => ({
    sourceRow, cells: [null, { text: task.id }, { text: task.title }, { integer: task.done ? "1" : "0" }],
  }))) }),
});
const boards = sqlTable({
  name: "boards", sources: [organizations, scopes],
  columns: [{ name: "id", type: "text" }, { name: "org_id", type: "text" }, { name: "scope_id", type: "text", nullable: true }, { name: "title", type: "text" }],
  grain: "One no-scope organization board plus one board per visible scope",
  project: (_ctx, batch) => ({ rows: batch.rows.map((row, sourceRow) => batch.source.name === organizations.name
    ? { sourceRow, cells: [{ text: `${row.key}:none` }, { text: String(row.key) }, null, { text: (row.value as Organization).title }] }
    : { sourceRow, cells: [{ text: String(row.key) }, { text: (row.value as Scope).org }, { text: String(row.key) }, { text: (row.value as Scope).title }] }) }),
});
const budgetTable = sqlTable({
  name: "budget_rows", source: budgetRows, columns: [{ name: "id", type: "text", sourceKey: true }],
  project: (_ctx, batch) => ({ rows: batch.rows.map((_row, sourceRow) => ({ sourceRow, cells: [null] })) }),
});
function escapeTable(name: string, escape: (ctx: SqlProviderContext, batch: SqlProviderInput) => void): SqlTable {
  return sqlTable({ name, source: customers, columns: [{ name: "id", type: "text", sourceKey: true }], project: (ctx, batch) => {
    // A caught forbidden callback operation must remain fatal natively.
    try { escape(ctx, batch); } catch { /* intentionally swallowed */ }
    return { rows: batch.rows.map((_row, sourceRow) => ({ sourceRow, cells: [null] })) };
  } });
}
const derivedEscape = escapeTable("provider_derived", (ctx) => { (ctx as QueryContext).get(privileged); });
// Adversarial fixture only: bypass the SDK's read-only callback context so the
// test reaches the native guard instead of merely catching an undefined writer.
declare const __flowerContexts: readonly { set?: (source: Collection<any, any, any>, key: string, value: Json) => unknown }[];
const writeEscape = escapeTable("provider_write", (_ctx) => {
  __flowerContexts[1].set!(vault, "escape", { secret: "ESCAPED" });
});
const classified = sqlTable({ name: "classified", source: vault, columns: [{ name: "secret", type: "text", sourceField: "secret" }],
  project: (_ctx, batch) => ({ rows: batch.rows.map((_row, sourceRow) => ({ sourceRow, cells: [null] })) }),
});
const tables = [visibleCustomers, scanCustomers, visibleOrders, tasks, boards, budgetTable, derivedEscape, writeEscape, classified];
const catalog = sqlCatalog({
  name: "fixture", version: "native-conformance-v1", tables,
  relationships: [
    { name: "order_customer", fromTable: "orders", fromColumns: ["customer_id"], toTable: "customers", toColumns: ["id"] },
    { name: "classified_customer", fromTable: "classified", fromColumns: ["secret"], toTable: "customers", toColumns: ["secret"] },
  ],
  authorize: (ctx, request) => {
    if (!request.invoker || request.invoker.subject === "$anonymous") return null;
    const purpose = request.purpose && typeof request.purpose === "object" && !Array.isArray(request.purpose) ? request.purpose : {};
    if (purpose.mode === "authority-derived") {
      try { (ctx as QueryContext).get(privileged); } catch { /* fatal must survive catch */ }
    }
    if (purpose.mode === "deny") return null;
    // Only this deployed callback chooses effective authority. Caller-supplied principal/effective is ignored.
    const principal = request.invoker.subject === "reporter" ? { subject: "alice", claims: { role: "user" } } : request.invoker;
    return { principal, context: { mode: purpose.mode === "report" ? "report" : "normal" },
      tables: tables.filter((table) => table.name !== "classified" || request.invoker!.claims && typeof request.invoker!.claims === "object"
        && !Array.isArray(request.invoker!.claims) && request.invoker!.claims.role === "root").map((table) => table.name) };
  },
});
const oneShot = { access: "authenticated", cache: false, watch: false } as const;
const input = v.object({
  sql: v.string(), parameters: v.optional(v.array(v.union(v.string(), v.number(), v.boolean(), v.null()))),
  maxRows: v.optional(v.int()), queryId: v.optional(v.string()), purpose: v.optional(v.json()),
});
const run = query("sql.query", { ...oneShot, args: input }, (ctx, args) => {
  const { purpose, ...request } = args;
  return ctx.sql.query(catalog, request, purpose).result;
});
const badFlags = query("sql.badFlags", { access: "authenticated" }, (ctx) => ctx.sql.query(catalog, { sql: "SELECT 1" }).result);

export default define({
  collections: [customers, orders, sessions, organizations, scopes, budgetRows, vault],
  definitions: [privileged], sql: [catalog],
  auth: { default: "authenticated", authenticate: (_ctx, credentials) => {
    if (typeof credentials !== "string" || !["alice", "bob", "root", "reporter"].includes(credentials)) return null;
    return { subject: credentials, claims: { role: credentials === "root" ? "root" : "user" } };
  } },
  http: {
    "sql.query": run,
    "sql.history": query("sql.history", { ...oneShot, args: input }, (ctx, args) => {
      const { purpose, ...request } = args;
      return { result: ctx.sql.query(catalog, request, purpose).result, history: ctx.history() };
    }),
    "sql.queryAlias": run,
    "sql.explain": query("sql.explain", { ...oneShot, args: input }, (ctx, args) => {
      const { purpose, ...request } = args; return ctx.sql.explain(catalog, request, purpose);
    }),
    "sql.catalog": query("sql.catalog", { ...oneShot, args: v.json() }, (ctx, purpose) => ctx.sql.catalog(catalog, purpose)),
    "sql.cancel": query("sql.cancel", { ...oneShot, args: v.object({ queryId: v.string(), purpose: v.optional(v.json()) }) },
      (ctx, args) => ctx.sql.cancel(catalog, args.queryId, args.purpose)),
    "sql.anonymousProbe": query("sql.anonymousProbe", { access: "public", cache: false, watch: false },
      (ctx) => ctx.sql.query(catalog, { sql: "SELECT COUNT(*) FROM customers" }).result),
    "sql.badFlags": badFlags,
    "sql.badFlagsAlias": badFlags,
    "sql.mutationProbe": mutation("sql.mutationProbe", { access: "authenticated" },
      (ctx) => ctx.sql.query(catalog, { sql: "SELECT 1" }).result),
    "ordinary.read": query("ordinary.read", { access: "authenticated" }, (ctx) => ctx.scan(customers).map((row) => ({ id: row.key, ...row.value }))),
    "ordinary.update": mutation("ordinary.update", { access: (_ctx, principal) => principal?.subject === "root", args: v.object({ id: v.string(), name: v.string() }) },
      (ctx, args) => {
        const customer = ctx.get(customers, args.id); if (!customer) fail("NOT_FOUND", "Customer missing");
        ctx.set(customers, args.id, { ...customer, name: args.name }); return args.name;
      }),
    setup: mutation("setup", { access: (_ctx, principal) => principal?.subject === "root" }, (ctx) => {
      const names = ["Alpha", "é", "", "\uE000", "😀", "e\u0301", "Å"];
      names.forEach((name, index) => ctx.set(customers, `c${index + 1}`, {
        owner: "alice", name, secret: "PROTECTED_SECRET_CANARY",
        ...(index === 2 || index === 4 ? { nullable: null } : index === 3 ? {} : { nullable: index === 6 ? "" : "present" }),
        profile: { team: index < 2 ? "blue" : "other", rank: index },
      }));
      ctx.set(customers, "private-bob", { owner: "bob", name: "HIDDEN_CUSTOMER_CANARY", secret: "HIDDEN_SECRET_CANARY", profile: { team: "red" } });
      ctx.set(orders, "o1", { owner: "alice", customer: "c1", nanodollars: "9007199254740993", status: "paid" });
      ctx.set(orders, "o2", { owner: "alice", customer: "c1", nanodollars: "7", status: "paid" });
      ctx.set(orders, "o3", { owner: "alice", customer: "c2", nanodollars: "17", status: "pending" });
      ctx.set(orders, "private-order", { owner: "bob", customer: "c1", nanodollars: "1000", status: "HIDDEN_ORDER_CANARY" });
      ctx.set(sessions, "s1", { owner: "alice", tasks: [{ id: "t1", title: "ship", done: true }, { id: "t2", title: "test", done: false }] });
      ctx.set(sessions, "s2", { owner: "alice", tasks: [] });
      ctx.set(sessions, "hidden-session", { owner: "bob", tasks: [{ id: "hidden-task", title: "HIDDEN_TASK_CANARY", done: false }] });
      ctx.set(organizations, "zero-scopes", { owner: "alice", title: "Zero scopes" });
      ctx.set(organizations, "with-scopes", { owner: "alice", title: "Scoped org" });
      ctx.set(organizations, "hidden-org", { owner: "bob", title: "HIDDEN_ORG_CANARY" });
      ctx.set(scopes, "scope-1", { owner: "alice", org: "with-scopes", title: "Scope one" });
      ctx.set(scopes, "hidden-scope", { owner: "bob", org: "hidden-org", title: "HIDDEN_SCOPE_CANARY" });
      ctx.set(vault, "classified", { secret: "CLASSIFIED_CANARY" });
      return { customers: 8, orders: 4 };
    }),
    "setup.budget": mutation("setup.budget", { access: (_ctx, principal) => principal?.subject === "root", args: v.object({ start: v.int(), count: v.int() }) },
      (ctx, { start, count }) => {
        if (start < 0 || count < 1 || count > 64) fail("INPUT_INVALID", "Budget seed batch is at most 64 rows");
        for (let i = start; i < start + count; i++) ctx.set(budgetRows, `b${String(i).padStart(5, "0")}`, { owner: "alice", payload: "x".repeat(8192) });
        return count;
      }),
  },
});
