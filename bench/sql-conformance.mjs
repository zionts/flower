#!/usr/bin/env node
/**
 * Native SDK/HTTP conformance, never the Node testDatabase imitation.
 *
 *   CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo build --bin flower --features sql
 *   node bench/sql-conformance.mjs
 *   FLOWER_BIN=/path/to/feature-enabled/flower node bench/sql-conformance.mjs --out /tmp/sql-conformance.json
 *   node bench/sql-conformance.mjs --expect-snapshot-gate  # hard-gated foundation; NOT positive SQL conformance
 *
 * Starts its own one-node Raft server and temporary database, deploys the bundled
 * TS fixture, and creates private data only through authenticated mutations.
 * It cannot attach to an existing server. Missing/native-SQL-disabled binaries
 * are failures, never skipped passes. Test-only guest credentials are intentional;
 * JWT/signature verification belongs to the consuming application's integration.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes, randomUUID, createHash } from "node:crypto";
import { constants } from "node:fs";
import { access, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { buildBundle } from "../sdk/bundle.ts";
import { FlowerAdmin, FlowerClient } from "../sdk/client.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { values } = parseArgs({ options: {
  binary: { type: "string", default: process.env.FLOWER_BIN ?? join(root, "target/debug/flower") },
  out: { type: "string" }, "keep-data": { type: "boolean", default: false },
  "no-history": { type: "boolean", default: false }, "expect-snapshot-gate": { type: "boolean", default: false },
} });
const binary = resolve(values.binary);
const report = { binary, binarySha256: null, bundleSha256: null, transport: "SDK over real HTTP", mode: values["expect-snapshot-gate"] ? "snapshot-gate-hold" : "positive-native-conformance", cases: [],
  limitations: ["No JWT/signature verification: disposable guest authenticator accepts fixed test credentials.",
    "System/maintenance invocations and active in-flight cancellation ownership need native/unit or consuming-app tests; this runner checks HTTP denials and completed-ID cleanup."],
  // Debug Wasmtime deployment can be slow on a shared build host. Native SQL
  // still enforces its own shorter deadline and unchanged memory/work budgets.
  generalEvaluationTimeoutMs: 120_000,
  passed: 0, failed: 0 };
let runtime;
let directory;
let failure;
const started = performance.now();

const I = (integer) => ({ integer: String(integer) });
const T = (text) => ({ text });
const code = (error) => error?.failure?.code ?? error?.code;
async function rejects(operation, expected) {
  await assert.rejects(operation, (error) => {
    assert.ok(expected.includes(code(error)), `Expected ${expected.join("|")}, received ${code(error)}: ${error.message}`);
    return true;
  });
}
async function check(name, operation) {
  const start = performance.now();
  try {
    await operation();
    report.passed++;
    report.cases.push({ name, status: "PASS", ms: Math.round(performance.now() - start) });
    console.log(`PASS ${name}`);
    return true;
  } catch (error) {
    report.failed++;
    report.cases.push({ name, status: "FAIL", ms: Math.round(performance.now() - start), code: code(error), error: error.stack ?? String(error) });
    console.error(`FAIL ${name}\n${error.stack ?? error}`);
    return false;
  }
}
function waitForLog(pattern, timeoutMs = 600_000) {
  if (pattern.test(runtime.logs)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let timer;
    const finish = (error) => {
      clearTimeout(timer);
      runtime.child.stdout.off("data", examine); runtime.child.stderr.off("data", examine);
      runtime.child.off("error", finish); runtime.child.off("close", ended);
      error ? reject(error) : resolve();
    };
    const examine = () => { if (pattern.test(runtime.logs)) finish(); };
    const ended = (exit, signal) => finish(new Error(`Flower exited before readiness: ${exit ?? signal}`));
    runtime.child.stdout.on("data", examine); runtime.child.stderr.on("data", examine);
    runtime.child.once("error", finish); runtime.child.once("close", ended);
    timer = setTimeout(() => finish(new Error(`Flower log readiness timed out (${pattern})`)), timeoutMs);
    examine();
  });
}
async function startServer() {
  await access(binary, constants.X_OK);
  directory = await mkdtemp(join(tmpdir(), "flower-native-sql-"));
  const reservation = createServer();
  await new Promise((resolve, reject) => { reservation.once("error", reject); reservation.listen(0, "127.0.0.1", resolve); });
  const address = `127.0.0.1:${reservation.address().port}`;
  await new Promise((resolve, reject) => reservation.close((error) => error ? reject(error) : resolve()));
  const adminToken = randomUUID();
  const child = spawn(binary, ["--id", "1", "--listen", address, "--data", directory], {
    // Never inherit operator backup/peer/retention settings into a disposable test database.
    cwd: root, env: { ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("FLOWER_"))), FLOWER_ADMIN_TOKEN: adminToken,
      FLOWER_EVALUATION_TIMEOUT_MS: String(report.generalEvaluationTimeoutMs),
      RUST_LOG: "flower=info,openraft=warn,openraft::engine::handler::server_state_handler=info" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  runtime = { child, logs: "", ended: false };
  const collect = (chunk) => { runtime.logs = (runtime.logs + chunk).slice(-64_000); };
  child.stdout.on("data", collect); child.stderr.on("data", collect);
  runtime.exited = new Promise((resolve) => child.once("close", (exit, signal) => { runtime.ended = true; resolve({ exit, signal }); }));
  await waitForLog(/Flower is listening/);
  // A concurrent cargo build can replace the path after spawn. Fingerprint the
  // running executable's inode on Linux, not a possibly newer file at that path.
  const executable = process.platform === "linux" ? `/proc/${child.pid}/exe` : binary;
  report.binarySha256 = createHash("sha256").update(await readFile(executable)).digest("hex");
  report.binaryFingerprintSource = process.platform === "linux" ? "running-process-executable" : "binary-path";
  const response = await fetch(`http://${address}/raft/initialize`, {
    method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ 1: address }), signal: AbortSignal.timeout(30_000),
  });
  assert.equal(response.status, 200, `Raft initialization: ${await response.text()}`);
  // Wait on an election event, not a status polling loop.
  await waitForLog(/become leader/);
  return { url: `http://${address}`, adminToken };
}
async function cleanup() {
  if (runtime && !runtime.ended) {
    runtime.child.kill("SIGTERM");
    let timer;
    try {
      const ended = await Promise.race([runtime.exited.then(() => true), new Promise((resolve) => { timer = setTimeout(() => resolve(false), 10_000); })]);
      if (!ended) { runtime.child.kill("SIGKILL"); await runtime.exited; }
    } finally { clearTimeout(timer); }
  }
  if (directory) {
    if (values["keep-data"]) console.log(`Kept isolated database: ${directory}`);
    else await rm(directory, { recursive: true, force: true });
  }
}

try {
  const server = await startServer();
  const admin = new FlowerAdmin(server.url, { adminToken: server.adminToken });
  const client = (credentials) => new FlowerClient(server.url, { credentials, retry: false });
  const alice = client("alice"), bob = client("bob"), rootClient = client("root"), reporter = client("reporter"), anonymous = client(undefined);
  const bundle = await buildBundle(join(root, "sdk/sql-native-fixture.ts"));
  report.bundleSha256 = bundle.hash;
  await admin.deploy(bundle, { requestId: "sql-conformance-deploy", signal: AbortSignal.timeout(120_000) });
  await rootClient.mutate("setup", null, { requestId: "sql-conformance-setup", signal: AbortSignal.timeout(120_000) });
  const query = async (sql, options = {}, caller = alice) => (await caller.query("sql.query", { sql, ...options }, { signal: AbortSignal.timeout(30_000) })).value;
  const rows = async (...args) => (await query(...args)).rows;

  if (values["expect-snapshot-gate"]) {
    report.limitations.push("Enforced snapshot reservation gate is closed. Positive SQL conformance is NOT executed or claimed in this mode.");
    await check("closed snapshot gate refuses every SQL operation before allocating evaluator work", async () => {
      for (const caller of [alice, rootClient]) {
        for (const [alias, input] of [["sql.query", { sql: "SELECT 1" }], ["sql.queryAlias", { sql: "SELECT COUNT(*) FROM customers" }],
          ["sql.explain", { sql: "SELECT 1" }], ["sql.catalog", null], ["sql.cancel", { queryId: "blocked" }]]) {
          await rejects(() => caller.query(alias, input), ["SQL_SNAPSHOT_UNBOUNDED"]);
        }
      }
    });
    await check("snapshot gate does not disable ordinary authenticated reads or mutations", async () => {
      const before = (await alice.query("ordinary.read", null)).value;
      assert.equal(before.length, 7); assert.ok(before.every((row) => !Object.hasOwn(row, "secret")));
      await rootClient.mutate("ordinary.update", { id: "c1", name: "Gated ordinary update" }, { requestId: "gated-ordinary-update" });
      assert.equal((await alice.query("ordinary.read", null)).value.find((row) => row.id === "c1").name, "Gated ordinary update");
      await rejects(() => anonymous.query("ordinary.read", null), ["UNAUTHENTICATED", "FORBIDDEN"]);
    });
  } else {
    const nativeAvailable = await check("native evaluator smoke and typed positional parameters", async () => {
      assert.deepEqual(await rows("SELECT ?, ?, ?, ?, ?", { parameters: ["é", 7, true, null, 1.25] }), [[T("é"), I(7), I(1), null, { real: 1.25 }]]);
    });
    if (!nativeAvailable) throw Object.assign(new Error("Native SQL conformance blocked at smoke test; no positive conformance is claimed. For the hard-gated foundation use --expect-snapshot-gate."), { code: "NATIVE_CONFORMANCE_BLOCKED" });
    await check("indexed join and aggregate preserve exact nanodollars beyond 2^53", async () => {
      const result = await query("SELECT c.name, SUM(o.nanodollars) AS nanodollars FROM customers c JOIN orders o ON o.customer_id=c.id GROUP BY c.id ORDER BY c.id");
      assert.deepEqual(result.rows, [[T("Alpha"), I("9007199254741000")], [T("é"), I("17")]]);
      assert.equal(result.resultTruncated, false);
      assert.equal(result.catalogVersion, "native-conformance-v1");
      assert.deepEqual(await rows("SELECT nanodollars FROM orders WHERE id='o1'"), [[I("9007199254740993")]]);
      assert.deepEqual(await rows("SELECT SUM(nanodollars) FROM orders"), [[I("9007199254741017")]]);
    });
    await check("private rows filtered before COUNT, EXISTS, JSON and SQL sort", async () => {
      assert.deepEqual(await rows("SELECT COUNT(*), COUNT(secret), COUNT(nullable) FROM customers"), [[I(7), I(0), I(4)]]);
      assert.deepEqual(await rows("SELECT COUNT(*) FROM customers c WHERE EXISTS (SELECT 1 FROM orders o WHERE o.customer_id=c.id)"), [[I(2)]]);
      assert.deepEqual(await rows("SELECT id FROM customers WHERE json_extract(profile_json,'$.team')='blue' ORDER BY id"), [[T("c1")], [T("c2")]]);
      assert.deepEqual(await rows("SELECT name FROM customers ORDER BY name"), ["", "Alpha", "e\u0301", "Å", "é", "\uE000", "😀"].map((name) => [T(name)]));
      assert.deepEqual(await rows("SELECT id FROM customers WHERE id='private-bob'"), []);
      assert.deepEqual(await rows("SELECT COUNT(*) FROM orders WHERE status='HIDDEN_ORDER_CANARY'"), [[I(0)]]);
      assert.deepEqual(await rows("SELECT COUNT(*) FROM customers", {}, bob), [[I(1)]]);
    });
    await check("native mapped columns override projector lies and redact protected fields", async () => {
      assert.deepEqual(await rows("SELECT id,name,secret,nullable FROM customers WHERE id='c1'"), [[T("c1"), T("Alpha"), null, T("present")]]);
      assert.deepEqual(await rows("SELECT id,nullable FROM customers WHERE id IN ('c3','c4','c5') ORDER BY id"), [[T("c3"), null], [T("c4"), null], [T("c5"), null]]);
      assert.deepEqual(await rows("SELECT secret FROM customers WHERE id='c1'", {}, rootClient), [[T("PROTECTED_SECRET_CANARY")]]);
    });
    await check("indexed equality equals conservative scan for Unicode and empty strings", async () => {
      for (const name of ["Alpha", "é", "", "\uE000", "😀", "e\u0301", "Å", "missing", "HIDDEN_CUSTOMER_CANARY"]) {
        const options = { parameters: [name] };
        const indexed = await rows("SELECT id,name,nullable FROM customers WHERE name=? ORDER BY id", options);
        assert.deepEqual(indexed, await rows("SELECT id,name,nullable FROM customers_scan WHERE name=? ORDER BY id", options));
        assert.deepEqual(indexed, await rows("SELECT id,name,nullable FROM customers WHERE +name=? ORDER BY id", options));
      }
    });
    await check("native explain distinguishes pushed indexed equality from conservative scan", async () => {
      const explain = async (sql) => (await alice.query("sql.explain", { sql })).value.plan.map((entry) => entry.detail).join("\n");
      assert.match(await explain("SELECT id FROM customers WHERE name='é'"), /VIRTUAL TABLE INDEX [1-9][0-9]*:/);
      assert.match(await explain("SELECT id FROM customers_scan WHERE name='é'"), /VIRTUAL TABLE INDEX 0:/);
      assert.match(await explain("SELECT id FROM customers WHERE name='alpha' COLLATE NOCASE"), /VIRTUAL TABLE INDEX 0:/);
      assert.match(await explain("SELECT c.id,SUM(o.nanodollars) FROM customers c JOIN orders o ON o.customer_id=c.id GROUP BY c.id"), /VIRTUAL TABLE INDEX [1-9][0-9]*:/);
    });
    await check("NULL, missing and non-BINARY/IN predicates retain conservative semantics", async () => {
      for (const where of ["nullable IS NULL", "name IS NULL", "name=NULL", "name COLLATE NOCASE='alpha'", "name IN ('é','😀')", "name>'Å'", "secret IS NULL"]) {
        assert.deepEqual(await rows(`SELECT id FROM customers WHERE ${where} ORDER BY id`), await rows(`SELECT id FROM customers_scan WHERE ${where} ORDER BY id`));
      }
      assert.deepEqual(await rows("SELECT COUNT(*) FROM customers WHERE nullable IS NULL"), [[I(3)]]);
    });
    await check("protected indexed fields cannot change invoker visibility or NULL behavior", async () => {
      assert.deepEqual(await rows("SELECT COUNT(*) FROM customers WHERE secret=?", { parameters: ["PROTECTED_SECRET_CANARY"] }), [[I(0)]]);
      assert.deepEqual(await rows("SELECT COUNT(*) FROM customers_scan WHERE secret=?", { parameters: ["PROTECTED_SECRET_CANARY"] }), [[I(0)]]);
      assert.deepEqual(await rows("SELECT COUNT(*) FROM customers WHERE secret IS NULL"), [[I(7)]]);
      assert.deepEqual(await rows("SELECT COUNT(*) FROM customers WHERE secret=?", { parameters: ["PROTECTED_SECRET_CANARY"] }, rootClient), [[I(7)]]);
    });
    await check("batch sourceRow binding preserves expanded session tasks", async () => {
      assert.deepEqual(await rows("SELECT session_id,id,title,done FROM tasks ORDER BY id"), [[T("s1"), T("t1"), T("ship"), I(1)], [T("s1"), T("t2"), T("test"), I(0)]]);
      assert.deepEqual(await rows("SELECT COUNT(*), SUM(done) FROM tasks"), [[I(2), I(1)]]);
    });
    await check("union sources include no-scope boards when an organization has zero scopes", async () => {
      assert.deepEqual(await rows("SELECT id,org_id,scope_id FROM boards ORDER BY id"), [[T("scope-1"), T("with-scopes"), T("scope-1")], [T("with-scopes:none"), T("with-scopes"), null], [T("zero-scopes:none"), T("zero-scopes"), null]]);
      assert.deepEqual(await rows("SELECT COUNT(*) FROM boards WHERE org_id='zero-scopes' AND scope_id IS NULL"), [[I(1)]]);
    });
    await check("duplicate SQL column aliases preserve positional values", async () => {
      const result = await query("SELECT name AS duplicate,id AS duplicate FROM customers WHERE id='c1'");
      assert.deepEqual(result.columns, [{ name: "duplicate" }, { name: "duplicate" }]);
      assert.deepEqual(result.rows, [[T("Alpha"), T("c1")]]);
    });
    await check("result row truncation is explicit and does not truncate aggregate input", async () => {
      const result = await query("SELECT id FROM customers ORDER BY id", { maxRows: 2 });
      assert.deepEqual(result.rows, [[T("c1")], [T("c2")]]);
      assert.equal(result.resultTruncated, true);
      const aggregate = await query("SELECT COUNT(*) FROM customers", { maxRows: 1 });
      assert.deepEqual(aggregate.rows, [[I(7)]]); assert.equal(aggregate.resultTruncated, false);
      assert.equal((await query("SELECT id FROM customers ORDER BY id LIMIT 2", { maxRows: 2 })).resultTruncated, false);
    });
    await check("discovery metadata filters unauthorized logical tables and hides native internals", async () => {
      const discovery = (await alice.query("sql.catalog", null)).value;
      assert.deepEqual(discovery.tables.map((table) => table.name).sort(), ["boards", "budget_rows", "customers", "customers_scan", "orders", "provider_derived", "provider_write", "tasks"].sort());
      assert.deepEqual(discovery.relationships.map((relation) => relation.name), ["order_customer"]);
      const encoded = JSON.stringify(discovery);
      assert.ok(!/fixture\.private|fixture\.unauthorized|sourceField|sourceKey|provider|provenance|classified|\$sql/.test(encoded.replaceAll("provider_derived", "").replaceAll("provider_write", "")), encoded);
      assert.deepEqual(await rows("SELECT name FROM sql_tables ORDER BY name"), discovery.tables.map((table) => [T(table.name)]).sort((a, b) => a[0].text.localeCompare(b[0].text)));
      assert.deepEqual(await rows("SELECT COUNT(*) FROM sql_columns WHERE table_name='classified'"), [[I(0)]]);
      assert.deepEqual(await rows("SELECT name FROM sql_relationships"), [[T("order_customer")]]);
      assert.ok((await rootClient.query("sql.catalog", null)).value.tables.some((table) => table.name === "classified"));
      await rejects(() => query("SELECT * FROM classified"), ["SQL_INVALID", "SQL_FORBIDDEN"]);
    });
    await check("public results never include projector provenance or hidden canaries", async () => {
      const result = await query("SELECT * FROM customers ORDER BY id");
      assert.deepEqual(Object.keys(result).sort(), ["columns", "rows", "resultTruncated", "warnings", "catalogVersion"].sort());
      assert.ok(!/INTERNAL_PROVENANCE_CANARY|PROTECTED_SECRET_CANARY|HIDDEN_|FORGED_|fixture\.private/.test(JSON.stringify(result)));
    });
    await check("authority validates context and effective invoker rather than caller-supplied authority", async () => {
      assert.deepEqual(await rows("SELECT authority_context FROM customers WHERE id='c1'", { purpose: { mode: "report", effective: "bob", principal: { subject: "root" }, secret: "RAW_PURPOSE_CANARY" } }), [[T('{"mode":"report"}')]]);
      assert.deepEqual(await rows("SELECT COUNT(*) FROM customers", {}, reporter), [[I(7)]]);
      assert.deepEqual(await rows("SELECT COUNT(secret) FROM customers", {}, reporter), [[I(0)]]);
      await rejects(() => query("SELECT 1", { purpose: { mode: "deny" } }), ["SQL_AUTHORITY_DENIED"]);
    });
    await check("query/explain/catalog/cancel require authenticated HTTP callers", async () => {
      for (const [alias, input] of [["sql.query", { sql: "SELECT 1" }], ["sql.explain", { sql: "SELECT 1" }], ["sql.catalog", null], ["sql.cancel", { queryId: "unknown" }]]) {
        await rejects(() => anonymous.query(alias, input), ["UNAUTHENTICATED", "FORBIDDEN", "AUTHORIZATION_DENIED"]);
      }
      await rejects(() => anonymous.query("sql.anonymousProbe", null), ["SQL_AUTHORITY_DENIED", "SQL_AUTHORITY_FORBIDDEN"]);
      await rejects(() => alice.mutate("sql.mutationProbe", null), ["SQL_AUTHORITY_FORBIDDEN"]);
    });
    await check("SQL cache/watch flag refusal and aliased one-shot methods", async () => {
      await rejects(() => alice.query("sql.badFlags", null), ["SQL_METHOD_NOT_ONESHOT"]);
      await rejects(() => alice.query("sql.badFlagsAlias", null), ["SQL_METHOD_NOT_ONESHOT"]);
      const expected = await query("SELECT COUNT(*) FROM customers");
      assert.deepEqual((await alice.query("sql.queryAlias", { sql: "SELECT COUNT(*) FROM customers" })).value, expected);
      for (const alias of ["sql.query", "sql.queryAlias"]) {
        const watch = alice.watch(alias, { sql: "SELECT 1" }, { signal: AbortSignal.timeout(10_000) });
        try { await rejects(() => watch.next(), ["WATCH_NOT_SUPPORTED"]); } finally { await watch.return(); }
      }
    });
    await check("dedicated provider and authority callback forbidden operations remain fatal after catch", async () => {
      await rejects(() => query("SELECT * FROM provider_derived"), ["SQL_CALLBACK_FORBIDDEN"]);
      await rejects(() => query("SELECT * FROM provider_write"), ["SQL_CALLBACK_FORBIDDEN"]);
      await rejects(() => query("SELECT 1", { purpose: { mode: "authority-derived" } }), ["SQL_CALLBACK_FORBIDDEN"]);
      assert.deepEqual(await rows("SELECT COUNT(*) FROM classified", {}, rootClient), [[I(1)]]);
    });
    await check("bounded explain hides physical sources and provenance", async () => {
      const explain = (await alice.query("sql.explain", { sql: "SELECT c.id,SUM(o.nanodollars) FROM customers c JOIN orders o ON o.customer_id=c.id GROUP BY c.id" })).value;
      assert.equal(explain.catalogVersion, "native-conformance-v1"); assert.ok(explain.plan.length > 0);
      assert.ok(explain.plan.every((entry) => typeof entry.detail === "string"));
      assert.ok(!/fixture\.private|fixture\.unauthorized|provenance|\$sql/.test(JSON.stringify(explain)));
    });
    await check("read-only and single-statement authorizer rejects SQL escape surfaces", async () => {
      for (const sql of ["DELETE FROM customers", "SELECT 1; SELECT 2", "PRAGMA database_list", "ATTACH DATABASE ':memory:' AS escaped", "SELECT * FROM sqlite_schema", "SELECT load_extension('not-a-library')"]) {
        await rejects(() => query(sql), ["SQL_FORBIDDEN", "SQL_INVALID", "SQL_INPUT_INVALID"]);
      }
      assert.deepEqual(await rows("SELECT COUNT(*) FROM customers"), [[I(7)]]);
    });
    await check("completed query IDs are cleaned and reusable; cancellation cannot find foreign/inactive IDs", async () => {
      const queryId = "sdk-conformance-query-id";
      assert.deepEqual(await rows("SELECT 1", { queryId }), [[I(1)]]);
      assert.equal((await bob.query("sql.cancel", { queryId })).value, false);
      assert.equal((await reporter.query("sql.cancel", { queryId })).value, false);
      assert.equal((await alice.query("sql.cancel", { queryId })).value, false);
      assert.deepEqual(await rows("SELECT 2", { queryId }), [[I(2)]]);
      await rejects(() => query("SELECT 1", { queryId: "" }), ["SQL_CANCEL_DENIED", "SQL_INPUT_INVALID"]);
    });
    await check("ordinary non-SQL read/update still works and later one-shot SQL sees the commit", async () => {
      const before = (await alice.query("ordinary.read", null)).value;
      assert.equal(before.length, 7); assert.ok(before.every((row) => !Object.hasOwn(row, "secret")));
      await rootClient.mutate("ordinary.update", { id: "c1", name: "Renamed" }, { requestId: "ordinary-update" });
      assert.equal((await alice.query("ordinary.read", null)).value.find((row) => row.id === "c1").name, "Renamed");
      assert.deepEqual(await rows("SELECT name FROM customers WHERE id='c1'"), [[T("Renamed")]]);
      assert.deepEqual(await rows("SELECT id FROM customers WHERE name='Renamed'"), [[T("c1")]]);
      await rootClient.mutate("ordinary.update", { id: "c1", name: "Alpha" }, { requestId: "ordinary-restore" });
    });
    if (!values["no-history"]) await check("same-snapshot query history envelope equals trusted context after retention initialization", async () => {
      const status = await admin.retentionStatus();
      const database = randomBytes(16).toString("hex"), incarnation = randomBytes(16).toString("hex");
      await admin.controlRetention(status.revision, { operation: "initialize", database, incarnation, max_receipt_bytes: null });
      const execution = await alice.query("sql.history", { sql: "SELECT COUNT(*) FROM customers" });
      assert.deepEqual(execution.history, { database, incarnation });
      assert.deepEqual(execution.value.history, execution.history);
      assert.deepEqual(execution.value.result.rows, [[I(7)]]);
    });
    else report.limitations.push("History test disabled by explicit --no-history.");

    await check("source work exhaustion fails scalar aggregates rather than return partial success", async () => {
      const count = 1100;
      for (let start = 0; start < count; start += 64) {
        await rootClient.mutate("setup.budget", { start, count: Math.min(64, count - start) },
          { requestId: `budget-${start}`, signal: AbortSignal.timeout(120_000) });
      }
      await rejects(() => query("SELECT COUNT(*) FROM budget_rows", { maxRows: 1 }), ["SQL_SOURCE_BUDGET"]);
      // A real SQL LIMIT is allowed to stop early; a response maxRows cap is not.
      const bounded = await query("SELECT id FROM budget_rows LIMIT 2", { maxRows: 2 });
      assert.deepEqual(bounded.rows, [[T("b00000")], [T("b00001")]]); assert.equal(bounded.resultTruncated, false);
      assert.deepEqual(await rows("SELECT COUNT(*) FROM customers"), [[I(7)]]);
    });
  }
} catch (error) {
  failure = error;
  report.failed++;
  report.cases.push({ name: code(error) === "NATIVE_CONFORMANCE_BLOCKED" ? "positive native conformance blocked" : "server launch/deploy/setup", status: "FAIL", code: code(error), error: error.stack ?? String(error) });
  console.error(error.stack ?? error);
} finally {
  await cleanup();
  report.elapsedMs = Math.round(performance.now() - started);
  report.status = code(failure) === "NATIVE_CONFORMANCE_BLOCKED" ? "BLOCKED" : report.failed === 0 ? (values["expect-snapshot-gate"] ? "GATED_HOLD" : "PASS") : "FAIL";
  if (values.out) {
    const output = resolve(values.out);
    await mkdir(dirname(output), { recursive: true });
    await writeFile(output, JSON.stringify(report, null, 2) + "\n");
    console.log(`Report: ${output}`);
  }
  console.log(`${report.status}: ${report.passed} passed; ${report.failed} failed; ${report.elapsedMs} ms; binary sha256=${report.binarySha256 ?? "unavailable"}`);
  for (const limitation of report.limitations) console.log(`NOT COVERED: ${limitation}`);
  if (report.failed) {
    if (failure || process.env.FLOWER_SQL_LOGS_ON_FAILURE === "1") console.error(`Flower log tail:\n${runtime?.logs ?? "not started"}`);
    process.exitCode = 1;
  }
}
