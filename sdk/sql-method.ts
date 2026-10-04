import { fail, plainObject, query, requireName, type Access, type HistoryIdentity, type Principal, type QueryMethod } from "./core.ts";
import { keyManifest, type ManagedKey } from "./keys.ts";
import type { Infer, SchemaLike } from "./schema.ts";
import type { Json } from "./json.ts";
import { sqlDeclaration, type SqlCatalog, type SqlCatalogInfo, type SqlExecution, type SqlExplain, type SqlQueryInput, type SqlResult } from "./sql.ts";

export type SqlOperation = "query" | "explain" | "catalog" | "cancel";
export type SqlCancelResultShape = "boolean" | "cancelled";
export interface SqlTerminalRequest {
  readonly input: SqlQueryInput | {readonly queryId: string} | null;
  /** Untrusted request purpose; only deployed authority validation can confer rights. */
  readonly purpose: Json;
}
export interface SqlFinishBinding {
  readonly invoker: Principal;
  readonly principal: Principal;
  readonly clock: number;
  readonly history: HistoryIdentity | null;
  readonly codeVersion: string;
  readonly catalogVersion: string;
  readonly authorityContext: Json;
  readonly sourceRevision: number;
  /** Actual native permission-ledger bound, exclusive; null is evaluated independence/invariance only. */
  readonly validUntil: number | null;
  readonly partition: {readonly name: string; readonly epoch: number} | null;
}
export interface SqlFinishMetadata extends SqlFinishBinding {readonly request: SqlTerminalRequest}
/** No source, SQL, write, definer, secret-handle or ambient clock getter exists. */
export interface SqlFinishContext {
  principal(): Principal;
  clock(): number;
  history(): HistoryIdentity | null;
  codeVersion(): string;
  readonly binding: SqlFinishBinding;
}
export type SqlPublicResult<O extends SqlOperation> = O extends "query" ? SqlResult : O extends "explain" ? SqlExplain : O extends "catalog" ? SqlCatalogInfo : boolean;
/** Application finalizers keep the established query {result,provenance} wrapper. */
export type SqlOperationResult<O extends SqlOperation> = O extends "query" ? SqlExecution : SqlPublicResult<O>;
/** Trusted native callback transport, adapted to finalize(ctx,execution,metadata). */
export interface SqlFinishInput<O extends SqlOperation = SqlOperation> {
  readonly request: SqlTerminalRequest;
  readonly result: SqlPublicResult<O>;
  readonly provenance: readonly Json[];
  readonly binding: SqlFinishBinding;
}
export interface SqlMethodSpec<A, O extends SqlOperation, V = SqlPublicResult<O>> {
  readonly catalog: SqlCatalog;
  readonly operation: O;
  /** Closed native cancellation formatting only; never a guest/caller choice. */
  readonly cancelResult?: O extends "cancel" ? SqlCancelResultShape : never;
  readonly args?: SchemaLike<A>;
  readonly access?: Access<A>;
  /** Readless: receives only actual verified invoker and validated method args. */
  readonly plan?: (invoker: Principal | null, args: A) => SqlTerminalRequest;
  /** Runs only after fresh native authority/source/expiry/code/history validation. */
  readonly finalize?: O extends "cancel" ? never : (ctx: SqlFinishContext, execution: SqlOperationResult<O>, metadata: SqlFinishMetadata) => V;
  /** Native finalizer signing is restricted to these declared keys and signing operations. */
  readonly signingKeys?: O extends "cancel" ? never : readonly ManagedKey[];
}
export interface SqlTerminalMetadata {
  readonly catalog: string;
  readonly operation: SqlOperation;
  readonly cancelResult?: SqlCancelResultShape;
  readonly finalizer: string;
  readonly signingKeys: readonly ManagedKey[];
}
interface Info {
  readonly catalog: SqlCatalog;
  readonly terminal: SqlTerminalMetadata;
  readonly finalizer: {readonly kind: "sqlFinalizer"; readonly name: string; readonly compute: (ctx: unknown, args: SqlFinishInput) => unknown};
}
const infos = new WeakMap<object, Info>();

export function sqlMethod<S extends SchemaLike<any>>(name: string, spec: SqlMethodSpec<Infer<S>, "cancel", {readonly cancelled:boolean}> & {readonly args:S;readonly cancelResult:"cancelled"}): QueryMethod<Infer<S>, {readonly cancelled:boolean}>;
export function sqlMethod<A = null>(name: string, spec: SqlMethodSpec<A, "cancel", {readonly cancelled:boolean}> & {readonly cancelResult:"cancelled"}): QueryMethod<A, {readonly cancelled:boolean}>;
export function sqlMethod<S extends SchemaLike<any>, O extends SqlOperation, V = SqlPublicResult<O>>(name: string, spec: SqlMethodSpec<Infer<S>, O, V> & {readonly args: S}): QueryMethod<Infer<S>, V>;
export function sqlMethod<A = null, O extends SqlOperation = "query", V = SqlPublicResult<O>>(name: string, spec: SqlMethodSpec<A, O, V>): QueryMethod<A, V>;
/** Dedicated terminal SQL alias. No ordinary query/ctx.sql execution fallback. */
export function sqlMethod(name: string, spec: SqlMethodSpec<any, SqlOperation, any>): QueryMethod<any, any> {
  requireName(name, "SQL method name");
  const settings = plainObject(spec, "Terminal SQL method", ["catalog", "operation", "cancelResult", "args", "access", "plan", "finalize", "signingKeys"]);
  const declaration = sqlDeclaration(settings.catalog as SqlCatalog);
  if (!["query", "explain", "catalog", "cancel"].includes(settings.operation as string)) throw new TypeError("SQL operation must be query, explain, catalog or cancel");
  if (settings.plan !== undefined && typeof settings.plan !== "function") throw new TypeError("SQL plan must be a readless function");
  if (settings.finalize !== undefined && typeof settings.finalize !== "function") throw new TypeError("SQL finalize must be a readless function");
  if (settings.signingKeys !== undefined && (!Array.isArray(settings.signingKeys) || settings.signingKeys.length > 8)) throw new TypeError("SQL signingKeys requires at most eight declared keys");
  const signingKeys = keyManifest((settings.signingKeys ?? []) as readonly ManagedKey[]);
  if (signingKeys.length && settings.finalize === undefined) throw new TypeError("SQL signingKeys require a finalizer");
  if (signingKeys.some((key) => !key.usages.includes("sign"))) throw new TypeError("SQL signingKeys require signing usage");
  const operation = settings.operation as SqlOperation;
  if (settings.cancelResult !== undefined && (operation !== "cancel" || !["boolean", "cancelled"].includes(settings.cancelResult as string))) throw new TypeError("SQL cancelResult is only boolean or cancelled on a cancellation method");
  if (operation === "cancel" && signingKeys.length) throw new TypeError("SQL cancellation cannot declare signing keys");
  if (operation === "cancel" && settings.finalize !== undefined) throw new TypeError("SQL cancellation uses closed native formatting and cannot declare a finalizer");
  const plan = settings.plan as SqlMethodSpec<any, SqlOperation>["plan"];
  const finalize = settings.finalize as ((ctx: SqlFinishContext, execution: SqlOperationResult<SqlOperation>, metadata: SqlFinishMetadata) => unknown) | undefined;
  const underlying = query(name, {args: settings.args as SchemaLike<any> | undefined, access: settings.access as Access<any> | undefined, cache: false, watch: false}, (ctx, args) => {
    const request = plan ? plan(ctx.principal(), args) : {input: (args ?? null) as SqlTerminalRequest["input"], purpose: null};
    plainObject(request, "SQL terminal request", ["input", "purpose"]);
    if (!Object.hasOwn(request, "input") || !Object.hasOwn(request, "purpose")) fail("SQL_INPUT_INVALID", "Terminal request requires input and purpose");
    return request;
  });
  const finalizer = Object.freeze({kind: "sqlFinalizer" as const, name: `${name}.$sql.finalize`, compute(_host: unknown, input: SqlFinishInput) {
    if (operation === "cancel") fail("SQL_CANCEL_NATIVE_ONLY", "Cancellation uses closed native formatting");
    // These values come only from the native fresh-finish binding. This adapter
    // deliberately never binds a database host or supplies source getters.
    const native = input?.binding;
    if (!native || typeof native !== "object" || !Object.hasOwn(native, "validUntil")
      || !Number.isSafeInteger(native.clock) || native.clock < 0
      || (native.validUntil !== null && (typeof native.validUntil !== "number"
        || !Number.isSafeInteger(native.validUntil) || native.validUntil <= native.clock))) {
      fail("SQL_NATIVE_BINDING_INVALID", "SQL_NATIVE_BINDING_INVALID");
    }
    // Shape validation is not JWT/source/runtime verification. Only the native
    // producer may issue null after a healthy completed permission callback.
    const binding = Object.freeze({...native});
    const ctx: SqlFinishContext = Object.freeze({
      principal: () => binding.principal, clock: () => binding.clock,
      history: () => binding.history, codeVersion: () => binding.codeVersion, binding,
    });
    const execution = (operation === "query" ? {result: input.result, provenance: input.provenance} : input.result) as SqlOperationResult<SqlOperation>;
    const metadata = Object.freeze({...binding, request: input.request});
    return finalize ? finalize(ctx, execution, metadata) : input.result;
  }});
  infos.set(underlying, {catalog: settings.catalog as SqlCatalog, terminal: Object.freeze({catalog: declaration.manifest.name, operation, ...(settings.cancelResult !== undefined ? {cancelResult: settings.cancelResult as SqlCancelResultShape} : {}), finalizer: finalizer.name, signingKeys: Object.freeze(signingKeys)}), finalizer});
  return underlying as unknown as QueryMethod<any, any>;
}
/** SDK internals; declarations only, no method selected by client input. */
export function sqlMethodInfo(method: object): Info | undefined {return infos.get(method)}
