import assert from "node:assert/strict";
import { test } from "node:test";
import { collection, define, key, sqlCatalog, sqlMethod, sqlTable, v, type Principal, type QueryMethod, type SqlCancelResultShape, type SqlMethodSpec, type SqlFinishBinding, type SqlQueryInput } from "./index.ts";
import { sqlMethodInfo } from "./sql-method.ts";
import { testDatabase } from "./testing.ts";
const source=collection("terminal.source");
const catalog=sqlCatalog({name:"terminal",version:"1",tables:[sqlTable({name:"notes",source,columns:[{name:"id",type:"text",sourceKey:true}],project:()=>({rows:[]})})],authorize:()=>null});
const signer=key("terminal.signer",{algorithm:"HS256",usages:["sign"]});
const binding:SqlFinishBinding={invoker:{subject:"caller"},principal:{subject:"effective"},clock:1000,history:{database:"database",incarnation:"incarnation"},codeVersion:"code",catalogVersion:"1",authorityContext:{verified:true},sourceRevision:10,partition:{name:"org",epoch:2}};

test("terminal SQL factory forces immutable metadata and preserves compiled access/argument policy",()=>{
 const run=sqlMethod("terminal.run",{catalog,operation:"query",args:v.object({sql:v.string()}),access:"authenticated",plan:(invoker,args)=>({input:args,purpose:{caller:invoker?.subject??null}}),signingKeys:[signer],finalize:(ctx,execution,meta)=>({result:execution.result,subject:ctx.principal().subject,request:meta.request.input})});
 const app=define({sql:[catalog],http:{run},auth:{authenticate:()=>({subject:"caller"})}});
 assert.deepEqual(app.http.run,{name:"terminal.run",kind:"query",cache:false,watch:false,terminal:{catalog:"terminal",operation:"query",finalizer:"terminal.run.$sql.finalize",signingKeys:[signer]}});
 assert.equal(app.definitions["terminal.run.$sql.finalize"].kind,"sqlFinalizer");
 assert.equal(app.definitions["$flower.authorize"].kind,"queryMethod");
 assert.ok(app.keys?.some(key=>key.name===signer.name));
 assert.throws(()=>define({http:{run},auth:{authenticate:()=>({subject:"caller"})}}),/explicitly registered/);
 const plan=run.compute({principal:()=>({subject:"actual"})} as never,{sql:"SELECT id FROM notes"}) as any;
 assert.equal(plan.purpose.caller,"actual");
 assert.deepEqual(plan.input,{sql:"SELECT id FROM notes"});
});

test("terminal finalizer adapter is readless and uses three-argument trusted binding",()=>{
 let seen:unknown;
 const run=sqlMethod<SqlQueryInput,"query",string>("terminal.signed",{catalog,operation:"query",signingKeys:[signer],finalize:(ctx,execution,metadata)=>{
   assert.equal((ctx as any).get,undefined);assert.equal((ctx as any).sql,undefined);assert.equal((ctx as any).now,undefined);
   assert.ok(Object.isFrozen(ctx));
   assert.equal(ctx.principal().subject,"effective");assert.equal(ctx.history()?.database,"database");assert.equal(ctx.codeVersion(),"code");assert.equal(ctx.clock(),1000);
   seen={execution,metadata};return "signed";
 }});
 const input={request:{input:{sql:"SELECT 1"},purpose:null},result:{columns:[],rows:[],resultTruncated:false,warnings:[],catalogVersion:"1"},provenance:[{trusted:true}],binding};
 const info=sqlMethodInfo(run)!;
 assert.equal(info.finalizer.compute(null,input),"signed");
 assert.deepEqual(seen,{execution:{result:input.result,provenance:input.provenance},metadata:{...binding,request:input.request}});
 const plain=sqlMethod("terminal.public",{catalog,operation:"query"});
 assert.deepEqual(sqlMethodInfo(plain)!.finalizer.compute(null,input),input.result);
});

test("terminal SQL refuses absent native runtime rather than expose its plan through testDatabase",async()=>{
 const run=sqlMethod("terminal.query",{catalog,operation:"query"});
 const db=await testDatabase(define({sql:[catalog],http:{run}}));
 assert.throws(()=>db.query("run"),error=>typeof error==="object"&&error!==null&&String(error).includes("native detached capture"));
});

test("terminal SQL settings are default-deny and signing-key limited",()=>{
 assert.throws(()=>sqlMethod("x",{catalog,operation:"bad" as never}),/operation/);
 assert.throws(()=>sqlMethod("x",{catalog,operation:"query",cache:true} as never),/does not accept/);
 assert.throws(()=>sqlMethod("x",{catalog,operation:"query",signingKeys:[signer]}),/require a finalizer/);
 assert.throws(()=>sqlMethod("x",{catalog,operation:"cancel",finalize:()=>true,signingKeys:[signer]} as never),/cancellation cannot declare signing keys/);
 assert.throws(()=>sqlMethod("x",{catalog,operation:"cancel",finalize:()=>true} as never),/closed native formatting/);
 const cancel=sqlMethod("terminal.cancel",{catalog,operation:"cancel"});
 assert.equal(sqlMethodInfo(cancel)?.terminal.operation,"cancel");
 const wrapped=sqlMethod("terminal.cancelWrapped",{catalog,operation:"cancel",cancelResult:"cancelled"});
 assert.equal(sqlMethodInfo(wrapped)?.terminal.cancelResult,"cancelled");
 assert.throws(()=>sqlMethod("x",{catalog,operation:"query",cancelResult:"cancelled"} as never),/cancelResult/);
 assert.throws(()=>sqlMethod("x",{catalog,operation:"cancel",cancelResult:"user-chosen"} as never),/cancelResult/);
 assert.deepEqual(sqlMethodInfo(cancel)?.terminal.signingKeys,[]);
 assert.throws(()=>sqlMethod("x",{catalog,operation:"query",finalize:()=>null,signingKeys:[key("n",{algorithm:"HS256",usages:["verify"]})]}),/signing usage/);
});


test("terminal native refusal follows real authentication, access and schema without executing callbacks",async()=>{
 let plans=0,finalizers=0,accesses=0;
 const run=sqlMethod("terminal.admitted",{catalog,operation:"query",access:"authenticated",args:v.object({sql:v.string()}),plan:()=>{plans++;return {input:{sql:"SELECT 1"},purpose:null}},finalize:()=>{finalizers++;return null}});
 const guarded=sqlMethod("terminal.guarded",{catalog,operation:"query",access:(_ctx,principal)=>{accesses++;return principal?.subject==="allowed"},args:v.object({sql:v.string()})});
 const db=await testDatabase(define({sql:[catalog],http:{run,guarded},auth:{authenticate:(_ctx,credential)=>typeof credential==="string"&&["allowed","blocked"].includes(credential)?{subject:credential}:null}}));
 const rejected=(status:number,code:string)=>(error:unknown)=>typeof error==="object"&&error!==null&&(error as any).status===status&&(error as any).failure?.code===code;
 assert.throws(()=>db.query("run",{sql:"SELECT 1"}),rejected(403,"UNAUTHENTICATED"));
 assert.throws(()=>db.query("guarded",{sql:"SELECT 1"},{credentials:"blocked"}),rejected(403,"FORBIDDEN"));
 assert.throws(()=>db.query("run",{sql:1} as never,{credentials:"allowed"}),rejected(422,"INVALID_ARGUMENT"));
 assert.throws(()=>db.query("run",{sql:"SELECT 1"},{credentials:"allowed"}),rejected(422,"SQL_UNAVAILABLE"));
 assert.equal(accesses,1);assert.equal(plans,0);assert.equal(finalizers,0);
});

test("bundled terminal argument guard crosses VM realm without evaluating its plan",async()=>{
 const db=await testDatabase(new URL("./sql-terminal-admission-fixture.ts",import.meta.url).pathname);
 assert.throws(()=>db.query("run",{sql:1} as never),error=>(error as any)?.failure?.code==="INVALID_ARGUMENT");
 assert.throws(()=>db.query("run",{sql:"SELECT 1"} as never),error=>(error as any)?.failure?.code==="SQL_UNAVAILABLE");
});


test("closed cancellation shape preserves schema inference without guest finalization",()=>{
 const shape:SqlCancelResultShape="cancelled";
 const wrapped:QueryMethod<{queryId:string},{readonly cancelled:boolean}>=sqlMethod("terminal.typedCancel",{catalog,operation:"cancel",cancelResult:shape,args:v.object({queryId:v.string()})});
 const plain:QueryMethod<null,boolean>=sqlMethod("terminal.typedBoolean",{catalog,operation:"cancel"});
 const explicit:QueryMethod<null,boolean>=sqlMethod("terminal.typedExplicit",{catalog,operation:"cancel",cancelResult:"boolean"});
 const app=define({sql:[catalog],http:{wrapped,plain,explicit}});
 assert.equal(app.http.wrapped.terminal?.cancelResult,"cancelled");
 assert.equal(app.http.plain.terminal?.cancelResult,undefined);
 assert.equal(app.http.explicit.terminal?.cancelResult,"boolean");
 assert.throws(()=>sqlMethodInfo(wrapped)!.finalizer.compute(null,{request:{input:{queryId:"ephemeral"},purpose:null},result:true,provenance:[],binding}),error=>(error as any)?.failure?.code==="SQL_CANCEL_NATIVE_ONLY"||String(error).includes("closed native formatting"));
});

// Compile-time contracts are checked by npm run typecheck; never executed.
function closedCancellationTypes() {
 // @ts-expect-error Cancellation has no application finalizer.
 const callback:SqlMethodSpec<null,"cancel">={catalog,operation:"cancel",finalize:()=>true};
 // @ts-expect-error Cancellation has no signing capability.
 const signing:SqlMethodSpec<null,"cancel">={catalog,operation:"cancel",signingKeys:[signer]};
 // @ts-expect-error Non-cancel operations cannot choose cancellation formatting.
 const query:SqlMethodSpec<null,"query">={catalog,operation:"query",cancelResult:"cancelled"};
 return [callback,signing,query];
}
