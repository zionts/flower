// Native component test fixture builder. Compiled BEFORE original job admission.
// The provider adapter is the UNMODIFIED actual sdk/sql.ts implementation.
import { buildSync } from "esbuild";
import { resolve } from "node:path";
const root=resolve(process.argv[2]);
const source=`
import { collection } from ${JSON.stringify(`${root}/sdk/core.ts`)};
import { v } from ${JSON.stringify(`${root}/sdk/schema.ts`)};
import { sqlMethod, sqlMethodInfo } from ${JSON.stringify(`${root}/sdk/sql-method.ts`)};
import { sqlTable, sqlCatalog, sqlDeclaration } from ${JSON.stringify(`${root}/sdk/sql.ts`)};
const source=collection("members").key(v.tuple([v.string(),v.string()]));
const parse=JSON.parse; let parsed=0;
JSON.parse=function(input){if(typeof input!=="string")throw new Error("SQL_FIXTURE_ENCODED_KEY_REQUIRED");parsed++;return parse(input)};
const table=sqlTable({name:"members",source,columns:[{name:"amount",type:"integer"}],project(ctx,batch){
 if(batch.rows.length!==2 || parsed!==2 || ctx.principal().subject!=="alice" || batch.rows.some(row=>!Array.isArray(row.key)||row.key.length!==2||row.key[1]!=="alice"))throw new Error("SQL_FIXTURE_NATIVE_BATCH_INVALID");
 return {rows:batch.rows.map((row,sourceRow)=>({sourceRow,cells:[{integer:String(row.value.amount)}]})),provenance:[{parsed}]};
}});
const catalog=sqlCatalog({name:"capture",version:"catalog-v1",tables:[table],authorize:()=>null});
const method=sqlMethod("capture.run",{catalog,operation:"query",finalize(ctx,execution,metadata){return {until:metadata.validUntil,sourceRevision:metadata.sourceRevision,clock:ctx.clock(),invoker:metadata.invoker.subject,principal:ctx.principal().subject,provenance:execution.provenance.length,get:typeof ctx.get}}});
const finalizer=sqlMethodInfo(method).finalizer;
const definitions=Object.fromEntries([...sqlDeclaration(catalog).definitions,finalizer].map(definition=>[definition.name,definition]));
globalThis.__flowerBundle={default:{definitions,http:{}}};
`;
const built=buildSync({stdin:{contents:source,resolveDir:root,sourcefile:"sql-native-provider-fixture.ts",loader:"ts"},bundle:true,format:"iife",platform:"neutral",target:"es2023",write:false,logLevel:"silent"});
process.stdout.write("/* flower:static-init */"+built.outputFiles[0].text);
