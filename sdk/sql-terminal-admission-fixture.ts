// Real bundled-VM admission fixture. Neither SQL nor plan execution is emulated.
import { collection, define, sqlCatalog, sqlMethod, sqlTable, v } from "./index.ts";
const source = collection("terminal.admission.source");
const catalog = sqlCatalog({name:"admission",version:"1",tables:[sqlTable({name:"notes",source,columns:[{name:"id",type:"text",sourceKey:true}],project:()=>({rows:[]})})],authorize:()=>null});
const run = sqlMethod("terminal.admission.run", {catalog,operation:"query",args:v.object({sql:v.string()}),plan:()=>{throw new Error("PLAN_MUST_NOT_EXECUTE")}});
export default define({sql:[catalog],http:{run}});
