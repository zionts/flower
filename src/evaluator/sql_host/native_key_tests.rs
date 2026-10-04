//! Actual SDK read manifest frozen from Ultimator main144c1a8d966e2f3577f952301ade24da675b61e8.
//! Backend edcb1909a356bfdc233e40b3d0bfd8702fbfa182 has IDENTICAL collection ACLs.
//! Exact read/field-read trees are retained, not replaced by public/allowed flags.
//! Nonread writes/reference/index metadata are omitted only from the full read
//! inventory; selected positive fixtures below retain COMPLETE stored policies.
//! All Value/Vec/JSON/reference setup is outside post-admission observations.
use super::super::super::sql_frame::{ColumnKind, FrameCell, FrameColumn};
use super::super::super::sql_policy::{CapturedSupportRow, PolicyEngine, VerifiedPrincipal};
use super::*;

#[cfg(sql_host_harness)]
const FROZEN_READ_MANIFEST: &str = r###"[{"name":"accessRequests","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"accountFences","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]},{"all":[{"not":{"exists":{"ref":["principal","tenant"]}}},{"readable":["superadmins",{"ref":["principal","subject"]}]}]},{"all":[{"in":[{"ref":["principal","claims","transaction"]},{"value":["token.exchange","account.revokeEverywhere","account.deleteEverywhere"]}]},{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]}]}]}}},{"name":"accountRecipients","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","subject"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"accountSessionGrants","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]}}},{"name":"accountSignIns","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]}]}}},{"name":"accountWorkflowGrants","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["row","grant","subject"]},{"ref":["principal","subject"]}]}]}}},{"name":"accounts","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]},"fields":{"userHandle":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]}]}},"invite":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}},"github":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]}]}}}}},{"name":"activityCells","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"activityPacks","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"addressPlace","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"agents","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["key","1"]},{"value":"org"}]},{"startsWith":[{"ref":["key","1"]},{"value":"scope:"}]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","updatedBy"]},{"ref":["principal","subject"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"startsWith":[{"ref":["key","1"]},{"value":"role:"}]},{"readable":["roleHolders",{"ref":["key","1"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"prompt":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["key","1"]},{"value":"org"}]},{"startsWith":[{"ref":["key","1"]},{"value":"scope:"}]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","updatedBy"]},{"ref":["principal","subject"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"startsWith":[{"ref":["key","1"]},{"value":"role:"}]},{"readable":["roleHolders",{"ref":["key","1"]}]}]}]}}}}},{"name":"approvalRequests","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"input":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}},"context":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}}}},{"name":"auditLog","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"autoMergePrefs","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"autoMergeRepos","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"autoMerges","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"autoResolveRepos","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"autoResolves","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"auxiliarySpends","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"avatarImages","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]}}},{"name":"backfills","access":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}},{"name":"billing","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]}]}}},{"name":"bindings","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"blobRefs","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"bookStates","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]}]}}},{"name":"ceremonies","access":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}},{"name":"chargeTotals","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"cliLogins","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"exists":{"ref":["row","approved"]}}},{"eq":[{"ref":["row","approved","subject"]},{"ref":["principal","subject"]}]}]}]}]},"fields":{"digest":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}}}},{"name":"clusterActions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","requestedBy"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"clusterSnapshots","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]},"fields":{"flowerUrl":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}},"problem":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}},"layout":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}},"health":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}},"cells":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}},"directory":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}}}},{"name":"codeReviews","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"completions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"readable":["sessions",{"ref":["row","payload","session"]}]}]}}},{"name":"computerRelays","access":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}},{"name":"computers","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"computer"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","id"]},{"ref":["principal","claims","computer"]}]}]}]}}},{"name":"confirmations","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"credentials","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]}]}}},{"name":"deletedAccounts","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"dependencies","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"deploySources","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]}}},{"name":"deploys","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]}}},{"name":"drafts","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"environmentSecrets","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]},"fields":{"value":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["sandbox","operator"]}]}}}}},{"name":"environments","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"computer"}]},{"eq":[{"ref":["principal","claims","use"]},{"value":"uplink"}]},{"exists":{"ref":["principal","claims","computer"]}},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"events","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"evergreenSessions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"explainSources","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"explainSpends","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"feeDefaults","access":{"read":{"const":true}}},{"name":"followChoices","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]}]}}},{"name":"followings","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["row","private"]},{"value":true}]}},{"all":[{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]},{"not":{"exists":{"ref":["row","roles"]}}}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","invited","reach"]}]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"formerOrgs","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"githubApps","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]},"fields":{"clientSecret":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","service","operator"]}]}},"webhookSecret":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","operator"]}]}},"privateKey":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","service","operator"]}]}}}}},{"name":"githubInstalls","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"githubRoutes","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"githubUsers","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]}]},"fields":{"tokens":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","service","operator"]}]}}}}},{"name":"glossSources","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"grants","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"computer"}]},{"eq":[{"ref":["principal","claims","use"]},{"value":"uplink"}]},{"exists":{"ref":["principal","claims","computer"]}},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"hourTotals","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"integrationSettings","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"computer"}]},{"eq":[{"ref":["principal","claims","use"]},{"value":"uplink"}]},{"exists":{"ref":["principal","claims","computer"]}},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"invites","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"exists":{"ref":["row","createdBy"]}}]}]}}},{"name":"journal","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"judges","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"readable":["sessions",{"ref":["row","payload","session"]}]}]}}},{"name":"judgments","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["row","payload","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"labels","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","owner"]},{"value":"org"}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"description":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","owner"]},{"value":"org"}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}]}]}}}}},{"name":"ledgerIntents","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"linearApps","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]},"fields":{"clientSecret":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","service","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}},"webhookSecret":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}}}},{"name":"listings","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["row","private"]},{"value":true}]}},{"all":[{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]},{"not":{"exists":{"ref":["row","roles"]}}}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","invited","reach"]}]}]}]}]}}},{"name":"liveReplies","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["row","session"]}]}]}}},{"name":"llmEnvironment","access":{"read":{"const":true}}},{"name":"machines","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"computer"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","id"]},{"ref":["principal","claims","computer"]}]}]}]},"fields":{"credential":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["yas","operator","gateway"]}]}}}}},{"name":"mcpClients","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"clientSecret":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}}}},{"name":"mcpConnections","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"tokens":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["service","operator"]}]}}}}},{"name":"mcpRefreshes","access":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}},{"name":"mcpServers","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"headers":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}}}},{"name":"members","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"exists":{"ref":["principal","claims","transaction"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"memories","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["key","1"]},{"value":"org"}]},{"startsWith":[{"ref":["key","1"]},{"value":"scope:"}]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","updatedBy"]},{"ref":["principal","subject"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"startsWith":[{"ref":["key","1"]},{"value":"role:"}]},{"readable":["roleHolders",{"ref":["key","1"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"content":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["key","1"]},{"value":"org"}]},{"startsWith":[{"ref":["key","1"]},{"value":"scope:"}]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","updatedBy"]},{"ref":["principal","subject"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"startsWith":[{"ref":["key","1"]},{"value":"role:"}]},{"readable":["roleHolders",{"ref":["key","1"]}]}]}]}}}}},{"name":"memoryChanges","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["key","1"]},{"value":"org"}]},{"startsWith":[{"ref":["key","1"]},{"value":"scope:"}]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","by"]},{"ref":["principal","subject"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"startsWith":[{"ref":["key","1"]},{"value":"role:"}]},{"readable":["roleHolders",{"ref":["key","1"]}]}]}]}}},{"name":"memoryReads","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"mentions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]}]}}},{"name":"messageSummarySources","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"messageSummarySpends","access":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}},{"name":"meterOperations","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]}]}}},{"name":"moduleSettings","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"noticeDecisions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"noticeInstructions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"noticeNews","access":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}},{"name":"notices","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","subject"]}]}]}}},{"name":"orgAdmins","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key"]},{"ref":["principal","claims","org"]}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","admins"]}]}]}]}}},{"name":"orgMoves","access":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}},{"name":"orgPictureReaders","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","subjects"]}]}]}]}}},{"name":"orgPictures","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"not":{"exists":{"ref":["principal","tenant"]}}},{"readable":["orgPictureReaders",{"ref":["key"]}]}]}]}}},{"name":"orgs","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"computer"}]},{"eq":[{"ref":["key"]},{"ref":["principal","claims","org"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]}]},"fields":{"settings":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key"]},{"ref":["principal","claims","org"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]}]}}}}},{"name":"outbound","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"readable":["sessions",{"ref":["row","payload","session"]}]}]}}},{"name":"partialHeads","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key"]}]}]}}},{"name":"partials","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"passkeys","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"passwords","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]}]},"fields":{"digest":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}}}},{"name":"personalLabels","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"previewCodes","access":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}},{"name":"previewGrants","access":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}},{"name":"previews","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"readable":["sessions",{"ref":["row","session"]}]}]}]}}},{"name":"provision","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]}]}}},{"name":"pullMirror","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"pullMirrorAsks","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"pullMirrorStates","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"pullMirrorViews","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"pullMirrors","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","payload","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","payload","kind"]},{"value":"list"}]}]}]}}},{"name":"pullSyncs","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["row","payload","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"pulls","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"pushDevices","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","subject"]}]}]}}},{"name":"pushPrefs","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","subject"]}]}]}}},{"name":"pushes","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"readable":["sessions",{"ref":["row","payload","session"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","payload","subject"]},{"ref":["principal","subject"]}]},{"not":{"exists":{"ref":["row","payload","session"]}}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","payload","request","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"repoAgents","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"prompt":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]}}}}},{"name":"repoWorkflows","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"reportVersions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["reports",{"ref":["key","0"]}]}]}}},{"name":"reports","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["row","private"]},{"value":true}]}},{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","reach"]}]}]}]}]}}},{"name":"requests","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"reviewNoteRecoveries","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"reviewPrefs","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"reviewRepos","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"reviews","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"readable":["sessions",{"ref":["row","payload","session"]}]}]}}},{"name":"roleHolders","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","members"]}]}]}]}}},{"name":"roleSessions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"roles","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"computer"}]},{"eq":[{"ref":["principal","claims","use"]},{"value":"uplink"}]},{"exists":{"ref":["principal","claims","computer"]}},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"rootTotals","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"rumDays","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"rumErrorAcks","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"rumErrors","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"rumHours","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"rumOrgDays","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"readable":["orgAdmins",{"ref":["principal","claims","org"]}]}]}]}}},{"name":"rumOrgErrorAcks","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"readable":["orgAdmins",{"ref":["principal","claims","org"]}]}]}]}}},{"name":"rumOrgErrors","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"readable":["orgAdmins",{"ref":["principal","claims","org"]}]}]}]}}},{"name":"rumOrgHours","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"readable":["orgAdmins",{"ref":["principal","claims","org"]}]}]}]}}},{"name":"rumPages","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"readable":["orgAdmins",{"ref":["principal","claims","org"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","user"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"rumUserDays","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"rumUserErrorAcks","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"rumUserErrors","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"rumUserHours","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"sandboxHosts","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]}]}}},{"name":"sandboxes","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"computer"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","id"]},{"ref":["principal","claims","computer"]}]}]}]}}},{"name":"scopeSpend","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"scopes","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"instructions":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}}}},{"name":"sealedMessages","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"sealing","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"readable":["sessions",{"ref":["row","payload","session"]}]}]}}},{"name":"secrets","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]},{"eq":[{"ref":["key","1"]},{"value":"org"}]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"eq":[{"ref":["principal","claims","transaction"]},{"value":"superadmin.org.remove"}]}]},"fields":{"value":{"read":{"any":[{"eq":[{"ref":["principal","claims","role"]},{"value":"operator"}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["service","gateway"]}]},{"not":{"in":[{"ref":["key","2"]},{"value":["ANTHROPIC_API_KEY","AWS_BEARER_TOKEN_BEDROCK","AWS_REGION","GOOGLE_VERTEX_CREDENTIALS","VERTEX_REGION","OPENAI_API_KEY","OPENROUTER_API_KEY","MOONSHOT_API_KEY","E2B_API_KEY","TENSORLAKE_API_KEY"]}]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"llm"}]},{"eq":[{"ref":["key","1"]},{"value":"org"}]},{"in":[{"ref":["key","2"]},{"value":["ANTHROPIC_API_KEY","AWS_BEARER_TOKEN_BEDROCK","AWS_REGION","GOOGLE_VERTEX_CREDENTIALS","VERTEX_REGION","OPENAI_API_KEY","OPENROUTER_API_KEY","MOONSHOT_API_KEY"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"sandbox"}]},{"eq":[{"ref":["key","1"]},{"value":"org"}]},{"in":[{"ref":["key","2"]},{"value":["E2B_API_KEY","TENSORLAKE_API_KEY"]}]}]}]}},"digest":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]},{"eq":[{"ref":["key","1"]},{"value":"org"}]}]}]}]}}}}},{"name":"seen","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]}]}}},{"name":"segments","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"sessionPrompts","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key"]}]}]}}},{"name":"sessionTotals","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"sessions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["row","private"]},{"value":true}]}},{"all":[{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]},{"not":{"exists":{"ref":["row","roles"]}}}]},{"all":[{"in":[{"ref":["principal","subject"]},{"ref":["row","invited","reach"]}]}]}]}]},{"all":[{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","overseers"]}]}]}]}}},{"name":"singletons","access":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}},{"name":"site","access":{"read":{"const":true}}},{"name":"skillFiles","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["key","1"]},{"value":"org"}]},{"startsWith":[{"ref":["key","1"]},{"value":"scope:"}]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","updatedBy"]},{"ref":["principal","subject"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"startsWith":[{"ref":["key","1"]},{"value":"role:"}]},{"readable":["roleHolders",{"ref":["key","1"]}]}]}]}}},{"name":"skills","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["key","1"]},{"value":"org"}]},{"startsWith":[{"ref":["key","1"]},{"value":"scope:"}]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","updatedBy"]},{"ref":["principal","subject"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"startsWith":[{"ref":["key","1"]},{"value":"role:"}]},{"readable":["roleHolders",{"ref":["key","1"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"description":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["key","1"]},{"value":"org"}]},{"startsWith":[{"ref":["key","1"]},{"value":"scope:"}]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","updatedBy"]},{"ref":["principal","subject"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"startsWith":[{"ref":["key","1"]},{"value":"role:"}]},{"readable":["roleHolders",{"ref":["key","1"]}]}]}]}},"files":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["key","1"]},{"value":"org"}]},{"startsWith":[{"ref":["key","1"]},{"value":"scope:"}]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","updatedBy"]},{"ref":["principal","subject"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"startsWith":[{"ref":["key","1"]},{"value":"role:"}]},{"readable":["roleHolders",{"ref":["key","1"]}]}]}]}}}}},{"name":"slackChannels","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"slackInstalls","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]},"fields":{"token":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["slack","gateway","operator"]}]}}}}},{"name":"slackLinks","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"slackMessages","access":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}},{"name":"slackPictures","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"slackRoutes","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"stripeRoutes","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"subscriptions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"tokens":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","operator"]}]}}}}},{"name":"subsessions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"superadminLog","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"superadmins","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]}}},{"name":"surfaceInstalls","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]},"fields":{"credential":{"read":{"any":[{"eq":[{"ref":["principal","claims","role"]},{"value":"operator"}]},{"all":[{"eq":[{"ref":["row","surface"]},{"value":"slack"}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"slack"}]}]},{"all":[{"eq":[{"ref":["row","surface"]},{"value":"github"}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"service"}]}]},{"all":[{"eq":[{"ref":["row","surface"]},{"value":"linear"}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"service"}]}]},{"all":[{"eq":[{"ref":["row","surface"]},{"value":"example"}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"service"}]}]},{"all":[{"eq":[{"ref":["row","surface"]},{"value":"example-agent"}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"service"}]}]}]}},"refresh":{"read":{"any":[{"eq":[{"ref":["principal","claims","role"]},{"value":"operator"}]},{"all":[{"eq":[{"ref":["row","surface"]},{"value":"slack"}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"slack"}]}]},{"all":[{"eq":[{"ref":["row","surface"]},{"value":"github"}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"service"}]}]},{"all":[{"eq":[{"ref":["row","surface"]},{"value":"linear"}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"service"}]}]},{"all":[{"eq":[{"ref":["row","surface"]},{"value":"example"}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"service"}]}]},{"all":[{"eq":[{"ref":["row","surface"]},{"value":"example-agent"}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"service"}]}]}]}}}}},{"name":"surfaceLinks","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"surfaceMessages","access":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}},{"name":"surfacePlaces","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"surfaceRoutes","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}},{"name":"teamInvites","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"teamMembers","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"teamSpreads","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]}}},{"name":"teams","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"description":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}}}},{"name":"titleSources","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key"]}]}]}}},{"name":"toolJobs","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"readable":["sessions",{"ref":["row","payload","session"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"exists":{"ref":["row","payload","owner"]}},{"eq":[{"ref":["row","payload","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"transcripts","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["key","0"]}]}]}}},{"name":"uplinkKeys","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"uplinkTokens","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]}]},"fields":{"digest":{"read":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}}}},{"name":"uplinks","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"usage","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}},{"name":"waiting","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]}]}]}}},{"name":"workflowDrafts","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"description":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]}]}]}}}}},{"name":"workflowExceptions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"message":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}},"details":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}}}},{"name":"workflowRuns","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"inputs":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}},"output":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}}}},{"name":"workflowSteps","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"output":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}},"files":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}}}},{"name":"workflowTriggers","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"inputs":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}},"tokenDigest":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}}}},{"name":"workflowVersions","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"definition":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}}}},{"name":"workflows","access":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"description":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}}}}]"###;

const ACCOUNTS_POLICY: &str = r###"{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]},"insert":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},"update":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]},{"eq":[{"ref":["next","subject"]},{"ref":["principal","subject"]}]}]},{"all":[{"readable":["superadmins",{"ref":["principal","subject"]}]},{"eq":[{"ref":["next","subject"]},{"ref":["key"]}]}]}]},"delete":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]},"fields":{"userHandle":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]}]}},"invite":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}},"github":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]}]}}}}"###;

const SESSIONS_POLICY: &str = r###"{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["row","private"]},{"value":true}]}},{"all":[{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]},{"not":{"exists":{"ref":["row","roles"]}}}]},{"all":[{"in":[{"ref":["principal","subject"]},{"ref":["row","invited","reach"]}]}]}]}]},{"all":[{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","overseers"]}]}]}]},"insert":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["next","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["next","private"]},{"value":true}]}},{"all":[{"eq":[{"ref":["next","createdBy"]},{"ref":["principal","subject"]}]},{"not":{"exists":{"ref":["next","roles"]}}}]},{"all":[{"in":[{"ref":["principal","subject"]},{"ref":["next","invited","reach"]}]},{"not":{"in":[{"ref":["principal","subject"]},{"ref":["next","invited","viewing"]}]}}]}]}]}]},"update":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["row","private"]},{"value":true}]}},{"all":[{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]},{"not":{"exists":{"ref":["row","roles"]}}}]},{"all":[{"in":[{"ref":["principal","subject"]},{"ref":["row","invited","reach"]}]},{"not":{"in":[{"ref":["principal","subject"]},{"ref":["row","invited","viewing"]}]}}]}]},{"eq":[{"ref":["next","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["next","private"]},{"value":true}]}},{"all":[{"eq":[{"ref":["next","createdBy"]},{"ref":["principal","subject"]}]},{"not":{"exists":{"ref":["next","roles"]}}}]},{"all":[{"in":[{"ref":["principal","subject"]},{"ref":["next","invited","reach"]}]},{"not":{"in":[{"ref":["principal","subject"]},{"ref":["next","invited","viewing"]}]}}]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","invited","reach"]}]},{"not":{"in":[{"ref":["principal","subject"]},{"ref":["next","invited","reach"]}]}},{"eq":[{"ref":["next","org"]},{"ref":["row","org"]}]},{"eq":[{"ref":["next","createdBy"]},{"ref":["row","createdBy"]}]},{"eq":[{"ref":["next","private"]},{"ref":["row","private"]}]}]}]},"delete":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["row","private"]},{"value":true}]}},{"all":[{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]},{"not":{"exists":{"ref":["row","roles"]}}}]},{"all":[{"in":[{"ref":["principal","subject"]},{"ref":["row","invited","reach"]}]},{"not":{"in":[{"ref":["principal","subject"]},{"ref":["row","invited","viewing"]}]}}]}]}]}]}}"###;

const SUPERADMINS_POLICY: &str = r###"{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]},"insert":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]},"update":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]},"delete":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]}]}}"###;

const MEMBERS_POLICY: &str = r###"{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"exists":{"ref":["principal","claims","transaction"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]},"insert":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"exists":{"ref":["principal","claims","transaction"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]},{"eq":[{"ref":["next","subject"]},{"ref":["key","1"]}]},{"eq":[{"ref":["next","org"]},{"ref":["key","0"]}]}]}]},"update":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"exists":{"ref":["principal","claims","transaction"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["next","subject"]},{"ref":["key","1"]}]},{"eq":[{"ref":["next","org"]},{"ref":["key","0"]}]},{"any":[{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"all":[{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]},{"eq":[{"ref":["next","role"]},{"ref":["row","role"]}]}]}]}]}]},"delete":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"exists":{"ref":["principal","claims","transaction"]}}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]}]}]}]}}"###;

const SCOPES_POLICY: &str = r###"{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"superadmin"}]},{"exists":{"ref":["principal","tenant"]}}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"insert":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["next","org"]},{"ref":["principal","claims","org"]}]},{"any":[{"not":{"eq":[{"ref":["next","personal"]},{"value":true}]}},{"eq":[{"ref":["next","createdBy"]},{"ref":["principal","subject"]}]}]},{"eq":[{"ref":["next","createdBy"]},{"ref":["principal","subject"]}]}]}]},"update":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"any":[{"not":{"eq":[{"ref":["row","personal"]},{"value":true}]}},{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["next","org"]},{"ref":["principal","claims","org"]}]},{"any":[{"not":{"eq":[{"ref":["next","personal"]},{"value":true}]}},{"eq":[{"ref":["next","createdBy"]},{"ref":["principal","subject"]}]}]},{"eq":[{"ref":["next","createdBy"]},{"ref":["row","createdBy"]}]}]}]},"delete":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"any":[{"not":{"eq":[{"ref":["row","personal"]},{"value":true}]}},{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]}]}]}]},"fields":{"instructions":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]}]}]}}}}"###;

const LABELS_POLICY: &str = r###"{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","owner"]},{"value":"org"}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"insert":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["next","org"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["next","owner"]},{"value":"org"}]},{"eq":[{"ref":["next","owner"]},{"ref":["principal","subject"]}]}]},{"eq":[{"ref":["next","createdBy"]},{"ref":["principal","subject"]}]}]}]},"update":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["row","owner"]},{"value":"org"}]},{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["next","org"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["next","owner"]},{"value":"org"}]},{"eq":[{"ref":["next","owner"]},{"ref":["principal","subject"]}]}]},{"eq":[{"ref":["next","owner"]},{"ref":["row","owner"]}]},{"eq":[{"ref":["next","createdBy"]},{"ref":["row","createdBy"]}]}]}]},"delete":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"any":[{"eq":[{"ref":["row","owner"]},{"value":"org"}]},{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"in":[{"ref":["principal","claims","transaction"]},{"value":["superadmin.members.set","superadmin.members.remove","superadmin.org.rename","superadmin.org.remove","superadmin.ledger.post","superadmin.ledger.floor","superadmin.billing.set","superadmin.fee.set","superadmin.fee.default"]}]}]}]},"fields":{"description":{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"in":[{"ref":["principal","claims","role"]},{"value":["user","computer"]}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","owner"]},{"value":"org"}]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key","0"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}]}]}}}}"###;

const REPORTS_POLICY: &str = r###"{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["row","private"]},{"value":true}]}},{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","reach"]}]}]}]}]},"insert":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["next","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["next","private"]},{"value":true}]}},{"eq":[{"ref":["next","createdBy"]},{"ref":["principal","subject"]}]},{"in":[{"ref":["principal","subject"]},{"ref":["next","reach"]}]}]}]}]},"update":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["row","private"]},{"value":true}]}},{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","reach"]}]}]},{"eq":[{"ref":["next","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["next","private"]},{"value":true}]}},{"eq":[{"ref":["next","createdBy"]},{"ref":["principal","subject"]}]},{"in":[{"ref":["principal","subject"]},{"ref":["next","reach"]}]}]}]}]},"delete":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"any":[{"not":{"eq":[{"ref":["row","private"]},{"value":true}]}},{"eq":[{"ref":["row","createdBy"]},{"ref":["principal","subject"]}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","reach"]}]}]}]}]}}"###;

const ORGADMINS_POLICY: &str = r###"{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key"]},{"ref":["principal","claims","org"]}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","admins"]}]}]}]},"insert":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},"update":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},"delete":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}"###;

const ROLEHOLDERS_POLICY: &str = r###"{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"in":[{"ref":["principal","subject"]},{"ref":["row","members"]}]}]}]},"insert":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["next","org"]},{"ref":["principal","claims","org"]}]}]}]},"update":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["next","org"]},{"ref":["principal","claims","org"]}]}]}]},"delete":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["row","org"]},{"ref":["principal","claims","org"]}]}]}]}}"###;

const TOOLJOBS_POLICY: &str = r###"{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["superadmins",{"ref":["principal","subject"]}]},{"readable":["sessions",{"ref":["row","payload","session"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"exists":{"ref":["row","payload","owner"]}},{"eq":[{"ref":["row","payload","org"]},{"ref":["principal","claims","org"]}]}]}]},"insert":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["next","payload","session"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"exists":{"ref":["next","payload","owner"]}},{"eq":[{"ref":["next","payload","org"]},{"ref":["principal","claims","org"]}]}]}]},"update":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"all":[{"any":[{"readable":["sessions",{"ref":["row","payload","session"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"exists":{"ref":["row","payload","owner"]}},{"eq":[{"ref":["row","payload","org"]},{"ref":["principal","claims","org"]}]}]}]},{"any":[{"readable":["sessions",{"ref":["next","payload","session"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"exists":{"ref":["next","payload","owner"]}},{"eq":[{"ref":["next","payload","org"]},{"ref":["principal","claims","org"]}]}]}]}]}]},"delete":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"readable":["sessions",{"ref":["row","payload","session"]}]},{"all":[{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"exists":{"ref":["row","payload","owner"]}},{"eq":[{"ref":["row","payload","org"]},{"ref":["principal","claims","org"]}]}]}]}}"###;

const ACCOUNTSESSIONGRANTS_POLICY: &str = r###"{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["row","subject"]},{"ref":["principal","subject"]}]}]},"insert":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},"update":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},"delete":{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]}}"###;

const ACCOUNTFENCES_POLICY: &str = r###"{"read":{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]},{"all":[{"not":{"exists":{"ref":["principal","tenant"]}}},{"readable":["superadmins",{"ref":["principal","subject"]}]}]},{"all":[{"in":[{"ref":["principal","claims","transaction"]},{"value":["token.exchange","account.revokeEverywhere","account.deleteEverywhere"]}]},{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]}]}]},"insert":{"any":[{"all":[{"not":{"exists":{"ref":["principal","tenant"]}}},{"eq":[{"ref":["principal","claims","role"]},{"value":"gateway"}]},{"eq":[{"ref":["next","generation"]},{"value":0}]},{"not":{"exists":{"ref":["next","disabled"]}}},{"not":{"exists":{"ref":["next","signedOutAt"]}}}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"operator"}]},{"all":[{"in":[{"ref":["principal","claims","transaction"]},{"value":["token.exchange","account.revokeEverywhere","account.deleteEverywhere"]}]},{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]}]}]},"update":{"any":[{"eq":[{"ref":["principal","claims","role"]},{"value":"operator"}]},{"all":[{"not":{"exists":{"ref":["principal","tenant"]}}},{"readable":["superadmins",{"ref":["principal","subject"]}]}]},{"all":[{"not":{"exists":{"ref":["principal","tenant"]}}},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]},{"eq":[{"ref":["key"]},{"ref":["principal","subject"]}]},{"eq":[{"ref":["principal","claims","transaction"]},{"value":"account.delete"}]}]},{"all":[{"in":[{"ref":["principal","claims","transaction"]},{"value":["token.exchange","account.revokeEverywhere","account.deleteEverywhere"]}]},{"any":[{"in":[{"ref":["principal","claims","role"]},{"value":["gateway","llm","slack","service","sandbox","yas","sim","operator"]}]},{"eq":[{"ref":["principal","claims","role"]},{"value":"user"}]}]}]}]},"delete":{"any":[]}}"###;

// Exact compiled collection access of service/authorization/sql_metadata_tests/application.mjs.
pub(super) const METADATA_POLICY: &str = r#"{"read":{"const":true},"insert":{"const":true},"update":{"const":true},"delete":{"eq":[{"ref":["principal","claims","serviceProcess"]},{"value":true}]},"fields":{"sqlSources":{"read":{"eq":[{"ref":["principal","claims","serviceProcess"]},{"value":true}]},"write":{"eq":[{"ref":["principal","claims","serviceProcess"]},{"value":true}]}},"sqlAuthority":{"read":{"eq":[{"ref":["principal","claims","serviceProcess"]},{"value":true}]},"write":{"eq":[{"ref":["principal","claims","serviceProcess"]},{"value":true}]}}}}"#;
pub(super) const ALICE: &str =
    r#"{"subject":"alice","claims":{"role":"user","org":"acme","serviceProcess":false}}"#;

fn bind_principal(f: &mut Fixture, text: &str) {
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let id = capture(&mut f.frame, text, &control);
    f.binding.invoker = id;
    f.binding.principal = id;
}
fn source_args(name: &str) -> Vec<u8> {
    args(&[json!({"kind":"collection","name":name})])
}

#[test]
fn actual_account_acl_redaction_preserves_logical_row_keys_before_provider() {
    let mut f = Fixture::new(ACCOUNTS_POLICY);
    bind_principal(&mut f, ALICE);
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let alice_key = f.frame.retain_key("alice").unwrap();
    let bob_key = f.frame.retain_key("bob").unwrap();
    let alice = capture(
        &mut f.frame,
        r#"{"subject":"alice","name":"Alice","userHandle":"alice-handle","github":"alice-github","invite":"alice-invite"}"#,
        &control,
    );
    let bob = capture(
        &mut f.frame,
        r#"{"subject":"bob","name":"Bob","userHandle":"bob-hidden-handle","github":"bob-hidden-github","invite":"bob-hidden-invite"}"#,
        &control,
    );
    let declaration = capture(
        &mut f.frame,
        r#"{"name":"accounts","jsonKey":false}"#,
        &control,
    );
    let superadmin = capture(&mut f.frame, SUPERADMINS_POLICY, &control);
    let policies = [
        CapturedCollection {
            name: "accounts",
            policy: Some(f.frame.json(f.policy, &control).unwrap()),
        },
        CapturedCollection {
            name: "superadmins",
            policy: Some(f.frame.json(superadmin, &control).unwrap()),
        },
    ];
    let support_rows = [CapturedSupportRow {
        collection: "superadmins",
        key: "alice",
        row: None,
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &support_rows).unwrap();
    let rows = [
        OwnedRow {
            key: alice_key,
            value: Some(alice),
        },
        OwnedRow {
            key: bob_key,
            value: Some(bob),
        },
    ];
    let relations = [OwnedRelation {
        name: "accounts",
        coverage: CaptureCoverage::Complete,
        rows: &rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let mut host = SqlHost::new(
        NativePhase::Provider,
        &mut admitted,
        &f.frame,
        &relations,
        f.binding,
        Some(support),
        &budget,
        native_point(&f.job, NativePhase::Provider, f.binding),
        &mut f.job,
    )
    .unwrap();
    let scan = json_response(host.call_checked("scan", &source_args("accounts")).unwrap());
    assert_eq!(scan[0]["key"], "alice");
    assert_eq!(scan[0]["value"]["userHandle"], "alice-handle");
    assert_eq!(
        scan[1],
        json!({"key":"bob","value":{"subject":"bob","name":"Bob"}})
    );
    let mut wire = WireArena::new(wire_limits()).unwrap();
    let bytes = host
        .prepare_provider_input_from_native_catalog(declaration)
        .unwrap();
    let id = wire.decode(bytes).unwrap();
    let batch: Value = serde_json::from_slice(wire.json(id).unwrap()).unwrap();
    assert_eq!(batch["rows"], scan);
    assert!(!batch.to_string().contains("bob-hidden"));
    assert!(!batch.to_string().contains("source:["));
}

#[test]
fn native_source_declaration_is_not_a_guest_key_mode_or_permission_flag() {
    for (declaration, expected) in [
        (r#"{"name":"rows","jsonKey":true}"#, HostError::Unsupported),
        (r#"{"name":"rows","jsonKey":"false"}"#, HostError::Invalid),
        (r#"{"name":"rows","json_key":false}"#, HostError::Invalid),
        (
            r#"{"name":"rows","jsonKey":false,"allowed":true}"#,
            HostError::Invalid,
        ),
        (r#"{"kind":"collection","name":"rows"}"#, HostError::Invalid),
        (
            r#"{"name":"source:[\"rows\",\"a\"]","jsonKey":false}"#,
            HostError::Forbidden,
        ),
        (
            r#"{"name":"__flowerContexts","jsonKey":false}"#,
            HostError::Forbidden,
        ),
    ] {
        let mut f = Fixture::new("null");
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let declaration = capture(&mut f.frame, declaration, &control);
        let policies = [CapturedCollection {
            name: "rows",
            policy: None,
        }];
        let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
        let relations = [OwnedRelation {
            name: "rows",
            coverage: CaptureCoverage::Complete,
            rows: &f.rows,
        }];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let mut host = SqlHost::new(
            NativePhase::Provider,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            Some(support),
            &budget,
            native_point(&f.job, NativePhase::Provider, f.binding),
            &mut f.job,
        )
        .unwrap();
        assert_eq!(
            host.prepare_provider_input_from_native_catalog(declaration)
                .unwrap_err(),
            expected
        );
        assert_eq!(host.failure(), Some(expected));
        assert!(host.finished().is_none());
    }
}

#[test]
fn misplaced_native_physical_id_never_leaves_any_scan_get_or_provider() {
    for key in [
        r#"source:["rows","a"]"#,
        r#"source:["other","private"]"#,
        "collection:rows",
        "cell:private",
        "root:private",
        "index:private",
        "$flower.fencing",
    ] {
        for operation in ["get", "scan", "provider"] {
            let mut f = Fixture::new("null");
            let control = FrameControl::new(&f.cancel, f.job.deadline());
            f.rows[0].key = f.frame.retain_key(key).unwrap();
            let declaration = capture(&mut f.frame, r#"{"name":"rows","jsonKey":false}"#, &control);
            let policies = [CapturedCollection {
                name: "rows",
                policy: None,
            }];
            let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
            let relations = [OwnedRelation {
                name: "rows",
                coverage: CaptureCoverage::Complete,
                rows: &f.rows,
            }];
            let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
            let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
            let mut host = SqlHost::new(
                NativePhase::Provider,
                &mut admitted,
                &f.frame,
                &relations,
                f.binding,
                Some(support),
                &budget,
                native_point(&f.job, NativePhase::Provider, f.binding),
                &mut f.job,
            )
            .unwrap();
            let result = if operation == "provider" {
                host.prepare_provider_input_from_native_catalog(declaration)
            } else {
                host.call_checked(
                    operation,
                    &if operation == "get" {
                        get("missing")
                    } else {
                        scan()
                    },
                )
            };
            assert_eq!(result.unwrap_err(), HostError::Forbidden);
            assert!(host.finished().is_none());
        }
        // Raw guest physical-looking keys fail BEFORE capture demand, even with
        // no captured relation. A logical lookup is never a source_id resolver.
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let mut host = SqlHost::new(
            NativePhase::InitialAuth,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            native_point(&f.job, NativePhase::InitialAuth, f.binding),
            &mut f.job,
        )
        .unwrap();
        assert_eq!(
            host.call_checked("get", &get(key)).unwrap_err(),
            HostError::Forbidden
        );
    }
}

#[test]
fn actual_metadata_hidden_index_suppresses_row_but_plain_scan_keeps_key() {
    let mut f = Fixture::new(METADATA_POLICY);
    bind_principal(&mut f, ALICE);
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let key = f.frame.retain_key("sql-policy").unwrap();
    let document = capture(
        &mut f.frame,
        r#"{"label":"fixture","sqlSources":[{"sourceId":"synthetic-private-source-id"}],"sqlAuthority":{"enabled":true}}"#,
        &control,
    );
    let policies = [CapturedCollection {
        name: "metadata",
        policy: Some(f.frame.json(f.policy, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let principal = VerifiedPrincipal::from_native_auth(
        f.frame.json(f.binding.invoker, &control).unwrap(),
        &budget,
        &mut f.job,
    )
    .unwrap();
    let engine = PolicyEngine::new(support, principal, f.binding.clock);
    let row = f.frame.json(document, &control).unwrap();
    let visible = engine
        .authorize(
            "metadata",
            "sql-policy",
            row,
            &["label"],
            &budget,
            &mut f.job,
        )
        .unwrap();
    assert!(visible.decision.allowed);
    assert!(
        visible
            .candidate
            .unwrap()
            .field("sqlSources", &budget, &mut f.job)
            .unwrap()
            .is_none()
    );
    let hidden = engine
        .authorize(
            "metadata",
            "sql-policy",
            row,
            &["sqlSources"],
            &budget,
            &mut f.job,
        )
        .unwrap();
    assert!(!hidden.decision.allowed);
    assert!(hidden.candidate.is_none());
    let rows = [OwnedRow {
        key,
        value: Some(document),
    }];
    let relations = [OwnedRelation {
        name: "metadata",
        coverage: CaptureCoverage::Complete,
        rows: &rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let mut host = SqlHost::new(
        NativePhase::Provider,
        &mut admitted,
        &f.frame,
        &relations,
        f.binding,
        Some(support),
        &budget,
        native_point(&f.job, NativePhase::Provider, f.binding),
        &mut f.job,
    )
    .unwrap();
    assert_eq!(
        json_response(host.call_checked("scan", &source_args("metadata")).unwrap()),
        json!([{"key":"sql-policy","value":{"label":"fixture"}}])
    );
}

#[test]
fn complete_native_filtered_redacted_batch_precedes_sealed_sqlite_count_and_sum() {
    use super::super::super::sqlite::{self, QueryOptions, SqlCell};
    let mut f = Fixture::new(METADATA_POLICY);
    bind_principal(&mut f, ALICE);
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let first = f.frame.retain_key("a").unwrap();
    let second = f.frame.retain_key("b").unwrap();
    // Synthetic numeric values under the ACTUAL untyped fixture ACL. This is
    // native/privacy integration evidence, not an actual Ultimator row seed.
    let a = capture(
        &mut f.frame,
        r#"{"amount":3,"sqlAuthority":7,"sqlSources":["private-a"]}"#,
        &control,
    );
    let b = capture(
        &mut f.frame,
        r#"{"amount":4,"sqlAuthority":900,"sqlSources":["private-b"]}"#,
        &control,
    );
    let declaration = capture(
        &mut f.frame,
        r#"{"name":"metadata","jsonKey":false}"#,
        &control,
    );
    let policies = [CapturedCollection {
        name: "metadata",
        policy: Some(f.frame.json(f.policy, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let rows = [
        OwnedRow {
            key: first,
            value: Some(a),
        },
        OwnedRow {
            key: second,
            value: Some(b),
        },
    ];
    let relations = [OwnedRelation {
        name: "metadata",
        coverage: CaptureCoverage::Complete,
        rows: &rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let mut typed = FrameBuilder::new(frame_limits(), &control).unwrap();
    let columns = [
        ("id", ColumnKind::Text, false),
        ("amount", ColumnKind::Integer, false),
        ("private_amount", ColumnKind::Integer, true),
    ]
    .map(|(name, kind, nullable)| FrameColumn {
        name,
        kind,
        nullable,
        logical_type: None,
        unit: None,
        equality: false,
    });
    let table = typed.add_table("visible", &columns).unwrap();
    {
        let mut host = SqlHost::new(
            NativePhase::Provider,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            Some(support),
            &budget,
            native_point(&f.job, NativePhase::Provider, f.binding),
            &mut f.job,
        )
        .unwrap();
        let mut input = WireArena::new(wire_limits()).unwrap();
        let batch = input
            .decode(
                host.prepare_provider_input_from_native_catalog(declaration)
                    .unwrap(),
            )
            .unwrap();
        for entry in input
            .value(batch)
            .unwrap()
            .member("rows")
            .unwrap()
            .iter()
            .unwrap()
        {
            let row = entry.value;
            let value = row.member("value").unwrap();
            // sourceKey derives from the checked LOGICAL key in the authorized
            // batch, sourceField from its REDACTED value, never a raw override.
            let key = row.member("key").unwrap().as_str().unwrap();
            let amount = value.member("amount").unwrap().as_f64().unwrap() as i64;
            assert!(value.member("sqlSources").is_none());
            let secret = value.member("sqlAuthority").map_or(FrameCell::Null, |v| {
                FrameCell::Integer(v.as_f64().unwrap() as i64)
            });
            typed
                .insert_row(
                    table,
                    &[FrameCell::Text(key), FrameCell::Integer(amount), secret],
                    &control,
                )
                .unwrap();
        }
    }
    budget.finish(&mut f.job, f.binding.clock).unwrap();
    drop(admitted);
    drop(f.frame); // NO raw/policy/source capabilities in SQLite
    let mut sealed = typed.seal(&control).unwrap();
    let tables = sealed.native_tables(1024 * 1024).unwrap();
    let result=sqlite::execute("SELECT COUNT(*),SUM(amount),COUNT(private_amount),SUM(private_amount),MIN(id) FROM visible",&[],&tables,&mut sealed,QueryOptions{batch_rows:1,max_rows:1,..QueryOptions::default()},&mut ||Ok(())).unwrap();
    assert_eq!(
        result.rows,
        [vec![
            SqlCell::Integer(2),
            SqlCell::Integer(7),
            SqlCell::Integer(0),
            SqlCell::Null,
            SqlCell::Text("a".into())
        ]]
    );
}

#[cfg(sql_host_harness)]
fn readable_targets(value: &Value, targets: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "readable" {
                    targets.insert(value[0].as_str().unwrap().to_owned());
                } else if key != "value" {
                    readable_targets(value, targets);
                }
            }
        }
        Value::Array(array) => {
            for value in array {
                readable_targets(value, targets);
            }
        }
        _ => (),
    }
}
#[cfg(sql_host_harness)]
fn has_key_parts(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            key == "ref" && value[0] == "key" && value.as_array().unwrap().len() > 1
                || key != "value" && has_key_parts(value)
        }),
        Value::Array(array) => array.iter().any(has_key_parts),
        _ => false,
    }
}
#[cfg(sql_host_harness)]
#[test]
fn frozen_entire_actual_ultimator_read_manifest_matches_native_or_explicit_keypart_hold() {
    let manifest: Value = serde_json::from_str(FROZEN_READ_MANIFEST).unwrap();
    let entries = manifest.as_array().unwrap();
    assert_eq!(entries.len(), 189);
    let principal: Value = serde_json::from_str(ALICE).unwrap();
    let row = json!({});
    let mut supported = 0;
    let mut unsupported = 0;
    for entry in entries {
        let name = entry["name"].as_str().unwrap();
        let policy = &entry["access"];
        let mut targets = std::collections::BTreeSet::new();
        readable_targets(policy, &mut targets);
        let target_policies: Vec<(String, Value)> = targets
            .iter()
            .map(|name| {
                (
                    name.clone(),
                    entries.iter().find(|entry| entry["name"] == *name).unwrap()["access"].clone(),
                )
            })
            .collect();
        let expected_unsupported = has_key_parts(policy)
            || target_policies
                .iter()
                .any(|(_, policy)| has_key_parts(&policy["read"]));
        let mut f = Fixture::new(&policy.to_string());
        bind_principal(&mut f, ALICE);
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let document = capture(&mut f.frame, "{}", &control);
        let ids: Vec<_> = target_policies
            .iter()
            .map(|(_, p)| capture(&mut f.frame, &p.to_string(), &control))
            .collect();
        let mut collections = vec![CapturedCollection {
            name,
            policy: Some(f.frame.json(f.policy, &control).unwrap()),
        }];
        collections.extend(
            target_policies
                .iter()
                .zip(ids.iter())
                .map(|((name, _), id)| CapturedCollection {
                    name,
                    policy: Some(f.frame.json(*id, &control).unwrap()),
                }),
        );
        let support_rows: Vec<_> = targets
            .iter()
            .flat_map(|name| {
                ["alice", "acme", "k", ""].map(|key| CapturedSupportRow {
                    collection: name,
                    key,
                    row: None,
                })
            })
            .collect();
        let support = CapturedSupport::from_owned_capture(&collections, &support_rows).unwrap();
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let verified = VerifiedPrincipal::from_native_auth(
            f.frame.json(f.binding.invoker, &control).unwrap(),
            &budget,
            &mut f.job,
        )
        .unwrap();
        let engine = PolicyEngine::new(support, verified, 1000);
        let actual = engine.authorize(
            name,
            "k",
            f.frame.json(document, &control).unwrap(),
            &[],
            &budget,
            &mut f.job,
        );
        if expected_unsupported {
            assert!(
                matches!(actual, Err(PolicyError::Unsupported)),
                "actual policy {name} unexpectedly accepted or failed another gate"
            );
            unsupported += 1;
        } else {
            let actual = actual.unwrap_or_else(|error| panic!("actual policy {name}: {error:?}"));
            let (allowed, redacted, _) = crate::reference::run(
                policy,
                &principal,
                &row,
                "k",
                &[],
                1000,
                &target_policies,
                &[],
            );
            assert_eq!(actual.decision.allowed, allowed, "actual policy {name}");
            if let Some(candidate) = actual.candidate {
                let mut bytes = [0; 1024];
                let n = candidate
                    .encode_json(&mut bytes, &budget, &mut f.job)
                    .unwrap();
                assert_eq!(
                    serde_json::from_slice::<Value>(&bytes[..n]).unwrap(),
                    redacted,
                    "actual field reads {name}"
                );
            }
            supported += 1;
        }
    }
    assert_eq!(
        (supported, unsupported),
        (100, 89),
        "manifest source/ACL drift needs recertification, not a loose success claim"
    );
}

#[cfg(sql_host_harness)]
#[test]
fn actual_sessions_invites_role_sessions_oversight_and_org_denials_match_native() {
    let policy: Value = serde_json::from_str(SESSIONS_POLICY).unwrap();
    let principal: Value = serde_json::from_str(ALICE).unwrap();
    for (row, expected) in [
        (
            json!({"org":"acme","private":false,"createdBy":"bob"}),
            true,
        ),
        (
            json!({"org":"acme","private":true,"createdBy":"alice"}),
            true,
        ),
        (
            json!({"org":"acme","private":true,"createdBy":"alice","roles":[]}),
            false,
        ),
        (
            json!({"org":"acme","private":true,"createdBy":"bob","invited":{"reach":["alice"],"viewing":["alice"]}}),
            true,
        ),
        (
            json!({"org":"acme","private":true,"createdBy":"bob","overseers":["alice"],"oversight":{"alice":999}}),
            true,
        ),
        (
            json!({"org":"acme","private":true,"createdBy":"bob"}),
            false,
        ),
        (
            json!({"org":"evil","private":false,"createdBy":"alice","overseers":["alice"]}),
            false,
        ),
    ] {
        let mut f = Fixture::new(SESSIONS_POLICY);
        bind_principal(&mut f, ALICE);
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let document = capture(&mut f.frame, &row.to_string(), &control);
        let policies = [CapturedCollection {
            name: "sessions",
            policy: Some(f.frame.json(f.policy, &control).unwrap()),
        }];
        let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let verified = VerifiedPrincipal::from_native_auth(
            f.frame.json(f.binding.invoker, &control).unwrap(),
            &budget,
            &mut f.job,
        )
        .unwrap();
        let engine = PolicyEngine::new(support, verified, 1000);
        let actual = engine
            .authorize(
                "sessions",
                "s",
                f.frame.json(document, &control).unwrap(),
                &[],
                &budget,
                &mut f.job,
            )
            .unwrap();
        assert_eq!(actual.decision.allowed, expected);
        assert_eq!(
            crate::reference::run(&policy, &principal, &row, "s", &[], 1000, &[], &[]).0,
            expected
        );
    }
    // Important actual product gap: collection ACL contains overseers[] but NO
    // time check. Method canRead/certifiedSqlContext must enforce oversight expiry;
    // native row-read PASS above MUST NOT be called full SQL authorization PASS.
}

#[test]
fn actual_typed_members_scopes_labels_remain_unsupported_even_for_native_process() {
    for (name, policy) in [
        ("members", MEMBERS_POLICY),
        ("scopes", SCOPES_POLICY),
        ("labels", LABELS_POLICY),
    ] {
        let mut f = Fixture::new(policy);
        bind_principal(
            &mut f,
            r#"{"subject":"operator","claims":{"role":"operator"}}"#,
        );
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let superadmin = capture(&mut f.frame, SUPERADMINS_POLICY, &control);
        let policies = [
            CapturedCollection {
                name,
                policy: Some(f.frame.json(f.policy, &control).unwrap()),
            },
            CapturedCollection {
                name: "superadmins",
                policy: Some(f.frame.json(superadmin, &control).unwrap()),
            },
        ];
        let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let verified = VerifiedPrincipal::from_native_auth(
            f.frame.json(f.binding.invoker, &control).unwrap(),
            &budget,
            &mut f.job,
        )
        .unwrap();
        let engine = PolicyEngine::new(support, verified, 1000);
        assert!(matches!(
            engine.authorize(
                name,
                r#"["acme","alice"]"#,
                f.frame.json(f.rows[0].value.unwrap(), &control).unwrap(),
                &[],
                &budget,
                &mut f.job
            ),
            Err(PolicyError::Unsupported)
        ));
    }
}

#[cfg(sql_host_harness)]
#[test]
fn actual_acl_redacted_scan_native_source_binding_and_refusals_remain_zero_heap() {
    let mut f = Fixture::new(METADATA_POLICY);
    bind_principal(&mut f, ALICE);
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    f.rows[0].value = Some(capture(
        &mut f.frame,
        r#"{"amount":3,"sqlSources":["actual-hidden-source"],"sqlAuthority":7}"#,
        &control,
    ));
    let source = capture(&mut f.frame, r#"{"name":"rows","jsonKey":false}"#, &control);
    let policies = [CapturedCollection {
        name: "rows",
        policy: Some(f.frame.json(f.policy, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let (result, count, bytes) = crate::allocation_probe::measure(|| -> Result<(), HostError> {
        let mut host = SqlHost::new(
            NativePhase::Provider,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            Some(support),
            &budget,
            native_point(&f.job, NativePhase::Provider, f.binding),
            &mut f.job,
        )?;
        host.prepare_provider_input_from_native_catalog(source)?;
        Ok(())
    });
    assert_eq!(result, Ok(()));
    assert_eq!((count, bytes), (0, 0));
    for (source, error) in [
        (r#"{"name":"rows","jsonKey":true}"#, HostError::Unsupported),
        (r#"{"name":"rows","allowed":true}"#, HostError::Invalid),
    ] {
        let mut f = Fixture::new("null");
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let source = capture(&mut f.frame, source, &control);
        let policies = [CapturedCollection {
            name: "rows",
            policy: None,
        }];
        let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
        let relations = [OwnedRelation {
            name: "rows",
            coverage: CaptureCoverage::Complete,
            rows: &f.rows,
        }];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let (result, count, bytes) =
            crate::allocation_probe::measure(|| -> Result<(), HostError> {
                let mut host = SqlHost::new(
                    NativePhase::Provider,
                    &mut admitted,
                    &f.frame,
                    &relations,
                    f.binding,
                    Some(support),
                    &budget,
                    native_point(&f.job, NativePhase::Provider, f.binding),
                    &mut f.job,
                )?;
                host.prepare_provider_input_from_native_catalog(source)?;
                Ok(())
            });
        assert_eq!(result, Err(error));
        assert_eq!((count, bytes), (0, 0));
    }
}

#[test]
fn native_logical_key_constructor_binds_canonical_captured_source_pair() {
    for key in [
        "a",
        "quote\"slash\\",
        "é中文🌸",
        "\n\t\u{0001}",
        "__proto__",
        r#"["this-is-a-string"]"#,
    ] {
        let mut f = Fixture::new("null");
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let key_id = f.frame.retain_key(key).unwrap();
        // Exactly source_id(collection,key)'s native serde JSON suffix; fixture
        // serialization occurs BEFORE the admitted constructor observation.
        let pair_text = serde_json::to_string(&["rows", key]).unwrap();
        let pair = capture(&mut f.frame, &pair_text, &control);
        let declaration = capture(&mut f.frame, r#"{"name":"rows","jsonKey":false}"#, &control);
        let relations = [];
        let support = CapturedSupport::from_owned_capture(&[], &[]).unwrap();
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let mut host = SqlHost::new(
            NativePhase::Provider,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            Some(support),
            &budget,
            native_point(&f.job, NativePhase::Provider, f.binding),
            &mut f.job,
        )
        .unwrap();
        let bound = host
            .bind_owned_native_string_row(
                declaration,
                pair,
                OwnedRow {
                    key: key_id,
                    value: f.rows[0].value,
                },
            )
            .unwrap();
        assert_eq!(bound.key, key_id);
    }
    for pair in [
        r#"["other","b"]"#,
        r#"["rows","wrong-key"]"#,
        r#"["rows","b",1]"#,
        r#"[ "rows", "b" ]"#,
        r#"["rows","\u0062"]"#,
        r#"{"collection":"rows","key":"b"}"#,
    ] {
        let mut f = Fixture::new("null");
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let pair = capture(&mut f.frame, pair, &control);
        let declaration = capture(&mut f.frame, r#"{"name":"rows","jsonKey":false}"#, &control);
        let relations = [];
        let support = CapturedSupport::from_owned_capture(&[], &[]).unwrap();
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let mut host = SqlHost::new(
            NativePhase::Provider,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            Some(support),
            &budget,
            native_point(&f.job, NativePhase::Provider, f.binding),
            &mut f.job,
        )
        .unwrap();
        assert!(matches!(
            host.bind_owned_native_string_row(declaration, pair, f.rows[1]),
            Err(HostError::Invalid)
        ));
        assert_eq!(host.failure(), Some(HostError::Invalid));
    }
}

#[cfg(sql_host_harness)]
#[test]
fn concrete_native_key_pair_binding_and_noncanonical_refusal_are_heap_free() {
    for (pair, expected) in [(r#"["rows","b"]"#, true), (r#"[ "rows", "b" ]"#, false)] {
        let mut f = Fixture::new("null");
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let pair = capture(&mut f.frame, pair, &control);
        let source = capture(&mut f.frame, r#"{"name":"rows","jsonKey":false}"#, &control);
        let relations = [];
        let support = CapturedSupport::from_owned_capture(&[], &[]).unwrap();
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let (result, count, bytes) =
            crate::allocation_probe::measure(|| -> Result<(), HostError> {
                let mut host = SqlHost::new(
                    NativePhase::Provider,
                    &mut admitted,
                    &f.frame,
                    &relations,
                    f.binding,
                    Some(support),
                    &budget,
                    native_point(&f.job, NativePhase::Provider, f.binding),
                    &mut f.job,
                )?;
                host.bind_owned_native_string_row(source, pair, f.rows[1])?;
                Ok(())
            });
        assert_eq!(result.is_ok(), expected);
        assert_eq!((count, bytes), (0, 0));
    }
}

#[test]
fn actual_session_acl_hidden_rows_do_not_enter_provider_or_sqlite_count_sum() {
    use super::super::super::sqlite::{self, QueryOptions, SqlCell};
    let mut f = Fixture::new(SESSIONS_POLICY);
    bind_principal(&mut f, ALICE);
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let docs = [
        r#"{"id":"aaaaaaaaaaaaaaaa","org":"acme","createdBy":"alice","private":true,"steps":3}"#,
        r#"{"id":"bbbbbbbbbbbbbbbb","org":"acme","createdBy":"bob","private":true,"steps":1000}"#,
        r#"{"id":"cccccccccccccccc","org":"acme","createdBy":"bob","private":false,"steps":4}"#,
    ];
    for (index, (key, text)) in ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc"]
        .iter()
        .zip(docs)
        .enumerate()
    {
        f.rows[index] = OwnedRow {
            key: f.frame.retain_key(key).unwrap(),
            value: Some(capture(&mut f.frame, text, &control)),
        };
    }
    let declaration = capture(
        &mut f.frame,
        r#"{"name":"sessions","jsonKey":false}"#,
        &control,
    );
    let policies = [CapturedCollection {
        name: "sessions",
        policy: Some(f.frame.json(f.policy, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let relations = [OwnedRelation {
        name: "sessions",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let mut typed = FrameBuilder::new(frame_limits(), &control).unwrap();
    let table = typed
        .add_table(
            "visible",
            &[
                FrameColumn {
                    name: "id",
                    kind: ColumnKind::Text,
                    nullable: false,
                    logical_type: None,
                    unit: None,
                    equality: false,
                },
                FrameColumn {
                    name: "steps",
                    kind: ColumnKind::Integer,
                    nullable: false,
                    logical_type: None,
                    unit: None,
                    equality: false,
                },
            ],
        )
        .unwrap();
    {
        let mut host = SqlHost::new(
            NativePhase::Provider,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            Some(support),
            &budget,
            native_point(&f.job, NativePhase::Provider, f.binding),
            &mut f.job,
        )
        .unwrap();
        let mut input = WireArena::new(wire_limits()).unwrap();
        let id = input
            .decode(
                host.prepare_provider_input_from_native_catalog(declaration)
                    .unwrap(),
            )
            .unwrap();
        let rows = input.value(id).unwrap().member("rows").unwrap();
        assert_eq!(rows.len(), Some(2));
        for entry in rows.iter().unwrap() {
            let row = entry.value;
            let key = row.member("key").unwrap().as_str().unwrap();
            assert_ne!(key, "bbbbbbbbbbbbbbbb");
            let value = row.member("value").unwrap();
            let steps = value.member("steps").unwrap().as_f64().unwrap() as i64;
            typed
                .insert_row(
                    table,
                    &[FrameCell::Text(key), FrameCell::Integer(steps)],
                    &control,
                )
                .unwrap();
        }
    }
    budget.finish(&mut f.job, f.binding.clock).unwrap();
    drop(admitted);
    drop(f.frame);
    let mut sealed = typed.seal(&control).unwrap();
    let tables = sealed.native_tables(1024 * 1024).unwrap();
    let result = sqlite::execute(
        "SELECT COUNT(*),SUM(steps) FROM visible LIMIT 1",
        &[],
        &tables,
        &mut sealed,
        QueryOptions {
            batch_rows: 1,
            max_rows: 1,
            ..QueryOptions::default()
        },
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(
        result.rows,
        [vec![SqlCell::Integer(2), SqlCell::Integer(7)]]
    );
}

#[test]
fn actual_policy_support_rows_for_native_jobs_grants_fences_roles_and_reports() {
    for (name, policy, key, row) in [
        (
            "orgAdmins",
            ORGADMINS_POLICY,
            "acme",
            json!({"admins":["alice"]}),
        ),
        (
            "roleHolders",
            ROLEHOLDERS_POLICY,
            "role:reviewer",
            json!({"org":"acme","members":["alice"]}),
        ),
        (
            "toolJobs",
            TOOLJOBS_POLICY,
            "service-job",
            json!({"state":"leased","payload":{"session":"s","call":"call","name":"query_sql"},"lease":{"token":7,"expiresAt":1002}}),
        ),
        (
            "accountSessionGrants",
            ACCOUNTSESSIONGRANTS_POLICY,
            "s",
            json!({"subject":"alice","generation":3}),
        ),
        (
            "accountFences",
            ACCOUNTFENCES_POLICY,
            "alice",
            json!({"generation":3,"disabled":null,"signedOutAt":null}),
        ),
        (
            "reports",
            REPORTS_POLICY,
            "report",
            json!({"org":"acme","private":true,"createdBy":"bob","reach":["alice"],"removed":true}),
        ),
    ] {
        let mut f = Fixture::new(policy);
        bind_principal(&mut f, ALICE);
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let document = capture(&mut f.frame, &row.to_string(), &control);
        let target = capture(&mut f.frame, SESSIONS_POLICY, &control);
        let superadmin = capture(&mut f.frame, SUPERADMINS_POLICY, &control);
        let session = capture(
            &mut f.frame,
            r#"{"id":"s","org":"acme","private":true,"createdBy":"alice"}"#,
            &control,
        );
        let policies = [
            CapturedCollection {
                name,
                policy: Some(f.frame.json(f.policy, &control).unwrap()),
            },
            CapturedCollection {
                name: "sessions",
                policy: Some(f.frame.json(target, &control).unwrap()),
            },
            CapturedCollection {
                name: "superadmins",
                policy: Some(f.frame.json(superadmin, &control).unwrap()),
            },
        ];
        let rows = [
            CapturedSupportRow {
                collection: "sessions",
                key: "s",
                row: Some(f.frame.json(session, &control).unwrap()),
            },
            CapturedSupportRow {
                collection: "superadmins",
                key: "alice",
                row: None,
            },
        ];
        let support = CapturedSupport::from_owned_capture(&policies, &rows).unwrap();
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let principal = VerifiedPrincipal::from_native_auth(
            f.frame.json(f.binding.invoker, &control).unwrap(),
            &budget,
            &mut f.job,
        )
        .unwrap();
        let engine = PolicyEngine::new(support, principal, 1000);
        assert!(
            engine
                .authorize(
                    name,
                    key,
                    f.frame.json(document, &control).unwrap(),
                    &[],
                    &budget,
                    &mut f.job
                )
                .unwrap()
                .decision
                .allowed,
            "actual native support policy {name}"
        );
        #[cfg(sql_host_harness)]
        {
            let principal: Value = serde_json::from_str(ALICE).unwrap();
            let policy: Value = serde_json::from_str(policy).unwrap();
            let targets = vec![
                (
                    "sessions".to_owned(),
                    serde_json::from_str(SESSIONS_POLICY).unwrap(),
                ),
                (
                    "superadmins".to_owned(),
                    serde_json::from_str(SUPERADMINS_POLICY).unwrap(),
                ),
            ];
            let rows = vec![
                (
                    "sessions".to_owned(),
                    "s".to_owned(),
                    Some(json!({"id":"s","org":"acme","private":true,"createdBy":"alice"})),
                ),
                ("superadmins".to_owned(), "alice".to_owned(), None),
            ];
            assert!(
                crate::reference::run(&policy, &principal, &row, key, &[], 1000, &targets, &rows).0
            );
        }
    }
    // These are collection read decisions only. Job/lease expiry, account
    // generation correlation and report removal remain real method checks.
}
