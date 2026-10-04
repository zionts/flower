# Actual frozen native typed-key policy compatibility

**Policy foundation only; native controller/runtime/service/SQL activation HOLD.**

This supplement changes the **new native-only policy API**, not the unowned
host. `sql_host/actual_acl_matrix.md` remains the accurate string-host baseline.
The old `authorize` API still refuses key-part and composite-readable operands.

## Exact inputs and counts

- Ultimator main: `144c1a8d966e2f3577f952301ade24da675b61e8`.
- Frozen backend: `edcb1909a356bfdc233e40b3d0bfd8702fbfa182`.
- Actual SDK-generated collection manifest:222 declarations,189 policies,
  33 authoritative policy absences; main/backend manifests are identical.
- Full source manifest SHA256:
  `fb2b851ffef2b190e88dfe75c12f7d36300c450200ec1e66cee1996f8333f8b4`.
- `typed_manifest.json` retains the **exact189 read/field-read ASTs**, not boolean
  permission classifiers. Nonread writes/references/indexes are excluded.
- Reduced fixture SHA256: `bc3fda5ff8c64a739c8617ca51a40e4ddde0a558800e14202843c97ae3ebd500`.
- Frozen read operators:all/any/const/eq/exists/in/not/readable/startsWith;
  **zero now references**. Existing temporal-compound refusal is unchanged.

| Surface | Supported ASTs | Explicit typed-key HOLD | Meaning |
|---|---:|---:|---|
| Previous/current legacy host + string policy API |100|89|Unchanged; no implicit host/provider upgrade.|
| New checked native-key policy API |189|0|Native rule semantics supported with exact captured keys/support; NOT189 allowed rows or serving success.|

The frozen14-table backend uses8 distinct native sources:3 string
(`sessions`, `orgs`, `reports`) and5 typed (`scopes`, `dependencies`, `labels`,
`usage`, `members`). Table-source uses remain9 string/6 typed. Typed binding
now supports all5 declared source modes in the policy foundation, including
`members[org,subject]` needed by the first real human. Host SDK decoding/output
and mandatory native capture-origin proof still require its owner to integrate
`NativeKeyRow`, `from_owned_native_capture`, and `authorize_native`.

## Real fixture evidence and scope

Tests compare against **current unmodified native access.rs/json.rs bodies**
compiled by `harness_build.rs`, now also extracting actual
`source_id/source_pair`. Reference row acquisition is explicitly synthetic
fixed captured support, not serving Records. The frozen actual SDK ASTs are not
rewritten. Fixture values are synthetic legacy-valid IDs, as current `id`
accepts nonempty strings (not only newer16-character minted IDs).

- Entire189-policy read/field-read matrix:5 native principals ×2 logical key
  forms =1,890 differential decisions/redaction checks. All89 old typed-key
  HOLD classifications are exercised as supported **ASTs**, not blindly allowed.
- Actual memberships/scopes/labels/usage/dependencies typed tuples, string
  orgs/reports/roleHolders/toolJobs/accountFences/accountSessionGrants, typed
  roles/grants/integrationSettings: actual allowed and hidden rows.
- Actual org settings and typed scope instructions field redaction, including
  selecting hidden fields suppressing the whole row.
- Actual first-human members `[org,subject]`: visible amount3, hidden1000,
  visible4. Only approved scalar cells enter the **same** admitted builder;
  capture is consumed at seal. Real native SQLite yields **COUNT=2,SUM=7**.
- Current sessions oversight collection ACL allows a listed overseer even with
  an expired synthetic oversight timestamp. This accurately demonstrates the
  separate required method/provider expiry gate; it is NOT expiry authorization.
- Whole encoded key vs array/object parts, nested/missing/null/scalar keys,
  +/leading-zero and overflow usize indices, exact native numeric equality/
  integer ordering; native UTF-16 object canonical ordering vs UTF-8 ACL text
  order, escaped strings, rounded numbers and negative zero.
- Canonical/wrong/physical/duplicate/source-name/decoded-token substitutions,
  uncaptured support vs actual absence, readonly-target readable recursion,
  sticky original work/cancel/deadline/temporal refusal.

No generated SDK/node mock SQL result, privileged guest switch, provider callback
lookup, Records/Source/Value acquisition, or actual managed JWT/authentication
launch fixture is invented. Full HTTP/controller freshness/crypto/runtime
positive remains HOLD.

## Verification

Final **81/81 PASS** in263.47s test time on the current shared foundation
(a30d38372d51ba7284c0727b01dc7e299ec32f40 plus staged source):2 original-control,
29 current-frame,32 policy (21 legacy +11 typed extension),18 current-native
SQLite tests; no ignored tests. Final strict `cargo clippy --all-targets --
-D warnings` and owned-file rustfmt check **PASS**. Typed key/source binding,
canonical UTF-16/number/escaping success, wrong/canonical/physical/refusal cases,
duplicate/foreign-owner/uncaptured/absent/recursive targets and original
work/cancel/deadline/temporal rejection all measure **0Rust allocations/0Layout
bytes post-admission**. These are native Rust probes, not a whole process/native
Wasm/allocator/stack admission proof. Additional exact key-part microdifferentials
cover7,008 predicates in56 finite admitted fixture frames.

An initial unbatched differential run exceeded its600s envelope under shared
load; superseded runs were interrupted/recompiled. A final intermediate run
found the legacy20-byte array-index subset regression and an overly short500ms
test setup deadline; both were corrected (legacy behavior preserved, deadline
fixture now blocks until its ONE original normal job expires). The exclusive
final run above passed all81, including SQLite fresh-process initialization.

The additional existing `/workspace/sql-acl-harness` compile check is **BLOCKED
by that harness's stale external host.rs copy**, not marked PASS: current
unowned authority/read files require NativeTimePoint, NativeBoundary,
TemporalError, PartialEq NativeBinding and new authority/temporal host fields
that its old copy lacks. No host/authority/time/root file was changed. Its new
physical-helper test dependency is prevented through the typed-only cfg below.
Parent/host owner must rerun current actual host/native fixtures after updating
its own registry/harness. Full Flower/SDK/native-service/HTTP/e2e checks remain
parent integration work, not silently green.

Each isolated command uses `CARGO_TARGET_DIR=/workspace/dlydpehxsr5sw6d6/target`,
`CARGO_BUILD_JOBS=2`, `CARGO_INCREMENTAL=0`, `--offline`, and current actual frame/
control/SQLite/native evaluator reference source. Only our finished `target` and failed/stale-harness `host-target` are
removed; no shared cache or sibling target is touched.

## Full189-policy classification update

`NATIVE_AST` is an exact supported rule tree, not an allowlist.
`NATIVE_TYPED_AST` also exercises key-part rules (direct or readable target).
The legacy classifications remain for integration clarity.

| Actual collection | Legacy policy/host | New native-only policy | Readable targets |
|---|---|---|---|
| `accessRequests` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `accountFences` | AST | NATIVE_AST | `superadmins` |
| `accountRecipients` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `accountSessionGrants` | AST | NATIVE_AST | — |
| `accountSignIns` | AST | NATIVE_AST | — |
| `accountWorkflowGrants` | AST | NATIVE_AST | — |
| `accounts` | AST | NATIVE_AST | `superadmins` |
| `activityCells` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `activityPacks` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `addressPlace` | AST | NATIVE_AST | `superadmins` |
| `agents` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `roleHolders`, `superadmins` |
| `approvalRequests` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `auditLog` | AST | NATIVE_AST | — |
| `autoMergePrefs` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `autoMergeRepos` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `autoMerges` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `autoResolveRepos` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `autoResolves` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `auxiliarySpends` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `avatarImages` | AST | NATIVE_AST | — |
| `backfills` | AST | NATIVE_AST | — |
| `billing` | AST | NATIVE_AST | `superadmins` |
| `bindings` | AST | NATIVE_AST | — |
| `blobRefs` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `bookStates` | AST | NATIVE_AST | `superadmins` |
| `ceremonies` | AST | NATIVE_AST | — |
| `chargeTotals` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `cliLogins` | AST | NATIVE_AST | — |
| `clusterActions` | AST | NATIVE_AST | `superadmins` |
| `clusterSnapshots` | AST | NATIVE_AST | `superadmins` |
| `codeReviews` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `completions` | AST | NATIVE_AST | `sessions`, `superadmins` |
| `computerRelays` | AST | NATIVE_AST | — |
| `computers` | AST | NATIVE_AST | `superadmins` |
| `confirmations` | AST | NATIVE_AST | — |
| `credentials` | AST | NATIVE_AST | `superadmins` |
| `deletedAccounts` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `dependencies` | AST | NATIVE_AST | — |
| `deploySources` | AST | NATIVE_AST | — |
| `deploys` | AST | NATIVE_AST | — |
| `drafts` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `environmentSecrets` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `environments` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `events` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `evergreenSessions` | AST | NATIVE_AST | — |
| `explainSources` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `explainSpends` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `feeDefaults` | AST | NATIVE_AST | — |
| `followChoices` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `followings` | AST | NATIVE_AST | — |
| `formerOrgs` | AST | NATIVE_AST | `superadmins` |
| `githubApps` | AST | NATIVE_AST | — |
| `githubInstalls` | AST | NATIVE_AST | `superadmins` |
| `githubRoutes` | AST | NATIVE_AST | `superadmins` |
| `githubUsers` | AST | NATIVE_AST | — |
| `glossSources` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `grants` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `hourTotals` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `integrationSettings` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `invites` | AST | NATIVE_AST | `superadmins` |
| `journal` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `judges` | AST | NATIVE_AST | `sessions`, `superadmins` |
| `judgments` | AST | NATIVE_AST | `superadmins` |
| `labels` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `ledgerIntents` | AST | NATIVE_AST | `superadmins` |
| `linearApps` | AST | NATIVE_AST | `superadmins` |
| `listings` | AST | NATIVE_AST | — |
| `liveReplies` | AST | NATIVE_AST | `sessions` |
| `llmEnvironment` | AST | NATIVE_AST | — |
| `machines` | AST | NATIVE_AST | `superadmins` |
| `mcpClients` | AST | NATIVE_AST | `superadmins` |
| `mcpConnections` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `mcpRefreshes` | AST | NATIVE_AST | — |
| `mcpServers` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `members` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `memories` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `roleHolders`, `superadmins` |
| `memoryChanges` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `roleHolders` |
| `memoryReads` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `mentions` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `messageSummarySources` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `messageSummarySpends` | AST | NATIVE_AST | — |
| `meterOperations` | AST | NATIVE_AST | `superadmins` |
| `moduleSettings` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `noticeDecisions` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `noticeInstructions` | AST | NATIVE_AST | — |
| `noticeNews` | AST | NATIVE_AST | — |
| `notices` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `orgAdmins` | AST | NATIVE_AST | — |
| `orgMoves` | AST | NATIVE_AST | — |
| `orgPictureReaders` | AST | NATIVE_AST | — |
| `orgPictures` | AST | NATIVE_AST | `orgPictureReaders` |
| `orgs` | AST | NATIVE_AST | `superadmins` |
| `outbound` | AST | NATIVE_AST | `sessions`, `superadmins` |
| `partialHeads` | AST | NATIVE_AST | `sessions` |
| `partials` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `passkeys` | AST | NATIVE_AST | `superadmins` |
| `passwords` | AST | NATIVE_AST | — |
| `personalLabels` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `previewCodes` | AST | NATIVE_AST | — |
| `previewGrants` | AST | NATIVE_AST | — |
| `previews` | AST | NATIVE_AST | `sessions` |
| `provision` | AST | NATIVE_AST | `superadmins` |
| `pullMirror` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `pullMirrorAsks` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `pullMirrorStates` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `pullMirrorViews` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `pullMirrors` | AST | NATIVE_AST | — |
| `pullSyncs` | AST | NATIVE_AST | — |
| `pulls` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `pushDevices` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `pushPrefs` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `pushes` | AST | NATIVE_AST | `sessions`, `superadmins` |
| `repoAgents` | AST | NATIVE_AST | `superadmins` |
| `repoWorkflows` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `reportVersions` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `reports` |
| `reports` | AST | NATIVE_AST | — |
| `requests` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `reviewNoteRecoveries` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `reviewPrefs` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `reviewRepos` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `reviews` | AST | NATIVE_AST | `sessions`, `superadmins` |
| `roleHolders` | AST | NATIVE_AST | — |
| `roleSessions` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `roles` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `rootTotals` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `rumDays` | AST | NATIVE_AST | `superadmins` |
| `rumErrorAcks` | AST | NATIVE_AST | `superadmins` |
| `rumErrors` | AST | NATIVE_AST | `superadmins` |
| `rumHours` | AST | NATIVE_AST | `superadmins` |
| `rumOrgDays` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `orgAdmins`, `superadmins` |
| `rumOrgErrorAcks` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `orgAdmins`, `superadmins` |
| `rumOrgErrors` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `orgAdmins`, `superadmins` |
| `rumOrgHours` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `orgAdmins`, `superadmins` |
| `rumPages` | AST | NATIVE_AST | `orgAdmins`, `superadmins` |
| `rumUserDays` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `rumUserErrorAcks` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `rumUserErrors` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `rumUserHours` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `sandboxHosts` | AST | NATIVE_AST | `superadmins` |
| `sandboxes` | AST | NATIVE_AST | `superadmins` |
| `scopeSpend` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `scopes` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `sealedMessages` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `sealing` | AST | NATIVE_AST | `sessions`, `superadmins` |
| `secrets` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `seen` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `segments` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `sessionPrompts` | AST | NATIVE_AST | `sessions` |
| `sessionTotals` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `sessions` | AST | NATIVE_AST | — |
| `singletons` | AST | NATIVE_AST | — |
| `site` | AST | NATIVE_AST | — |
| `skillFiles` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `roleHolders` |
| `skills` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `roleHolders`, `superadmins` |
| `slackChannels` | AST | NATIVE_AST | `superadmins` |
| `slackInstalls` | AST | NATIVE_AST | `superadmins` |
| `slackLinks` | AST | NATIVE_AST | `superadmins` |
| `slackMessages` | AST | NATIVE_AST | — |
| `slackPictures` | AST | NATIVE_AST | — |
| `slackRoutes` | AST | NATIVE_AST | `superadmins` |
| `stripeRoutes` | AST | NATIVE_AST | `superadmins` |
| `subscriptions` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `subsessions` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `superadminLog` | AST | NATIVE_AST | `superadmins` |
| `superadmins` | AST | NATIVE_AST | — |
| `surfaceInstalls` | AST | NATIVE_AST | `superadmins` |
| `surfaceLinks` | AST | NATIVE_AST | `superadmins` |
| `surfaceMessages` | AST | NATIVE_AST | — |
| `surfacePlaces` | AST | NATIVE_AST | `superadmins` |
| `surfaceRoutes` | AST | NATIVE_AST | `superadmins` |
| `teamInvites` | AST | NATIVE_AST | `superadmins` |
| `teamMembers` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `teamSpreads` | AST | NATIVE_AST | `superadmins` |
| `teams` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `titleSources` | AST | NATIVE_AST | `sessions` |
| `toolJobs` | AST | NATIVE_AST | `sessions`, `superadmins` |
| `transcripts` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `sessions` |
| `uplinkKeys` | AST | NATIVE_AST | — |
| `uplinkTokens` | AST | NATIVE_AST | — |
| `uplinks` | AST | NATIVE_AST | — |
| `usage` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `waiting` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | — |
| `workflowDrafts` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `workflowExceptions` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `workflowRuns` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `workflowSteps` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `workflowTriggers` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `workflowVersions` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
| `workflows` | KEY_PARTS_HOLD | NATIVE_TYPED_AST | `superadmins` |
