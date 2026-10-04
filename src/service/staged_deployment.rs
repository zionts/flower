//! Durable online index and reactive-graph preparation. Bounded pages build a
//! hidden generation, maintained alongside the active graph until atomic cutover.
use super::*;
use crate::evaluator::staging::{self, IndexSpec, Schema};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod graph_pages;
use graph_pages::advance_graph;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Backfill,
    Rebuilding,
    Ready,
    Failed,
    Active,
    Canceled,
    Collected,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Job {
    request_id: String,
    fingerprint: String,
    phase: Phase,
    base_revision: u64,
    base_bundle_hash: Option<String>,
    bundle_hash: String,
    #[serde(skip)]
    bundle: Option<Value>,
    #[serde(skip)]
    base_schema: Schema,
    #[serde(skip)]
    schema: Schema,
    #[serde(skip)]
    added: Vec<IndexSpec>,
    #[serde(skip)]
    cleanup: Vec<IndexSpec>,
    position: usize,
    cursor: Option<String>,
    cleanup_position: usize,
    cleanup_cursor: Option<String>,
    scanned_rows: u64,
    built_entries: u64,
    #[serde(default)]
    generation: Option<String>,
    #[serde(default)]
    base_generation: Option<String>,
    #[serde(default)]
    graph_cursor: Option<String>,
    #[serde(default)]
    rebuilt_roots: u64,
    #[serde(default = "initial_graph_page_roots")]
    graph_page_roots: usize,
    #[serde(default)]
    graph_root_bytes: usize,
    #[serde(default)]
    error: Option<String>,
}
fn initial_graph_page_roots() -> usize {
    1
}
// Values/futures are declared before their leases so cancellation destroys
// their allocations before releasing coverage, including an in-flight commit.
struct Held<T> {
    value: T,
    retained: admission::Input,
}
const PLAN: &str = "deployment:plan";
fn ensure_construction_bytes(bytes: usize) -> Result<(), ApiError> {
    if bytes
        > evaluator::config::settings()
            .map_err(unavailable)?
            .rust_memory_bytes
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "EVALUATION_BUDGET",
            "staged plan construction exceeds the Rust memory budget".into(),
        ));
    }
    Ok(())
}
fn plan_construction_bytes(
    base: Option<&Value>,
    schema: &Schema,
    bundle: &Value,
) -> Result<usize, ApiError> {
    let base = base.unwrap_or(&Value::Null);
    // For this serde_json serializer, each new JSON string has its serialized
    // length's capacity, each array slot is one Value, and object entries have
    // the input_bytes 128-byte allowance. Even a one-byte scalar occupies a
    // wire token, so 128 * wire bytes bounds the new JSON tree, including
    // embedded rule operands. Count only new schema/index JSON, NOT JavaScript:
    // that allocation moves. Include native base parsing and both added-index
    // representations while the Control worker holds its Rust reservation.
    let encoded = crate::consensus::encoded_json_len(base)
        .and_then(|base| {
            crate::consensus::encoded_json_len(schema).map(|target| base.saturating_add(target))
        })
        .and_then(|schemas| {
            crate::consensus::encoded_json_len(&schema.indexes)
                .map(|indexes| schemas.saturating_add(indexes.saturating_mul(2)))
        })
        .map_err(|error| invalid(error.into()))?;
    Ok(8192usize
        .saturating_add(admission::input_bytes(bundle))
        .saturating_add(staging::schema_bytes(schema))
        .saturating_add(admission::input_bytes(base).saturating_mul(2))
        .saturating_add(encoded.saturating_mul(128)))
}
fn take_plan(job: &mut Job) -> Value {
    // Consume the heavy fields before the plan is retained across commit. In
    // particular, serialization must finish dropping the native schemas before
    // their exclusive reservation can cover the resulting JSON instead.
    Value::Object(serde_json::Map::from_iter([
        ("bundle".into(), job.bundle.take().unwrap_or(Value::Null)),
        (
            "baseSchema".into(),
            serde_json::to_value(std::mem::take(&mut job.base_schema)).expect("schema encodes"),
        ),
        (
            "schema".into(),
            serde_json::to_value(std::mem::take(&mut job.schema)).expect("schema encodes"),
        ),
        (
            "added".into(),
            serde_json::to_value(std::mem::take(&mut job.added)).expect("indexes encode"),
        ),
        (
            "cleanup".into(),
            serde_json::to_value(std::mem::take(&mut job.cleanup)).expect("indexes encode"),
        ),
    ]))
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Stage {
        #[serde(rename = "requestId")]
        request_id: String,
        bundle: Value,
    },
    Status,
    Advance {
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "maxBytes")]
        max_bytes: Option<usize>,
    },
    Activate {
        #[serde(rename = "requestId")]
        request_id: String,
    },
    Cancel {
        #[serde(rename = "requestId")]
        request_id: String,
    },
    Collect {
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "maxBytes")]
        max_bytes: Option<usize>,
    },
}
fn error(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "DEPLOYMENT_CONFLICT", message.into())
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, ApiError> {
    serde_json::from_value(value.clone()).map_err(|error| invalid(error.into()))
}
fn progress(state: &Snapshot) -> Result<Option<Job>, ApiError> {
    let job: Option<Job> = state.data.get(staging::JOB).map(decode).transpose()?;
    if let Some(job) = &job {
        for generation in [&job.generation, &job.base_generation]
            .into_iter()
            .flatten()
        {
            staging::validate_generation(generation).map_err(evaluation_error)?;
        }
        if job.generation.is_some() && job.generation == job.base_generation {
            return Err(error("staged and base graph generations must differ"));
        }
        if [job.scanned_rows, job.built_entries, job.rebuilt_roots]
            .iter()
            .any(|count| *count > 9_007_199_254_740_991)
        {
            return Err(error("deployment progress counter is not a safe integer"));
        }
        if let Some(cursor) = &job.graph_cursor {
            let prefix = job.base_generation.as_ref().map_or_else(
                || "root:".to_owned(),
                |generation| format!("graph:{generation}:root:"),
            );
            let valid = job.generation.is_some()
                && cursor
                    .strip_prefix(&prefix)
                    .and_then(|suffix| serde_json::from_str::<(String, Value)>(suffix).ok())
                    .is_some();
            if !valid {
                return Err(error(
                    "staged graph cursor is outside its root namespace or malformed",
                ));
            }
        }
    }
    Ok(job)
}
fn load(state: &Snapshot) -> Result<Option<Job>, ApiError> {
    let Some(mut job) = progress(state)? else {
        return Ok(None);
    };
    if job.phase != Phase::Collected {
        let plan = state
            .data
            .get(PLAN)
            .ok_or_else(|| error("staged deployment plan is missing"))?;
        job.base_schema = staging::schema(plan.get("baseSchema")).map_err(evaluation_error)?;
        job.schema = staging::schema(plan.get("schema")).map_err(evaluation_error)?;
        job.added = decode(&plan["added"])?;
        job.cleanup = match job.phase {
            Phase::Active => job
                .base_schema
                .indexes
                .iter()
                .filter(|index| !job.schema.indexes.contains(index))
                .cloned()
                .collect(),
            Phase::Canceled => job.added.clone(),
            _ => vec![],
        };
        // The immutable code stays borrowed in Records during native paging;
        // only activation copies it into the actual evaluator invocation.
    }
    Ok(Some(job))
}
fn status(job: &Job) -> Value {
    json!({"requestId":job.request_id,"phase":job.phase,"baseRevision":job.base_revision,
        "baseBundleHash":job.base_bundle_hash,"bundleHash":job.bundle_hash,
        "cursor":job.cursor,"scannedRows":job.scanned_rows,"builtEntries":job.built_entries,
        "generation":job.generation,"graphCursor":job.graph_cursor,"rebuiltRoots":job.rebuilt_roots,"error":job.error,
        "cleanupCursor":job.cleanup_cursor})
}
fn response(state: &Snapshot, job: Option<&Job>) -> Value {
    json!({"revision":state.revision,"value":job.map(status)})
}
pub(super) fn ensure_request_id_available(state: &Snapshot, id: &str) -> Result<(), ApiError> {
    // This check is on every writer path. Unrelated IDs need no allocation or
    // decoding of the staged job; matching metadata is validated below.
    if state
        .data
        .get(staging::JOB)
        .and_then(|job| job.get("requestId"))
        .and_then(Value::as_str)
        != Some(id)
    {
        return Ok(());
    }
    if progress(state)?.is_some_and(|job| {
        job.request_id == id
            && matches!(
                job.phase,
                Phase::Backfill | Phase::Rebuilding | Phase::Ready | Phase::Failed
            )
    }) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "REQUEST_ID_REUSED",
            "requestId is reserved by a live staged deployment".into(),
        ));
    }
    Ok(())
}
fn matching(state: &Snapshot, id: &str) -> Result<Job, ApiError> {
    load(state)?
        .filter(|job| job.request_id == id)
        .ok_or_else(|| error("staged deployment request ID does not match the current job"))
}
fn base_matches(state: &Snapshot, job: &Job) -> Result<(), ApiError> {
    if state
        .data
        .get("bundle")
        .and_then(|bundle| bundle["hash"].as_str())
        != job.base_bundle_hash.as_deref()
        || staging::schema(state.data.get("schema")).map_err(evaluation_error)? != job.base_schema
        || (job.generation.is_some() && state.data.active_graph() != job.base_generation.as_deref())
    {
        return Err(error(
            "active code or schema changed during staged deployment",
        ));
    }
    let maintained = staging::schema(state.data.get(staging::INDEXES)).map_err(evaluation_error)?;
    if maintained.indexes != job.added || !maintained.aggregates.is_empty() {
        return Err(error("staged index maintenance metadata changed"));
    }
    Ok(())
}
fn command(
    state: &Snapshot,
    job: &Job,
    puts: BTreeMap<String, Value>,
    deletes: Vec<String>,
    terminal: bool,
) -> Commit {
    let mut puts = puts;
    puts.insert(staging::JOB.into(), json!(job));
    Commit {
        internal: !terminal,
        request_id: if terminal {
            job.request_id.clone()
        } else {
            String::new()
        },
        fingerprint: if terminal {
            job.fingerprint.clone()
        } else {
            String::new()
        },
        expected_revision: state.revision,
        puts,
        deletes,
        result: if terminal { status(job) } else { Value::Null },
    }
}
fn fits(app: &App, command: &Commit) -> bool {
    crate::consensus::encoded_json_len(command)
        .is_ok_and(|bytes| bytes <= app.consensus.command_payload_limit())
}
async fn persist(app: &App, state: &Snapshot, command: Commit) -> Result<Value, ApiError> {
    persist_retained(app, state, command, None).await
}
async fn persist_retained(
    app: &App,
    state: &Snapshot,
    command: Commit,
    retained: Option<admission::Input>,
) -> Result<Value, ApiError> {
    transactions::ensure_write_capacity(state)?;
    if !fits(app, &command) {
        return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE,"TRANSACTION_TOO_LARGE","staged deployment page exceeds FLOWER_TRANSACTION_MAX_BYTES; lower maxBytes or increase the configured transaction budget".into()));
    }
    let bytes = command
        .puts
        .iter()
        .fold(512usize, |bytes, (key, value)| {
            bytes
                .saturating_add(key.capacity())
                .saturating_add(128)
                .saturating_add(admission::input_bytes(value))
        })
        .saturating_add(command.deletes.iter().fold(0usize, |bytes, key| {
            bytes.saturating_add(key.capacity()).saturating_add(32)
        }));
    let output = match retained {
        Some(mut retained) => {
            retained.retain_at_least(&app.admission, admission::Class::Control, bytes)?;
            retained
        }
        None => app.admission.retain(admission::Class::Control, bytes)?,
    };
    let mut held = Held {
        value: Box::pin(app.consensus.commit(command)),
        retained: output,
    };
    let result = held.value.as_mut().await.map_err(unavailable)?;
    Ok(json!({"revision":result.revision,"value":result.result,"duplicate":result.duplicate}))
}
fn budget(app: &App, requested: Option<usize>) -> Result<usize, ApiError> {
    let limit = requested.unwrap_or(app.consensus.limits().transaction_max_bytes);
    if limit == 0 {
        return Err(invalid(anyhow::anyhow!("maxBytes must be positive")));
    }
    Ok(limit)
}
pub(super) fn validate_admin(input: &Value) -> Result<(), ApiError> {
    let operation: Operation = decode(input)?;
    match operation {
        Operation::Stage { request_id, bundle } => {
            evaluator::validate_mutation(&json!({"requestId":request_id,"bundle":bundle}))
                .map_err(invalid)
        }
        Operation::Status => Ok(()),
        Operation::Advance {
            request_id,
            max_bytes,
        }
        | Operation::Collect {
            request_id,
            max_bytes,
        } => {
            if request_id.is_empty() || max_bytes == Some(0) {
                Err(invalid(anyhow::anyhow!(
                    "requestId must be nonempty and maxBytes positive"
                )))
            } else {
                Ok(())
            }
        }
        Operation::Activate { request_id } | Operation::Cancel { request_id } => {
            if request_id.is_empty() {
                Err(invalid(anyhow::anyhow!("requestId must be nonempty")))
            } else {
                Ok(())
            }
        }
    }
}

async fn start(app: &App, request_id: String, bundle: Value) -> Result<Value, ApiError> {
    // json! serializes by reference, including an already-owned Value. Move
    // the bundle instead of keeping a second callee copy across writer waits.
    // This is separate from administer's root-caller coverage. The local
    // bundle also lives through admission/writer waits and needs its own lease.
    let value = Value::Object(serde_json::Map::from_iter([
        ("requestId".into(), Value::String(request_id)),
        ("bundle".into(), bundle),
    ]));
    let retained = app
        .admission
        .retain(admission::Class::Control, admission::input_bytes(&value))?;
    let mut input = Held { value, retained };
    let fingerprint = authorization::fingerprint(&input.value, true, &Value::Null);
    // Analyze without pinning a live database or holding its writer. Drop the
    // worker permit before waiting for the writer, preserving admission order.
    // Deployment work takes its own class: control slots are what maintenance
    // waits for while it holds a writer.
    let permit = admission::acquire_retained(app, admission::Class::Deployment).await?;
    let analyze = input.value.clone();
    let (schema, permit) = tokio::task::spawn_blocking(move || {
        staging::analyze(analyze).map(|schema| (schema, permit))
    })
    .await
    .map_err(|error| unavailable(error.into()))?
    .map_err(evaluation_error)?;
    let retained = app
        .admission
        .retain(admission::Class::Control, staging::schema_bytes(&schema))?;
    let schema = Held {
        value: schema,
        retained,
    };
    drop(permit);
    let bundle = input
        .value
        .as_object_mut()
        .unwrap()
        .remove("bundle")
        .unwrap();
    let request_id = match input
        .value
        .as_object_mut()
        .unwrap()
        .remove("requestId")
        .unwrap()
    {
        Value::String(request_id) => request_id,
        _ => unreachable!("owned stage request ID is a string"),
    };
    let Held { value, retained } = input;
    drop(value);
    let bundle = Held {
        value: bundle,
        retained,
    };
    let _writer = app.writer.lock().await;
    let _permit = admission::acquire_retained(app, admission::Class::Control).await?;
    let state = app.consensus.read_for_writer().await.map_err(unavailable)?;
    transactions::ensure_unlocked(&state)?;
    crate::consensus::retention::require_scoped(&state, &request_id)
        .and_then(|()| {
            crate::consensus::retention::validate_request_owner(
                &state,
                &request_id,
                &authorization::owner(&Value::Null, true),
            )
        })
        .map_err(retention::error)?;
    if let Some(receipt) = state.requests.get(&request_id) {
        if receipt.fingerprint != fingerprint {
            return Err(error(
                "request ID was used for different deployment content",
            ));
        }
        return Ok(json!({"revision":receipt.revision,"value":receipt.result,"duplicate":true}));
    }
    // Existing staged metadata is decoded only under the Control worker, with
    // the same conservative JSON-plus-native bound used by schema loading.
    if let Some(plan) = state.data.get(PLAN) {
        let bytes = ["baseSchema", "schema", "added"]
            .into_iter()
            .map(|key| admission::input_bytes(&plan[key]).saturating_mul(2))
            .fold(0usize, usize::saturating_add);
        ensure_construction_bytes(bytes)?;
    }
    if let Some(job) = load(&state)? {
        if job.request_id == request_id {
            if job.fingerprint != fingerprint {
                return Err(error("request ID was used for different staged content"));
            }
            return Ok(response(&state, Some(&job)));
        }
        if job.phase != Phase::Collected {
            return Err(error(
                "collect the previous staged deployment before starting another",
            ));
        }
    }
    transactions::ensure_request_id_available(&state, &request_id)?;
    ensure_construction_bytes(plan_construction_bytes(
        state.data.get("schema"),
        &schema.value,
        &bundle.value,
    )?)?;
    let base_schema = staging::schema(state.data.get("schema")).map_err(evaluation_error)?;
    let added: Vec<_> = schema
        .value
        .indexes
        .iter()
        .filter(|index| !base_schema.indexes.contains(index))
        .cloned()
        .collect();
    let generation = evaluator::hash(
        serde_json::to_string(&json!([request_id, fingerprint]))
            .map_err(|error| invalid(error.into()))?
            .as_bytes(),
    );
    let Held {
        value: bundle,
        retained: bundle_output,
    } = bundle;
    let Held {
        value: schema,
        retained: schema_output,
    } = schema;
    let mut job = Job {
        request_id,
        fingerprint,
        phase: if added.is_empty() {
            Phase::Rebuilding
        } else {
            Phase::Backfill
        },
        base_revision: state.revision,
        base_bundle_hash: state
            .data
            .get("bundle")
            .and_then(|bundle| bundle["hash"].as_str())
            .map(str::to_owned),
        bundle_hash: bundle["hash"].as_str().unwrap().to_owned(),
        bundle: Some(bundle),
        base_schema,
        schema,
        added: added.clone(),
        cleanup: vec![],
        position: 0,
        cursor: None,
        cleanup_position: 0,
        cleanup_cursor: None,
        scanned_rows: 0,
        built_entries: 0,
        generation: Some(generation),
        base_generation: state.data.active_graph().map(str::to_owned),
        graph_cursor: None,
        rebuilt_roots: 0,
        graph_page_roots: 1,
        graph_root_bytes: 0,
        error: None,
    };
    let indexes = Schema {
        indexes: added,
        aggregates: BTreeMap::new(),
        aggregate_versions: BTreeMap::new(),
        policies: BTreeMap::new(),
        derived_access: BTreeMap::new(),
        references: Vec::new(),
    };
    let plan = take_plan(&mut job);
    let command = command(
        &state,
        &job,
        BTreeMap::from([
            (
                staging::INDEXES.into(),
                serde_json::to_value(indexes).expect("indexes encode"),
            ),
            (PLAN.into(), plan),
        ]),
        vec![],
        false,
    );
    // The native target schema is now actually destroyed; only the bundle
    // moved into the command. Grow its exclusive lease to the whole output.
    // Root-caller and ingress leases remain unchanged throughout the attempt.
    drop(schema_output);
    let committed = persist_retained(app, &state, command, Some(bundle_output)).await?;
    Ok(json!({"revision":committed["revision"],"value":status(&job)}))
}

async fn advance(app: &App, id: String, requested: Option<usize>) -> Result<Value, ApiError> {
    let max_bytes = budget(app, requested)?;
    let _writer = app.writer.lock().await;
    let permit = admission::acquire_retained(app, admission::Class::Deployment).await?;
    let state = app.consensus.read_for_writer().await.map_err(unavailable)?;
    transactions::ensure_unlocked(&state)?;
    let mut job = matching(&state, &id)?;
    if job.phase == Phase::Rebuilding {
        base_matches(&state, &job)?;
        return advance_graph(app, &state, job, max_bytes, permit).await;
    }
    if job.phase != Phase::Backfill {
        return Ok(response(&state, Some(&job)));
    }
    base_matches(&state, &job)?;
    let base = state.clone();
    let limit = app.consensus.command_payload_limit();
    let (next,puts,_permit)=tokio::task::spawn_blocking(move||{
        let deadline=Instant::now()+evaluator::config::settings().map_err(unavailable)?.evaluation_timeout;
        let mut puts=BTreeMap::new();
        let mut patch_bytes=0usize;
        let mut used=0usize;
        let mut stopped=false;
        // One index definition per cursor phase; input and output bytes both
        // count, including rows that have no indexed field.
        while job.position<job.added.len() {
            let spec=&job.added[job.position];
            let prefix=staging::source_prefix(&spec.collection);
            let bound=job.cursor.as_deref().map_or(std::ops::Bound::Included(prefix.as_str()),std::ops::Bound::Excluded);
            for (key,value) in base.data.range::<(std::ops::Bound<&str>,std::ops::Bound<&str>)>((bound,std::ops::Bound::Unbounded)).take_while(|(key,_)|key.starts_with(&prefix)) {
                if Instant::now()>=deadline {stopped=true;break;}
                let entries=staging::entries(spec,key,value).map_err(evaluation_error)?;
                let amount=key.len().saturating_add(crate::consensus::encoded_json_len(value).unwrap_or(usize::MAX))
                    .saturating_add(crate::consensus::encoded_json_len(&entries).unwrap_or(usize::MAX)).saturating_add(256);
                if used.saturating_add(amount)>max_bytes {stopped=true;break;}
                let previous=(job.cursor.clone(),job.scanned_rows,job.built_entries);
                job.cursor=Some(key.clone());
                job.scanned_rows=job.scanned_rows.checked_add(1).filter(|n|*n<=9_007_199_254_740_991).ok_or_else(||error("deployment progress counter exhausted"))?;
                job.built_entries=job.built_entries.checked_add(entries.len() as u64).filter(|n|*n<=9_007_199_254_740_991).ok_or_else(||error("deployment progress counter exhausted"))?;
                let extra=entries.iter().try_fold(0usize,|bytes,(key,value)|{
                    Ok::<_,ApiError>(bytes.saturating_add(crate::consensus::encoded_json_len(key).map_err(|error|invalid(error.into()))?)
                        .saturating_add(crate::consensus::encoded_json_len(value).map_err(|error|invalid(error.into()))?).saturating_add(2))
                })?;
                let size=crate::consensus::encoded_json_len(&command(&base,&job,BTreeMap::new(),vec![],false)).unwrap_or(usize::MAX)
                    .saturating_add(patch_bytes).saturating_add(extra);
                if size>limit {job.cursor=previous.0;job.scanned_rows=previous.1;job.built_entries=previous.2;stopped=true;break;}
                puts.extend(entries);patch_bytes=patch_bytes.saturating_add(extra);used+=amount;
            }
            if stopped{break;}
            job.position+=1;job.cursor=None;
        }
        if job.position==job.added.len(){job.phase=if job.generation.is_some(){Phase::Rebuilding}else{Phase::Ready};}
        if stopped && used==0{return Err(error("deployment page made no progress; increase maxBytes/configured budgets for a single row, or retry after transient CPU pressure"));}
        Ok::<_,ApiError>((job,puts,permit))
    }).await.map_err(|error|unavailable(error.into()))??;
    let committed = persist(app, &state, command(&state, &next, puts, vec![], false)).await?;
    Ok(json!({"revision":committed["revision"],"value":status(&next)}))
}

async fn activate(app: &App, id: String) -> Result<Value, ApiError> {
    let _writer = app.writer.lock().await;
    let permit = admission::acquire_retained(app, admission::Class::Deployment).await?;
    let state = app.consensus.read_for_writer().await.map_err(unavailable)?;
    transactions::ensure_unlocked(&state)?;
    let mut job = matching(&state, &id)?;
    crate::consensus::retention::require_scoped(&state, &id)
        .and_then(|()| {
            crate::consensus::retention::validate_request_owner(
                &state,
                &id,
                &authorization::owner(&Value::Null, true),
            )
        })
        .map_err(retention::error)?;
    if job.phase == Phase::Canceled {
        return Err(error("a canceled deployment cannot be activated"));
    }
    if matches!(job.phase, Phase::Active | Phase::Collected) {
        if let Some(receipt) = state.requests.get(&id) {
            if receipt.result["phase"] != "active" {
                return Err(error("a canceled deployment cannot be activated"));
            }
            return Ok(
                json!({"revision":receipt.revision,"value":receipt.result,"duplicate":true}),
            );
        }
        return Err(error(
            "deployment has already terminated; its retry receipt was retired",
        ));
    }
    if job.phase != Phase::Ready {
        return Err(error(
            "index and materialized-graph preparation must finish before activation",
        ));
    }
    base_matches(&state, &job)?;
    let input = json!({"requestId":id,"bundle":state.data.get(PLAN).and_then(|plan|plan.get("bundle")).filter(|bundle|!bundle.is_null()).ok_or_else(||error("staged bundle is missing"))?});
    let data = state.data.clone();
    let now = app.clock.sample(&state).map_err(unavailable)?;
    let (evaluation, _permit) = tokio::task::spawn_blocking(move || {
        staging::activate(data, input, now).map(|evaluation| (evaluation, permit))
    })
    .await
    .map_err(|error| unavailable(error.into()))?
    .map_err(evaluation_error)?;
    if staging::schema(if evaluation.deletes.iter().any(|key| key == "schema") {
        None
    } else {
        evaluation
            .puts
            .get("schema")
            .or_else(|| state.data.get("schema"))
    })
    .map_err(evaluation_error)?
        != job.schema
    {
        return Err(error("staged bundle schema changed during activation"));
    }
    job.phase = Phase::Active;
    job.cursor = None;
    job.cleanup = job
        .base_schema
        .indexes
        .iter()
        .filter(|spec| !job.schema.indexes.contains(spec))
        .cloned()
        .collect();
    let mut deletes = evaluation.deletes;
    deletes.push(staging::INDEXES.into());
    let command = command(&state, &job, evaluation.puts, deletes, true);
    crate::consensus::retention::validate_capacity_for(
        &state,
        &job.request_id,
        &job.fingerprint,
        &command.result,
        0,
    )
    .map_err(retention::error)?;
    persist(app, &state, command).await
}
async fn cancel(app: &App, id: String) -> Result<Value, ApiError> {
    let _writer = app.writer.lock().await;
    let _permit = admission::acquire_retained(app, admission::Class::Control).await?;
    let state = app.consensus.read_for_writer().await.map_err(unavailable)?;
    transactions::ensure_unlocked(&state)?;
    let mut job = matching(&state, &id)?;
    if matches!(job.phase, Phase::Canceled | Phase::Collected) {
        return Ok(response(&state, Some(&job)));
    }
    if job.phase == Phase::Active {
        return Err(error(
            "an activated deployment cannot be canceled; stage a new deployment to roll forward",
        ));
    }
    base_matches(&state, &job)?;
    // Retirement may happen during a long build. It forbids activation, but
    // must not prevent cancellation: the permanent retry fence already prevents
    // this request ID from acquiring new effects after cleanup.
    // Epoch/history fences precede session lookup: once an old session has
    // been collected, owner lookup alone cannot distinguish it from an unknown
    // live session. Only irreversible retry rejection authorizes this escape.
    let retired = match crate::consensus::retention::require_scoped(&state, &id)
        .and_then(|()| crate::consensus::retention::validate_request(&state, &id))
    {
        Ok(()) => false,
        Err(reason) => {
            let reason = retention::error(reason);
            if !matches!(
                reason.code,
                "HISTORY_MISMATCH"
                    | "RETRY_WINDOW_EXPIRED"
                    | "ALREADY_ACKNOWLEDGED"
                    | "RETRY_SESSION_CLOSED"
                    | "REQUEST_ID_SCOPE_REQUIRED"
            ) {
                return Err(reason);
            }
            true
        }
    };
    if !retired {
        crate::consensus::retention::validate_request_owner(
            &state,
            &id,
            &authorization::owner(&Value::Null, true),
        )
        .map_err(retention::error)?;
    }
    job.phase = Phase::Canceled;
    job.cleanup = job.added.clone();
    job.cursor = None;
    let command = command(
        &state,
        &job,
        BTreeMap::new(),
        vec![staging::INDEXES.into()],
        !retired,
    );
    if !retired {
        crate::consensus::retention::validate_capacity_for(
            &state,
            &job.request_id,
            &job.fingerprint,
            &command.result,
            0,
        )
        .map_err(retention::error)?;
    }
    let committed = persist(app, &state, command).await?;
    Ok(
        json!({"revision":committed["revision"],"value":status(&job),"duplicate":committed["duplicate"]}),
    )
}
async fn collect(app: &App, id: String, requested: Option<usize>) -> Result<Value, ApiError> {
    let max_bytes = budget(app, requested)?;
    let _writer = app.writer.lock().await;
    let _permit = admission::acquire_retained(app, admission::Class::Deployment).await?;
    let state = app.consensus.read_for_writer().await.map_err(unavailable)?;
    transactions::ensure_unlocked(&state)?;
    let mut job = matching(&state, &id)?;
    if job.phase == Phase::Collected {
        return Ok(response(&state, Some(&job)));
    }
    if !matches!(job.phase, Phase::Active | Phase::Canceled) {
        return Err(error("activate or cancel before collecting staged indexes"));
    }
    let active = staging::schema(state.data.get("schema")).map_err(evaluation_error)?;
    if job.cleanup.iter().any(|spec| active.indexes.contains(spec)) {
        return Err(error("cleanup would remove an active/shared index"));
    }
    let mut prefixes: Vec<_> = job.cleanup.iter().flat_map(staging::prefixes).collect();
    if let Some(generation) = &job.generation {
        if job.phase == Phase::Canceled {
            if state.data.active_graph() == Some(generation.as_str()) {
                return Err(error("cleanup would remove the active graph"));
            }
            prefixes.push(format!("graph:{generation}:"));
        } else if let Some(previous) = &job.base_generation {
            if state.data.active_graph() == Some(previous.as_str()) {
                return Err(error("cleanup would remove the active graph"));
            }
            prefixes.push(format!("graph:{previous}:"));
        } else {
            if state.data.active_graph().is_none() {
                return Err(error("cleanup would remove the active legacy graph"));
            }
            prefixes.extend([
                "cell:".into(),
                "root:".into(),
                "clock".into(),
                "reader:".into(),
                "height:".into(),
            ]);
        }
    }
    let mut deletes = Vec::new();
    let mut deletion_bytes = 0usize;
    let mut used = 0usize;
    let mut stopped = false;
    let deadline = Instant::now()
        + evaluator::config::settings()
            .map_err(unavailable)?
            .evaluation_timeout;
    while job.cleanup_position < prefixes.len() {
        let prefix = &prefixes[job.cleanup_position];
        let bound = job.cleanup_cursor.as_deref().map_or(
            std::ops::Bound::Included(prefix.as_str()),
            std::ops::Bound::Excluded,
        );
        for (key, value) in state
            .data
            .range::<(std::ops::Bound<&str>, std::ops::Bound<&str>)>((
                bound,
                std::ops::Bound::Unbounded,
            ))
            .take_while(|(key, _)| key.starts_with(prefix))
        {
            let amount = key
                .len()
                .saturating_add(crate::consensus::encoded_json_len(value).unwrap_or(usize::MAX))
                .saturating_add(128);
            if used.saturating_add(amount) > max_bytes || Instant::now() >= deadline {
                stopped = true;
                break;
            }
            let previous = job.cleanup_cursor.replace(key.clone());
            let next_bytes = deletion_bytes
                .saturating_add(
                    crate::consensus::encoded_json_len(key)
                        .map_err(|error| invalid(error.into()))?,
                )
                .saturating_add(usize::from(!deletes.is_empty()));
            let size = crate::consensus::encoded_json_len(&command(
                &state,
                &job,
                BTreeMap::new(),
                vec![],
                false,
            ))
            .unwrap_or(usize::MAX)
            .saturating_add(next_bytes);
            if size > app.consensus.command_payload_limit() {
                job.cleanup_cursor = previous;
                stopped = true;
                break;
            }
            deletes.push(key.clone());
            deletion_bytes = next_bytes;
            used += amount;
        }
        if stopped {
            break;
        }
        job.cleanup_position += 1;
        job.cleanup_cursor = None;
    }
    if stopped && deletes.is_empty() {
        return Err(error(
            "cleanup page made no progress; increase maxBytes or configured transaction budget",
        ));
    }
    if job.cleanup_position == prefixes.len() {
        let previous = job.phase;
        job.phase = Phase::Collected;
        deletes.push(PLAN.into());
        if !fits(
            app,
            &command(&state, &job, BTreeMap::new(), deletes.clone(), false),
        ) {
            job.phase = previous;
            deletes.pop();
        }
    }
    let committed = persist(
        app,
        &state,
        command(&state, &job, BTreeMap::new(), deletes, false),
    )
    .await?;
    Ok(json!({"revision":committed["revision"],"value":status(&job)}))
}

pub(super) async fn administer(app: &App, input: Value) -> Result<Value, ApiError> {
    validate_admin(&input)?;
    let _input = app
        .admission
        .retain(admission::Class::Control, admission::input_bytes(&input))?;
    // Keep this lease until the entire operation completes: the root router
    // retains its input clone for leader-change forwarding. Consuming our copy
    // must not credit that other holder's allocation.
    match serde_json::from_value(input).map_err(|error| invalid(error.into()))? {
        Operation::Stage { request_id, bundle } => start(app, request_id, bundle).await,
        Operation::Status => {
            let _permit = admission::acquire_retained(app, admission::Class::Control).await?;
            let state = app.consensus.read_query().await.map_err(unavailable)?;
            let job = progress(&state)?;
            Ok(response(&state, job.as_ref()))
        }
        Operation::Advance {
            request_id,
            max_bytes,
        } => advance(app, request_id, max_bytes).await,
        Operation::Activate { request_id } => activate(app, request_id).await,
        Operation::Cancel { request_id } => cancel(app, request_id).await,
        Operation::Collect {
            request_id,
            max_bytes,
        } => collect(app, request_id, max_bytes).await,
    }
}

#[cfg(test)]
mod tests;
