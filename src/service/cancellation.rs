//! Cancellation bound to actual admitted work, never client-supplied authority.
//! SQL query/cancel operations remain ordinary authorized application aliases.
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Owned by the request future: dropping it cancels the still-running closure,
/// but does not release the admission lease that closure continues to hold.
pub(super) struct Request(Arc<AtomicBool>);
impl Request {
    pub(super) fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
    pub(super) fn token(&self) -> Arc<AtomicBool> {
        self.0.clone()
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[cfg(any(feature = "sql", test))]
pub(crate) use native::scope;
#[cfg(feature = "sql")]
pub(crate) use native::{bind_effective, cancel, register};

#[cfg(any(feature = "sql", test))]
mod native {
    #[cfg(test)]
    use super::Request;
    use anyhow::{Result, bail, ensure};
    use serde_json::Value;
    use std::{
        cell::RefCell,
        collections::BTreeMap,
        marker::PhantomData,
        rc::Rc,
        sync::{
            Arc, Mutex, OnceLock,
            atomic::{AtomicBool, Ordering},
        },
    };
    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct Key {
        partition: Option<String>,
        principal: String,
        query_id: String,
    }
    struct Context {
        partition: Option<String>,
        principal: Value,
        binding: Option<(Value, Value)>,
        token: Arc<AtomicBool>,
        registered: Option<Key>,
    }
    thread_local! {
        static CONTEXT: RefCell<Option<Context>> = const { RefCell::new(None) };
    }
    fn registry() -> &'static Mutex<BTreeMap<Key, Arc<AtomicBool>>> {
        static REGISTRY: OnceLock<Mutex<BTreeMap<Key, Arc<AtomicBool>>>> = OnceLock::new();
        REGISTRY.get_or_init(Mutex::default)
    }

    /// Kept until the blocking closure exits, including cancellation unwind.
    /// Not Send: the trusted scope belongs to the current thread.
    pub(crate) struct Scope {
        previous: Option<Context>,
        _thread: PhantomData<Rc<()>>,
    }
    pub(crate) fn scope(
        partition: Option<&str>,
        principal: Value,
        token: Arc<AtomicBool>,
    ) -> Scope {
        let previous = CONTEXT.with(|context| {
            context.replace(Some(Context {
                partition: partition.map(str::to_owned),
                principal,
                binding: None,
                token,
                registered: None,
            }))
        });
        Scope {
            previous,
            _thread: PhantomData,
        }
    }
    impl Drop for Scope {
        fn drop(&mut self) {
            let removed = CONTEXT.with(|context| context.replace(self.previous.take()));
            if let Some(Context {
                registered: Some(key),
                token,
                ..
            }) = removed
            {
                let mut active = registry().lock().expect("query cancellation registry");
                if active
                    .get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &token))
                {
                    active.remove(&key);
                }
            }
        }
    }
    fn key(context: &Context, query_id: &str) -> Result<Key> {
        ensure!(
            !context.principal.is_null(),
            "SQL_CANCEL_FORBIDDEN: authenticated principal required"
        );
        ensure!(
            !query_id.is_empty() && query_id.len() <= 256,
            "SQL_QUERY_ID_INVALID: queryId must contain 1 to 256 bytes"
        );
        Ok(Key {
            partition: context.partition.clone(),
            // Keep the original authenticated principal as well as any
            // authority-narrowed principal and validated purpose. An authority
            // mapping two callers to one effective subject cannot merge their
            // cancellation namespaces.
            principal: serde_json::to_string(&(&context.principal, &context.binding))?,
            query_id: query_id.to_owned(),
        })
    }

    /// Bind only a deployed native authority decision, before registering/cancelling an ID.
    /// The effective principal AND validated purpose fence the cancellation namespace.
    pub(crate) fn bind_effective(principal: &Value, purpose: &Value) -> Result<()> {
        CONTEXT.with(|context| {
            let mut context = context.borrow_mut();
            let Some(context) = context.as_mut() else {
                bail!("SQL_CANCEL_UNAVAILABLE: no admitted query scope");
            };
            ensure!(
                context.registered.is_none(),
                "SQL_QUERY_ID_IN_USE: cannot rebind an active worker"
            );
            ensure!(
                principal
                    .get("subject")
                    .and_then(Value::as_str)
                    .is_some_and(|subject| !subject.is_empty() && subject != "$anonymous"),
                "SQL_CANCEL_FORBIDDEN: effective authenticated principal required"
            );
            context.binding = Some((principal.clone(), purpose.clone()));
            Ok(())
        })
    }

    /// Native SQL host registration, not generic alias args (cancel also takes ID).
    /// At most one ID per admitted worker; an active ID is never overwritten, and
    /// remains reserved until the worker exits, not merely until the VM returns.
    pub(crate) fn register(query_id: &str) -> Result<()> {
        CONTEXT.with(|context| {
            let mut context = context.borrow_mut();
            let Some(context) = context.as_mut() else {
                bail!("SQL_CANCEL_UNAVAILABLE: no admitted query scope")
            };
            ensure!(
                context.registered.is_none(),
                "SQL_QUERY_ID_IN_USE: worker already registered a queryId"
            );
            let key = key(context, query_id)?;
            let mut active = registry().lock().expect("query cancellation registry");
            ensure!(
                !active.contains_key(&key),
                "SQL_QUERY_ID_IN_USE: queryId already executing"
            );
            active.insert(key.clone(), context.token.clone());
            context.registered = Some(key);
            Ok(())
        })
    }

    /// Native SQL cancel host operation in an ordinary authorized query alias.
    /// Authority is read from this worker's scope; no principal argument is accepted.
    pub(crate) fn cancel(query_id: &str) -> Result<bool> {
        CONTEXT.with(|context| {
            let context = context.borrow();
            let Some(context) = context.as_ref() else {
                bail!("SQL_CANCEL_UNAVAILABLE: no admitted query scope")
            };
            let key = key(context, query_id)?;
            let active = registry().lock().expect("query cancellation registry");
            let Some(token) = active.get(&key) else {
                return Ok(false);
            };
            token.store(true, Ordering::Release);
            Ok(true)
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;
        #[test]
        fn query_ids_are_scoped_to_partition_and_complete_authenticated_principal() {
            let token = Arc::new(AtomicBool::new(false));
            let owner = json!({"subject":"alice","purpose":"human"});
            let _job = scope(Some("scope-partition"), owner.clone(), token.clone());
            register("same-id").unwrap();
            for (partition, principal) in [
                (Some("other-partition"), owner.clone()),
                (
                    Some("scope-partition"),
                    json!({"subject":"bob","purpose":"human"}),
                ),
                (
                    Some("scope-partition"),
                    json!({"subject":"alice","purpose":"agent"}),
                ),
            ] {
                let _caller = scope(partition, principal, Arc::new(AtomicBool::new(false)));
                assert!(!cancel("same-id").unwrap());
                assert!(!token.load(Ordering::Acquire));
            }
            assert!(cancel("same-id").unwrap());
            assert!(token.load(Ordering::Acquire));
            let _anonymous = scope(
                Some("scope-partition"),
                Value::Null,
                Arc::new(AtomicBool::new(false)),
            );
            assert!(cancel("same-id").is_err());
        }
        #[test]
        fn effective_authority_and_purpose_narrow_but_never_replace_authenticated_identity() {
            let token = Arc::new(AtomicBool::new(false));
            let original = json!({"subject":"original-owner","tenant":"t"});
            let effective = json!({"subject":"effective-shared","tenant":"t"});
            let purpose = json!({"generation":"g1"});
            let _job = scope(Some("effective-partition"), original.clone(), token.clone());
            bind_effective(&effective, &purpose).unwrap();
            register("effective-id").unwrap();
            for (authenticated, binding, purpose) in [
                (
                    json!({"subject":"other-caller","tenant":"t"}),
                    effective.clone(),
                    purpose.clone(),
                ),
                (
                    original.clone(),
                    json!({"subject":"other-effective","tenant":"t"}),
                    purpose.clone(),
                ),
                (
                    original.clone(),
                    effective.clone(),
                    json!({"generation":"g2"}),
                ),
            ] {
                let _caller = scope(
                    Some("effective-partition"),
                    authenticated,
                    Arc::new(AtomicBool::new(false)),
                );
                bind_effective(&binding, &purpose).unwrap();
                assert!(!cancel("effective-id").unwrap());
            }
            assert!(!token.load(Ordering::Acquire));
            let _caller = scope(
                Some("effective-partition"),
                original,
                Arc::new(AtomicBool::new(false)),
            );
            bind_effective(&effective, &purpose).unwrap();
            bind_effective(&effective, &purpose).unwrap();
            assert!(
                cancel("effective-id").unwrap(),
                "rebinding the same unregistered alias is idempotent"
            );
            assert!(token.load(Ordering::Acquire));
        }

        #[test]
        fn query_id_cannot_be_reused_until_worker_scope_exits() {
            let owner = json!({"subject":"query-id-owner"});
            let job = scope(
                Some("reuse-partition"),
                owner.clone(),
                Arc::new(AtomicBool::new(false)),
            );
            register("active-id").unwrap();
            {
                let _second = scope(
                    Some("reuse-partition"),
                    owner.clone(),
                    Arc::new(AtomicBool::new(false)),
                );
                assert!(register("active-id").is_err());
                assert!(cancel("active-id").unwrap());
                assert!(
                    register("active-id").is_err(),
                    "cancel must not free the active ID"
                );
            }
            drop(job);
            let _second = scope(
                Some("reuse-partition"),
                owner,
                Arc::new(AtomicBool::new(false)),
            );
            register("active-id").unwrap();
        }
        #[test]
        fn request_drop_cancels_but_worker_scope_owns_registration() {
            let request = Request::new();
            let token = request.token();
            let _worker = scope(
                Some("drop-partition"),
                json!({"subject":"owner"}),
                token.clone(),
            );
            register("active-id").unwrap();
            drop(request);
            assert!(token.load(Ordering::Acquire));
            assert!(register("another-id").is_err());
        }
        #[tokio::test]
        async fn dropping_request_keeps_admission_until_blocking_cleanup_finishes() {
            use crate::service::admission::{Class, Pool};
            let pool = Pool::new([1, 1], [1, 1], [4096, 4096], 1);
            let admitted = pool
                .acquire("cancel-test".into(), Class::User, 0)
                .await
                .unwrap();
            let (started, ready) = tokio::sync::oneshot::channel();
            let (inspect, inspect_rx) = std::sync::mpsc::channel();
            let (observed, cancelled) = tokio::sync::oneshot::channel();
            let (finish, finish_rx) = std::sync::mpsc::channel();
            let (exited, done) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let request = Request::new();
                let token = request.token();
                tokio::task::spawn_blocking(move || {
                    let scope = scope(
                        Some("permit-partition"),
                        json!({"subject":"owner"}),
                        token.clone(),
                    );
                    register("active-id").unwrap();
                    started.send(()).unwrap();
                    inspect_rx.recv().unwrap();
                    observed.send(token.load(Ordering::Acquire)).unwrap();
                    finish_rx.recv().unwrap();
                    drop(scope);
                    drop(admitted);
                    exited.send(()).unwrap();
                })
                .await
                .unwrap();
            });
            ready.await.unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            inspect.send(()).unwrap();
            assert!(cancelled.await.unwrap());
            assert_eq!(pool.metrics()["classes"][0]["active"], 1);
            assert_eq!(pool.metrics()["classes"][0]["reservedEvaluationBytes"], 1);
            finish.send(()).unwrap();
            done.await.unwrap();
            assert_eq!(pool.metrics()["classes"][0]["active"], 0);
        }

        #[test]
        fn native_cancel_requires_trusted_scope_and_bounded_id() {
            assert!(cancel("id").is_err());
            let _worker = scope(
                None,
                json!({"subject":"owner"}),
                Arc::new(AtomicBool::new(false)),
            );
            assert!(register("").is_err());
            assert!(register(&"x".repeat(257)).is_err());
            assert!(cancel(&"x".repeat(257)).is_err());
        }
    }
}
