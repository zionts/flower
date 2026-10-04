use super::{Host, failure_parts, max_json_bytes};
use crate::evaluator::wire::{self, Reply};
use anyhow::{Result, bail, ensure};
use serde_json::Value;
use wasmtime::{Caller, Engine, Linker};

type HostCall<'a> = dyn FnMut(&str, Value) -> Result<Reply> + 'a;

#[cfg(feature = "sql")]
pub(super) const MAX_ENCODED_BYTES: usize = 1024 * 1024;

/// SQL-only synchronous byte transport. `input` and `outcome` borrow a suspended
/// guest, whereas the returned outcome MUST borrow the host (typically its
/// admitted fixed output slab), never the guest's argument bytes. A safe
/// implementation cannot retain an input/outcome slice beyond the call.
#[cfg(feature = "sql")]
pub(in crate::evaluator) trait EncodedHost {
    fn call<'a>(&'a mut self, operation: &str, input: &[u8]) -> Result<&'a [u8]>;
    fn finish(&mut self, outcome: &[u8]) -> Result<()>;
}

#[derive(Clone, Copy)]
enum Dispatch {
    Value(unsafe fn(*mut (), &str, Value) -> Result<Reply>),
    #[cfg(feature = "sql")]
    Encoded(for<'a> unsafe fn(&'a mut *mut (), &str, &[u8]) -> Result<&'a [u8]>),
}

#[derive(Clone, Copy)]
pub(super) struct Callback {
    data: *mut (),
    dispatch: Dispatch,
}
impl Callback {
    /// Caller must keep the borrowed bridge alive for every synchronous guest
    /// Store that contains this token. Tokens are detached or their Store is
    /// dropped before execute() returns; a recycled Store never retains one.
    pub(super) unsafe fn scoped(bridge: &mut &mut HostCall<'_>) -> Self {
        unsafe fn dispatch(data: *mut (), method: &str, args: Value) -> Result<Reply> {
            // SAFETY: execute owns the pointed-to bridge on its stack, and
            // synchronous Wasmtime callbacks cannot outlive that scope.
            let callback = unsafe { &mut *(data as *mut &mut HostCall<'static>) };
            callback(method, args)
        }
        Self {
            data: (bridge as *mut &mut HostCall<'_>).cast(),
            dispatch: Dispatch::Value(dispatch),
        }
    }
    #[cfg(feature = "sql")]
    pub(super) unsafe fn scoped_encoded(bridge: &mut &mut dyn EncodedHost) -> Self {
        unsafe fn dispatch<'a>(
            data: &'a mut *mut (),
            method: &str,
            input: &[u8],
        ) -> Result<&'a [u8]> {
            // SAFETY: execute_prepared_encoded keeps this stack-local bridge
            // alive until all synchronous uses stop and the token is detached.
            // The erased trait-object lifetime does not grant retention: the
            // response is reborrowed only for `data`, not `input`, and is copied
            // into the guest before any other call can mutate the host arena.
            let callback = unsafe { &mut *(*data as *mut &mut dyn EncodedHost) };
            callback.call(method, input)
        }
        Self {
            data: (bridge as *mut &mut dyn EncodedHost).cast(),
            dispatch: Dispatch::Encoded(dispatch),
        }
    }
    #[cfg(feature = "sql")]
    pub(super) fn is_encoded(self) -> bool {
        matches!(self.dispatch, Dispatch::Encoded(_))
    }
    #[cfg(feature = "sql")]
    pub(super) unsafe fn invoke_encoded<'a>(
        &'a mut self,
        method: &str,
        input: &[u8],
    ) -> Result<&'a [u8]> {
        let Dispatch::Encoded(call) = self.dispatch else {
            bail!("owned callback cannot accept encoded arguments");
        };
        // SAFETY: same scope as scoped_encoded; the result's borrow is tied
        // to this local token, explicitly not to the guest input memory.
        unsafe { call(&mut self.data, method, input) }
    }
    pub(super) unsafe fn invoke(self, method: &str, args: Value) -> Result<Reply> {
        match self.dispatch {
            // SAFETY: same scoped execution invariant as scoped().
            Dispatch::Value(call) => unsafe { call(self.data, method, args) },
            #[cfg(feature = "sql")]
            Dispatch::Encoded(_) => bail!("encoded callback cannot accept owned values"),
        }
    }
    /// `invoke` for Rust callers that read the result as owned JSON.
    pub(super) unsafe fn invoke_value(self, method: &str, args: Value) -> Result<Value> {
        // SAFETY: same scoped execution invariant as scoped().
        unsafe { self.invoke(method, args) }.map(Reply::into_value)
    }
}

/// Operation numbers from GUEST_ABI.md. Native-only operations, such as
/// resolving managed keys for the crypto bridge, have no number.
fn operation(op: i32) -> Result<&'static str> {
    Ok(match op {
        1 => "now",
        2 => "principal",
        3 => "history",
        4 => "get",
        5 => "scan",
        6 => "range",
        7 => "query",
        8 => "set",
        9 => "delete",
        10 => "materialize",
        11 => "unmaterialize",
        12 => "clock",
        13 => "changesAt",
        14 => "definer",
        15 => "sql",
        16 => "codeVersion",
        17 => "requireCommitBefore",
        _ => bail!("unknown host operation {op}"),
    })
}

fn host_call(
    mut caller: Caller<'_, Host>,
    op: i32,
    payload_pointer: i32,
    payload_length: i32,
) -> wasmtime::Result<i64> {
    (|| -> Result<i64> {
        caller.data().shared.check()?;
        let abi = caller
            .data()
            .abi
            .clone()
            .ok_or_else(|| anyhow::anyhow!("guest ABI not bound"))?;
        let method = operation(op)?;
        #[cfg(feature = "sql")]
        if let Some(mut callback) = caller
            .data()
            .callback
            .filter(|callback| callback.is_encoded())
        {
            let input = abi.arguments_bytes(&caller, payload_pointer, payload_length)?;
            // SAFETY: execute_prepared_encoded owns the scoped bridge. Input is
            // borrowed from the suspended guest only for this call; response
            // borrows the local token/host instead, so this borrow ends before
            // the guest allocator can move memory. No Value/Vec is constructed.
            let response = unsafe { callback.invoke_encoded(method, input) }?;
            caller.data().shared.check()?;
            ensure!(
                response.len() <= MAX_ENCODED_BYTES,
                "SQL_WIRE_CAPACITY: host outcome exceeds the admitted wire limit"
            );
            return abi.response(&mut caller, response);
        }
        let response = match abi.arguments(&caller, payload_pointer, payload_length)? {
            Err(invalid) => wire::failure("INVALID_VALUE", invalid.0, None),
            Ok(arguments) => {
                let callback = caller.data().callback.ok_or_else(|| {
                    anyhow::anyhow!("database access is unavailable during bundle initialization")
                })?;
                // SAFETY: callbacks can only be bound by execute, which holds the
                // borrowed bridge until this Store has been dropped or completely
                // reset. Take a copy of the token, releasing the Host borrow
                // before nested calls can execute.
                let result = unsafe { callback.invoke(method, Value::Array(arguments)) };
                caller.data().shared.check()?;
                match result {
                    Ok(reply) => wire::success_reply(&reply)?,
                    Err(error) => {
                        let (code, message, details) = failure_parts(error);
                        wire::failure(&code, &message, details.as_ref())
                    }
                }
            }
        };
        ensure!(
            response.len() <= max_json_bytes()?,
            "host result exceeds FLOWER_RESULT_MAX_BYTES"
        );
        abi.response(&mut caller, &response)
    })()
    .map_err(wasmtime::Error::from_anyhow)
}

pub(super) fn linker(engine: &Engine) -> Result<Linker<Host>> {
    let mut linker = Linker::new(engine);
    linker.func_wrap("flower", "host_call", host_call)?;
    linker.func_wrap("flower", "crypto_call", super::crypto::call)?;
    Ok(linker)
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_numbered_operations_reach_the_database() {
        assert_eq!(super::operation(4).unwrap(), "get");
        assert_eq!(super::operation(11).unwrap(), "unmaterialize");
        assert_eq!(super::operation(12).unwrap(), "clock");
        assert_eq!(super::operation(13).unwrap(), "changesAt");
        assert_eq!(super::operation(14).unwrap(), "definer");
        assert_eq!(super::operation(15).unwrap(), "sql");
        assert_eq!(super::operation(16).unwrap(), "codeVersion");
        assert_eq!(super::operation(17).unwrap(), "requireCommitBefore");
        for op in [0, 18, -1, i32::MAX] {
            assert!(super::operation(op).is_err(), "{op}");
        }
    }
}
