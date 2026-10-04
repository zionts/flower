//! Real Wasmtime/QuickJS raw callback tests using admitted fixed arenas.
use super::*;
use crate::evaluator::sql_bridge::{WireArena, WireId, WireLimits, WireOutcome};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

type Call = dyn FnMut(&str, &[u8], &WireArena, WireId, &mut WireArena) -> Result<WireOutcome>;

fn arena() -> WireArena {
    WireArena::new(WireLimits {
        message_bytes: 64 * 1024,
        text_bytes: 256 * 1024,
        nodes: 4096,
        keys: 4096,
        logical_key_bytes: 1024 * 1024,
        output_bytes: 64 * 1024,
        depth: 64,
        job_work: 8 * 1024 * 1024,
    })
    .unwrap()
}

struct BoundedHost<'a> {
    input: WireArena,
    output: WireArena,
    on_call: &'a mut Call,
    outcome: Option<WireOutcome>,
    calls: usize,
    finishes: usize,
}
impl<'a> BoundedHost<'a> {
    fn new(on_call: &'a mut Call) -> Self {
        Self {
            input: arena(),
            output: arena(),
            on_call,
            outcome: None,
            calls: 0,
            finishes: 0,
        }
    }
    fn success_json(&mut self) -> &[u8] {
        let WireOutcome::Success(value) = self.outcome.unwrap() else {
            panic!("expected success")
        };
        self.input.json(value).unwrap()
    }
    fn failure_code(&self) -> &str {
        let WireOutcome::Failure { code, .. } = self.outcome.unwrap() else {
            panic!("expected failure")
        };
        self.input.value(code).unwrap().as_str().unwrap()
    }
}
impl EncodedHost for BoundedHost<'_> {
    fn call<'a>(&'a mut self, operation: &str, input: &[u8]) -> Result<&'a [u8]> {
        self.calls += 1;
        self.input.reset_checked(&mut || Ok(()))?;
        let root = self.input.decode_arguments_checked(input, &mut || Ok(()))?;
        self.output.reset_checked(&mut || Ok(()))?;
        let outcome = (self.on_call)(operation, input, &self.input, root, &mut self.output)?;
        let response = self
            .output
            .encode_outcome_checked(outcome, &mut || Ok(()))?;
        // A host reply borrows a fixed host slab, never the guest input. This
        // disjointness remains true if response allocation grows linear memory.
        let guest = input.as_ptr() as usize..input.as_ptr() as usize + input.len();
        let host = response.as_ptr() as usize..response.as_ptr() as usize + response.len();
        assert!(guest.end <= host.start || host.end <= guest.start);
        Ok(response)
    }
    fn finish(&mut self, outcome: &[u8]) -> Result<()> {
        self.finishes += 1;
        self.input.reset_checked(&mut || Ok(()))?;
        self.outcome = Some(self.input.decode_outcome_checked(outcome, &mut || Ok(()))?);
        Ok(())
    }
}

fn source(kind: &str, compute: &str, static_init: bool) -> String {
    let definition = if kind == "sqlPlan" {
        "queryMethod"
    } else {
        kind
    };
    let terminal = if kind == "sqlPlan" {
        "terminal:{},"
    } else {
        ""
    };
    format!(
        "{}var __flowerBundle={{default:{{definitions:{{test:{{name:'test',kind:'{definition}',{terminal}compute:{compute}",
        if static_init { STATIC_INIT_MARKER } else { "" }
    ) + "}},http:{}}};"
}

#[test]
fn native_encoded_plans_and_finalizers_have_readless_principal_surfaces() {
    for kind in ["sqlPlan", "sqlFinalizer"] {
        for static_init in [false, true] {
            let code = source(
                kind,
                "(ctx,args)=>[args,Object.isFrozen(ctx),typeof ctx.get,typeof ctx.set,typeof ctx.sql,ctx.principal(),ctx.clock(),ctx.codeVersion()]",
                static_init,
            );
            let prepared = prepare(&code, tests::limits()).unwrap();
            let mut call =
                |operation: &str, bytes: &[u8], input: &WireArena, root, output: &mut WireArena| {
                    assert!(
                        bytes.is_empty(),
                        "no synthetic ARRAY header on native host arguments"
                    );
                    assert_eq!(input.value(root)?.len(), Some(0));
                    let value = match operation {
                        "principal" => {
                            let value = output.object()?;
                            let subject = output.text("verified🌸")?;
                            output.insert(value, "subject", subject)?;
                            value
                        }
                        "clock" => output.integer(1000)?,
                        "codeVersion" => output.text("generation")?,
                        _ => panic!("readless context escaped: {operation}"),
                    };
                    Ok(WireOutcome::Success(value))
                };
            let mut host = BoundedHost::new(&mut call);
            execute_prepared_encoded(
                &prepared,
                "test",
                &[wire::NULL],
                kind,
                &mut host,
                tests::limits(),
            )
            .unwrap();
            assert_eq!(host.calls, 3);
            assert_eq!(host.finishes, 1);
            assert_eq!(host.success_json(), "[null,true,\"undefined\",\"undefined\",\"undefined\",{\"subject\":\"verified🌸\"},1000,\"generation\"]".as_bytes());
        }
    }
}

#[test]
fn native_encoded_get_keeps_unicode_and_concat_keys_for_each_call() {
    for kind in ["sqlAuthority", "sqlProvider"] {
        let code = source(
            kind,
            "ctx=>{const out=[];for(let i=0;i<3;i++)out.push(ctx.get({kind:'collection',name:'字🌻'},{kind:'collection',name:'a\\u0000b'}));return out}",
            true,
        );
        let prepared = prepare(&code, tests::limits()).unwrap();
        let mut call =
            |operation: &str, bytes: &[u8], input: &WireArena, root, output: &mut WireArena| {
                assert_eq!(operation, "get");
                assert_eq!(
                    bytes[0],
                    wire::MAP,
                    "host payload is concatenated, not ARRAY framed"
                );
                assert!(bytes.windows(5).any(|b| b == [wire::KEY, 0, 0, 0, 0]));
                assert!(bytes.windows(5).any(|b| b == [wire::KEY, 1, 0, 0, 0]));
                let args = input.value(root)?;
                assert_eq!(args.len(), Some(2));
                let target = args.index(0).unwrap();
                assert_eq!(target.member("name").unwrap().as_str(), Some("字🌻"));
                let second = args.index(1).unwrap();
                assert_eq!(second.member("kind").unwrap().as_str(), Some("collection"));
                assert_eq!(second.member("name").unwrap().as_str(), Some("a\0b"));
                let result = output.object()?;
                let text = output.text("payload\0é")?;
                output.insert(result, "😀", text)?;
                let number = output.integer(2)?;
                output.insert(result, "\u{e000}", number)?;
                Ok(WireOutcome::Success(result))
            };
        let mut host = BoundedHost::new(&mut call);
        execute_prepared_encoded(
            &prepared,
            "test",
            &[wire::NULL],
            kind,
            &mut host,
            tests::limits(),
        )
        .unwrap();
        assert_eq!(host.calls, 3);
        assert_eq!(host.success_json(), "[{\"😀\":\"payload\\u0000é\",\"\u{e000}\":2},{\"😀\":\"payload\\u0000é\",\"\u{e000}\":2},{\"😀\":\"payload\\u0000é\",\"\u{e000}\":2}]".as_bytes());
    }
}

#[test]
fn native_encoded_kinds_and_business_outcomes_are_transport_not_owned_values() {
    let prepared = prepare(&source("sqlAuthority", "()=>null", true), tests::limits()).unwrap();
    let mut no_call =
        |_: &str, _: &[u8], _: &WireArena, _, _: &mut WireArena| panic!("unexpected host call");
    let mut host = BoundedHost::new(&mut no_call);
    let error = execute_prepared_encoded(
        &prepared,
        "test",
        &[wire::NULL],
        "query",
        &mut host,
        tests::limits(),
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("SQL_KIND_INVALID:"));
    assert_eq!(host.finishes, 0);
    execute_prepared_encoded(
        &prepared,
        "test",
        &[wire::NULL],
        "sqlPlan",
        &mut host,
        tests::limits(),
    )
    .unwrap();
    assert_eq!(host.failure_code(), "METHOD_KIND_MISMATCH");
    let prepared = prepare(
        &source(
            "sqlAuthority",
            "()=>{throw Object.assign(new Error('business 🌸'),{code:'CUSTOM',details:{n:1}})}",
            true,
        ),
        tests::limits(),
    )
    .unwrap();
    execute_prepared_encoded(
        &prepared,
        "test",
        &[wire::NULL],
        "sqlAuthority",
        &mut host,
        tests::limits(),
    )
    .unwrap();
    assert_eq!(host.failure_code(), "CUSTOM");
    let WireOutcome::Failure {
        message,
        details: Some(details),
        ..
    } = host.outcome.unwrap()
    else {
        panic!("details missing")
    };
    assert_eq!(
        host.input.value(message).unwrap().as_str(),
        Some("business 🌸")
    );
    assert_eq!(
        host.input
            .value(details)
            .unwrap()
            .member("n")
            .unwrap()
            .as_i32(),
        Some(1)
    );
}

#[test]
fn native_encoded_host_decides_capabilities_and_guest_catch_cannot_save_fatal_denial() {
    let compute = "ctx=>{try{__flowerContexts[1].set({kind:'collection',name:'x'},'k',1)}catch(_){return 'caught'}return 'write'}";
    let prepared = prepare(&source("sqlProvider", compute, true), tests::limits()).unwrap();
    let mut call = |operation: &str, _: &[u8], input: &WireArena, root, _: &mut WireArena| {
        assert_eq!(
            operation, "set",
            "the byte transport must not impersonate host policy"
        );
        assert_eq!(input.value(root)?.len(), Some(3));
        anyhow::bail!("SQL_WRITE_FORBIDDEN: host denied captured write capability")
    };
    let mut host = BoundedHost::new(&mut call);
    let error = execute_prepared_encoded(
        &prepared,
        "test",
        &[wire::NULL],
        "sqlProvider",
        &mut host,
        tests::limits(),
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("SQL_WRITE_FORBIDDEN"),
        "{error:#}"
    );
    assert_eq!(host.calls, 1);
    assert_eq!(host.finishes, 0);
}

#[test]
fn native_encoded_crypto_denies_every_family_before_managed_or_json_parse() {
    // Pure hashes are deliberately HOLD too: no raw route falls back through
    // nacl::Output(Vec), serde JSON, managed secret selectors or shared handles.
    for expression in [
        "__flowerCrypto(17,0,new Uint8Array([1,2]))",
        "__flowerCrypto(15,0,new Uint8Array([1,2]))",
        "__flowerCrypto(101,0,'not-a-token','not-a-key','not-json')",
        "__flowerCrypto(200,0,'not-json','','','')",
    ] {
        let compute =
            format!("()=>{{try{{{expression};}}catch(_){{return 'caught'}}return 'crypto'}}");
        let prepared = prepare(&source("sqlAuthority", &compute, true), tests::limits()).unwrap();
        let shared = tests::limits();
        let mut no_call = |_: &str, _: &[u8], _: &WireArena, _, _: &mut WireArena| {
            panic!("crypto attempted ordinary host parsing")
        };
        let mut host = BoundedHost::new(&mut no_call);
        let error = execute_prepared_encoded(
            &prepared,
            "test",
            &[wire::NULL],
            "sqlAuthority",
            &mut host,
            shared.clone(),
        )
        .unwrap_err();
        assert!(
            error.to_string().starts_with("SQL_CRYPTO_FORBIDDEN:"),
            "{error:#}"
        );
        assert_eq!(host.calls, 0);
        assert_eq!(host.finishes, 0);
        shared.check().unwrap(); // context denial is not a fabricated memory limit.
    }
}

#[test]
fn native_encoded_cancellation_is_sticky_and_request_callbacks_are_discarded() {
    // Runtime/module compilation is setup, not the request's cancellation or
    // execution budget. Warm it before creating the finite test allowance;
    // a cold shared runner otherwise expires preparation before this test can
    // exercise either pre-cancel or cancellation from a host call.
    warmup().unwrap();
    let prepared = prepare(
        &source("sqlAuthority", "ctx=>ctx.principal()", true),
        tests::limits(),
    )
    .unwrap();
    let cancellation = Arc::new(AtomicBool::new(true));
    let shared = Limits::new_cancellable(
        Instant::now() + Duration::from_secs(30),
        MAX_MEMORY_BYTES,
        cancellation.clone(),
    );
    let cancel_on_call = cancellation.clone();
    let mut call = move |_: &str, _: &[u8], _: &WireArena, _, output: &mut WireArena| {
        cancel_on_call.store(true, Ordering::Release);
        Ok(WireOutcome::Success(output.null()?))
    };
    let mut host = BoundedHost::new(&mut call);
    let error = execute_prepared_encoded(
        &prepared,
        "test",
        &[wire::NULL],
        "sqlAuthority",
        &mut host,
        shared.clone(),
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("EVALUATION_CANCELLED:"));
    assert_eq!(host.calls, 0);
    cancellation.store(false, Ordering::Release);
    assert!(shared.check().is_err());
    let shared = Limits::new_cancellable(
        Instant::now() + Duration::from_secs(30),
        MAX_MEMORY_BYTES,
        cancellation.clone(),
    );
    let error = execute_prepared_encoded(
        &prepared,
        "test",
        &[wire::NULL],
        "sqlAuthority",
        &mut host,
        shared,
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("EVALUATION_CANCELLED:"));
    assert_eq!(host.calls, 1);
    assert_eq!(host.finishes, 0);
    let mut fresh = |_: &str, _: &[u8], _: &WireArena, _, output: &mut WireArena| {
        Ok(WireOutcome::Success(output.integer(42)?))
    };
    let mut host = BoundedHost::new(&mut fresh);
    execute_prepared_encoded(
        &prepared,
        "test",
        &[wire::NULL],
        "sqlAuthority",
        &mut host,
        tests::limits(),
    )
    .unwrap();
    assert_eq!(host.success_json(), b"42");
}

#[test]
fn native_encoded_recycle_rebinds_stack_callbacks_and_clears_mutable_guest_state() {
    let code = format!(
        "let count=0;{}",
        source("sqlAuthority", "ctx=>[++count,ctx.principal()]", true)
    );
    // Keep the static-init marker at the front, as preparation requires.
    let code = format!(
        "{STATIC_INIT_MARKER}{}",
        code.replace(STATIC_INIT_MARKER, "")
    );
    let prepared = prepare(&code, tests::limits()).unwrap();
    for number in [1, 40, 99] {
        let mut call = move |_: &str, _: &[u8], _: &WireArena, _, output: &mut WireArena| {
            Ok(WireOutcome::Success(output.integer(number)?))
        };
        let mut host = BoundedHost::new(&mut call);
        execute_prepared_encoded(
            &prepared,
            "test",
            &[wire::NULL],
            "sqlAuthority",
            &mut host,
            tests::limits(),
        )
        .unwrap();
        assert_eq!(host.success_json(), format!("[1,{number}]").as_bytes());
    }
    // Checkout attaches a NEW Host regardless of fresh or recycled storage;
    // managed shared-key declarations/authorizations never survive a request.
    let mut no_call =
        |_: &str, _: &[u8], _: &WireArena, _, _: &mut WireArena| panic!("unexpected host call");
    let mut host = BoundedHost::new(&mut no_call);
    let mut bridge: &mut dyn EncodedHost = &mut host;
    let callback = unsafe { Callback::scoped_encoded(&mut bridge) };
    let runtime = cache::runtime().unwrap();
    let mut cell =
        recycle::checkout(&prepared, &runtime.engine, tests::limits(), callback, &None).unwrap();
    assert!(cell.store.data().managed_shared.is_empty());
    assert!(cell.store.data().managed_authorizations.is_empty());
    assert_eq!(cell.store.data().managed_shared_bytes, 0);
    assert_eq!(cell.store.data().managed_authorization_bytes, 0);
    assert!(!cell.store.data().encoded_crypto_denied);
    cell.store.data_mut().callback = None;
    recycle::discard(cell);
}

// A tiny native guest gives hostile spans without the trusted QuickJS encoder.
// Building/compiling this fixture is setup, before any raw invocation admission.
fn native_host_guest(payload: &[u8], pointer: i32, length: i32) -> Arc<Prepared> {
    native_guest(payload, Some((pointer, length)), 0)
}

fn native_guest(payload: &[u8], host_span: Option<(i32, i32)>, outcome: i64) -> Arc<Prepared> {
    use base64::Engine as _;
    use wasm_encoder::*;
    let mut module = Module::new();
    let mut types = TypeSection::new();
    types.ty().function([ValType::I32; 3], [ValType::I64]);
    types.ty().function([ValType::I32], [ValType::I32]);
    types.ty().function([ValType::I32; 5], [ValType::I64]);
    types.ty().function([], [ValType::I64]);
    module.section(&types);
    let mut imports = ImportSection::new();
    imports.import("flower", "host_call", EntityType::Function(0));
    module.section(&imports);
    let mut functions = FunctionSection::new();
    functions.function(1).function(2).function(3);
    module.section(&functions);
    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: 1,
        maximum: Some(2),
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memories);
    let mut globals = GlobalSection::new();
    globals.global(
        GlobalType {
            val_type: ValType::I32,
            mutable: true,
            shared: false,
        },
        &ConstExpr::i32_const(8192),
    );
    module.section(&globals);
    let mut exports = ExportSection::new();
    exports
        .export("memory", ExportKind::Memory, 0)
        .export("flower_alloc", ExportKind::Func, 1)
        .export("flower_invoke", ExportKind::Func, 2)
        .export("flower_manifest", ExportKind::Func, 3);
    module.section(&exports);
    let mut code = CodeSection::new();
    let mut alloc = Function::new([]);
    alloc
        .instruction(&Instruction::GlobalGet(0))
        .instruction(&Instruction::GlobalGet(0))
        .instruction(&Instruction::LocalGet(0))
        .instruction(&Instruction::I32Add)
        .instruction(&Instruction::GlobalSet(0))
        .instruction(&Instruction::End);
    code.function(&alloc);
    let mut invoke = Function::new([]);
    if let Some((pointer, length)) = host_span {
        invoke
            .instruction(&Instruction::I32Const(4))
            .instruction(&Instruction::I32Const(pointer))
            .instruction(&Instruction::I32Const(length))
            .instruction(&Instruction::Call(0));
    } else {
        invoke.instruction(&Instruction::I64Const(outcome));
    }
    invoke.instruction(&Instruction::End);
    code.function(&invoke);
    let mut manifest = Function::new([]);
    manifest
        .instruction(&Instruction::I64Const((6i64 << 32) | 64))
        .instruction(&Instruction::End);
    code.function(&manifest);
    module.section(&code);
    let mut data = DataSection::new();
    data.active(0, &ConstExpr::i32_const(32), payload.iter().copied());
    data.active(
        0,
        &ConstExpr::i32_const(64),
        [wire::SUCCESS, wire::MAP, 0, 0, 0, 0],
    );
    module.section(&data);
    let wasm = module.finish();
    prepare_bundle(&json!({"hash":crate::evaluator::hash(&wasm),"wasm":base64::engine::general_purpose::STANDARD.encode(&wasm)}), tests::limits()).unwrap()
}

#[test]
fn native_encoded_quota_rejection_precedes_any_owned_value_parse() {
    struct Admission {
        calls: usize,
    }
    impl EncodedHost for Admission {
        fn call<'a>(&'a mut self, method: &str, input: &[u8]) -> Result<&'a [u8]> {
            self.calls += 1;
            assert_eq!(method, "get");
            assert_eq!(
                input,
                [255],
                "malformed native byte reached admission without a Value decoder"
            );
            anyhow::bail!("SQL_HOST_QUOTA: argument arena not admitted")
        }
        fn finish(&mut self, _: &[u8]) -> Result<()> {
            panic!("quota failure produced an outcome")
        }
    }
    let prepared = native_host_guest(&[255], 32, 1);
    let mut host = Admission { calls: 0 };
    let error = execute_prepared_encoded(
        &prepared,
        "test",
        &[wire::NULL],
        "sqlProvider",
        &mut host,
        tests::limits(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("SQL_HOST_QUOTA"), "{error:#}");
    assert_eq!(host.calls, 1);
}

#[test]
fn native_encoded_guest_bounds_and_wire_capacity_fail_before_host_parse() {
    for (pointer, length, message) in [
        (65535, 2, "guest arguments bounds"),
        (32, -1, "SQL_WIRE_CAPACITY"),
    ] {
        let prepared = native_host_guest(&[wire::NULL], pointer, length);
        let mut no_call = |_: &str, _: &[u8], _: &WireArena, _, _: &mut WireArena| {
            panic!("span admission bypassed")
        };
        let mut host = BoundedHost::new(&mut no_call);
        let error = execute_prepared_encoded(
            &prepared,
            "test",
            &[wire::NULL],
            "sqlProvider",
            &mut host,
            tests::limits(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains(message), "{error:#}");
        assert_eq!(host.calls, 0);
        assert_eq!(host.finishes, 0);
    }
}

#[test]
fn native_encoded_outcome_bytes_are_borrowed_and_admitted_before_decode() {
    let packed =
        |pointer: u32, length: u32| ((u64::from(length) << 32) | u64::from(pointer)) as i64;
    let prepared = native_guest(
        &[wire::SUCCESS, wire::INT, 42, 0, 0, 0],
        None,
        packed(32, 6),
    );
    let mut no_call =
        |_: &str, _: &[u8], _: &WireArena, _, _: &mut WireArena| panic!("unexpected host call");
    let mut host = BoundedHost::new(&mut no_call);
    execute_prepared_encoded(
        &prepared,
        "test",
        &[wire::NULL],
        "sqlProvider",
        &mut host,
        tests::limits(),
    )
    .unwrap();
    assert_eq!(host.finishes, 1);
    assert_eq!(host.success_json(), b"42");
    for (pointer, length, message) in [
        (65535, 2, "guest outcome bounds"),
        (
            32,
            (host::MAX_ENCODED_BYTES + 1) as u32,
            "SQL_WIRE_CAPACITY",
        ),
    ] {
        let prepared = native_guest(&[255], None, packed(pointer, length));
        let mut host = BoundedHost::new(&mut no_call);
        let error = execute_prepared_encoded(
            &prepared,
            "test",
            &[wire::NULL],
            "sqlProvider",
            &mut host,
            tests::limits(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains(message), "{error:#}");
        assert_eq!(host.finishes, 0);
    }
    struct OutcomeAdmission;
    impl EncodedHost for OutcomeAdmission {
        fn call<'a>(&'a mut self, _: &str, _: &[u8]) -> Result<&'a [u8]> {
            panic!("unexpected host call")
        }
        fn finish(&mut self, outcome: &[u8]) -> Result<()> {
            assert_eq!(
                outcome,
                [255],
                "raw route must not turn malformed bytes into owned INVALID_VALUE"
            );
            anyhow::bail!("SQL_OUTCOME_QUOTA: arena not admitted")
        }
    }
    let prepared = native_guest(&[255], None, packed(32, 1));
    let error = execute_prepared_encoded(
        &prepared,
        "test",
        &[wire::NULL],
        "sqlProvider",
        &mut OutcomeAdmission,
        tests::limits(),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "SQL_OUTCOME_QUOTA: arena not admitted");
}

#[test]
fn native_encoded_request_input_is_copied_to_guest_not_retained_in_host_token() {
    let prepared = prepare(
        &source("sqlProvider", "(ctx,args)=>[args,ctx.get('x',args)]", true),
        tests::limits(),
    )
    .unwrap();
    let mut request = arena();
    let root = request.text("caller-owned\0🌻").unwrap();
    let bytes = request.encode_checked(root, &mut || Ok(())).unwrap();
    let caller = bytes.as_ptr() as usize..bytes.as_ptr() as usize + bytes.len();
    let mut call =
        move |operation: &str, input: &[u8], arena: &WireArena, root, output: &mut WireArena| {
            assert_eq!(operation, "get");
            let guest = input.as_ptr() as usize..input.as_ptr() as usize + input.len();
            assert!(
                guest.end <= caller.start || caller.end <= guest.start,
                "token pointed into caller request bytes"
            );
            assert_eq!(
                arena.value(root)?.index(1).unwrap().as_str(),
                Some("caller-owned\0🌻")
            );
            Ok(WireOutcome::Success(output.integer(7)?))
        };
    let mut host = BoundedHost::new(&mut call);
    execute_prepared_encoded(
        &prepared,
        "test",
        bytes,
        "sqlProvider",
        &mut host,
        tests::limits(),
    )
    .unwrap();
    assert_eq!(
        host.success_json(),
        "[\"caller-owned\\u0000🌻\",7]".as_bytes()
    );
    // All Store/token uses have ended before caller storage is invalidated.
    request.reset_checked(&mut || Ok(())).unwrap();
    let bytes = vec![wire::NULL; host::MAX_ENCODED_BYTES + 1];
    let error = execute_prepared_encoded(
        &prepared,
        "test",
        &bytes,
        "sqlProvider",
        &mut host,
        tests::limits(),
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("SQL_WIRE_CAPACITY:"));
    assert_eq!(host.calls, 1);
    assert_eq!(host.finishes, 1);
}
