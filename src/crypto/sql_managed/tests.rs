use super::*;
use crate::allocation_probe::measure;
use crate::evaluator::sql_frame::FrameLimits;
use aws_lc_rs::aead::{AES_256_GCM, LessSafeKey};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::Duration;

const WRAPPING_ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const SEALED: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const NONCE: &str = "AAAAAAAAAAAAAAAA";
const SEED: [u8; 32] = [7; 32];
const CLAIMS: &[u8] = r#"{"aud":["flower","other"],"exp":20,"iat":1,"iss":"issuer","nbf":10,"sub":"alice","unicode":"🌷"}"#.as_bytes();
const OPTIONS: &[u8] = br#"{"algorithms":["EdDSA"],"audience":["flower"],"issuer":"issuer","subject":"alice","typ":"JWT"}"#;
fn control(cancelled: &AtomicBool) -> Control<'_> {
    Control::new(
        cancelled,
        Instant::now() + Duration::from_secs(30),
        MAX_JOB_WORK,
    )
    .unwrap()
}
fn point() -> FreshPoint {
    FreshPoint {
        job: 1,
        snapshot: 17,
        certificate: [3; 32],
    }
}
fn fields() -> KeyFields<'static> {
    KeyFields {
        domain: "domain",
        id: "id",
        name: "tokens",
        algorithm: "Ed25519",
        declaration_algorithm: "Ed25519",
        binding_usages: &["sign", "verify", "publicKey"],
        declaration_usages: &["sign", "verify"],
        version: 1,
        active_version: 1,
        revoked: false,
        retired: false,
        envelope: Some(EnvelopeFields {
            provider: "mounted",
            wrapping_id: WRAPPING_ID,
            wrapped_dek: SEALED,
            wrapping_nonce: NONCE,
            ciphertext: SEALED,
            nonce: NONCE,
        }),
    }
}
fn attenuation(phase: Phase) -> Attenuation<'static> {
    match phase {
        Phase::InitialAuthentication | Phase::FreshAuthentication => Attenuation {
            phase,
            definition: "$flower.authorize",
            authentication_key: Some("tokens"),
            signing_keys: &[],
        },
        Phase::ReadlessFinalizer => Attenuation {
            phase,
            definition: "sql.query.$sql.finalize",
            authentication_key: None,
            signing_keys: &["tokens"],
        },
    }
}
fn grant(phase: Phase, control: &Control<'_>) -> Grant<'static> {
    unsafe { Grant::from_trusted_capture(fields(), attenuation(phase), point(), control) }.unwrap()
}
fn parser(control: &Control<'_>) -> FrameBuilder {
    FrameBuilder::new(
        FrameLimits {
            raw_bytes: 0,
            support_bytes: 256 * 1024,
            decoded_bytes: 256 * 1024,
            nodes: 8192,
            documents: 128,
            keys: 0,
            key_bytes: 0,
            tables: 0,
            columns: 0,
            rows: 0,
            cells: 0,
            text_bytes: 0,
            provenance_bytes: 0,
            parse_work: MAX_JOB_WORK,
        },
        control.frame(),
    )
    .unwrap()
}
// Test-only observer of the ACTUAL current thread extent. The production token
// is an unsafe driver attestation of PRE-launch admission, not this query. The
// fresh-thread fixtures below preselect/admit a 2MiB hard stack before spawn.
fn native_allowance() -> NativeAllowance {
    #[cfg(target_os = "linux")]
    {
        let mut attr = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
        let mut address = std::ptr::null_mut();
        let mut bytes = 0;
        unsafe {
            assert_eq!(
                libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr()),
                0
            );
            assert_eq!(
                libc::pthread_attr_getstack(attr.as_ptr(), &mut address, &mut bytes),
                0
            );
            assert_eq!(libc::pthread_attr_destroy(attr.as_mut_ptr()), 0);
            NativeAllowance::from_trusted_launch(bytes, 0).unwrap()
        }
    }
    #[cfg(not(target_os = "linux"))]
    panic!("the audited harness requires Linux");
}
fn workspace(control: &Control<'_>) -> Workspace {
    let native = native_allowance();
    Workspace::new(
        Workspace::required_admission(native).unwrap().bytes(),
        native,
        control,
    )
    .unwrap()
}
fn signed(header: &[u8], claims: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let signature = SigningKey::from_bytes(seed).sign(message.as_bytes());
    format!(
        "{}.{}",
        message,
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
    .into_bytes()
}
fn token(claims: &[u8]) -> Vec<u8> {
    signed(
        br#"{"alg":"EdDSA","kid":"flower.id.1","typ":"JWT"}"#,
        claims,
        &SEED,
    )
}
fn verify_case(token: &[u8], options: &[u8], now: u64) -> Result<TimeDependency, Error> {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    let grant = grant(Phase::FreshAuthentication, &control);
    workspace.install_seed_for_test(&grant, &SEED);
    let result = workspace
        .verify(grant, point(), token, options, now, &mut parser, &control)
        .map(|verified| verified.dependency);
    assert!(workspace.binding.is_none());
    assert!(workspace.secret.iter().all(|b| *b == 0));
    result
}

#[test]
fn real_ed25519_sign_verify_and_borrowed_claims() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    let signing = grant(Phase::ReadlessFinalizer, &control);
    workspace.install_seed_for_test(&signing, &SEED);
    let result = workspace
        .sign(signing, point(), CLAIMS, b"{}", &mut parser, &control)
        .unwrap()
        .as_bytes()
        .to_vec();
    assert_eq!(result, token(CLAIMS));
    assert!(workspace.binding.is_none());
    let verification = grant(Phase::InitialAuthentication, &control);
    workspace.install_seed_for_test(&verification, &SEED);
    let verified = workspace
        .verify(
            verification,
            point(),
            &result,
            OPTIONS,
            15_000,
            &mut parser,
            &control,
        )
        .unwrap();
    assert_eq!(
        verified.claims.get("sub").unwrap().unwrap().as_str(),
        Some("alice")
    );
    assert_eq!(
        verified.claims.get("unicode").unwrap().unwrap().as_str(),
        Some("🌷")
    );
    assert_eq!(
        verified
            .protected_header
            .get("kid")
            .unwrap()
            .unwrap()
            .as_str(),
        Some("flower.id.1")
    );
    assert_eq!(
        verified.dependency,
        TimeDependency {
            checked_at_ms: 15_000,
            valid_from_ms: Some(10_000),
            expires_at_ms: 20_000
        }
    );
}
#[test]
fn rfc8032_stack_sign_and_strict_verify_vector() {
    fn hex<const N: usize>(text: &str) -> [u8; N] {
        let mut out = [0; N];
        for (i, pair) in text.as_bytes().chunks(2).enumerate() {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            out[i] = digit(pair[0]) * 16 + digit(pair[1]);
        }
        out
    }
    let seed = hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let expected = hex::<64>(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    let ((), count, bytes) = measure(|| {
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(key.verifying_key().to_bytes(), public);
        assert_eq!(key.sign(b"").to_bytes(), expected);
        assert!(
            key.verifying_key()
                .verify_strict(b"", &Signature::from_bytes(&expected))
                .is_ok()
        );
    });
    assert_eq!((count, bytes), (0, 0));
}
#[test]
fn wrong_key_and_message_rejected() {
    let wrong = signed(
        br#"{"alg":"EdDSA","kid":"flower.id.1","typ":"JWT"}"#,
        CLAIMS,
        &[8; 32],
    );
    assert_eq!(verify_case(&wrong, OPTIONS, 15_000), Err(Error::Signature));
    let mut altered = token(CLAIMS);
    let at = altered.iter().position(|b| *b == b'.').unwrap() + 1;
    altered[at] = if altered[at] == b'e' { b'f' } else { b'e' };
    assert!(verify_case(&altered, OPTIONS, 15_000).is_err());
}
#[test]
fn exact_algorithm_header_and_kid_checks() {
    for header in [
        br#"{"alg":"HS256","kid":"flower.id.1"}"#.as_slice(),
        br#"{"alg":"none","kid":"flower.id.1"}"#,
        br#"{"alg":"EdDSA","kid":"flower.other.1"}"#,
        br#"{"alg":"EdDSA","kid":"flower.id.01"}"#,
        br#"{"alg":"EdDSA","kid":"flower.id.0"}"#,
        br#"{"alg":"EdDSA"}"#,
        br#"{"kid":"flower.id.1"}"#,
        br#"{"alg":"EdDSA","kid":"flower.id.1","crit":[]}"#,
        br#"{"alg":"EdDSA","kid":"flower.id.1","jku":"https://untrusted"}"#,
        br#"{"alg":"EdDSA","alg":"EdDSA","kid":"flower.id.1"}"#,
        br#"{"alg":"EdDSA","kid":1}"#,
    ] {
        assert!(verify_case(&signed(header, CLAIMS, &SEED), OPTIONS, 15_000).is_err());
    }
}
#[test]
fn strict_option_allowlist_and_types() {
    for options in [
        br#"{"keyFormat":"raw"}"#.as_slice(),
        br#"{"algorithm":"EdDSA"}"#,
        br#"{"algorithms":["HS256"]}"#,
        br#"{"algorithms":["EdDSA","EdDSA"]}"#,
        br#"{"algorithms":[]}"#,
        br#"{"issuer":null}"#,
        br#"{"audience":"flower"}"#,
        br#"{"audience":[1]}"#,
        br#"{"clockToleranceSeconds":-1}"#,
        br#"{"clockToleranceSeconds":0.5}"#,
        br#"{"clockToleranceSeconds":3601}"#,
        br#"{"requireExpiration":false}"#,
        br#"{"unknown":true}"#,
        br#"{"issuer":"a","issuer":"a"}"#,
        b"null",
        b"[]",
    ] {
        assert!(verify_case(&token(CLAIMS), options, 15_000).is_err());
    }
}
#[test]
fn issuer_audience_subject_and_type_exact() {
    for options in [
        br#"{"audience":["flower"],"issuer":"wrong"}"#.as_slice(),
        br#"{"audience":["wrong"]}"#,
        br#"{"audience":[]}"#,
        br#"{"audience":["flower"],"subject":"wrong"}"#,
        br#"{"audience":["flower"],"typ":"wrong"}"#,
        br#"{}"#,
    ] {
        assert_eq!(
            verify_case(&token(CLAIMS), options, 15_000),
            Err(Error::Claims)
        );
    }
    assert!(verify_case(&token(CLAIMS), br#"{"audience":["other"]}"#, 15_000).is_ok());
    assert!(
        verify_case(
            &token(br#"{"aud":"flower","exp":20}"#),
            br#"{"audience":["flower"]}"#,
            0
        )
        .is_ok()
    );
    assert_eq!(
        verify_case(&token(br#"{"exp":20}"#), br#"{"audience":["flower"]}"#, 0),
        Err(Error::Claims)
    );
}
#[test]
fn expiration_nbf_and_tolerance_exact_milliseconds_and_dependencies() {
    assert_eq!(
        verify_case(&token(CLAIMS), OPTIONS, 9_999),
        Err(Error::NotActive {
            changes_at_ms: 10_000
        })
    );
    assert!(verify_case(&token(CLAIMS), OPTIONS, 10_000).is_ok());
    assert!(verify_case(&token(CLAIMS), OPTIONS, 19_999).is_ok());
    assert_eq!(
        verify_case(&token(CLAIMS), OPTIONS, 20_000),
        Err(Error::Expired { at_ms: 20_000 })
    );
    let options = br#"{"audience":["flower"],"clockToleranceSeconds":2}"#;
    assert_eq!(
        verify_case(&token(CLAIMS), options, 7_999),
        Err(Error::NotActive {
            changes_at_ms: 8_000
        })
    );
    assert!(verify_case(&token(CLAIMS), options, 8_000).is_ok());
    assert!(verify_case(&token(CLAIMS), options, 21_999).is_ok());
    assert_eq!(
        verify_case(&token(CLAIMS), options, 22_000),
        Err(Error::Expired { at_ms: 22_000 })
    );
}
#[test]
fn numericdate_strict_range_and_shape() {
    for claims in [
        br#"{}"#.as_slice(),
        br#"{"exp":"20"}"#,
        br#"{"exp":20.1}"#,
        br#"{"exp":2e1}"#,
        br#"{"exp":-1}"#,
        br#"{"exp":-0}"#,
        br#"{"exp":9007199254740992}"#,
        br#"{"exp":18446744073709551615}"#,
        br#"{"exp":1e999}"#,
        br#"{"exp":20,"iat":null}"#,
        br#"{"exp":20,"nbf":1.1}"#,
        br#"{"exp":20,"iss":1}"#,
        br#"{"exp":20,"sub":1}"#,
        br#"{"exp":20,"aud":[false]}"#,
        br#"{"exp":20,"aud":null}"#,
    ] {
        assert!(verify_case(&token(claims), b"{}", 0).is_err());
    }
    assert!(verify_case(&token(br#"{"exp":9007199254740991}"#), b"{}", u64::MAX / 4).is_ok());
}
#[test]
fn malformed_json_duplicate_depth_utf_and_quota_rejected() {
    for claims in [
        br#"{"exp":20,"nested":{"x":1,"x":2}}"#.as_slice(),
        br#"{"exp":20,"a":1,"\u0061":2}"#,
        br#"{"exp":20,"s":"\ud800"}"#,
        br#"{"exp":20,"s":"\udc00"}"#,
        b"{\"exp\":20,\"s\":\"\xff\"}",
        b"{\"exp\":20,\"s\":\"\x00\"}",
        b"{\"exp\":20} false",
        b"[20]",
    ] {
        assert!(verify_case(&token(claims), b"{}", 0).is_err());
    }
    let deep = format!(
        "{{\"exp\":20,\"nested\":{}{}}}",
        "[".repeat(65),
        "]".repeat(65)
    );
    assert!(verify_case(&token(deep.as_bytes()), b"{}", 0).is_err());
    let wide = format!("{{\"exp\":20,\"s\":\"{}\"}}", "x".repeat(MAX_CLAIMS_BYTES));
    assert_eq!(
        verify_case(&token(wide.as_bytes()), b"{}", 0),
        Err(Error::Capacity)
    );
    assert_eq!(
        verify_case(&vec![b'x'; MAX_TOKEN_BYTES + 1], b"{}", 0),
        Err(Error::Capacity)
    );
    assert_eq!(
        verify_case(
            &token(br#"{"exp":20}"#),
            &vec![b' '; MAX_OPTIONS_BYTES + 1],
            0
        ),
        Err(Error::Capacity)
    );
}
#[test]
fn audience_and_text_quotas() {
    let many = format!("{{\"exp\":20,\"aud\":[{}]}}", vec!["\"x\""; 17].join(","));
    assert_eq!(
        verify_case(&token(many.as_bytes()), br#"{"audience":["x"]}"#, 0),
        Err(Error::Capacity)
    );
    let long = format!(
        "{{\"exp\":20,\"iss\":\"{}\"}}",
        "x".repeat(MAX_OPTION_TEXT + 1)
    );
    assert_eq!(
        verify_case(&token(long.as_bytes()), b"{}", 0),
        Err(Error::Capacity)
    );
}
#[test]
fn compact_and_canonical_base64_checks() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    for invalid in [
        b"a".as_slice(),
        b"Zg=",
        b"Zg==",
        b"Zh",
        b"Zm9",
        b"Zm+v",
        b"Zm/v",
        b"Zg\n",
        b"\xffg",
    ] {
        assert!(codec::decode(invalid, &mut [0; 32], &control).is_err());
    }
    for len in 0..130 {
        let input: Vec<u8> = (0..len).map(|i| (i * 137) as u8).collect();
        let mut encoded = [0; 180];
        let at = codec::encode(&input, &mut encoded, &control).unwrap();
        assert_eq!(&encoded[..at], URL_SAFE_NO_PAD.encode(&input).as_bytes());
        let mut decoded = [0; 130];
        let count = codec::decode(&encoded[..at], &mut decoded, &control).unwrap();
        assert_eq!(&decoded[..count], input.as_slice());
    }
    for invalid in [
        b"".as_slice(),
        b"a",
        b"a.b",
        b"a.b.c.d",
        b".b.c",
        b"a..c",
        b"a.b.",
    ] {
        assert!(codec::parts(invalid, &control).is_err());
    }
}
#[test]
fn native_definition_identity_accepts_real_sdk_names_and_bounds_complete_bytes() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut fingerprints = [[0; 32]; 3];
    for (index, definition) in [
        "sql.query.$sql.finalize",
        "查詢.🌸.$sql.finalize",
        "sql.query.\0.$sql.finalize",
    ]
    .into_iter()
    .enumerate()
    {
        let mut attenuation = attenuation(Phase::ReadlessFinalizer);
        attenuation.definition = definition;
        let grant =
            unsafe { Grant::from_trusted_capture(fields(), attenuation, point(), &control) }
                .unwrap();
        fingerprints[index] = grant.fingerprint;
    }
    assert!(fingerprints[0] != fingerprints[1]);
    assert!(fingerprints[0] != fingerprints[2]);
    assert!(fingerprints[1] != fingerprints[2]);
    let boundary = "a".repeat(MAX_DEFINITION_BYTES);
    let mut spec = attenuation(Phase::ReadlessFinalizer);
    spec.definition = &boundary;
    assert!(unsafe { Grant::from_trusted_capture(fields(), spec, point(), &control) }.is_ok());
    let too_long = "a".repeat(MAX_DEFINITION_BYTES + 1);
    for invalid in ["", too_long.as_str()] {
        let mut spec = attenuation(Phase::ReadlessFinalizer);
        spec.definition = invalid;
        assert!(matches!(
            unsafe { Grant::from_trusted_capture(fields(), spec, point(), &control) },
            Err(Error::Invalid)
        ));
    }
}

#[test]
fn exact_grant_attenuation_and_version_restrictions() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    for phase in [Phase::InitialAuthentication, Phase::FreshAuthentication] {
        let mut key = fields();
        key.retired = true;
        key.active_version = 2;
        assert!(
            unsafe { Grant::from_trusted_capture(key, attenuation(phase), point(), &control) }
                .is_ok()
        );
    }
    for change in 0..10 {
        let mut key = fields();
        match change {
            0 => key.revoked = true,
            1 => key.envelope = None,
            2 => key.retired = true,
            3 => key.active_version = 2,
            4 => key.algorithm = "P256",
            5 => key.declaration_algorithm = "RSA",
            6 => key.binding_usages = &["verify"],
            7 => key.declaration_usages = &["verify"],
            8 => key.envelope.as_mut().unwrap().provider = "remote",
            9 => key.version = 0,
            _ => unreachable!(),
        }
        assert!(
            unsafe {
                Grant::from_trusted_capture(
                    key,
                    attenuation(Phase::ReadlessFinalizer),
                    point(),
                    &control,
                )
            }
            .is_err()
        );
    }
    let mut auth = attenuation(Phase::InitialAuthentication);
    auth.authentication_key = Some("other");
    assert!(unsafe { Grant::from_trusted_capture(fields(), auth, point(), &control) }.is_err());
    let mut auth = attenuation(Phase::InitialAuthentication);
    auth.signing_keys = &["tokens"];
    assert!(unsafe { Grant::from_trusted_capture(fields(), auth, point(), &control) }.is_err());
    let mut finalizer = attenuation(Phase::ReadlessFinalizer);
    finalizer.signing_keys = &["other"];
    assert!(
        unsafe { Grant::from_trusted_capture(fields(), finalizer, point(), &control) }.is_err()
    );
    let mut finalizer = attenuation(Phase::ReadlessFinalizer);
    finalizer.authentication_key = Some("tokens");
    assert!(
        unsafe { Grant::from_trusted_capture(fields(), finalizer, point(), &control) }.is_err()
    );
}
#[test]
fn crossphase_sign_and_verify_denied_and_secrets_erased() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    for phase in [Phase::InitialAuthentication, Phase::FreshAuthentication] {
        let grant = grant(phase, &control);
        workspace.install_seed_for_test(&grant, &SEED);
        assert_eq!(
            workspace.sign(grant, point(), CLAIMS, b"{}", &mut parser, &control),
            Err(Error::Authority)
        );
        assert!(workspace.binding.is_none());
        assert!(workspace.secret.iter().all(|b| *b == 0));
    }
    let grant = grant(Phase::ReadlessFinalizer, &control);
    workspace.install_seed_for_test(&grant, &SEED);
    assert!(matches!(
        workspace.verify(
            grant,
            point(),
            &token(CLAIMS),
            OPTIONS,
            15_000,
            &mut parser,
            &control
        ),
        Err(Error::Authority)
    ));
}
#[test]
fn exact_fresh_point_and_seed_binding_no_reuse() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    for change in 0..3 {
        let grant = grant(Phase::ReadlessFinalizer, &control);
        workspace.install_seed_for_test(&grant, &SEED);
        let mut different = point();
        match change {
            0 => different.job += 1,
            1 => different.snapshot += 1,
            2 => different.certificate[0] ^= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            workspace.sign(grant, different, CLAIMS, b"{}", &mut parser, &control),
            Err(Error::StalePoint)
        );
        assert!(workspace.secret.iter().all(|b| *b == 0));
    }
    let grant1 = grant(Phase::ReadlessFinalizer, &control);
    workspace.install_seed_for_test(&grant1, &SEED);
    workspace
        .sign(grant1, point(), CLAIMS, b"{}", &mut parser, &control)
        .unwrap();
    assert_eq!(
        workspace.sign(
            grant(Phase::ReadlessFinalizer, &control),
            point(),
            CLAIMS,
            b"{}",
            &mut parser,
            &control
        ),
        Err(Error::SecretUnavailable)
    );
    let mut stale = point();
    stale.certificate = [0; 32];
    assert!(matches!(
        unsafe {
            Grant::from_trusted_capture(
                fields(),
                attenuation(Phase::InitialAuthentication),
                stale,
                &control,
            )
        },
        Err(Error::StalePoint)
    ));
}
#[test]
fn secret_cannot_rebind_to_changed_envelope() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    let original = grant(Phase::ReadlessFinalizer, &control);
    workspace.install_seed_for_test(&original, &SEED);
    let replacement = URL_SAFE_NO_PAD.encode([1; 48]);
    let mut key = fields();
    key.envelope.as_mut().unwrap().ciphertext = &replacement;
    let replaced = unsafe {
        Grant::from_trusted_capture(
            key,
            attenuation(Phase::ReadlessFinalizer),
            point(),
            &control,
        )
    }
    .unwrap();
    assert_eq!(
        workspace.sign(replaced, point(), CLAIMS, b"{}", &mut parser, &control),
        Err(Error::SecretUnavailable)
    );
}
#[test]
fn fixed_mapping_admission_pin_pretouch_and_reset() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let native = native_allowance();
    let required = Workspace::required_admission(native).unwrap();
    assert!(matches!(
        Workspace::new(required.bytes() - 1, native, &control),
        Err(Error::Capacity)
    ));
    let (result, count, bytes) = measure(|| Workspace::new(required.bytes(), native, &control));
    let mut workspace = result.unwrap();
    assert_eq!((count, bytes), (0, 0));
    assert_eq!(workspace.admission().bytes(), required.bytes());
    assert_eq!(required.mapped_bytes, required.pinned_bytes);
    assert_eq!(required.stack_extent_bytes, native.stack_extent_bytes);
    eprintln!(
        "Workspace admission: mappings={}, owner={}, total={}, pinned={}",
        required.mapped_bytes,
        required.owner_bytes,
        required.bytes(),
        required.pinned_bytes
    );
    workspace.secret[..32].fill(5);
    workspace.output[0] = 1;
    workspace.decoded[0] = 2;
    workspace.reset();
    assert!(workspace.secret.iter().all(|b| *b == 0));
    assert!(workspace.output.iter().all(|b| *b == 0));
    assert!(workspace.decoded.iter().all(|b| *b == 0));
    #[cfg(target_os = "linux")]
    for pointer in [
        workspace.secret.as_ptr(),
        workspace.decoded.as_ptr(),
        workspace.output.as_ptr(),
    ] {
        let mut resident = [0; 1];
        assert_eq!(
            unsafe {
                libc::mincore(
                    pointer.cast_mut().cast(),
                    slab::mapped_bytes(1).unwrap(),
                    resident.as_mut_ptr(),
                )
            },
            0
        );
        assert_eq!(resident[0] & 1, 1);
    }
}
#[test]
fn post_admission_sign_verify_grant_and_hash_allocate_zero_rust_heap() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    let (signing, count, bytes) = measure(|| grant(Phase::ReadlessFinalizer, &control));
    assert_eq!((count, bytes), (0, 0));
    workspace.install_seed_for_test(&signing, &SEED);
    let (result, count, bytes) =
        measure(|| workspace.sign(signing, point(), CLAIMS, b"{}", &mut parser, &control));
    let result = result.unwrap().as_bytes().to_vec(); // copy outside measured phase.
    assert_eq!((count, bytes), (0, 0));
    let verification = grant(Phase::FreshAuthentication, &control);
    workspace.install_seed_for_test(&verification, &SEED);
    let (verified, count, bytes) = measure(|| {
        workspace.verify(
            verification,
            point(),
            &result,
            OPTIONS,
            15_000,
            &mut parser,
            &control,
        )
    });
    assert!(verified.is_ok());
    assert_eq!((count, bytes), (0, 0));
    let ((sha256, sha512), count, bytes) =
        measure(|| (sha256(b"abc", &control), sha512(b"abc", &control)));
    assert_eq!(sha256.unwrap(), <[u8; 32]>::from(Sha256::digest(b"abc")));
    assert_eq!(sha512.unwrap(), <[u8; 64]>::from(Sha512::digest(b"abc")));
    assert_eq!((count, bytes), (0, 0));
}
#[test]
fn post_admission_invalid_parse_error_allocates_zero_and_erases_secret() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    let signing = grant(Phase::ReadlessFinalizer, &control);
    workspace.install_seed_for_test(&signing, &SEED);
    let (result, count, bytes) = measure(|| {
        workspace.sign(
            signing,
            point(),
            br#"{"exp":20,"a":1,"a":2}"#,
            b"{}",
            &mut parser,
            &control,
        )
    });
    assert!(result.is_err());
    assert_eq!((count, bytes), (0, 0));
    assert!(workspace.secret.iter().all(|b| *b == 0));
    assert!(workspace.output.iter().all(|b| *b == 0));
}
#[test]
fn signing_options_and_unicode_quoting_are_bounded() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    for invalid in [
        br#"{"keyFormat":"raw"}"#.as_slice(),
        br#"{"algorithm":"HS256"}"#,
        br#"{"kid":"flower.id.2"}"#,
        br#"{"typ":1}"#,
        br#"{"unknown":true}"#,
    ] {
        let mut parser = parser(&control);
        let mut workspace = workspace(&control);
        let signing = grant(Phase::ReadlessFinalizer, &control);
        workspace.install_seed_for_test(&signing, &SEED);
        assert!(
            workspace
                .sign(signing, point(), CLAIMS, invalid, &mut parser, &control)
                .is_err()
        );
    }
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    let signing = grant(Phase::ReadlessFinalizer, &control);
    workspace.install_seed_for_test(&signing, &SEED);
    let token = workspace
        .sign(
            signing,
            point(),
            CLAIMS,
            r#"{"typ":"🌷\n\"\\"}"#.as_bytes(),
            &mut parser,
            &control,
        )
        .unwrap();
    let header = URL_SAFE_NO_PAD
        .decode(token.split('.').next().unwrap())
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&header).unwrap();
    assert_eq!(parsed["typ"], "🌷\n\"\\");
}
#[test]
fn cancellation_deadline_and_cumulative_work_are_sticky() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    let signing = grant(Phase::ReadlessFinalizer, &control);
    workspace.install_seed_for_test(&signing, &SEED);
    cancelled.store(true, Ordering::Release);
    assert_eq!(
        workspace.sign(signing, point(), CLAIMS, b"{}", &mut parser, &control),
        Err(Error::Cancelled)
    );
    assert!(workspace.secret.iter().all(|b| *b == 0));
    cancelled.store(false, Ordering::Release);
    assert_eq!(sha256(b"x", &control), Err(Error::Cancelled));
    let expired = Control::new(&cancelled, Instant::now(), MAX_JOB_WORK).unwrap();
    assert_eq!(sha512(b"x", &expired), Err(Error::Deadline));
    let exhausted = Control::new(&cancelled, Instant::now() + Duration::from_secs(1), 2).unwrap();
    assert_eq!(sha256(b"abc", &exhausted), Err(Error::WorkLimit));
    assert_eq!(sha256(b"", &exhausted), Err(Error::WorkLimit));
    let long = vec![0; MAX_BORROWED_BYTES + 1];
    assert_eq!(sha256(&long, &control), Err(Error::Capacity));
}

// Optional GLIBC native interposition evidence. Run with the provided C probe
// loaded, SQL_MANAGED_NATIVE_PROBE=1. This is not an all-platform native proof.
type ProbeStart = unsafe extern "C" fn();
type ProbeStop = unsafe extern "C" fn() -> usize;
fn native_probe() -> Option<(ProbeStart, ProbeStop)> {
    std::env::var_os("SQL_MANAGED_NATIVE_PROBE")?;
    unsafe fn symbol<T: Copy>(name: &std::ffi::CStr) -> T {
        let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
        assert!(!pointer.is_null());
        assert_eq!(size_of::<T>(), size_of::<*mut libc::c_void>());
        unsafe { std::mem::transmute_copy(&pointer) }
    }
    Some((
        unsafe { symbol(c"sql_managed_native_probe_start") },
        unsafe { symbol(c"sql_managed_native_probe_stop") },
    ))
}
#[test]
fn native_context_allocation_is_not_caught_by_rust_globalalloc() {
    let Some((start, stop)) = native_probe() else {
        return;
    };
    let (key, rust_count, rust_bytes) = measure(|| {
        unsafe { start() };
        let key = aws_lc_rs::aead::UnboundKey::new(&AES_256_GCM, &[9; 32]);
        let native_count = unsafe { stop() };
        (key, native_count)
    });
    assert!(key.0.is_ok());
    assert!(
        key.1 >= 1,
        "native EVP_AEAD_CTX allocation must be observed"
    );
    assert_eq!((rust_count, rust_bytes), (0, 0));
    eprintln!(
        "DEK-context creation: native allocator calls={}, Rust allocator calls={rust_count}",
        key.1
    );
}
#[test]
fn preinitialized_native_open_cold_failure_allocates_error_state() {
    let Some((start, stop)) = native_probe() else {
        return;
    };
    let cipher =
        LessSafeKey::new(aws_lc_rs::aead::UnboundKey::new(&AES_256_GCM, &[9; 32]).unwrap());
    let count = std::thread::spawn(move || {
        let mut encrypted = [0; 48];
        let ((failed, native_count), rust_count, rust_bytes) = measure(|| {
            unsafe { start() };
            let failed = cipher
                .open_in_place(
                    aws_lc_rs::aead::Nonce::assume_unique_for_key([0; 12]),
                    aws_lc_rs::aead::Aad::empty(),
                    &mut encrypted,
                )
                .is_err();
            let native_count = unsafe { stop() };
            (failed, native_count)
        });
        assert!(failed);
        assert_eq!((rust_count, rust_bytes), (0, 0));
        native_count
    })
    .join()
    .unwrap();
    assert!(
        count >= 1,
        "cold ERR_STATE/TLS allocations must be observed"
    );
    eprintln!(
        "Preinitialized mount open cold failure: native allocator calls={count}, Rust allocator calls=0"
    );
}
#[test]
fn admitted_native_jwt_core_and_hashes_allocate_zero_c_and_rust_heap() {
    let Some((start, stop)) = native_probe() else {
        return;
    };
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    let signing = grant(Phase::ReadlessFinalizer, &control);
    workspace.install_seed_for_test(&signing, &SEED);
    let ((len, native_count), rust_count, rust_bytes) = measure(|| {
        unsafe { start() };
        let len = workspace
            .sign(signing, point(), CLAIMS, b"{}", &mut parser, &control)
            .map(str::len);
        let count = unsafe { stop() };
        (len, count)
    });
    assert_eq!((native_count, rust_count, rust_bytes), (0, 0, 0));
    let token = workspace.output[..len.unwrap()].to_vec();
    let verification = grant(Phase::FreshAuthentication, &control);
    workspace.install_seed_for_test(&verification, &SEED);
    let ((verified, native_count), rust_count, rust_bytes) = measure(|| {
        unsafe { start() };
        let verified = workspace
            .verify(
                verification,
                point(),
                &token,
                OPTIONS,
                15_000,
                &mut parser,
                &control,
            )
            .map(|value| value.dependency);
        let count = unsafe { stop() };
        (verified, count)
    });
    assert!(verified.is_ok());
    assert_eq!((native_count, rust_count, rust_bytes), (0, 0, 0));
    let ((hashes, native_count), rust_count, rust_bytes) = measure(|| {
        unsafe { start() };
        let hashes = (sha256(b"abc", &control), sha512(b"abc", &control));
        let count = unsafe { stop() };
        (hashes, count)
    });
    assert!(hashes.0.is_ok() && hashes.1.is_ok());
    assert_eq!((native_count, rust_count, rust_bytes), (0, 0, 0));
    eprintln!(
        "Admitted JWT sign/verify/SHA core: native allocator calls=0, Rust allocator calls=0"
    );
}
#[test]
fn operation_unwind_guard_erases_and_disarms_material() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut workspace = workspace(&control);
    let grant = grant(Phase::ReadlessFinalizer, &control);
    workspace.install_seed_for_test(&grant, &SEED);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _erase = ExitErase::new(&mut workspace);
        workspace.decoded[0] = 1;
        panic!("test-only unwind after private material admission");
    }));
    assert!(unwind.is_err());
    assert!(workspace.secret.iter().all(|byte| *byte == 0));
    assert!(workspace.decoded.iter().all(|byte| *byte == 0));
    assert!(workspace.binding.is_none());
}
#[test]
fn phase_and_definition_are_bound_to_admitted_material() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    let initial = grant(Phase::InitialAuthentication, &control);
    workspace.install_seed_for_test(&initial, &SEED);
    let fresh = grant(Phase::FreshAuthentication, &control);
    assert!(matches!(
        workspace.verify(
            fresh,
            point(),
            &token(CLAIMS),
            OPTIONS,
            15_000,
            &mut parser,
            &control
        ),
        Err(Error::SecretUnavailable)
    ));
    let first = grant(Phase::ReadlessFinalizer, &control);
    workspace.install_seed_for_test(&first, &SEED);
    let mut other = attenuation(Phase::ReadlessFinalizer);
    other.definition = "otherFinalizer";
    let second =
        unsafe { Grant::from_trusted_capture(fields(), other, point(), &control) }.unwrap();
    assert_eq!(
        workspace.sign(second, point(), CLAIMS, b"{}", &mut parser, &control),
        Err(Error::SecretUnavailable)
    );
}
#[test]
fn exact_managed_aad_writer_uses_fixed_buffer_without_allocations() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let grant = grant(Phase::FreshAuthentication, &control);
    for (purpose, text) in [
        (EnvelopePurpose::Dek, "dek"),
        (EnvelopePurpose::Material, "material"),
    ] {
        let mut output = [0; 512];
        let (result, count, bytes) =
            measure(|| envelope_aad_into(&grant, purpose, &mut output, &control));
        let expected = serde_json::to_vec(&serde_json::json!([
            "flower-key-v1",
            "domain",
            "id",
            1,
            "Ed25519",
            text
        ]))
        .unwrap();
        assert_eq!(&output[..result.unwrap()], expected.as_slice());
        assert_eq!((count, bytes), (0, 0));
    }
    assert_eq!(
        envelope_aad_into(&grant, EnvelopePurpose::Dek, &mut [0; 1], &control),
        Err(Error::Capacity)
    );
}
#[test]
fn jwt_strict_signature_rejects_scalar_malleability() {
    let mut token = token(CLAIMS);
    let signature_at = token.iter().rposition(|b| *b == b'.').unwrap() + 1;
    let mut signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&token[signature_at..])
        .unwrap()
        .try_into()
        .unwrap();
    let order: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for (byte, addend) in signature[32..].iter_mut().zip(order) {
        carry += u16::from(*byte) + u16::from(addend);
        *byte = carry as u8;
        carry >>= 8;
    }
    token.truncate(signature_at);
    token.extend_from_slice(URL_SAFE_NO_PAD.encode(signature).as_bytes());
    assert_eq!(verify_case(&token, OPTIONS, 15_000), Err(Error::Signature));
}

#[test]
fn native_crypto_call_count_is_hard_bounded_and_fatal_sticky() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    for _ in 0..MAX_CRYPTO_CALLS {
        let denied = grant(Phase::InitialAuthentication, &control);
        assert_eq!(
            workspace.sign(denied, point(), CLAIMS, b"{}", &mut parser, &control),
            Err(Error::Authority)
        );
    }
    let denied = grant(Phase::InitialAuthentication, &control);
    assert_eq!(
        workspace.sign(denied, point(), CLAIMS, b"{}", &mut parser, &control),
        Err(Error::WorkLimit)
    );
    assert_eq!(sha256(b"", &control), Err(Error::WorkLimit));
    assert!(control.work.get() > 0); // specifically the hard call cap, not bytes.
}

#[test]
fn untrusted_header_selector_is_borrowed_bounded_and_never_authenticates() {
    let cancelled = AtomicBool::new(false);
    let control = control(&cancelled);
    let mut parser = parser(&control);
    let mut workspace = workspace(&control);
    // Deliberately wrong signature: selector is NOT authentication evidence.
    let forged = signed(br#"{"alg":"EdDSA","kid":"flower.id.7"}"#, CLAIMS, &[8; 32]);
    let (selector, count, bytes) =
        measure(|| workspace.untrusted_kid(&forged, &mut parser, &control));
    assert_eq!(selector.unwrap().value, "flower.id.7");
    assert_eq!((count, bytes), (0, 0));
    assert!(workspace.binding.is_none());
    assert!(workspace.secret.iter().all(|b| *b == 0));
    assert_eq!(
        workspace.sign(
            grant(Phase::ReadlessFinalizer, &control),
            point(),
            CLAIMS,
            b"{}",
            &mut parser,
            &control
        ),
        Err(Error::SecretUnavailable)
    );
}

#[test]
fn not_active_dependency_wakes_at_earlier_expiration_boundary() {
    let future = token(br#"{"exp":20,"nbf":30}"#);
    assert_eq!(
        verify_case(&future, b"{}", 15_000),
        Err(Error::NotActive {
            changes_at_ms: 20_000
        })
    );
    assert_eq!(
        verify_case(&future, b"{}", 20_000),
        Err(Error::Expired { at_ms: 20_000 })
    );
}

#[path = "mounted_tests.rs"]
mod mounted_tests;

#[test]
fn definition_identity_unicode_nul_and_384_byte_bound_are_length_delimited() {
    let cancelled = AtomicBool::new(false);
    let original = control(&cancelled);
    let mut attenuation = attenuation(Phase::ReadlessFinalizer);
    attenuation.definition = "public.λ\0.$sql.finalize";
    let first =
        unsafe { Grant::from_trusted_capture(fields(), attenuation, point(), &original) }.unwrap();
    let mut attenuation = self::attenuation(Phase::ReadlessFinalizer);
    attenuation.definition = "public.λ\0.$sql.finalize.changed";
    let changed =
        unsafe { Grant::from_trusted_capture(fields(), attenuation, point(), &original) }.unwrap();
    assert!(first.fingerprint != changed.fingerprint);
    let longest = "λ".repeat(MAX_DEFINITION_BYTES / 2);
    let mut attenuation = self::attenuation(Phase::ReadlessFinalizer);
    attenuation.definition = &longest;
    assert!(
        unsafe { Grant::from_trusted_capture(fields(), attenuation, point(), &original) }.is_ok()
    );
    let too_long = format!("{longest}x");
    let mut attenuation = self::attenuation(Phase::ReadlessFinalizer);
    attenuation.definition = &too_long;
    assert!(matches!(
        unsafe { Grant::from_trusted_capture(fields(), attenuation, point(), &original) },
        Err(Error::Invalid)
    ));
    assert_eq!(name("λ"), Err(Error::Invalid));
    assert_eq!(name("tokens\0other"), Err(Error::Invalid));
}
