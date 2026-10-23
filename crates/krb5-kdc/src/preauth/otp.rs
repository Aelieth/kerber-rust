//! OTP preauth for a client's tokens.

use std::time::{Duration, Instant};

use krb5_asn1::{decode, encode};
use krb5_crypto::{KeyUsage, ProtocolKey, decrypt_enc_data};
use krb5_log::klog;
use krb5_types::k5json::{self, Value};
use krb5_types::otp::{OtpTokenInfo, PaOtpChallenge, PaOtpEncRequest, PaOtpRequest};
use krb5_types::{KerberosFlags, PaData, PaEncTsEnc, PrincipalName, err, ku, pa};
use zeroize::Zeroizing;

use super::find_pa;
use crate::ad::authind_add;
use crate::asn1_text::decode_failure_text;
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::plugins::{
    OtpOutcome, OtpTokenFields, OtpVerdict, OtpVerifyRequest, PreauthAction, PreauthHint,
    PreauthRock, bounded_verify, find_otp_verifier, kdc_otp_event, otp_log_refusal,
    otp_verifier_names, request_peer, sanitize_otp_error,
};
use crate::store::{Principal, unix_now_u32};

// MIT: `DEFAULT_TYPE_NAME` (plugins/preauth/otp/otp_state.c:42-42)
pub(crate) const DEFAULT_TYPE: &str = krb5_config::DEFAULT_OTP_TYPE;

pub(crate) use krb5_config::OtpType as OtpTypeConfig;

pub(crate) struct OtpTypes(Vec<OtpTypeConfig>);

impl OtpTypes {
    // MIT: `token_type_default` (plugins/preauth/otp/otp_state.c:152-166)
    /// A verifier with no section is still a type.
    pub(crate) fn from_config(configured: &[OtpTypeConfig]) -> Self {
        let mut v = configured.to_vec();
        for n in otp_verifier_names() {
            if !v.iter().any(|t| t.name == n) {
                v.push(OtpTypeConfig::builtin(n));
            }
        }
        Self(v)
    }

    // MIT: `token_types_decode` (plugins/preauth/otp/otp_state.c:298-344)
    #[cfg(test)]
    pub(crate) fn builtin() -> Self {
        Self::from_config(&[OtpTypeConfig::builtin(DEFAULT_TYPE)])
    }

    // MIT: `token_decode` (plugins/preauth/otp/otp_state.c:422-427)
    fn find(&self, name: &[u8]) -> Option<&OtpTypeConfig> {
        self.0.iter().rev().find(|t| t.name.as_bytes() == name)
    }
}

// MIT: `otp_state_new` (plugins/preauth/otp/otp_state.c:564-610)
fn otp_types(store: &dyn PrincipalRead) -> OtpTypes {
    match store.policy().otp_kdc() {
        Ok(configured) => OtpTypes::from_config(configured),
        Err(_) => OtpTypes(Vec::new()),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OtpToken {
    pub(crate) ty: OtpTypeConfig,
    pub(crate) username: Vec<u8>,
    pub(crate) indicators: Option<Vec<String>>,
}

// MIT: `get_string` (kdc/kdc_preauth.c:410-414)
pub(crate) fn otp_attr(client: &Principal) -> Option<&str> {
    client
        .string_attrs
        .iter()
        .find(|(k, _)| k == "otp")
        .map(|(_, v)| v.as_str())
}

pub(crate) fn serve_start_diagnostics(store: &dyn PrincipalRead, registry_empty: bool) {
    if !crate::plugins::startup_module_loaded(&store.policy().kdcpreauth, "otp") {
        return;
    }
    let principals = store.list_principals().unwrap_or_default();
    let mut otp_users = 0usize;
    for p in &principals {
        if otp_attr(p).is_none() {
            continue;
        }
        otp_users += 1;
        if p.attributes & crate::store::KDB_REQUIRES_PRE_AUTH == 0 {
            tracing::warn!(
                target: "kdc.otp",
                "principal {} has an otp attribute but not +requires_preauth; OTP is never demanded",
                p.name.unparse_with_realm(store.realm())
            );
        }
    }
    if registry_empty && otp_users > 0 {
        crate::plugins::otp_log_refusal(&format!(
            "the otp preauth module is loaded and {otp_users} principal(s) have an otp attribute, \
             but no OTP verifier is registered; those logins will be refused"
        ));
    }
}

// MIT: `nonce_generate` (plugins/preauth/otp/main.c:137-153)
pub(crate) fn nonce_generate(key_len: usize) -> Result<Vec<u8>, Error> {
    let mut nonce = vec![0u8; 4 + key_len];
    getrandom::getrandom(&mut nonce[4..]).map_err(|_| Error::Rng)?;
    nonce[..4].copy_from_slice(&unix_now_u32().to_be_bytes());
    Ok(nonce)
}

// MIT: `krb5_check_clockskew` (lib/krb5/os/timeofday.c:54-67)
fn within_skew(then: u32, skew: i64) -> bool {
    (i64::from(unix_now_u32()) - i64::from(then)).abs() <= skew
}

const E_PREAUTH_FAILED: &str = "Preauthentication failed";
// MIT: `on_response` (plugins/preauth/otp/main.c:167-168)
const KRB5_PREAUTH_FAILED: i32 = -1_765_328_174;
const E_GENERIC: &str = "Generic preauthentication failure";
const E_INTEGRITY: &str = "Decrypt integrity check failed";
const E_SKEW: &str = "Clock skew too great";
pub(crate) const E_EINVAL: &str = "Invalid argument";
const E_ASN1: &str = "ASN.1 identifier doesn't match expected value";
pub(crate) const E_BAD_ENCTYPE: &str = "Bad encryption type";
pub(crate) const E_BAD_MSIZE: &str = "Message size is incompatible with encryption type";
const E_MSG_SIZE: &str = "Message too long";
// MIT: `MAX_ATTRSIZE` (lib/krad/internal.h:49-49)
// MIT: `attributes` (lib/krad/attr.c:62-62)
const MAX_USER_NAME: usize = 253;
// MIT: `attributes` (lib/krad/attr.c:63-63)
const MAX_USER_PASSWORD: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OtpFail {
    pub(crate) code: i32,
    pub(crate) emsg: String,
}

fn fail(code: i32, emsg: &str) -> OtpFail {
    OtpFail {
        code,
        emsg: emsg.to_owned(),
    }
}

// MIT: `kr_attr_valid` (lib/krad/attr.c:252-261)
fn attr_sizes_ok(username: &[u8], otp_value: &[u8]) -> bool {
    (1..=MAX_USER_NAME).contains(&username.len())
        && (1..=MAX_USER_PASSWORD).contains(&otp_value.len())
}

fn com_err(code_text: &str, text: &str) {
    klog::com_err(Some(code_text), text);
}

// MIT: `otp_edata` (plugins/preauth/otp/main.c:235-276)
pub(crate) fn otp_edata(client: &Principal, armor: Option<&ProtocolKey>) -> PreauthHint {
    let (Some(_), Some(armor)) = (otp_attr(client), armor) else {
        return PreauthHint::default();
    };
    let Ok(nonce) = nonce_generate(armor.as_bytes().len()) else {
        return PreauthHint::default();
    };
    // MIT: `otp_edata` (plugins/preauth/otp/main.c:254-256)
    let info = OtpTokenInfo {
        flags: KerberosFlags::from_slice(&[0, 0, 0, 0]),
        vendor: None,
        challenge: None,
        length: None,
        format: None,
        token_id: None,
        alg_id: None,
        supported_hash_alg: None,
        iteration_count: None,
    };
    let challenge = PaOtpChallenge {
        nonce: nonce.into(),
        service: None,
        token_info: vec![info],
        salt: None,
        s2kparams: None,
    };
    let Ok(der) = encode(&challenge) else {
        return PreauthHint::default();
    };
    PreauthHint {
        padata: vec![PaData {
            padata_type: pa::OTP_CHALLENGE,
            padata_value: der.into(),
        }],
        cookie: Vec::new(),
    }
}

// MIT: `decode_config_json` (plugins/preauth/otp/otp_state.c:485-502)
// MIT: `tokens_decode` (plugins/preauth/otp/otp_state.c:523-541)
// MIT: `indicators_decode` (plugins/preauth/otp/otp_state.c:378-397)
pub(crate) fn decode_tokens(
    name: &PrincipalName,
    realm: &str,
    types: &OtpTypes,
    config: &[u8],
) -> Result<Vec<OtpToken>, ()> {
    let Value::Array(mut items) = k5json::decode(config).map_err(|_| ())? else {
        return Err(());
    };
    if items.is_empty() {
        items.push(Value::Object(Vec::new()));
    }
    items
        .iter()
        .map(|item| {
            if !matches!(item, Value::Object(_)) {
                return Err(());
            }
            let type_name = match item.member("type") {
                Some(Value::String(s)) => s.as_slice(),
                _ => DEFAULT_TYPE.as_bytes(),
            };
            let ty = types.find(type_name).ok_or(())?;
            let username = match item.member("username") {
                Some(Value::String(s)) => s.clone(),
                _ if ty.strip_realm => name.unparse_no_realm().into_bytes(),
                _ => name.unparse_with_realm(realm).into_bytes(),
            };
            let indicators = match item.member("indicators") {
                None => None,
                Some(Value::Array(a)) => Some(
                    a.iter()
                        .map(indicator)
                        .collect::<Result<Vec<String>, ()>>()?,
                ),
                Some(_) => return Err(()),
            };
            Ok(OtpToken {
                ty: ty.clone(),
                username,
                indicators,
            })
        })
        .collect()
}

// MIT: `indicators_decode` (plugins/preauth/otp/otp_state.c:378-397)
fn indicator(v: &Value) -> Result<String, ()> {
    match v {
        Value::String(s) => String::from_utf8(s.clone()).map_err(|_| ()),
        _ => Err(()),
    }
}

// MIT: `nonce_verify` (plugins/preauth/otp/main.c:91-101)
fn nonce_verify(armor_len: usize, plain: &[u8], skew: i64) -> Result<(), OtpFail> {
    let er: PaOtpEncRequest =
        decode(plain).map_err(|_| fail(24, decode_failure_text(plain, false)))?;
    let n: &[u8] = er.nonce.as_ref();
    // Any other nonce length passes, with no clock check.
    if n.len() != armor_len + 4 {
        return Ok(());
    }
    if within_skew(u32::from_be_bytes([n[0], n[1], n[2], n[3]]), skew) {
        Ok(())
    } else {
        Err(fail(err::SKEW, E_SKEW))
    }
}

// MIT: `timestamp_verify` (plugins/preauth/otp/main.c:117-123)
fn timestamp_verify(plain: &[u8], skew: i64) -> Result<(), OtpFail> {
    let ts: PaEncTsEnc = decode(plain).map_err(|_| fail(24, decode_failure_text(plain, true)))?;
    if within_skew(ts.patimestamp.unix_seconds(), skew) {
        Ok(())
    } else {
        Err(fail(err::SKEW, E_SKEW))
    }
}

// MIT: `finish_verify_padata` (kdc/kdc_preauth.c:1224-1228)
pub(crate) fn process_otp(rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
    otp_verify(rock).map_err(OtpFail::into_error)
}

impl OtpFail {
    fn into_error(self) -> Error {
        Error::PreauthModule {
            code: self.code,
            message: self.emsg,
        }
    }
}

// MIT: `otp_verify` (plugins/preauth/otp/main.c:298-355)
fn otp_verify(rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, OtpFail> {
    let Some(raw) = find_pa(rock.padata, pa::OTP_REQUEST) else {
        return Ok(None);
    };
    let Some(armor) = rock.armor_key else {
        com_err(E_PREAUTH_FAILED, "No armor key found when verifying padata");
        return Err(fail(24, E_PREAUTH_FAILED));
    };
    let req: PaOtpRequest = decode(raw).map_err(|_| {
        com_err(E_ASN1, "Unable to decode OTP request");
        fail(24, E_ASN1)
    })?;
    let usage = KeyUsage::new(ku::PA_OTP_REQUEST).map_err(|_| fail(24, E_GENERIC))?;
    let plain = decrypt_enc_data(
        armor,
        usage,
        req.enc_data.etype,
        req.enc_data.cipher.as_ref(),
    )
    .map_err(|e| {
        let (code, emsg) = match e {
            krb5_crypto::Error::Integrity => (err::BAD_INTEGRITY, E_INTEGRITY),
            krb5_crypto::Error::BadEnctype(_) => (24, E_BAD_ENCTYPE),
            krb5_crypto::Error::CiphertextTooShort => (24, E_BAD_MSIZE),
            _ => (24, E_GENERIC),
        };
        com_err(emsg, "Unable to decrypt encData in PA-OTP-REQUEST");
        com_err(emsg, "Unable to decrypt nonce");
        fail(code, emsg)
    })?;
    let skew = rock.store.policy().skew;
    if let Err(e) = nonce_verify(armor.as_bytes().len(), &plain, skew)
        .or_else(|_| timestamp_verify(&plain, skew))
    {
        com_err(&e.emsg, "Unable to verify nonce or timestamp");
        return Err(e);
    }
    let Some(config) = otp_attr(rock.client) else {
        return Err(fail(24, E_GENERIC));
    };
    let realm = rock.store.realm();
    let Ok(tokens) = decode_tokens(
        &rock.client.name,
        realm,
        &otp_types(rock.store),
        config.as_bytes(),
    ) else {
        com_err(
            E_EINVAL,
            &format!(
                "Can't decode otp config string for principal '{}'",
                rock.client.name.unparse_with_realm(realm)
            ),
        );
        return Err(fail(24, E_EINVAL));
    };
    let otp_value: &[u8] = req.otp_value.as_ref().map_or(&[][..], AsRef::as_ref);
    let runtime = rock.store.otp_runtime();
    let pool = runtime.map(crate::plugins::OtpRuntime::pool);
    let principal_label = rock.client.name.unparse_with_realm(realm);
    let peer = request_peer();
    for tok in &tokens {
        // A bad length fails before a verifier runs.
        if !attr_sizes_ok(&tok.username, otp_value) {
            return Err(fail(24, E_MSG_SIZE));
        }
        let verifier = match runtime {
            Some(rt) => rt.find(&tok.ty.name),
            None => find_otp_verifier(&tok.ty.name),
        };
        let Some(verifier) = verifier else {
            otp_log_refusal(&format!(
                "no OTP verifier registered for token type '{}'",
                tok.ty.name
            ));
            return Err(fail(
                24,
                &format!(
                    "No OTP verifier registered for token type '{}'",
                    tok.ty.name
                ),
            ));
        };
        let vname = verifier.name();
        // MIT: `request_send` (plugins/preauth/otp/otp_state.c:661)
        let timeout_ms = match u64::try_from(tok.ty.timeout_ms) {
            Ok(ms) if ms > 0 => ms,
            _ => 5000,
        };
        let timeout = Duration::from_millis(timeout_ms);
        let now = Instant::now();
        let request = OtpVerifyRequest {
            principal: rock.client.clone(),
            realm: realm.to_owned(),
            token_type: tok.ty.name.clone(),
            username: tok.username.clone(),
            otp_value: Zeroizing::new(otp_value.to_vec()),
            peer: peer.clone(),
            request_time: now,
            deadline: now + timeout,
            token: OtpTokenFields {
                ty_name: tok.ty.name.clone(),
                indicators: tok
                    .indicators
                    .clone()
                    .unwrap_or_else(|| tok.ty.indicators.clone()),
            },
        };
        let outcome = bounded_verify(pool, verifier, request, timeout);
        let duration_us = u64::try_from(now.elapsed().as_micros()).unwrap_or(u64::MAX);
        match outcome {
            OtpOutcome::Verdict(OtpVerdict::Accept) => {
                kdc_otp_event(&principal_label, &tok.ty.name, "accept", duration_us);
                // MIT: `callback` (plugins/preauth/otp/otp_state.c:632-657)
                let mut indicators = Vec::new();
                // Empty indicators replace the type's, even an empty list.
                for ind in tok.indicators.as_deref().unwrap_or(&tok.ty.indicators[..]) {
                    authind_add(&mut indicators, ind);
                }
                return Ok(Some(PreauthAction::Otp {
                    key: armor.clone(),
                    indicators,
                }));
            }
            OtpOutcome::Verdict(OtpVerdict::Reject) => {
                kdc_otp_event(&principal_label, &tok.ty.name, "reject", duration_us);
            }
            OtpOutcome::Verdict(OtpVerdict::Error(text)) => {
                kdc_otp_event(&principal_label, &tok.ty.name, "error", duration_us);
                let text = sanitize_otp_error(&text);
                otp_log_refusal(&format!(
                    "OTP verifier '{vname}' errored for {principal_label}: {text}"
                ));
                return Err(fail(24, &text));
            }
            OtpOutcome::TimedOut => {
                kdc_otp_event(&principal_label, &tok.ty.name, "timeout", duration_us);
                otp_log_refusal(&format!(
                    "OTP verifier '{vname}' did not answer in {} ms (deadline {timeout_ms}) for {principal_label}",
                    duration_us / 1000
                ));
                return Err(fail(24, "OTP verifier timed out"));
            }
        }
    }
    Err(fail(KRB5_PREAUTH_FAILED, E_GENERIC))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{OtpVerifier, clear_thread_otp_verifiers, set_thread_otp_verifiers};
    use krb5_crypto::{EncryptionType, encrypt};
    use krb5_types::EncryptedData;
    use krb5_types::otp::PaOtpRequest as Req;
    use std::sync::Arc;

    fn types(strip: bool) -> OtpTypes {
        let mut t = OtpTypes::builtin();
        t.0.push(OtpTypeConfig {
            name: "udp".into(),
            strip_realm: strip,
            indicators: vec!["t1".into(), "t2".into()],
            timeout_ms: 5000,
            retries: 3,
        });
        t
    }

    fn user() -> PrincipalName {
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["u"])
    }

    fn dec(cfg: &str) -> Result<Vec<OtpToken>, ()> {
        decode_tokens(&user(), "R", &types(true), cfg.as_bytes())
    }

    #[test]
    fn decode_tokens_table() {
        for bad in [
            "",
            " ",
            "{}",
            "1",
            "\"x\"",
            "null",
            "[1]",
            "[null]",
            "[[]]",
            "[{} x",
            "[{}] x",
            "[{\"type\":\"nosuch\"}]",
            "[{\"type\":\"default\"}]",
            "[{\"indicators\":\"a\"}]",
            "[{\"indicators\":[1]}]",
            "[{\"indicators\":null}]",
            "[{\"indicators\":{}}]",
            "[{},]",
        ] {
            assert!(dec(bad).is_err(), "{bad:?}");
        }
        // MIT drops a malformed nested array with its member: no indicators, and the token stands.
        let t = dec(r#"[{"indicators":["a"}]"#).unwrap();
        assert_eq!(t[0].indicators, None);
        // An empty array is [{}], with the defaults.
        let t = dec("[]").unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].ty.name, "DEFAULT");
        assert_eq!(t[0].username, b"u@R");
        assert_eq!(t[0].indicators, None);
        // A non-string type or username takes the default.
        let t = dec(r#"[{"type":5,"username":7}]"#).unwrap();
        assert_eq!(t[0].ty.name, "DEFAULT");
        assert_eq!(t[0].username, b"u@R");
        // A strip_realm type unparses without its realm; a JSON username is taken verbatim, even empty.
        let t = dec(r#"[{"type":"udp"},{"type":"udp","username":""}]"#).unwrap();
        assert_eq!(t[0].username, b"u");
        assert_eq!(t[1].username, b"");
        // A duplicate key: the last value wins. Indicators override the type's and may be empty.
        let t = dec(r#"[{"username":"a","username":"b","indicators":[]}]"#).unwrap();
        assert_eq!(t[0].username, b"b");
        assert_eq!(t[0].indicators, Some(vec![]));
        let t = dec(r#"[{"type":"udp","indicators":["x"]}]"#).unwrap();
        assert_eq!(t[0].indicators, Some(vec!["x".to_owned()]));
        assert_eq!(t[0].ty.indicators, vec!["t1".to_owned(), "t2".to_owned()]);
        // The unparsed username quotes the separators, as krb5_unparse_name does.
        let n = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["a/b", "c@d"]);
        let t = decode_tokens(&n, "R", &types(false), b"[{}]").unwrap();
        assert_eq!(t[0].username, r"a\/b/c\@d@R".as_bytes());
    }

    struct Fixed(&'static str, OtpVerdict);
    impl OtpVerifier for Fixed {
        fn name(&self) -> &'static str {
            self.0
        }
        fn verify(&self, _: &OtpVerifyRequest) -> OtpVerdict {
            self.1.clone()
        }
    }

    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            clear_thread_otp_verifiers();
        }
    }

    fn enc_req(nonce: &[u8]) -> Vec<u8> {
        encode(&PaOtpEncRequest {
            nonce: nonce.to_vec().into(),
        })
        .unwrap()
    }

    fn pa142(key: &ProtocolKey, etype: i32, plain: &[u8]) -> PaData {
        let cipher = encrypt(key, KeyUsage::new(ku::PA_OTP_REQUEST).unwrap(), plain).unwrap();
        let req = Req {
            flags: KerberosFlags::from_slice(&[0; 4]),
            nonce: None,
            enc_data: EncryptedData {
                etype,
                kvno: None,
                cipher: cipher.into(),
            },
            hash_alg: None,
            iteration_count: None,
            otp_value: Some(b"1".to_vec().into()),
            pin: None,
            challenge: None,
            time: None,
            counter: None,
            format: None,
            token_id: None,
            alg_id: None,
            vendor: None,
        };
        PaData {
            padata_type: pa::OTP_REQUEST,
            padata_value: encode(&req).unwrap().into(),
        }
    }

    fn run(
        attr: Option<&str>,
        armor: Option<&ProtocolKey>,
        padata: &[PaData],
    ) -> Result<Option<PreauthAction>, OtpFail> {
        let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::testrealm::TEST_USER]);
        if let Some(a) = attr {
            store.set_string(&name, "otp", Some(a)).unwrap();
        }
        let client = store.get_name(&name).unwrap().clone();
        let k = client.keys[0].key.clone();
        otp_verify(&PreauthRock {
            store: &store,
            client: &client,
            padata: Some(padata),
            ikey: Some(&k),
            etype: Some(k.etype()),
            armor_key: armor,
            as_req_der: &[],
            body_der: &[],
            cname: &name,
        })
    }

    /// The (code, message) of every failure path of MIT `otp_verify`, and the accept result.
    #[test]
    fn every_failure_path_has_its_mit_code_and_message() {
        let _g = Guard;
        let a = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[5; 32]).unwrap();
        let b = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[6; 32]).unwrap();
        let t = a.etype().to_iana();
        let fresh = enc_req(&nonce_generate(32).unwrap());
        let mut stale_nonce = nonce_generate(32).unwrap();
        stale_nonce[..4].copy_from_slice(&unix_now_u32().saturating_sub(4000).to_be_bytes());
        let ts = |t: u32| {
            encode(&PaEncTsEnc {
                patimestamp: krb5_types::KerberosTime::from_unix_seconds(t),
                pausec: None,
            })
            .unwrap()
        };
        let got = |r: Result<Option<PreauthAction>, OtpFail>| {
            let f = r.unwrap_err();
            (f.code, f.emsg)
        };
        let want = |c: i32, m: &str| (c, m.to_owned());
        let ok = Some("[{}]");
        set_thread_otp_verifiers(vec![]);
        assert_eq!(
            got(run(ok, None, &[pa142(&a, t, &fresh)])),
            want(24, E_PREAUTH_FAILED)
        );
        let junk = PaData {
            padata_type: pa::OTP_REQUEST,
            padata_value: b"junk".to_vec().into(),
        };
        assert_eq!(got(run(ok, Some(&a), &[junk])), want(24, E_ASN1));
        assert_eq!(
            got(run(ok, Some(&a), &[pa142(&b, t, &fresh)])),
            want(31, E_INTEGRITY)
        );
        assert_eq!(
            got(run(ok, Some(&a), &[pa142(&a, 17, &fresh)])),
            want(24, E_BAD_ENCTYPE)
        );
        let mut short = pa142(&a, t, &fresh);
        let mut req: Req = decode(short.padata_value.as_ref()).unwrap();
        req.enc_data.cipher = vec![1, 2, 3].into();
        short.padata_value = encode(&req).unwrap().into();
        assert_eq!(got(run(ok, Some(&a), &[short])), want(24, E_BAD_MSIZE));
        // A stale PA-ENC-TS-ENC is clock skew: the timestamp check fails before any verifier is looked up.
        assert_eq!(
            got(run(
                ok,
                Some(&a),
                &[pa142(&a, t, &ts(unix_now_u32() - 4000))]
            )),
            want(err::SKEW, E_SKEW)
        );
        assert_eq!(
            got(run(ok, Some(&a), &[pa142(&a, t, &enc_req(&stale_nonce))])),
            want(24, "ASN.1 structure is missing a required field")
        );
        assert_eq!(
            got(run(ok, Some(&a), &[pa142(&a, t, b"garbage")])),
            want(24, "ASN.1 encoding ended unexpectedly")
        );
        // The other plaintext failures: none at all, an identifier error, and a missing field.
        for (plain, text) in [
            (&b""[..], "ASN.1 encoding ended unexpectedly"),
            (
                &[0x04, 0x02, 0xaa, 0xbb][..],
                "ASN.1 identifier doesn't match expected value",
            ),
            (
                &[0x30, 0x03, 0x81, 0x01, 0x00][..],
                "ASN.1 structure is missing a required field",
            ),
        ] {
            assert_eq!(
                got(run(ok, Some(&a), &[pa142(&a, t, plain)])),
                want(24, text),
                "{plain:?}"
            );
        }
        assert_eq!(
            got(run(None, Some(&a), &[pa142(&a, t, &fresh)])),
            want(24, E_GENERIC)
        );
        for bad in ["", "{}", r#"[{"type":"nosuch"}]"#] {
            assert_eq!(
                got(run(Some(bad), Some(&a), &[pa142(&a, t, &fresh)])),
                want(24, E_EINVAL),
                "{bad:?}"
            );
        }
        assert_eq!(
            got(run(ok, Some(&a), &[pa142(&a, t, &fresh)])),
            want(24, "No OTP verifier registered for token type 'DEFAULT'")
        );
        set_thread_otp_verifiers(vec![Arc::new(Fixed("DEFAULT", OtpVerdict::Reject))]);
        assert_eq!(
            got(run(ok, Some(&a), &[pa142(&a, t, &fresh)])),
            want(KRB5_PREAUTH_FAILED, E_GENERIC)
        );
        set_thread_otp_verifiers(vec![Arc::new(Fixed(
            "DEFAULT",
            OtpVerdict::Error("backend down".into()),
        ))]);
        assert_eq!(
            got(run(ok, Some(&a), &[pa142(&a, t, &fresh)])),
            want(24, "backend down")
        );
        set_thread_otp_verifiers(vec![Arc::new(Fixed("DEFAULT", OtpVerdict::Accept))]);
        let Ok(Some(PreauthAction::Otp { key, indicators })) = run(
            Some(r#"[{"indicators":["a"]}]"#),
            Some(&a),
            &[pa142(&a, t, &fresh)],
        ) else {
            panic!("accept")
        };
        assert_eq!(
            (key.as_bytes(), indicators),
            (a.as_bytes(), vec!["a".to_owned()])
        );
        assert!(matches!(run(ok, Some(&a), &[]), Ok(None)));
    }

    #[test]
    fn nonce_layout() {
        let n = nonce_generate(32).unwrap();
        assert_eq!(n.len(), 36);
        assert!(u32::from_be_bytes(n[..4].try_into().unwrap()).abs_diff(unix_now_u32()) <= 2);
        assert_ne!(nonce_generate(32).unwrap()[4..], n[4..]);
    }

    #[test]
    fn nonce_verify_quirks() {
        let enc = |n: &[u8]| {
            encode(&PaOtpEncRequest {
                nonce: n.to_vec().into(),
            })
            .unwrap()
        };
        let fresh = nonce_generate(32).unwrap();
        assert!(nonce_verify(32, &enc(&fresh), 300).is_ok());
        let mut stale = fresh.clone();
        stale[..4].copy_from_slice(&unix_now_u32().saturating_sub(4000).to_be_bytes());
        assert!(matches!(
            nonce_verify(32, &enc(&stale), 300),
            Err(OtpFail { code: 37, .. })
        ));
        // A nonce of another length passes with no clock check.
        assert!(nonce_verify(32, &enc(&[0, 0, 0, 1, 9]), 300).is_ok());
        assert!(nonce_verify(32, &[], 300).is_err());
        assert!(nonce_verify(32, b"junk", 300).is_err());
    }

    /// Stricter, fail-closed deviation: MIT reads a PA-ENC-TS-ENC as a wrong-length nonce, with no clock check, and this port refuses it as a nonce.
    // MIT: `decode_atype` (lib/krb5/asn.1/asn1_encode.c:1184-1199)
    /// an implicit tag decodes its element's contents as the base type, with no tag check of its own.
    // MIT: `check_atype_tag` (lib/krb5/asn.1/asn1_encode.c:1099-1105)
    /// an implicit tag's construction bit is not checked.
    #[test]
    fn a_pa_enc_ts_enc_is_not_read_as_a_nonce() {
        let ts = encode(&PaEncTsEnc {
            patimestamp: krb5_types::KerberosTime::from_unix_seconds(unix_now_u32()),
            pausec: None,
        })
        .unwrap();
        assert_eq!(&ts[..4], [0x30, 0x13, 0xa0, 0x11]);
        assert!(decode::<PaOtpEncRequest>(&ts).is_err());
    }

    /// One X3 case: its number, the `otp` octets, MIT's decode verdict, and the username octets.
    type X3Case = (u32, &'static [u8], bool, Option<&'static [u8]>);

    /// The `otp` strings of settle cell X3, with MIT's verdict on each. `true` is a decode, and the username is the one MIT's RADIUS stub received when the token names one.
    /// The cases where the KDC died under MIT (SEGV) are `false`: this port fails closed there.
    const X3_CASES: &[X3Case] = &[
        (1, b"[]", true, None),
        (2, b"[{}]", true, None),
        (3, b"{}", false, None),
        (4, b"[1]", false, None),
        (5, b"[[]]", false, None),
        (6, b"[null]", false, None),
        (7, b"[true]", false, None),
        (8, b"\"str\"", false, None),
        (9, b"null", false, None),
        (10, b"1", false, None),
        (11, b"", false, None),
        (12, b" ", false, None),
        (13, b"[{}] x", false, None),
        (14, b"[{}][{}]", false, None),
        (15, b" [{}] ", true, None),
        (16, b"[{},]", false, None),
        (17, b"[,{}]", false, None),
        (18, b"[{\"type\":5}]", true, None),
        (19, b"[{\"type\":null}]", true, None),
        (20, b"[{\"type\":\"DEFAULT\"}]", true, None),
        (21, b"[{\"type\":\"default\"}]", false, None),
        (22, b"[{\"type\":\"\"}]", false, None),
        (23, b"[{\"username\":5}]", true, None),
        (24, b"[{\"username\":null}]", true, None),
        (25, b"[{\"username\":\"\"}]", true, Some(b"")),
        (26, b"[{\"username\":\"a b\"}]", true, Some(b"a b")),
        (27, b"[{\"indicators\":\"x\"}]", false, None),
        (28, b"[{\"indicators\":null}]", false, None),
        (29, b"[{\"indicators\":[1]}]", false, None),
        (30, b"[{\"indicators\":[\"a\"]}]", true, None),
        (31, b"[{\"indicators\":[]}]", true, None),
        (32, b"[{\"unknown\":1}]", true, None),
        (
            33,
            b"[{\"type\":\"nosuch\",\"type\":\"DEFAULT\"}]",
            true,
            None,
        ),
        (
            34,
            b"[{\"type\":\"DEFAULT\",\"type\":\"nosuch\"}]",
            false,
            None,
        ),
        (35, b"[{\"x\":1.5}]", false, None),
        (36, b"[{\"x\":1e3}]", false, None),
        (37, b"[{\"x\":-1}]", true, None),
        (38, b"[{\"x\":01}]", true, None),
        (39, b"[{\"x\":+1}]", false, None),
        (40, b"[{\"x\":0x10}]", false, None),
        (41, b"[{\"x\":\"\\u00e9\"}]", false, None),
        (42, b"[{\"x\":\"\\u0100\"}]", false, None),
        (43, b"[{\"x\":\"\\ud83d\\ude00\"}]", false, None),
        (44, b"[{\"x\":\"\xc3\xa9\"}]", true, None),
        (45, b"[{\"x\":\"\xc4\x80\"}]", true, None),
        (46, b"[{\"x\":\"\xff\"}]", true, None),
        (47, b"[{\"x\":\"\x01\"}]", true, None),
        (48, b"[{\"x\":\"\\q\"}]", false, None),
        (49, b"[{\"x\":\"a\x09b\"}]", true, None),
        (50, b"[{\"x\":\"a\\tb\"}]", true, None),
        (51, b"[{\"username\":\"a\\u00e9b\"}]", false, None),
        (52, b"[{\"username\":\"a\\/b\"}]", true, Some(b"a/b")),
        (53, b"[{\"username\":\"a\\u0100b\"}]", false, None),
        (54, b"[{\"username\":\"\\ud83d\\ude00\"}]", false, None),
        (55, b"[{\"username\":\"a\\u0000b\"}]", true, Some(b"a")),
        (56, b"[{\"username\":\"a\\u0041b\"}]", true, Some(b"aAb")),
        (57, b"[{\"username\":\"a\\u007fb\"}]", false, None),
        (58, b"[{\"username\":\"a\\u0080b\"}]", true, Some(b"a\x80b")),
        (59, b"[{\"username\":\"a\\u00ffb\"}]", false, None),
        (60, b"[{\"username\":\"a\\u007Fb\"}]", true, Some(b"a\x7fb")),
        (61, b"[{\"username\":\"a\\u00E9b\"}]", true, Some(b"a\xe9b")),
        (62, b"[{\"username\":\"a\\u00FFb\"}]", true, Some(b"a\xffb")),
        (63, b"[{\"username\":\"a\\u004Ab\"}]", true, Some(b"aJb")),
        (64, b"[{\"username\":\"a\\u004ab\"}]", false, None),
        (65, b"[{\"username\":\"a\\nb\"}]", true, Some(b"a\x0ab")),
        (
            66,
            b"[{\"username\":\"a\xc3\xa9b\"}]",
            true,
            Some(b"a\xc3\xa9b"),
        ),
        (
            67,
            b"[{\"username\":\"x\",\"username\":\"y\"}]",
            true,
            Some(b"y"),
        ),
        (68, b"[{\"x\":99999999999999999999}]", false, None),
        (69, b"[{\"x\":-0}]", true, None),
        (70, b"[ ]", true, None),
        (71, b"[ {} ]", true, None),
        (72, b"[{\"type\":true}]", true, None),
        (73, b"[{\"username\":true}]", true, None),
        (74, b"[{\"indicators\":[\"a\",1]}]", false, None),
        (75, b"[{\"indicators\":[[\"a\"]]}]", false, None),
        (76, b"[{\"indicators\":[\"a\",\"a\"]}]", true, None),
        (77, b"[{\"t\\u0079pe\":\"nosuch\"}]", false, None),
        (
            78,
            b"[{\"type\":\"DEFAULT\"},{\"type\":\"DEFAULT\"}]",
            true,
            None,
        ),
        (79, b"[{\"x\":{\"y\":[{\"z\":null}]}}]", true, None),
        // X3 case 80 (X3.txt:156) (SEGV: fail closed)
        (80, b"[{\"x\":\"unterminated}]", false, None),
        (81, b"[{\"x\":tru}]", false, None),
        // X3 case 90 (X3.txt:170) (SEGV: fail closed)
        (90, b"[{}", false, None),
        // X3 case 91 (X3.txt:171) (SEGV: fail closed)
        (91, b"[1,", false, None),
        // X3 case 92 (X3.txt:172) (SEGV: fail closed)
        (92, b"[", false, None),
        // X3 case 93 (X3.txt:173) (SEGV: fail closed)
        (93, b"[1", false, None),
        (94, b"[{\"x\":[1,}]", true, None),
        (95, b"[{\"x\":[1,2}]", true, None),
        // X3 case 96 (X3.txt:176) (SEGV: fail closed)
        (96, b"[{\"a\":1", false, None),
        (97, b"[{\"x\":[}]", true, None),
        // X3 case 98 (X3.txt:178) (SEGV: fail closed)
        (98, b"[{\"type\":\"DEFAULT\"", false, None),
    ];

    /// MIT's JSON reader gives the verdict of each X3 case, and of the depth cases 82 to 89 (an array nested N deep inside the first member of the outer array's object).
    #[test]
    fn otp_json_matches_mits_decoder() {
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["otpuser"]);
        let types = OtpTypes::builtin();
        let decode = |input: &[u8]| decode_tokens(&name, "SETTLE.TEST", &types, input);
        for &(case, input, ok, username) in X3_CASES {
            let got = decode(input);
            assert_eq!(
                got.is_ok(),
                ok,
                "X3 case {case}: {:?}",
                String::from_utf8_lossy(input)
            );
            if let (Ok(tokens), Some(want)) = (&got, username) {
                assert_eq!(tokens[0].username, want, "X3 case {case}");
            }
        }
        for (n, ok) in [
            (30, true),
            (61, true),
            (62, false),
            (63, false),
            (64, false),
            (65, false),
            (100, false),
            (130, false),
        ] {
            let input = format!("[{{\"x\":{}{}}}]", "[".repeat(n), "]".repeat(n));
            assert_eq!(decode(input.as_bytes()).is_ok(), ok, "X3 depth {n}");
        }
    }

    /// The types in force are `[otp]`'s, in listing order, then one built-in type per registered verifier no section names; a verifier whose name a section carries keeps the section's settings; the last entry of a name is the one a token finds.
    #[test]
    fn configured_types_come_first_and_verifiers_add_the_rest() {
        let _g = Guard;
        set_thread_otp_verifiers(vec![
            Arc::new(Fixed("totp", OtpVerdict::Accept)),
            Arc::new(Fixed("sec", OtpVerdict::Accept)),
        ]);
        let mut sec = OtpTypeConfig::builtin("sec");
        sec.strip_realm = true;
        sec.indicators = vec!["mfa".into()];
        let t = OtpTypes::from_config(&[OtpTypeConfig::builtin("DEFAULT"), sec.clone()]);
        let names: Vec<&str> = t.0.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["DEFAULT", "sec", "totp"]);
        assert_eq!(t.find(b"sec"), Some(&sec));
        assert_eq!(t.find(b"totp"), Some(&OtpTypeConfig::builtin("totp")));
        assert_eq!(t.find(b"nosuch"), None);
        // The token found for a repeated name is the last one.
        let mut later = sec.clone();
        later.indicators = vec!["later".into()];
        let t = OtpTypes::from_config(&[sec, later.clone()]);
        assert_eq!(t.find(b"sec"), Some(&later));
    }

    /// The RADIUS sizes of the username and of the OTP value: 1 to 253 and 1 to 128 octets.
    #[test]
    fn attribute_sizes_are_the_radius_limits() {
        let fits = |u: usize, p: usize| attr_sizes_ok(&vec![b'u'; u], &vec![b'1'; p]);
        assert!(fits(1, 1) && fits(253, 128) && fits(253, 1) && fits(1, 128));
        assert!(!fits(0, 1) && !fits(254, 1) && !fits(1, 0) && !fits(1, 129));
    }
}
