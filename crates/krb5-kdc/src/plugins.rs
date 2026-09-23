//! kdcpreauth / kdcpolicy / kdcauthdata extension points (Rust traits, not dlopen).

use std::sync::{Arc, Mutex, OnceLock};

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_types::{AuthorizationData, KerberosTime, PaData, PrincipalName, pa};

use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::preauth::{SpakeStep, process_pkinit, process_spake};
use crate::status;
use crate::store::{KDB_REQUIRES_HW_AUTH, Principal};

/// Outcome of one preauth module on an AS-REQ.
#[derive(Debug)]
pub enum PreauthAction {
    /// PKINIT produced a reply key and PA-PK-AS-REP.
    Pkinit {
        /// AS-REP key.
        key: ProtocolKey,
        /// PA-PK-AS-REP.
        pa: PaData,
        /// CMS SignedData verified (MIT `is_signed`).
        signed: bool,
    },
    /// SPAKE challenge METHOD-DATA.
    Challenge(Vec<u8>),
    /// SPAKE finished; key encrypts AS-REP.
    SpakeDone(ProtocolKey),
    /// PA-ENC-TIMESTAMP verified (replay recorded); caller must not re-verify.
    EncTsOk,
}

/// Rock passed to a kdcpreauth module's AS handler.
///
/// MIT `krb5_kdcpreauth_rock` (`kdc/kdc_util.h:422`).
#[derive(Clone, Copy)]
pub struct PreauthRock<'a> {
    /// KDC store the module reads.
    pub store: &'a dyn PrincipalRead,
    /// Client principal entry.
    pub client: &'a Principal,
    /// AS-REQ padata. `None` when the request carried none.
    pub padata: Option<&'a [PaData]>,
    /// Initial reply key.
    pub ikey: &'a ProtocolKey,
    /// Selected encryption type.
    pub etype: EncryptionType,
    /// Encoded AS-REQ.
    pub as_req_der: &'a [u8],
    /// Encoded request body.
    pub body_der: &'a [u8],
    /// Client name from the request.
    pub cname: &'a PrincipalName,
}

/// One kdcpreauth module.
pub trait KdcPreauth: Send + Sync {
    /// Stable name (built-in or demo).
    fn name(&self) -> &'static str;
    /// PA-DATA types this module owns.
    fn pa_types(&self) -> &'static [i32];
    /// METHOD-DATA offers for PREAUTH_REQUIRED.
    /// `armor` is set when the request is FAST-tunneled (`get_edata` rock).
    /// `requested` is the AS-REQ etype list (`have_client_keys`).
    fn advertise(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        armor: bool,
        requested: &[i32],
    ) -> Vec<PaData>;
    /// MIT `PA_HARDWARE` (`kdcpreauth_plugin.h`). FAST is still advertised
    /// under `hw_only` (`kdc_preauth.c:999-1001`).
    fn hardware(&self) -> bool {
        false
    }
    /// Process AS padata. `None` = not this module's request.
    ///
    /// # Errors
    ///
    /// Protocol / crypto failures.
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error>;
}

struct FastMod;
struct PkinitMod;
struct SpakeMod;
struct EncTsMod;

impl KdcPreauth for FastMod {
    fn name(&self) -> &'static str {
        "fast"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[pa::FX_FAST]
    }
    fn advertise(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _armor: bool,
        _requested: &[i32],
    ) -> Vec<PaData> {
        vec![PaData {
            padata_type: pa::FX_FAST,
            padata_value: Vec::<u8>::new().into(),
        }]
    }
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
        #[allow(unused_variables)]
        let PreauthRock {
            store,
            client,
            padata,
            ikey,
            etype,
            as_req_der,
            body_der,
            cname,
        } = *rock;
        Ok(None)
    }
}

impl KdcPreauth for PkinitMod {
    fn name(&self) -> &'static str {
        "pkinit"
    }
    fn hardware(&self) -> bool {
        true
    }
    fn pa_types(&self) -> &'static [i32] {
        &[pa::PK_AS_REQ]
    }
    fn advertise(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        _armor: bool,
        _requested: &[i32],
    ) -> Vec<PaData> {
        if store.pkinit_ca().is_none() {
            return Vec::new();
        }
        let mut out = vec![PaData {
            padata_type: pa::PK_AS_REQ,
            padata_value: Vec::<u8>::new().into(),
        }];
        // pkinit_srv.c:928-929: PKINIT_KX is PA_INFO, not PA_HARDWARE.
        if client.attributes & KDB_REQUIRES_HW_AUTH == 0 {
            out.push(PaData {
                padata_type: pa::PKINIT_KX,
                padata_value: Vec::<u8>::new().into(),
            });
        }
        out
    }
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
        #[allow(unused_variables)]
        let PreauthRock {
            store,
            client,
            padata,
            ikey,
            etype,
            as_req_der,
            body_der,
            cname,
        } = *rock;
        match process_pkinit(
            store,
            padata,
            etype,
            as_req_der,
            body_der,
            cname,
            store.realm(),
        ) {
            Ok(Some((key, pa, signed))) => {
                store.record_as_outcome(cname, true);
                Ok(Some(PreauthAction::Pkinit { key, pa, signed }))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                store.record_as_outcome(cname, false);
                Err(e)
            }
        }
    }
}

impl KdcPreauth for SpakeMod {
    fn name(&self) -> &'static str {
        "spake"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[pa::SPAKE]
    }
    fn advertise(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        _armor: bool,
        requested: &[i32],
    ) -> Vec<PaData> {
        // spake_edata (spake_kdc.c:309-314): omit when client_keyblock is
        // NULL — `select_client_key` left ENCTYPE_NULL, the same condition
        // as `have_client_keys` being false. Groups still required
        // (groups.c:60,235-238).
        if store.policy().spake_preauth_groups.is_empty()
            || !have_client_keys(store, client, requested)
        {
            return Vec::new();
        }
        vec![PaData {
            padata_type: pa::SPAKE,
            padata_value: Vec::<u8>::new().into(),
        }]
    }
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
        #[allow(unused_variables)]
        let PreauthRock {
            store,
            client,
            padata,
            ikey,
            etype,
            as_req_der,
            body_der,
            cname,
        } = *rock;
        match process_spake(store, client, padata, ikey, body_der) {
            Ok(Some(SpakeStep::Challenge(e_data))) => Ok(Some(PreauthAction::Challenge(e_data))),
            Ok(Some(SpakeStep::Done(k))) => {
                store.record_as_outcome(cname, true);
                Ok(Some(PreauthAction::SpakeDone(k)))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                store.record_as_outcome(cname, false);
                Err(e)
            }
        }
    }
}

impl KdcPreauth for EncTsMod {
    fn name(&self) -> &'static str {
        "enc-timestamp"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[pa::ENC_TIMESTAMP]
    }
    fn advertise(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        armor: bool,
        requested: &[i32],
    ) -> Vec<PaData> {
        // enc_ts_get (kdc_preauth_encts.c:39-43): ENOENT when FAST armor is
        // present or `have_client_keys` is false (`kdc_preauth.c:442`).
        if armor || !have_client_keys(store, client, requested) {
            return Vec::new();
        }
        vec![PaData {
            padata_type: pa::ENC_TIMESTAMP,
            padata_value: Vec::<u8>::new().into(),
        }]
    }
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
        #[allow(unused_variables)]
        let PreauthRock {
            store,
            client,
            padata,
            ikey,
            etype,
            as_req_der,
            body_der,
            cname,
        } = *rock;
        let Some(blob) = crate::issue::extract_enc_timestamp(padata) else {
            return Ok(None);
        };
        let enc: krb5_types::EncryptedData = match krb5_asn1::decode(blob.as_ref()) {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };
        // enc_ts_verify (kdc_preauth_encts.c:74-92): krb5_dbe_search_enctype
        // (client, &start, etype, -1, kvno 0) walks the keys of the declared
        // etype at the *highest kvno* only (kdb_default.c:65-67) and skips
        // non-permitted enctypes (:60-61, :82-86) — a timestamp under a
        // retired kvno's key (a stale keytab) never decrypts. A miss is
        // KRB5_KDB_NO_MATCHING_KEY, remapped to KRB5KDC_ERR_PREAUTH_FAILED
        // (24) at :113-114; KRB5_KDB_NO_PERMITTED_KEY (a declared etype
        // outside permitted_enctypes, :60-61) is not remapped here but is
        // not a pass-through code either, so `filter_preauth_error`
        // (kdc_preauth.c:1092-1133) makes it the same 24 on the wire. An
        // unknown etype matches no key.
        let policy = store.policy();
        let top = client.keys.iter().map(|k| k.kvno).max();
        let keys: Vec<_> = match krb5_crypto::EncryptionType::known(enc.etype) {
            Ok(pa_et) if !policy.etype_permitted(pa_et) => Vec::new(),
            Ok(pa_et) => client
                .keys
                .iter()
                .filter(|k| Some(k.kvno) == top && k.etype == pa_et)
                .collect(),
            Err(_) => Vec::new(),
        };
        let mut last_err = None;
        for k in keys {
            match crate::issue::verify_enc_timestamp(store, client, &k.key, blob.as_ref()) {
                Ok(()) => {
                    store.record_as_outcome(cname, true);
                    return Ok(Some(PreauthAction::EncTsOk));
                }
                Err(e) => last_err = Some(e),
            }
        }
        store.record_as_outcome(cname, false);
        Err(last_err.unwrap_or_else(|| {
            crate::preauth::proto(
                krb5_types::err::PREAUTH_FAILED,
                crate::status::PREAUTH_FAILED,
            )
        }))
    }
}

struct EncChallengeMod;

impl KdcPreauth for EncChallengeMod {
    fn name(&self) -> &'static str {
        "encrypted-challenge"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[pa::ENCRYPTED_CHALLENGE]
    }
    fn advertise(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        armor: bool,
        requested: &[i32],
    ) -> Vec<PaData> {
        // ec_edata (kdc_preauth_ec.c:37-48): empty 138 only with armor and
        // `have_client_keys` (`kdc_preauth.c:442`).
        if !armor || !have_client_keys(store, client, requested) {
            return Vec::new();
        }
        vec![PaData {
            padata_type: pa::ENCRYPTED_CHALLENGE,
            padata_value: Vec::<u8>::new().into(),
        }]
    }
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
        #[allow(unused_variables)]
        let PreauthRock {
            store,
            client,
            padata,
            ikey,
            etype,
            as_req_der,
            body_der,
            cname,
        } = *rock;
        Ok(None)
    }
}

static EXTRA: Mutex<Vec<Arc<dyn KdcPreauth>>> = Mutex::new(Vec::new());
static BUILTIN: OnceLock<Vec<Arc<dyn KdcPreauth>>> = OnceLock::new();

fn builtins() -> &'static [Arc<dyn KdcPreauth>] {
    BUILTIN.get_or_init(|| {
        vec![
            Arc::new(FastMod) as Arc<dyn KdcPreauth>,
            Arc::new(PkinitMod),
            Arc::new(SpakeMod),
            Arc::new(EncChallengeMod),
            Arc::new(EncTsMod),
        ]
    })
}

/// Extra modules after the built-ins (tests / deploy).
pub fn register_preauth(m: Arc<dyn KdcPreauth>) {
    EXTRA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(m);
}

/// All modules, built-ins first.
#[must_use]
pub(crate) fn preauth_modules() -> Vec<Arc<dyn KdcPreauth>> {
    let mut v: Vec<Arc<dyn KdcPreauth>> = builtins().to_vec();
    v.extend(
        EXTRA
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned(),
    );
    v
}

/// One kdcauthdata module (`kdcauthdata_plugin.h:105-118`). Errors are logged, not fatal.
pub trait KdcAuthdata: Send + Sync {
    /// Stable name (`greet` in MIT `plugins/authdata/greet_server`).
    fn name(&self) -> &'static str;
    /// Mutate ticket authdata. TGS-only modules return immediately on AS.
    ///
    /// `session` / `issuer` are `enc_tkt_reply->session` and the local TGS
    /// principal (`kdcauthdata_plugin.h:111-117`).
    ///
    /// # Errors
    ///
    /// Module-specific; the KDC logs and continues (`kdc_authdata.c:610-611`).
    fn handle(
        &self,
        is_tgs: bool,
        reply: &mut AuthorizationData,
        session: Option<&ProtocolKey>,
        issuer: Option<(&PrincipalName, &str)>,
    ) -> Result<(), Error>;
}

static EXTRA_AD: Mutex<Vec<Arc<dyn KdcAuthdata>>> = Mutex::new(Vec::new());

/// Extra kdcauthdata modules (tests / deploy). None are built in.
pub fn register_authdata(m: Arc<dyn KdcAuthdata>) {
    EXTRA_AD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(m);
}

/// Loaded kdcauthdata modules (empty unless [`register_authdata`] was called).
#[must_use]
pub(crate) fn authdata_modules() -> Vec<Arc<dyn KdcAuthdata>> {
    EXTRA_AD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// METHOD-DATA modules after the leading empty PA-FX-FAST
/// (`get_preauth_hint_list` `kdc_preauth.c:999-1006`).
pub fn advertise_preauth(
    store: &dyn PrincipalRead,
    client: &Principal,
    armor: bool,
    requested: &[i32],
) -> Vec<PaData> {
    let hw_only = client.attributes & KDB_REQUIRES_HW_AUTH != 0;
    let mut out = vec![PaData {
        padata_type: pa::FX_FAST,
        padata_value: Vec::<u8>::new().into(),
    }];
    for m in preauth_modules() {
        if m.name() == "fast" {
            continue;
        }
        if hw_only && !m.hardware() {
            continue;
        }
        out.extend(m.advertise(store, client, armor, requested));
    }
    out
}

/// MIT `have_client_keys` (`kdc_preauth.c:434-447`): true when
/// `krb5_dbe_find_enctype(client, requested[i], -1, 0)` succeeds for any
/// requested etype — top kvno only, permitted enctypes only.
fn have_client_keys(store: &dyn PrincipalRead, client: &Principal, requested: &[i32]) -> bool {
    requested.iter().any(|&iana| {
        let Ok(et) = EncryptionType::known(iana) else {
            return false;
        };
        store.policy().find_enctype(client, Some(et), 0).is_ok()
    })
}

/// Run registered AS preauth modules in order. First `Some` action wins;
/// later modules (EXTRA after EncTsOk on a normal login) are skipped.
/// Observe-every-AS is a future kadm5_hook, not this cascade.
///
/// # Errors
///
/// Module protocol failures.
pub fn run_as_preauth(rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
    #[allow(unused_variables)]
    let PreauthRock {
        store,
        client,
        padata,
        ikey,
        etype,
        as_req_der,
        body_der,
        cname,
    } = *rock;
    for m in preauth_modules() {
        match m.process_as(&PreauthRock {
            store,
            client,
            padata,
            ikey,
            etype,
            as_req_der,
            body_der,
            cname,
        }) {
            Ok(Some(a)) => return Ok(Some(a)),
            Ok(None) => {}
            Err(e) => return Err(filter_preauth_error(e)),
        }
    }
    Ok(None)
}

/// MIT `filter_preauth_error` (`kdc_preauth.c:1092-1133`), applied where
/// `finish_check_padata` applies it (`:1206`): a module failure keeps its
/// code only when it is on the pass-through list; anything else — a KDB
/// code such as `KRB5_KDB_NO_PERMITTED_KEY`, an ASN.1 or crypto failure, 90
/// `PREAUTH_EXPIRED` — reaches the client as 24 `PREAUTH_FAILED`. Whatever
/// the code, the status word is the `PREAUTH_FAILED` `finish_preauth` sets
/// for every module failure (`do_as_req.c:442`), so the e_text is too. The
/// module's e-data rides along (`:1194-1196`), and the original failure
/// stays in the log detail. 34 `REPEAT` is the
/// documented R2-D1 exception (the replay cache answers before the filter
/// would run); FAST errors never pass here (`FastMod::process_as` is a
/// no-op, `kdc_find_fast` is not a module in MIT either).
pub(crate) fn filter_preauth_error(e: Error) -> Error {
    use krb5_types::err;
    const PASS_THROUGH: &[i32] = &[
        err::BAD_INTEGRITY,
        err::SKEW,
        err::PREAUTH_REQUIRED,
        err::ETYPE_NOSUPP,
        // rfc 4556
        err::CLIENT_NOT_TRUSTED,
        err::INVALID_SIG,
        err::DH_KEY_PARAMETERS_NOT_ACCEPTED,
        70, // CANT_VERIFY_CERTIFICATE
        71, // INVALID_CERTIFICATE
        72, // REVOKED_CERTIFICATE
        73, // REVOCATION_STATUS_UNKNOWN
        75, // CLIENT_NAME_MISMATCH
        77, // INCONSISTENT_KEY_PURPOSE
        78, // DIGEST_IN_CERT_NOT_ACCEPTED
        79, // PA_CHECKSUM_MUST_BE_INCLUDED
        80, // DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED
        81, // PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED
        // earlier drafts of what became rfc 4556
        66, // CERTIFICATE_MISMATCH
        63, // KDC_NOT_TRUSTED
        74, // REVOCATION_STATUS_UNAVAILABLE
        // pkinit alg-agility
        100, // NO_ACCEPTABLE_KDF
        // rfc 6113
        err::MORE_PREAUTH_DATA_REQUIRED,
        // k5e1 KRB5KDC_ERR_DISCARD (kdc_preauth.c:1125); do_as_req.c:372
        // suppresses the reply
        err::DISCARD,
        // R2-D1 (docs/security.md replay row): not in MIT's list
        err::REPEAT,
    ];
    match e {
        Error::PreauthRequired { .. } => e,
        Error::Protocol {
            code,
            text,
            e_data,
            detail,
        } => {
            let wire = if code == err::PREAUTH_FAILED || PASS_THROUGH.contains(&code) {
                code
            } else {
                err::PREAUTH_FAILED
            };
            // The module's own status word and any code the filter rewrote
            // survive in the log detail (MIT syslogs "preauth (%s) verify
            // failure: %s", kdc_preauth.c:1224-1226).
            let why = text.filter(|t| t != status::PREAUTH_FAILED);
            let detail = match (why, detail, wire == code) {
                (None, d, true) => d,
                (Some(w), Some(d), _) => Some(format!("preauth verify failure: {w} ({code}): {d}")),
                (Some(w), None, _) => Some(format!("preauth verify failure: {w} ({code})")),
                (None, Some(d), false) => Some(format!("preauth verify failure ({code}): {d}")),
                (None, None, false) => Some(format!("preauth verify failure ({code})")),
            };
            Error::Protocol {
                code: wire,
                text: Some(status::PREAUTH_FAILED.to_owned()),
                e_data,
                detail,
            }
        }
        other => Error::Protocol {
            code: err::PREAUTH_FAILED,
            text: Some(status::PREAUTH_FAILED.to_owned()),
            e_data: None,
            detail: Some(format!("preauth verify failure: {other}")),
        },
    }
}

/// MIT `check_kdcpolicy_as/tgs` lifetime rewrite (`policy.c:91-99`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyAdjustment {
    /// Seconds; 0 = leave `endtime` unchanged.
    pub lifetime: i64,
    /// Seconds; 0 = leave `renew_till` unchanged.
    pub renew_lifetime: i64,
}

/// Cap ticket times the way MIT `update_ticket_times` does.
pub fn apply_policy_times(
    now: &KerberosTime,
    end: &mut KerberosTime,
    renew_till: &mut Option<KerberosTime>,
    adj: &PolicyAdjustment,
) {
    if adj.lifetime != 0
        && let Ok(cap) = now.add_seconds(adj.lifetime)
        && cap.unix_seconds() < end.unix_seconds()
    {
        *end = cap;
    }
    if adj.renew_lifetime != 0
        && let Ok(cap) = now.add_seconds(adj.renew_lifetime)
    {
        match renew_till {
            Some(r) if cap.unix_seconds() < r.unix_seconds() => *r = cap,
            _ => {}
        }
    }
}

/// Ticket-policy hook (etype / transited stay on DefaultPolicy).
pub trait KdcPolicy: Send + Sync {
    /// Called after AS times are computed; `Err` denies the request.
    ///
    /// # Errors
    ///
    /// Policy denial.
    fn check_as(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        indicators: &[String],
    ) -> Result<PolicyAdjustment, Error>;
    /// Called after TGS times are computed; `Err` denies the request.
    ///
    /// # Errors
    ///
    /// Policy denial.
    fn check_tgs(
        &self,
        store: &dyn PrincipalRead,
        sname: &PrincipalName,
        indicators: &[String],
    ) -> Result<PolicyAdjustment, Error>;
}

/// Default policy: records nothing; built-in ticket rules stay in issue/.
pub struct DefaultPolicy;

impl KdcPolicy for DefaultPolicy {
    fn check_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Ok(PolicyAdjustment::default())
    }
    fn check_tgs(
        &self,
        _store: &dyn PrincipalRead,
        _sname: &PrincipalName,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Ok(PolicyAdjustment::default())
    }
}

static POLICY: Mutex<Option<Arc<dyn KdcPolicy>>> = Mutex::new(None);

thread_local! {
    static THREAD_POLICY: std::cell::RefCell<Option<Arc<dyn KdcPolicy>>> =
        const { std::cell::RefCell::new(None) };
}

/// Install the policy hook for every thread (KDC serve workers).
pub fn set_policy(p: Arc<dyn KdcPolicy>) {
    *POLICY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(p);
}

/// Install a thread-local hook checked before the process-wide slot (tests).
pub fn set_thread_policy(p: Arc<dyn KdcPolicy>) {
    THREAD_POLICY.with(|t| *t.borrow_mut() = Some(p));
}

/// Drop the thread-local hook so this thread uses the process-wide slot.
pub fn clear_thread_policy() {
    THREAD_POLICY.with(|t| *t.borrow_mut() = None);
}

/// Current policy hook.
#[must_use]
pub fn current_policy() -> Arc<dyn KdcPolicy> {
    if let Some(p) = THREAD_POLICY.with(|t| t.borrow().clone()) {
        return p;
    }
    POLICY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .unwrap_or_else(|| Arc::new(DefaultPolicy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    use krb5_types::cammac::AdKdcIssued;

    use crate::testrealm::bootstrap_documented;
    use crate::testrealm::{
        DemoPolicy, DemoPreauth, DenyPolicy, GREET_AD_TYPE, GREET_TEXT, GreetAuth,
    };

    use crate::testrealm::{TEST_REALM, TEST_USER};

    use krb5_protocol::{as_req, pa_enc_timestamp};
    use krb5_types::PrincipalName;

    #[test]
    fn demo_preauth_and_policy_are_consulted() {
        let demo = DemoPreauth::new();
        register_preauth(Arc::clone(&demo) as Arc<dyn KdcPreauth>);
        let pol = Arc::new(DemoPolicy::default());
        set_thread_policy(Arc::clone(&pol) as Arc<dyn KdcPolicy>);
        let (store, _) = bootstrap_documented().unwrap();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let req = as_req(cname.clone(), TEST_REALM, 3, None).unwrap();
        let err = crate::issue_as(&store, &req).unwrap_err();
        match err {
            Error::PreauthRequired { .. } => {}
            other => panic!("{other:?}"),
        }
        assert!(
            demo.ads.load(Ordering::SeqCst) >= 1,
            "demo advertise must run from preauth_required"
        );
        let procs_after_required = demo.procs.load(Ordering::SeqCst);
        assert!(
            procs_after_required >= 1,
            "demo process_as must run when no module returns an action"
        );
        let key = store
            .get_name(&cname)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let padata = vec![pa_enc_timestamp(&key).unwrap()];
        let req = as_req(cname, TEST_REALM, 4, Some(padata)).unwrap();
        crate::issue_as(&store, &req).expect("AS");
        assert_eq!(
            demo.procs.load(Ordering::SeqCst),
            procs_after_required,
            "EncTsOk short-circuits EXTRA process_as"
        );
        assert!(
            pol.as_checks.load(Ordering::SeqCst) >= 1,
            "demo policy check_as must run"
        );
        EXTRA
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        clear_thread_policy();
    }

    #[test]
    fn deny_policy_blocks_issue_as_and_issue_tgs() {
        use crate::testrealm::documented_host;

        use krb5_protocol::tgs_req;

        set_thread_policy(Arc::new(DenyPolicy));
        let (store, _) = bootstrap_documented().unwrap();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let key = store
            .get_name(&cname)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = as_req(
            cname.clone(),
            TEST_REALM,
            5,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        let as_err = crate::issue_as(&store, &req).unwrap_err();
        match as_err {
            Error::Protocol { code, .. } if code == krb5_types::err::POLICY => {}
            other => panic!("AS deny: {other:?}"),
        }
        clear_thread_policy();
        let req = as_req(
            cname.clone(),
            TEST_REALM,
            6,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        let issued = crate::issue_as(&store, &req).expect("AS with default policy");
        set_thread_policy(Arc::new(DenyPolicy));
        let tgs = tgs_req(
            issued.rep.0.ticket.clone(),
            &issued.session_key,
            TEST_REALM,
            &cname,
            documented_host(),
            TEST_REALM,
            7,
        )
        .unwrap();
        let tgs_err = crate::issue_tgs(&store, &tgs).unwrap_err();
        match tgs_err {
            Error::Protocol { code, .. } if code == krb5_types::err::POLICY => {}
            other => panic!("TGS deny: {other:?}"),
        }
        clear_thread_policy();
        let tgs_ok = tgs_req(
            issued.rep.0.ticket.clone(),
            &issued.session_key,
            TEST_REALM,
            &cname,
            documented_host(),
            TEST_REALM,
            8,
        )
        .unwrap();
        crate::issue_tgs(&store, &tgs_ok).expect("TGS with default policy");
    }

    #[test]
    fn swapped_policy_does_not_drop_as_lockout() {
        use crate::store::NamedPolicy;

        set_thread_policy(Arc::new(DemoPolicy::default()));
        let (mut store, _) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        store.put_policy(NamedPolicy {
            name: "lock".into(),
            min_length: 0,
            min_classes: 0,
            history: 0,
            max_fail: 1,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
            pw_min_life: 0,
            pw_max_life: 0,
            allowed_keysalts: None,
        });
        store
            .set_principal_policy(&user, Some("lock".into()))
            .unwrap();
        let zeros = krb5_crypto::ProtocolKey::from_bytes(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            &[0u8; 32],
        )
        .unwrap();
        let mut skew = 0i64;
        let mut bad_as = || {
            skew += 1;
            let ts = krb5_types::KerberosTime::now().add_seconds(skew).unwrap();
            as_req(
                user.clone(),
                TEST_REALM,
                1,
                Some(vec![
                    krb5_protocol::pa_enc_timestamp_at(&zeros, &ts).unwrap(),
                ]),
            )
            .unwrap()
        };
        assert!(crate::issue_as(&store, &bad_as()).is_err());
        let locked = crate::issue_as(&store, &bad_as()).unwrap_err();
        match locked {
            Error::Protocol { code, .. } if code == krb5_types::err::CLIENT_REVOKED => {}
            other => panic!("lockout must stay inline: {other:?}"),
        }
        clear_thread_policy();
    }

    #[test]
    fn set_policy_is_visible_on_a_spawned_thread() {
        let (store, _) = bootstrap_documented().unwrap();
        let pol = Arc::new(DemoPolicy::default());
        set_policy(Arc::clone(&pol) as Arc<dyn KdcPolicy>);
        let hits = std::thread::spawn({
            let pol = Arc::clone(&pol);
            let store = store.clone();
            move || {
                let user = store
                    .get_name(&PrincipalName::new(
                        PrincipalName::NT_PRINCIPAL,
                        [TEST_USER],
                    ))
                    .expect("user");
                current_policy()
                    .check_as(&store, user, &[])
                    .expect("demo policy allows");
                pol.as_checks.load(Ordering::SeqCst)
            }
        })
        .join()
        .expect("join");
        *POLICY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        assert!(
            hits >= 1,
            "serve-thread current_policy must see set_policy, got {hits}"
        );
    }

    #[test]
    fn enc_timestamp_registry_success_does_not_double_verify() {
        let (store, _) = bootstrap_documented().unwrap();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let key = store
            .get_name(&cname)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let padata = vec![pa_enc_timestamp(&key).unwrap()];
        let req = as_req(cname, TEST_REALM, 9, Some(padata)).unwrap();
        crate::issue_as(&store, &req).expect("registry EncTsOk must not re-verify (replay)");
        let replay = crate::issue_as(&store, &req).unwrap_err();
        match replay {
            Error::Protocol { code, .. } if code == krb5_types::err::REPEAT => {}
            other => panic!("second AS must REPEAT, got {other:?}"),
        }
    }

    #[test]
    fn greet_is_tgs_only() {
        let session = ProtocolKey::from_bytes(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            &[0x11; 32],
        )
        .unwrap();
        let tgs = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "KERBER.TEST"]);
        let mut as_ad = Vec::new();
        GreetAuth
            .handle(
                false,
                &mut as_ad,
                Some(&session),
                Some((&tgs, "KERBER.TEST")),
            )
            .unwrap();
        assert!(as_ad.is_empty());
        let mut tgs_ad = Vec::new();
        GreetAuth
            .handle(
                true,
                &mut tgs_ad,
                Some(&session),
                Some((&tgs, "KERBER.TEST")),
            )
            .unwrap();
        assert_eq!(tgs_ad.len(), 1);
        assert_eq!(tgs_ad[0].ad_type, pa::AD_IF_RELEVANT);
        let inner: AuthorizationData = krb5_asn1::decode(tgs_ad[0].ad_data.as_ref()).unwrap();
        assert_eq!(inner[0].ad_type, pa::AD_KDC_ISSUED);
        let issued: AdKdcIssued = krb5_asn1::decode(inner[0].ad_data.as_ref()).unwrap();
        assert_eq!(issued.elements[0].ad_type, GREET_AD_TYPE);
        assert_eq!(issued.elements[0].ad_data.as_ref(), GREET_TEXT);
    }
}
