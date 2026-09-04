//! kdcpreauth / kdcpolicy extension points (Rust traits, not dlopen).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use krb5_crypto::ProtocolKey;
use krb5_types::{PaData, PrincipalName, pa};

use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::preauth::{SpakeStep, process_pkinit, process_spake};
use crate::store::Principal;

/// Outcome of one preauth module on an AS-REQ.
#[derive(Debug)]
pub enum PreauthAction {
    /// PKINIT produced a reply key and PA-PK-AS-REP.
    Pkinit {
        /// AS-REP key.
        key: ProtocolKey,
        /// PA-PK-AS-REP.
        pa: PaData,
    },
    /// SPAKE challenge METHOD-DATA.
    Challenge(Vec<u8>),
    /// SPAKE finished; key encrypts AS-REP.
    SpakeDone(ProtocolKey),
    /// PA-ENC-TIMESTAMP verified (replay recorded); caller must not re-verify.
    EncTsOk,
}

/// One kdcpreauth module.
pub trait KdcPreauth: Send + Sync {
    /// Stable name (built-in or demo).
    fn name(&self) -> &'static str;
    /// PA-DATA types this module owns.
    fn pa_types(&self) -> &'static [i32];
    /// METHOD-DATA offers for PREAUTH_REQUIRED.
    fn advertise(&self, store: &dyn PrincipalRead, _client: &Principal) -> Vec<PaData>;
    /// Process AS padata. `None` = not this module's request.
    ///
    /// # Errors
    ///
    /// Protocol / crypto failures.
    #[allow(clippy::too_many_arguments)]
    fn process_as(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        padata: Option<&[PaData]>,
        ikey: &ProtocolKey,
        etype: krb5_crypto::EncryptionType,
        as_req_der: &[u8],
        body_der: &[u8],
        cname: &PrincipalName,
    ) -> Result<Option<PreauthAction>, Error>;
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
    fn advertise(&self, _store: &dyn PrincipalRead, _client: &Principal) -> Vec<PaData> {
        vec![PaData {
            padata_type: pa::FX_FAST,
            padata_value: Vec::<u8>::new().into(),
        }]
    }
    fn process_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _padata: Option<&[PaData]>,
        _ikey: &ProtocolKey,
        _etype: krb5_crypto::EncryptionType,
        _as_req_der: &[u8],
        _body_der: &[u8],
        _cname: &PrincipalName,
    ) -> Result<Option<PreauthAction>, Error> {
        Ok(None)
    }
}

impl KdcPreauth for PkinitMod {
    fn name(&self) -> &'static str {
        "pkinit"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[pa::PK_AS_REQ]
    }
    fn advertise(&self, store: &dyn PrincipalRead, _client: &Principal) -> Vec<PaData> {
        if store.pkinit_ca().is_none() {
            return Vec::new();
        }
        vec![
            PaData {
                padata_type: pa::PK_AS_REQ,
                padata_value: Vec::<u8>::new().into(),
            },
            PaData {
                padata_type: pa::TD_DH_PARAMETERS,
                padata_value: krb5_types::pkinit::encode_td_dh_p256().into(),
            },
        ]
    }
    fn process_as(
        &self,
        store: &dyn PrincipalRead,
        _client: &Principal,
        padata: Option<&[PaData]>,
        _ikey: &ProtocolKey,
        etype: krb5_crypto::EncryptionType,
        as_req_der: &[u8],
        body_der: &[u8],
        cname: &PrincipalName,
    ) -> Result<Option<PreauthAction>, Error> {
        match process_pkinit(
            store,
            padata,
            etype,
            as_req_der,
            body_der,
            cname,
            store.realm(),
        ) {
            Ok(Some((key, pa))) => {
                store.record_as_outcome(cname, true);
                Ok(Some(PreauthAction::Pkinit { key, pa }))
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
    fn advertise(&self, _store: &dyn PrincipalRead, _client: &Principal) -> Vec<PaData> {
        vec![PaData {
            padata_type: pa::SPAKE,
            padata_value: Vec::<u8>::new().into(),
        }]
    }
    fn process_as(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        padata: Option<&[PaData]>,
        ikey: &ProtocolKey,
        _etype: krb5_crypto::EncryptionType,
        _as_req_der: &[u8],
        body_der: &[u8],
        cname: &PrincipalName,
    ) -> Result<Option<PreauthAction>, Error> {
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
    fn advertise(&self, _store: &dyn PrincipalRead, _client: &Principal) -> Vec<PaData> {
        vec![PaData {
            padata_type: pa::ENC_TIMESTAMP,
            padata_value: Vec::<u8>::new().into(),
        }]
    }
    fn process_as(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        padata: Option<&[PaData]>,
        _ikey: &ProtocolKey,
        _etype: krb5_crypto::EncryptionType,
        _as_req_der: &[u8],
        _body_der: &[u8],
        cname: &PrincipalName,
    ) -> Result<Option<PreauthAction>, Error> {
        if !client.requires_preauth {
            return Ok(None);
        }
        let Some(blob) = crate::issue::extract_enc_timestamp(padata) else {
            return Ok(None);
        };
        let enc: krb5_types::EncryptedData = match krb5_asn1::decode(blob.as_ref()) {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };
        let Ok(pa_et) = krb5_crypto::EncryptionType::known(enc.etype) else {
            return Ok(None);
        };
        let keys: Vec<_> = client.keys.iter().filter(|k| k.etype == pa_et).collect();
        if keys.is_empty() {
            return Ok(None);
        }
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

/// Demo extra module: counts advertise/process so tests prove the registry.
#[derive(Debug)]
pub struct DemoPreauth {
    /// advertise() calls.
    pub ads: AtomicU64,
    /// process_as() calls.
    pub procs: AtomicU64,
}

impl DemoPreauth {
    /// Zero counters.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ads: AtomicU64::new(0),
            procs: AtomicU64::new(0),
        })
    }
}

impl KdcPreauth for DemoPreauth {
    fn name(&self) -> &'static str {
        "demo"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[]
    }
    fn advertise(&self, _store: &dyn PrincipalRead, _client: &Principal) -> Vec<PaData> {
        self.ads.fetch_add(1, Ordering::SeqCst);
        Vec::new()
    }
    fn process_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _padata: Option<&[PaData]>,
        _ikey: &ProtocolKey,
        _etype: krb5_crypto::EncryptionType,
        _as_req_der: &[u8],
        _body_der: &[u8],
        _cname: &PrincipalName,
    ) -> Result<Option<PreauthAction>, Error> {
        self.procs.fetch_add(1, Ordering::SeqCst);
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
pub fn preauth_modules() -> Vec<Arc<dyn KdcPreauth>> {
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

/// METHOD-DATA from every registered module plus ETYPE-INFO2 from the caller.
pub fn advertise_preauth(store: &dyn PrincipalRead, client: &Principal) -> Vec<PaData> {
    let mut out = Vec::new();
    for m in preauth_modules() {
        out.extend(m.advertise(store, client));
    }
    out
}

/// Run registered AS preauth modules in order. First `Some` action wins;
/// later modules (EXTRA after EncTsOk on a normal login) are skipped.
/// Observe-every-AS is a future kadm5_hook, not this cascade.
///
/// # Errors
///
/// Module protocol failures.
#[allow(clippy::too_many_arguments)]
pub fn run_as_preauth(
    store: &dyn PrincipalRead,
    client: &Principal,
    padata: Option<&[PaData]>,
    ikey: &ProtocolKey,
    etype: krb5_crypto::EncryptionType,
    as_req_der: &[u8],
    body_der: &[u8],
    cname: &PrincipalName,
) -> Result<Option<PreauthAction>, Error> {
    for m in preauth_modules() {
        if let Some(a) = m.process_as(
            store, client, padata, ikey, etype, as_req_der, body_der, cname,
        )? {
            return Ok(Some(a));
        }
    }
    Ok(None)
}

/// Ticket-policy hook (etype / transited / lifetimes stay on DefaultPolicy).
pub trait KdcPolicy: Send + Sync {
    /// Called on each AS issue after fetch; `Err` denies the request.
    ///
    /// # Errors
    ///
    /// Policy denial.
    fn check_as(&self, store: &dyn PrincipalRead, client: &Principal) -> Result<(), Error>;
    /// Called on each TGS issue; `Err` denies the request.
    ///
    /// # Errors
    ///
    /// Policy denial.
    fn check_tgs(&self, store: &dyn PrincipalRead, sname: &PrincipalName) -> Result<(), Error>;
}

/// Default policy: records nothing; built-in ticket rules stay in issue.rs.
pub struct DefaultPolicy;

impl KdcPolicy for DefaultPolicy {
    fn check_as(&self, _store: &dyn PrincipalRead, _client: &Principal) -> Result<(), Error> {
        Ok(())
    }
    fn check_tgs(&self, _store: &dyn PrincipalRead, _sname: &PrincipalName) -> Result<(), Error> {
        Ok(())
    }
}

/// Test hook: deny every AS and TGS.
pub struct DenyPolicy;

impl KdcPolicy for DenyPolicy {
    fn check_as(&self, _store: &dyn PrincipalRead, _client: &Principal) -> Result<(), Error> {
        Err(Error::Protocol {
            code: krb5_types::err::POLICY,
            text: Some("kdcpolicy".into()),
            e_data: None,
            detail: None,
        })
    }
    fn check_tgs(&self, _store: &dyn PrincipalRead, _sname: &PrincipalName) -> Result<(), Error> {
        Err(Error::Protocol {
            code: krb5_types::err::POLICY,
            text: Some("kdcpolicy".into()),
            e_data: None,
            detail: None,
        })
    }
}

/// Demo policy: counts AS/TGS checks.
#[derive(Debug, Default)]
pub struct DemoPolicy {
    /// AS checks.
    pub as_checks: AtomicU64,
    /// TGS checks.
    pub tgs_checks: AtomicU64,
}

impl KdcPolicy for DemoPolicy {
    fn check_as(&self, _store: &dyn PrincipalRead, _client: &Principal) -> Result<(), Error> {
        self.as_checks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn check_tgs(&self, _store: &dyn PrincipalRead, _sname: &PrincipalName) -> Result<(), Error> {
        self.tgs_checks.fetch_add(1, Ordering::SeqCst);
        Ok(())
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
    use crate::bootstrap_documented;
    use crate::{TEST_REALM, TEST_USER};
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
        use crate::documented_host;
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
                    .check_as(&store, user)
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
}
