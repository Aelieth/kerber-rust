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

struct PkinitMod;
struct SpakeMod;
struct EncTsMod;

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
        _body_der: &[u8],
        cname: &PrincipalName,
    ) -> Result<Option<PreauthAction>, Error> {
        Ok(
            process_pkinit(store, padata, etype, as_req_der, cname, store.realm())?
                .map(|(key, pa)| PreauthAction::Pkinit { key, pa }),
        )
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
        _cname: &PrincipalName,
    ) -> Result<Option<PreauthAction>, Error> {
        match process_spake(store, client, padata, ikey, body_der)? {
            Some(SpakeStep::Challenge(e_data)) => Ok(Some(PreauthAction::Challenge(e_data))),
            Some(SpakeStep::Done(k)) => Ok(Some(PreauthAction::SpakeDone(k))),
            None => Ok(None),
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
            Arc::new(PkinitMod) as Arc<dyn KdcPreauth>,
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

/// Run registered AS preauth modules in order.
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
    /// Called on each AS issue.
    fn check_as(&self, store: &dyn PrincipalRead, client: &PrincipalName);
    /// Called on each TGS issue.
    fn check_tgs(&self, store: &dyn PrincipalRead, sname: &PrincipalName);
}

/// Default policy: records nothing; built-in ticket rules stay in issue.rs.
pub struct DefaultPolicy;

impl KdcPolicy for DefaultPolicy {
    fn check_as(&self, _store: &dyn PrincipalRead, _client: &PrincipalName) {}
    fn check_tgs(&self, _store: &dyn PrincipalRead, _sname: &PrincipalName) {}
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
    fn check_as(&self, _store: &dyn PrincipalRead, _client: &PrincipalName) {
        self.as_checks.fetch_add(1, Ordering::SeqCst);
    }
    fn check_tgs(&self, _store: &dyn PrincipalRead, _sname: &PrincipalName) {
        self.tgs_checks.fetch_add(1, Ordering::SeqCst);
    }
}

static POLICY: Mutex<Option<Arc<dyn KdcPolicy>>> = Mutex::new(None);

/// Replace the process-wide policy hook (tests).
pub fn set_policy(p: Arc<dyn KdcPolicy>) {
    *POLICY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(p);
}

/// Current policy hook.
#[must_use]
pub fn current_policy() -> Arc<dyn KdcPolicy> {
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
        set_policy(Arc::clone(&pol) as Arc<dyn KdcPolicy>);
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
        assert!(
            demo.procs.load(Ordering::SeqCst) >= 1,
            "demo process_as must run on the AS path"
        );
        assert!(
            pol.as_checks.load(Ordering::SeqCst) >= 1,
            "demo policy check_as must run"
        );
        EXTRA
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        *POLICY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}
