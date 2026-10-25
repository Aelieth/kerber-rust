//! kdcpreauth, kdcpolicy, and kdcauthdata, as Rust traits.

use std::os::fd::OwnedFd;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_log::klog::{self, Severity};
use krb5_types::{
    AuthorizationData, EncTicketPart, HostAddress, KdcReqBody, KerberosTime, PaData, PrincipalName,
    pa,
};
use zeroize::Zeroizing;

use crate::audit::kdc_error_message;
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::preauth::{SpakeStep, process_pkinit, process_spake, spake_edata};
use crate::status;
use crate::store::{KDB_REQUIRES_HW_AUTH, Policy, Principal};

#[derive(Debug)]
pub enum PreauthAction {
    Pkinit {
        key: ProtocolKey,
        pa: PaData,
        signed: bool,
    },
    Challenge(Vec<u8>),
    SpakeDone(ProtocolKey),
    /// Already verified; the caller must not verify it again.
    EncTsOk,
    Otp {
        key: ProtocolKey,
        indicators: Vec<String>,
    },
}

// MIT: `send_challenge` (plugins/preauth/spake/spake_kdc.c:261-277)
/// A cookie's octets are not printed; SPAKE's stage-0 cookie is zapped.
#[derive(Default)]
pub struct PreauthHint {
    pub padata: Vec<PaData>,
    pub cookie: Vec<PaData>,
}

impl std::fmt::Debug for PreauthHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreauthHint")
            .field("padata", &self.padata)
            .field("cookie", &RedactedPadata(&self.cookie))
            .finish()
    }
}

struct RedactedPadata<'a>(&'a [PaData]);

impl std::fmt::Debug for RedactedPadata<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(
                self.0
                    .iter()
                    .map(|p| RedactedEntry(p.padata_type, p.padata_value.len())),
            )
            .finish()
    }
}

struct RedactedEntry(i32, usize);

impl std::fmt::Debug for RedactedEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaData")
            .field("padata_type", &self.0)
            .field("len", &self.1)
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct PreauthRock<'a> {
    pub store: &'a dyn PrincipalRead,
    pub client: &'a Principal,
    pub padata: Option<&'a [PaData]>,
    pub ikey: Option<&'a ProtocolKey>,
    pub etype: Option<EncryptionType>,
    pub armor_key: Option<&'a ProtocolKey>,
    pub as_req_der: &'a [u8],
    pub body_der: &'a [u8],
    pub cname: &'a PrincipalName,
}

pub trait KdcPreauth: Send + Sync {
    fn name(&self) -> &'static str;
    fn pa_types(&self) -> &'static [i32];
    fn advertise(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        armor: bool,
        requested: &[i32],
    ) -> Vec<PaData>;
    // MIT: `krb5_kdcpreauth_edata_fn` (kdcpreauth_plugin.h:311-328)
    fn edata(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        armor: bool,
        requested: &[i32],
        ikey: Option<&ProtocolKey>,
    ) -> PreauthHint {
        let _ = ikey;
        PreauthHint {
            padata: self.advertise(store, client, armor, requested),
            cookie: Vec::new(),
        }
    }
    fn edata_with_armor(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        armor: Option<&ProtocolKey>,
        requested: &[i32],
        ikey: Option<&ProtocolKey>,
    ) -> PreauthHint {
        self.edata(store, client, armor.is_some(), requested, ikey)
    }
    // MIT: `get_preauth_hint_list` (kdc_preauth.c:999-1001)
    /// The empty PA-FX-FAST is added first, whatever `hw_only` says.
    fn hardware(&self) -> bool {
        false
    }
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error>;
}

struct FastMod;
struct PkinitMod;
struct OtpMod;
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
        let PreauthRock {
            store: _store,
            client: _client,
            padata: _padata,
            ikey: _ikey,
            etype: _etype,
            armor_key: _armor_key,
            as_req_der: _as_req_der,
            body_der: _body_der,
            cname: _cname,
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
        if store.pkinit().is_none() {
            return Vec::new();
        }
        let mut out = vec![PaData {
            padata_type: pa::PK_AS_REQ,
            padata_value: Vec::<u8>::new().into(),
        }];
        // MIT: `pkinit_server_get_flags` (pkinit_srv.c:928-929)
        if client.attributes & KDB_REQUIRES_HW_AUTH == 0 {
            out.push(PaData {
                padata_type: pa::PKINIT_KX,
                padata_value: Vec::<u8>::new().into(),
            });
        }
        out
    }
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
        let PreauthRock {
            store,
            client,
            padata,
            ikey: _ikey,
            etype,
            armor_key: _armor_key,
            as_req_der,
            body_der,
            cname,
        } = *rock;
        // MIT: `load_preauth_plugins` (kdc_preauth.c:207-219)
        if store.pkinit().is_none() {
            return Ok(None);
        }
        let Some(etype) = etype else {
            return if crate::preauth::find_pa(padata, pa::PK_AS_REQ).is_some() {
                Err(crate::preauth::proto(
                    krb5_types::err::ETYPE_NOSUPP,
                    status::CANT_FIND_CLIENT_KEY,
                ))
            } else {
                Ok(None)
            };
        };
        let done = process_pkinit(store, client, padata, etype, as_req_der, body_der, cname)?;
        Ok(done.map(|(key, pa, signed)| PreauthAction::Pkinit { key, pa, signed }))
    }
}

// MIT: `kdcpreauth_otp_initvt` (plugins/preauth/otp/main.c:378-387)
impl KdcPreauth for OtpMod {
    fn name(&self) -> &'static str {
        "otp"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[pa::OTP_REQUEST]
    }
    fn advertise(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _armor: bool,
        _requested: &[i32],
    ) -> Vec<PaData> {
        Vec::new()
    }
    fn edata_with_armor(
        &self,
        _store: &dyn PrincipalRead,
        client: &Principal,
        armor: Option<&ProtocolKey>,
        _requested: &[i32],
        _ikey: Option<&ProtocolKey>,
    ) -> PreauthHint {
        crate::preauth::otp_edata(client, armor)
    }
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
        crate::preauth::process_otp(rock)
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
        // MIT: `spake_edata` (spake_kdc.c:309-314)
        // MIT: `group_init_state` (groups.c:235-238)
        if store.policy().spake_kdc().is_err() || !have_client_keys(store, client, requested) {
            return Vec::new();
        }
        vec![PaData {
            padata_type: pa::SPAKE,
            padata_value: Vec::<u8>::new().into(),
        }]
    }
    fn edata(
        &self,
        store: &dyn PrincipalRead,
        _client: &Principal,
        _armor: bool,
        _requested: &[i32],
        ikey: Option<&ProtocolKey>,
    ) -> PreauthHint {
        spake_edata(store, ikey)
    }
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
        let PreauthRock {
            store,
            client,
            padata,
            ikey,
            etype: _etype,
            armor_key: _armor_key,
            as_req_der: _as_req_der,
            body_der,
            cname: _cname,
        } = *rock;
        let Some(ikey) = ikey else {
            // MIT: `verify_response` (spake_kdc.c:380-384)
            return if store.policy().spake_kdc().is_ok()
                && crate::preauth::find_pa(padata, pa::SPAKE).is_some()
            {
                Err(crate::preauth::proto(
                    krb5_types::err::ETYPE_NOSUPP,
                    status::PREAUTH_FAILED,
                ))
            } else {
                Ok(None)
            };
        };
        Ok(
            process_spake(store, client, padata, ikey, body_der)?.map(|step| match step {
                SpakeStep::Challenge(e_data) => PreauthAction::Challenge(e_data),
                SpakeStep::Done(k) => PreauthAction::SpakeDone(k),
            }),
        )
    }
}

impl KdcPreauth for EncTsMod {
    fn name(&self) -> &'static str {
        "encrypted_timestamp"
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
        // MIT: `enc_ts_get` (kdc_preauth_encts.c:39-43)
        // MIT: `have_client_keys` (kdc_preauth.c:442-442)
        if armor || !have_client_keys(store, client, requested) {
            return Vec::new();
        }
        vec![PaData {
            padata_type: pa::ENC_TIMESTAMP,
            padata_value: Vec::<u8>::new().into(),
        }]
    }
    // MIT: `enc_ts_verify` (kdc_preauth_encts.c:74-97)
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
        let PreauthRock {
            store,
            client,
            padata,
            ikey: _ikey,
            etype: _etype,
            armor_key: _armor_key,
            as_req_der: _as_req_der,
            body_der: _body_der,
            cname: _cname,
        } = *rock;
        let Some(blob) = crate::issue::extract_enc_timestamp(padata) else {
            return Ok(None);
        };
        let enc: krb5_types::EncryptedData = match krb5_asn1::decode(blob.as_ref()) {
            Ok(e) => e,
            Err(_) => {
                return Err(crate::asn1_text::preauth_decode_failure(
                    blob.as_ref(),
                    true,
                ));
            }
        };
        // MIT: `krb5_dbe_def_search_enctype` (kdb_default.c:65-67)
        // Only the highest kvno is tried, so a retired key does not verify.
        // MIT: `filter_preauth_error` (kdc_preauth.c:1092-1133)
        // A code off the pass-through list becomes 24.
        let policy = store.policy();
        let top = client.keys.iter().map(|k| k.kvno).max();
        let Some(pa_et) = krb5_crypto::EncryptionType::known(enc.etype)
            .ok()
            .filter(|et| policy.etype_permitted(*et))
        else {
            return Err(Error::PreauthModule {
                code: KDB_NO_PERMITTED_KEY,
                message: NO_PERMITTED_KEY.to_owned(),
            });
        };
        for k in client
            .keys
            .iter()
            .filter(|k| Some(k.kvno) == top && k.etype == pa_et)
        {
            match crate::issue::verify_enc_timestamp(store, &k.key, blob.as_ref()) {
                Ok(()) => return Ok(Some(PreauthAction::EncTsOk)),
                // MIT: `enc_ts_verify` (kdc_preauth_encts.c:75-92)
                // MIT: `enc_ts_verify` (kdc_preauth_encts.c:74-92)
                Err(
                    Error::Crypto(_) | Error::BadEnctype | Error::DesBadParity | Error::DesWeakKey,
                ) => {}
                Err(e) => return Err(e),
            }
        }
        // MIT: `enc_ts_verify` (kdc_preauth_encts.c:113-116)
        Err(crate::preauth::proto(
            krb5_types::err::PREAUTH_FAILED,
            crate::status::PREAUTH_FAILED,
        ))
    }
}

// MIT: `KRB5_KDB_NO_PERMITTED_KEY` (lib/krb5/error_tables/kdb5_err.et:72-72)
const NO_PERMITTED_KEY: &str = "No matching key in entry having a permitted enctype";
const KDB_NO_PERMITTED_KEY: i32 = -1_780_008_418;

struct EncChallengeMod;

impl KdcPreauth for EncChallengeMod {
    fn name(&self) -> &'static str {
        "encrypted_challenge"
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
        // MIT: `ec_edata` (kdc_preauth_ec.c:37-48)
        if !armor || !have_client_keys(store, client, requested) {
            return Vec::new();
        }
        vec![PaData {
            padata_type: pa::ENCRYPTED_CHALLENGE,
            padata_value: Vec::<u8>::new().into(),
        }]
    }
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
        let PreauthRock {
            store: _store,
            client: _client,
            padata: _padata,
            ikey: _ikey,
            etype: _etype,
            armor_key: _armor_key,
            as_req_der: _as_req_der,
            body_der: _body_der,
            cname: _cname,
        } = *rock;
        Ok(None)
    }
}

static BUILTIN: OnceLock<Vec<Arc<dyn KdcPreauth>>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static THREAD_EXTRA: std::cell::RefCell<Option<Vec<Arc<dyn KdcPreauth>>>> =
        const { std::cell::RefCell::new(None) };
}

fn builtins() -> &'static [Arc<dyn KdcPreauth>] {
    BUILTIN.get_or_init(|| {
        vec![
            Arc::new(FastMod) as Arc<dyn KdcPreauth>,
            Arc::new(PkinitMod),
            Arc::new(OtpMod),
            Arc::new(SpakeMod),
            Arc::new(EncChallengeMod),
            Arc::new(EncTsMod),
        ]
    })
}

#[doc(hidden)]
pub fn register_preauth(m: Arc<dyn KdcPreauth>) {
    let name = m.name();
    lock_plugins().register_preauth(m);
    note_late_register("kdcpreauth", name);
}

#[cfg(test)]
pub fn set_thread_preauth(modules: Vec<Arc<dyn KdcPreauth>>) {
    THREAD_EXTRA.with(|t| *t.borrow_mut() = Some(modules));
}

#[cfg(test)]
pub fn clear_thread_preauth() {
    THREAD_EXTRA.with(|t| *t.borrow_mut() = None);
}

#[cfg(test)]
pub(crate) fn take_thread_preauth() -> Option<Vec<Arc<dyn KdcPreauth>>> {
    THREAD_EXTRA.with(|t| t.borrow_mut().take())
}

#[cfg(test)]
pub(crate) fn restore_thread_preauth(modules: Option<Vec<Arc<dyn KdcPreauth>>>) {
    THREAD_EXTRA.with(|t| *t.borrow_mut() = modules);
}

#[must_use]
pub(crate) fn preauth_modules(policy: &Policy) -> Vec<Arc<dyn KdcPreauth>> {
    let mut v: Vec<Arc<dyn KdcPreauth>> = builtins().to_vec();
    #[cfg(test)]
    if let Some(extra) = THREAD_EXTRA.with(|t| t.borrow().clone()) {
        v.extend(extra);
        return v;
    }
    v.extend(policy.plugins.preauth());
    v
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OtpVerdict {
    Accept,
    Reject,
    Error(String),
}

#[derive(Clone, Debug)]
pub struct OtpTokenFields {
    pub ty_name: String,
    pub indicators: Vec<String>,
}

/// Owned and `Send` for the worker; not `Debug` (`otp_value` is secret).
#[derive(Clone)]
#[non_exhaustive]
pub struct OtpVerifyRequest {
    pub principal: Principal,
    pub realm: String,
    pub token_type: String,
    pub username: Vec<u8>,
    /// Untrusted bytes, not UTF-8: it may be the password and the code.
    pub otp_value: Zeroizing<Vec<u8>>,
    pub peer: Option<HostAddress>,
    pub request_time: Instant,
    pub deadline: Instant,
    pub token: OtpTokenFields,
}

impl OtpVerifyRequest {
    #[doc(hidden)]
    #[must_use]
    pub fn for_test(
        principal: Principal,
        realm: impl Into<String>,
        token_type: impl Into<String>,
        username: impl Into<Vec<u8>>,
        otp_value: impl Into<Vec<u8>>,
    ) -> Self {
        let token_type = token_type.into();
        let now = Instant::now();
        Self {
            principal,
            realm: realm.into(),
            token: OtpTokenFields {
                ty_name: token_type.clone(),
                indicators: Vec::new(),
            },
            token_type,
            username: username.into(),
            otp_value: Zeroizing::new(otp_value.into()),
            peer: None,
            request_time: now,
            deadline: now + Duration::from_secs(5),
        }
    }
}

/// Runs on a worker under a deadline; a hang or panic fails closed; `Error` text is logged.
pub trait OtpVerifier: Send + Sync {
    fn name(&self) -> &'static str;
    fn verify(&self, req: &OtpVerifyRequest) -> OtpVerdict;
}

#[cfg(test)]
thread_local! {
    static THREAD_OTP: std::cell::RefCell<Option<Vec<Arc<dyn OtpVerifier>>>> =
        const { std::cell::RefCell::new(None) };
}

#[doc(hidden)]
pub fn register_otp_verifier(v: Arc<dyn OtpVerifier>) -> Result<(), Error> {
    let name = v.name();
    lock_plugins().register_otp_verifier(v)?;
    note_late_register("otp", name);
    Ok(())
}

#[cfg(test)]
pub fn set_thread_otp_verifiers(v: Vec<Arc<dyn OtpVerifier>>) {
    THREAD_OTP.with(|t| *t.borrow_mut() = Some(v));
}

#[cfg(test)]
pub fn clear_thread_otp_verifiers() {
    THREAD_OTP.with(|t| *t.borrow_mut() = None);
}

#[cfg(test)]
pub(crate) fn take_thread_otp_verifiers() -> Option<Vec<Arc<dyn OtpVerifier>>> {
    THREAD_OTP.with(|t| t.borrow_mut().take())
}

#[cfg(test)]
pub(crate) fn restore_thread_otp_verifiers(v: Option<Vec<Arc<dyn OtpVerifier>>>) {
    THREAD_OTP.with(|t| *t.borrow_mut() = v);
}

pub(crate) fn otp_verifiers(policy: &Policy) -> Vec<Arc<dyn OtpVerifier>> {
    #[cfg(test)]
    if let Some(v) = THREAD_OTP.with(|t| t.borrow().clone()) {
        return v;
    }
    policy.plugins.otp()
}

pub(crate) fn find_otp_verifier(policy: &Policy, name: &str) -> Option<Arc<dyn OtpVerifier>> {
    #[cfg(test)]
    if let Some(v) = THREAD_OTP.with(|t| t.borrow().clone()) {
        return v.into_iter().find(|module| module.name() == name);
    }
    policy.plugins.find_otp(name)
}

pub(crate) fn otp_verifier_names(policy: &Policy) -> Vec<&'static str> {
    otp_verifiers(policy).iter().map(|v| v.name()).collect()
}

#[cfg(test)]
pub(crate) fn thread_otp_names() -> Vec<&'static str> {
    #[cfg(test)]
    if let Some(v) = THREAD_OTP.with(|t| t.borrow().clone()) {
        return v.iter().map(|module| module.name()).collect();
    }
    Vec::new()
}

const OTP_WORKERS: usize = 4;
const OTP_QUEUE: usize = 64;

type OtpJob = (
    OtpVerifyRequest,
    Arc<dyn OtpVerifier>,
    SyncSender<OtpVerdict>,
);

pub(crate) struct OtpPool {
    tx: SyncSender<OtpJob>,
    wake_read: Option<OwnedFd>,
}

impl OtpPool {
    fn new(threads: usize) -> Self {
        let (tx, rx) = sync_channel::<OtpJob>(OTP_QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        let (wake_read, wake_write) = match nix::unistd::pipe2(
            nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_NONBLOCK,
        ) {
            Ok((r, w)) => (Some(r), Some(Arc::new(w))),
            Err(_) => (None, None),
        };
        for _ in 0..threads.max(1) {
            let rx = Arc::clone(&rx);
            let wake = wake_write.clone();
            let _ = std::thread::Builder::new()
                .name("otp-verify".to_owned())
                .spawn(move || run_otp_worker(&rx, wake.as_deref()));
        }
        Self { tx, wake_read }
    }

    pub(crate) fn submit(
        &self,
        req: OtpVerifyRequest,
        verifier: Arc<dyn OtpVerifier>,
    ) -> Option<Receiver<OtpVerdict>> {
        let (reply_tx, reply_rx) = sync_channel::<OtpVerdict>(1);
        self.tx.try_send((req, verifier, reply_tx)).ok()?;
        Some(reply_rx)
    }

    pub(crate) fn wake_read_fd(&self) -> Option<OwnedFd> {
        self.wake_read.as_ref().and_then(|fd| fd.try_clone().ok())
    }
}

fn run_otp_worker(rx: &Mutex<Receiver<OtpJob>>, wake: Option<&OwnedFd>) {
    loop {
        let job = {
            let guard = rx.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.recv()
        };
        let Ok((req, verifier, reply)) = job else {
            return;
        };
        // Past its deadline: the caller gave up, so skip verify (don't burn a TOTP step).
        if Instant::now() >= req.deadline {
            continue;
        }
        let verdict = catch_unwind(AssertUnwindSafe(|| verifier.verify(&req)))
            .unwrap_or_else(|_| OtpVerdict::Error("the OTP verifier panicked".to_owned()));
        let _ = reply.send(verdict);
        if let Some(w) = wake {
            let _ = nix::unistd::write(w, &[1u8]);
        }
    }
}

#[doc(hidden)]
pub struct OtpRuntime {
    verifiers: Vec<Arc<dyn OtpVerifier>>,
    pool: OtpPool,
}

impl OtpRuntime {
    pub(crate) fn new(verifiers: Vec<Arc<dyn OtpVerifier>>) -> Self {
        Self {
            verifiers,
            pool: OtpPool::new(OTP_WORKERS),
        }
    }

    pub(crate) fn find(&self, name: &str) -> Option<Arc<dyn OtpVerifier>> {
        self.verifiers.iter().find(|v| v.name() == name).cloned()
    }

    pub(crate) fn pool(&self) -> &OtpPool {
        &self.pool
    }
}

impl std::fmt::Debug for OtpRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtpRuntime")
            .field("verifiers", &self.verifiers.len())
            .finish_non_exhaustive()
    }
}

pub(crate) enum OtpOutcome {
    Verdict(OtpVerdict),
    TimedOut,
    QueueFull,
}

pub(crate) struct ParkedOtp {
    pub(crate) rx: Receiver<OtpVerdict>,
    pub(crate) deadline: Instant,
    pub(crate) started: Instant,
    pub(crate) token_index: usize,
    pub(crate) token_type: String,
    pub(crate) username: Vec<u8>,
}

pub(crate) struct OtpResume {
    pub(crate) token_index: usize,
    pub(crate) started: Instant,
    pub(crate) token_type: String,
    pub(crate) username: Vec<u8>,
    pub(crate) outcome: OtpOutcome,
}

thread_local! {
    static OTP_PARK: std::cell::RefCell<Option<ParkedOtp>> = const { std::cell::RefCell::new(None) };
    static OTP_RESUME: std::cell::RefCell<Option<OtpResume>> = const { std::cell::RefCell::new(None) };
    static OTP_PARK_ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(crate) fn set_otp_park(p: ParkedOtp) {
    OTP_PARK.with(|t| *t.borrow_mut() = Some(p));
}

pub(crate) fn take_otp_park() -> Option<ParkedOtp> {
    OTP_PARK.with(|t| t.borrow_mut().take())
}

pub(crate) fn otp_park_pending() -> bool {
    OTP_PARK.with(|t| t.borrow().is_some())
}

pub(crate) fn set_otp_resume(r: Option<OtpResume>) {
    OTP_RESUME.with(|t| *t.borrow_mut() = r);
}

pub(crate) fn take_otp_resume() -> Option<OtpResume> {
    OTP_RESUME.with(|t| t.borrow_mut().take())
}

pub(crate) fn set_otp_park_enabled(on: bool) {
    OTP_PARK_ENABLED.with(|t| t.set(on));
}

pub(crate) fn otp_park_enabled() -> bool {
    OTP_PARK_ENABLED.with(std::cell::Cell::get)
}

pub(crate) fn bounded_verify(
    pool: Option<&OtpPool>,
    verifier: Arc<dyn OtpVerifier>,
    req: OtpVerifyRequest,
    timeout: Duration,
) -> OtpOutcome {
    let reply_rx = match pool {
        Some(p) => match p.submit(req, verifier) {
            Some(rx) => rx,
            None => return OtpOutcome::QueueFull,
        },
        None => one_shot_verify(req, verifier),
    };
    match reply_rx.recv_timeout(timeout) {
        Ok(v) => OtpOutcome::Verdict(v),
        Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => OtpOutcome::TimedOut,
    }
}

fn one_shot_verify(req: OtpVerifyRequest, verifier: Arc<dyn OtpVerifier>) -> Receiver<OtpVerdict> {
    let (tx, rx) = sync_channel::<OtpVerdict>(1);
    let _ = std::thread::Builder::new()
        .name("otp-verify-1".to_owned())
        .spawn(move || {
            let verdict = catch_unwind(AssertUnwindSafe(|| verifier.verify(&req)))
                .unwrap_or_else(|_| OtpVerdict::Error("the OTP verifier panicked".to_owned()));
            let _ = tx.send(verdict);
        });
    rx
}

static OTP_LAST_REFUSAL_LOG: Mutex<Option<Instant>> = Mutex::new(None);

pub(crate) fn otp_log_refusal(msg: &str) {
    let now = Instant::now();
    let mut last = OTP_LAST_REFUSAL_LOG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fire = match *last {
        Some(t) => now.duration_since(t) >= Duration::from_secs(1),
        None => true,
    };
    if fire {
        *last = Some(now);
        drop(last);
        klog::syslog(Severity::Err, msg);
        tracing::error!(target: "kdc.otp", "{}", msg);
    }
}

pub(crate) fn sanitize_otp_error(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        let piece = if ch.is_control() {
            ch.escape_default().count()
        } else {
            ch.len_utf8()
        };
        if out.len() + piece > 256 {
            break;
        }
        if ch.is_control() {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    out
}

pub(crate) fn kdc_otp_event(principal: &str, token_type: &str, verdict: &str, duration_us: u64) {
    tracing::debug!(
        target: "kdc.otp",
        principal = principal,
        token_type = token_type,
        verdict = verdict,
        duration_us = duration_us,
    );
}

// MIT: `krb5_kdcauthdata_handle_fn` (kdcauthdata_plugin.h:105-117)
pub trait KdcAuthdata: Send + Sync {
    fn name(&self) -> &'static str;
    // MIT: `handle_authdata` (kdc_authdata.c:610-611)
    /// A module error is logged and the next module still runs.
    fn handle(
        &self,
        is_tgs: bool,
        reply: &mut AuthorizationData,
        session: Option<&ProtocolKey>,
        issuer: Option<(&PrincipalName, &str)>,
    ) -> Result<(), Error>;
}

fn push_module<T: ?Sized>(list: &mut Vec<Arc<T>>, module: Arc<T>) {
    if list.iter().any(|item| Arc::ptr_eq(item, &module)) {
        return;
    }
    list.push(module);
}

fn drop_named<T: ?Sized>(list: &mut Vec<Arc<T>>, name: &str, name_of: impl Fn(&T) -> &str) {
    list.retain(|item| name_of(item.as_ref()) != name);
}

#[derive(Clone)]
pub struct PluginSet {
    preauth: Vec<Arc<dyn KdcPreauth>>,
    sole_policy: Option<Arc<dyn KdcPolicy>>,
    policies: Vec<Arc<dyn KdcPolicy>>,
    sole_audit: Option<Arc<dyn crate::audit::KdcAudit>>,
    audits: Vec<Arc<dyn crate::audit::KdcAudit>>,
    authdata: Vec<Arc<dyn KdcAuthdata>>,
    otp: Vec<Arc<dyn OtpVerifier>>,
}

impl std::fmt::Debug for PluginSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginSet")
            .field("preauth", &self.preauth.len())
            .field("policies", &self.policies.len())
            .field("audits", &self.audits.len())
            .field("authdata", &self.authdata.len())
            .field("otp", &self.otp.len())
            .finish_non_exhaustive()
    }
}

impl PluginSet {
    const fn empty() -> Self {
        Self {
            preauth: Vec::new(),
            sole_policy: None,
            policies: Vec::new(),
            sole_audit: None,
            audits: Vec::new(),
            authdata: Vec::new(),
            otp: Vec::new(),
        }
    }

    pub(crate) fn snapshot() -> Self {
        let set = default_plugins()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        COPIED.fetch_add(1, Ordering::Relaxed);
        set
    }

    pub fn register_preauth(&mut self, module: Arc<dyn KdcPreauth>) {
        push_module(&mut self.preauth, module);
    }

    pub fn unregister_preauth(&mut self, name: &str) {
        drop_named(&mut self.preauth, name, |module| module.name());
    }

    pub fn register_kdcpolicy(&mut self, module: Arc<dyn KdcPolicy>) {
        push_module(&mut self.policies, module);
    }

    pub fn unregister_kdcpolicy(&mut self, name: &str) {
        drop_named(&mut self.policies, name, |module| module.name());
        if self
            .sole_policy
            .as_ref()
            .is_some_and(|module| module.name() == name)
        {
            self.sole_policy = None;
        }
    }

    pub fn set_policy(&mut self, module: Arc<dyn KdcPolicy>) {
        self.sole_policy = Some(module);
    }

    pub fn clear_policy(&mut self) {
        self.sole_policy = None;
    }

    pub fn register_audit(&mut self, module: Arc<dyn crate::audit::KdcAudit>) {
        push_module(&mut self.audits, module);
    }

    pub fn unregister_audit(&mut self, name: &str) {
        drop_named(&mut self.audits, name, |module| module.name());
        if self
            .sole_audit
            .as_ref()
            .is_some_and(|module| module.name() == name)
        {
            self.sole_audit = None;
        }
    }

    pub fn set_audit(&mut self, module: Arc<dyn crate::audit::KdcAudit>) {
        self.sole_audit = Some(module);
    }

    pub fn clear_audit(&mut self) {
        self.sole_audit = None;
    }

    pub fn register_authdata(&mut self, module: Arc<dyn KdcAuthdata>) {
        push_module(&mut self.authdata, module);
    }

    pub fn unregister_authdata(&mut self, name: &str) {
        drop_named(&mut self.authdata, name, |module| module.name());
    }

    pub fn register_otp_verifier(&mut self, module: Arc<dyn OtpVerifier>) -> Result<(), Error> {
        if self.otp.iter().any(|item| item.name() == module.name()) {
            return Err(Error::InvalidArgument(format!(
                "an OTP verifier named '{}' is already registered",
                module.name()
            )));
        }
        self.otp.push(module);
        Ok(())
    }

    pub fn unregister_otp_verifier(&mut self, name: &str) {
        drop_named(&mut self.otp, name, |module| module.name());
    }

    pub fn clear_otp_verifiers(&mut self) {
        self.otp.clear();
    }

    pub fn set_otp_verifiers(&mut self, modules: Vec<Arc<dyn OtpVerifier>>) {
        self.otp = modules;
    }

    pub(crate) fn preauth(&self) -> Vec<Arc<dyn KdcPreauth>> {
        self.preauth.clone()
    }

    pub(crate) fn sole_policy(&self) -> Option<Arc<dyn KdcPolicy>> {
        self.sole_policy.clone()
    }

    pub(crate) fn policies(&self) -> Vec<Arc<dyn KdcPolicy>> {
        self.policies.clone()
    }

    pub(crate) fn sole_audit(&self) -> Option<Arc<dyn crate::audit::KdcAudit>> {
        self.sole_audit.clone()
    }

    pub(crate) fn audits(&self) -> Vec<Arc<dyn crate::audit::KdcAudit>> {
        self.audits.clone()
    }

    pub(crate) fn authdata(&self) -> Vec<Arc<dyn KdcAuthdata>> {
        self.authdata.clone()
    }

    pub(crate) fn otp(&self) -> Vec<Arc<dyn OtpVerifier>> {
        self.otp.clone()
    }

    pub(crate) fn find_otp(&self, name: &str) -> Option<Arc<dyn OtpVerifier>> {
        self.otp
            .iter()
            .find(|module| module.name() == name)
            .cloned()
    }
}

fn default_plugins() -> &'static Mutex<PluginSet> {
    static SET: Mutex<PluginSet> = Mutex::new(PluginSet::empty());
    &SET
}

static COPIED: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn note_late_register(kind: &str, name: &str) {
    if COPIED.load(Ordering::Relaxed) == 0 {
        return;
    }
    tracing::error!(
        target: "krb5_kdc",
        "{kind} {name} registered on the process default after a store copied it; it applies only to stores opened later"
    );
}

pub(crate) fn lock_plugins() -> std::sync::MutexGuard<'static, PluginSet> {
    default_plugins()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
thread_local! {
    static THREAD_EXTRA_AD: std::cell::RefCell<Option<Vec<Arc<dyn KdcAuthdata>>>> =
        const { std::cell::RefCell::new(None) };
}

#[doc(hidden)]
pub fn register_authdata(m: Arc<dyn KdcAuthdata>) {
    let name = m.name();
    lock_plugins().register_authdata(m);
    note_late_register("authdata", name);
}

#[cfg(test)]
pub fn set_thread_authdata(modules: Vec<Arc<dyn KdcAuthdata>>) {
    THREAD_EXTRA_AD.with(|t| *t.borrow_mut() = Some(modules));
}

#[cfg(test)]
pub fn clear_thread_authdata() {
    THREAD_EXTRA_AD.with(|t| *t.borrow_mut() = None);
}

#[cfg(test)]
pub(crate) fn take_thread_authdata() -> Option<Vec<Arc<dyn KdcAuthdata>>> {
    THREAD_EXTRA_AD.with(|t| t.borrow_mut().take())
}

#[cfg(test)]
pub(crate) fn restore_thread_authdata(modules: Option<Vec<Arc<dyn KdcAuthdata>>>) {
    THREAD_EXTRA_AD.with(|t| *t.borrow_mut() = modules);
}

#[must_use]
pub(crate) fn authdata_modules(policy: &Policy) -> Vec<Arc<dyn KdcAuthdata>> {
    #[cfg(test)]
    if let Some(modules) = THREAD_EXTRA_AD.with(|t| t.borrow().clone()) {
        return modules;
    }
    policy.plugins.authdata()
}

// MIT: `get_plugin_vtables` (kdc/kdc_preauth.c:117-163)
// MIT: `k5_plugin_load_all` (lib/krb5/krb/plugin.c:421-455)
pub(crate) fn selected_preauth(policy: &Policy) -> Vec<Arc<dyn KdcPreauth>> {
    let mut fast = Vec::new();
    let mut named = Vec::new();
    for module in preauth_modules(policy) {
        if module.name() == "fast" {
            fast.push(module);
        } else if module.name() != "otp" || policy.otp.is_ok() {
            named.push(module);
        }
    }
    let names: Vec<&str> = named.iter().map(|module| module.name()).collect();
    let kept = krb5_config::filter_plugin_modules(&policy.kdcpreauth, &names);
    for want in kept {
        if let Some(index) = named.iter().position(|module| module.name() == want) {
            fast.push(named.remove(index));
        }
    }
    fast
}

pub(crate) fn kdcpreauth_loaded(store: &dyn PrincipalRead, name: &str) -> bool {
    selected_preauth(store.policy())
        .iter()
        .any(|module| module.name() == name)
}

// MIT: `pkinit_server_plugin_init` (plugins/preauth/pkinit/pkinit_srv.c:1384-1390)
#[must_use]
pub fn preauth_startup_lines(
    relations: &krb5_config::PluginRelations,
    pkinit_failure: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut lines = Vec::new();
    if startup_module_loaded(relations, "otp") {
        lines.push(("info", "Loaded".to_owned()));
    }
    if let Some(msg) = pkinit_failure.filter(|_| startup_module_loaded(relations, "pkinit")) {
        lines.push((
            "error",
            format!("preauth pkinit failed to initialize: PKINIT initialization failed: {msg}"),
        ));
    }
    lines
}

#[must_use]
pub fn otp_startup_lines(policy: &Policy) -> Vec<(&'static str, String)> {
    let Err(e) = policy.otp_kdc() else {
        return Vec::new();
    };
    if !startup_module_loaded(&policy.kdcpreauth, "otp") {
        return Vec::new();
    }
    let mut lines = Vec::new();
    if let Some(detail) = &e.detail {
        lines.push(("error", format!("{} - {detail}", e.emsg)));
    }
    lines.push((
        "error",
        format!("preauth otp failed to initialize: {}", e.emsg),
    ));
    lines
}

pub(crate) fn startup_module_loaded(relations: &krb5_config::PluginRelations, name: &str) -> bool {
    krb5_config::filter_plugin_modules(relations, &[name])
        .iter()
        .any(|kept| kept == name)
}

// MIT: `kdc_fast_set_cookie` (fast_util.c:631-651)
pub fn advertise_preauth(
    store: &dyn PrincipalRead,
    client: &Principal,
    armor: Option<&ProtocolKey>,
    requested: &[i32],
    ikey: Option<&ProtocolKey>,
) -> PreauthHint {
    let hw_only = client.attributes & KDB_REQUIRES_HW_AUTH != 0;
    let mut out = PreauthHint {
        padata: vec![PaData {
            padata_type: pa::FX_FAST,
            padata_value: Vec::<u8>::new().into(),
        }],
        cookie: Vec::new(),
    };
    for m in selected_preauth(store.policy()) {
        if m.name() == "fast" {
            continue;
        }
        if hw_only && !m.hardware() {
            continue;
        }
        let hint = m.edata_with_armor(store, client, armor, requested, ikey);
        out.padata.extend(hint.padata);
        for c in hint.cookie {
            if !out.cookie.iter().any(|p| p.padata_type == c.padata_type) {
                out.cookie.push(c);
            }
        }
    }
    out
}

fn have_client_keys(store: &dyn PrincipalRead, client: &Principal, requested: &[i32]) -> bool {
    requested.iter().any(|&iana| {
        let Ok(et) = EncryptionType::known(iana) else {
            return false;
        };
        store.policy().find_enctype(client, Some(et), 0).is_ok()
    })
}

pub fn run_as_preauth(rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
    let PreauthRock {
        store,
        client,
        padata,
        ikey,
        etype,
        armor_key,
        as_req_der,
        body_der,
        cname,
    } = *rock;
    for m in selected_preauth(store.policy()) {
        match m.process_as(&PreauthRock {
            store,
            client,
            padata,
            ikey,
            etype,
            armor_key,
            as_req_der,
            body_der,
            cname,
        }) {
            Ok(Some(a)) => {
                if matches!(a, PreauthAction::Challenge(_)) {
                    log_verify_failure(
                        m.name(),
                        &kdc_error_message(krb5_types::err::MORE_PREAUTH_DATA_REQUIRED),
                    );
                }
                return Ok(Some(a));
            }
            Ok(None) => {}
            Err(e) => {
                if otp_park_pending() {
                    return Err(e);
                }
                return Err(finish_verify_padata(m.name(), e));
            }
        }
    }
    Ok(None)
}

// MIT: `finish_verify_padata` (kdc_preauth.c:1213-1228)
pub(crate) fn finish_verify_padata(module: &str, e: Error) -> Error {
    if is_return_padata(&e) {
        return e;
    }
    log_verify_failure(module, &verify_failure_text(&e));
    filter_preauth_error(e)
}

// MIT: `finish_process_as_req` (kdc/do_as_req.c:251-256)
/// A `return_padata` failure goes out unfiltered.
fn is_return_padata(e: &Error) -> bool {
    matches!(e, Error::Protocol { text: Some(t), .. } if t == status::KDC_RETURN_PADATA)
}

fn verify_failure_text(e: &Error) -> String {
    match e {
        Error::Protocol { code, detail, .. } => detail
            .clone()
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| kdc_error_message(*code)),
        Error::PreauthRequired { .. } => kdc_error_message(krb5_types::err::PREAUTH_REQUIRED),
        Error::PreauthModule { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

pub(crate) fn log_verify_failure(module: &str, emsg: &str) {
    klog::syslog(
        Severity::Info,
        &format!("preauth ({module}) verify failure: {emsg}"),
    );
}

// MIT: `filter_preauth_error` (kdc_preauth.c:1092-1133)
/// A failure keeps its code only on the pass-through list.
// MIT: `finish_preauth` (do_as_req.c:442-442)
// MIT: `finish_process_as_req` (do_as_req.c:358-359)
// MIT: `finish_preauth` (do_as_req.c:442-442)
pub(crate) fn filter_preauth_error(e: Error) -> Error {
    use krb5_types::err;
    const CANT_VERIFY_CERTIFICATE: i32 = 70;
    const INVALID_CERTIFICATE: i32 = 71;
    const REVOKED_CERTIFICATE: i32 = 72;
    const REVOCATION_STATUS_UNKNOWN: i32 = 73;
    const CLIENT_NAME_MISMATCH: i32 = 75;
    const INCONSISTENT_KEY_PURPOSE: i32 = 77;
    const DIGEST_IN_CERT_NOT_ACCEPTED: i32 = 78;
    const PA_CHECKSUM_MUST_BE_INCLUDED: i32 = 79;
    const DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED: i32 = 80;
    const PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED: i32 = 81;
    const CERTIFICATE_MISMATCH: i32 = 66;
    const KDC_NOT_TRUSTED: i32 = 63;
    const REVOCATION_STATUS_UNAVAILABLE: i32 = 74;
    const NO_ACCEPTABLE_KDF: i32 = 100;
    const PASS_THROUGH: &[i32] = &[
        err::BAD_INTEGRITY,
        err::SKEW,
        err::PREAUTH_REQUIRED,
        err::ETYPE_NOSUPP,
        err::CLIENT_NOT_TRUSTED,
        err::INVALID_SIG,
        err::DH_KEY_PARAMETERS_NOT_ACCEPTED,
        CANT_VERIFY_CERTIFICATE,
        INVALID_CERTIFICATE,
        REVOKED_CERTIFICATE,
        REVOCATION_STATUS_UNKNOWN,
        CLIENT_NAME_MISMATCH,
        INCONSISTENT_KEY_PURPOSE,
        DIGEST_IN_CERT_NOT_ACCEPTED,
        PA_CHECKSUM_MUST_BE_INCLUDED,
        DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED,
        PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED,
        CERTIFICATE_MISMATCH,
        KDC_NOT_TRUSTED,
        REVOCATION_STATUS_UNAVAILABLE,
        NO_ACCEPTABLE_KDF,
        err::MORE_PREAUTH_DATA_REQUIRED,
        err::DISCARD,
    ];
    let wire_of = |code| {
        if code == err::PREAUTH_FAILED || PASS_THROUGH.contains(&code) {
            code
        } else {
            err::PREAUTH_FAILED
        }
    };
    match e {
        Error::PreauthRequired { .. } => e,
        Error::PreauthModule { code, message } => {
            let wire = wire_of(code);
            Error::Protocol {
                code: wire,
                text: Some(status::PREAUTH_FAILED.to_owned()),
                e_data: None,
                detail: (wire == code).then_some(message),
            }
        }
        Error::Protocol {
            code,
            text: _,
            e_data,
            detail,
        } => {
            let wire = wire_of(code);
            Error::Protocol {
                code: wire,
                text: Some(status::PREAUTH_FAILED.to_owned()),
                e_data,
                detail: detail.filter(|_| wire == code),
            }
        }
        _ => Error::Protocol {
            code: err::PREAUTH_FAILED,
            text: Some(status::PREAUTH_FAILED.to_owned()),
            e_data: None,
            detail: None,
        },
    }
}

// MIT: `update_ticket_times` (policy.c:91-99)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyAdjustment {
    /// Seconds; 0 leaves `endtime` unchanged.
    pub lifetime: i64,
    /// Seconds; 0 leaves `renew_till` unchanged.
    pub renew_lifetime: i64,
}

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

pub trait KdcPolicy: Send + Sync {
    fn name(&self) -> &'static str {
        ""
    }

    fn check_as(
        &self,
        store: &dyn PrincipalRead,
        client: &Principal,
        indicators: &[String],
    ) -> Result<PolicyAdjustment, Error>;
    fn check_tgs(
        &self,
        store: &dyn PrincipalRead,
        sname: &PrincipalName,
        indicators: &[String],
    ) -> Result<PolicyAdjustment, Error>;

    // MIT: `krb5_kdcpolicy_check_as_fn` (kdcpolicy_plugin.h:95-102)
    fn check_as_req(
        &self,
        _request: &KdcReqBody,
        store: &dyn PrincipalRead,
        client: &Principal,
        _server: &Principal,
        indicators: &[String],
        _status: &mut Option<&'static str>,
    ) -> Result<PolicyAdjustment, Error> {
        self.check_as(store, client, indicators)
    }

    // MIT: `krb5_kdcpolicy_check_tgs_fn` (kdcpolicy_plugin.h:111-118)
    fn check_tgs_req(
        &self,
        _request: &KdcReqBody,
        store: &dyn PrincipalRead,
        server: &Principal,
        _ticket: &EncTicketPart,
        indicators: &[String],
        _status: &mut Option<&'static str>,
    ) -> Result<PolicyAdjustment, Error> {
        self.check_tgs(store, &server.name, indicators)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "MIT check_as plus the socket the KDC accepted"
    )]
    fn check_as_from(
        &self,
        request: &KdcReqBody,
        store: &dyn PrincipalRead,
        client: &Principal,
        server: &Principal,
        indicators: &[String],
        peer: Option<&HostAddress>,
        status: &mut Option<&'static str>,
    ) -> Result<PolicyAdjustment, Error> {
        let _ = peer;
        self.check_as_req(request, store, client, server, indicators, status)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "MIT check_tgs plus the socket the KDC accepted"
    )]
    fn check_tgs_from(
        &self,
        request: &KdcReqBody,
        store: &dyn PrincipalRead,
        server: &Principal,
        ticket: &EncTicketPart,
        indicators: &[String],
        peer: Option<&HostAddress>,
        status: &mut Option<&'static str>,
    ) -> Result<PolicyAdjustment, Error> {
        let _ = peer;
        self.check_tgs_req(request, store, server, ticket, indicators, status)
    }
}

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

#[cfg(test)]
thread_local! {
    static THREAD_POLICY: std::cell::RefCell<Option<Arc<dyn KdcPolicy>>> =
        const { std::cell::RefCell::new(None) };
    static THREAD_POLICIES: std::cell::RefCell<Option<Vec<Arc<dyn KdcPolicy>>>> =
        const { std::cell::RefCell::new(None) };
}

thread_local! {
    static REQUEST_PEER: std::cell::RefCell<Option<HostAddress>> =
        const { std::cell::RefCell::new(None) };
}

#[doc(hidden)]
pub fn set_policy(p: Arc<dyn KdcPolicy>) {
    let name = p.name();
    lock_plugins().set_policy(p);
    note_late_register("kdcpolicy", name);
}

#[cfg(test)]
pub fn set_thread_policy(p: Arc<dyn KdcPolicy>) {
    THREAD_POLICY.with(|t| *t.borrow_mut() = Some(p));
}

#[cfg(test)]
pub fn clear_thread_policy() {
    THREAD_POLICY.with(|t| *t.borrow_mut() = None);
}

#[cfg(test)]
pub(crate) fn take_thread_policy() -> Option<Arc<dyn KdcPolicy>> {
    THREAD_POLICY.with(|t| t.borrow_mut().take())
}

#[cfg(test)]
pub(crate) fn restore_thread_policy(p: Option<Arc<dyn KdcPolicy>>) {
    THREAD_POLICY.with(|t| *t.borrow_mut() = p);
}

#[must_use]
pub fn current_policy() -> Arc<dyn KdcPolicy> {
    #[cfg(test)]
    if let Some(p) = THREAD_POLICY.with(|t| t.borrow().clone()) {
        return p;
    }
    lock_plugins()
        .sole_policy()
        .unwrap_or_else(|| Arc::new(DefaultPolicy))
}

#[doc(hidden)]
pub fn register_kdcpolicy(module: Arc<dyn KdcPolicy>) {
    let name = module.name();
    lock_plugins().register_kdcpolicy(module);
    note_late_register("kdcpolicy", name);
}

#[cfg(test)]
pub fn set_thread_kdcpolicies(modules: Vec<Arc<dyn KdcPolicy>>) {
    THREAD_POLICIES.with(|slot| *slot.borrow_mut() = Some(modules));
}

#[cfg(test)]
pub fn clear_thread_kdcpolicies() {
    THREAD_POLICIES.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
pub(crate) fn take_thread_kdcpolicies() -> Option<Vec<Arc<dyn KdcPolicy>>> {
    THREAD_POLICIES.with(|slot| slot.borrow_mut().take())
}

#[cfg(test)]
pub(crate) fn restore_thread_kdcpolicies(modules: Option<Vec<Arc<dyn KdcPolicy>>>) {
    THREAD_POLICIES.with(|slot| *slot.borrow_mut() = modules);
}

pub(crate) fn set_request_peer(peer: Option<HostAddress>) {
    REQUEST_PEER.with(|slot| *slot.borrow_mut() = peer);
}

#[must_use]
pub(crate) fn request_peer() -> Option<HostAddress> {
    REQUEST_PEER.with(|slot| slot.borrow().clone())
}

// MIT: `filter_enabled_modules` (lib/krb5/krb/plugin.c:271-299)
fn selected_kdcpolicies(
    relations: &krb5_config::PluginRelations,
    modules: Vec<Arc<dyn KdcPolicy>>,
) -> Vec<Arc<dyn KdcPolicy>> {
    let names: Vec<&str> = modules.iter().map(|module| module.name()).collect();
    let kept = krb5_config::filter_plugin_modules(relations, &names);
    let mut left = modules;
    let mut out = Vec::new();
    for want in kept {
        if let Some(index) = left.iter().position(|module| module.name() == want) {
            out.push(left.remove(index));
        }
    }
    out
}

// MIT: `check_kdcpolicy_as` (kdc/policy.c:104-136)
fn active_kdcpolicies(store: &dyn PrincipalRead) -> Vec<Arc<dyn KdcPolicy>> {
    #[cfg(test)]
    if let Some(module) = THREAD_POLICY.with(|slot| slot.borrow().clone()) {
        return vec![module];
    }
    #[cfg(test)]
    if let Some(modules) = THREAD_POLICIES.with(|slot| slot.borrow().clone()) {
        return selected_kdcpolicies(&store.policy().kdcpolicy, modules);
    }
    let plugins = &store.policy().plugins;
    if let Some(module) = plugins.sole_policy() {
        return vec![module];
    }
    selected_kdcpolicies(&store.policy().kdcpolicy, plugins.policies())
}

#[expect(
    clippy::too_many_arguments,
    reason = "MIT check_kdcpolicy_as passes the request, both principals, the indicators and both ticket times"
)]
pub(crate) fn enforce_kdcpolicy_as(
    store: &dyn PrincipalRead,
    request: &KdcReqBody,
    client: &Principal,
    server: &Principal,
    indicators: &[String],
    now: &KerberosTime,
    end: &mut KerberosTime,
    renew_till: &mut Option<KerberosTime>,
) -> Result<(), Error> {
    let peer = request_peer();
    for module in active_kdcpolicies(store) {
        let mut status = None;
        match module.check_as_from(
            request,
            store,
            client,
            server,
            indicators,
            peer.as_ref(),
            &mut status,
        ) {
            Ok(adj) => apply_policy_times(now, end, renew_till, &adj),
            Err(err) => {
                return Err(match status {
                    Some(word) => crate::ad::with_status(err, word),
                    None => err,
                });
            }
        }
    }
    Ok(())
}

// MIT: `check_kdcpolicy_tgs` (kdc/policy.c:144-176)
#[expect(
    clippy::too_many_arguments,
    reason = "MIT check_kdcpolicy_tgs passes the request, the server, the ticket, the indicators and both ticket times"
)]
pub(crate) fn enforce_kdcpolicy_tgs(
    store: &dyn PrincipalRead,
    request: &KdcReqBody,
    server: &Principal,
    ticket: &EncTicketPart,
    indicators: &[String],
    now: &KerberosTime,
    end: &mut KerberosTime,
    renew_till: &mut Option<KerberosTime>,
) -> Result<(), Error> {
    let peer = request_peer();
    for module in active_kdcpolicies(store) {
        let mut status = None;
        match module.check_tgs_from(
            request,
            store,
            server,
            ticket,
            indicators,
            peer.as_ref(),
            &mut status,
        ) {
            Ok(adj) => apply_policy_times(now, end, renew_till, &adj),
            Err(err) => {
                return Err(match status {
                    Some(word) => crate::ad::with_status(err, word),
                    None => err,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use krb5_types::cammac::AdKdcIssued;

    use crate::testrealm::bootstrap_documented;
    use crate::testrealm::{
        DemoPolicy, DemoPreauth, DenyPolicy, GREET_AD_TYPE, GREET_TEXT, GreetAuth,
    };

    use crate::testrealm::{TEST_REALM, TEST_USER};

    use krb5_protocol::{as_req, pa_enc_timestamp};
    use krb5_types::PrincipalName;

    #[test]
    fn a_hints_cookie_shows_no_octets() {
        let hint = PreauthHint {
            padata: vec![PaData {
                padata_type: pa::SPAKE,
                padata_value: b"challenge".to_vec().into(),
            }],
            cookie: vec![PaData {
                padata_type: pa::SPAKE,
                padata_value: b"private scalar".to_vec().into(),
            }],
        };
        let shown = format!("{hint:?}");
        assert!(!shown.contains("private scalar"), "{shown}");
        assert!(
            shown.contains("cookie: [PaData { padata_type: 151, len: 14 }]"),
            "{shown}"
        );
        assert!(shown.contains("challenge"), "{shown}");
    }

    #[test]
    fn demo_preauth_and_policy_are_consulted() {
        let demo = DemoPreauth::new();
        set_thread_preauth(vec![Arc::clone(&demo) as Arc<dyn KdcPreauth>]);
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
        clear_thread_preauth();
        clear_thread_policy();
    }

    struct CountingAuthdata(std::sync::atomic::AtomicU64);

    impl KdcAuthdata for CountingAuthdata {
        fn name(&self) -> &'static str {
            "counting"
        }
        fn handle(
            &self,
            _is_tgs: bool,
            _reply: &mut AuthorizationData,
            _session: Option<&ProtocolKey>,
            _issuer: Option<(&PrincipalName, &str)>,
        ) -> Result<(), Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn thread_preauth_and_authdata_stay_on_their_thread() {
        let (store, _) = bootstrap_documented().unwrap();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let no_padata = |nonce| as_req(cname.clone(), TEST_REALM, nonce, None).unwrap();
        let demo = DemoPreauth::new();
        set_thread_preauth(vec![Arc::clone(&demo) as Arc<dyn KdcPreauth>]);
        let counting = Arc::new(CountingAuthdata(std::sync::atomic::AtomicU64::new(0)));
        set_thread_authdata(vec![Arc::clone(&counting) as Arc<dyn KdcAuthdata>]);
        let other = std::thread::spawn({
            let store = store.clone();
            let req = no_padata(21);
            move || {
                let as_err = crate::issue_as(&store, &req).unwrap_err();
                crate::ad::handle_authdata(
                    &crate::store::Policy::default(),
                    true,
                    false,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .expect("handle_authdata");
                as_err
            }
        })
        .join()
        .expect("join");
        assert!(matches!(other, Error::PreauthRequired { .. }), "{other:?}");
        assert_eq!(
            (
                demo.ads.load(Ordering::SeqCst),
                demo.procs.load(Ordering::SeqCst)
            ),
            (0, 0),
            "another thread's AS must not run this thread's preauth module"
        );
        assert_eq!(
            counting.0.load(Ordering::SeqCst),
            0,
            "another thread must not run this thread's authdata module"
        );
        let _ = crate::issue_as(&store, &no_padata(22)).unwrap_err();
        crate::ad::handle_authdata(
            &crate::store::Policy::default(),
            true,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("handle_authdata");
        assert_eq!(demo.procs.load(Ordering::SeqCst), 1, "this thread's AS");
        assert_eq!(counting.0.load(Ordering::SeqCst), 1, "this thread's TGS");
        clear_thread_preauth();
        clear_thread_authdata();
        let _ = crate::issue_as(&store, &no_padata(23)).unwrap_err();
        crate::ad::handle_authdata(
            &crate::store::Policy::default(),
            true,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("handle_authdata");
        assert_eq!(
            (
                demo.procs.load(Ordering::SeqCst),
                counting.0.load(Ordering::SeqCst)
            ),
            (1, 1),
            "cleared: the thread is back on the process-wide modules"
        );
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
        store
            .put_policy(NamedPolicy {
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
            })
            .unwrap();
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
        lock_plugins().clear_policy();
        assert!(
            hits >= 1,
            "serve-thread current_policy must see set_policy, got {hits}"
        );
    }

    #[test]
    fn enc_timestamp_registry_replay_is_issued_again() {
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
        crate::issue_as(&store, &req).expect("registry EncTsOk issues");
        // MIT: `enc_ts_verify` (kdc/kdc_preauth_encts.c:94-101)
        // no replay cache, so the same timestamp verifies again.
        crate::issue_as(&store, &req).expect("the replayed timestamp issues again");
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
        assert_eq!(as_ad, [] as [krb5_types::AuthorizationDataValue; 0]);
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

    #[test]
    fn startup_lines_match_the_mit_kdc_log() {
        let missing = "No pkinit_identity supplied for realm KERBER.TEST";
        let lines = preauth_startup_lines(&krb5_config::PluginRelations::default(), Some(missing));
        assert_eq!(
            lines,
            vec![
                ("info", "Loaded".to_owned()),
                (
                    "error",
                    "preauth pkinit failed to initialize: PKINIT initialization failed: No pkinit_identity supplied for realm KERBER.TEST".to_owned(),
                ),
            ]
        );
        let ready = preauth_startup_lines(&krb5_config::PluginRelations::default(), None);
        assert_eq!(ready, vec![("info", "Loaded".to_owned())]);
        let off = krb5_config::PluginRelations {
            disable: Some(vec!["otp".to_owned(), "pkinit".to_owned()]),
            ..krb5_config::PluginRelations::default()
        };
        assert_eq!(
            preauth_startup_lines(&off, Some(missing)),
            Vec::<(&str, String)>::new()
        );
        let only_pkinit = krb5_config::PluginRelations {
            enable_only: Some(vec!["pkinit".to_owned()]),
            ..krb5_config::PluginRelations::default()
        };
        assert_eq!(
            preauth_startup_lines(&only_pkinit, Some(missing)),
            vec![(
                "error",
                "preauth pkinit failed to initialize: PKINIT initialization failed: No pkinit_identity supplied for realm KERBER.TEST".to_owned(),
            )]
        );
    }

    /// `[plugins] kdcpreauth` left out never initializes, so it logs nothing.
    #[test]
    fn a_failed_otp_init_is_logged_and_the_module_left_out() {
        let mut store = crate::store::PrincipalStore::new("KERBER.TEST");
        assert_eq!(
            otp_startup_lines(store.policy()),
            Vec::<(&str, String)>::new()
        );
        let kdc = krb5_config::KdcConf::parse(
            "[otp]\n    DEFAULT = {\n        server = /s/o.sock\n    }\n",
        )
        .unwrap();
        store.apply_kdc_conf(&kdc).unwrap();
        assert_eq!(
            otp_startup_lines(store.policy()),
            vec![
                (
                    "error",
                    "Invalid argument - Unsupported relation 'server' (token type 'DEFAULT'): RADIUS is not implemented; an embedder's OtpVerifier decides".to_owned(),
                ),
                (
                    "error",
                    "preauth otp failed to initialize: Invalid argument".to_owned(),
                ),
            ]
        );
        let loaded = |s: &crate::store::PrincipalStore| -> Vec<&'static str> {
            selected_preauth(s.policy())
                .iter()
                .map(|m| m.name())
                .collect()
        };
        assert!(!loaded(&store).contains(&"otp"));
        assert!(loaded(&store).contains(&"spake"));
        let kdc =
            krb5_config::KdcConf::parse("[otp]\n    A = {\n        timeout = 5s\n    }\n").unwrap();
        store.apply_kdc_conf(&kdc).unwrap();
        assert_eq!(
            otp_startup_lines(store.policy()),
            vec![(
                "error",
                "preauth otp failed to initialize: Invalid integer value".to_owned(),
            )]
        );
        let kdc = krb5_config::KdcConf::parse(
            "[otp]\n    A = {\n        timeout = 5s\n    }\n[plugins]\n    kdcpreauth = {\n        disable = otp\n    }\n",
        )
        .unwrap();
        store.apply_kdc_conf(&kdc).unwrap();
        assert_eq!(
            otp_startup_lines(store.policy()),
            Vec::<(&str, String)>::new()
        );
        let kdc =
            krb5_config::KdcConf::parse("[otp]\n    A = {\n        timeout = 5\n    }\n").unwrap();
        store.apply_kdc_conf(&kdc).unwrap();
        assert_eq!(
            otp_startup_lines(store.policy()),
            Vec::<(&str, String)>::new()
        );
        assert!(loaded(&store).contains(&"otp"));
    }

    struct ClearKdcpolicy;

    impl ClearKdcpolicy {
        fn list(modules: Vec<Arc<dyn KdcPolicy>>) -> Self {
            set_thread_kdcpolicies(modules);
            Self
        }

        fn slot(module: Arc<dyn KdcPolicy>) -> Self {
            set_thread_policy(module);
            Self
        }
    }

    impl Drop for ClearKdcpolicy {
        fn drop(&mut self) {
            clear_thread_kdcpolicies();
            clear_thread_policy();
        }
    }

    struct CapModule {
        name: &'static str,
        life: i64,
        deny: bool,
        hits: AtomicU64,
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl CapModule {
        fn new(name: &'static str, life: i64, log: &Arc<Mutex<Vec<&'static str>>>) -> Arc<Self> {
            Arc::new(Self {
                name,
                life,
                deny: false,
                hits: AtomicU64::new(0),
                log: Arc::clone(log),
            })
        }

        fn deny(name: &'static str, log: &Arc<Mutex<Vec<&'static str>>>) -> Arc<Self> {
            Arc::new(Self {
                name,
                life: 0,
                deny: true,
                hits: AtomicU64::new(0),
                log: Arc::clone(log),
            })
        }
    }

    impl KdcPolicy for CapModule {
        fn name(&self) -> &'static str {
            self.name
        }

        fn check_as(
            &self,
            _store: &dyn PrincipalRead,
            _client: &Principal,
            _indicators: &[String],
        ) -> Result<PolicyAdjustment, Error> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            self.log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(self.name);
            if self.deny {
                return Err(Error::Protocol {
                    code: krb5_types::err::POLICY,
                    text: Some(status::LOCAL_POLICY.to_owned()),
                    e_data: None,
                    detail: None,
                });
            }
            Ok(PolicyAdjustment {
                lifetime: self.life,
                renew_lifetime: self.life.saturating_mul(2),
            })
        }

        fn check_tgs(
            &self,
            _store: &dyn PrincipalRead,
            _sname: &PrincipalName,
            _indicators: &[String],
        ) -> Result<PolicyAdjustment, Error> {
            let life = self.life / 2;
            self.hits.fetch_add(1, Ordering::SeqCst);
            self.log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(self.name);
            if self.deny {
                return Err(Error::Protocol {
                    code: krb5_types::err::POLICY,
                    text: Some(status::LOCAL_POLICY.to_owned()),
                    e_data: None,
                    detail: None,
                });
            }
            Ok(PolicyAdjustment {
                lifetime: life,
                renew_lifetime: life.saturating_mul(2),
            })
        }
    }

    struct TicketSeen {
        end: AtomicU64,
    }

    impl KdcPolicy for TicketSeen {
        fn name(&self) -> &'static str {
            "ticket"
        }

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

        fn check_tgs_req(
            &self,
            _request: &KdcReqBody,
            _store: &dyn PrincipalRead,
            _server: &Principal,
            ticket: &EncTicketPart,
            _indicators: &[String],
            _status: &mut Option<&'static str>,
        ) -> Result<PolicyAdjustment, Error> {
            self.end
                .store(u64::from(ticket.endtime.unix_seconds()), Ordering::SeqCst);
            Ok(PolicyAdjustment {
                lifetime: 1800,
                renew_lifetime: 0,
            })
        }
    }

    fn policy_log() -> Arc<Mutex<Vec<&'static str>>> {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn kdcpolicy_stanza(store: &mut crate::store::PrincipalStore, body: &str) {
        let text = format!("[plugins]\n    kdcpolicy = {{\n{body}    }}\n");
        store.policy.kdcpolicy = krb5_config::Krb5Conf::parse(&text)
            .expect("stanza")
            .plugin_relations("kdcpolicy");
    }

    fn policy_pair(store: &crate::store::PrincipalStore) -> (Principal, Principal) {
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let client = store.get_name(&user).expect("user").clone();
        let server = store.fetch_krbtgt().expect("krbtgt").expect("krbtgt row");
        (client, server)
    }

    fn policy_body(cname: Option<&str>, sname: Option<&str>) -> KdcReqBody {
        let part = |s: &str| PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s]);
        KdcReqBody {
            kdc_options: krb5_types::KdcOptions::none(),
            cname: cname.map(part),
            realm: krb5_types::try_ascii(TEST_REALM).expect("realm"),
            sname: sname.map(part),
            from: None,
            till: KerberosTime::from_unix_seconds(2_000_000_000),
            rtime: None,
            nonce: 1,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        }
    }

    fn open_times() -> (KerberosTime, KerberosTime, Option<KerberosTime>) {
        let now = KerberosTime::from_unix_seconds(1_700_000_000);
        let end = now.add_seconds(30 * 24 * 3600).expect("end");
        let renew = Some(now.add_seconds(30 * 24 * 3600).expect("renew"));
        (now, end, renew)
    }

    fn header_ticket(end_at: u32) -> EncTicketPart {
        let now = KerberosTime::from_unix_seconds(1_700_000_000);
        EncTicketPart {
            flags: krb5_types::TicketFlags::initial_preauth(),
            key: krb5_types::EncryptionKey {
                keytype: 18,
                keyvalue: vec![0u8; 32].into(),
            },
            crealm: krb5_types::try_ascii(TEST_REALM).expect("realm"),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]),
            transited: krb5_types::TransitedEncoding::empty(),
            authtime: now.clone(),
            starttime: Some(now),
            endtime: KerberosTime::from_unix_seconds(end_at),
            renew_till: None,
            caddr: None,
            authorization_data: None,
        }
    }

    #[test]
    fn named_modules_cap_to_the_tighter_life() {
        let (mut store, _) = bootstrap_documented().unwrap();
        kdcpolicy_stanza(&mut store, "        disable = nosuch\n");
        let log = policy_log();
        let wide = CapModule::new("wide", 7 * 3600, &log);
        let tight = CapModule::new("tight", 3600, &log);
        let _guard = ClearKdcpolicy::list(vec![
            Arc::clone(&wide) as Arc<dyn KdcPolicy>,
            Arc::clone(&tight) as Arc<dyn KdcPolicy>,
        ]);
        let (client, server) = policy_pair(&store);
        let (now, mut end, mut renew) = open_times();
        enforce_kdcpolicy_as(
            &store,
            &policy_body(None, None),
            &client,
            &server,
            &[],
            &now,
            &mut end,
            &mut renew,
        )
        .expect("both allow");
        assert_eq!(wide.hits.load(Ordering::SeqCst), 1);
        assert_eq!(tight.hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            log.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            ["wide", "tight"]
        );
        assert_eq!(end, now.add_seconds(3600).expect("cap"));
        assert_eq!(renew, Some(now.add_seconds(7200).expect("renew")));
    }

    #[test]
    fn disable_drops_the_named_module() {
        let (mut store, _) = bootstrap_documented().unwrap();
        kdcpolicy_stanza(&mut store, "        disable = tight\n");
        let log = policy_log();
        let wide = CapModule::new("wide", 7 * 3600, &log);
        let tight = CapModule::new("tight", 3600, &log);
        let _guard = ClearKdcpolicy::list(vec![
            Arc::clone(&wide) as Arc<dyn KdcPolicy>,
            Arc::clone(&tight) as Arc<dyn KdcPolicy>,
        ]);
        let (client, server) = policy_pair(&store);
        let (now, mut end, mut renew) = open_times();
        enforce_kdcpolicy_as(
            &store,
            &policy_body(None, None),
            &client,
            &server,
            &[],
            &now,
            &mut end,
            &mut renew,
        )
        .expect("wide allows");
        assert_eq!(wide.hits.load(Ordering::SeqCst), 1);
        assert_eq!(tight.hits.load(Ordering::SeqCst), 0);
        assert_eq!(end, now.add_seconds(7 * 3600).expect("wide"));
        assert_eq!(renew, Some(now.add_seconds(14 * 3600).expect("renew")));
    }

    #[test]
    fn enable_only_orders_the_named_modules() {
        let (mut store, _) = bootstrap_documented().unwrap();
        kdcpolicy_stanza(
            &mut store,
            "        enable_only = tight\n        enable_only = wide\n",
        );
        let log = policy_log();
        let wide = CapModule::new("wide", 7 * 3600, &log);
        let tight = CapModule::new("tight", 3600, &log);
        let _guard = ClearKdcpolicy::list(vec![
            Arc::clone(&wide) as Arc<dyn KdcPolicy>,
            Arc::clone(&tight) as Arc<dyn KdcPolicy>,
        ]);
        let (client, server) = policy_pair(&store);
        let (now, mut end, mut renew) = open_times();
        enforce_kdcpolicy_as(
            &store,
            &policy_body(None, None),
            &client,
            &server,
            &[],
            &now,
            &mut end,
            &mut renew,
        )
        .expect("both allow");
        assert_eq!(
            log.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            ["tight", "wide"]
        );
        assert_eq!(end, now.add_seconds(3600).expect("tighter cap stays"));
    }

    #[test]
    fn enable_only_of_an_unknown_name_keeps_nothing() {
        let (mut store, _) = bootstrap_documented().unwrap();
        kdcpolicy_stanza(&mut store, "        enable_only = nosuch\n");
        let log = policy_log();
        let wide = CapModule::new("wide", 7 * 3600, &log);
        let _guard = ClearKdcpolicy::list(vec![Arc::clone(&wide) as Arc<dyn KdcPolicy>]);
        let (client, server) = policy_pair(&store);
        let (now, mut end, mut renew) = open_times();
        let start_end = end.clone();
        let start_renew = renew.clone();
        enforce_kdcpolicy_as(
            &store,
            &policy_body(None, None),
            &client,
            &server,
            &[],
            &now,
            &mut end,
            &mut renew,
        )
        .expect("nothing loaded still allows");
        assert_eq!(wide.hits.load(Ordering::SeqCst), 0);
        assert_eq!(end, start_end);
        assert_eq!(renew, start_renew);
    }

    #[test]
    fn a_denial_stops_later_modules() {
        let (store, _) = bootstrap_documented().unwrap();
        let log = policy_log();
        let first = CapModule::new("wide", 7 * 3600, &log);
        let second = CapModule::deny("deny", &log);
        let third = CapModule::new("tight", 3600, &log);
        let _guard = ClearKdcpolicy::list(vec![
            Arc::clone(&first) as Arc<dyn KdcPolicy>,
            Arc::clone(&second) as Arc<dyn KdcPolicy>,
            Arc::clone(&third) as Arc<dyn KdcPolicy>,
        ]);
        let (client, server) = policy_pair(&store);
        let (now, mut end, mut renew) = open_times();
        let err = enforce_kdcpolicy_as(
            &store,
            &policy_body(None, None),
            &client,
            &server,
            &[],
            &now,
            &mut end,
            &mut renew,
        )
        .expect_err("second module denies");
        match err {
            Error::Protocol { code, text, .. } => {
                assert_eq!(code, krb5_types::err::POLICY);
                assert_eq!(text.as_deref(), Some(status::LOCAL_POLICY));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(first.hits.load(Ordering::SeqCst), 1);
        assert_eq!(second.hits.load(Ordering::SeqCst), 1);
        assert_eq!(third.hits.load(Ordering::SeqCst), 0);
        assert_eq!(end, now.add_seconds(7 * 3600).expect("first cap stays"));
    }

    #[test]
    fn an_empty_list_leaves_the_times() {
        let (store, _) = bootstrap_documented().unwrap();
        let _guard = ClearKdcpolicy::list(Vec::new());
        let (client, server) = policy_pair(&store);
        let (now, mut end, mut renew) = open_times();
        let start_end = end.clone();
        enforce_kdcpolicy_as(
            &store,
            &policy_body(None, None),
            &client,
            &server,
            &[],
            &now,
            &mut end,
            &mut renew,
        )
        .expect("no module allows");
        assert_eq!(end, start_end);
    }

    #[test]
    fn filter_preauth_error_sends_24_and_keeps_the_text_only_with_a_kept_code() {
        use krb5_types::err;
        let module_text = |code, detail: &str| Error::Protocol {
            code,
            text: Some("CANT_FIND_CLIENT_KEY".to_owned()),
            e_data: None,
            detail: Some(detail.to_owned()),
        };
        // 60 is off the list: 24 on the wire, the module's text dropped, the status word MIT's.
        match filter_preauth_error(module_text(err::GENERIC, "boom")) {
            Error::Protocol {
                code, text, detail, ..
            } => {
                assert_eq!(code, err::PREAUTH_FAILED);
                assert_eq!(text.as_deref(), Some(status::PREAUTH_FAILED));
                assert_eq!(detail, None);
            }
            other => panic!("expected a protocol error, got {other:?}"),
        }
        for code in [err::PREAUTH_FAILED, err::SKEW, err::ETYPE_NOSUPP, 75] {
            match filter_preauth_error(module_text(code, "left for it")) {
                Error::Protocol {
                    code: kept, detail, ..
                } => {
                    assert_eq!(kept, code);
                    assert_eq!(detail.as_deref(), Some("left for it"), "code {code}");
                }
                other => panic!("expected a protocol error, got {other:?}"),
            }
        }
        for e in [
            Error::PreauthModule {
                code: 22,
                message: "Invalid argument".to_owned(),
            },
            Error::Rng,
            Error::Asn1("x".to_owned()),
        ] {
            match filter_preauth_error(e) {
                Error::Protocol { code, detail, .. } => {
                    assert_eq!(code, err::PREAUTH_FAILED);
                    assert_eq!(detail, None);
                }
                other => panic!("expected a protocol error, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_failure_is_logged_with_the_message_of_its_own_code() {
        use krb5_types::err;
        let protocol = |code, detail: Option<&str>| Error::Protocol {
            code,
            text: None,
            e_data: None,
            detail: detail.map(str::to_owned),
        };
        for (e, want) in [
            (
                protocol(err::PREAUTH_FAILED, None),
                "Preauthentication failed",
            ),
            (protocol(err::SKEW, None), "Clock skew too great"),
            (
                protocol(err::PREAUTH_EXPIRED, None),
                "Preauthentication expired",
            ),
            (
                protocol(err::MORE_PREAUTH_DATA_REQUIRED, None),
                "More preauthentication data is required",
            ),
            (
                protocol(err::ETYPE_NOSUPP, None),
                "KDC has no support for encryption type",
            ),
            (
                protocol(
                    err::PREAUTH_FAILED,
                    Some("Pkinit request not signed, but client not anonymous."),
                ),
                "Pkinit request not signed, but client not anonymous.",
            ),
            (
                Error::PreauthModule {
                    code: KDB_NO_PERMITTED_KEY,
                    message: "No matching key in entry having a permitted enctype".to_owned(),
                },
                "No matching key in entry having a permitted enctype",
            ),
            (
                Error::PreauthRequired { e_data: Vec::new() },
                "Additional pre-authentication required",
            ),
        ] {
            assert_eq!(verify_failure_text(&e), want, "{e:?}");
        }
    }

    struct Tagged(&'static str, OtpVerdict);

    impl OtpVerifier for Tagged {
        fn name(&self) -> &'static str {
            self.0
        }
        fn verify(&self, _req: &OtpVerifyRequest) -> OtpVerdict {
            self.1.clone()
        }
    }

    #[test]
    fn register_rejects_a_duplicate_name_and_a_thread_list_replaces() {
        let (store, _) = bootstrap_documented().unwrap();
        let client = store
            .get_name(&PrincipalName::new(
                PrincipalName::NT_PRINCIPAL,
                [TEST_USER],
            ))
            .unwrap()
            .clone();
        let verdict = |name: &str| {
            let policy = crate::store::Policy::default();
            let v = find_otp_verifier(&policy, name).expect("a verifier of that name");
            v.verify(&OtpVerifyRequest::for_test(
                client.clone(),
                TEST_REALM,
                name,
                b"u".to_vec(),
                b"1".to_vec(),
            ))
        };
        register_otp_verifier(Arc::new(Tagged("registry-first", OtpVerdict::Accept))).unwrap();
        assert!(
            register_otp_verifier(Arc::new(Tagged("registry-first", OtpVerdict::Reject))).is_err()
        );
        assert_eq!(verdict("registry-first"), OtpVerdict::Accept);
        set_thread_otp_verifiers(vec![Arc::new(Tagged("registry-first", OtpVerdict::Reject))]);
        assert_eq!(verdict("registry-first"), OtpVerdict::Reject);
        clear_thread_otp_verifiers();
        assert_eq!(verdict("registry-first"), OtpVerdict::Accept);
        lock_plugins().unregister_otp_verifier("registry-first");
    }

    #[test]
    fn a_thread_slot_ignores_the_stanza() {
        let (mut store, _) = bootstrap_documented().unwrap();
        kdcpolicy_stanza(&mut store, "        disable = tight\n");
        let log = policy_log();
        let tight = CapModule::new("tight", 3600, &log);
        let _guard = ClearKdcpolicy::slot(Arc::clone(&tight) as Arc<dyn KdcPolicy>);
        let (client, server) = policy_pair(&store);
        let (now, mut end, mut renew) = open_times();
        enforce_kdcpolicy_as(
            &store,
            &policy_body(None, None),
            &client,
            &server,
            &[],
            &now,
            &mut end,
            &mut renew,
        )
        .expect("slot allows");
        assert_eq!(tight.hits.load(Ordering::SeqCst), 1);
        assert_eq!(end, now.add_seconds(3600).expect("slot cap"));
    }

    #[test]
    fn request_client_fail_denies_before_the_database_name() {
        let (store, _) = bootstrap_documented().unwrap();
        let _guard = ClearKdcpolicy::slot(Arc::new(crate::testrealm::TestPolicy));
        let (client, server) = policy_pair(&store);
        let (now, mut end, mut renew) = open_times();
        let err = enforce_kdcpolicy_as(
            &store,
            &policy_body(Some("fail"), None),
            &client,
            &server,
            &[],
            &now,
            &mut end,
            &mut renew,
        )
        .expect_err("request cname fail");
        match err {
            Error::Protocol { code, text, .. } => {
                assert_eq!(code, krb5_types::err::POLICY);
                assert_eq!(text.as_deref(), Some(status::LOCAL_POLICY));
            }
            other => panic!("{other:?}"),
        }
    }

    struct StatusOut;

    impl KdcPolicy for StatusOut {
        fn name(&self) -> &'static str {
            "status"
        }

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

        fn check_as_req(
            &self,
            _request: &KdcReqBody,
            _store: &dyn PrincipalRead,
            _client: &Principal,
            _server: &Principal,
            _indicators: &[String],
            status: &mut Option<&'static str>,
        ) -> Result<PolicyAdjustment, Error> {
            *status = Some("KDCPOLICY_STATUS");
            Err(Error::Protocol {
                code: krb5_types::err::POLICY,
                text: Some("NOT_THE_STATUS".to_owned()),
                e_data: None,
                detail: None,
            })
        }
    }

    #[test]
    fn a_status_out_is_the_denial_text() {
        let (store, _) = bootstrap_documented().unwrap();
        let _guard = ClearKdcpolicy::slot(Arc::new(StatusOut));
        let (client, server) = policy_pair(&store);
        let (now, mut end, mut renew) = open_times();
        let err = enforce_kdcpolicy_as(
            &store,
            &policy_body(None, None),
            &client,
            &server,
            &[],
            &now,
            &mut end,
            &mut renew,
        )
        .expect_err("status module denies");
        match err {
            Error::Protocol { code, text, .. } => {
                assert_eq!(code, krb5_types::err::POLICY);
                assert_eq!(text.as_deref(), Some("KDCPOLICY_STATUS"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn tgs_module_sees_the_header_ticket() {
        let (store, _) = bootstrap_documented().unwrap();
        let seen = Arc::new(TicketSeen {
            end: AtomicU64::new(0),
        });
        let _guard = ClearKdcpolicy::list(vec![Arc::clone(&seen) as Arc<dyn KdcPolicy>]);
        let (_client, server) = policy_pair(&store);
        let ticket = header_ticket(1_800_000_000);
        let (now, mut end, mut renew) = open_times();
        enforce_kdcpolicy_tgs(
            &store,
            &policy_body(None, Some("host")),
            &server,
            &ticket,
            &[],
            &now,
            &mut end,
            &mut renew,
        )
        .expect("ticket module allows");
        assert_eq!(seen.end.load(Ordering::SeqCst), 1_800_000_000);
        assert_eq!(end, now.add_seconds(1800).expect("tgs cap"));
    }

    #[test]
    fn kdc_conf_and_krb5_conf_disables_both_apply() {
        let (mut store, _) = bootstrap_documented().unwrap();
        let kdc = krb5_config::KdcConf::parse(
            "[plugins]\n    kdcpolicy = {\n        disable = tight\n    }\n",
        )
        .expect("kdc.conf");
        let krb5 = krb5_config::Krb5Conf::parse(
            "[plugins]\n    kdcpolicy = {\n        disable = wide\n    }\n",
        )
        .expect("krb5.conf");
        store.apply_kdcpolicy_plugins(Some(&kdc), Some(&krb5));
        let log = policy_log();
        let wide = CapModule::new("wide", 7 * 3600, &log);
        let tight = CapModule::new("tight", 3600, &log);
        let _guard = ClearKdcpolicy::list(vec![
            Arc::clone(&wide) as Arc<dyn KdcPolicy>,
            Arc::clone(&tight) as Arc<dyn KdcPolicy>,
        ]);
        let (client, server) = policy_pair(&store);
        let (now, mut end, mut renew) = open_times();
        let start_end = end.clone();
        enforce_kdcpolicy_as(
            &store,
            &policy_body(None, None),
            &client,
            &server,
            &[],
            &now,
            &mut end,
            &mut renew,
        )
        .expect("nothing loaded still allows");
        assert_eq!(wide.hits.load(Ordering::SeqCst), 0);
        assert_eq!(tight.hits.load(Ordering::SeqCst), 0);
        assert_eq!(end, start_end);
    }

    struct ClearPeer;

    impl Drop for ClearPeer {
        fn drop(&mut self) {
            set_request_peer(None);
        }
    }

    struct PeerSeen {
        octets: Mutex<Option<Vec<u8>>>,
    }

    impl KdcPolicy for PeerSeen {
        fn name(&self) -> &'static str {
            "peer"
        }

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

        fn check_as_from(
            &self,
            request: &KdcReqBody,
            store: &dyn PrincipalRead,
            client: &Principal,
            server: &Principal,
            indicators: &[String],
            peer: Option<&HostAddress>,
            status: &mut Option<&'static str>,
        ) -> Result<PolicyAdjustment, Error> {
            *self
                .octets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                peer.map(|addr| addr.address.as_ref().to_vec());
            self.check_as_req(request, store, client, server, indicators, status)
        }
    }

    #[test]
    fn policy_sees_the_socket_peer_not_the_request_addresses() {
        let (store, _) = bootstrap_documented().unwrap();
        let seen = Arc::new(PeerSeen {
            octets: Mutex::new(None),
        });
        let _guard = ClearKdcpolicy::slot(Arc::clone(&seen) as Arc<dyn KdcPolicy>);
        set_request_peer(Some(HostAddress {
            addr_type: HostAddress::ADDRTYPE_INET,
            address: vec![10, 1, 2, 3].into(),
        }));
        let _peer = ClearPeer;
        let mut body = policy_body(None, None);
        body.addresses = Some(vec![HostAddress {
            addr_type: HostAddress::ADDRTYPE_INET,
            address: vec![10, 9, 9, 9].into(),
        }]);
        let (client, server) = policy_pair(&store);
        let (now, mut end, mut renew) = open_times();
        enforce_kdcpolicy_as(
            &store,
            &body,
            &client,
            &server,
            &[],
            &now,
            &mut end,
            &mut renew,
        )
        .expect("peer module allows");
        assert_eq!(
            seen.octets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_deref(),
            Some(&[10, 1, 2, 3][..])
        );
    }
}

#[path = "kdcpolicy_test.rs"]
mod kdcpolicy_test;

pub fn register_kdcpolicy_test_if_selected(
    plugins: &mut PluginSet,
    relations: &krb5_config::PluginRelations,
) {
    let Some(names) = relations.enable_only.as_ref() else {
        return;
    };
    if !names.iter().any(|name| name == "test") {
        return;
    }
    plugins.register_kdcpolicy(std::sync::Arc::new(kdcpolicy_test::TestModule));
}
