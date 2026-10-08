//! kdcpreauth, kdcpolicy, and kdcauthdata extension points.
//!
//! These are Rust traits, not loaded objects. A preauth module returns
//! an action the KDC already understands. There is no dlopen path that
//! can change that action after the module returns.

use std::sync::{Arc, Mutex, OnceLock};

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_types::{
    AuthorizationData, EncTicketPart, HostAddress, KdcReqBody, KerberosTime, PaData, PrincipalName,
    pa,
};

use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::preauth::{SpakeStep, process_pkinit, process_spake, spake_edata};
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
    /// PA-ENC-TIMESTAMP verified; caller must not re-verify.
    EncTsOk,
}

/// What one kdcpreauth module adds to a PREAUTH_REQUIRED (or PREAUTH_FAILED) hint list.
///
/// `Debug` prints a cookie entry's type and length, not its octets, as [`ProtocolKey`]'s prints
/// no key octets: a module's cookie state is secret.
/// MIT `send_challenge` (`plugins/preauth/spake/spake_kdc.c:261-277`): SPAKE's stage-0 cookie holds the group, the KDC's private scalar and the transcript hash, and is zapped once set.
#[derive(Default)]
pub struct PreauthHint {
    /// The module's METHOD-DATA offers, in its order.
    pub padata: Vec<PaData>,
    /// Padata the KDC keeps for the module in its secure cookie (MIT's `set_cookie`).
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

/// Padata shown as type and length only.
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

/// One redacted padata: its type and its value's length.
struct RedactedEntry(i32, usize);

impl std::fmt::Debug for RedactedEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaData")
            .field("padata_type", &self.0)
            .field("len", &self.1)
            .finish()
    }
}

/// Rock passed to a kdcpreauth module's AS handler.
///
/// MIT `struct krb5_kdcpreauth_rock_st` (`kdc/kdc_util.h:422-422`): the struct behind
/// `krb5_kdcpreauth_rock`, the information handle for kdcpreauth callbacks.
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
    /// The module's hint with the client's reply key, and the state it keeps in the KDC cookie.
    /// The default is [`Self::advertise`] and no state.
    ///
    /// MIT `krb5_kdcpreauth_edata_fn` (`kdcpreauth_plugin.h:311-328`): a module sees the request and the rock, whose `client_keyblock` and `set_cookie` callbacks SPAKE's optimistic challenge uses.
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
    /// MIT `PA_HARDWARE` (`kdcpreauth_plugin.h`). FAST is still advertised
    /// under `hw_only`.
    /// MIT `get_preauth_hint_list` (`kdc_preauth.c:999-1001`): the empty PA-FX-FAST is
    /// added before any module hint, whatever `hw_only` says.
    fn hardware(&self) -> bool {
        false
    }
    /// Process AS padata. `None` = not this module's request.
    ///
    /// # Errors
    ///
    /// The [`Error`] with which a module refuses its padata. The built-in modules return
    /// [`Error::Protocol`] for a failed check (`PREAUTH_FAILED`, `SKEW`, ...),
    /// [`Error::Crypto`] when a timestamp does not decrypt or a PKINIT or SPAKE derivation fails,
    /// and [`Error::Asn1`] when padata does not decode or a reply does not encode; `run_as_preauth`
    /// then applies MIT's `filter_preauth_error`.
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
        let PreauthRock {
            store: _store,
            client: _client,
            padata: _padata,
            ikey: _ikey,
            etype: _etype,
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
        if store.pkinit_ca().is_none() {
            return Vec::new();
        }
        let mut out = vec![PaData {
            padata_type: pa::PK_AS_REQ,
            padata_value: Vec::<u8>::new().into(),
        }];
        // MIT `pkinit_server_get_flags` (`pkinit_srv.c:928-929`): PKINIT_KX is PA_INFO,
        // not PA_HARDWARE.
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
            client: _client,
            padata,
            ikey: _ikey,
            etype,
            as_req_der,
            body_der,
            cname,
        } = *rock;
        let done = process_pkinit(
            store,
            padata,
            etype,
            as_req_der,
            body_der,
            cname,
            store.realm(),
        )?;
        Ok(done.map(|(key, pa, signed)| PreauthAction::Pkinit { key, pa, signed }))
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
        // Without the reply key there is no optimistic challenge: the empty PA-SPAKE MIT sends
        // when none is configured. The KDC itself uses `edata`.
        // MIT `spake_edata` (`spake_kdc.c:309-314`): omitted when client_keyblock is NULL, the same condition as `have_client_keys` being false.
        // MIT `group_init_state` (`groups.c:235-238`): no permitted group is `KRB5_PLUGIN_OP_NOTSUPP` ("No SPAKE preauth groups configured").
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
            as_req_der: _as_req_der,
            body_der,
            cname: _cname,
        } = *rock;
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
        // MIT `enc_ts_get` (`kdc_preauth_encts.c:39-43`): ENOENT when FAST armor is
        // present or `have_client_keys` is false.
        // MIT `have_client_keys` (`kdc_preauth.c:442-442`): true when some requested enctype
        // has a client key.
        if armor || !have_client_keys(store, client, requested) {
            return Vec::new();
        }
        vec![PaData {
            padata_type: pa::ENC_TIMESTAMP,
            padata_value: Vec::<u8>::new().into(),
        }]
    }
    /// MIT `enc_ts_verify` (`kdc_preauth_encts.c:74-97`): the timestamp is tried against keys
    /// of that etype, and a clock skew after decrypt is still a failure.
    /// Only the highest kvno is tried, so a timestamp under a retired key does not succeed.
    fn process_as(&self, rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
        let PreauthRock {
            store,
            client,
            padata,
            ikey: _ikey,
            etype: _etype,
            as_req_der: _as_req_der,
            body_der: _body_der,
            cname: _cname,
        } = *rock;
        let Some(blob) = crate::issue::extract_enc_timestamp(padata) else {
            return Ok(None);
        };
        let enc: krb5_types::EncryptedData = match krb5_asn1::decode(blob.as_ref()) {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };
        // MIT `enc_ts_verify` (`kdc_preauth_encts.c:74-92`): krb5_dbe_search_enctype
        // (client, &start, etype, -1, kvno 0) walks the keys of the declared etype.
        // A miss is KRB5_KDB_NO_MATCHING_KEY, remapped to KRB5KDC_ERR_PREAUTH_FAILED
        // (24) at :113-114.
        // MIT `krb5_dbe_def_search_enctype` (`kdb_default.c:65-67`): the walk covers the
        // *highest kvno* only and skips non-permitted enctypes (:60-61, :82-86) — a
        // timestamp under a retired kvno's key (a stale keytab) never decrypts.
        // KRB5_KDB_NO_PERMITTED_KEY (a declared etype outside permitted_enctypes,
        // :60-61) is not remapped by `enc_ts_verify` but is not a pass-through code
        // either.
        // MIT `filter_preauth_error` (`kdc_preauth.c:1092-1133`): a code off the
        // pass-through list, such as KRB5_KDB_NO_PERMITTED_KEY, becomes the same 24 on
        // the wire. An unknown etype matches no key.
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
            match crate::issue::verify_enc_timestamp(store, &k.key, blob.as_ref()) {
                Ok(()) => return Ok(Some(PreauthAction::EncTsOk)),
                Err(e) => last_err = Some(e),
            }
        }
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
        // MIT `ec_edata` (`kdc_preauth_ec.c:37-48`): empty 138 only with armor and
        // `have_client_keys`.
        // MIT `have_client_keys` (`kdc_preauth.c:442-442`): true when some requested enctype
        // has a client key.
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
            as_req_der: _as_req_der,
            body_der: _body_der,
            cname: _cname,
        } = *rock;
        Ok(None)
    }
}

static EXTRA: Mutex<Vec<Arc<dyn KdcPreauth>>> = Mutex::new(Vec::new());
static BUILTIN: OnceLock<Vec<Arc<dyn KdcPreauth>>> = OnceLock::new();

thread_local! {
    static THREAD_EXTRA: std::cell::RefCell<Option<Vec<Arc<dyn KdcPreauth>>>> =
        const { std::cell::RefCell::new(None) };
}

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

/// Extra modules after the built-ins, for every thread that has not set its own list (the KDC's loop).
pub fn register_preauth(m: Arc<dyn KdcPreauth>) {
    EXTRA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(m);
}

/// Install this thread's extra modules, used in place of the process-wide ones (tests).
pub fn set_thread_preauth(modules: Vec<Arc<dyn KdcPreauth>>) {
    THREAD_EXTRA.with(|t| *t.borrow_mut() = Some(modules));
}

/// Drop this thread's extra modules so it uses the process-wide ones.
pub fn clear_thread_preauth() {
    THREAD_EXTRA.with(|t| *t.borrow_mut() = None);
}

/// Take this thread's own extra modules off it, leaving the process-wide ones in force on the
/// thread.
pub(crate) fn take_thread_preauth() -> Option<Vec<Arc<dyn KdcPreauth>>> {
    THREAD_EXTRA.with(|t| t.borrow_mut().take())
}

/// Put back what [`take_thread_preauth`] took.
pub(crate) fn restore_thread_preauth(modules: Option<Vec<Arc<dyn KdcPreauth>>>) {
    THREAD_EXTRA.with(|t| *t.borrow_mut() = modules);
}

/// All modules, built-ins first, then this thread's extras when it has set them, else the
/// process-wide ones.
#[must_use]
pub(crate) fn preauth_modules() -> Vec<Arc<dyn KdcPreauth>> {
    let mut v: Vec<Arc<dyn KdcPreauth>> = builtins().to_vec();
    if let Some(extra) = THREAD_EXTRA.with(|t| t.borrow().clone()) {
        v.extend(extra);
        return v;
    }
    v.extend(
        EXTRA
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned(),
    );
    v
}

/// One kdcauthdata module. Errors are logged, not fatal.
/// MIT `krb5_kdcauthdata_handle_fn` (`kdcauthdata_plugin.h:105-117`): a module's handler
/// is passed the DB entries, their keys, the request and both ticket parts.
pub trait KdcAuthdata: Send + Sync {
    /// Stable name (`greet` in MIT `plugins/authdata/greet_server`).
    fn name(&self) -> &'static str;
    /// Mutate ticket authdata. TGS-only modules return immediately on AS.
    ///
    /// `session` / `issuer` are `enc_tkt_reply->session` and the local TGS
    /// principal.
    /// MIT `krb5_kdcauthdata_handle_fn` (`kdcauthdata_plugin.h:111-117`): the handler is
    /// passed the keys, the request and `enc_tkt_reply`, which carries the session key.
    ///
    /// # Errors
    ///
    /// Module-specific; the KDC logs and continues.
    /// MIT `handle_authdata` (`kdc_authdata.c:610-611`): a module error is logged with
    /// `kdc_err` and the next module still runs.
    fn handle(
        &self,
        is_tgs: bool,
        reply: &mut AuthorizationData,
        session: Option<&ProtocolKey>,
        issuer: Option<(&PrincipalName, &str)>,
    ) -> Result<(), Error>;
}

static EXTRA_AD: Mutex<Vec<Arc<dyn KdcAuthdata>>> = Mutex::new(Vec::new());

thread_local! {
    static THREAD_EXTRA_AD: std::cell::RefCell<Option<Vec<Arc<dyn KdcAuthdata>>>> =
        const { std::cell::RefCell::new(None) };
}

/// Extra kdcauthdata modules for every thread that has not set its own list. None are built in.
pub fn register_authdata(m: Arc<dyn KdcAuthdata>) {
    EXTRA_AD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(m);
}

/// Install this thread's kdcauthdata modules, used in place of the process-wide ones (tests).
pub fn set_thread_authdata(modules: Vec<Arc<dyn KdcAuthdata>>) {
    THREAD_EXTRA_AD.with(|t| *t.borrow_mut() = Some(modules));
}

/// Drop this thread's kdcauthdata modules so it uses the process-wide ones.
pub fn clear_thread_authdata() {
    THREAD_EXTRA_AD.with(|t| *t.borrow_mut() = None);
}

/// Take this thread's own kdcauthdata modules off it, leaving the process-wide ones in force on
/// the thread.
pub(crate) fn take_thread_authdata() -> Option<Vec<Arc<dyn KdcAuthdata>>> {
    THREAD_EXTRA_AD.with(|t| t.borrow_mut().take())
}

/// Put back what [`take_thread_authdata`] took.
pub(crate) fn restore_thread_authdata(modules: Option<Vec<Arc<dyn KdcAuthdata>>>) {
    THREAD_EXTRA_AD.with(|t| *t.borrow_mut() = modules);
}

/// Loaded kdcauthdata modules: this thread's when it has set them, else the process-wide ones
/// (empty unless [`register_authdata`] was called).
#[must_use]
pub(crate) fn authdata_modules() -> Vec<Arc<dyn KdcAuthdata>> {
    if let Some(modules) = THREAD_EXTRA_AD.with(|t| t.borrow().clone()) {
        return modules;
    }
    EXTRA_AD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Named kdcpreauth modules after `[plugins] kdcpreauth` `disable` and `enable_only`.
///
/// `fast` is not a kdcpreauth module, so it stays loaded and is not a name the profile can select.
/// MIT `get_plugin_vtables` (`kdc/kdc_preauth.c:117-163`): built-ins register, then `k5_plugin_load_all` applies the profile.
/// MIT `k5_plugin_load_all` (`lib/krb5/krb/plugin.c:421-455`): a caller walks only the modules that stayed loaded.
pub(crate) fn selected_preauth(
    relations: &krb5_config::PluginRelations,
) -> Vec<Arc<dyn KdcPreauth>> {
    let mut fast = Vec::new();
    let mut named = Vec::new();
    for module in preauth_modules() {
        if module.name() == "fast" {
            fast.push(module);
        } else {
            named.push(module);
        }
    }
    let names: Vec<&str> = named.iter().map(|module| module.name()).collect();
    let kept = krb5_config::filter_plugin_modules(relations, &names);
    for want in kept {
        if let Some(index) = named.iter().position(|module| module.name() == want) {
            fast.push(named.remove(index));
        }
    }
    fast
}

/// Whether `[plugins] kdcpreauth` left `name` loaded.
pub(crate) fn kdcpreauth_loaded(store: &dyn PrincipalRead, name: &str) -> bool {
    selected_preauth(&store.policy().kdcpreauth)
        .iter()
        .any(|module| module.name() == name)
}

/// METHOD-DATA modules after the leading empty PA-FX-FAST, and the cookie state they keep.
/// `ikey` is the client's reply key, when one was selected.
/// MIT `get_preauth_hint_list` (`kdc_preauth.c:999-1006`): the empty PA-FX-FAST and the
/// etype info come first, then the module hints.
/// MIT `kdc_fast_set_cookie` (`fast_util.c:631-651`): the first state set for a padata type is the one kept.
pub fn advertise_preauth(
    store: &dyn PrincipalRead,
    client: &Principal,
    armor: bool,
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
    for m in selected_preauth(&store.policy().kdcpreauth) {
        if m.name() == "fast" {
            continue;
        }
        if hw_only && !m.hardware() {
            continue;
        }
        let hint = m.edata(store, client, armor, requested, ikey);
        out.padata.extend(hint.padata);
        for c in hint.cookie {
            if !out.cookie.iter().any(|p| p.padata_type == c.padata_type) {
                out.cookie.push(c);
            }
        }
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
/// [`Error::Protocol`] with status `PREAUTH_FAILED` when the first module to fail refuses its
/// padata: the module's code when MIT's pass-through list keeps it (`SKEW`, `BAD_INTEGRITY`,
/// `ETYPE_NOSUPP`, `MORE_PREAUTH_DATA_REQUIRED`, the PKINIT codes, ...), else
/// `PREAUTH_FAILED` for any other code or variant. A module's [`Error::PreauthRequired`] passes
/// through unchanged.
pub fn run_as_preauth(rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
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
    for m in selected_preauth(&store.policy().kdcpreauth) {
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

/// MIT `filter_preauth_error` (`kdc_preauth.c:1092-1133`): a module failure keeps its
/// code only when it is on the pass-through list; anything else — a KDB
/// code such as `KRB5_KDB_NO_PERMITTED_KEY`, an ASN.1 or crypto failure, 90
/// `PREAUTH_EXPIRED` — reaches the client as 24 `PREAUTH_FAILED`. It is applied
/// where `finish_check_padata` applies it (`:1206`). The module's e-data rides
/// along (`:1194-1196`), and the original failure stays in the log detail.
/// MIT `finish_preauth` (`do_as_req.c:442-442`): whatever the code, the status word
/// is the `PREAUTH_FAILED` it sets for every module failure, so the e_text is too.
/// FAST errors never pass here (`FastMod::process_as` is a no-op, `kdc_find_fast` is not a
/// module in MIT either).
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
        // k5e1 KRB5KDC_ERR_DISCARD.
        // MIT `filter_preauth_error` (`kdc_preauth.c:1125-1125`): KRB5KDC_ERR_DISCARD
        // passes through.
        // MIT `finish_process_as_req` (`do_as_req.c:372-372`): suppresses the reply.
        err::DISCARD,
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
            // survive in the log detail.
            // MIT `finish_verify_padata` (`kdc_preauth.c:1224-1226`): syslogs "preauth (%s)
            // verify failure: %s".
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

/// MIT `check_kdcpolicy_as/tgs` lifetime rewrite.
/// MIT `update_ticket_times` (`policy.c:91-99`): a non-zero policy lifetime caps
/// `endtime`, and a non-zero renew lifetime caps `renew_till`, both from now.
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
///
/// Several modules may be registered by [`name`](KdcPolicy::name). `[plugins] kdcpolicy`
/// `disable` then `enable_only` select which of them run. [`set_policy`] and
/// [`set_thread_policy`] install one module and skip that stanza.
pub trait KdcPolicy: Send + Sync {
    /// Module name for `[plugins] kdcpolicy`. The default is empty, which is not a built-in name.
    fn name(&self) -> &'static str {
        ""
    }

    /// Called after AS times are computed; `Err` denies the request.
    ///
    /// # Errors
    ///
    /// The [`Error`] that denies the request, usually [`Error::Protocol`] with the KRB-ERROR code
    /// to send (such as `POLICY`); `DefaultPolicy` never fails.
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
    /// The [`Error`] that denies the request, usually [`Error::Protocol`] with the KRB-ERROR code
    /// to send (such as `POLICY`); `DefaultPolicy` never fails.
    fn check_tgs(
        &self,
        store: &dyn PrincipalRead,
        sname: &PrincipalName,
        indicators: &[String],
    ) -> Result<PolicyAdjustment, Error>;

    /// MIT `krb5_kdcpolicy_check_as_fn` (`kdcpolicy_plugin.h:95-102`): the request, both database
    /// principals, the auth indicators, and the status out. Lifetime and renew lifetime come back
    /// as [`PolicyAdjustment`]. The default ignores the request, the server, and the status and
    /// calls [`Self::check_as`].
    ///
    /// # Errors
    ///
    /// The [`Error`] that denies the request. A denial stops later modules. When `status` is set,
    /// that string is the KRB-ERROR text.
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

    /// MIT `krb5_kdcpolicy_check_tgs_fn` (`kdcpolicy_plugin.h:111-118`): the request, the server,
    /// the header ticket, the auth indicators, and the status out. Lifetime and renew lifetime
    /// come back as [`PolicyAdjustment`]. The default ignores the request, the ticket, and the
    /// status and calls [`Self::check_tgs`] with the server name.
    ///
    /// # Errors
    ///
    /// The [`Error`] that denies the request. A denial stops later modules. When `status` is set,
    /// that string is the KRB-ERROR text.
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

    /// AS check with the socket peer. MIT's kdcpolicy receives no peer address.
    /// `peer` is the address the KDC accepted the request from, not `request.addresses`.
    /// The default ignores `peer` and calls [`Self::check_as_req`].
    ///
    /// # Errors
    ///
    /// The [`Error`] that denies the request. A denial stops later modules.
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

    /// TGS check with the socket peer. The default ignores `peer` and calls [`Self::check_tgs_req`].
    ///
    /// # Errors
    ///
    /// The [`Error`] that denies the request. A denial stops later modules.
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
static NAMED_POLICIES: Mutex<Vec<Arc<dyn KdcPolicy>>> = Mutex::new(Vec::new());

thread_local! {
    static THREAD_POLICY: std::cell::RefCell<Option<Arc<dyn KdcPolicy>>> =
        const { std::cell::RefCell::new(None) };
    static THREAD_POLICIES: std::cell::RefCell<Option<Vec<Arc<dyn KdcPolicy>>>> =
        const { std::cell::RefCell::new(None) };
    static REQUEST_PEER: std::cell::RefCell<Option<HostAddress>> =
        const { std::cell::RefCell::new(None) };
}

/// Install the policy hook for every thread that has not set its own (the KDC's loop).
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

/// Take this thread's own hook off it, leaving the process-wide slot in force on the thread.
pub(crate) fn take_thread_policy() -> Option<Arc<dyn KdcPolicy>> {
    THREAD_POLICY.with(|t| t.borrow_mut().take())
}

/// Put back what [`take_thread_policy`] took.
pub(crate) fn restore_thread_policy(p: Option<Arc<dyn KdcPolicy>>) {
    THREAD_POLICY.with(|t| *t.borrow_mut() = p);
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

/// Register one named kdcpolicy module for every thread that has not set its own list.
///
/// `test` is registered only when `enable_only` names it. [`set_policy`] still installs one module and skips this list.
pub fn register_kdcpolicy(module: Arc<dyn KdcPolicy>) {
    NAMED_POLICIES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(module);
}

/// Install this thread's named kdcpolicy modules, used in place of [`register_kdcpolicy`] (tests).
///
/// An empty list allows the request and leaves the ticket times. The list is filtered by
/// `[plugins] kdcpolicy`. It is not used while [`set_thread_policy`] is set.
pub fn set_thread_kdcpolicies(modules: Vec<Arc<dyn KdcPolicy>>) {
    THREAD_POLICIES.with(|slot| *slot.borrow_mut() = Some(modules));
}

/// Drop this thread's named kdcpolicy modules so it uses the process-wide registry.
pub fn clear_thread_kdcpolicies() {
    THREAD_POLICIES.with(|slot| *slot.borrow_mut() = None);
}

/// Take this thread's named kdcpolicy modules off it.
pub(crate) fn take_thread_kdcpolicies() -> Option<Vec<Arc<dyn KdcPolicy>>> {
    THREAD_POLICIES.with(|slot| slot.borrow_mut().take())
}

/// Put back what [`take_thread_kdcpolicies`] took.
pub(crate) fn restore_thread_kdcpolicies(modules: Option<Vec<Arc<dyn KdcPolicy>>>) {
    THREAD_POLICIES.with(|slot| *slot.borrow_mut() = modules);
}

/// The socket peer for policy checks on this thread. `None` outside the listener.
///
/// This is not the `addresses` field of the request, which is the client's claim.
pub(crate) fn set_request_peer(peer: Option<HostAddress>) {
    REQUEST_PEER.with(|slot| *slot.borrow_mut() = peer);
}

/// Peer address set by [`set_request_peer`].
#[must_use]
pub(crate) fn request_peer() -> Option<HostAddress> {
    REQUEST_PEER.with(|slot| slot.borrow().clone())
}

/// Named modules after `[plugins] kdcpolicy` `disable` and `enable_only`, in the order that remains.
///
/// MIT `filter_enabled_modules` (`lib/krb5/krb/plugin.c:271-299`): each enabled name takes the first
/// remaining match.
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

/// Modules for this request.
///
/// A thread slot ([`set_thread_policy`]) or the process slot ([`set_policy`]) is that one module,
/// not filtered. Otherwise the thread's named list, if set, or the process registry, after the
/// profile. An empty selection allows the request.
/// MIT `check_kdcpolicy_as` (`kdc/policy.c:104-136`): a null method is skipped and no loaded module
/// leaves the times unchanged.
fn active_kdcpolicies(store: &dyn PrincipalRead) -> Vec<Arc<dyn KdcPolicy>> {
    if let Some(module) = THREAD_POLICY.with(|slot| slot.borrow().clone()) {
        return vec![module];
    }
    if let Some(modules) = THREAD_POLICIES.with(|slot| slot.borrow().clone()) {
        return selected_kdcpolicies(&store.policy().kdcpolicy, modules);
    }
    if let Some(module) = POLICY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
    {
        return vec![module];
    }
    let modules = NAMED_POLICIES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    selected_kdcpolicies(&store.policy().kdcpolicy, modules)
}

/// Walk the loaded kdcpolicy modules for an AS request and cap the ticket times.
///
/// MIT `check_kdcpolicy_as` (`kdc/policy.c:104-136`): each module may deny or return lifetimes;
/// the first error stops the walk.
/// MIT `update_ticket_times` (`kdc/policy.c:91-99`): a non-zero lifetime caps `endtime` from now,
/// and a non-zero renew lifetime caps `renew_till`.
///
/// # Errors
///
/// The first module's denial. Times already capped by an earlier module stay capped.
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

/// Walk the loaded kdcpolicy modules for a TGS request and cap the ticket times.
///
/// MIT `check_kdcpolicy_tgs` (`kdc/policy.c:144-176`): same walk as the AS check, with the header
/// ticket and no client database entry.
///
/// # Errors
///
/// The first module's denial. Times already capped by an earlier module stay capped.
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
        // SPAKE's stage-0 cookie holds the KDC's private scalar, which MIT zaps: Debug shows the
        // entry's type and length, as ProtocolKey's shows no key octets.
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

    /// A module counting its `handle` calls.
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
                crate::ad::handle_authdata(true, false, None, None, None, None, None, None)
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
        crate::ad::handle_authdata(true, false, None, None, None, None, None, None)
            .expect("handle_authdata");
        assert_eq!(demo.procs.load(Ordering::SeqCst), 1, "this thread's AS");
        assert_eq!(counting.0.load(Ordering::SeqCst), 1, "this thread's TGS");
        clear_thread_preauth();
        clear_thread_authdata();
        let _ = crate::issue_as(&store, &no_padata(23)).unwrap_err();
        crate::ad::handle_authdata(true, false, None, None, None, None, None, None)
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
        // MIT `enc_ts_verify` (`kdc/kdc_preauth_encts.c:94-101`): no replay cache, so the same timestamp verifies again.
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

    /// Clears this thread's kdcpolicy slot and named list.
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

/// Register MIT's kdcpolicy test module when `enable_only` names `test`.
///
/// A missing `enable_only` registers nothing, so a KDC with no stanza does not
/// deny a principal named `fail` or cap ticket lifetimes. A second call does
/// not register a second copy. `module` is not read.
pub fn register_kdcpolicy_test_if_selected(relations: &krb5_config::PluginRelations) {
    let Some(names) = relations.enable_only.as_ref() else {
        return;
    };
    if !names.iter().any(|name| name == "test") {
        return;
    }
    let already = NAMED_POLICIES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|module| module.name() == "test");
    if already {
        return;
    }
    register_kdcpolicy(std::sync::Arc::new(kdcpolicy_test::TestModule));
}
