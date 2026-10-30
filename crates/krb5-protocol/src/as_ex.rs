use crate::error::Error;
use crate::keytab::KeytabFailure;
use crate::preauth::{KdcTrust, pa_pk_as_req_signed_at, pkinit_reply_key_agile};
use crate::trace;
use crate::transport::{KdcAddr, SendKind, sendto_kdc};
use krb5_asn1::{decode, encode};
use krb5_config::Krb5Conf;
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, decrypt_enc_data, encrypt, krb_fx_cf2,
    parse_enctype_list, string_to_key,
};
use krb5_types::pkinit::{KxGroup, KxKey};
use krb5_types::{
    AsRep, AsReq, EncKdcRepPart, EncryptedData, EncryptionKey, EtypeInfo, EtypeInfo2, KdcOptions,
    KdcReq, KdcReqBody, KerberosTime, KrbError, MethodData, PaData, PrincipalName, TypedDataList,
    err, flag_bit, ku, pa,
};
use sha1::{Digest, Sha1};
use std::time::Instant;
use zeroize::{Zeroize, Zeroizing};

mod clock;
mod ec;
mod fast;
mod otp;
mod password;
mod responder;
mod spake;

use clock::Clock;
pub use fast::FastArmor;
pub(crate) use fast::fast_error_material;
pub use fast::set_service_restart;
use fast::{ask_gak_question, ask_responder, continue_fast};
pub use otp::{OtpChallengeView, OtpTokenView};
use password::{ModuleFail, PasswordCell};
pub use responder::{QUESTION_OTP, QUESTION_PASSWORD, Responder, ResponderItems};
use spake::{
    SpakeEnd, client_groups, continue_spake, refuse_spake_combo, refuse_spake_skip, spake_forced,
    trace_unknown_groups,
};

#[derive(Clone, Debug)]
pub struct AsOutcome {
    pub ticket: krb5_types::Ticket,
    pub enc_part: EncKdcRepPart,
    pub client_key: ProtocolKey,
    pub session_key: ProtocolKey,
    pub cname: PrincipalName,
    pub crealm: krb5_types::Realm,
    pub fast_avail: bool,
    pub used_fast: bool,
    pub pa_type: Option<i32>,
    pub pa_config: Option<Vec<u8>>,
    pub time_offset: i64,
}

#[derive(Clone)]
pub struct AsRequest<'a> {
    pub cname: PrincipalName,
    pub realm: &'a str,
    pub password: &'a [u8],
    pub kdc: &'a KdcAddr,
    pub profile: &'a Krb5Conf,
    pub want_spake: bool,
    pub fast_armor: Option<&'a FastArmor>,
    /// Empty PA-150 first; PA-16 on the retry.
    pub pkinit: Option<Pkinit<'a>>,
    pub canonicalize: bool,
    pub sname: Option<&'a PrincipalName>,
    pub etypes: Option<&'a [i32]>,
    pub ticket: AsTicketOpts,
}

#[derive(Clone, Debug)]
pub struct AsTicketOpts {
    // MIT: `krb5_init_creds_init` (get_in_tkt.c:936-947)
    pub lifetime: Option<u64>,
    pub rlife: Option<u64>,
    pub forwardable: bool,
    pub proxiable: bool,
    pub addresses: Option<krb5_types::HostAddresses>,
    /// Also unsigned PKINIT.
    pub anonymous: bool,
    pub starttime: Option<i64>,
    // MIT: `maybe_add_pac_request` (lib/krb5/krb/get_in_tkt.c:1243-1245)
    pub pac_request: Option<bool>,
    pub allowed_preauth_type: Option<i32>,
    pub pa_config_in: Option<Vec<u8>>,
    // MIT: `restart_init_creds_loop` (lib/krb5/krb/get_in_tkt.c:836-838)
    pub restart: Option<AsRestart>,
}

#[derive(Clone, Debug)]
struct AsReqTimes {
    till: KerberosTime,
    rtime: Option<KerberosTime>,
    from: Option<KerberosTime>,
    opts: KdcOptions,
}

/// FAST's outer body: the request as the last restart found it.
#[derive(Clone, Debug)]
pub struct AsRestart {
    nonce: u32,
    times: AsReqTimes,
}

#[expect(
    clippy::derivable_impls,
    reason = "MIT's library default is written out in full"
)]
impl Default for AsTicketOpts {
    fn default() -> Self {
        Self {
            lifetime: None,
            rlife: None,
            forwardable: false,
            proxiable: false,
            addresses: None,
            anonymous: false,
            starttime: None,
            pac_request: None,
            allowed_preauth_type: None,
            pa_config_in: None,
            restart: None,
        }
    }
}

impl AsTicketOpts {
    #[must_use]
    pub fn preauth_allowed(&self, pa_type: i32) -> bool {
        self.allowed_preauth_type.is_none_or(|t| t == pa_type)
    }
}

#[derive(Clone, Copy)]
pub enum Pkinit<'a> {
    Client(&'a PkinitClient),
    Failed(&'a PkinitFailure),
}

// MIT: `pkinit_client_process` (plugins/preauth/pkinit/pkinit_clnt.c:950-998)
/// No anchors, or the identity prompt failed.
#[derive(Clone, Debug)]
pub struct PkinitFailure {
    pub code: i64,
    pub text: String,
    pub no_identity: bool,
    pub prompted: bool,
}

pub struct PkinitClient {
    pub cert: Vec<u8>,
    pub key: krb5_types::pkinit::IdentityKey,
    pub anchors: Vec<Vec<u8>>,
    pub pool: Vec<Vec<u8>>,
    pub dh_min_bits: Option<String>,
    pub kdc_hostnames: Vec<String>,
    pub eku_checking: Option<String>,
}

impl PkinitClient {
    fn trust(&self) -> KdcTrust<'_> {
        let (require_eku, accept_secondary_eku) = match self.eku_checking.as_deref() {
            Some(v) if v.eq_ignore_ascii_case("kpServerAuth") => (true, true),
            Some(v) if v.eq_ignore_ascii_case("none") => (false, false),
            _ => (true, false),
        };
        KdcTrust {
            anchors: &self.anchors,
            pool: &self.pool,
            hostnames: &self.kdc_hostnames,
            require_eku,
            accept_secondary_eku,
        }
    }

    fn dh_size(&self) -> u32 {
        krb5_types::pkinit::parse_dh_min_bits(self.dh_min_bits.as_deref()).unwrap_or_else(|v| {
            trace::pkinit_dh_invalid_min_bits(&v);
            2048
        })
    }
}

impl Drop for PkinitClient {
    fn drop(&mut self) {
        self.key.zeroize();
        #[cfg(test)]
        if let krb5_types::pkinit::IdentityKey::P256(k) = &self.key {
            let _ = pkinit_client_drop_tests::DROPPED.try_with(|d| d.borrow_mut().push(**k));
        }
    }
}

#[cfg(test)]
mod pkinit_client_drop_tests;

pub fn as_exchange(req: &AsRequest<'_>) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], None, None, false)
}

pub fn as_exchange_with_keys(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
) -> Result<AsOutcome, Error> {
    wrap_as(req, keys, None, None, false)
}

pub fn as_exchange_key(
    profile: &Krb5Conf,
    cname: PrincipalName,
    realm: &str,
    keys: &[ProtocolKey],
    kdc: &KdcAddr,
) -> Result<AsOutcome, Error> {
    wrap_as(
        &AsRequest {
            cname,
            realm,
            password: b"",
            kdc,
            profile,
            want_spake: false,
            fast_armor: None,
            pkinit: None,
            canonicalize: false,
            sname: None,
            etypes: None,
            ticket: AsTicketOpts::default(),
        },
        keys,
        None,
        None,
        false,
    )
}

pub fn as_exchange_prompted(
    req: &AsRequest<'_>,
    prompt: &mut PasswordPrompt<'_>,
) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], None, Some(&mut || prompt()), false)
}

pub fn as_exchange_defer_fast(req: &AsRequest<'_>) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], None, None, true)
}

pub fn as_exchange_prompted_defer_fast(
    req: &AsRequest<'_>,
    prompt: &mut PasswordPrompt<'_>,
) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], None, Some(&mut || prompt()), true)
}

pub fn as_exchange_with_keys_defer_fast(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
) -> Result<AsOutcome, Error> {
    wrap_as(req, keys, None, None, true)
}

pub fn as_exchange_with_unreadable_keytab(
    req: &AsRequest<'_>,
    failure: &KeytabFailure,
) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], Some(failure), None, false)
}

pub fn as_exchange_with_unreadable_keytab_defer_fast(
    req: &AsRequest<'_>,
    failure: &KeytabFailure,
) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], Some(failure), None, true)
}

pub type PasswordPrompt<'p> = dyn FnMut() -> Result<Zeroizing<Vec<u8>>, Error> + 'p;

// MIT: `KRB5_PROMPT_TYPE_PASSWORD` (include/krb5/krb5.hin:7884-7884)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptType {
    Password = 1,
    NewPassword = 2,
    NewPasswordAgain = 3,
    Preauth = 4,
}

#[derive(Clone, Copy, Debug)]
pub struct PreauthPrompt<'a> {
    pub banner: Option<&'a str>,
    /// The prompter adds the colon.
    pub prompt: &'a str,
    pub hidden: bool,
    pub prompt_type: PromptType,
}

pub trait AsPrompt {
    fn password(&mut self) -> Result<Zeroizing<Vec<u8>>, Error>;

    fn preauth(&mut self, prompt: &PreauthPrompt<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
        let _ = prompt;
        Err(Error::File(std::io::Error::other("Cannot read password")))
    }

    fn responder(&mut self) -> Option<&mut dyn Responder> {
        None
    }
}

impl<F: FnMut() -> Result<Zeroizing<Vec<u8>>, Error>> AsPrompt for F {
    fn password(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self()
    }
}

pub fn as_exchange_interactive(
    req: &AsRequest<'_>,
    ui: &mut dyn AsPrompt,
    defer_fast: bool,
) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], None, Some(ui), defer_fast)
}

fn wrap_as(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    unreadable: Option<&KeytabFailure>,
    prompt: Option<&mut dyn AsPrompt>,
    defer_fast: bool,
) -> Result<AsOutcome, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(correlation_id.clone());
    let started = Instant::now();
    let result = as_exchange_inner(req, keys, unreadable, prompt, defer_fast);
    emit(
        krb5_log::events::PROTOCOL_AS,
        &correlation_id,
        started,
        result.as_ref().err(),
    );
    result
}

fn req_sname(req: &AsRequest<'_>) -> PrincipalName {
    req.sname
        .cloned()
        .unwrap_or_else(|| PrincipalName::krbtgt(req.realm))
}

// MIT: `restart_init_creds_loop` (get_in_tkt.c:807-813)
fn as_exchange_inner(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    unreadable: Option<&KeytabFailure>,
    prompt: Option<&mut dyn AsPrompt>,
    defer_fast: bool,
) -> Result<AsOutcome, Error> {
    let _ = krb5_types::try_ascii(req.realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?;
    refuse_spake_combo(req)?;
    trace_unknown_groups(req.profile);
    let etypes: Vec<i32> = match req.etypes {
        Some(e) if !e.is_empty() => e.to_vec(),
        _ => conf_etypes(req.profile, false),
    };
    let nonce = random_nonce()?;
    let clock = Clock::new(req.profile, restart_point(req));
    let bound = request_times(req, &clock, nonce);

    if req.fast_armor.is_some() {
        return continue_fast(
            req, keys, unreadable, nonce, &bound, &etypes, &clock, prompt,
        );
    }
    // MIT: `k5_init_preauth_context` (lib/krb5/krb/preauth2.c:133-146)
    // Anonymous has no mechanism after PKINIT.
    if crate::clpreauth::loaded(req.profile, "pkinit")
        && (matches!(req.pkinit, Some(Pkinit::Client(_))) || req.ticket.anonymous)
    {
        let hint = match continue_pkinit(req, nonce, &bound, &etypes, &clock, defer_fast)? {
            PkinitEnd::Decrypt {
                rep,
                wire,
                reply_key,
                learned,
                nonce,
                bound,
            } => {
                let mut pw = PasswordCell::new(
                    prompt,
                    req.password,
                    !keys.is_empty() || unreadable.is_some(),
                )
                .with_unreadable_keytab(unreadable);
                let (salt, params) = fallback_s2k(
                    rep.0.padata.as_deref(),
                    &etypes,
                    learned,
                    &rep.0.cname,
                    &rep.0.crealm,
                );
                let mut fallback = |et: EncryptionType| {
                    long_term_as_key(req, keys, &mut pw, et, &salt, params.as_deref())
                };
                return finish_as_rep(
                    req.profile,
                    *rep,
                    nonce,
                    Some(reply_key),
                    req.password,
                    &req.cname,
                    req.realm,
                    Some(pa::PK_AS_REQ),
                    req.canonicalize,
                    &req_sname(req),
                    &bound,
                    Some(&wire),
                    false,
                    Some(&mut fallback),
                );
            }
            PkinitEnd::Reply {
                rep,
                wire,
                traced,
                nonce,
                bound,
            } if !req.ticket.anonymous => {
                return finish_bare_reply(
                    req, keys, unreadable, prompt, *rep, nonce, &etypes, &bound, &wire, traced,
                );
            }
            PkinitEnd::Reply { .. } => {
                return Err(Error::ReplyMismatch("PKINIT expected METHOD-DATA".into()));
            }
            PkinitEnd::Walk(hint) => *hint,
        };
        if req.ticket.anonymous {
            return Err(preauth_failed());
        }
        let mut pw = PasswordCell::new(
            prompt,
            req.password,
            !keys.is_empty() || unreadable.is_some(),
        )
        .with_unreadable_keytab(unreadable);
        return continue_from_hint(req, keys, nonce, &etypes, &hint, &clock, &mut pw);
    }
    if req.ticket.anonymous {
        return Err(preauth_failed());
    }
    let first = build_as_req_from(req, nonce, &bound, None, &etypes)?;
    let wire = encode(&first)?;
    trace::init_creds_preauth_none();
    let msg = send_as(req, &wire, &etypes)?;
    let spake_more =
        |e: &KrbError| req.want_spake && e.error_code == err::MORE_PREAUTH_DATA_REQUIRED;
    // The offset is noted before the password is read.
    if let KdcMsg::Error(e) = &msg
        && retried(e)
        && e.error_code == err::PREAUTH_REQUIRED
    {
        clock.note(e, false);
    }
    // MIT: `k5_upgrade_to_fast_p` (lib/krb5/krb/fast.c:677-688)
    // PA-FX-FAST with no armor key yet restarts first.
    upgrade_to_fast(&msg, defer_fast, &clock)?;
    if let KdcMsg::Error(e) = &msg
        && e.error_code == err::PREAUTH_REQUIRED
        && !hint_offers_real_mechanism(req, e)
    {
        return Err(preauth_failed());
    }
    match msg {
        KdcMsg::AsRep(rep) => finish_bare_reply(
            req, keys, unreadable, prompt, rep, nonce, &etypes, &bound, &wire, false,
        ),
        KdcMsg::Error(e) if spake_more(&e) => {
            if !crate::clpreauth::loaded(req.profile, "spake") {
                return Err(preauth_failed());
            }
            if trace::enabled() {
                trace::init_creds_preauth();
                trace_preauth_input(&method_from_error(&e).unwrap_or_default(), &etypes);
            }
            let mut pw = PasswordCell::new(
                prompt,
                req.password,
                !keys.is_empty() || unreadable.is_some(),
            )
            .with_unreadable_keytab(unreadable);
            spake_forced(req, keys, nonce, &etypes, &e, &clock, &mut pw)
        }
        KdcMsg::Error(e) if e.error_code == err::PREAUTH_REQUIRED => {
            let mut pw = PasswordCell::new(
                prompt,
                req.password,
                !keys.is_empty() || unreadable.is_some(),
            )
            .with_unreadable_keytab(unreadable);
            continue_from_hint(req, keys, nonce, &etypes, &e, &clock, &mut pw)
        }
        KdcMsg::Error(e) => Err(kdc_error(req, &clock, &e)),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the AS round's state, no value type"
)]
fn finish_bare_reply(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    unreadable: Option<&KeytabFailure>,
    prompt: Option<&mut dyn AsPrompt>,
    rep: AsRep,
    nonce: u32,
    etypes: &[i32],
    bound: &AsReqTimes,
    wire: &[u8],
    traced: bool,
) -> Result<AsOutcome, Error> {
    refuse_spake_skip(req.want_spake)?;
    if !traced {
        reply_padata(rep.0.padata.as_deref(), etypes, None)?;
    }
    let mut pw = PasswordCell::new(
        prompt,
        req.password,
        !keys.is_empty() || unreadable.is_some(),
    )
    .with_unreadable_keytab(unreadable);
    finish_as_rep_keys(req, rep, nonce, keys, etypes, bound, Some(wire), &mut pw)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the AS round's state, no value type"
)]
fn finish_as_rep_keys(
    req: &AsRequest<'_>,
    rep: AsRep,
    nonce: u32,
    keys: &[ProtocolKey],
    etypes: &[i32],
    bound: &AsReqTimes,
    req_der: Option<&[u8]>,
    pw: &mut PasswordCell<'_, '_>,
) -> Result<AsOutcome, Error> {
    let (cname, realm) = (&req.cname, req.realm);
    let (canonicalize, expected_sname) = (req.canonicalize, &req_sname(req));
    let etype = EncryptionType::known(rep.0.enc_part.etype)?;
    if let Some(failure) = pw.unreadable_keytab() {
        trace_gak_salt(
            req,
            &rep.0.cname,
            &rep.0.crealm,
            rep.0.padata.as_deref(),
            etypes,
            true,
        );
        trace_keytab_gak(req, keys, Some(failure), etype);
        return Err(ModuleFail::keytab(failure).unwrapped());
    }
    if keys.is_empty() {
        trace_salt_princ(&rep.0.cname, &rep.0.crealm, rep.0.padata.as_deref(), etypes);
        ask_gak_question(pw)?;
        trace_gak(req, rep.0.padata.as_deref(), etypes, false);
        let password = pw.get().map_err(ModuleFail::unwrapped)?;
        let (salt, params) = fallback_s2k(
            rep.0.padata.as_deref(),
            etypes,
            None,
            &rep.0.cname,
            &rep.0.crealm,
        );
        let key = string_to_key(etype, &password, &salt, params.as_deref())?;
        trace::init_creds_as_key_gak((&key).into());
        return finish_as_rep(
            req.profile,
            rep,
            nonce,
            Some(key),
            &password,
            cname,
            realm,
            None,
            canonicalize,
            expected_sname,
            bound,
            req_der,
            false,
            None,
        );
    }
    let password = req.password;
    trace_gak_salt(
        req,
        &rep.0.cname,
        &rep.0.crealm,
        rep.0.padata.as_deref(),
        etypes,
        true,
    );
    trace_keytab_gak(req, keys, None, etype);
    let picked = pick_key(keys, Some(etype));
    if let Some(k) = &picked
        && gak_found(keys, k, etype)
    {
        trace::init_creds_as_key_gak(k.into());
    }
    let mut not_opened = None;
    let others = keys
        .iter()
        .filter(|k| picked.as_ref().is_none_or(|p| !same_key(p, k)));
    for k in picked.iter().chain(others) {
        match opens_as_reply(&rep, k) {
            Ok(()) => {
                return finish_as_rep(
                    req.profile,
                    rep,
                    nonce,
                    Some(k.clone()),
                    password,
                    cname,
                    realm,
                    None,
                    canonicalize,
                    expected_sname,
                    bound,
                    req_der,
                    false,
                    None,
                );
            }
            Err(e) => {
                not_opened.get_or_insert(e);
            }
        }
    }
    Err(not_opened.unwrap_or_else(|| Error::ReplyMismatch("no keytab key decrypted AS-REP".into())))
}

fn opens_as_reply(rep: &AsRep, key: &ProtocolKey) -> Result<(), Error> {
    let plain = as_rep_plain(key, &rep.0.enc_part)?;
    drop(Zeroizing::new(plain));
    Ok(())
}

// MIT: `decrypt_as_reply` (lib/krb5/krb/get_in_tkt.c:115-123)
fn long_term_as_key(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    pw: &mut PasswordCell<'_, '_>,
    etype: EncryptionType,
    salt: &[u8],
    params: Option<&[u8]>,
) -> Result<ProtocolKey, Error> {
    trace::init_creds_gak(salt, params.unwrap_or(&[]));
    if !keys.is_empty() || pw.unreadable_keytab().is_some() {
        trace_keytab_gak(req, keys, pw.unreadable_keytab(), etype);
        if let Some(failure) = pw.unreadable_keytab() {
            return Err(ModuleFail::keytab(failure).unwrapped());
        }
        let Some(key) = keys.iter().find(|k| k.etype() == etype).cloned() else {
            return Err(Error::Keytab {
                code: trace::KRB5_KT_NOTFOUND,
                text: "Key table entry not found".into(),
            });
        };
        trace::init_creds_as_key_gak((&key).into());
        return Ok(key);
    }
    let password = pw.get().map_err(ModuleFail::unwrapped)?;
    let key = string_to_key(etype, &password, salt, params)?;
    trace::init_creds_as_key_gak((&key).into());
    Ok(key)
}

fn as_rep_plain(key: &ProtocolKey, enc: &krb5_types::EncryptedData) -> Result<Vec<u8>, Error> {
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART)?;
    decrypt_enc_data(key, usage, enc.etype, enc.cipher.as_ref()).map_err(|e| match e {
        krb5_crypto::Error::Integrity => Error::ReplyIntegrity,
        other => other.into(),
    })
}

fn same_key(a: &ProtocolKey, b: &ProtocolKey) -> bool {
    a.etype() == b.etype() && a.as_bytes() == b.as_bytes()
}

fn gak_found(keys: &[ProtocolKey], key: &ProtocolKey, etype: EncryptionType) -> bool {
    keys.is_empty() || key.etype() == etype
}

fn pick_key(keys: &[ProtocolKey], etype: Option<EncryptionType>) -> Option<ProtocolKey> {
    if keys.is_empty() {
        return None;
    }
    if let Some(et) = etype
        && let Some(k) = keys.iter().find(|k| k.etype() == et)
    {
        return Some(k.clone());
    }
    keys.first().cloned()
}

// MIT: `sort_krb5_padata_sequence` (get_in_tkt.c:400-471)
/// PKINIT's four pa-types: MIT tries PKINIT first.
pub const DEFAULT_PREFERRED_PREAUTH_TYPES: &[i32] = &[17, 16, 15, 14];

#[must_use]
pub fn conf_preferred_preauth_types_for(profile: &Krb5Conf, realm: &str) -> Vec<i32> {
    match profile.preferred_preauth_for(realm) {
        Some(list) => list.to_vec(),
        None => DEFAULT_PREFERRED_PREAUTH_TYPES.to_vec(),
    }
}

#[must_use]
pub fn sort_krb5_padata_sequence(padata: &[PaData], preferred: &[i32]) -> Vec<PaData> {
    let mut out = padata.to_vec();
    let mut base = 0;
    for &want in preferred {
        if let Some(i) = out[base..].iter().position(|p| p.padata_type == want) {
            let i = base + i;
            let tmp = out.remove(i);
            out.insert(base, tmp);
            base += 1;
        }
    }
    out
}

fn continue_from_hint(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    etypes: &[i32],
    err: &KrbError,
    clock: &Clock,
    pw: &mut PasswordCell<'_, '_>,
) -> Result<AsOutcome, Error> {
    if req.want_spake {
        if !crate::clpreauth::loaded(req.profile, "spake") {
            return Err(preauth_failed());
        }
        if trace::enabled() {
            trace::init_creds_preauth();
            trace_preauth_input(
                &sort_krb5_padata_sequence(
                    &method_from_error(err).unwrap_or_default(),
                    &conf_preferred_preauth_types_for(req.profile, req.realm),
                ),
                etypes,
            );
        }
        return spake_forced(req, keys, nonce, etypes, err, clock, pw);
    }
    let preferred = conf_preferred_preauth_types_for(req.profile, req.realm);
    // MIT: `spake_init` (spake_client.c:62-73)
    // No permitted group means no SPAKE module.
    let groups = client_groups(req.profile);
    // MIT: `k5_preauth_note_failed` (lib/krb5/krb/preauth2.c:208-221)
    let mut failed: Vec<i32> = Vec::new();
    if !crate::clpreauth::loaded(req.profile, "spake") {
        failed.push(pa::SPAKE);
    }
    let mut first_failure: Option<Error> = None;
    let mut refused: Option<KrbError> = None;
    let mut prepared = false;
    let mut hint = err.clone();
    loop {
        let method = method_from_error(&hint)?;
        let sorted = sort_krb5_padata_sequence(&method, &preferred);
        trace::init_creds_preauth();
        trace_preauth_input(&sorted, etypes);
        check_etype_info(&sorted, etypes)?;
        let allowed = allowed_padata(req, &sorted);
        pkinit_prepare(req, &allowed, &mut prepared);
        ask_responder(req, pw, None, &allowed)?;
        'walk: loop {
            let next = sorted.iter().find_map(|p| {
                if !req.ticket.preauth_allowed(p.padata_type) {
                    return None;
                }
                unarmored_mech(req, p.padata_type, &failed)
            });
            match next {
                Some(Unarmored::Pkinit(f)) => {
                    let fail = pkinit_fails(f);
                    failed.push(pa::PK_AS_REQ);
                    first_failure.get_or_insert(fail.error);
                }
                Some(Unarmored::Spake) => {
                    match continue_spake(req, keys, nonce, etypes, &hint, &groups, clock, pw)? {
                        SpakeEnd::Done(out) => return Ok(*out),
                        SpakeEnd::Fallback {
                            hint: next_err,
                            fail,
                            refusal,
                            new_walk,
                        } => {
                            failed.push(pa::SPAKE);
                            if let Some(f) = fail {
                                first_failure.get_or_insert(f.error);
                            }
                            if let Some(e) = refusal {
                                refused = Some(*e);
                            }
                            hint = *next_err;
                            if new_walk {
                                break 'walk;
                            }
                        }
                    }
                }
                Some(Unarmored::Encts) => {
                    match continue_preauth(req, keys, nonce, etypes, &hint, clock, pw)? {
                        Ok(out) => return Ok(out),
                        Err(f) => {
                            f.trace(ENCTS_MODULE, pa::ENC_TIMESTAMP);
                            if f.interrupted {
                                return Err(f.error);
                            }
                            failed.push(pa::ENC_TIMESTAMP);
                            first_failure.get_or_insert(f.error);
                        }
                    }
                }
                Some(Unarmored::Embedder(module, pa_type)) => {
                    return continue_embedder(
                        req,
                        keys,
                        nonce,
                        etypes,
                        &hint,
                        clock,
                        module.as_ref(),
                        pa_type,
                        pw,
                    );
                }
                None => {
                    return Err(match (refused, first_failure) {
                        (Some(e), _) => kdc_error(req, clock, &e),
                        (None, Some(first)) => Error::PreauthFailed(Box::new(first)),
                        (None, None) => preauth_failed(),
                    });
                }
            }
        }
    }
}

enum Unarmored<'a> {
    Pkinit(&'a PkinitFailure),
    Spake,
    Encts,
    Embedder(std::sync::Arc<dyn crate::clpreauth::ClPreauth>, i32),
}

// MIT: `process_pa_data` (lib/krb5/krb/preauth2.c:669-674)
/// Encrypted challenge runs only under armor.
fn unarmored_mech<'a>(req: &AsRequest<'a>, pa_type: i32, failed: &[i32]) -> Option<Unarmored<'a>> {
    if failed.contains(&pa_type) {
        return None;
    }
    match crate::clpreauth::owner_of(req.profile, pa_type) {
        Some(crate::clpreauth::Owner::Pkinit) => match req.pkinit {
            Some(Pkinit::Failed(f)) => Some(Unarmored::Pkinit(f)),
            _ => None,
        },
        Some(crate::clpreauth::Owner::Spake) => Some(Unarmored::Spake),
        Some(crate::clpreauth::Owner::EncTs) => Some(Unarmored::Encts),
        Some(crate::clpreauth::Owner::Embedder(module)) if module.real(pa_type) => {
            Some(Unarmored::Embedder(module, pa_type))
        }
        _ => None,
    }
}

fn continue_preauth(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    etypes: &[i32],
    preauth_err: &KrbError,
    clock: &Clock,
    pw: &mut PasswordCell<'_, '_>,
) -> Result<Result<AsOutcome, ModuleFail>, Error> {
    if let Ok(method) = method_from_error(preauth_err)
        && !method.iter().any(|p| p.padata_type == pa::ENC_TIMESTAMP)
    {
        return Err(preauth_failed());
    }
    if encrypted_timestamp_disabled(req.profile, req.realm) {
        return Ok(Err(ModuleFail::encts_disabled()));
    }
    let (etype, salt, params) =
        select_s2k(preauth_err, &salt_cname(&req.cname), req.realm, etypes)?;
    trace_keytab_gak(req, keys, pw.unreadable_keytab(), etype);
    let client_key = match pick_key(keys, Some(etype)) {
        Some(key) => key,
        None => match pw.get() {
            Ok(password) => match string_to_key(etype, &password, &salt, params.as_deref()) {
                Err(krb5_crypto::Error::BadS2kParams) => {
                    return Ok(Err(ModuleFail::key_refused(Error::BadS2kParams)));
                }
                key => key?,
            },
            Err(f) => return Ok(Err(f)),
        },
    };
    if gak_found(keys, &client_key, etype) {
        trace::preauth_enc_ts_key_gak((&client_key).into());
    }
    let mut padata = error_cookie(preauth_err);
    match pa_enc_timestamp_at(&client_key, clock.now(true), false) {
        Ok(p) => padata.push(p),
        Err(e @ (Error::DesBadParity | Error::DesWeakKey)) => {
            return Ok(Err(ModuleFail::key_refused(e)));
        }
        Err(e) => return Err(e),
    }
    trace::preauth_process(ENCTS_MODULE, pa::ENC_TIMESTAMP, true, 0, None);
    trace::preauth_output(&padata);
    let bound = request_times(req, clock, nonce);
    let second = build_as_req_from(req, nonce, &bound, Some(padata), etypes)?;
    let wire = encode(&second)?;
    let mut finish =
        |rep: AsRep, wire: &[u8], etypes: &[i32], client_key: ProtocolKey, bound: &AsReqTimes| {
            reply_padata(rep.0.padata.as_deref(), etypes, None)?;
            trace::init_creds_as_key_preauth((&client_key).into());
            let (fsalt, fparams) = fallback_s2k(
                rep.0.padata.as_deref(),
                etypes,
                learned_s2k(preauth_err, &salt_cname(&req.cname), req.realm, etypes),
                &rep.0.cname,
                &rep.0.crealm,
            );
            let mut fallback = |et: EncryptionType| {
                long_term_as_key(req, keys, pw, et, &fsalt, fparams.as_deref())
            };
            finish_as_rep(
                req.profile,
                rep,
                nonce,
                Some(client_key),
                req.password,
                &req.cname,
                req.realm,
                Some(pa::ENC_TIMESTAMP),
                req.canonicalize,
                &req_sname(req),
                bound,
                Some(wire),
                false,
                Some(&mut fallback),
            )
        };
    match send_as(req, &wire, etypes)? {
        KdcMsg::AsRep(rep) => finish(rep, &wire, etypes, client_key, &bound),
        KdcMsg::Error(e) => {
            encts_tryagain(&e);
            Err(kdc_error(req, clock, &e))
        }
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
    .map(Ok)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the AS round's state, no value type"
)]
fn continue_embedder(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    etypes: &[i32],
    preauth_err: &KrbError,
    clock: &Clock,
    module: &dyn crate::clpreauth::ClPreauth,
    pa_type: i32,
    pw: &mut PasswordCell<'_, '_>,
) -> Result<AsOutcome, Error> {
    let method = method_from_error(preauth_err)?;
    let Some(input) = find_pa(&method, pa_type) else {
        return Err(preauth_failed());
    };
    let produced = module.process(input)?;
    let Some(produced) = produced else {
        return Err(preauth_failed());
    };
    trace::preauth_process(module.name(), pa_type, true, 0, None);
    let mut padata = error_cookie(preauth_err);
    padata.extend(produced);
    trace::preauth_output(&padata);
    let bound = request_times(req, clock, nonce);
    let second = build_as_req_from(req, nonce, &bound, Some(padata), etypes)?;
    let wire = encode(&second)?;
    match send_as(req, &wire, etypes)? {
        KdcMsg::AsRep(rep) => {
            finish_as_rep_keys(req, rep, nonce, keys, etypes, &bound, Some(&wire), pw)
        }
        KdcMsg::Error(e) => Err(kdc_error(req, clock, &e)),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

fn preauth_failed() -> Error {
    Error::preauth_no_mech()
}

pub(super) fn allowed_padata(req: &AsRequest<'_>, method: &[PaData]) -> Vec<PaData> {
    method
        .iter()
        .filter(|p| req.ticket.preauth_allowed(p.padata_type))
        .cloned()
        .collect()
}

fn hint_offers_real_mechanism(req: &AsRequest<'_>, err: &KrbError) -> bool {
    if req.want_spake || !retried(err) {
        return true;
    }
    let Ok(method) = method_from_error(err) else {
        return true;
    };
    if method.is_empty() {
        return true;
    }
    method.iter().any(|p| {
        req.ticket.preauth_allowed(p.padata_type)
            && unarmored_mech(req, p.padata_type, &[]).is_some()
    })
}

// MIT: `krb5int_fast_process_error` (lib/krb5/krb/fast.c:494-497)
/// Without FAST, only e-data is retried.
fn retried(e: &KrbError) -> bool {
    e.e_data.as_ref().is_some_and(|d| !d.as_ref().is_empty())
}

// MIT: `k5_preauth_tryagain` (lib/krb5/krb/preauth2.c:905-922)
fn encts_tryagain(e: &KrbError) {
    let handled = matches!(
        e.error_code,
        err::PREAUTH_REQUIRED | err::PREAUTH_FAILED | err::MORE_PREAUTH_DATA_REQUIRED
    );
    if handled || !retried(e) || !trace::enabled() {
        return;
    }
    trace_tryagain_input(e, pa::ENC_TIMESTAMP);
    trace::preauth_tryagain(ENCTS_MODULE, pa::ENC_TIMESTAMP, 0, None);
}

const ENCTS_MODULE: &str = "encrypted_timestamp";

const PKINIT_MODULE: &str = "pkinit";
const MAX_IN_TKT_LOOPS: usize = 16;

// MIT: `pkinit_client_prep_questions` (plugins/preauth/pkinit/pkinit_clnt.c:766-783)
fn pkinit_prepare(req: &AsRequest<'_>, method: &[PaData], prepared: &mut bool) {
    if *prepared
        || !method.iter().any(|p| p.padata_type == pa::PK_AS_REQ)
        || !matches!(
            crate::clpreauth::owner_of(req.profile, pa::PK_AS_REQ),
            Some(crate::clpreauth::Owner::Pkinit)
        )
    {
        return;
    }
    *prepared = true;
    if let Some(Pkinit::Failed(f)) = req.pkinit
        && f.no_identity
    {
        trace::pkinit_client_no_identity();
    }
}

fn pkinit_fails(f: &PkinitFailure) -> ModuleFail {
    if f.prompted {
        trace::pkinit_client_no_identity();
    }
    let fail = ModuleFail::new(f.code, &f.text);
    fail.trace(PKINIT_MODULE, pa::PK_AS_REQ);
    fail
}

fn trace_tryagain_input(e: &KrbError, pa_type: i32) {
    if !trace::enabled() {
        return;
    }
    trace::init_creds_preauth_tryagain(e.error_code, pa_type);
    trace::preauth_tryagain_input(pa_type, &error_padata(e));
}

fn error_padata(e: &KrbError) -> Vec<PaData> {
    let Some(ed) = &e.e_data else {
        return Vec::new();
    };
    decode::<MethodData>(ed.as_ref())
        .or_else(|_| {
            decode::<TypedDataList>(ed.as_ref()).map(|td| {
                td.into_iter()
                    .map(|t| PaData {
                        padata_type: t.data_type,
                        padata_value: t.data_value,
                    })
                    .collect()
            })
        })
        .unwrap_or_default()
}

pub fn insert_module_padata_before_info_pa(list: &mut Vec<PaData>, module_pa: PaData) {
    let at = list
        .iter()
        .position(|p| p.padata_type == pa::AS_FRESHNESS || p.padata_type == pa::REQ_ENC_PA_REP)
        .unwrap_or(list.len());
    list.insert(at, module_pa);
}

// MIT: `pkinit_as_req_create` (pkinit_clnt.c:194-195)
// MIT: `pa_pkinit_gen_req` (plugins/preauth/pkinit/pkinit_clnt.c:125-136)
fn continue_pkinit(
    req: &AsRequest<'_>,
    nonce: u32,
    bound: &AsReqTimes,
    etypes: &[i32],
    clock: &Clock,
    defer_fast: bool,
) -> Result<PkinitEnd, Error> {
    let pk = match req.pkinit {
        Some(Pkinit::Client(pk)) => Some(pk),
        Some(Pkinit::Failed(_)) if req.ticket.anonymous => None,
        _ => return Err(Error::ReplyMismatch("PKINIT identity missing".into())),
    };
    let first = build_as_req_from(req, nonce, bound, None, etypes)?;
    let first_wire = encode(&first)?;
    trace::init_creds_preauth_none();
    let msg = send_as(req, &first_wire, etypes)?;
    upgrade_to_fast(&msg, defer_fast, clock)?;
    let (token, cookie, learned) = match msg {
        KdcMsg::Error(e)
            if e.error_code == err::PREAUTH_REQUIRED || e.error_code == err::PREAUTH_FAILED =>
        {
            if retried(&e) {
                clock.note(&e, false);
            }
            let learned = learned_s2k(&e, &salt_cname(&req.cname), req.realm, etypes);
            let method = method_from_error(&e)?;
            if !method.iter().any(|p| p.padata_type == pa::PK_AS_REQ) {
                return Ok(PkinitEnd::Walk(Box::new(e)));
            }
            if trace::enabled() {
                trace::init_creds_preauth();
                trace_preauth_input(
                    &sort_krb5_padata_sequence(
                        &method,
                        &conf_preferred_preauth_types_for(req.profile, req.realm),
                    ),
                    etypes,
                );
            }
            check_etype_info(&method, etypes)?;
            let token = find_pa(&method, pa::AS_FRESHNESS)
                .map(|p| p.padata_value.as_ref())
                .filter(|v| !v.is_empty())
                .map(<[u8]>::to_vec);
            let cookie = find_pa(&method, pa::FX_COOKIE).cloned();
            (token, cookie, learned)
        }
        KdcMsg::Error(e) => return Err(kdc_error(req, clock, &e)),
        KdcMsg::AsRep(rep) => {
            return Ok(PkinitEnd::Reply {
                rep: Box::new(rep),
                wire: first_wire,
                traced: false,
                nonce,
                bound: bound.clone(),
            });
        }
        KdcMsg::TgsRep => return Err(Error::UnexpectedPdu),
    };
    // MIT: `process_pa_data` (preauth2.c:684-712)
    let Some(pk) = pk else {
        let Some(Pkinit::Failed(f)) = req.pkinit else {
            return Err(Error::ReplyMismatch("PKINIT identity missing".into()));
        };
        return Err(Error::PreauthFailed(Box::new(pkinit_fails(f).error)));
    };
    let mut dh_size = pk.dh_size();
    let mut tryagain: Option<Retry> = None;
    for _ in 1..MAX_IN_TKT_LOOPS {
        let group = KxGroup::for_bits(dh_size).unwrap_or(KxGroup::Modp2048);
        // MIT: `init_creds_step_request` (lib/krb5/krb/get_in_tkt.c:1273-1281)
        let nonce = random_nonce()?;
        let bound = request_times(req, clock, nonce);
        let extra = match &tryagain {
            None => cookie.iter().cloned().collect(),
            Some(_) => Vec::new(),
        };
        let mut req2 = build_as_req_from(req, nonce, &bound, Some(extra), etypes)?;
        trace::pkinit_dh_proposing_group(group.desc());
        let kp =
            KxKey::generate(group).ok_or_else(|| Error::Crypto("PKINIT key exchange".into()))?;
        let pa = pkinit_padata(
            req,
            pk,
            &kp,
            nonce,
            &req2.0.req_body,
            token.as_deref(),
            clock,
        )?;
        let list = req2.0.padata.get_or_insert_with(Vec::new);
        insert_module_padata_before_info_pa(list, pa);
        if let Some(Retry(Some(c))) = &tryagain {
            insert_module_padata_before_info_pa(list, c.clone());
        }
        if trace::enabled() {
            let produced: Vec<PaData> = list
                .iter()
                .filter(|p| p.padata_type == pa::FX_COOKIE || p.padata_type == pa::PK_AS_REQ)
                .cloned()
                .collect();
            if tryagain.is_some() {
                trace::preauth_tryagain(PKINIT_MODULE, pa::PK_AS_REQ, 0, None);
                trace::preauth_tryagain_output(&produced);
            } else {
                trace::preauth_process(PKINIT_MODULE, pa::PK_AS_REQ, true, 0, None);
                trace::preauth_output(&produced);
            }
        }
        let wire = encode(&req2)?;
        tracing::debug!(
            event = krb5_log::events::CLIENT_PKINIT,
            component = "krb5-protocol",
            outcome = "ok",
            pa_type = pa::PK_AS_REQ,
            freshness = token.is_some(),
        );
        match send_as(req, &wire, etypes)? {
            KdcMsg::AsRep(rep) => {
                let etype = EncryptionType::known(rep.0.enc_part.etype)?;
                let padata = rep.0.padata.as_deref().unwrap_or_default();
                trace_preauth_input(padata, etypes);
                check_etype_info(padata, etypes)?;
                let reply_key = match pkinit_reply_key_agile(
                    &kp,
                    &rep.0.padata,
                    etype,
                    pk.trust(),
                    &wire,
                    &req.cname,
                    req.realm,
                ) {
                    Ok(key) => key,
                    Err(Error::PkinitReply { code, text }) => {
                        ModuleFail::new(code, &text).trace(PKINIT_MODULE, pa::PK_AS_REP);
                        trace::preauth_output(&[]);
                        return Ok(PkinitEnd::Reply {
                            rep: Box::new(rep),
                            wire,
                            traced: true,
                            nonce,
                            bound,
                        });
                    }
                    Err(e) => return Err(e),
                };
                if padata.iter().any(|p| p.padata_type == pa::PK_AS_REP) {
                    trace::preauth_process(PKINIT_MODULE, pa::PK_AS_REP, true, 0, None);
                }
                trace::preauth_output(&[]);
                trace::init_creds_as_key_preauth((&reply_key).into());
                return Ok(PkinitEnd::Decrypt {
                    rep: Box::new(rep),
                    wire,
                    reply_key,
                    learned,
                    nonce,
                    bound,
                });
            }
            KdcMsg::Error(e) => {
                tryagain = Some(pkinit_refused(req, clock, &e, &mut dh_size)?);
            }
            KdcMsg::TgsRep => return Err(Error::UnexpectedPdu),
        }
    }
    Err(Error::Message(
        "Looping detected inside krb5_get_in_tkt".into(),
    ))
}

fn pkinit_padata(
    req: &AsRequest<'_>,
    pk: &PkinitClient,
    kp: &KxKey,
    nonce: u32,
    body: &KdcReqBody,
    token: Option<&[u8]>,
    clock: &Clock,
) -> Result<PaData, Error> {
    let sha1 = Sha1::digest(encode(body)?);
    let now = clock.now(true);
    if req.ticket.anonymous || krb5_types::pkinit::is_anonymous_principal(&req.cname) {
        crate::preauth::pa_pk_as_req_unsigned_at(&kp.spki(), nonce, &sha1, token, now)
    } else {
        pa_pk_as_req_signed_at(&kp.spki(), &pk.cert, &pk.key, nonce, &sha1, token, now)
    }
}

enum PkinitEnd {
    Decrypt {
        rep: Box<AsRep>,
        wire: Vec<u8>,
        reply_key: ProtocolKey,
        learned: Option<LearnedSalt>,
        nonce: u32,
        bound: AsReqTimes,
    },
    Walk(Box<KrbError>),
    Reply {
        rep: Box<AsRep>,
        wire: Vec<u8>,
        traced: bool,
        nonce: u32,
        bound: AsReqTimes,
    },
}

pub(crate) struct Retry(Option<PaData>);

// MIT: `pa_pkinit_gen_req` (pkinit_clnt.c:160-162)
// Sending the PK-AS-REQ disables fallback.
// MIT: `init_creds_step_request` (get_in_tkt.c:1315-1336)
// PREAUTH_FAILED, or a refusal tryagain does not answer, ends it.
fn pkinit_refused(
    req: &AsRequest<'_>,
    clock: &Clock,
    e: &KrbError,
    dh_size: &mut u32,
) -> Result<Retry, Error> {
    let handled = matches!(
        e.error_code,
        err::PREAUTH_REQUIRED | err::MORE_PREAUTH_DATA_REQUIRED | err::PREAUTH_FAILED
    );
    if retried(e)
        && !handled
        && let Some(retry) = pkinit_tryagain(e, dh_size)
    {
        return Ok(retry);
    }
    Err(kdc_error(req, clock, e))
}

fn pkinit_tryagain(e: &KrbError, dh_size: &mut u32) -> Option<Retry> {
    trace_tryagain_input(e, pa::PK_AS_REQ);
    let padata = error_padata(e);
    let group = padata
        .iter()
        .filter(|p| p.padata_type == pa::TD_DH_PARAMETERS)
        .find_map(|p| krb5_types::pkinit::choose_td_group(p.padata_value.as_ref(), *dh_size)?);
    let Some(group) = group else {
        trace::preauth_tryagain(PKINIT_MODULE, pa::PK_AS_REQ, 0, None);
        return None;
    };
    trace::pkinit_dh_negotiated_group(group.desc());
    trace::pkinit_client_tryagain();
    *dh_size = group.bits();
    Some(Retry(
        padata.into_iter().find(|p| p.padata_type == pa::FX_COOKIE),
    ))
}

fn upgrade_to_fast(msg: &KdcMsg, defer_fast: bool, clock: &Clock) -> Result<(), Error> {
    let KdcMsg::Error(e) = msg else {
        return Ok(());
    };
    if defer_fast
        && method_from_error(e).is_ok_and(|m| m.iter().any(|p| p.padata_type == pa::FX_FAST))
    {
        trace::fast_padata_upgrade();
        return Err(Error::FastUpgrade(Box::new(clock.restart())));
    }
    Ok(())
}

// MIT: `encts_disabled` (lib/krb5/krb/get_in_tkt.c:757-772)
fn encrypted_timestamp_disabled(profile: &Krb5Conf, realm: &str) -> bool {
    profile.encrypted_timestamp_disabled(realm)
}

fn method_from_error(err: &KrbError) -> Result<MethodData, Error> {
    let Some(ed) = &err.e_data else {
        return Ok(Vec::new());
    };
    decode(ed.as_ref()).map_err(Error::from)
}

fn find_pa(method: &[PaData], ty: i32) -> Option<&PaData> {
    method.iter().find(|p| p.padata_type == ty)
}

// MIT: `copy_cookie` (preauth2.c:857-884)
fn error_cookie(e: &KrbError) -> Vec<PaData> {
    method_from_error(e)
        .ok()
        .and_then(|m| find_pa(&m, pa::FX_COOKIE).cloned())
        .into_iter()
        .collect()
}

// MIT: `init_creds_step_reply` (lib/krb5/krb/get_in_tkt.c:1688-1766)
fn kdc_error(req: &AsRequest<'_>, clock: &Clock, e: &KrbError) -> Error {
    let canon = req.canonicalize || req.cname.name_type == PrincipalName::NT_ENTERPRISE;
    if canon && let Some(realm) = referral_realm(e, req.realm) {
        trace::init_creds_referral(realm.as_bytes());
        return Error::ClientReferral {
            code: e.error_code,
            realm,
            restart: Box::new(clock.restart()),
        };
    }
    match e.error_code {
        err::SKEW => Error::KrbError {
            code: err::SKEW,
            text: Some("clock skew; resync local clock and retry".into()),
        },
        err::ETYPE_NOSUPP => Error::KrbError {
            code: err::ETYPE_NOSUPP,
            text: Some("no common etype".into()),
        },
        _ => krb_err(e),
    }
}

// MIT: `is_referral` (lib/krb5/krb/get_in_tkt.c:1450-1458)
fn referral_realm(e: &KrbError, realm: &str) -> Option<String> {
    let crealm = e.crealm.as_ref()?;
    ((e.error_code == err::WRONG_REALM || e.error_code == err::C_PRINCIPAL_UNKNOWN)
        && e.cname.is_some()
        && crealm.as_bytes() != realm.as_bytes())
    .then(|| String::from_utf8_lossy(crealm.as_bytes()).into_owned())
}

enum KdcMsg {
    AsRep(AsRep),
    TgsRep,
    Error(KrbError),
}

fn classify(bytes: &[u8]) -> Result<KdcMsg, Error> {
    if bytes.is_empty() {
        return Err(Error::TruncatedReply);
    }
    match bytes[0] {
        0x6b => Ok(KdcMsg::AsRep(decode(bytes)?)),
        0x6d => {
            let _: krb5_types::TgsRep = decode(bytes)?;
            Ok(KdcMsg::TgsRep)
        }
        0x7e => Ok(KdcMsg::Error(decode(bytes)?)),
        _ => Err(Error::UnexpectedPdu),
    }
}

fn krb_err(e: &KrbError) -> Error {
    let text = e
        .e_text
        .as_ref()
        .and_then(|s| std::str::from_utf8(s.as_bytes()).ok())
        .map(str::to_owned);
    tracing::error!(
        event = krb5_log::events::PROTOCOL_KRB_ERROR,
        component = "krb5-protocol",
        outcome = "error",
        error_code = e.error_code,
        error = text.as_deref().unwrap_or(""),
    );
    Error::KrbError {
        code: e.error_code,
        text,
    }
}

// MIT: `warn_deprecated` (lib/krb5/krb/get_in_tkt.c:1584-1607)
#[must_use]
pub fn deprecated_enctype_warning(out: &AsOutcome) -> Option<String> {
    let reply = out.client_key.etype();
    let session = out.session_key.etype();
    let etype = if reply.is_deprecated() {
        reply
    } else if session.is_deprecated() {
        session
    } else {
        return None;
    };
    Some(format!(
        "Warning: encryption type {} used for authentication is deprecated and will be disabled",
        etype.to_mit_name()
    ))
}

pub fn warn_deprecated_enctype(out: &AsOutcome) {
    if let Some(banner) = deprecated_enctype_warning(out) {
        println!("{banner}");
    }
}

// MIT: `krb5int_fast_verify_nego` (fast.c:648-664)
#[expect(clippy::too_many_arguments, reason = "client AS, not a params struct")]
fn finish_as_rep(
    profile: &Krb5Conf,
    rep: AsRep,
    nonce: u32,
    client_key: Option<ProtocolKey>,
    password: &[u8],
    cname: &PrincipalName,
    realm: &str,
    pa_type: Option<i32>,
    canonicalize: bool,
    expected_sname: &PrincipalName,
    bound: &AsReqTimes,
    req_der: Option<&[u8]>,
    used_fast: bool,
    mut fallback: Option<&mut dyn FnMut(EncryptionType) -> Result<ProtocolKey, Error>>,
) -> Result<AsOutcome, Error> {
    let inner = rep.0;
    let had_preauth = pa_type.is_some();
    let etype = EncryptionType::known(inner.enc_part.etype)?;
    let mut key = if let Some(k) = client_key {
        k
    } else {
        let salt = salt_cname(cname).default_salt(realm);
        string_to_key(etype, password, &salt, None)?
    };
    // MIT: `decrypt_as_reply` (lib/krb5/krb/get_in_tkt.c:61-89)
    let plain = Zeroizing::new(match as_rep_plain(&key, &inner.enc_part) {
        Ok(plain) => plain,
        Err(e) if had_preauth => {
            let Some(fallback) = fallback.as_mut() else {
                return Err(e);
            };
            trace::init_creds_preauth_decrypt_fail(trace::kdc_code(krb5_types::err::BAD_INTEGRITY));
            key = fallback(etype)?;
            as_rep_plain(&key, &inner.enc_part)?
        }
        Err(e) => return Err(e),
    });
    let enc_part = decode_enc_as(&plain)?;
    trace::init_creds_decrypted_reply((&enc_part.key).into());
    if enc_part.nonce != nonce {
        return Err(Error::NonceMismatch);
    }
    if let Some(rd) = req_der {
        let verified = crate::preauth::verify_req_enc_pa_rep(&enc_part, &key, rd);
        if trace::enabled() {
            trace::fast_nego(verified.is_ok() && fast_avail_in(&enc_part));
        }
        verified?;
    } else if trace::enabled() {
        trace::fast_nego(fast_avail_in(&enc_part));
    }
    let expect_anon = krb5_types::pkinit::is_anonymous_principal(cname);
    if inner.cname != *cname {
        let enterprise = cname.name_type == PrincipalName::NT_ENTERPRISE;
        let anon_ok = expect_anon && krb5_types::pkinit::is_anonymous_principal(&inner.cname);
        if !anon_ok && (!(canonicalize || enterprise) || inner.cname.name_string.is_empty()) {
            return Err(Error::ReplyMismatch("AS-REP cname mismatch".into()));
        }
    }
    if inner.crealm.as_bytes() != realm.as_bytes() {
        let anon_realm = expect_anon
            && inner.crealm.as_bytes() == krb5_types::pkinit::ANONYMOUS_REALM.as_bytes();
        if !anon_realm {
            return Err(Error::ReplyMismatch("AS-REP crealm mismatch".into()));
        }
    }
    let canon_req = canonicalize || cname.name_type == PrincipalName::NT_ENTERPRISE || expect_anon;
    verify_as_reply_server(
        &enc_part.sname,
        &enc_part.srealm,
        &inner.ticket.sname,
        &inner.ticket.realm,
        expected_sname,
        realm,
        canon_req,
    )?;
    if inner.enc_part.etype != key.etype().to_iana() && inner.enc_part.etype != enc_part.key.keytype
    {
        return Err(Error::ReplyMismatch("AS-REP etype mismatch".into()));
    }
    if !enc_part.flags.initial() || !enc_part.flags.pre_authent() {
        // A service-ticket AS may omit INITIAL.
        if had_preauth && !enc_part.flags.pre_authent() {
            return Err(Error::ReplyMismatch("AS-REP missing PRE-AUTHENT".into()));
        }
    }
    let now = i64::from(KerberosTime::now().unix_seconds());
    let skew = i64::from(profile.clockskew);
    check_as_rep_times(
        &enc_part,
        now,
        skew,
        profile.kdc_timesync,
        bound.from.as_ref(),
    )?;
    verify_as_reply_req_times(
        &enc_part,
        &bound.till,
        bound.rtime.as_ref(),
        bound.from.as_ref(),
        &bound.opts,
    )?;
    if expect_anon {
        verify_anonymous(inner.padata.as_deref(), &key, &enc_part)?;
    }
    let session_etype = EncryptionType::known(enc_part.key.keytype)?;
    let session_key = ProtocolKey::from_bytes(session_etype, enc_part.key.keyvalue.as_ref())?;
    let fast_avail = fast_avail_in(&enc_part);
    // MIT: `verify_as_reply` (lib/krb5/krb/get_in_tkt.c:260-262)
    let time_offset = if profile.kdc_timesync {
        i64::from(enc_part.authtime.unix_seconds()) - now
    } else {
        0
    };
    Ok(AsOutcome {
        ticket: inner.ticket,
        enc_part,
        client_key: key,
        session_key,
        cname: inner.cname,
        crealm: inner.crealm,
        fast_avail,
        used_fast,
        pa_type,
        pa_config: None,
        time_offset,
    })
}

fn fast_avail_in(enc_part: &EncKdcRepPart) -> bool {
    enc_part.flags.enc_pa_rep()
        && enc_part
            .encrypted_pa_data
            .as_ref()
            .is_some_and(|v| v.iter().any(|p| p.padata_type == pa::FX_FAST))
}

fn verify_anonymous(
    padata: Option<&[PaData]>,
    as_key: &ProtocolKey,
    enc_part: &EncKdcRepPart,
) -> Result<(), Error> {
    let raw = padata
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::PKINIT_KX))
        .ok_or_else(|| {
            Error::ReplyMismatch("Reply has wrong form of session key for anonymous request".into())
        })?;
    let enc: EncryptedData = decode(raw.padata_value.as_ref())?;
    let usage = KeyUsage::new(ku::PA_PKINIT_KX)?;
    let plain = Zeroizing::new(decrypt_enc_data(
        as_key,
        usage,
        enc.etype,
        enc.cipher.as_ref(),
    )?);
    let kdc_key: EncryptionKey = decode(&plain)?;
    let contrib = ProtocolKey::from_bytes(
        EncryptionType::known(kdc_key.keytype)?,
        kdc_key.keyvalue.as_ref(),
    )?;
    let expected = krb_fx_cf2(&contrib, as_key, b"PKINIT", b"KEYEXCHANGE")?;
    if expected.etype().to_iana() != enc_part.key.keytype
        || expected.as_bytes() != enc_part.key.keyvalue.as_ref()
    {
        return Err(Error::ReplyMismatch(
            "Reply has wrong form of session key for anonymous request".into(),
        ));
    }
    Ok(())
}

pub(crate) fn as_sname_eq(
    got: &PrincipalName,
    expected: &PrincipalName,
    why: &'static str,
) -> Result<(), Error> {
    if got.name_string != expected.name_string {
        return Err(Error::ReplyMismatch(why.into()));
    }
    Ok(())
}

pub fn verify_as_reply_server(
    enc_sname: &PrincipalName,
    enc_srealm: &krb5_types::Realm,
    ticket_sname: &PrincipalName,
    ticket_realm: &krb5_types::Realm,
    request_sname: &PrincipalName,
    request_realm: &str,
    canon_req: bool,
) -> Result<(), Error> {
    as_sname_eq(enc_sname, ticket_sname, "AS-REP sname/ticket mismatch")?;
    if enc_srealm.as_bytes() != ticket_realm.as_bytes() {
        return Err(Error::ReplyMismatch("AS-REP sname/ticket mismatch".into()));
    }
    let canon_ok = canon_req && request_sname.is_krbtgt() && enc_sname.is_krbtgt();
    if canon_ok {
        return Ok(());
    }
    as_sname_eq(enc_sname, request_sname, "AS-REP sname mismatch")?;
    if enc_srealm.as_bytes() != request_realm.as_bytes() {
        return Err(Error::ReplyMismatch("AS-REP sname mismatch".into()));
    }
    Ok(())
}

/// Time 0 unspecified; MIT's KDCREP_MODIFIED is ReplyMismatch.
pub fn verify_as_reply_req_times(
    enc: &EncKdcRepPart,
    till: &KerberosTime,
    rtime: Option<&KerberosTime>,
    from: Option<&KerberosTime>,
    opts: &KdcOptions,
) -> Result<(), Error> {
    let start = enc.starttime.as_ref().unwrap_or(&enc.authtime);
    if opts.bit(flag_bit::POSTDATED)
        && let Some(from) = from
        && from.unix_seconds() != 0
        && from.unix_seconds() != start.unix_seconds()
    {
        return Err(Error::ReplyMismatch(
            "AS-REP starttime != request from".into(),
        ));
    }
    if till.unix_seconds() != 0 && enc.endtime.unix_seconds() > till.unix_seconds() {
        return Err(Error::ReplyMismatch(
            "AS-REP endtime after request till".into(),
        ));
    }
    if opts.bit(flag_bit::RENEWABLE)
        && let Some(rtime) = rtime
        && rtime.unix_seconds() != 0
        && enc
            .renew_till
            .as_ref()
            .is_some_and(|rt| rt.unix_seconds() > rtime.unix_seconds())
    {
        return Err(Error::ReplyMismatch(
            "AS-REP renew-till after request rtime".into(),
        ));
    }
    if opts.bit(flag_bit::RENEWABLE_OK)
        && !opts.bit(flag_bit::RENEWABLE)
        && enc.flags.renewable()
        && till.unix_seconds() != 0
        && enc
            .renew_till
            .as_ref()
            .is_some_and(|rt| rt.unix_seconds() > till.unix_seconds())
    {
        return Err(Error::ReplyMismatch(
            "AS-REP renew-till after request till".into(),
        ));
    }
    Ok(())
}

/// kdc_timesync 0: expired ticket is ReplyMismatch, stricter than MIT.
// MIT: `verify_as_reply` (lib/krb5/krb/get_in_tkt.c:266-269)
pub fn check_as_rep_times(
    enc_part: &EncKdcRepPart,
    now: i64,
    skew: i64,
    timesync: bool,
    from: Option<&KerberosTime>,
) -> Result<(), Error> {
    if timesync {
        return Ok(());
    }
    let start = enc_part.starttime.as_ref().unwrap_or(&enc_part.authtime);
    let postdated = from.is_some_and(|f| f.unix_seconds() != 0);
    if !postdated && (i64::from(start.unix_seconds()) - now).abs() > skew {
        return Err(Error::KdcReplySkew);
    }
    let end = i64::from(enc_part.endtime.unix_seconds());
    if end + skew < now {
        return Err(Error::ReplyMismatch("AS-REP ticket expired".into()));
    }
    Ok(())
}

fn decode_enc_as(plain: &[u8]) -> Result<EncKdcRepPart, Error> {
    krb5_asn1::decode_enc_kdc_rep_part(plain).map_err(|e| Error::Asn1(e.to_string()))
}

fn salt_cname(cname: &PrincipalName) -> PrincipalName {
    if cname.name_type != PrincipalName::NT_ENTERPRISE {
        return cname.clone();
    }
    let raw = cname.components_joined();
    let user = match raw.rsplit_once('@') {
        Some((u, _)) if !u.is_empty() => u,
        _ => raw.as_str(),
    };
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user])
}

fn build_as_req_from(
    req: &AsRequest<'_>,
    nonce: u32,
    bound: &AsReqTimes,
    padata: Option<Vec<PaData>>,
    etypes: &[i32],
) -> Result<AsReq, Error> {
    let addresses = req.ticket.addresses.clone().filter(|list| !list.is_empty());
    let mut as_req = build_as_req(
        &req.cname,
        req.realm,
        nonce,
        bound.till.clone(),
        bound.rtime.clone(),
        bound.from.clone(),
        bound.opts.clone(),
        addresses,
        padata,
        etypes,
        &req_sname(req),
    )?;
    if let Some(include_pac) = req.ticket.pac_request {
        let value = encode(&krb5_types::PaPacRequest { include_pac })?;
        as_req.0.padata.get_or_insert_with(Vec::new).push(PaData {
            padata_type: pa::PAC_REQUEST,
            padata_value: value.into(),
        });
    }
    Ok(as_req)
}

#[expect(clippy::too_many_arguments, reason = "client AS, not a params struct")]
fn build_as_req(
    cname: &PrincipalName,
    realm: &str,
    nonce: u32,
    till: KerberosTime,
    rtime: Option<KerberosTime>,
    from: Option<KerberosTime>,
    kdc_options: KdcOptions,
    addresses: Option<krb5_types::HostAddresses>,
    padata: Option<Vec<PaData>>,
    etypes: &[i32],
    sname: &PrincipalName,
) -> Result<AsReq, Error> {
    let realm_s = krb5_types::try_ascii(realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?;
    let mut pa_list = padata.unwrap_or_default();
    pa_list.push(PaData {
        padata_type: pa::AS_FRESHNESS,
        padata_value: Vec::new().into(),
    });
    pa_list.push(PaData {
        padata_type: pa::REQ_ENC_PA_REP,
        padata_value: Vec::new().into(),
    });
    Ok(AsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_AS_REQ,
        padata: Some(pa_list),
        req_body: KdcReqBody {
            kdc_options,
            cname: Some(cname.clone()),
            realm: realm_s,
            sname: Some(sname.clone()),
            from,
            till,
            rtime,
            nonce,
            etype: etypes.to_vec(),
            addresses,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    }))
}

// MIT: `krb5_get_default_in_tkt_ktypes` (lib/krb5/krb/init_ctx.c:514-528)
// MIT: `krb5int_parse_enctype_list` (lib/krb5/krb/init_ctx.c:447-502)
// MIT: `krb5int_c_weak_enctype` (lib/crypto/krb/enctype_util.c:58-64)
/// ETYPE_WEAK is dropped. rc4-hmac is not weak.
#[must_use]
pub fn conf_etypes(conf: &Krb5Conf, tgs: bool) -> Vec<i32> {
    let preferred: Vec<i32> = EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect();
    let names = if tgs && !conf.default_tgs_enctypes.is_empty() {
        &conf.default_tgs_enctypes
    } else if !tgs && !conf.default_tkt_enctypes.is_empty() {
        &conf.default_tkt_enctypes
    } else if let Some(names) = conf.permitted_enctypes.as_ref().filter(|n| !n.is_empty()) {
        names
    } else {
        return preferred;
    };
    parse_enctype_list(&names.join(" "), conf.allow_weak_crypto)
        .map(|list| list.into_iter().map(EncryptionType::to_iana).collect())
        .unwrap_or(preferred)
}

// MIT: `set_request_times` (lib/krb5/krb/get_in_tkt.c:707-710)
fn request_times(req: &AsRequest<'_>, clock: &Clock, nonce: u32) -> AsReqTimes {
    let (now, _) = clock.now(true);
    // MIT: `kdc_get_ticket_renewtime` (kdc/kdc_util.c:1735-1737)
    let now = if clock.follows_kdc() {
        now
    } else {
        crate::auth_con::request_lifetime_now(now)
    };
    let times = ticket_body(req, &now);
    clock.note_request(AsRestart {
        nonce,
        times: times.clone(),
    });
    times
}

// MIT: `krb5_init_creds_step` (lib/krb5/krb/get_in_tkt.c:1910-1913)
fn restart_point(req: &AsRequest<'_>) -> AsRestart {
    req.ticket.restart.clone().unwrap_or_else(|| AsRestart {
        nonce: 0,
        times: AsReqTimes {
            till: KerberosTime::from_unix_seconds(0),
            rtime: None,
            from: None,
            opts: initial_options(req),
        },
    })
}

// MIT: `krb5_init_creds_init` (lib/krb5/krb/get_in_tkt.c:897-963)
fn initial_options(req: &AsRequest<'_>) -> KdcOptions {
    let mut opts = KdcOptions::from_u32(req.profile.kdc_default_options.cast_unsigned());
    if req.ticket.forwardable {
        opts = opts.with_bit(flag_bit::FORWARDABLE, true);
    }
    if req.ticket.proxiable {
        opts = opts.with_bit(flag_bit::PROXIABLE, true);
    }
    if req.canonicalize {
        opts = opts.with_bit(flag_bit::CANONICALIZE, true);
    }
    if req.ticket.starttime.unwrap_or(0) > 0 {
        opts = opts
            .with_bit(flag_bit::MAY_POSTDATE, true)
            .with_bit(flag_bit::POSTDATED, true);
    }
    if req.ticket.rlife.is_some_and(|r| r > 0) {
        opts = opts.with_bit(flag_bit::RENEWABLE, true);
    }
    if req.ticket.anonymous || krb5_types::pkinit::is_anonymous_principal(&req.cname) {
        opts = opts.with_bit(flag_bit::ANONYMOUS, true);
    }
    opts
}

fn ticket_body(req: &AsRequest<'_>, now: &KerberosTime) -> AsReqTimes {
    let start = req.ticket.starttime.unwrap_or(0);
    let from = if start == 0 {
        None
    } else {
        now.add_seconds(start).ok()
    };
    let base = from.as_ref().unwrap_or(now);
    let life = req.ticket.lifetime.unwrap_or(24 * 3600);
    let till = base
        .add_seconds(i64::try_from(life).unwrap_or(i64::MAX))
        .unwrap_or_else(|_| base.clone());
    let mut opts = initial_options(req);
    let mut rtime = match req.ticket.rlife {
        Some(r) if r > 0 => {
            opts = opts.with_bit(flag_bit::RENEWABLE_OK, false);
            base.add_seconds(i64::try_from(r).unwrap_or(i64::MAX)).ok()
        }
        _ => None,
    };
    if let Some(rt) = rtime.as_mut()
        && till.unix_seconds() > rt.unix_seconds()
    {
        *rt = till.clone();
    }
    AsReqTimes {
        till,
        rtime,
        from,
        opts,
    }
}

#[must_use]
pub fn as_init_creds_options(req: &AsRequest<'_>) -> (KdcOptions, Option<KerberosTime>) {
    let t = ticket_body(req, &KerberosTime::now());
    (t.opts, t.from)
}

fn pa_enc_timestamp_at(
    key: &ProtocolKey,
    now: (KerberosTime, krb5_types::Microseconds),
    armored: bool,
) -> Result<PaData, Error> {
    let (now, usec) = now;
    let ts = ec::pa_enc_ts(&now, usec);
    let der = encode(&ts)?;
    let usage = KeyUsage::new(ku::PA_ENC_TIMESTAMP)?;
    let cipher = encrypt(key, usage, &der)?;
    let (sec, usec) = (
        i64::from(now.unix_seconds()),
        i32::try_from(usec.get()).unwrap_or_default(),
    );
    if armored {
        trace::preauth_enc_ts_armored(sec, usec, &der, &cipher);
    } else {
        trace::preauth_enc_ts(sec, usec, &der, &cipher);
    }
    let enc = EncryptedData {
        etype: key.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    };
    Ok(PaData {
        padata_type: pa::ENC_TIMESTAMP,
        padata_value: encode(&enc)?.into(),
    })
}

pub(super) type S2kMaterial = (EncryptionType, Vec<u8>, Option<Vec<u8>>);
pub(super) type LearnedSalt = (Vec<u8>, Option<Vec<u8>>);

fn first_etype(etypes: &[i32]) -> EncryptionType {
    etypes
        .first()
        .and_then(|n| EncryptionType::known(*n).ok())
        .unwrap_or(EncryptionType::Aes256CtsHmacSha196)
}

fn select_s2k(
    error: &KrbError,
    cname: &PrincipalName,
    realm: &str,
    etypes: &[i32],
) -> Result<S2kMaterial, Error> {
    let start = (first_etype(etypes), cname.default_salt(realm), None);
    select_s2k_after(error, cname, realm, etypes, start)
}

// MIT: `get_salt` (lib/krb5/krb/preauth2.c:743-786)
pub(super) fn select_s2k_after(
    error: &KrbError,
    cname: &PrincipalName,
    realm: &str,
    etypes: &[i32],
    prev: S2kMaterial,
) -> Result<S2kMaterial, Error> {
    let Some(edata) = &error.e_data else {
        return Ok(prev);
    };
    let method: MethodData = decode(edata.as_ref())?;
    let default_salt = cname.default_salt(realm);
    let picked = if let Some(p) = find_pa(&method, pa::ETYPE_INFO2) {
        decode::<EtypeInfo2>(p.padata_value.as_ref())
            .ok()
            .map(|info| {
                pick_info2(&info, &default_salt, etypes)
                    .ok_or_else(|| no_requested_etype(info.iter().map(|e| e.etype)))
            })
    } else if let Some(p) = find_pa(&method, pa::ETYPE_INFO) {
        decode::<EtypeInfo>(p.padata_value.as_ref())
            .ok()
            .map(|info| {
                pick_info(&info, &default_salt, etypes)
                    .ok_or_else(|| no_requested_etype(info.iter().map(|e| e.etype)))
            })
    } else {
        None
    };
    if let Some(found) = picked {
        return found;
    }
    let (etype, salt, params) = prev;
    if let Some(p) = find_pa(&method, pa::PW_SALT) {
        return Ok((etype, p.padata_value.as_ref().to_vec(), params));
    }
    if let Some(p) = find_pa(&method, pa::AFS3_SALT) {
        let mut afs = p.padata_value.as_ref().to_vec();
        if let Some(at) = afs.iter().position(|&b| b == b'@') {
            afs.truncate(at);
        }
        if afs.last() == Some(&0) {
            afs.pop();
        }
        return Ok((etype, afs, Some(vec![1])));
    }
    Ok((etype, salt, params))
}

pub(super) fn error_has_salt(error: &KrbError) -> bool {
    let Some(edata) = &error.e_data else {
        return false;
    };
    let Ok(method) = decode::<MethodData>(edata.as_ref()) else {
        return false;
    };
    find_pa(&method, pa::ETYPE_INFO2).is_some()
        || find_pa(&method, pa::ETYPE_INFO).is_some()
        || find_pa(&method, pa::PW_SALT).is_some()
        || find_pa(&method, pa::AFS3_SALT).is_some()
}

pub(super) fn learned_s2k(
    error: &KrbError,
    cname: &PrincipalName,
    realm: &str,
    etypes: &[i32],
) -> Option<LearnedSalt> {
    if !error_has_salt(error) {
        return None;
    }
    select_s2k(error, cname, realm, etypes)
        .ok()
        .map(|(_, salt, params)| (salt, params))
}

fn no_requested_etype(listed: impl IntoIterator<Item = i32>) -> Error {
    if listed.into_iter().any(|n| EncryptionType::known(n).is_ok()) {
        Error::ConfigEtypeNosupp
    } else {
        Error::ProgEtypeNosupp
    }
}

fn pick_info2(info: &EtypeInfo2, default_salt: &[u8], etypes: &[i32]) -> Option<S2kMaterial> {
    let mut order: Vec<EncryptionType> = etypes
        .iter()
        .filter_map(|n| EncryptionType::known(*n).ok())
        .collect();
    if order.is_empty() {
        order.extend(EncryptionType::preferred());
    }
    for wanted in order {
        if let Some(ent) = info.iter().find(|e| e.etype == wanted.to_iana()) {
            let salt = ent
                .salt
                .as_ref()
                .map_or_else(|| default_salt.to_vec(), |s| s.as_bytes().to_vec());
            let params = ent.s2kparams.as_ref().map(|p| p.as_ref().to_vec());
            return Some((wanted, salt, params));
        }
    }
    None
}

fn pick_info(info: &EtypeInfo, default_salt: &[u8], etypes: &[i32]) -> Option<S2kMaterial> {
    let mut order: Vec<EncryptionType> = etypes
        .iter()
        .filter_map(|n| EncryptionType::known(*n).ok())
        .collect();
    if order.is_empty() {
        order.extend(EncryptionType::preferred());
    }
    for wanted in order {
        if let Some(ent) = info.iter().find(|e| e.etype == wanted.to_iana()) {
            let salt = ent
                .salt
                .as_ref()
                .map_or_else(|| default_salt.to_vec(), |s| s.as_ref().to_vec());
            return Some((wanted, salt, None));
        }
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentifyReply {
    Here,
    Referral(String),
}

pub fn as_identify_realm(req: &AsRequest<'_>) -> Result<IdentifyReply, Error> {
    let _ = krb5_types::try_ascii(req.realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?;
    let etypes: Vec<i32> = match req.etypes {
        Some(e) if !e.is_empty() => e.to_vec(),
        _ => conf_etypes(req.profile, false),
    };
    let nonce = random_nonce()?;
    let clock = Clock::new(req.profile, restart_point(req));
    let bound = request_times(req, &clock, nonce);
    let first = build_as_req_from(req, nonce, &bound, None, &etypes)?;
    let wire = encode(&first)?;
    trace::init_creds_preauth_none();
    match send_as(req, &wire, &etypes)? {
        KdcMsg::AsRep(_) => Ok(IdentifyReply::Here),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
        KdcMsg::Error(e)
            if e.error_code == err::PREAUTH_REQUIRED || e.error_code == err::KEY_EXPIRED =>
        {
            Ok(IdentifyReply::Here)
        }
        KdcMsg::Error(e) => match referral_realm(&e, req.realm) {
            Some(realm) => {
                trace::init_creds_referral(realm.as_bytes());
                Ok(IdentifyReply::Referral(realm))
            }
            None => Err(kdc_error(req, &clock, &e)),
        },
    }
}

fn random_nonce() -> Result<u32, Error> {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|e| Error::transport_msg(e.to_string()))?;
    let n = u32::from_be_bytes(b) & 0x7fff_ffff;
    Ok(if n == 0 { 1 } else { n })
}

// MIT: `k5_init_creds_get` (lib/krb5/krb/get_in_tkt.c:546-588)
// MIT: `init_creds_validate_reply` (lib/krb5/krb/get_in_tkt.c:1081-1115)
fn send_as(req: &AsRequest<'_>, wire: &[u8], etypes: &[i32]) -> Result<KdcMsg, Error> {
    let msg = classify(&sendto_kdc(
        req.profile,
        req.kdc,
        req.realm,
        wire,
        SendKind::As,
    )?)?;
    if let KdcMsg::Error(e) = &msg {
        trace::init_creds_error_reply(trace::kdc_code(e.error_code));
    }
    // MIT: `check_reply_enctype` (lib/krb5/krb/get_in_tkt.c:1412-1422)
    if let KdcMsg::AsRep(rep) = &msg
        && !etypes.contains(&rep.0.enc_part.etype)
    {
        return Err(Error::ConfigEtypeNosupp);
    }
    Ok(msg)
}

fn client_princ<'a>(req: &'a AsRequest<'_>) -> trace::Princ<'a> {
    trace::Princ::new(&req.cname, req.realm.as_bytes())
}

fn trace_preauth_input(padata: &[PaData], etypes: &[i32]) {
    if !trace::enabled() {
        return;
    }
    trace::preauth_input(padata);
    trace_etype_info(padata, etypes);
    if let Some(c) = find_pa(padata, pa::FX_COOKIE) {
        trace::preauth_cookie(c.padata_value.as_ref());
    }
}

type EtypeEntry = (i32, Option<Vec<u8>>, Vec<u8>);
type ReplyS2k = (Option<Vec<u8>>, Option<Vec<u8>>);

// MIT: `k5_get_etype_info` (lib/krb5/krb/preauth2.c:798-809)
fn etype_entries(padata: &[PaData]) -> Option<Vec<EtypeEntry>> {
    if let Some(p) = find_pa(padata, pa::ETYPE_INFO2) {
        return decode::<EtypeInfo2>(p.padata_value.as_ref())
            .ok()
            .map(|info| {
                info.iter()
                    .map(|e| {
                        (
                            e.etype,
                            e.salt.as_ref().map(|s| s.as_bytes().to_vec()),
                            e.s2kparams
                                .as_ref()
                                .map(|p| p.as_ref().to_vec())
                                .unwrap_or_default(),
                        )
                    })
                    .collect()
            });
    }
    let p = find_pa(padata, pa::ETYPE_INFO)?;
    decode::<EtypeInfo>(p.padata_value.as_ref())
        .ok()
        .map(|info| {
            info.iter()
                .map(|e| {
                    (
                        e.etype,
                        e.salt.as_ref().map(|s| s.as_ref().to_vec()),
                        Vec::new(),
                    )
                })
                .collect()
        })
}

// MIT: `get_salt` (lib/krb5/krb/preauth2.c:743-786)
fn pw_salt(padata: &[PaData]) -> Option<(i32, Vec<u8>)> {
    let p = find_pa(padata, pa::PW_SALT).or_else(|| find_pa(padata, pa::AFS3_SALT))?;
    let mut salt = p.padata_value.as_ref().to_vec();
    if p.padata_type == pa::AFS3_SALT {
        if let Some(at) = salt.iter().position(|&b| b == b'@') {
            salt.truncate(at);
        }
        if salt.last() == Some(&0) {
            salt.pop();
        }
    }
    Some((p.padata_type, salt))
}

fn trace_etype_info(padata: &[PaData], etypes: &[i32]) {
    if let Some(list) = etype_entries(padata) {
        if let Some((etype, salt, params)) = etypes
            .iter()
            .find_map(|want| list.iter().find(|e| e.0 == *want))
        {
            trace::preauth_etype_info(*etype, salt.as_deref().unwrap_or_default(), params);
        }
        return;
    }
    if let Some((kind, salt)) = pw_salt(padata) {
        trace::preauth_salt(&salt, kind);
    }
}

fn reply_padata(
    padata: Option<&[PaData]>,
    etypes: &[i32],
    module: Option<(&str, i32, i64)>,
) -> Result<(), Error> {
    let Some(padata) = padata else {
        return Ok(());
    };
    trace_preauth_input(padata, etypes);
    check_etype_info(padata, etypes)?;
    if let Some((name, patype, code)) = module
        && padata.iter().any(|p| p.padata_type == patype)
    {
        trace::preauth_process(name, patype, true, code, None);
    }
    trace::preauth_output(&[]);
    Ok(())
}

// MIT: `k5_get_etype_info` (lib/krb5/krb/preauth2.c:818-833)
fn check_etype_info(padata: &[PaData], etypes: &[i32]) -> Result<(), Error> {
    match etype_entries(padata) {
        Some(list) if !list.iter().any(|e| etypes.contains(&e.0)) => {
            Err(no_requested_etype(list.iter().map(|e| e.0)))
        }
        _ => Ok(()),
    }
}

fn trace_gak_salt(
    req: &AsRequest<'_>,
    cname: &PrincipalName,
    realm: &krb5_types::Realm,
    padata: Option<&[PaData]>,
    etypes: &[i32],
    keytab: bool,
) {
    trace_salt_princ(cname, realm, padata, etypes);
    trace_gak(req, padata, etypes, keytab);
}

// MIT: `init_creds_step_reply` (lib/krb5/krb/get_in_tkt.c:1817-1819)
fn trace_salt_princ(
    cname: &PrincipalName,
    realm: &krb5_types::Realm,
    padata: Option<&[PaData]>,
    etypes: &[i32],
) {
    if !trace::enabled() || reply_salt(padata, etypes).is_some() {
        return;
    }
    let text = String::from_utf8_lossy(realm.as_bytes());
    trace::init_creds_salt_princ(&salt_cname(cname).default_salt(&text));
}

// MIT: `init_creds_step_reply` (lib/krb5/krb/get_in_tkt.c:1802-1820)
pub(super) fn fallback_s2k(
    padata: Option<&[PaData]>,
    etypes: &[i32],
    learned: Option<LearnedSalt>,
    reply_cname: &PrincipalName,
    reply_realm: &krb5_types::Realm,
) -> LearnedSalt {
    let default_salt = || {
        let text = String::from_utf8_lossy(reply_realm.as_bytes());
        salt_cname(reply_cname).default_salt(&text)
    };
    match reply_s2k(padata, etypes) {
        Some((Some(salt), params)) => (salt, params),
        Some((None, params)) => (default_salt(), params),
        None => learned.unwrap_or_else(|| (default_salt(), None)),
    }
}

fn trace_gak(req: &AsRequest<'_>, padata: Option<&[PaData]>, etypes: &[i32], keytab: bool) {
    if !trace::enabled() {
        return;
    }
    let default_salt = salt_cname(&req.cname).default_salt(req.realm);
    let kdc_salt = reply_salt(padata, etypes);
    let salt = kdc_salt.as_deref().filter(|_| keytab);
    trace::init_creds_gak(salt.unwrap_or(&default_salt), &[]);
}

/// The reply's salt and s2kparams: `Some((None, _))` is an entry with no salt, the default one.
// MIT: `k5_get_etype_info` (lib/krb5/krb/preauth2.c:788-846)
fn reply_s2k(padata: Option<&[PaData]>, etypes: &[i32]) -> Option<ReplyS2k> {
    let padata = padata?;
    let Some(list) = etype_entries(padata) else {
        return pw_salt(padata).map(|(kind, salt)| {
            let params = (kind == pa::AFS3_SALT).then(|| vec![1]);
            (Some(salt), params)
        });
    };
    let (_, salt, params) = etypes
        .iter()
        .find_map(|want| list.iter().find(|e| e.0 == *want))?;
    Some((salt.clone(), Some(params.clone()).filter(|p| !p.is_empty())))
}

fn reply_salt(padata: Option<&[PaData]>, etypes: &[i32]) -> Option<Vec<u8>> {
    reply_s2k(padata, etypes)?.0
}

// MIT: `krb5_kt_get_entry` (lib/krb5/keytab/ktfns.c:57-80)
fn trace_keytab_gak(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    unreadable: Option<&KeytabFailure>,
    etype: EncryptionType,
) {
    if (keys.is_empty() && unreadable.is_none()) || !trace::enabled() {
        return;
    }
    let Some(name) = trace::gak_keytab() else {
        return;
    };
    let client = client_princ(req);
    if let Some(failure) = unreadable {
        trace::kt_get_entry(
            &name,
            client,
            0,
            etype.to_iana(),
            failure.code,
            Some(&failure.text),
        );
        return;
    }
    // MIT: `krb5_ktfile_get_entry` (lib/krb5/keytab/kt_file.c:379-391)
    let (code, msg) = if keys.iter().any(|k| k.etype() == etype) {
        (0, None)
    } else {
        (
            trace::KRB5_KT_NOTFOUND,
            Some(format!("No key table entry found for {}", client.unparse())),
        )
    };
    trace::kt_get_entry(&name, client, 0, etype.to_iana(), code, msg.as_deref());
}

fn emit(event: &'static str, correlation_id: &str, started: Instant, err: Option<&Error>) {
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    if let Some(e) = err {
        tracing::error!(
            event,
            correlation_id,
            component = "krb5-protocol",
            duration_us,
            outcome = "error",
            error = %e,
        );
    } else {
        tracing::debug!(
            event,
            correlation_id,
            component = "krb5-protocol",
            duration_us,
            outcome = "ok",
        );
    }
}

#[cfg(test)]
mod spake_factor_tests;

#[cfg(test)]
mod as_kdc_options_tests;
