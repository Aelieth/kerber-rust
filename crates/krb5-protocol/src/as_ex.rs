//! AS-REQ / AS-REP with PA-ENC-TIMESTAMP, SPAKE, FAST, or PKINIT.

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
};

#[derive(Clone, Debug)]
pub struct AsOutcome {
    /// AS-REP ticket (TGT).
    pub ticket: krb5_types::Ticket,
    /// Decrypted EncKDCRepPart.
    pub enc_part: EncKdcRepPart,
    /// Client long-term key used to unwrap the AS-REP.
    pub client_key: ProtocolKey,
    /// TGS session key.
    pub session_key: ProtocolKey,
    /// Client principal as returned by the KDC.
    pub cname: PrincipalName,
    /// Client realm as returned by the KDC.
    pub crealm: krb5_types::Realm,
    /// RFC 6806 FAST negotiation: the enc-padata carried PA-FX-FAST, so the KDC supports FAST (MIT records `fast_avail` in the ccache).
    pub fast_avail: bool,
    /// The AS-REQ itself was FAST-armored.
    pub used_fast: bool,
    /// The preauth type that produced the reply (MIT `selected_preauth_type`, recorded as the ccache `pa_type` config); `None` without preauth.
    pub pa_type: Option<i32>,
    /// The preauth config the modules recorded (MIT `cc_config_out`, JSON octets), stored in the ccache as `pa_config_data`; `None` when no module recorded any.
    pub pa_config: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct AsRequest<'a> {
    /// Client name (without realm).
    pub cname: PrincipalName,
    /// Realm.
    pub realm: &'a str,
    /// Password octets (UTF-8).
    pub password: &'a [u8],
    /// KDC address.
    pub kdc: &'a KdcAddr,
    /// The profile the request runs under, its program's [`krb5_config::ClientContext`]'s.
    pub profile: &'a Krb5Conf,
    /// Use PA-SPAKE (151) in the configured groups, never another mechanism.
    pub want_spake: bool,
    /// FAST armor (PA-FX-FAST). The inner preauth is the first loaded real mechanism in the hint: SPAKE, then encrypted challenge, then encrypted timestamp.
    pub fast_armor: Option<&'a FastArmor>,
    /// PKINIT: an identity that loaded (empty 150 first; PA-16 on the retry with the hint token), or one that cannot run.
    pub pkinit: Option<Pkinit<'a>>,
    /// RFC 6806 canonicalize (NT-ENTERPRISE client names).
    pub canonicalize: bool,
    /// Optional AS sname (default `krbtgt/REALM`). `kadmin/changepw` for kpasswd.
    pub sname: Option<&'a PrincipalName>,
    /// AS-REQ etype list. `None` is krb5.conf's ([`conf_etypes`]), as MIT's default for a caller that sets none; `kinit` passes that list sorted for its keytab.
    pub etypes: Option<&'a [i32]>,
    /// Lifetime, renewable life, and KDC option flags (`kinit -l/-r/-f/-p/-a`).
    pub ticket: AsTicketOpts,
}

#[derive(Clone, Debug)]
pub struct AsTicketOpts {
    /// Ticket lifetime in seconds (`-l`). `None` is 24 hours.
    /// MIT `krb5_init_creds_init` (`get_in_tkt.c:936-947`): with no caller lifetime and no `ticket_lifetime`, the lifetime is 24 hours.
    pub lifetime: Option<u64>,
    /// Renewable lifetime in seconds (`-r`).
    pub rlife: Option<u64>,
    /// Request `forwardable` (MIT default true here).
    pub forwardable: bool,
    /// Request `proxiable`.
    pub proxiable: bool,
    /// Host addresses: [`crate::os_localaddr`]'s list for `kinit -a` or a false `noaddresses`. `None` omits the field, and so does a list with no element.
    pub addresses: Option<krb5_types::HostAddresses>,
    /// `kinit -n`: REQUEST_ANONYMOUS + unsigned PKINIT.
    pub anonymous: bool,
    /// Seconds from now (`kinit -s`), negative for a time past. `None` or 0 omits `from`.
    pub starttime: Option<i64>,
    /// `kinit --request-pac` (true) / `--no-request-pac` (false): a PA-PAC-REQUEST on every AS-REQ; `None` sends none.
    /// MIT `maybe_add_pac_request` (`lib/krb5/krb/get_in_tkt.c:1243-1245`): the request is added only when the option was set.
    pub pac_request: Option<bool>,
    /// The one real preauthentication type an input cache allows; `None` allows any.
    pub allowed_preauth_type: Option<i32>,
    /// The input cache's `pa_config_data` for the request's server, as stored (the JSON's octets).
    pub pa_config_in: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct AsReqTimes {
    till: KerberosTime,
    rtime: Option<KerberosTime>,
    from: Option<KerberosTime>,
    opts: KdcOptions,
}

impl Default for AsTicketOpts {
    fn default() -> Self {
        Self {
            lifetime: None,
            rlife: None,
            forwardable: true,
            proxiable: false,
            addresses: None,
            anonymous: false,
            starttime: None,
            pac_request: None,
            allowed_preauth_type: None,
            pa_config_in: None,
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

/// MIT `pkinit_client_process` (`plugins/preauth/pkinit/pkinit_clnt.c:950-998`): no anchors, else `pkinit_identity_prompt`'s failure: the certificates, the choice among them, the anchors.
#[derive(Clone, Debug)]
pub struct PkinitFailure {
    /// MIT's `krb5_error_code`.
    pub code: i64,
    /// The message MIT sets for it.
    pub text: String,
    /// `pkinit_identity_initialize` failed, which the module traces when it prepares.
    pub no_identity: bool,
    /// The failure is `pkinit_identity_prompt`'s, which the module traces too.
    pub prompted: bool,
}

/// RFC 4556 client certificate + trust anchor for PKINIT.
pub struct PkinitClient {
    /// Leaf certificate (DER).
    pub cert: Vec<u8>,
    pub key: krb5_types::pkinit::IdentityKey,
    /// CA certificates used to verify the KDC CMS (DER): the anchors, and `pkinit_pool`'s.
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

/// Obtain a TGT. Sends a bare AS-REQ first; if the KDC requires preauth, walks the hint list in MIT `sort_krb5_padata_sequence` order and runs the first mechanism we can (SPAKE before enc-timestamp when both are advertised).
/// [`Error::KrbError`] with the KDC's code when it refuses the request (`PREAUTH_FAILED` also when a decrypted FAST error holds no FX-ERROR); [`Error::ReplyIntegrity`] when the AS-REP enc-part fails its integrity check under the reply key (a wrong password); [`Error::NonceMismatch`] for another nonce; [`Error::ReplyMismatch`] when the reply fails a check against the request (names, etype, flags, times, the enc-pa-rep checksum, or the FAST,
/// SPAKE, or PKINIT exchange) or the request is refused before it is sent (a realm that is not a GeneralString, SPAKE with FAST or PKINIT, anonymous without a PKINIT identity); [`Error::TruncatedReply`] for an empty reply and [`Error::UnexpectedPdu`] for one that is neither AS-REP nor KRB-ERROR; [`Error::Asn1`] when a message does not encode or decode; [`Error::Crypto`] when a key cannot be derived or another crypto step fails;
/// [`Error::DesBadParity`] or [`Error::DesWeakKey`] when a key of the reply is a des3 key MIT refuses.
pub fn as_exchange(req: &AsRequest<'_>) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], None, None, false)
}

/// [`as_exchange`] using long-term keys (keytab).
/// [`Error::KrbError`] with the KDC's code when it refuses the request (`PREAUTH_FAILED` also when a decrypted FAST error holds no FX-ERROR); [`Error::ReplyIntegrity`] when the AS-REP enc-part fails its integrity check under the reply key (a wrong key or password); [`Error::NonceMismatch`] for another nonce; [`Error::ReplyMismatch`] when the reply fails a check against the request (names, etype, flags, times, the enc-pa-rep checksum, or the FAST,
/// SPAKE, or PKINIT exchange) or the request is refused before it is sent (a realm that is not a GeneralString, SPAKE with FAST or PKINIT, anonymous without a PKINIT identity); [`Error::TruncatedReply`] for an empty reply and [`Error::UnexpectedPdu`] for one that is neither AS-REP nor KRB-ERROR; [`Error::Asn1`] when a message does not encode or decode; [`Error::Crypto`] when a key cannot be derived or another crypto step fails; [`Error::DesBadParity`] or
/// [`Error::DesWeakKey`] when a key of the AS reply is a des3 key MIT refuses, and, when the encrypted timestamp is what met it, [`Error::PreauthFailed`] around it with no second request sent.
pub fn as_exchange_with_keys(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
) -> Result<AsOutcome, Error> {
    wrap_as(req, keys, None, None, false)
}

/// AS-REQ using long-term keys (keytab), not a password.
/// [`Error::KrbError`] with the KDC's code when it refuses the request; [`Error::ReplyIntegrity`] when the AS-REP enc-part fails its integrity check under the reply key (a wrong key); [`Error::NonceMismatch`] for another nonce; [`Error::ReplyMismatch`] when the reply fails a check against the request (names, etype, flags, times, the enc-pa-rep checksum, or a SPAKE exchange) or `realm` is not a GeneralString; [`Error::TruncatedReply`]
/// key is a des3 key MIT refuses, [`Error::PreauthFailed`] around it when the timestamp met it.
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

/// [`as_exchange`] reading the password through `prompt` only when the KDC's reply to the first request shows the reply key is needed; `req.password` is not used.
/// a preauth module reads the password when it answers the KDC's hint.
pub fn as_exchange_prompted(
    req: &AsRequest<'_>,
    prompt: &mut PasswordPrompt<'_>,
) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], None, Some(&mut || prompt()), false)
}

/// [`as_exchange`] that returns [`Error::FastUpgrade`] when the KDC's error offers PA-FX-FAST and `req` has no armor key yet, before a password is read or a second request is sent.
pub fn as_exchange_defer_fast(req: &AsRequest<'_>) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], None, None, true)
}

/// [`as_exchange_prompted`] with the same FAST deferral as [`as_exchange_defer_fast`].
pub fn as_exchange_prompted_defer_fast(
    req: &AsRequest<'_>,
    prompt: &mut PasswordPrompt<'_>,
) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], None, Some(&mut || prompt()), true)
}

/// [`as_exchange_with_keys`] with the same FAST deferral as [`as_exchange_defer_fast`].
pub fn as_exchange_with_keys_defer_fast(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
) -> Result<AsOutcome, Error> {
    wrap_as(req, keys, None, None, true)
}

/// [`as_exchange_with_keys`] for a keytab that could not be read: the request is made, and a key asked of the keytab fails with `failure`, as the preauth module's that wanted it or as the reply's decrypt.
pub fn as_exchange_with_unreadable_keytab(
    req: &AsRequest<'_>,
    failure: &KeytabFailure,
) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], Some(failure), None, false)
}

/// [`as_exchange_with_unreadable_keytab`] with the same FAST deferral as [`as_exchange_defer_fast`].
pub fn as_exchange_with_unreadable_keytab_defer_fast(
    req: &AsRequest<'_>,
    failure: &KeytabFailure,
) -> Result<AsOutcome, Error> {
    wrap_as(req, &[], Some(failure), None, true)
}

/// Reads the AS password when the exchange first needs it.
pub type PasswordPrompt<'p> = dyn FnMut() -> Result<Zeroizing<Vec<u8>>, Error> + 'p;

/// MIT `KRB5_PROMPT_TYPE_PASSWORD` (`include/krb5/krb5.hin:7884-7884`): the numbers of the prompt types are MIT's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptType {
    /// `KRB5_PROMPT_TYPE_PASSWORD`.
    Password = 1,
    /// `KRB5_PROMPT_TYPE_NEW_PASSWORD`.
    NewPassword = 2,
    /// `KRB5_PROMPT_TYPE_NEW_PASSWORD_AGAIN`.
    NewPasswordAgain = 3,
    Preauth = 4,
}

#[derive(Clone, Copy, Debug)]
pub struct PreauthPrompt<'a> {
    /// Printed on its own line before the prompt.
    pub banner: Option<&'a str>,
    /// The prompt text; the prompter adds `: `.
    pub prompt: &'a str,
    /// Whether the reply is typed with echo off.
    pub hidden: bool,
    /// What is being asked.
    pub prompt_type: PromptType,
}

/// What an AS exchange may ask of its caller: the password when a reply needs the key, and a preauth module's prompts.
/// the password is read when a module first wants the key, and a read that works is kept; one that fails is asked again by the next module that wants the key.
pub trait AsPrompt {
    /// The AS password. An `Error::File` of kind `Interrupted` is a keyboard interrupt (`KRB5_LIBOS_PWDINTR`), which no other mechanism follows. Any other error fails the module that asked, and the next module that needs the key calls this again.
    /// Why the password could not be read.
    fn password(&mut self) -> Result<Zeroizing<Vec<u8>>, Error>;

    /// Why the reply could not be read; kinds as for [`AsPrompt::password`].
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

/// [`as_exchange_prompted`] with a preauth prompter as well as the password: reads them through `ui` only when the exchange needs them.
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

/// MIT `restart_init_creds_loop` (`get_in_tkt.c:807-813`): optimistic preauth is sent only when the caller supplied a preauth list. The default first request therefore carries no module padata, and a preauth-required hint is what selects the real mechanism.
fn as_exchange_inner(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    unreadable: Option<&KeytabFailure>,
    prompt: Option<&mut dyn AsPrompt>,
    defer_fast: bool,
) -> Result<AsOutcome, Error> {
    let _ = krb5_types::try_ascii(req.realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?;
    refuse_spake_combo(req)?;
    // a caller that sets no etype list asks for `krb5_get_default_in_tkt_ktypes`, krb5.conf's order.
    let etypes: Vec<i32> = match req.etypes {
        Some(e) if !e.is_empty() => e.to_vec(),
        _ => conf_etypes(req.profile, false),
    };
    let nonce = random_nonce()?;
    let clock = Clock::new(req.profile);
    let bound = request_times(req, &clock);

    if req.fast_armor.is_some() {
        return continue_fast(
            req, keys, unreadable, nonce, &bound, &etypes, &clock, prompt,
        );
    }
    // MIT `k5_init_preauth_context` (`lib/krb5/krb/preauth2.c:133-146`): pkinit answers only when that clpreauth module loaded. Anonymous has no other mechanism.
    if crate::clpreauth::loaded(req.profile, "pkinit")
        && (matches!(req.pkinit, Some(Pkinit::Client(_))) || req.ticket.anonymous)
    {
        let hint = match continue_pkinit(req, nonce, &bound, &etypes, &clock, defer_fast)? {
            PkinitEnd::Done(out) => return Ok(*out),
            PkinitEnd::Reply { rep, wire, traced } if !req.ticket.anonymous => {
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
    let msg = send_as(req, &wire)?;
    let spake_more =
        |e: &KrbError| req.want_spake && e.error_code == err::MORE_PREAUTH_DATA_REQUIRED;
    // the offset is noted when the error arrives, before the next request's module reads the password.
    if let KdcMsg::Error(e) = &msg
        && retried(e)
        && e.error_code == err::PREAUTH_REQUIRED
    {
        clock.note(e, false);
    }
    // MIT `k5_upgrade_to_fast_p` (`lib/krb5/krb/fast.c:677-688`): an error that carries PA-FX-FAST, with armor available and no armor key yet, restarts before preauth.
    upgrade_to_fast(&msg, defer_fast)?;
    // no listed mechanism means `KRB5_PREAUTH_FAILED`, and the password prompter is not called.
    if let KdcMsg::Error(e) = &msg
        && e.error_code == err::PREAUTH_REQUIRED
        && !hint_offers_real_mechanism(req, e)
    {
        return Err(preauth_failed());
    }
    // a preauth module reads the password when it wants the key, so a hint is not answered with a read made ahead of the module. Only a reply no module answered reads it here.
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
        KdcMsg::Error(e) => classify_kdc_error(&e),
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
        trace_reply_padata(rep.0.padata.as_deref(), etypes, None);
    }
    let mut pw = PasswordCell::new(
        prompt,
        req.password,
        !keys.is_empty() || unreadable.is_some(),
    )
    .with_unreadable_keytab(unreadable);
    finish_as_rep_keys(req, rep, nonce, keys, etypes, bound, Some(wire), &mut pw)
}

/// with no key from preauth, the reply key is got from the password, with the client's own salt, or from the keytab.
/// the responder is asked for the password first, then the key is got, and `gak_fct`'s error is returned as it is.
/// The password's failure as it is (a read that failed, or `EIO` with nothing to read it from), the responder's error, or the reply's.
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
        trace_gak_salt(req, rep.0.padata.as_deref(), etypes, true);
        trace_keytab_gak(req, keys, Some(failure), etype);
        return Err(ModuleFail::keytab(failure).unwrapped());
    }
    if keys.is_empty() {
        trace_salt_princ(req, rep.0.padata.as_deref(), etypes);
        ask_gak_question(pw)?;
        trace_gak(req, rep.0.padata.as_deref(), etypes, false);
        let password = pw.get().map_err(ModuleFail::unwrapped)?;
        let salt = salt_cname(cname).default_salt(realm);
        let key = string_to_key(etype, &password, &salt, None)?;
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
        );
    }
    let password = req.password;
    trace_gak_salt(req, rep.0.padata.as_deref(), etypes, true);
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
                );
            }
            Err(e) => {
                not_opened.get_or_insert(e);
            }
        }
    }
    Err(not_opened.unwrap_or_else(|| Error::ReplyMismatch("no keytab key decrypted AS-REP".into())))
}

/// and nothing after it. The plaintext is wiped.
fn opens_as_reply(rep: &AsRep, key: &ProtocolKey) -> Result<(), Error> {
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART)?;
    let plain = decrypt_enc_data(
        key,
        usage,
        rep.0.enc_part.etype,
        rep.0.enc_part.cipher.as_ref(),
    )
    .map_err(|e| match e {
        krb5_crypto::Error::Integrity => Error::ReplyIntegrity,
        other => other.into(),
    })?;
    drop(Zeroizing::new(plain));
    Ok(())
}

fn same_key(a: &ProtocolKey, b: &ProtocolKey) -> bool {
    a.etype() == b.etype() && a.as_bytes() == b.as_bytes()
}

/// password, or a keytab key of that enctype. A keytab without it fails the lookup there, and no key is traced.
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

/// Default when `preferred_preauth_types` is unset.
/// MIT `sort_krb5_padata_sequence` (`get_in_tkt.c:400-471`): uses "17, 16, 15, 14" (PKINIT first) when `preferred_preauth_types` is unset.
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
    // MIT `spake_init` (`spake_client.c:62-73`): with no permitted group there is no SPAKE module.
    let groups = client_groups(req.profile);
    // MIT `k5_preauth_note_failed` (`lib/krb5/krb/preauth2.c:208-221`): the real types that failed in this authentication, which are not tried again.
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
                        (Some(e), _) => kdc_error(&e),
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

/// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:669-674`): a pa-type with no loaded module is skipped. Encrypted challenge runs only under armor (`fast_mechanism`).
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

/// An unsupported etype is retried once with aes256 alone, a retry MIT's error branch does not have; any other error is not another guess.
/// The module gets the AS key first, and a password the prompter cannot read is the module's failure, with no request sent, so the walk can go on to the next mechanism.
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
            Ok(password) => string_to_key(etype, &password, &salt, params.as_deref())?,
            Err(f) => return Ok(Err(f)),
        },
    };
    if gak_found(keys, &client_key, etype) {
        trace::preauth_enc_ts_key_gak((&client_key).into());
    }
    let mut padata = error_cookie(preauth_err);
    // `krb5_encrypt_helper` fails with the key's code when the key is a des3 key MIT refuses, and that is the module's failure.
    match pa_enc_timestamp_at(&client_key, clock.now(true), false) {
        Ok(p) => padata.push(p),
        Err(e @ (Error::DesBadParity | Error::DesWeakKey)) => {
            return Ok(Err(ModuleFail::des_key(e)));
        }
        Err(e) => return Err(e),
    }
    trace::preauth_process(ENCTS_MODULE, pa::ENC_TIMESTAMP, true, 0, None);
    trace::preauth_output(&padata);
    let bound = request_times(req, clock);
    let second = build_as_req_from(req, nonce, &bound, Some(padata), etypes)?;
    let wire = encode(&second)?;
    let finish =
        |rep: AsRep, wire: &[u8], etypes: &[i32], client_key: ProtocolKey, bound: &AsReqTimes| {
            trace_reply_padata(rep.0.padata.as_deref(), etypes, None);
            trace::init_creds_as_key_preauth((&client_key).into());
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
            )
        };
    match send_as(req, &wire)? {
        KdcMsg::AsRep(rep) => finish(rep, &wire, etypes, client_key, &bound),
        KdcMsg::Error(e) if e.error_code == err::ETYPE_NOSUPP => {
            let etypes = vec![EncryptionType::Aes256CtsHmacSha196.to_iana()];
            trace_tryagain_input(&e, pa::ENC_TIMESTAMP);
            let mut padata = vec![pa_enc_timestamp_at(&client_key, clock.now(true), false)?];
            tryagain_padata(error_cookie(&e), &mut padata);
            let bound = request_times(req, clock);
            let retry = build_as_req_from(req, nonce, &bound, Some(padata), &etypes)?;
            let wire = encode(&retry)?;
            match send_as(req, &wire)? {
                KdcMsg::AsRep(rep) => finish(rep, &wire, &etypes, client_key, &bound),
                KdcMsg::Error(e) => classify_kdc_error(&e),
                KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
            }
        }
        KdcMsg::Error(e) => {
            encts_tryagain(&e);
            classify_kdc_error(&e)
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
    let bound = request_times(req, clock);
    let second = build_as_req_from(req, nonce, &bound, Some(padata), etypes)?;
    let wire = encode(&second)?;
    match send_as(req, &wire)? {
        KdcMsg::AsRep(rep) => {
            finish_as_rep_keys(req, rep, nonce, keys, etypes, &bound, Some(&wire), pw)
        }
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

fn preauth_failed() -> Error {
    Error::ReplyMismatch("Generic preauthentication failure".into())
}

/// The padata of a KDC message that the input cache allows.
pub(super) fn allowed_padata(req: &AsRequest<'_>, method: &[PaData]) -> Vec<PaData> {
    method
        .iter()
        .filter(|p| req.ticket.preauth_allowed(p.padata_type))
        .cloned()
        .collect()
}

/// Whether the hint lists a mechanism this client runs, so the password may be read.
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

/// MIT `krb5int_fast_process_error` (`lib/krb5/krb/fast.c:494-497`): without FAST, an error is retried only when its e-data isn't empty.
fn retried(e: &KrbError) -> bool {
    e.e_data.as_ref().is_some_and(|d| !d.as_ref().is_empty())
}

/// an error no branch handles continues, when retried, with the selected mechanism.
/// MIT `k5_preauth_tryagain` (`lib/krb5/krb/preauth2.c:905-922`): a module with no tryagain returns no padata and is noted failed, after the trace.
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

/// MIT `pkinit_client_prep_questions` (`plugins/preauth/pkinit/pkinit_clnt.c:766-783`): `pkinit_identity_initialize` runs once per request.
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

fn tryagain_padata(cookie: Vec<PaData>, padata: &mut Vec<PaData>) {
    if trace::enabled() {
        trace::preauth_tryagain(ENCTS_MODULE, pa::ENC_TIMESTAMP, 0, None);
        for c in &cookie {
            trace::preauth_cookie(c.padata_value.as_ref());
        }
    }
    padata.extend(cookie);
    trace::preauth_tryagain_output(padata);
}

/// Place a selected preauth module's PA-DATA after any FX-COOKIE and before the `info_pa_permitted` pair (150/149).
pub fn insert_module_padata_before_info_pa(list: &mut Vec<PaData>, module_pa: PaData) {
    let at = list
        .iter()
        .position(|p| p.padata_type == pa::AS_FRESHNESS || p.padata_type == pa::REQ_ENC_PA_REP)
        .unwrap_or(list.len());
    list.insert(at, module_pa);
}

/// MIT `pkinit_as_req_create` (`pkinit_clnt.c:194-195`): the freshness token is placed in the auth pack when freshness is enabled. The first request carries no PKINIT, and a reply that is not preauth-required or preauth-failed is not turned into an AuthPack.
/// MIT `pa_pkinit_gen_req` (`plugins/preauth/pkinit/pkinit_clnt.c:125-136`): the authenticator's time is the one `get_preauth_time` gives, the KDC's after a preauth error.
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
    let msg = send_as(req, &first_wire)?;
    upgrade_to_fast(&msg, defer_fast)?;
    let (token, cookie) = match msg {
        KdcMsg::Error(e)
            if e.error_code == err::PREAUTH_REQUIRED || e.error_code == err::PREAUTH_FAILED =>
        {
            if retried(&e) {
                clock.note(&e, false);
            }
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
            let token = find_pa(&method, pa::AS_FRESHNESS)
                .map(|p| p.padata_value.as_ref())
                .filter(|v| !v.is_empty())
                .map(<[u8]>::to_vec);
            let cookie = find_pa(&method, pa::FX_COOKIE).cloned();
            (token, cookie)
        }
        KdcMsg::Error(e) => return classify_kdc_error(&e).map(|o| PkinitEnd::Done(Box::new(o))),
        KdcMsg::AsRep(rep) => {
            return Ok(PkinitEnd::Reply {
                rep: Box::new(rep),
                wire: first_wire,
                traced: false,
            });
        }
        KdcMsg::TgsRep => return Err(Error::UnexpectedPdu),
    };
    // MIT `process_pa_data` (`preauth2.c:684-712`): anonymous has no mechanism after pkinit, so a pkinit failure before the request is the error.
    let Some(pk) = pk else {
        let Some(Pkinit::Failed(f)) = req.pkinit else {
            return Err(Error::ReplyMismatch("PKINIT identity missing".into()));
        };
        return Err(Error::PreauthFailed(Box::new(pkinit_fails(f).error)));
    };
    let mut dh_size = pk.dh_size();
    let mut nonce = nonce;
    let mut tryagain: Option<Retry> = None;
    for _ in 1..MAX_IN_TKT_LOOPS {
        let group = KxGroup::for_bits(dh_size).unwrap_or(KxGroup::Modp2048);
        let bound = &request_times(req, clock);
        let extra = match &tryagain {
            None => cookie.iter().cloned().collect(),
            Some(_) => Vec::new(),
        };
        let mut req2 = build_as_req_from(req, nonce, bound, Some(extra), etypes)?;
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
        tracing::info!(
            event = krb5_log::events::CLIENT_PKINIT,
            component = "krb5-protocol",
            outcome = "ok",
            pa_type = pa::PK_AS_REQ,
            freshness = token.is_some(),
        );
        match send_as(req, &wire)? {
            KdcMsg::AsRep(rep) => {
                let etype = EncryptionType::known(rep.0.enc_part.etype)?;
                let padata = rep.0.padata.as_deref().unwrap_or_default();
                trace_preauth_input(padata, etypes);
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
                        });
                    }
                    Err(e) => return Err(e),
                };
                if padata.iter().any(|p| p.padata_type == pa::PK_AS_REP) {
                    trace::preauth_process(PKINIT_MODULE, pa::PK_AS_REP, true, 0, None);
                }
                trace::preauth_output(&[]);
                trace::init_creds_as_key_preauth((&reply_key).into());
                return finish_as_rep(
                    req.profile,
                    rep,
                    nonce,
                    Some(reply_key),
                    req.password,
                    &req.cname,
                    req.realm,
                    Some(pa::PK_AS_REQ),
                    req.canonicalize,
                    &req_sname(req),
                    bound,
                    Some(&wire),
                    false,
                )
                .map(|o| PkinitEnd::Done(Box::new(o)));
            }
            KdcMsg::Error(e) => {
                tryagain = Some(pkinit_refused(&e, &mut dh_size)?);
                nonce = random_nonce()?;
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
    Done(Box<AsOutcome>),
    Walk(Box<KrbError>),
    Reply {
        rep: Box<AsRep>,
        wire: Vec<u8>,
        traced: bool,
    },
}

pub(crate) struct Retry(Option<PaData>);

// MIT `pa_pkinit_gen_req` (`pkinit_clnt.c:160-162`): handing out the PK-AS-REQ disables fallback.
// MIT `init_creds_step_request` (`get_in_tkt.c:1315-1336`): then a PREAUTH_FAILED, or a refusal tryagain doesn't answer, ends the exchange.
fn pkinit_refused(e: &KrbError, dh_size: &mut u32) -> Result<Retry, Error> {
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
    Err(kdc_error(e))
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

fn upgrade_to_fast(msg: &KdcMsg, defer_fast: bool) -> Result<(), Error> {
    let KdcMsg::Error(e) = msg else {
        return Ok(());
    };
    if defer_fast
        && method_from_error(e).is_ok_and(|m| m.iter().any(|p| p.padata_type == pa::FX_FAST))
    {
        trace::fast_padata_upgrade();
        return Err(Error::FastUpgrade);
    }
    Ok(())
}

/// MIT `encts_disabled` (`lib/krb5/krb/get_in_tkt.c:757-772`): the client realm's boolean, default false.
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

/// MIT `copy_cookie` (`preauth2.c:857-884`): the PA-FX-COOKIE an error's e-data carries, to be sent back as it came.
fn error_cookie(e: &KrbError) -> Vec<PaData> {
    method_from_error(e)
        .ok()
        .and_then(|m| find_pa(&m, pa::FX_COOKIE).cloned())
        .into_iter()
        .collect()
}

fn kdc_error(err: &KrbError) -> Error {
    match classify_kdc_error(err) {
        Err(e) => e,
        Ok(_) => Error::UnexpectedPdu,
    }
}

fn classify_kdc_error(e: &KrbError) -> Result<AsOutcome, Error> {
    match e.error_code {
        err::SKEW => Err(Error::KrbError {
            code: err::SKEW,
            text: Some("clock skew; resync local clock and retry".into()),
        }),
        err::ETYPE_NOSUPP => Err(Error::KrbError {
            code: err::ETYPE_NOSUPP,
            text: Some("no common etype".into()),
        }),
        err::WRONG_REALM => {
            let realm = e.realm.as_bytes().to_vec();
            Err(Error::KrbError {
                code: err::WRONG_REALM,
                text: Some(format!(
                    "wrong realm; chase {}",
                    String::from_utf8_lossy(&realm)
                )),
            })
        }
        _ => krb_err(e),
    }
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

fn krb_err(e: &KrbError) -> Result<AsOutcome, Error> {
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
    Err(Error::KrbError {
        code: e.error_code,
        text,
    })
}

/// MIT `krb5int_fast_verify_nego` (`fast.c:648-664`): a ticket with the enc-pa-rep flag and no matching checksum over the request is not accepted. The client name in the reply may differ only for an anonymous or canonicalized request.
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
) -> Result<AsOutcome, Error> {
    let inner = rep.0;
    let had_preauth = pa_type.is_some();
    let etype = EncryptionType::known(inner.enc_part.etype)?;
    let key = if let Some(k) = client_key {
        k
    } else {
        let salt = salt_cname(cname).default_salt(realm);
        string_to_key(etype, password, &salt, None)?
    };
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART)?;
    let plain = decrypt_enc_data(
        &key,
        usage,
        inner.enc_part.etype,
        inner.enc_part.cipher.as_ref(),
    )
    .map_err(|e| match e {
        krb5_crypto::Error::Integrity => Error::ReplyIntegrity,
        other => other.into(),
    })?;
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
        // Some KDCs omit INITIAL on service-ticket AS; require pre-authent when we sent PA-ENC-TIMESTAMP (client_key is Some).
        if had_preauth && !enc_part.flags.pre_authent() {
            return Err(Error::ReplyMismatch("AS-REP missing PRE-AUTHENT".into()));
        }
    }
    let now = i64::from(KerberosTime::now().unix_seconds());
    let skew = i64::from(profile.clockskew);
    check_as_rep_times(&enc_part, now, skew, profile.kdc_timesync)?;
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
    let plain = decrypt_enc_data(as_key, usage, enc.etype, enc.cipher.as_ref())?;
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

/// Always requires `enc.server == ticket.server` (name and realm).
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

/// `till`/`rtime`/`from` of 0 are unspecified (MIT). `endtime` after `till`, `renew_till` after `rtime` (RENEWABLE) or after `till` (RENEWABLE_OK without RENEWABLE), or POSTDATED `from` ≠ starttime, is `KRB5_KDCREP_MODIFIED`.
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

/// Default `kdc_timesync` (1) skips starttime vs the local clock (MIT then sets a per-context `time_offset`; we have no `krb5_context`).
/// in that mode is [`Error::ReplyMismatch`] (stricter than MIT).
pub fn check_as_rep_times(
    enc_part: &EncKdcRepPart,
    now: i64,
    skew: i64,
    timesync: bool,
) -> Result<(), Error> {
    if timesync {
        return Ok(());
    }
    let start = enc_part.starttime.as_ref().unwrap_or(&enc_part.authtime);
    if (i64::from(start.unix_seconds()) - now).abs() > skew {
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

/// every request advertises an empty freshness token and an enc-pa-rep request. Those two items are appended after the caller's padata, so a mechanism that replaces the list would drop the checksum the reply is checked against.
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

/// MIT `krb5_get_default_in_tkt_ktypes` (`lib/krb5/krb/init_ctx.c:514-528`): `default_tkt_enctypes`, else `permitted_enctypes`, else MIT's default list.
/// MIT `krb5int_parse_enctype_list` (`lib/krb5/krb/init_ctx.c:447-502`): `DEFAULT` and the family words expand.
/// MIT `krb5int_c_weak_enctype` (`lib/crypto/krb/enctype_util.c:58-64`): a type is dropped only when it has `ETYPE_WEAK`, which rc4-hmac does not.
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

/// MIT `set_request_times` (`lib/krb5/krb/get_in_tkt.c:707-710`): each request's times are made at `k5_init_creds_current_time`, the KDC's time once a preauth error gave it.
fn request_times(req: &AsRequest<'_>, clock: &Clock) -> AsReqTimes {
    let (now, _) = clock.now(true);
    // MIT `kdc_get_ticket_renewtime` (`kdc/kdc_util.c:1735-1737`): `RENEWABLE_OK` renews when `till` is after `endtime`.
    let now = if clock.follows_kdc() {
        now
    } else {
        crate::auth_con::request_lifetime_now(now)
    };
    ticket_body(req, &now)
}

/// the start time is omitted unless the caller asked for one, and a renewable end is not requested before the ticket end. A future start marks the request postdated, and omitting a renewable lifetime asks only for renewable-ok.
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
    let mut opts = if req.ticket.forwardable {
        KdcOptions::forwardable()
    } else {
        KdcOptions::none()
    };
    if req.ticket.proxiable {
        opts = opts.with_bit(flag_bit::PROXIABLE, true);
    }
    if start > 0 {
        opts = opts
            .with_bit(flag_bit::MAY_POSTDATE, true)
            .with_bit(flag_bit::POSTDATED, true);
    }
    let mut rtime = match req.ticket.rlife {
        Some(r) if r > 0 => {
            opts = opts.with_bit(flag_bit::RENEWABLE, true);
            base.add_seconds(i64::try_from(r).unwrap_or(i64::MAX)).ok()
        }
        _ => {
            opts = opts.with_bit(flag_bit::RENEWABLE_OK, true);
            None
        }
    };
    // don't ask for a smaller renewable time than the lifetime (`rtime = from+renew_life; if till > rtime then rtime = till`).
    if let Some(rt) = rtime.as_mut()
        && till.unix_seconds() > rt.unix_seconds()
    {
        *rt = till.clone();
    }
    if req.canonicalize {
        opts = opts.with_bit(flag_bit::CANONICALIZE, true);
    }
    if req.ticket.anonymous || krb5_types::pkinit::is_anonymous_principal(&req.cname) {
        opts = opts.with_bit(flag_bit::ANONYMOUS, true);
    }
    AsReqTimes {
        till,
        rtime,
        from,
        opts,
    }
}

/// sets `from` only when the caller asked for a start time, and clears RENEWABLE_OK when a renewable life is asked for.
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

/// The string-to-key inputs for the password: enctype, salt and s2kparams.
pub(super) type S2kMaterial = (EncryptionType, Vec<u8>, Option<Vec<u8>>);

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

/// The string-to-key inputs after `error`: its ETYPE-INFO2, else its ETYPE-INFO (the entry for the first requested enctype it lists), else its PA-PW-SALT, else its PA-AFS3-SALT. An element that does not decode counts as absent. An error that names none, as a SPAKE challenge answering a request that carried the cookie, leaves `prev`, what an earlier error set.
/// MIT `get_salt` (`lib/krb5/krb/preauth2.c:743-786`): a pw-salt sets the salt alone, an afs3-salt the salt and AFS string-to-key, and with no salt element nothing changes.
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

/// One AS-REQ for `req`'s client in `req`'s realm, no preauthentication sent, to learn whether the client exists there: an AS-REP, or preauthentication required, or an expired key, says it does; a WRONG_REALM or C_PRINCIPAL_UNKNOWN error naming the client in another realm refers it there; any other error is the answer. The reply is not decrypted.
/// MIT `is_referral` (`lib/krb5/krb/get_in_tkt.c:1450-1458`): a referral is WRONG_REALM or C_PRINCIPAL_UNKNOWN whose client is in another realm.
pub fn as_identify_realm(req: &AsRequest<'_>) -> Result<IdentifyReply, Error> {
    let _ = krb5_types::try_ascii(req.realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?;
    let etypes: Vec<i32> = match req.etypes {
        Some(e) if !e.is_empty() => e.to_vec(),
        _ => conf_etypes(req.profile, false),
    };
    let nonce = random_nonce()?;
    let clock = Clock::new(req.profile);
    let bound = request_times(req, &clock);
    let first = build_as_req_from(req, nonce, &bound, None, &etypes)?;
    let wire = encode(&first)?;
    trace::init_creds_preauth_none();
    match send_as(req, &wire)? {
        KdcMsg::AsRep(_) => Ok(IdentifyReply::Here),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
        KdcMsg::Error(e)
            if e.error_code == err::PREAUTH_REQUIRED || e.error_code == err::KEY_EXPIRED =>
        {
            Ok(IdentifyReply::Here)
        }
        KdcMsg::Error(e) => {
            let referral = (e.error_code == err::WRONG_REALM
                || e.error_code == err::C_PRINCIPAL_UNKNOWN)
                && e.cname.is_some();
            if referral
                && let Some(crealm) = e.crealm.as_ref()
                && crealm.as_bytes() != req.realm.as_bytes()
            {
                let realm = String::from_utf8_lossy(crealm.as_bytes()).into_owned();
                trace::init_creds_referral(realm.as_bytes());
                Ok(IdentifyReply::Referral(realm))
            } else {
                classify_kdc_error(&e).map(|_| IdentifyReply::Here)
            }
        }
    }
}

fn random_nonce() -> Result<u32, Error> {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|e| Error::transport_msg(e.to_string()))?;
    let n = u32::from_be_bytes(b) & 0x7fff_ffff;
    Ok(if n == 0 { 1 } else { n })
}

/// MIT `k5_init_creds_get` (`lib/krb5/krb/get_in_tkt.c:546-588`): each request goes to the KDCs of the request's realm.
/// MIT `init_creds_validate_reply` (`lib/krb5/krb/get_in_tkt.c:1081-1115`): a KRB-ERROR answer is traced as it arrives.
fn send_as(req: &AsRequest<'_>, wire: &[u8]) -> Result<KdcMsg, Error> {
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

fn trace_etype_info(padata: &[PaData], etypes: &[i32]) {
    type Entry = (i32, Option<Vec<u8>>, Vec<u8>);
    let entries: Option<Vec<Entry>> = if let Some(p) = find_pa(padata, pa::ETYPE_INFO2) {
        decode::<EtypeInfo2>(p.padata_value.as_ref())
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
            })
    } else if let Some(p) = find_pa(padata, pa::ETYPE_INFO) {
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
    } else {
        None
    };
    if let Some(list) = entries {
        if let Some((etype, salt, params)) = etypes
            .iter()
            .find_map(|want| list.iter().find(|e| e.0 == *want))
        {
            trace::preauth_etype_info(*etype, salt.as_deref().unwrap_or_default(), params);
        }
        return;
    }
    let Some(p) = find_pa(padata, pa::PW_SALT).or_else(|| find_pa(padata, pa::AFS3_SALT)) else {
        return;
    };
    let mut salt = p.padata_value.as_ref().to_vec();
    if p.padata_type == pa::AFS3_SALT {
        if let Some(at) = salt.iter().position(|&b| b == b'@') {
            salt.truncate(at);
        }
        if salt.last() == Some(&0) {
            salt.pop();
        }
    }
    trace::preauth_salt(&salt, p.padata_type);
}

fn trace_reply_padata(padata: Option<&[PaData]>, etypes: &[i32], module: Option<(&str, i32, i64)>) {
    let Some(padata) = padata else {
        return;
    };
    trace_preauth_input(padata, etypes);
    if let Some((name, patype, code)) = module
        && padata.iter().any(|p| p.padata_type == patype)
    {
        trace::preauth_process(name, patype, true, code, None);
    }
    trace::preauth_output(&[]);
}

/// then the salt the reply key is got for: the client's own for the password, as before this trace; the KDC's, if any, for a keytab.
fn trace_gak_salt(req: &AsRequest<'_>, padata: Option<&[PaData]>, etypes: &[i32], keytab: bool) {
    trace_salt_princ(req, padata, etypes);
    trace_gak(req, padata, etypes, keytab);
}

fn trace_salt_princ(req: &AsRequest<'_>, padata: Option<&[PaData]>, etypes: &[i32]) {
    if !trace::enabled() || reply_salt(padata, etypes).is_some() {
        return;
    }
    trace::init_creds_salt_princ(&salt_cname(&req.cname).default_salt(req.realm));
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

fn reply_salt(padata: Option<&[PaData]>, etypes: &[i32]) -> Option<Vec<u8>> {
    let p = find_pa(padata?, pa::ETYPE_INFO2)?;
    let info = decode::<EtypeInfo2>(p.padata_value.as_ref()).ok()?;
    let entry = etypes
        .iter()
        .find_map(|want| info.iter().find(|e| e.etype == *want))?;
    entry.salt.as_ref().map(|s| s.as_bytes().to_vec())
}

/// MIT `krb5_kt_get_entry` (`lib/krb5/keytab/ktfns.c:57-80`): the lookup is traced with its result. Only a request [`trace::with_gak_keytab`] names a keytab for is traced.
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
    // MIT `krb5_ktfile_get_entry` (`lib/krb5/keytab/kt_file.c:379-391`): no entry is KRB5_KT_NOTFOUND with a message naming the principal.
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
        tracing::info!(
            event,
            correlation_id,
            component = "krb5-protocol",
            duration_us,
            outcome = "ok",
        );
    }
}

#[cfg(test)]
mod decode_enc_as_tests;

#[cfg(test)]
mod as_sname_tests;

#[cfg(test)]
mod spake_factor_tests;

#[cfg(test)]
mod as_kdc_options_tests;

#[cfg(test)]
mod etype_info_tests;
