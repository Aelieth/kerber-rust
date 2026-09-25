//! AS-REQ / AS-REP with PA-ENC-TIMESTAMP, SPAKE, FAST, or PKINIT.
//!
//! FAST armor lives in `fast` (`lib/krb5/krb/fast.c`); SPAKE lives in
//! `spake` (`plugins/preauth/spake/spake_client.c`).

use crate::error::Error;
use crate::preauth::{pa_pk_as_req_signed, pkinit_reply_key_agile};
use crate::transport::{KdcAddr, exchange};
use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt, krb_fx_cf2, p256_generate,
    string_to_key,
};
use krb5_types::{
    AsRep, AsReq, EncKdcRepPart, EncryptedData, EncryptionKey, EtypeInfo, EtypeInfo2, KdcOptions,
    KdcReq, KdcReqBody, KerberosTime, KrbError, MethodData, PaData, PaEncTsEnc, PrincipalName, err,
    flag_bit, ku, pa,
};
use sha1::{Digest, Sha1};
use std::time::Instant;
use zeroize::Zeroize;

mod fast;
mod spake;

pub use fast::FastArmor;
use fast::continue_fast;
pub(crate) use fast::fast_error_material;
use spake::{continue_spake, refuse_spake_combo, refuse_spake_skip};

/// Successful AS exchange: TGT plus session key.
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
    /// RFC 6806 FAST negotiation: the enc-padata carried PA-FX-FAST, so the KDC
    /// supports FAST (MIT records `fast_avail` in the ccache).
    pub fast_avail: bool,
    /// The AS-REQ itself was FAST-armored.
    pub used_fast: bool,
    /// The preauth type that produced the reply (selected_preauth_type,
    /// recorded as the ccache `pa_type` config); `None` without preauth.
    pub pa_type: Option<i32>,
}

/// Parameters for an AS-REQ.
pub struct AsRequest<'a> {
    /// Client name (without realm).
    pub cname: PrincipalName,
    /// Realm.
    pub realm: &'a str,
    /// Password octets (UTF-8).
    pub password: &'a [u8],
    /// KDC address.
    pub kdc: &'a KdcAddr,
    /// Use PA-SPAKE (151, P-256) instead of PA-ENC-TIMESTAMP.
    pub want_spake: bool,
    /// FAST armor (PA-FX-FAST). Inner preauth is still enc-timestamp.
    pub fast_armor: Option<&'a FastArmor>,
    /// PKINIT identity. Empty 150 first; PA-16 on the retry with the hint token.
    pub pkinit: Option<&'a PkinitClient>,
    /// RFC 6806 canonicalize (NT-ENTERPRISE client names).
    pub canonicalize: bool,
    /// Optional AS sname (default `krbtgt/REALM`). `kadmin/changepw` for kpasswd.
    pub sname: Option<&'a PrincipalName>,
    /// AS-REQ etype list. `None` is [`EncryptionType::preferred`]. `kinit` passes `krb5.conf`.
    pub etypes: Option<&'a [i32]>,
    /// Lifetime, renewable life, and KDC option flags (`kinit -l/-r/-f/-p/-a`).
    pub ticket: AsTicketOpts,
}

/// AS-REQ ticket policy from `kinit` flags.
#[derive(Clone, Debug)]
pub struct AsTicketOpts {
    /// Ticket lifetime in seconds (`-l`). `None` is 24 hours
    /// MIT `krb5_init_creds_init` (`get_in_tkt.c:936-947`): same check.
    pub lifetime: Option<u64>,
    /// Renewable lifetime in seconds (`-r`).
    pub rlife: Option<u64>,
    /// Request `forwardable` (MIT default true here).
    pub forwardable: bool,
    /// Request `proxiable`.
    pub proxiable: bool,
    /// Host addresses (`-a`). `None` omits the field.
    pub addresses: Option<krb5_types::HostAddresses>,
    /// `kinit -n`: REQUEST_ANONYMOUS + unsigned PKINIT.
    pub anonymous: bool,
    /// Seconds from now (`kinit -s`). `None` or 0 omits `from`.
    pub starttime: Option<u64>,
}

/// MIT `verify_as_reply` (`get_in_tkt.c:207-272`): Request times/options compares to EncKDCRepPart.
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
        }
    }
}

/// RFC 4556 client certificate + trust anchor for PKINIT.
pub struct PkinitClient {
    /// Leaf certificate (DER).
    pub cert: Vec<u8>,
    /// P-256 scalar matching `cert`.
    pub key: [u8; 32],
    /// CA certificate used to verify the KDC CMS (DER).
    pub ca_cert: Vec<u8>,
}

impl Drop for PkinitClient {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Obtain a TGT. Sends a bare AS-REQ first; if the KDC requires preauth,
/// MIT `sort_krb5_padata_sequence` (`get_in_tkt.c:403-471`): walks the hint list in order and runs
/// the first mechanism we can (SPAKE before enc-timestamp when both are
/// advertised).
///
/// # Errors
///
/// Returns transport, crypto, or `KRB-ERROR` failures.
pub fn as_exchange(req: &AsRequest<'_>) -> Result<AsOutcome, Error> {
    wrap_as(req, &[])
}

/// [`as_exchange`] using long-term keys (keytab).
///
/// # Errors
///
/// Transport, key, or a KDC error.
pub fn as_exchange_with_keys(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
) -> Result<AsOutcome, Error> {
    wrap_as(req, keys)
}

/// AS-REQ using long-term keys (keytab), not a password.
///
/// # Errors
///
/// Transport, key, or a KDC error.
pub fn as_exchange_key(
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
            want_spake: false,
            fast_armor: None,
            pkinit: None,
            canonicalize: false,
            sname: None,
            etypes: None,
            ticket: AsTicketOpts::default(),
        },
        keys,
    )
}

fn wrap_as(req: &AsRequest<'_>, keys: &[ProtocolKey]) -> Result<AsOutcome, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(correlation_id.clone());
    let started = Instant::now();
    let result = as_exchange_inner(req, keys);
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

/// MIT `restart_init_creds_loop` (`get_in_tkt.c:807-813`): optimistic preauth is sent only when the caller supplied a preauth list.
/// The default first request therefore carries no module padata, and a preauth-required hint is what selects the real mechanism.
fn as_exchange_inner(req: &AsRequest<'_>, keys: &[ProtocolKey]) -> Result<AsOutcome, Error> {
    let _ = krb5_types::try_ascii(req.realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?;
    refuse_spake_combo(req)?;
    let etypes: Vec<i32> = match req.etypes {
        Some(e) if !e.is_empty() => e.to_vec(),
        _ => EncryptionType::preferred()
            .iter()
            .map(|e| e.to_iana())
            .collect(),
    };
    let nonce = random_nonce()?;
    let (bound, _) = ticket_body(req);

    if req.fast_armor.is_some() {
        return continue_fast(req, keys, nonce, &bound, &etypes);
    }
    if req.pkinit.is_some() || req.ticket.anonymous {
        return continue_pkinit(req, nonce, &bound, &etypes);
    }
    // MIT `restart_init_creds_loop` (`get_in_tkt.c:807-813`): MIT only sets `optimistic_padata` when the
    // app called `krb5_get_init_creds_opt_set_preauth_list`. Default
    // kinit (even with `preferred_preauth_types = 151`) first-shots
    // empty module padata — `info_pa_permitted` 150/149 only — and
    // gets PREAUTH_REQUIRED 25. After that hint, `k5_preauth` plus
    // `sort_krb5_padata_sequence` picks the first runnable real type
    // (`continue_from_hint`). `--spake` still forces SPAKE.
    let first = build_as_req_from(req, nonce, &bound, None, &etypes)?;
    let wire = encode(&first)?;
    let reply = exchange(req.kdc, &wire)?;

    match classify(&reply)? {
        KdcMsg::AsRep(rep) => {
            refuse_spake_skip(req.want_spake)?;
            finish_as_rep_keys(
                rep,
                nonce,
                keys,
                req.password,
                &req.cname,
                req.realm,
                req.canonicalize,
                &req_sname(req),
                &bound,
                Some(&wire),
            )
        }
        KdcMsg::Error(e) if e.error_code == err::SKEW => {
            // First-reply SKEW: resync from KDC stime and retry the bare AS-REQ.
            let skew_time = e.stime.clone();
            let first = build_as_req_from(req, nonce, &bound, None, &etypes)?;
            let wire = encode(&first)?;
            let reply = exchange(req.kdc, &wire)?;
            match classify(&reply)? {
                KdcMsg::AsRep(rep) => {
                    refuse_spake_skip(req.want_spake)?;
                    finish_as_rep_keys(
                        rep,
                        nonce,
                        keys,
                        req.password,
                        &req.cname,
                        req.realm,
                        req.canonicalize,
                        &req_sname(req),
                        &bound,
                        Some(&wire),
                    )
                }
                KdcMsg::Error(e) if e.error_code == err::PREAUTH_REQUIRED => {
                    continue_from_hint(req, keys, nonce, &bound, &etypes, &e, Some(&skew_time))
                }
                KdcMsg::Error(e) => classify_kdc_error(&e),
                KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
            }
        }
        KdcMsg::Error(e) if req.want_spake && e.error_code == err::MORE_PREAUTH_DATA_REQUIRED => {
            continue_spake(req, keys, nonce, &bound, &etypes, &e)
        }
        KdcMsg::Error(e) if e.error_code == err::PREAUTH_REQUIRED => {
            continue_from_hint(req, keys, nonce, &bound, &etypes, &e, None)
        }
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

/// MIT `get_as_key_keytab` (`gic_keytab.c:68-71`): the reply etype selects the keytab key, and a wrong etype is not reused.
/// A checksum failure on that key is not final: every other supplied key is tried before the reply is rejected.
#[expect(clippy::too_many_arguments, reason = "client AS, not a params struct")]
fn finish_as_rep_keys(
    rep: AsRep,
    nonce: u32,
    keys: &[ProtocolKey],
    password: &[u8],
    cname: &PrincipalName,
    realm: &str,
    canonicalize: bool,
    expected_sname: &PrincipalName,
    bound: &AsReqTimes,
    req_der: Option<&[u8]>,
) -> Result<AsOutcome, Error> {
    if keys.is_empty() {
        return finish_as_rep(
            rep,
            nonce,
            None,
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
    let want = EncryptionType::known(rep.0.enc_part.etype).ok();
    if let Some(k) = pick_key(keys, want)
        && let Ok(out) = finish_as_rep(
            rep.clone(),
            nonce,
            Some(k),
            password,
            cname,
            realm,
            None,
            canonicalize,
            expected_sname,
            bound,
            req_der,
            false,
        )
    {
        return Ok(out);
    }
    let mut last = Error::ReplyMismatch("no keytab key decrypted AS-REP".into());
    for k in keys {
        match finish_as_rep(
            rep.clone(),
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
        ) {
            Ok(out) => return Ok(out),
            Err(e) => last = e,
        }
    }
    Err(last)
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

/// MIT `get_in_tkt.c` default when `preferred_preauth_types` is unset.
pub const DEFAULT_PREFERRED_PREAUTH_TYPES: &[i32] = &[17, 16, 15, 14];

/// `[libdefaults] preferred_preauth_types`, or MIT's PKINIT-first default.
#[must_use]
pub fn conf_preferred_preauth_types() -> Vec<i32> {
    match krb5_config::load_krb5_conf() {
        Some(c) if !c.preferred_preauth_types.is_empty() => c.preferred_preauth_types,
        _ => DEFAULT_PREFERRED_PREAUTH_TYPES.to_vec(),
    }
}

/// Bubble `preferred` types to the front, keeping the rest in hint order.
///
/// MIT `sort_krb5_padata_sequence` (`get_in_tkt.c:403-471`): same check.
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
    bound: &AsReqTimes,
    etypes: &[i32],
    err: &KrbError,
    skew_hint: Option<&KerberosTime>,
) -> Result<AsOutcome, Error> {
    if req.want_spake {
        return continue_spake(req, keys, nonce, bound, etypes, err);
    }
    let method = method_from_error(err)?;
    let preferred = conf_preferred_preauth_types();
    let sorted = sort_krb5_padata_sequence(&method, &preferred);
    for p in &sorted {
        match p.padata_type {
            pa::SPAKE => return continue_spake(req, keys, nonce, bound, etypes, err),
            pa::ENC_TIMESTAMP => {
                return continue_preauth(req, keys, nonce, bound, etypes, err, skew_hint);
            }
            _ => {}
        }
    }
    continue_preauth(req, keys, nonce, bound, etypes, err, skew_hint)
}

/// MIT `init_creds_step_reply` (`get_in_tkt.c:1727-1729`): the KDC time is what the next encrypted timestamp is built from.
/// A skew error is retried once at that time, and an unsupported etype is retried once as aes256; any other error is not another guess.
fn continue_preauth(
    req: &AsRequest<'_>,
    keys: &[ProtocolKey],
    nonce: u32,
    bound: &AsReqTimes,
    etypes: &[i32],
    preauth_err: &KrbError,
    skew_hint: Option<&KerberosTime>,
) -> Result<AsOutcome, Error> {
    let (etype, salt, params) =
        select_s2k(preauth_err, &salt_cname(&req.cname), req.realm, etypes)?;
    let client_key = pick_key(keys, Some(etype)).map_or_else(
        || string_to_key(etype, req.password, &salt, params.as_deref()),
        Ok,
    )?;
    let padata = vec![match skew_hint {
        Some(t) => pa_enc_timestamp_at(&client_key, t)?,
        None => pa_enc_timestamp(&client_key)?,
    }];
    let second = build_as_req_from(req, nonce, bound, Some(padata), etypes)?;
    let wire = encode(&second)?;
    let reply = exchange(req.kdc, &wire)?;
    match classify(&reply)? {
        KdcMsg::AsRep(rep) => finish_as_rep(
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
            Some(&wire),
            false,
        ),
        KdcMsg::Error(e) if e.error_code == err::SKEW => {
            let skew_time = e.stime.clone();
            let padata = vec![pa_enc_timestamp_at(&client_key, &skew_time)?];
            let third = build_as_req_from(req, nonce, bound, Some(padata), etypes)?;
            let wire = encode(&third)?;
            let reply = exchange(req.kdc, &wire)?;
            match classify(&reply)? {
                KdcMsg::AsRep(rep) => finish_as_rep(
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
                    Some(&wire),
                    false,
                ),
                KdcMsg::Error(e) => classify_kdc_error(&e),
                KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
            }
        }
        KdcMsg::Error(e) if e.error_code == err::ETYPE_NOSUPP => {
            let etypes = vec![EncryptionType::Aes256CtsHmacSha196.to_iana()];
            let padata = vec![pa_enc_timestamp(&client_key)?];
            let retry = build_as_req_from(req, nonce, bound, Some(padata), &etypes)?;
            let wire = encode(&retry)?;
            let reply = exchange(req.kdc, &wire)?;
            match classify(&reply)? {
                KdcMsg::AsRep(rep) => finish_as_rep(
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
                    Some(&wire),
                    false,
                ),
                KdcMsg::Error(e) => classify_kdc_error(&e),
                KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
            }
        }
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
}

/// Place a selected preauth module's PA-DATA after any FX-COOKIE and
/// before the `info_pa_permitted` pair (150/149).
///
/// MIT `k5_preauth` (`preauth2.c:992-1019`): copies the cookie first
/// MIT `init_creds_step_request` (`get_in_tkt.c:1365-1372`): then the module output; appends empty
/// PA-AS-FRESHNESS and PA-REQ-ENC-PA-REP after that.
pub fn insert_module_padata_before_info_pa(list: &mut Vec<PaData>, module_pa: PaData) {
    let at = list
        .iter()
        .position(|p| p.padata_type == pa::AS_FRESHNESS || p.padata_type == pa::REQ_ENC_PA_REP)
        .unwrap_or(list.len());
    list.insert(at, module_pa);
}

/// MIT `pkinit_as_req_create` (`pkinit_clnt.c:194-195`): the freshness token is placed in the auth pack when freshness is enabled.
/// The first request carries no PKINIT, and a reply that is not preauth-required or preauth-failed is not turned into an AuthPack.
fn continue_pkinit(
    req: &AsRequest<'_>,
    nonce: u32,
    bound: &AsReqTimes,
    etypes: &[i32],
) -> Result<AsOutcome, Error> {
    let pk = req
        .pkinit
        .ok_or_else(|| Error::ReplyMismatch("PKINIT identity missing".into()))?;
    let kp = p256_generate()?;
    // MIT get_in_tkt: empty 150 first, then copy the hint token into AuthPack.
    let first = build_as_req_from(req, nonce, bound, None, etypes)?;
    let first_wire = encode(&first)?;
    let first_reply = exchange(req.kdc, &first_wire)?;
    let (token, cookie) = match classify(&first_reply)? {
        KdcMsg::Error(e)
            if e.error_code == err::PREAUTH_REQUIRED || e.error_code == err::PREAUTH_FAILED =>
        {
            let method = method_from_error(&e)?;
            let token = find_pa(&method, pa::AS_FRESHNESS)
                .map(|p| p.padata_value.as_ref())
                .filter(|v| !v.is_empty())
                .map(<[u8]>::to_vec);
            (token, find_pa(&method, pa::FX_COOKIE).cloned())
        }
        KdcMsg::Error(e) => return classify_kdc_error(&e),
        KdcMsg::AsRep(_) | KdcMsg::TgsRep => {
            return Err(Error::ReplyMismatch("PKINIT expected METHOD-DATA".into()));
        }
    };
    let mut extra = Vec::new();
    if let Some(c) = cookie {
        extra.push(c);
    }
    let mut req2 = build_as_req_from(req, nonce, bound, Some(extra), etypes)?;
    let body_der = encode(&req2.0.req_body)?;
    let mut h = Sha1::new();
    h.update(&body_der);
    let sha1 = h.finalize();
    let anonymous = req.ticket.anonymous || krb5_types::pkinit::is_anonymous_principal(&req.cname);
    let pa = if anonymous {
        crate::preauth::pa_pk_as_req_unsigned(&kp.public, nonce, &sha1, token.as_deref())?
    } else {
        pa_pk_as_req_signed(
            &kp.public,
            &pk.cert,
            &pk.key,
            nonce,
            &sha1,
            token.as_deref(),
        )?
    };
    insert_module_padata_before_info_pa(req2.0.padata.get_or_insert_with(Vec::new), pa);
    let wire = encode(&req2)?;
    tracing::info!(
        event = "client.pkinit",
        component = "krb5-protocol",
        outcome = "ok",
        pa_type = pa::PK_AS_REQ,
        freshness = token.is_some(),
    );
    let reply = exchange(req.kdc, &wire)?;
    match classify(&reply)? {
        KdcMsg::AsRep(rep) => {
            let etype = EncryptionType::known(rep.0.enc_part.etype)?;
            let reply_key = pkinit_reply_key_agile(
                &kp.secret,
                &rep.0.padata,
                etype,
                &pk.ca_cert,
                &wire,
                &req.cname,
                req.realm,
            )?;
            finish_as_rep(
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
        }
        KdcMsg::Error(e) => classify_kdc_error(&e),
        KdcMsg::TgsRep => Err(Error::UnexpectedPdu),
    }
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

/// MIT `krb5int_fast_verify_nego` (`fast.c:648-664`): a ticket with the enc-pa-rep flag and no matching checksum over the request is not accepted.
/// The client name in the reply may differ only for an anonymous or canonicalized request.
#[expect(clippy::too_many_arguments, reason = "client AS, not a params struct")]
fn finish_as_rep(
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
    let plain = decrypt(&key, usage, inner.enc_part.cipher.as_ref()).map_err(|e| match e {
        krb5_crypto::Error::Integrity => Error::ReplyIntegrity,
        other => other.into(),
    })?;
    let enc_part = decode_enc_as(&plain)?;
    if enc_part.nonce != nonce {
        return Err(Error::NonceMismatch);
    }
    // MIT `krb5int_fast_verify_nego` (`fast.c:635-675`): a ticket with enc-pa-rep
    // must carry a PA-REQ-ENC-PA-REP checksum over the AS-REQ (the outer
    // request under FAST) under the reply key, else KRB5_KDCREP_MODIFIED.
    if let Some(rd) = req_der {
        crate::preauth::verify_req_enc_pa_rep(&enc_part, &key, rd)?;
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
        // Some KDCs omit INITIAL on service-ticket AS; require pre-authent when
        // we sent PA-ENC-TIMESTAMP (client_key is Some).
        if had_preauth && !enc_part.flags.pre_authent() {
            return Err(Error::ReplyMismatch("AS-REP missing PRE-AUTHENT".into()));
        }
    }
    let now = i64::from(KerberosTime::now().unix_seconds());
    let (skew, timesync) = krb5_config::load_krb5_conf()
        .map_or((300, true), |c| (i64::from(c.clockskew), c.kdc_timesync));
    check_as_rep_times_sync(&enc_part, now, skew, timesync)?;
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
    let fast_avail = enc_part.flags.enc_pa_rep()
        && enc_part
            .encrypted_pa_data
            .as_ref()
            .is_some_and(|v| v.iter().any(|p| p.padata_type == pa::FX_FAST));
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
    })
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
    let plain = decrypt(as_key, usage, enc.cipher.as_ref())?;
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

/// MIT `verify_as_reply` (`get_in_tkt.c:227-239`): verify_as_reply server half.
///
/// Always requires `enc.server == ticket.server` (name and realm).
/// `canon_req` (CANONICALIZE, NT-ENTERPRISE, or anonymous) plus both
/// names being TGS allows the issued TGS name to differ from the
/// request; otherwise `enc.server` must match the requested server.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] (`KRB5_KDCREP_MODIFIED`).
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

/// MIT `verify_as_reply` (`get_in_tkt.c:243-255`): verify_as_reply request-time half.
///
/// `till`/`rtime`/`from` of 0 are unspecified (MIT). `endtime` after `till`,
/// `renew_till` after `rtime` (RENEWABLE) or after `till` (RENEWABLE_OK
/// without RENEWABLE), or POSTDATED `from` ≠ starttime, is
/// `KRB5_KDCREP_MODIFIED`.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] (`KRB5_KDCREP_MODIFIED`).
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

/// MIT `verify_as_reply` (`get_in_tkt.c:260-270`): verify_as_reply time half.
///
/// Default `kdc_timesync` (1) skips starttime vs the local clock (MIT
/// then sets a per-context `time_offset`; we have no `krb5_context`).
/// `kdc_timesync = 0` is `KRB5_KDCREP_SKEW` when starttime (or authtime
/// if starttime is omitted) is outside skew.
///
/// # Errors
///
/// `kdc_timesync = 0` and starttime (or authtime) outside `skew` is
/// [`Error::ReplyMismatch`] (`KRB5_KDCREP_SKEW`). An expired `endtime`
/// in that mode is the same error class (stricter than MIT).
pub fn check_as_rep_times(enc_part: &EncKdcRepPart, now: i64, skew: i64) -> Result<(), Error> {
    let timesync = krb5_config::load_krb5_conf().is_none_or(|c| c.kdc_timesync);
    check_as_rep_times_sync(enc_part, now, skew, timesync)
}

/// [`check_as_rep_times`] with an explicit `kdc_timesync` flag.
pub(crate) fn check_as_rep_times_sync(
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
        return Err(Error::ReplyMismatch(
            "Clock skew too great in KDC reply".into(),
        ));
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
    let (_, addresses) = ticket_body(req);
    build_as_req(
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
    )
}

/// MIT `init_creds_step_request` (`get_in_tkt.c:1365-1372`): every request advertises an empty freshness token and an enc-pa-rep request.
/// Those two items are appended after the caller's padata, so a mechanism that replaces the list would drop the checksum the reply is checked against.
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
    // MIT `init_creds_step_request` (`get_in_tkt.c:1365-1372`): MIT info_pa_permitted: every AS-REQ advertises an
    // empty PA-AS-FRESHNESS then PA-REQ-ENC-PA-REP so the KDC echoes an
    // enc-pa-rep checksum (verified by krb5int_fast_verify_nego).
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

/// Etype list from `krb5.conf` (`default_tkt_enctypes` / `default_tgs_enctypes`).
#[must_use]
pub fn conf_etypes(tgs: bool) -> Vec<i32> {
    let preferred: Vec<i32> = EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect();
    let Some(conf) = krb5_config::load_krb5_conf() else {
        return preferred;
    };
    let names = if tgs && !conf.default_tgs_enctypes.is_empty() {
        &conf.default_tgs_enctypes
    } else if !tgs && !conf.default_tkt_enctypes.is_empty() {
        &conf.default_tkt_enctypes
    } else if !conf.permitted_enctypes.is_empty() {
        &conf.permitted_enctypes
    } else {
        return preferred;
    };
    let v: Vec<i32> = names
        .iter()
        .filter_map(|n| {
            EncryptionType::from_mit_name(n)
                .ok()
                .map(EncryptionType::to_iana)
        })
        .collect();
    if v.is_empty() { preferred } else { v }
}

/// MIT `set_request_times` (`get_in_tkt.c:711-722`): the start time is omitted unless the caller asked for one, and a renewable end is not requested before the ticket end.
/// Asking for a start time marks the request postdated, and omitting a renewable lifetime asks only for renewable-ok.
fn ticket_body(req: &AsRequest<'_>) -> (AsReqTimes, Option<krb5_types::HostAddresses>) {
    let now = KerberosTime::now();
    // MIT `set_request_times` (`get_in_tkt.c:711-714`): MIT omits `from` unless start_time != 0.
    // MIT `krb5_init_creds_init` (`get_in_tkt.c:932-934`): then sets ALLOW_POSTDATE | POSTDATED.
    let from = match req.ticket.starttime {
        Some(s) if s > 0 => now.add_seconds(i64::try_from(s).unwrap_or(i64::MAX)).ok(),
        _ => None,
    };
    let base = from.as_ref().unwrap_or(&now);
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
    if from.is_some() {
        opts = opts
            .with_bit(flag_bit::MAY_POSTDATE, true)
            .with_bit(flag_bit::POSTDATED, true);
    }
    // MIT `krb5_init_context_profile` (`init_ctx.c:265-267`): kdc_default_options = `KDC_OPT_RENEWABLE_OK`.
    // MIT `set_request_times` (`get_in_tkt.c:723-723`): clears it when `renew_life > 0` (RENEWABLE is set).
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
    // MIT `set_request_times` (`get_in_tkt.c:718-722`): don't ask for a smaller renewable time
    // than the lifetime (`rtime = from+renew_life; if till > rtime then
    // rtime = till`).
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
    (
        AsReqTimes {
            till,
            rtime,
            from,
            opts,
        },
        req.ticket.addresses.clone(),
    )
}

/// KDCOptions and optional `from` MIT `get_in_tkt.c` would set.
#[must_use]
pub fn as_init_creds_options(req: &AsRequest<'_>) -> (KdcOptions, Option<KerberosTime>) {
    let (t, _) = ticket_body(req);
    (t.opts, t.from)
}

fn pa_enc_timestamp(key: &ProtocolKey) -> Result<PaData, Error> {
    pa_enc_timestamp_at(key, &KerberosTime::now())
}

fn pa_enc_timestamp_at(key: &ProtocolKey, now: &KerberosTime) -> Result<PaData, Error> {
    let usec = now.0.timestamp_subsec_micros() % 1_000_000;
    let ts = PaEncTsEnc {
        patimestamp: now.clone(),
        pausec: Some(krb5_types::Microseconds::from_subsec_micros(usec)),
    };
    let der = encode(&ts)?;
    let usage = KeyUsage::new(ku::PA_ENC_TIMESTAMP)?;
    let cipher = encrypt(key, usage, &der)?;
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

type S2kMaterial = (EncryptionType, Vec<u8>, Option<Vec<u8>>);

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
    let default_salt = cname.default_salt(realm);
    let fallback = first_etype(etypes);
    let Some(edata) = &error.e_data else {
        return Ok((fallback, default_salt, None));
    };
    let method: MethodData = decode(edata.as_ref())?;
    for p in &method {
        if p.padata_type == pa::ETYPE_INFO2 {
            let info: EtypeInfo2 = decode(p.padata_value.as_ref())?;
            if let Some(found) = pick_info2(&info, &default_salt, etypes) {
                return Ok(found);
            }
        }
    }
    for p in &method {
        if p.padata_type == pa::ETYPE_INFO {
            let info: EtypeInfo = decode(p.padata_value.as_ref())?;
            if let Some(found) = pick_info(&info, &default_salt, etypes) {
                return Ok(found);
            }
        }
        if p.padata_type == pa::PW_SALT {
            return Ok((fallback, p.padata_value.as_ref().to_vec(), None));
        }
    }
    Ok((fallback, default_salt, None))
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

fn random_nonce() -> Result<u32, Error> {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|e| Error::transport_msg(e.to_string()))?;
    let n = u32::from_be_bytes(b) & 0x7fff_ffff;
    Ok(if n == 0 { 1 } else { n })
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
