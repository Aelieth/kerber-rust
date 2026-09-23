//! Shared KDC helpers (`kdc_util.c`, `addr_srch.c`, `rd_req_dec.c`,
//! `valid_times.c`, `authdata_dec.c`, `kdc_authdata.c`):
//! `kdc_process_tgs_req`, header ticket decrypt,
//! `validate_as_request`, session etype, `include_pac_p`, and the
//! small encoding helpers.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, cksumtype_is_coll_proof, cksumtype_is_known,
    decrypt, parse_enctype_list, verify_checksum_type,
};
use krb5_types::{
    AuthorizationData, AuthorizationDataValue, Checksum, EncTicketPart, EncryptionKey, HostAddress,
    HostAddresses, KdcReqBody, KerberosTime, OctetString, PaData, PrincipalName, TicketFlags, err,
    flag_bit, ku, pa,
};

use super::as_req::is_anonymous_principal;
use crate::der::take_der;
use crate::error::Error;
use crate::kdb::{PrincipalRead, lookup_principal_id};
use crate::kdb_dump::TL_LAST_ADMIN_UNLOCK;
use crate::preauth::{proto, proto_d};
use crate::status;
use crate::store::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_POSTDATED, KDB_DISALLOW_PROXIABLE,
    KDB_DISALLOW_RENEWABLE, KDB_DISALLOW_SVR, KDB_NO_AUTH_DATA_REQUIRED, KDB_OK_AS_DELEGATE,
    KDB_OK_TO_AUTH_AS_DELEGATE, KDB_PWCHANGE_SERVICE, KDB_REQUIRES_PWCHANGE, Principal,
};

pub(super) struct HeaderTgt {
    pub(super) ap: krb5_types::ApReq,
    pub(super) enc_tkt: EncTicketPart,
    pub(super) tgt_key: ProtocolKey,
    pub(super) session: ProtocolKey,
    pub(super) authenticator: krb5_types::Authenticator,
    pub(super) header_realm: String,
    pub(super) header_server: Principal,
}

pub(super) fn process_tgs_header(
    store: &dyn PrincipalRead,
    ap_raw: &[u8],
    body_der: &[u8],
    sender: Option<&HostAddress>,
) -> Result<HeaderTgt, Error> {
    let ap: krb5_types::ApReq = decode(ap_raw)?;
    if ap.ap_options.use_session_key() || ap.ap_options.wants_mutual() {
        return Err(proto(err::POLICY, status::PROCESS_TGS));
    }
    let header_realm = utf8_realm(&ap.ticket.realm)?.to_owned();
    let tkt_etype = EncryptionType::from_iana(ap.ticket.enc_part.etype)
        .or_else(|_| EncryptionType::known(ap.ticket.enc_part.etype))?;
    let (enc_tkt, tgt_key, _, header_server) = decrypt_presented_tgt(store, &ap, tkt_etype)?;
    let sess_etype = EncryptionType::from_iana(enc_tkt.key.keytype)
        .or_else(|_| EncryptionType::known(enc_tkt.key.keytype))?;
    let session = ProtocolKey::from_bytes(sess_etype, enc_tkt.key.keyvalue.as_ref())?;
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR)?;
    let auth_plain = decrypt(&session, auth_usage, ap.authenticator.cipher.as_ref())?;
    let authenticator: krb5_types::Authenticator = decode(&auth_plain)?;
    authenticator
        .cusec
        .validate()
        .map_err(|_| proto(err::GENERIC, status::PROCESS_TGS))?;
    let auth_realm = utf8_realm(&authenticator.crealm)?;
    let tkt_realm = utf8_realm(&enc_tkt.crealm)?;
    if !krb5_types::principal_compare(&authenticator.cname, auth_realm, &enc_tkt.cname, tkt_realm) {
        return Err(proto(err::BADMATCH, status::PROCESS_TGS));
    }
    // MIT rd_req_dec.c:536-540: after client compare, before FX-ARMOR.
    if let Some(remote) = sender
        && !address_search(remote, enc_tkt.caddr.as_ref())
    {
        return Err(proto(err::BADADDR, status::PROCESS_TGS));
    }
    // MIT rd_req_dec.c:627: times after BADMATCH/BADADDR.
    check_header_times_rd_req(store, &enc_tkt)?;
    // MIT kdc_util.c:217-229: after rd_req, before the authenticator checksum.
    match fx_armor_present(
        enc_tkt.authorization_data.as_deref(),
        authenticator.authorization_data.as_deref(),
    ) {
        Ok(true) => {
            return Err(proto_d(
                err::POLICY,
                status::PROCESS_TGS,
                "ticket valid only as FAST armor",
            ));
        }
        Ok(false) => {}
        Err(Error::Asn1(_)) => return Err(proto(err::GENERIC, status::PROCESS_TGS)),
        Err(e) => return Err(e),
    }
    if let Some(ck) = &authenticator.cksum {
        // MIT kdc_util.c:112-140 comp_cksum: unknown 15, not coll-proof 50,
        // verify fail 31. 1.22.2 sets CKSUM_NOT_COLL_PROOF on no row.
        if !cksumtype_is_known(ck.cksumtype) {
            return Err(proto(err::SUMTYPE_NOSUPP, status::PROCESS_TGS));
        }
        if !cksumtype_is_coll_proof(ck.cksumtype) {
            return Err(proto(err::INAPP_CKSUM, status::PROCESS_TGS));
        }
        let ck_usage = KeyUsage::new(ku::TGS_REQ_AUTH_CKSUM)?;
        verify_checksum_type(
            &session,
            ck_usage,
            body_der,
            ck.cksumtype,
            ck.checksum.as_ref(),
        )
        .map_err(|e| match e {
            krb5_crypto::Error::UnsupportedChecksum(_) | krb5_crypto::Error::BadChecksumSize => {
                proto(err::GENERIC, status::PROCESS_TGS)
            }
            _ => proto(err::BAD_INTEGRITY, status::PROCESS_TGS),
        })?;
    } else {
        return Err(proto(err::INAPP_CKSUM, status::PROCESS_TGS));
    }
    Ok(HeaderTgt {
        ap,
        enc_tkt,
        tgt_key,
        session,
        authenticator,
        header_realm,
        header_server,
    })
}

/// MIT `krb5_find_authdata` (`authdata_dec.c:115-181`): recurse into
/// IF-RELEVANT only; authenticator AD skips KDC-issued container types.
fn fx_armor_present(
    ticket_ad: Option<&[AuthorizationDataValue]>,
    authenticator_ad: Option<&[AuthorizationDataValue]>,
) -> Result<bool, Error> {
    if let Some(ad) = ticket_ad
        && find_authdata(ad, pa::AD_FX_ARMOR, false)?
    {
        return Ok(true);
    }
    if let Some(ad) = authenticator_ad
        && find_authdata(ad, pa::AD_FX_ARMOR, true)?
    {
        return Ok(true);
    }
    Ok(false)
}

fn find_authdata(
    in_ad: &[AuthorizationDataValue],
    ad_type: i32,
    from_ap_req: bool,
) -> Result<bool, Error> {
    for ad in in_ad {
        if ad.ad_type == pa::AD_IF_RELEVANT {
            let inner: AuthorizationData = decode(ad.ad_data.as_ref())?;
            if find_authdata(&inner, ad_type, from_ap_req)? {
                return Ok(true);
            }
            continue;
        }
        if from_ap_req
            && matches!(
                ad.ad_type,
                pa::AD_SIGNTICKET
                    | pa::AD_KDC_ISSUED
                    | pa::AD_WIN2K_PAC
                    | pa::AD_CAMMAC
                    | pa::AD_AUTH_INDICATOR
            )
        {
            continue;
        }
        if ad.ad_type == ad_type {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn omit_start_if_auth(
    start: &KerberosTime,
    auth: &KerberosTime,
) -> Option<KerberosTime> {
    let s = start.unix_seconds();
    (s != 0 && s != auth.unix_seconds()).then(|| start.clone())
}

pub(super) fn kdc_get_ticket_endtime(
    store: &dyn PrincipalRead,
    starttime: &KerberosTime,
    header_end: Option<&KerberosTime>,
    till: &KerberosTime,
    client: Option<&Principal>,
    server: &Principal,
) -> Result<KerberosTime, Error> {
    let start = starttime.unix_seconds();
    let till_s = till.unix_seconds();
    let header_s = header_end.map(KerberosTime::unix_seconds);
    let until = if till_s == 0 {
        header_s.unwrap_or(u32::MAX)
    } else {
        header_s.map_or(till_s, |h| till_s.min(h))
    };
    let mut life = i64::from(until.wrapping_sub(start).cast_signed());
    if until > start && life < 0 {
        life = i64::from(i32::MAX);
    }
    if let Some(c) = client
        && c.max_life > 0
    {
        life = life.min(i64::try_from(c.max_life).unwrap_or(i64::MAX));
    }
    if server.max_life > 0 {
        life = life.min(i64::try_from(server.max_life).unwrap_or(i64::MAX));
    }
    let realm = store.policy().max_life;
    if realm > 0 {
        life = life.min(i64::try_from(realm).unwrap_or(i64::MAX));
    }
    starttime
        .add_seconds(life)
        .or_else(|_| starttime.add_hours(10))
        .map_err(|_| proto(err::NEVER_VALID, status::UNKNOWN_REASON))
}

pub(super) fn decrypt_presented_tgt(
    store: &dyn PrincipalRead,
    ap: &krb5_types::ApReq,
    tkt_etype: EncryptionType,
) -> Result<(EncTicketPart, ProtocolKey, Vec<u8>, Principal), Error> {
    // MIT kdc_get_server_key (kdc_util.c:377-379): ticket->server, no fallback.
    let ticket_realm = utf8_realm(&ap.ticket.realm)?;
    let princ = store.fetch(&lookup_principal_id(&ap.ticket.sname, ticket_realm))?;
    let Some(p) = princ else {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::PROCESS_TGS));
    };
    if attr(&p, KDB_DISALLOW_ALL_TIX) || attr(&p, KDB_DISALLOW_SVR) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::PROCESS_TGS));
    }
    // MIT kdc_rd_ap_req: search_enctype = -1 only for a local TGS
    // (instance == ticket.server.realm), not every krbtgt/KDC-realm.
    let local_tgs = ap.ticket.sname.is_local_tgs_principal(ticket_realm);
    let search_enctype = if local_tgs { None } else { Some(tkt_etype) };
    let ticket_kvno = ap.ticket.enc_part.kvno.unwrap_or(0);
    let mut kvno = ticket_kvno;
    let mut tries = 3u32;
    let usage = KeyUsage::new(ku::TICKET)?;
    let cipher = ap.ticket.enc_part.cipher.as_ref();
    loop {
        let last = match find_server_key(store.policy(), &p, search_enctype, kvno) {
            Ok((key, found)) => {
                kvno = found;
                if let Ok(plain) = decrypt(&key, usage, cipher)
                    && let Ok(part) = decode::<EncTicketPart>(&plain)
                {
                    return Ok((part, key, plain, p.clone()));
                }
                proto(err::BAD_INTEGRITY, status::PROCESS_TGS)
            }
            Err(e) => e,
        };
        if ticket_kvno != 0 || kvno <= 1 || tries <= 1 {
            return Err(last);
        }
        kvno -= 1;
        tries -= 1;
    }
}

/// MIT `find_server_key` (`kdc_util.c:417-457`): `krb5_dbe_find_enctype(server,
/// enctype, -1, kvno ? kvno : -1)` (`:426-427`), so kvno 0 means any kvno and
/// keys outside `permitted_enctypes` are never chosen; a requested etype that
/// is not similar to the key's is `KRB5_KDB_NO_PERMITTED_KEY` (`:441-449`).
/// Either KDB code → 60 `PROCESS_TGS`.
pub(super) fn find_server_key(
    policy: &crate::store::Policy,
    p: &Principal,
    search_enctype: Option<EncryptionType>,
    kvno: u32,
) -> Result<(ProtocolKey, u32), Error> {
    // kvno -1 (any): MIT walks `key_data` in descending-kvno order and takes
    // the first permitted match, so the highest kvno holding one wins.
    let key = if kvno == 0 {
        let mut kvnos: Vec<u32> = p.keys.iter().map(|k| k.kvno).collect();
        kvnos.sort_unstable_by(|a, b| b.cmp(a));
        kvnos.dedup();
        kvnos
            .into_iter()
            .find_map(|v| policy.find_enctype(p, search_enctype, v).ok())
    } else {
        policy.find_enctype(p, search_enctype, kvno).ok()
    };
    let Some(k) = key else {
        return Err(proto(err::GENERIC, status::PROCESS_TGS));
    };
    if let Some(want) = search_enctype
        && want != k.etype
    {
        return Err(proto(err::GENERIC, status::PROCESS_TGS));
    }
    Ok((k.key.clone(), k.kvno))
}

/// MIT `krb5int_validate_times` inside `kdc_process_tgs_req` (PROCESS_TGS):
/// `kdc_rd_ap_req` → `krb5_rd_req_decoded_anyflag` → `rd_req_dec.c:627` →
/// `valid_times.c:44-51`, a header ticket with no `starttime` is judged by its
/// `authtime`.
fn check_header_times_rd_req(store: &dyn PrincipalRead, tkt: &EncTicketPart) -> Result<(), Error> {
    let now = KerberosTime::now();
    let skew = store.policy().skew;
    let start = tkt.starttime.as_ref().unwrap_or(&tkt.authtime);
    if now.delta_seconds(start) < -skew {
        return Err(proto(err::TKT_NYV, status::PROCESS_TGS));
    }
    if tkt.endtime.delta_seconds(&now) < -skew {
        return Err(proto(err::TKT_EXPIRED, status::PROCESS_TGS));
    }
    Ok(())
}

pub(super) fn include_pac_for_reply(
    store: &dyn PrincipalRead,
    server: &Principal,
    padata: Option<&[PaData]>,
    is_as_req: bool,
    subject_had_pac: bool,
    anonymous: bool,
) -> bool {
    if attr(server, KDB_NO_AUTH_DATA_REQUIRED) {
        return false;
    }
    if store.policy().disable_pac || anonymous {
        return false;
    }
    if is_as_req {
        include_pac_p(padata)
    } else {
        subject_had_pac
    }
}

fn include_pac_p(padata: Option<&[PaData]>) -> bool {
    let Some(raw) = padata.and_then(|ps| {
        ps.iter()
            .find(|p| p.padata_type == pa::PAC_REQUEST)
            .map(|p| p.padata_value.as_ref())
    }) else {
        return true;
    };
    decode::<krb5_types::PaPacRequest>(raw).map_or(true, |p| p.include_pac)
}

/// MIT `addr_srch.c:55-59`: NULL matches; a lone NetBIOS list is empty.
fn address_search(addr: &HostAddress, list: Option<&HostAddresses>) -> bool {
    let Some(list) = list else {
        return true;
    };
    if list.len() == 1 && list[0].addr_type == HostAddress::ADDRTYPE_NETBIOS {
        return true;
    }
    list.iter().any(|a| a == addr)
}

/// MIT `kdc_handle_protected_negotiation` (`kdc_util.c:1768-1806`).
pub(super) fn enc_pa_rep_padata(
    reply_key: &ProtocolKey,
    req_pkt: &[u8],
) -> Result<Vec<PaData>, Error> {
    let usage = KeyUsage::new(ku::AS_REQ)?;
    let mic = checksum(reply_key, usage, req_pkt)?;
    let ck = Checksum {
        cksumtype: reply_key.etype().checksum_type(),
        checksum: mic.into(),
    };
    Ok(vec![
        PaData {
            padata_type: pa::REQ_ENC_PA_REP,
            padata_value: encode(&ck)?.into(),
        },
        PaData {
            padata_type: pa::FX_FAST,
            padata_value: Vec::new().into(),
        },
    ])
}

pub(super) fn encryption_key(key: &ProtocolKey) -> EncryptionKey {
    EncryptionKey {
        keytype: key.etype().to_iana(),
        keyvalue: OctetString::from(key.as_bytes().to_vec()),
    }
}

/// `enctype_requires_etype_info_2` (`kdc_util.c:1663-1674`): every valid
/// enctype except des3-cbc-sha1/raw and rc4-hmac/exp.
pub(super) fn enctype_requires_etype_info_2(etype: i32) -> bool {
    matches!(
        EncryptionType::known(etype),
        Ok(e) if !matches!(e, EncryptionType::Des3CbcSha1 | EncryptionType::Rc4Hmac)
    )
}

/// MIT `dbentry_supports_enctype` (`kdc_util.c:1040-1077`): the
/// `session_enctypes` attribute when set, else aes256 or a *permitted*
/// long-term key of that etype at the highest kvno
/// (`krb5_dbe_find_enctype(server, enctype, -1, 0)`, `:1076`).
fn dbentry_supports_enctype(
    policy: &crate::store::Policy,
    server: &Principal,
    enctype: EncryptionType,
) -> bool {
    if let Some((_, raw)) = server
        .string_attrs
        .iter()
        .find(|(k, _)| k == "session_enctypes")
        && !raw.is_empty()
        && let Some(list) = parse_enctype_list(raw, policy.allow_weak_crypto)
    {
        return list.contains(&enctype);
    }
    enctype == EncryptionType::Aes256CtsHmacSha196
        || policy.find_enctype(server, Some(enctype), 0).is_ok()
}

pub(super) fn select_session_keytype(
    server: &Principal,
    requested: &[i32],
    policy: &crate::store::Policy,
) -> Result<EncryptionType, Error> {
    for n in requested {
        let Ok(e) = EncryptionType::known(*n) else {
            continue;
        };
        if !policy.etype_permitted(e) {
            continue;
        }
        if e == EncryptionType::Des3CbcSha1 && !policy.allow_des3 {
            continue;
        }
        if e == EncryptionType::Rc4Hmac && !policy.allow_rc4 {
            continue;
        }
        if dbentry_supports_enctype(policy, server, e) {
            return Ok(e);
        }
    }
    Err(proto(err::ETYPE_NOSUPP, status::BAD_ENCRYPTION_TYPE))
}

pub(super) fn ks(s: &str) -> Result<krb5_types::KerberosString, Error> {
    krb5_types::try_ascii(s).map_err(|_| proto(err::GENERIC, status::UNKNOWN_REASON))
}

/// Wire KDC-REQ-BODY (EXPLICIT [4] contents) from an AS-REQ/TGS-REQ PDU.
/// FAST and TGS authenticator checksums must cover MIT's original DER.
pub(super) fn kdc_req_body_der(raw: &[u8]) -> Option<&[u8]> {
    let (tag, app, _) = take_der(raw)?;
    if tag != 0x6a && tag != 0x6c {
        return None;
    }
    let (t, seq, _) = take_der(app)?;
    let body = if t == 0x30 { seq } else { app };
    let mut cur = body;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_der(cur)?;
        if tag == 0xa4 {
            return Some(inner);
        }
        cur = rest;
    }
    None
}

/// MIT `s4u2self_forwardable` (`kdc_util.c:1625-1644`).
pub(super) fn s4u2self_forwardable(
    server: &crate::store::Principal,
    flags: TicketFlags,
) -> TicketFlags {
    if attr(server, KDB_OK_TO_AUTH_AS_DELEGATE) || server.s4u_allowed_to.is_empty() {
        return flags;
    }
    flags.with_bit(flag_bit::FORWARDABLE, false)
}

/// MIT `check_anon` (`kdc_util.c:702-713`): restrict_anon + anonymous client
/// + non-local TGS → 12 `ANONYMOUS NOT ALLOWED`.
pub(super) fn check_anon(
    store: &dyn PrincipalRead,
    client: &PrincipalName,
    server: &PrincipalName,
) -> Result<(), Error> {
    if store.policy().restrict_anon
        && is_anonymous_principal(client)
        && !server.is_local_tgs_principal(store.realm())
    {
        return Err(proto(err::POLICY, status::ANONYMOUS_NOT_ALLOWED));
    }
    Ok(())
}

/// MIT `validate_as_request`: 0 = never; principal expiry before password expiry.
pub(super) fn check_db_times(client: Option<&Principal>, server: &Principal) -> Result<(), Error> {
    let now = crate::store::unix_now_u32();
    let pwchange_svc = server.attributes & KDB_PWCHANGE_SERVICE != 0;
    if let Some(c) = client {
        if c.expiration != 0 && now > c.expiration {
            return Err(proto(err::NAME_EXP, status::CLIENT_EXPIRED));
        }
        if c.pw_expire != 0 && now > c.pw_expire && !pwchange_svc {
            return Err(proto(err::KEY_EXPIRED, status::CLIENT_KEY_EXPIRED));
        }
    }
    if server.expiration != 0 && now > server.expiration {
        return Err(proto(err::SERVICE_EXP, status::SERVICE_EXPIRED));
    }
    // MIT checks REQUIRES_PWCHANGE after SERVICE EXPIRED, with its own status
    // (kdc_util.c:762-766); a lapsed pw_expire above is CLIENT KEY EXPIRED.
    if let Some(c) = client
        && attr(c, KDB_REQUIRES_PWCHANGE)
        && !pwchange_svc
    {
        return Err(proto(err::KEY_EXPIRED, status::REQUIRED_PWCHANGE));
    }
    Ok(())
}

pub(super) fn attr(p: &Principal, bit: u32) -> bool {
    p.attributes & bit != 0
}

fn last_admin_unlock(p: &Principal) -> u32 {
    // KRB5_TL_LAST_ADMIN_UNLOCK (0x0700): 4-byte LE unix timestamp.
    // MIT krb5_dbe_lookup_last_admin_unlock: absent or short TL → stamp 0
    // (kdb5.c:1539-1545,1574-1576). locked_check_p then !ts_after(last_failed, 0).
    p.tl_data
        .iter()
        .find(|t| t.ty == TL_LAST_ADMIN_UNLOCK)
        .and_then(|t| t.contents.get(..4))
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_le_bytes)
}

/// MIT `validate_as_request` (`kdc_util.c:716-800`): the AS policy checks in
/// MIT's order, run after the client/server lookups and before preauth
/// (`do_as_req.c:630` precedes `check_padata` at `:758`), so a preauth-required
/// client that trips a check gets that status, not NEEDED_PREAUTH. The
/// `krb5_db_check_policy_as` failcount lockout is the last check.
pub(super) fn validate_as_request(
    store: &dyn PrincipalRead,
    client: &Principal,
    server: &Principal,
    body: &krb5_types::KdcReqBody,
) -> Result<(), Error> {
    // MIT tests only AS_INVALID_OPTIONS here (kdc_util.c:727), the TGS-only
    // options FORWARDED/PROXY/RENEW/VALIDATE/ENC-TKT-IN-SKEY/CNAME-IN-ADDL-TKT.
    // It does not reject other unknown or reserved KDCOption bits; those pass
    // and take effect elsewhere or not at all (e.g. REQUEST_ANONYMOUS proceeds
    // to the reply-phase anonymous-principal check in issue_as_body).
    if body.kdc_options.as_invalid_bits() != 0 {
        return Err(proto(err::BADOPTION, status::INVALID_AS_OPTIONS));
    }
    let now = crate::store::unix_now_u32();
    let pwchange_svc = attr(server, KDB_PWCHANGE_SERVICE);
    if client.expiration != 0 && now > client.expiration {
        return Err(proto(err::NAME_EXP, status::CLIENT_EXPIRED));
    }
    if client.pw_expire != 0 && now > client.pw_expire && !pwchange_svc {
        return Err(proto(err::KEY_EXPIRED, status::CLIENT_KEY_EXPIRED));
    }
    if server.expiration != 0 && now > server.expiration {
        return Err(proto(err::SERVICE_EXP, status::SERVICE_EXPIRED));
    }
    if attr(client, KDB_REQUIRES_PWCHANGE) && !pwchange_svc {
        return Err(proto(err::KEY_EXPIRED, status::REQUIRED_PWCHANGE));
    }
    if (body.kdc_options.bit(flag_bit::MAY_POSTDATE) || body.kdc_options.bit(flag_bit::POSTDATED))
        && (attr(client, KDB_DISALLOW_POSTDATED) || attr(server, KDB_DISALLOW_POSTDATED))
    {
        return Err(proto(err::CANNOT_POSTDATE, status::POSTDATE_NOT_ALLOWED));
    }
    if attr(client, KDB_DISALLOW_ALL_TIX) {
        return Err(proto(err::CLIENT_REVOKED, status::CLIENT_LOCKED_OUT));
    }
    if attr(server, KDB_DISALLOW_ALL_TIX) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::SERVICE_LOCKED_OUT));
    }
    if attr(server, KDB_DISALLOW_SVR) {
        return Err(proto(err::MUST_USE_USER2USER, status::SERVICE_NOT_ALLOWED));
    }
    // kdc_util.c:795-798: check_anon uses request->server, not the S4U empty_server.
    let req_server = body
        .sname
        .clone()
        .unwrap_or_else(|| PrincipalName::krbtgt(store.realm()));
    check_anon(store, &client.name, &req_server)?;
    let mut fails = store.fail_auth_of(client);
    let max_fail = store.max_fail_for(client);
    let last_failed = store.last_failed_of(client);
    let (interval, duration) = store
        .named_policy_for(client)
        .map_or((0, 0), |p| (p.pw_failcnt_interval, p.pw_lockout_duration));
    if interval > 0 && last_failed > 0 && now >= last_failed.saturating_add(interval) {
        store.clear_as_fail_count(&client.name);
        fails = 0;
    }
    let count_locked = max_fail > 0 && fails >= max_fail;
    let in_lockout_window =
        duration == 0 || (last_failed > 0 && now < last_failed.saturating_add(duration));
    if last_failed <= last_admin_unlock(client) {
        return Ok(());
    }
    if count_locked && in_lockout_window {
        return Err(proto(err::CLIENT_REVOKED, status::CLIENT_LOCKED_OUT));
    }
    Ok(())
}

pub(super) fn get_ticket_flags(
    req: &krb5_types::KdcOptions,
    client: Option<&Principal>,
    server: &Principal,
    header: Option<&TicketFlags>,
) -> TicketFlags {
    if let Some(h) = header
        && (req.bit(flag_bit::VALIDATE) || req.bit(flag_bit::RENEW))
    {
        return h.clone().with_bit(flag_bit::INVALID, false);
    }
    // MIT kdc_util.h:500 OPTS2FLAGS, :529 COPY_TKT_FLAGS.
    let mut flags = TicketFlags::none()
        .with_bit(flag_bit::FORWARDABLE, req.bit(flag_bit::FORWARDABLE))
        .with_bit(flag_bit::FORWARDED, req.bit(flag_bit::FORWARDED))
        .with_bit(flag_bit::PROXIABLE, req.bit(flag_bit::PROXIABLE))
        .with_bit(flag_bit::PROXY, req.bit(flag_bit::PROXY))
        .with_bit(flag_bit::MAY_POSTDATE, req.bit(flag_bit::MAY_POSTDATE))
        .with_bit(flag_bit::POSTDATED, req.bit(flag_bit::POSTDATED))
        .with_bit(flag_bit::ANONYMOUS, req.bit(flag_bit::ANONYMOUS))
        .with_bit(flag_bit::ENC_PA_REP, true);
    if req.bit(flag_bit::POSTDATED) {
        flags = flags.with_bit(flag_bit::INVALID, true);
    }
    if let Some(h) = header {
        for bit in [
            flag_bit::FORWARDED,
            flag_bit::PROXY,
            flag_bit::PRE_AUTHENT,
            flag_bit::HW_AUTHENT,
            flag_bit::ANONYMOUS,
        ] {
            if h.bit(bit) {
                flags = flags.with_bit(bit, true);
            }
        }
        if attr(server, KDB_OK_AS_DELEGATE) {
            flags = flags.with_bit(flag_bit::OK_AS_DELEGATE, true);
        }
        if !h.proxiable() {
            flags = flags.with_bit(flag_bit::PROXIABLE, false);
        }
        if !h.forwardable() {
            flags = flags.with_bit(flag_bit::FORWARDABLE, false);
        }
        if !h.bit(flag_bit::ANONYMOUS) {
            flags = flags.with_bit(flag_bit::ANONYMOUS, false);
        }
    } else {
        flags = flags.with_bit(flag_bit::INITIAL, true);
    }
    if attr(server, KDB_DISALLOW_PROXIABLE)
        || client.is_some_and(|c| attr(c, KDB_DISALLOW_PROXIABLE))
    {
        flags = flags.with_bit(flag_bit::PROXIABLE, false);
    }
    if attr(server, KDB_DISALLOW_FORWARDABLE)
        || client.is_some_and(|c| attr(c, KDB_DISALLOW_FORWARDABLE))
    {
        flags = flags.with_bit(flag_bit::FORWARDABLE, false);
    }
    flags
}

#[expect(clippy::too_many_arguments, reason = "MIT passes args positionally")]
pub(super) fn kdc_get_ticket_renewtime(
    store: &dyn PrincipalRead,
    body: &KdcReqBody,
    header: Option<&EncTicketPart>,
    client: Option<&Principal>,
    server: &Principal,
    flags: &mut TicketFlags,
    starttime: &KerberosTime,
    endtime: &KerberosTime,
) -> Option<KerberosTime> {
    *flags = flags.clone().with_bit(flag_bit::RENEWABLE, false);
    if attr(server, KDB_DISALLOW_RENEWABLE)
        || client.is_some_and(|c| attr(c, KDB_DISALLOW_RENEWABLE))
    {
        return None;
    }
    if header.is_some_and(|h| !h.flags.renewable()) {
        return None;
    }
    let rtime = if body.kdc_options.bit(flag_bit::RENEWABLE) {
        body.rtime
            .clone()
            .unwrap_or_else(|| KerberosTime::from_unix_seconds(u32::MAX))
    } else if body.kdc_options.bit(flag_bit::RENEWABLE_OK)
        && body.till.unix_seconds() > endtime.unix_seconds()
    {
        body.till.clone()
    } else {
        return None;
    };
    let mut rsec = rtime.unix_seconds();
    if let Some(h) = header
        && let Some(till) = &h.renew_till
    {
        rsec = rsec.min(till.unix_seconds());
    }
    let mut max_rlife = server
        .max_renewable_life
        .min(store.policy().realm_max_renewable_life);
    if let Some(c) = client {
        max_rlife = max_rlife.min(c.max_renewable_life);
    }
    if let Ok(cap) = starttime.add_seconds(i64::try_from(max_rlife).unwrap_or(i64::MAX)) {
        rsec = rsec.min(cap.unix_seconds());
    }
    if !body.kdc_options.bit(flag_bit::RENEWABLE) && rsec <= endtime.unix_seconds() {
        return None;
    }
    *flags = flags.clone().with_bit(flag_bit::RENEWABLE, true);
    Some(KerberosTime::from_unix_seconds(rsec))
}

pub(super) fn utf8_realm(r: &krb5_types::Realm) -> Result<&str, Error> {
    std::str::from_utf8(r.as_bytes()).map_err(|_| proto(err::GENERIC, status::UNKNOWN_REASON))
}
