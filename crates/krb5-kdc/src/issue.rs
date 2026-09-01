//! AS and TGS ticket issuance as functions over the principal store.

use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt, krb_fx_cf2, verify_checksum,
};
use krb5_protocol::{ReplayCache, ReplayKey};
use krb5_types::pac::{PacIdentity, parse_kerb_validation_info};
use krb5_types::{
    AsRep, AsReq, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, EncTicketPart, EncryptedData,
    EncryptionKey, EtypeInfo2, EtypeInfo2Entry, KdcReqBody, KerberosTime, KrbError, LastReqValue,
    MethodData, Microseconds, OctetString, PaData, PaEncTsEnc, PrincipalName, TgsRep, TgsReq,
    Ticket, TicketFlags, TransitedEncoding, err, flag_bit, ku, pa,
};

use crate::ad::{
    presented_tgt_logon, s4u2proxy_client, s4u2self_client, sign_pac, u2u_session, wrap_win2k_pac,
};
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::plugins::{PreauthAction, current_policy, run_as_preauth};
use crate::preauth::{
    FastOk, fast_finished, find_pa, make_cookie, unwrap_fast, unwrap_fast_padata, wrap_fast_rep,
};
use crate::store::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_POSTDATED, KDB_DISALLOW_PROXIABLE,
    KDB_DISALLOW_RENEWABLE, KDB_DISALLOW_SVR, KDB_DISALLOW_TGT_BASED, KDB_NO_AUTH_DATA_REQUIRED,
    KDB_OK_AS_DELEGATE, KDB_PWCHANGE_SERVICE, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PWCHANGE,
    Principal, random_key, s2k_params,
};

/// Issued AS-REP plus the session key (for tests that decrypt the TGT).
#[derive(Debug)]
pub struct IssuedAs {
    /// Wire AS-REP.
    pub rep: AsRep,
    /// Session key placed in the ticket and EncKDCRepPart.
    pub session_key: ProtocolKey,
    /// Key that encrypted the AS-REP enc-part (long-term, SPAKE, PKINIT, or FAST-strengthened).
    pub as_rep_key: ProtocolKey,
}

/// Issued TGS-REP plus the service session key.
#[derive(Debug)]
pub struct IssuedTgs {
    /// Wire TGS-REP.
    pub rep: TgsRep,
    /// Service session key.
    pub session_key: ProtocolKey,
}

/// Dispatch one UDP/TCP payload (AS-REQ or TGS-REQ) to the issue path.
///
/// Every request yields a byte reply: success PDU or KRB-ERROR. Crypto and
/// ASN.1 failures become `KDC_ERR_PREAUTH_FAILED` / generic KRB-ERROR.
///
/// # Errors
///
/// Only store-programming failures that cannot be encoded as KRB-ERROR.
pub fn handle_request(store: &dyn PrincipalRead, raw: &[u8]) -> Result<Vec<u8>, Error> {
    let id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(id);
    let started = Instant::now();
    krb5_protocol::capture_pdu("kdc-req", raw);
    let result = handle_inner(store, raw);
    if let Ok(bytes) = &result {
        krb5_protocol::capture_pdu("kdc-rep", bytes);
    }
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => tracing::info!(
            event = krb5_log::events::KDC_ISSUE,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            duration_us,
            outcome = "ok",
        ),
        Err(e) => tracing::error!(
            event = krb5_log::events::KDC_ISSUE,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            duration_us,
            outcome = "error",
            error = %e,
        ),
    }
    result
}

fn handle_inner(store: &dyn PrincipalRead, raw: &[u8]) -> Result<Vec<u8>, Error> {
    if raw.is_empty() {
        return Ok(encode_krb_error(
            store,
            err::GENERIC,
            Some("empty"),
            None,
            None,
        ));
    }
    match raw[0] {
        0x6a => match decode::<AsReq>(raw) {
            Ok(req) => as_reply(store, &req, raw),
            Err(_) => Ok(encode_krb_error(
                store,
                err::GENERIC,
                Some("asn1"),
                None,
                None,
            )),
        },
        0x6c => match decode::<TgsReq>(raw) {
            Ok(req) => tgs_reply(store, &req, raw),
            Err(_) => Ok(encode_krb_error(
                store,
                err::GENERIC,
                Some("asn1"),
                None,
                None,
            )),
        },
        _ => Ok(encode_krb_error(
            store,
            err::BAD_PVNO,
            Some("unexpected PDU"),
            None,
            None,
        )),
    }
}

fn as_reply(store: &dyn PrincipalRead, req: &AsReq, raw: &[u8]) -> Result<Vec<u8>, Error> {
    let body = Some(&req.0.req_body);
    match issue_as_from(store, req, Some(raw)) {
        Ok(issued) => Ok(encode(&issued.rep)?),
        Err(Error::PreauthRequired { e_data }) => Ok(encode_krb_error(
            store,
            err::PREAUTH_REQUIRED,
            None,
            Some(e_data),
            body,
        )),
        Err(Error::Protocol { code, text, e_data }) => {
            Ok(encode_krb_error(store, code, text.as_deref(), e_data, body))
        }
        Err(Error::Crypto(_)) => Ok(encode_krb_error(
            store,
            err::PREAUTH_FAILED,
            Some("preauth"),
            None,
            body,
        )),
        Err(Error::Asn1(_)) => Ok(encode_krb_error(
            store,
            err::GENERIC,
            Some("asn1"),
            None,
            body,
        )),
        Err(e) => Ok(encode_krb_error(
            store,
            err::GENERIC,
            Some(&e.to_string()),
            None,
            body,
        )),
    }
}

fn tgs_reply(store: &dyn PrincipalRead, req: &TgsReq, raw: &[u8]) -> Result<Vec<u8>, Error> {
    let body = Some(&req.0.req_body);
    match issue_tgs_from(store, req, Some(raw)) {
        Ok(issued) => Ok(encode(&issued.rep)?),
        Err(Error::Protocol { code, text, e_data }) => {
            Ok(encode_krb_error(store, code, text.as_deref(), e_data, body))
        }
        Err(Error::Crypto(_)) => Ok(encode_krb_error(
            store,
            err::BAD_INTEGRITY,
            Some("integrity"),
            None,
            body,
        )),
        Err(Error::Asn1(_)) => Ok(encode_krb_error(
            store,
            err::GENERIC,
            Some("asn1"),
            None,
            body,
        )),
        Err(e) => Ok(encode_krb_error(
            store,
            err::GENERIC,
            Some(&e.to_string()),
            None,
            body,
        )),
    }
}

/// Issue an AS-REP for `req`, or [`Error::PreauthRequired`].
///
/// # Errors
///
/// Unknown client, bad preauth, or crypto/DER failures.
pub fn issue_as(store: &dyn PrincipalRead, req: &AsReq) -> Result<IssuedAs, Error> {
    issue_as_from(store, req, None)
}

fn issue_as_from(
    store: &dyn PrincipalRead,
    req: &AsReq,
    raw: Option<&[u8]>,
) -> Result<IssuedAs, Error> {
    let outer = &req.0.req_body;
    let fast = unwrap_fast(store, req)?;
    let inner_owned: Option<KdcReqBody> = match fast.as_ref() {
        Some(f) => Some(decode(&f.inner_body)?),
        None => None,
    };
    let body = inner_owned.as_ref().unwrap_or(outer);
    issue_as_body(store, req, raw, body, fast.as_ref())
        .map_err(|e| wrap_as_fast(store, fast.as_ref(), e, body))
}

fn issue_as_body(
    store: &dyn PrincipalRead,
    req: &AsReq,
    raw: Option<&[u8]>,
    body: &KdcReqBody,
    fast: Option<&FastOk>,
) -> Result<IssuedAs, Error> {
    if let Some(f) = fast {
        check_fast_options(&f.fast_options)?;
    }
    if utf8_realm(&body.realm) != store.realm() {
        return Err(proto(err::C_PRINCIPAL_UNKNOWN, "wrong realm"));
    }
    if body.kdc_options.unsupported_bits() != 0 {
        return Err(proto(err::BADOPTION, "unsupported KDCOptions"));
    }
    let req_cname = body
        .cname
        .clone()
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, "no cname"))?;
    let client = store
        .fetch_name(&req_cname)?
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, "unknown client"))?;
    let cname = if req_cname.name_type == PrincipalName::NT_ENTERPRISE
        || body.kdc_options.bit(flag_bit::CANONICALIZE)
    {
        client.name.clone()
    } else {
        req_cname.clone()
    };
    let mut fails = store.fail_auth_of(&client);
    let max_fail = store.max_fail_for(&client);
    let last_failed = store.last_failed_of(&client);
    let now = crate::store::unix_now_u32();
    let (interval, duration) = store
        .named_policy_for(&client)
        .map_or((0, 0), |p| (p.pw_failcnt_interval, p.pw_lockout_duration));
    if interval > 0 && last_failed > 0 && now >= last_failed.saturating_add(interval) {
        store.clear_as_fail_count(&client.name);
        fails = 0;
    }
    let count_locked = max_fail > 0 && fails >= max_fail;
    let in_lockout_window =
        duration == 0 || (last_failed > 0 && now < last_failed.saturating_add(duration));
    if client.locked || (count_locked && in_lockout_window) {
        return Err(proto(err::CLIENT_REVOKED, "locked"));
    }
    current_policy().check_as(store, &client)?;
    let etype = select_etype(&body.etype, &client, store.policy().allow_weak_crypto)?;
    let ckey = client
        .key_for(etype)
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, "no client key"))?;
    let encoded_body;
    let body_der: &[u8] = if let Some(slice) = raw.and_then(kdc_req_body_der) {
        slice
    } else {
        encoded_body = encode(body)?;
        &encoded_body
    };
    let work_padata = if let Some(f) = fast {
        Some(f.inner_padata.clone())
    } else {
        req.0.padata.clone()
    };
    let pa_body: &[u8] = match fast {
        Some(f) => f.inner_body.as_slice(),
        None => body_der,
    };

    let mut extra_padata: Vec<PaData> = vec![supported_enctypes_pa(&client)];
    let mut as_rep_key = ckey.key.clone();
    let mut skip_timestamp = false;
    let mut hw_preauth = false;
    let as_req_der = match raw {
        Some(r) => r.to_vec(),
        None => encode(req)?,
    };
    match run_as_preauth(
        store,
        &client,
        work_padata.as_deref(),
        &ckey.key,
        etype,
        &as_req_der,
        pa_body,
        &cname,
    )? {
        Some(PreauthAction::Pkinit { key, pa }) => {
            as_rep_key = key;
            extra_padata.push(pa);
            skip_timestamp = true;
            hw_preauth = true;
        }
        Some(PreauthAction::Challenge(e_data)) => {
            return Err(Error::Protocol {
                code: err::MORE_PREAUTH_DATA_REQUIRED,
                text: Some("SPAKE challenge".into()),
                e_data: Some(e_data),
            });
        }
        Some(PreauthAction::SpakeDone(k)) => {
            as_rep_key = k;
            skip_timestamp = true;
        }
        Some(PreauthAction::EncTsOk) => {
            skip_timestamp = true;
        }
        None => {}
    }
    if !skip_timestamp
        && let Some(f) = fast
        && let Some(blob) = find_pa(Some(&f.inner_padata), pa::ENCRYPTED_CHALLENGE)
        && !blob.is_empty()
    {
        match verify_encrypted_challenge(store, &client, &ckey.key, &f.armor_key, blob) {
            Ok(()) => {
                store.record_as_outcome(&cname, true);
                skip_timestamp = true;
                extra_padata.push(kdc_encrypted_challenge(&f.armor_key, &ckey.key)?);
            }
            Err(e) => {
                store.record_as_outcome(&cname, false);
                return Err(e);
            }
        }
    }
    if client.requires_preauth && !skip_timestamp {
        return Err(preauth_required(store, &client));
    }
    if attr(&client, KDB_REQUIRES_HW_AUTH) && !hw_preauth {
        return Err(proto(err::PREAUTH_FAILED, "NO HW PREAUTH"));
    }

    let sname = body
        .sname
        .clone()
        .unwrap_or_else(|| PrincipalName::krbtgt(store.realm()));
    let server = store
        .fetch_name(&sname)?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "unknown server"))?;
    let skey = server
        .key_for(etype)
        .or_else(|| server.best_key())
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no server key"))?;
    check_db_times(Some(&client), &server)?;
    check_as_policy_flags(&client, &server, body)?;
    if let Some(from) = &body.from
        && from.unix_seconds() > body.till.unix_seconds()
    {
        return Err(proto(err::NEVER_VALID, "from after till"));
    }
    let session = random_key(etype)?;
    let now = KerberosTime::now();
    let mut starttime = now.clone();
    let mut flags = TicketFlags::initial_preauth();
    if body.kdc_options.bit(flag_bit::FORWARDABLE) {
        flags = flags.with_bit(flag_bit::FORWARDABLE, true);
    }
    if body.kdc_options.bit(flag_bit::PROXIABLE) {
        flags = flags.with_bit(flag_bit::PROXIABLE, true);
    }
    if body.kdc_options.bit(flag_bit::RENEWABLE) {
        flags = flags.with_bit(flag_bit::RENEWABLE, true);
    }
    if body.kdc_options.bit(flag_bit::MAY_POSTDATE) {
        flags = flags.with_bit(flag_bit::MAY_POSTDATE, true);
    }
    if let Some(from) = &body.from
        && from.unix_seconds() > now.unix_seconds()
        && body.kdc_options.bit(flag_bit::POSTDATED)
    {
        starttime = from.clone();
        flags = flags
            .with_bit(flag_bit::POSTDATED, true)
            .with_bit(flag_bit::INVALID, true);
    }
    flags = apply_disallow_flags(flags, Some(&client), &server);
    let life = requested_life(store, &client, body, &starttime);
    let end = starttime
        .add_seconds(i64::try_from(life).unwrap_or(i64::MAX))
        .or_else(|_| starttime.add_hours(10))
        .map_err(|_| proto(err::NEVER_VALID, "endtime"))?;
    let include_pac = !attr(&server, KDB_NO_AUTH_DATA_REQUIRED);
    let krbtgt_p = store
        .fetch_krbtgt()?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let krbtgt_key = krbtgt_p
        .best_key()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let pac_kdc = if sname.is_krbtgt_for(store.realm()) {
        skey.key.clone()
    } else {
        krbtgt_key.key.clone()
    };
    let ticket = mint_ticket(
        &skey.key,
        skey.kvno,
        skey.etype,
        &session,
        store.realm(),
        &sname,
        store.realm(),
        &cname,
        &now,
        &end,
        flags.clone(),
        &pac_kdc,
        TransitedEncoding::empty(),
        renew_till_for(
            store,
            &now,
            &flags,
            Some(&client),
            Some(&server),
            body.rtime.as_ref(),
        ),
        store,
        include_pac,
        None,
        &starttime,
    )?;
    let renew_till = renew_till_for(
        store,
        &now,
        &flags,
        Some(&client),
        Some(&server),
        body.rtime.as_ref(),
    );
    let enc_part = enc_rep_part(
        &session,
        fast.map_or(body.nonce, |f| f.nonce),
        &now,
        &now,
        &starttime,
        &end,
        store.realm(),
        &sname,
        flags,
        renew_till,
    )?;
    let mut reply_key = as_rep_key.clone();
    let mut outer_padata = extra_padata;
    if let Some(f) = fast {
        let sk = random_key(etype)?;
        reply_key = krb_fx_cf2(&sk, &as_rep_key, b"strengthenkey", b"replykey")?;
        let finished = fast_finished(&f.armor_key, &ticket, &cname, store.realm())?;
        let inner = std::mem::take(&mut outer_padata);
        outer_padata = vec![wrap_fast_rep(
            &f.armor_key,
            inner,
            Some(&sk),
            f.nonce,
            Some(finished),
        )?];
    }
    let enc_der = encode(&EncAsRepPart(enc_part))?;
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART)?;
    let cipher = encrypt(&reply_key, usage, &enc_der)?;
    let kvno = if skip_timestamp {
        None
    } else {
        Some(ckey.kvno)
    };
    let padata = if outer_padata.is_empty() {
        None
    } else {
        Some(outer_padata)
    };
    let rep = AsRep(krb5_types::KdcRep {
        pvno: krb5_types::KdcRep::PVNO,
        msg_type: krb5_types::KdcRep::MSG_AS_REP,
        padata,
        crealm: ks(store.realm())?,
        cname,
        ticket,
        enc_part: EncryptedData {
            etype: reply_key.etype().to_iana(),
            kvno,
            cipher: cipher.into(),
        },
    });
    Ok(IssuedAs {
        rep,
        session_key: session,
        as_rep_key: reply_key,
    })
}

/// Issue a TGS-REP for `req` using the TGT in PA-TGS-REQ.
///
/// # Errors
///
/// Bad authenticator, unknown server, or crypto/DER failures.
pub fn issue_tgs(store: &dyn PrincipalRead, req: &TgsReq) -> Result<IssuedTgs, Error> {
    issue_tgs_from(store, req, None)
}

fn issue_tgs_from(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    raw: Option<&[u8]>,
) -> Result<IssuedTgs, Error> {
    let outer = &req.0.req_body;
    let encoded_body;
    let body_der: &[u8] = if let Some(slice) = raw.and_then(kdc_req_body_der) {
        slice
    } else {
        encoded_body = encode(outer)?;
        &encoded_body
    };
    let tgs_fast = unwrap_fast_padata(store, req.0.padata.as_deref(), body_der)?;
    let inner_owned: Option<KdcReqBody> = match tgs_fast.as_ref() {
        Some(f) => Some(decode(&f.inner_body)?),
        None => None,
    };
    let body = inner_owned.as_ref().unwrap_or(outer);
    issue_tgs_body(store, req, body, tgs_fast.as_ref(), body_der)
        .map_err(|e| wrap_as_fast(store, tgs_fast.as_ref(), e, body))
}

fn issue_tgs_body(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    body: &KdcReqBody,
    tgs_fast: Option<&FastOk>,
    body_der: &[u8],
) -> Result<IssuedTgs, Error> {
    if let Some(f) = tgs_fast {
        check_fast_options(&f.fast_options)?;
    }
    if body.kdc_options.unsupported_bits() != 0 {
        return Err(proto(err::BADOPTION, "unsupported KDCOptions"));
    }
    let tgs_padata = if let Some(f) = tgs_fast {
        Some(f.inner_padata.as_slice())
    } else {
        req.0.padata.as_deref()
    };
    let ap_raw = extract_pa_tgs(tgs_padata)
        .or_else(|| extract_pa_tgs(req.0.padata.as_deref()))
        .ok_or_else(|| proto(err::PREAUTH_FAILED, "no PA-TGS-REQ"))?;
    let ap: krb5_types::ApReq = decode(ap_raw.as_ref())?;
    if !ap.ticket.sname.is_krbtgt_for(store.realm()) {
        return Err(proto(err::NOT_US, "presented ticket is not a TGT"));
    }
    let tkt_etype = EncryptionType::from_iana(ap.ticket.enc_part.etype)
        .or_else(|_| EncryptionType::known(ap.ticket.enc_part.etype))?;
    let (enc_tkt, tgt_key, tgt_plain) = decrypt_presented_tgt(store, &ap, tkt_etype)?;
    let renew = body.kdc_options.bit(flag_bit::RENEW);
    let validate = body.kdc_options.bit(flag_bit::VALIDATE);
    if renew && validate {
        return Err(proto(err::BADOPTION, "RENEW with VALIDATE"));
    }
    check_ticket_times(store, &enc_tkt, renew, validate)?;
    let sess_etype = EncryptionType::from_iana(enc_tkt.key.keytype)
        .or_else(|_| EncryptionType::known(enc_tkt.key.keytype))?;
    let tgt_session = ProtocolKey::from_bytes(sess_etype, enc_tkt.key.keyvalue.as_ref())?;
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR)?;
    let auth_plain = decrypt(&tgt_session, auth_usage, ap.authenticator.cipher.as_ref())?;
    let authenticator: krb5_types::Authenticator = decode(&auth_plain)?;
    authenticator
        .cusec
        .validate()
        .map_err(|_| proto(err::GENERIC, "cusec"))?;
    if authenticator.cname != enc_tkt.cname {
        return Err(proto(err::BAD_INTEGRITY, "TGS authenticator mismatch"));
    }
    if let Some(ck) = &authenticator.cksum {
        let ck_usage = KeyUsage::new(ku::TGS_REQ_AUTH_CKSUM)?;
        verify_checksum(&tgt_session, ck_usage, body_der, ck.checksum.as_ref())
            .map_err(|_| proto(err::INAPP_CKSUM, "TGS req-body checksum"))?;
    } else {
        return Err(proto(
            err::INAPP_CKSUM,
            "TGS authenticator missing checksum",
        ));
    }
    let rkey = ReplayKey {
        client: format!(
            "{}@{}",
            authenticator.cname.components_joined(),
            utf8_realm(&enc_tkt.crealm)
        ),
        server: format!("krbtgt/{}@{}", store.realm(), store.realm()),
        ctime: authenticator.ctime.unix_seconds(),
        cusec: authenticator.cusec.get(),
        auth_hash: ReplayCache::hash_authenticator(ap.authenticator.cipher.as_ref()),
    };
    if store.tgs_replay().check_and_store(rkey) {
        return Err(proto(err::REPEAT, "TGS authenticator replay"));
    }
    let mut sname = body
        .sname
        .clone()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no sname"))?;
    let req_realm = utf8_realm(&body.realm).to_owned();
    if store.fetch_name(&sname)?.is_none() && req_realm != store.realm() {
        let referral =
            PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", req_realm.as_str()]);
        if store.fetch_name(&referral)?.is_some() {
            sname = referral;
        }
    }
    if (renew || validate) && sname != ap.ticket.sname {
        return Err(proto(err::BADOPTION, "RENEW/VALIDATE server mismatch"));
    }
    current_policy().check_tgs(store, &sname)?;
    let server = store
        .fetch_name(&sname)?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "unknown server"))?;
    let want = body
        .etype
        .iter()
        .find_map(|n| EncryptionType::from_iana_policy(*n, store.policy().allow_weak_crypto).ok());
    let skey = want
        .and_then(|e| server.key_for(e))
        .or_else(|| server.best_key())
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no server key"))?;
    let tgs_client = store.fetch_name(&enc_tkt.cname)?;
    // MIT TGS checks the server only; a valid TGT still issues after client expiry.
    check_db_times(None, &server)?;
    check_tgs_policy_flags(&server, body, ap.ticket.sname.is_krbtgt(), &enc_tkt)?;
    let mut ticket_cname = enc_tkt.cname.clone();
    let mut ticket_crealm = utf8_realm(&enc_tkt.crealm).to_owned();
    let mut evidence_logon = None;
    if let Some((user, realm)) = s4u2self_client(&tgt_session, tgs_padata)? {
        check_s4u2self_for_user(store, &user, &server)?;
        ticket_cname = user;
        ticket_crealm = realm;
    } else if let Some((cn, logon)) = s4u2proxy_client(store, req, &enc_tkt.cname, tgs_padata)? {
        ticket_cname = cn;
        evidence_logon = Some(logon);
    } else if let Some(logon) = presented_tgt_logon(&enc_tkt, &tgt_key, &tgt_plain, store.realm())?
    {
        evidence_logon = Some(logon);
    }
    let skip_transited = body.kdc_options.bit(flag_bit::DISABLE_TRANSITED_CHECK);
    let (tkt_key, tkt_kvno, tkt_etype) = match u2u_session(store, req)? {
        Some((k, kv, et)) => (k, kv, et),
        None => (skey.key.clone(), skey.kvno, skey.etype),
    };
    let mut transited = enc_tkt.transited.clone();
    // MIT `add_to_transited`: name the incoming TGT's server realm (the
    // previous hop) unless that realm is the client or the requested server.
    let prev_hop = utf8_realm(&ap.ticket.realm);
    let crealm = utf8_realm(&enc_tkt.crealm);
    if prev_hop != crealm && prev_hop != req_realm.as_str() {
        transited = transited.with_realm(prev_hop);
    }
    let transit_checked = store.policy().transit_allowed(
        utf8_realm(&enc_tkt.crealm),
        &req_realm,
        &transited.realms(),
    );
    if !skip_transited && !transit_checked && store.policy().reject_bad_transit {
        return Err(proto(err::PATH_NOT_ACCEPTED, "transited"));
    }
    let set_transited_flag = !skip_transited && transit_checked;
    let session = random_key(skey.etype)?;
    let now = KerberosTime::now();
    let authtime;
    let starttime;
    let mut end;
    let mut flags;
    let ticket_renew_till;
    if renew {
        if !enc_tkt.flags.renewable() {
            return Err(proto(err::BADOPTION, "TICKET NOT RENEWABLE"));
        }
        authtime = enc_tkt.authtime.clone();
        starttime = now.clone();
        let old_start = enc_tkt
            .starttime
            .clone()
            .unwrap_or_else(|| enc_tkt.authtime.clone());
        let old_life = enc_tkt.endtime.delta_seconds(&old_start).max(0);
        end = now.add_seconds(old_life).unwrap_or_else(|_| now.clone());
        if let Some(till) = &enc_tkt.renew_till
            && till.unix_seconds() < end.unix_seconds()
        {
            end = till.clone();
        }
        flags = enc_tkt.flags.clone().with_bit(flag_bit::INVALID, false);
        flags = apply_disallow_flags(flags, tgs_client.as_ref(), &server);
        if flags.renewable() {
            ticket_renew_till = enc_tkt.renew_till.clone();
        } else {
            ticket_renew_till = None;
        }
        if set_transited_flag {
            flags = flags.with_bit(flag_bit::TRANSITED_POLICY_CHECKED, true);
        }
    } else if validate {
        authtime = enc_tkt.authtime.clone();
        starttime = enc_tkt
            .starttime
            .clone()
            .unwrap_or_else(|| enc_tkt.authtime.clone());
        end = enc_tkt.endtime.clone();
        ticket_renew_till = enc_tkt.renew_till.clone();
        flags = enc_tkt.flags.clone().with_bit(flag_bit::INVALID, false);
        if set_transited_flag {
            flags = flags.with_bit(flag_bit::TRANSITED_POLICY_CHECKED, true);
        }
    } else {
        authtime = now.clone();
        starttime = now.clone();
        end = enc_tkt.endtime.clone();
        let life = requested_life(store, &server, body, &now);
        if let Ok(capped) = now.add_seconds(i64::try_from(life).unwrap_or(i64::MAX))
            && capped.unix_seconds() < end.unix_seconds()
        {
            end = capped;
        }
        flags = TicketFlags::none();
        if set_transited_flag {
            flags = flags.with_bit(flag_bit::TRANSITED_POLICY_CHECKED, true);
        }
        if enc_tkt.flags.pre_authent() {
            flags = flags.with_bit(flag_bit::PRE_AUTHENT, true);
        }
        if body.kdc_options.bit(flag_bit::FORWARDABLE) && enc_tkt.flags.forwardable() {
            flags = flags.with_bit(flag_bit::FORWARDABLE, true);
        }
        if body.kdc_options.bit(flag_bit::RENEWABLE) && enc_tkt.flags.renewable() {
            flags = flags.with_bit(flag_bit::RENEWABLE, true);
        }
        if body.kdc_options.bit(flag_bit::PROXIABLE) && enc_tkt.flags.proxiable() {
            flags = flags.with_bit(flag_bit::PROXIABLE, true);
        }
        flags = apply_disallow_flags(flags, tgs_client.as_ref(), &server);
        ticket_renew_till = renew_till_for(
            store,
            &now,
            &flags,
            tgs_client.as_ref(),
            Some(&server),
            body.rtime.as_ref(),
        );
    }
    if attr(&server, KDB_OK_AS_DELEGATE) {
        flags = flags.with_bit(flag_bit::OK_AS_DELEGATE, true);
    }
    let krbtgt_p = store
        .fetch_krbtgt()?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let krbtgt_key = krbtgt_p
        .best_key()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    // Referral TGT PAC 16/19/7 must be keyed with the inter-realm key
    // the foreign KDC holds (Windows TDO inbound), not the local krbtgt.
    let pac_kdc = if sname.is_krbtgt() && !sname.is_krbtgt_for(store.realm()) {
        tkt_key.clone()
    } else {
        krbtgt_key.key.clone()
    };
    let include_pac = !attr(&server, KDB_NO_AUTH_DATA_REQUIRED);
    let ticket = mint_ticket(
        &tkt_key,
        tkt_kvno,
        tkt_etype,
        &session,
        store.realm(),
        &sname,
        &ticket_crealm,
        &ticket_cname,
        &authtime,
        &end,
        flags.clone(),
        &pac_kdc,
        transited,
        ticket_renew_till.clone(),
        store,
        include_pac,
        evidence_logon.as_deref(),
        &starttime,
    )?;
    let enc_part = enc_rep_part(
        &session,
        tgs_fast.map_or(body.nonce, |f| f.nonce),
        &now,
        &authtime,
        &starttime,
        &end,
        store.realm(),
        &sname,
        flags,
        ticket_renew_till,
    )?;
    let enc_der = encode(&EncTgsRepPart(enc_part))?;
    let (enc_key, enc_usage) = if let Some(sub) = authenticator.subkey {
        let st = EncryptionType::from_iana(sub.keytype)
            .or_else(|_| EncryptionType::known(sub.keytype))?;
        (
            ProtocolKey::from_bytes(st, sub.keyvalue.as_ref())?,
            ku::TGS_REP_ENC_PART_SUBKEY,
        )
    } else {
        (tgt_session.clone(), ku::TGS_REP_ENC_PART)
    };
    let usage = KeyUsage::new(enc_usage)?;
    let cipher = encrypt(&enc_key, usage, &enc_der)?;
    let mut tgs_pa = Vec::new();
    if let Some(client_p) = store.fetch_name(&ticket_cname)? {
        tgs_pa.push(supported_enctypes_pa(&client_p));
    }
    let padata = if let Some(f) = tgs_fast {
        let finished = fast_finished(&f.armor_key, &ticket, &ticket_cname, &ticket_crealm)?;
        Some(vec![wrap_fast_rep(
            &f.armor_key,
            tgs_pa,
            None,
            f.nonce,
            Some(finished),
        )?])
    } else if tgs_pa.is_empty() {
        None
    } else {
        Some(tgs_pa)
    };
    let rep = TgsRep(krb5_types::KdcRep {
        pvno: krb5_types::KdcRep::PVNO,
        msg_type: krb5_types::KdcRep::MSG_TGS_REP,
        padata,
        crealm: ks(&ticket_crealm)?,
        cname: ticket_cname,
        ticket,
        enc_part: EncryptedData {
            etype: enc_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    });
    Ok(IssuedTgs {
        rep,
        session_key: session,
    })
}

fn requested_life(
    store: &dyn PrincipalRead,
    princ: &Principal,
    body: &krb5_types::KdcReqBody,
    origin: &KerberosTime,
) -> u64 {
    let till = u64::from(body.till.unix_seconds());
    let start = u64::from(origin.unix_seconds());
    let want = till.saturating_sub(start);
    let cap = if princ.max_life > 0 {
        princ.max_life.min(store.policy().max_life)
    } else {
        store.policy().max_life
    };
    if want == 0 { cap } else { want.min(cap) }
}

fn decrypt_presented_tgt(
    store: &dyn PrincipalRead,
    ap: &krb5_types::ApReq,
    tkt_etype: EncryptionType,
) -> Result<(EncTicketPart, ProtocolKey, Vec<u8>), Error> {
    let usage = KeyUsage::new(ku::TICKET)?;
    let cipher = ap.ticket.enc_part.cipher.as_ref();
    let kvno = ap.ticket.enc_part.kvno;
    let mut candidates: Vec<krb5_crypto::ProtocolKey> = Vec::new();
    if let Some(p) = store.fetch_krbtgt()?
        && let Some(v) = kvno
        && let Some(k) = p.key_for_kvno(tkt_etype, v)
    {
        candidates.push(k.key.clone());
    }
    candidates.extend(store.krbtgt_keys()?);
    let mut last = proto(err::BAD_INTEGRITY, "TGT decrypt");
    for key in &candidates {
        match decrypt(key, usage, cipher) {
            Ok(plain) => {
                if let Ok(part) = decode::<EncTicketPart>(&plain) {
                    return Ok((part, key.clone(), plain));
                }
            }
            Err(e) => last = Error::from(e),
        }
    }
    Err(last)
}

fn check_ticket_times(
    store: &dyn PrincipalRead,
    tkt: &EncTicketPart,
    renew: bool,
    validate: bool,
) -> Result<(), Error> {
    let now = KerberosTime::now();
    let skew = store.policy().skew;
    if validate {
        if !tkt.flags.invalid() {
            return Err(proto(err::BADOPTION, "VALIDATE VALID TICKET"));
        }
        let start = tkt.starttime.as_ref().unwrap_or(&tkt.authtime);
        if now.delta_seconds(start) < -skew {
            return Err(proto(err::TKT_NYV, "NOT_YET_VALID"));
        }
        if tkt.endtime.delta_seconds(&now) < -skew {
            return Err(proto(err::TKT_EXPIRED, "expired"));
        }
        return Ok(());
    }
    if tkt.flags.invalid() {
        return Err(proto(err::TKT_NYV, "INVALID"));
    }
    if let Some(start) = &tkt.starttime
        && now.delta_seconds(start) < -skew
    {
        return Err(proto(err::TKT_NYV, "not yet valid"));
    }
    if renew {
        if !tkt.flags.renewable() {
            return Err(proto(err::BADOPTION, "TICKET NOT RENEWABLE"));
        }
        match &tkt.renew_till {
            Some(till) if till.unix_seconds() <= now.unix_seconds() => {
                return Err(proto(err::TKT_EXPIRED, "renew_till"));
            }
            None => return Err(proto(err::TKT_EXPIRED, "renew_till")),
            Some(_) => {}
        }
        return Ok(());
    }
    if tkt.endtime.delta_seconds(&now) < -skew {
        return Err(proto(err::TKT_EXPIRED, "expired"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn mint_ticket(
    service_key: &ProtocolKey,
    kvno: u32,
    service_etype: EncryptionType,
    session: &ProtocolKey,
    srealm: &str,
    sname: &PrincipalName,
    crealm: &str,
    cname: &PrincipalName,
    authtime: &KerberosTime,
    endtime: &KerberosTime,
    flags: TicketFlags,
    kdc_key: &ProtocolKey,
    transited: TransitedEncoding,
    renew_till: Option<KerberosTime>,
    store: &dyn PrincipalRead,
    include_pac: bool,
    logon_override: Option<&[u8]>,
    starttime: &KerberosTime,
) -> Result<Ticket, Error> {
    let mut part = EncTicketPart {
        flags,
        key: encryption_key(session),
        crealm: ks(crealm)?,
        cname: cname.clone(),
        transited,
        authtime: authtime.clone(),
        starttime: Some(starttime.clone()),
        endtime: endtime.clone(),
        renew_till,
        caddr: None,
        authorization_data: None,
    };
    if include_pac {
        let placeholder = wrap_win2k_pac(&[0])?;
        part.authorization_data = Some(placeholder);
        let checksum_der = encode(&part)?;
        let ident = if let Some(b) = logon_override {
            let v = parse_kerb_validation_info(b)
                .map_err(|e| proto(err::BAD_INTEGRITY, &format!("PAC logon: {e}")))?;
            PacIdentity {
                sam: v.effective_name.value,
                realm: crealm.to_owned(),
                domain_sid: v.logon_domain_id,
                rid: v.user_id,
            }
        } else {
            store.pac_identity(cname, crealm)
        };
        let pac = sign_pac(
            cname,
            authtime.unix_seconds(),
            service_key,
            kdc_key,
            &checksum_der,
            &ident,
            logon_override,
        )?;
        part.authorization_data = Some(wrap_win2k_pac(&pac)?);
    }
    let der = encode(&part)?;
    let usage = KeyUsage::new(ku::TICKET)?;
    let cipher = encrypt(service_key, usage, &der)?;
    Ok(Ticket {
        tkt_vno: Ticket::VNO,
        realm: ks(srealm)?,
        sname: sname.clone(),
        enc_part: EncryptedData {
            etype: service_etype.to_iana(),
            kvno: Some(kvno),
            cipher: cipher.into(),
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn enc_rep_part(
    session: &ProtocolKey,
    nonce: u32,
    now: &KerberosTime,
    authtime: &KerberosTime,
    starttime: &KerberosTime,
    end: &KerberosTime,
    realm: &str,
    sname: &PrincipalName,
    flags: TicketFlags,
    renew_till: Option<KerberosTime>,
) -> Result<EncKdcRepPart, Error> {
    Ok(EncKdcRepPart {
        key: encryption_key(session),
        last_req: vec![LastReqValue {
            lr_type: 0,
            lr_value: now.clone(),
        }],
        nonce,
        key_expiration: None,
        flags,
        authtime: authtime.clone(),
        starttime: Some(starttime.clone()),
        endtime: end.clone(),
        renew_till,
        srealm: ks(realm)?,
        sname: sname.clone(),
        caddr: None,
        encrypted_pa_data: None,
    })
}

fn encryption_key(key: &ProtocolKey) -> EncryptionKey {
    EncryptionKey {
        keytype: key.etype().to_iana(),
        keyvalue: OctetString::from(key.as_bytes().to_vec()),
    }
}

fn supported_enctypes_pa(princ: &Principal) -> PaData {
    PaData {
        padata_type: pa::SUPPORTED_ENCTYPES,
        padata_value: princ
            .supported_enctypes_mask()
            .to_le_bytes()
            .to_vec()
            .into(),
    }
}

fn select_etype(
    requested: &[i32],
    princ: &Principal,
    allow_weak: bool,
) -> Result<EncryptionType, Error> {
    for n in requested {
        if let Ok(e) = EncryptionType::from_iana_policy(*n, allow_weak)
            && princ.key_for(e).is_some()
        {
            return Ok(e);
        }
    }
    Err(proto(err::ETYPE_NOSUPP, "no common etype"))
}

pub(crate) fn extract_enc_timestamp(padata: Option<&[PaData]>) -> Option<&OctetString> {
    padata?.iter().find_map(|p| {
        if p.padata_type == pa::ENC_TIMESTAMP {
            Some(&p.padata_value)
        } else {
            None
        }
    })
}

fn extract_pa_tgs(padata: Option<&[PaData]>) -> Option<&OctetString> {
    padata?.iter().find_map(|p| {
        if p.padata_type == pa::TGS_REQ {
            Some(&p.padata_value)
        } else {
            None
        }
    })
}

fn verify_encrypted_challenge(
    store: &dyn PrincipalRead,
    client: &Principal,
    long_term: &ProtocolKey,
    armor_key: &ProtocolKey,
    blob: &[u8],
) -> Result<(), Error> {
    let enc: EncryptedData = decode(blob)?;
    let chal = krb_fx_cf2(
        armor_key,
        long_term,
        b"clientchallengearmor",
        b"challengelongterm",
    )?;
    let usage = KeyUsage::new(ku::ENC_CHALLENGE_CLIENT)?;
    let plain = decrypt(&chal, usage, enc.cipher.as_ref())
        .map_err(|_| proto(err::PREAUTH_FAILED, "encrypted challenge"))?;
    let ts: PaEncTsEnc =
        decode(&plain).map_err(|_| proto(err::PREAUTH_FAILED, "encrypted challenge der"))?;
    if let Some(u) = ts.pausec {
        u.validate().map_err(|_| proto(err::GENERIC, "pausec"))?;
    }
    let now = i64::from(KerberosTime::now().unix_seconds());
    let then = i64::from(ts.patimestamp.unix_seconds());
    if (now - then).abs() > store.policy().skew {
        return Err(proto(err::SKEW, "encrypted challenge skew"));
    }
    let rkey = ReplayKey {
        client: client.id(),
        server: format!("krbtgt/{}@{}", store.realm(), store.realm()),
        ctime: ts.patimestamp.unix_seconds(),
        cusec: ts.pausec.map_or(0, Microseconds::get),
        auth_hash: ReplayCache::hash_authenticator(blob),
    };
    if store.pa_replay().check_and_store(rkey) {
        return Err(proto(err::REPEAT, "encrypted challenge replay"));
    }
    Ok(())
}

fn kdc_encrypted_challenge(
    armor_key: &ProtocolKey,
    long_term: &ProtocolKey,
) -> Result<PaData, Error> {
    let chal = krb_fx_cf2(
        armor_key,
        long_term,
        b"kdcchallengearmor",
        b"challengelongterm",
    )?;
    let ts = PaEncTsEnc {
        patimestamp: KerberosTime::now(),
        pausec: None,
    };
    let der = encode(&ts)?;
    let usage = KeyUsage::new(ku::ENC_CHALLENGE_KDC)?;
    let cipher = encrypt(&chal, usage, &der)?;
    let enc = EncryptedData {
        etype: chal.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    };
    Ok(PaData {
        padata_type: pa::ENCRYPTED_CHALLENGE,
        padata_value: encode(&enc)?.into(),
    })
}

pub(crate) fn verify_enc_timestamp(
    store: &dyn PrincipalRead,
    client: &Principal,
    key: &ProtocolKey,
    blob: &[u8],
) -> Result<(), Error> {
    let enc: EncryptedData = decode(blob)?;
    let usage = KeyUsage::new(ku::PA_ENC_TIMESTAMP)?;
    let plain = decrypt(key, usage, enc.cipher.as_ref())?;
    let ts: PaEncTsEnc = decode(&plain)?;
    if let Some(u) = ts.pausec {
        u.validate().map_err(|_| proto(err::GENERIC, "pausec"))?;
    }
    let now = i64::from(KerberosTime::now().unix_seconds());
    let then = i64::from(ts.patimestamp.unix_seconds());
    if (now - then).abs() > store.policy().skew {
        return Err(proto(err::SKEW, "PA-ENC-TIMESTAMP skew"));
    }
    let rkey = ReplayKey {
        client: client.id(),
        server: format!("krbtgt/{}@{}", store.realm(), store.realm()),
        ctime: ts.patimestamp.unix_seconds(),
        cusec: ts.pausec.map_or(0, Microseconds::get),
        auth_hash: ReplayCache::hash_authenticator(blob),
    };
    if store.pa_replay().check_and_store(rkey) {
        return Err(proto(err::REPEAT, "PA-ENC-TIMESTAMP replay"));
    }
    Ok(())
}

fn check_fast_options(opts: &krb5_types::fast::FastOptions) -> Result<(), Error> {
    // MIT UNSUPPORTED_CRITICAL_FAST_OPTIONS = 0xbfff0000 (RFC bits 0, 2..15).
    // Bit 1 (hide-client-names) is known in MIT; we refuse it (anonymous
    // cname in the AS reply is a non-goal) rather than issue silently.
    let n = opts.len().min(16);
    for i in 0..n {
        if opts[i] {
            return Err(proto(err::UNKNOWN_CRITICAL_FAST_OPTION, "FAST option"));
        }
    }
    Ok(())
}

fn wrap_as_fast(
    store: &dyn PrincipalRead,
    fast: Option<&FastOk>,
    err: Error,
    body: &KdcReqBody,
) -> Error {
    let Some(f) = fast else {
        return err;
    };
    let (code, text, inner_ed, as_preauth) = match err {
        Error::PreauthRequired { e_data } => {
            let mut method = decode::<MethodData>(&e_data).unwrap_or_default();
            method.retain(|p| p.padata_type != pa::FX_FAST && p.padata_type != pa::SPAKE);
            if !method
                .iter()
                .any(|p| p.padata_type == pa::ENCRYPTED_CHALLENGE)
            {
                method.insert(
                    0,
                    PaData {
                        padata_type: pa::ENCRYPTED_CHALLENGE,
                        padata_value: Vec::<u8>::new().into(),
                    },
                );
            }
            let inner = encode(&method).unwrap_or_default();
            (err::PREAUTH_REQUIRED, None, inner, Some(method))
        }
        Error::Protocol { code, text, e_data } => (code, text, e_data.unwrap_or_default(), None),
        Error::Crypto(_) => (
            err::PREAUTH_FAILED,
            Some("preauth".into()),
            Vec::new(),
            None,
        ),
        Error::Asn1(_) => (err::GENERIC, Some("asn1".into()), Vec::new(), None),
        other => (err::GENERIC, Some(other.to_string()), Vec::new(), None),
    };
    let inner_err = encode_krb_error(
        store,
        code,
        text.as_deref(),
        if inner_ed.is_empty() {
            None
        } else {
            Some(inner_ed)
        },
        Some(body),
    );
    let mut padata = vec![PaData {
        padata_type: pa::FX_ERROR,
        padata_value: inner_err.into(),
    }];
    match make_cookie(store, b"fast") {
        Ok(c) => padata.push(PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: c.into(),
        }),
        Err(e) => return e,
    }
    if let Some(method) = as_preauth {
        padata.extend(method);
    }
    match wrap_fast_rep(&f.armor_key, padata, None, f.nonce, None) {
        Ok(pa) => match encode(&vec![pa]) {
            Ok(outer) => {
                if code == err::PREAUTH_REQUIRED {
                    Error::PreauthRequired { e_data: outer }
                } else {
                    Error::Protocol {
                        code,
                        text,
                        e_data: Some(outer),
                    }
                }
            }
            Err(e) => e.into(),
        },
        Err(e) => e,
    }
}

fn preauth_required(store: &dyn PrincipalRead, client: &Principal) -> Error {
    let salt =
        krb5_types::KerberosString::try_from(String::from_utf8_lossy(&client.salt).as_ref()).ok();
    let mut info: EtypeInfo2 = Vec::new();
    for k in &client.keys {
        info.push(EtypeInfo2Entry {
            etype: k.etype.to_iana(),
            salt: salt.clone(),
            s2kparams: Some(s2k_params(k.etype).into()),
        });
    }
    let etype_info = PaData {
        padata_type: pa::ETYPE_INFO2,
        padata_value: encode(&info).map_or_else(|_| Vec::new().into(), Into::into),
    };
    let mut method: MethodData = crate::plugins::advertise_preauth(store, client);
    method.push(etype_info);
    let e_data = encode(&method).unwrap_or_default();
    Error::PreauthRequired { e_data }
}

fn encode_krb_error(
    store: &dyn PrincipalRead,
    code: i32,
    text: Option<&str>,
    e_data: Option<Vec<u8>>,
    body: Option<&krb5_types::KdcReqBody>,
) -> Vec<u8> {
    // MIT 1.22.2 echoes the request realm/sname (C_PRINCIPAL_UNKNOWN for a
    // foreign-realm AS-REQ, not WRONG_REALM).
    let realm_s = body
        .map(|b| utf8_realm(&b.realm).to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| store.realm().to_owned());
    let realm = match krb5_types::try_ascii(&realm_s) {
        Ok(r) => r,
        Err(_) => match krb5_types::try_ascii("INVALID") {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        },
    };
    let sname = if let Some(n) = body.and_then(|b| b.sname.clone()) {
        n
    } else {
        match PrincipalName::try_new(PrincipalName::NT_SRV_INST, ["krbtgt", realm_s.as_str()]) {
            Ok(n) => n,
            Err(_) => {
                match PrincipalName::try_new(PrincipalName::NT_SRV_INST, ["krbtgt", "INVALID"]) {
                    Ok(n) => n,
                    Err(_) => return Vec::new(),
                }
            }
        }
    };
    let pdu = KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: code,
        crealm: None,
        cname: None,
        realm,
        sname,
        e_text: text.and_then(|t| krb5_types::try_ascii(t).ok()),
        e_data: e_data.map(Into::into),
    };
    encode(&pdu).unwrap_or_default()
}

fn ks(s: &str) -> Result<krb5_types::KerberosString, Error> {
    krb5_types::try_ascii(s).map_err(|_| proto(err::GENERIC, "non-ascii realm"))
}

fn renew_till_for(
    store: &dyn PrincipalRead,
    now: &KerberosTime,
    flags: &TicketFlags,
    client: Option<&Principal>,
    server: Option<&Principal>,
    rtime: Option<&KerberosTime>,
) -> Option<KerberosTime> {
    if !flags.renewable() {
        return None;
    }
    let mut life = u64::MAX;
    let pol = store.policy();
    if pol.max_renewable_life_set {
        life = life.min(pol.max_renewable_life);
    }
    for p in [client, server].into_iter().flatten() {
        if p.max_renewable_life > 0 {
            life = life.min(p.max_renewable_life);
        }
    }
    if let Some(rt) = rtime {
        let want = u64::from(rt.unix_seconds()).saturating_sub(u64::from(now.unix_seconds()));
        if want > 0 {
            life = life.min(want);
        }
    }
    if life == u64::MAX {
        life = pol.max_renewable_life;
    }
    now.add_seconds(i64::try_from(life).unwrap_or(i64::MAX))
        .ok()
}

/// Wire KDC-REQ-BODY (EXPLICIT [4] contents) from an AS-REQ/TGS-REQ PDU.
/// FAST and TGS authenticator checksums must cover MIT's original DER.
fn kdc_req_body_der(raw: &[u8]) -> Option<&[u8]> {
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

fn take_der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (hlen, ln) = if first < 128 {
        (1usize, usize::from(first))
    } else if first == 0x81 && input.len() >= 3 {
        (2, usize::from(input[2]))
    } else if first == 0x82 && input.len() >= 4 {
        (3, usize::from(u16::from_be_bytes([input[2], input[3]])))
    } else {
        return None;
    };
    let start = 1 + hlen;
    let end = start.checked_add(ln)?;
    let inner = input.get(start..end)?;
    let rest = input.get(end..)?;
    Some((tag, inner, rest))
}

fn proto(code: i32, text: &str) -> Error {
    Error::Protocol {
        code,
        text: Some(text.to_owned()),
        e_data: None,
    }
}

/// MIT `kdc_process_s4u2self_req`: look up the impersonated client.
fn check_s4u2self_for_user(
    store: &dyn PrincipalRead,
    user: &PrincipalName,
    server: &Principal,
) -> Result<(), Error> {
    let for_p = store
        .fetch_name(user)?
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, "S4U2Self"))?;
    if for_p.locked || attr(&for_p, KDB_DISALLOW_ALL_TIX) {
        return Err(proto(err::CLIENT_REVOKED, "S4U2Self locked"));
    }
    check_db_times(Some(&for_p), server)
}

/// MIT `validate_as_request`: 0 = never; principal expiry before password expiry.
fn check_db_times(client: Option<&Principal>, server: &Principal) -> Result<(), Error> {
    let now = crate::store::unix_now_u32();
    if let Some(c) = client {
        if c.expiration != 0 && now > c.expiration {
            return Err(proto(err::NAME_EXP, "CLIENT EXPIRED"));
        }
        let needchange = attr(c, KDB_REQUIRES_PWCHANGE);
        let pw_lapsed = c.pw_expire != 0 && now > c.pw_expire;
        if (needchange || pw_lapsed) && server.attributes & KDB_PWCHANGE_SERVICE == 0 {
            return Err(proto(err::KEY_EXPIRED, "CLIENT KEY EXPIRED"));
        }
    }
    if server.expiration != 0 && now > server.expiration {
        return Err(proto(err::SERVICE_EXP, "SERVICE EXPIRED"));
    }
    Ok(())
}

fn attr(p: &Principal, bit: u32) -> bool {
    p.attributes & bit != 0
}

fn check_as_policy_flags(
    client: &Principal,
    server: &Principal,
    body: &krb5_types::KdcReqBody,
) -> Result<(), Error> {
    if attr(server, KDB_DISALLOW_ALL_TIX) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, "SERVICE LOCKED OUT"));
    }
    if attr(server, KDB_DISALLOW_SVR) && !body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) {
        return Err(proto(err::MUST_USE_USER2USER, "SERVICE NOT ALLOWED"));
    }
    if (body.kdc_options.bit(flag_bit::MAY_POSTDATE) || body.kdc_options.bit(flag_bit::POSTDATED))
        && (attr(client, KDB_DISALLOW_POSTDATED) || attr(server, KDB_DISALLOW_POSTDATED))
    {
        return Err(proto(err::CANNOT_POSTDATE, "POSTDATE NOT ALLOWED"));
    }
    Ok(())
}

fn check_tgs_policy_flags(
    server: &Principal,
    body: &krb5_types::KdcReqBody,
    header_is_tgt: bool,
    tkt: &EncTicketPart,
) -> Result<(), Error> {
    if attr(server, KDB_DISALLOW_ALL_TIX) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, "SERVER LOCKED OUT"));
    }
    if attr(server, KDB_DISALLOW_SVR) && !body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) {
        return Err(proto(err::MUST_USE_USER2USER, "SERVER NOT ALLOWED"));
    }
    if attr(server, KDB_DISALLOW_TGT_BASED) && header_is_tgt {
        return Err(proto(err::POLICY, "TGT BASED NOT ALLOWED"));
    }
    if attr(server, KDB_REQUIRES_HW_AUTH) && !tkt.flags.bit(flag_bit::HW_AUTHENT) {
        return Err(proto(err::GENERIC, "NO HW PREAUTH"));
    }
    if attr(server, KDB_DISALLOW_POSTDATED)
        && (body.kdc_options.bit(flag_bit::MAY_POSTDATE)
            || body.kdc_options.bit(flag_bit::POSTDATED))
    {
        return Err(proto(err::CANNOT_POSTDATE, "NON-POSTDATABLE TICKET"));
    }
    Ok(())
}

fn apply_disallow_flags(
    mut flags: TicketFlags,
    client: Option<&Principal>,
    server: &Principal,
) -> TicketFlags {
    let deny_fwd = attr(server, KDB_DISALLOW_FORWARDABLE)
        || client.is_some_and(|c| attr(c, KDB_DISALLOW_FORWARDABLE));
    if deny_fwd {
        flags = flags.with_bit(flag_bit::FORWARDABLE, false);
    }
    let deny_ren = attr(server, KDB_DISALLOW_RENEWABLE)
        || client.is_some_and(|c| attr(c, KDB_DISALLOW_RENEWABLE));
    if deny_ren {
        flags = flags.with_bit(flag_bit::RENEWABLE, false);
    }
    let deny_prx = attr(server, KDB_DISALLOW_PROXIABLE)
        || client.is_some_and(|c| attr(c, KDB_DISALLOW_PROXIABLE));
    if deny_prx {
        flags = flags.with_bit(flag_bit::PROXIABLE, false);
    }
    flags
}

fn utf8_realm(r: &krb5_types::Realm) -> &str {
    std::str::from_utf8(r.as_bytes()).unwrap_or("KERBER.TEST")
}
