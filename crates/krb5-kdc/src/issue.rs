//! AS and TGS ticket issuance as functions over the principal store.

use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    decrypt, encrypt, krb_fx_cf2, verify_checksum, EncryptionType, KeyUsage, ProtocolKey,
};
use krb5_protocol::{ReplayCache, ReplayKey};
use krb5_types::{
    err, flag_bit, ku, pa, AsRep, AsReq, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, EncTicketPart,
    EncryptedData, EncryptionKey, EtypeInfo2, EtypeInfo2Entry, KerberosTime, KrbError,
    LastReqValue, MethodData, Microseconds, OctetString, PaData, PaEncTsEnc, PrincipalName, TgsRep,
    TgsReq, Ticket, TicketFlags, TransitedEncoding,
};

use crate::ad::{s4u2proxy_client, s4u2self_client, sign_pac, u2u_session, wrap_win2k_pac};
use crate::error::Error;
use crate::preauth::{
    fast_finished, process_pkinit, process_spake, unwrap_fast, unwrap_fast_padata, wrap_fast_rep,
    SpakeStep,
};
use crate::store::{random_key, s2k_params, Principal, PrincipalStore};

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
pub fn handle_request(store: &PrincipalStore, raw: &[u8]) -> Result<Vec<u8>, Error> {
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

fn handle_inner(store: &PrincipalStore, raw: &[u8]) -> Result<Vec<u8>, Error> {
    if raw.is_empty() {
        return Ok(encode_krb_error(store, err::GENERIC, Some("empty"), None));
    }
    match raw[0] {
        0x6a => match decode::<AsReq>(raw) {
            Ok(req) => as_reply(store, &req, raw),
            Err(_) => Ok(encode_krb_error(store, err::GENERIC, Some("asn1"), None)),
        },
        0x6c => match decode::<TgsReq>(raw) {
            Ok(req) => tgs_reply(store, &req, raw),
            Err(_) => Ok(encode_krb_error(store, err::GENERIC, Some("asn1"), None)),
        },
        _ => Ok(encode_krb_error(
            store,
            err::BAD_PVNO,
            Some("unexpected PDU"),
            None,
        )),
    }
}

fn as_reply(store: &PrincipalStore, req: &AsReq, raw: &[u8]) -> Result<Vec<u8>, Error> {
    match issue_as_from(store, req, Some(raw)) {
        Ok(issued) => Ok(encode(&issued.rep)?),
        Err(Error::PreauthRequired { e_data }) => Ok(encode_krb_error(
            store,
            err::PREAUTH_REQUIRED,
            None,
            Some(e_data),
        )),
        Err(Error::Protocol { code, text, e_data }) => {
            Ok(encode_krb_error(store, code, text.as_deref(), e_data))
        }
        Err(Error::Crypto(_)) => Ok(encode_krb_error(
            store,
            err::PREAUTH_FAILED,
            Some("preauth"),
            None,
        )),
        Err(Error::Asn1(_)) => Ok(encode_krb_error(store, err::GENERIC, Some("asn1"), None)),
        Err(e) => Ok(encode_krb_error(
            store,
            err::GENERIC,
            Some(&e.to_string()),
            None,
        )),
    }
}

fn tgs_reply(store: &PrincipalStore, req: &TgsReq, raw: &[u8]) -> Result<Vec<u8>, Error> {
    match issue_tgs_from(store, req, Some(raw)) {
        Ok(issued) => Ok(encode(&issued.rep)?),
        Err(Error::Protocol { code, text, e_data }) => {
            Ok(encode_krb_error(store, code, text.as_deref(), e_data))
        }
        Err(Error::Crypto(_)) => Ok(encode_krb_error(
            store,
            err::BAD_INTEGRITY,
            Some("integrity"),
            None,
        )),
        Err(Error::Asn1(_)) => Ok(encode_krb_error(store, err::GENERIC, Some("asn1"), None)),
        Err(e) => Ok(encode_krb_error(
            store,
            err::GENERIC,
            Some(&e.to_string()),
            None,
        )),
    }
}

/// Issue an AS-REP for `req`, or [`Error::PreauthRequired`].
///
/// # Errors
///
/// Unknown client, bad preauth, or crypto/DER failures.
pub fn issue_as(store: &PrincipalStore, req: &AsReq) -> Result<IssuedAs, Error> {
    issue_as_from(store, req, None)
}

fn issue_as_from(
    store: &PrincipalStore,
    req: &AsReq,
    raw: Option<&[u8]>,
) -> Result<IssuedAs, Error> {
    let body = &req.0.req_body;
    if utf8_realm(&body.realm) != store.realm() {
        return Err(proto(err::WRONG_REALM, store.realm()));
    }
    if body.kdc_options.unsupported_bits() != 0 {
        return Err(proto(err::BADOPTION, "unsupported KDCOptions"));
    }
    let cname = body
        .cname
        .clone()
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, "no cname"))?;
    let client = store
        .get_name(&cname)
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, "unknown client"))?;
    if client.locked {
        return Err(proto(err::CLIENT_REVOKED, "locked"));
    }
    let etype = select_etype(&body.etype, client, store.policy.allow_weak_crypto)?;
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

    let fast = unwrap_fast(store, req)?;
    let work_padata = if let Some(ref f) = fast {
        Some(f.inner_padata.clone())
    } else {
        req.0.padata.clone()
    };

    let mut extra_padata: Vec<PaData> = vec![supported_enctypes_pa(client)];
    let mut as_rep_key = ckey.key.clone();
    let mut skip_timestamp = false;
    let as_req_der = match raw {
        Some(r) => r.to_vec(),
        None => encode(req)?,
    };
    if let Some((rk, pa_pk)) = process_pkinit(
        store,
        work_padata.as_deref(),
        etype,
        &as_req_der,
        &cname,
        store.realm(),
    )? {
        as_rep_key = rk;
        extra_padata.push(pa_pk);
        skip_timestamp = true;
    } else if let Some(step) =
        process_spake(store, client, work_padata.as_deref(), &ckey.key, body_der)?
    {
        match step {
            SpakeStep::Challenge(e_data) => {
                return Err(Error::Protocol {
                    code: err::MORE_PREAUTH_DATA_REQUIRED,
                    text: Some("SPAKE challenge".into()),
                    e_data: Some(e_data),
                });
            }
            SpakeStep::Done(k) => {
                as_rep_key = k;
                skip_timestamp = true;
            }
        }
    }
    if client.requires_preauth && !skip_timestamp {
        match extract_enc_timestamp(work_padata.as_deref()) {
            None => return Err(preauth_required(store, client)),
            Some(blob) => verify_enc_timestamp(store, client, &ckey.key, blob.as_ref())?,
        }
    }

    let sname = body
        .sname
        .clone()
        .unwrap_or_else(|| PrincipalName::krbtgt(store.realm()));
    let server = store
        .get_name(&sname)
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "unknown server"))?;
    let skey = server
        .key_for(etype)
        .or_else(|| server.best_key())
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no server key"))?;
    let session = random_key(etype)?;
    let now = KerberosTime::now();
    let life = requested_life(store, client, body);
    let end = now
        .add_seconds(i64::try_from(life).unwrap_or(i64::MAX))
        .or_else(|_| now.add_hours(10))
        .map_err(|_| proto(err::NEVER_VALID, "endtime"))?;
    let mut flags = TicketFlags::initial_preauth();
    if body.kdc_options.bit(flag_bit::FORWARDABLE) {
        flags = flags.with_bit(flag_bit::FORWARDABLE, true);
    }
    if body.kdc_options.bit(flag_bit::RENEWABLE) {
        flags = flags.with_bit(flag_bit::RENEWABLE, true);
    }
    let krbtgt_key = store
        .krbtgt()
        .and_then(|p| p.best_key())
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
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
        &krbtgt_key.key,
        TransitedEncoding::empty(),
        renew_till_for(store, &now, &flags),
        store,
        true,
    )?;
    let renew_till = renew_till_for(store, &now, &flags);
    let enc_part = enc_rep_part(
        &session,
        body.nonce,
        &now,
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
            body.nonce,
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
pub fn issue_tgs(store: &PrincipalStore, req: &TgsReq) -> Result<IssuedTgs, Error> {
    issue_tgs_from(store, req, None)
}

fn issue_tgs_from(
    store: &PrincipalStore,
    req: &TgsReq,
    raw: Option<&[u8]>,
) -> Result<IssuedTgs, Error> {
    let body = &req.0.req_body;
    if body.kdc_options.unsupported_bits() != 0 {
        return Err(proto(err::BADOPTION, "unsupported KDCOptions"));
    }
    let encoded_body;
    let body_der: &[u8] = if let Some(slice) = raw.and_then(kdc_req_body_der) {
        slice
    } else {
        encoded_body = encode(body)?;
        &encoded_body
    };
    let tgs_fast = unwrap_fast_padata(store, req.0.padata.as_deref(), body_der)?;
    let tgs_padata = if let Some(ref f) = tgs_fast {
        Some(f.inner_padata.as_slice())
    } else {
        req.0.padata.as_deref()
    };
    let ap_raw = extract_pa_tgs(tgs_padata)
        .or_else(|| extract_pa_tgs(req.0.padata.as_deref()))
        .ok_or_else(|| proto(err::PREAUTH_FAILED, "no PA-TGS-REQ"))?;
    let ap: krb5_types::ApReq = decode(ap_raw.as_ref())?;
    if !ap.ticket.sname.is_krbtgt_for(store.realm()) {
        return Err(proto(err::NO_TGT, "presented ticket is not a TGT"));
    }
    let tkt_etype = EncryptionType::from_iana(ap.ticket.enc_part.etype)
        .or_else(|_| EncryptionType::known(ap.ticket.enc_part.etype))?;
    let enc_tkt = decrypt_presented_tgt(store, &ap, tkt_etype)?;
    check_ticket_times(store, &enc_tkt)?;
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
    if store.tgs_replay.check_and_store(rkey) {
        return Err(proto(err::REPEAT, "TGS authenticator replay"));
    }
    let mut sname = body
        .sname
        .clone()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no sname"))?;
    let req_realm = utf8_realm(&body.realm).to_owned();
    if store.get_name(&sname).is_none() && req_realm != store.realm() {
        let referral =
            PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", req_realm.as_str()]);
        if store.get_name(&referral).is_some() {
            sname = referral;
        }
    }
    let server = store
        .get_name(&sname)
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "unknown server"))?;
    let want = body
        .etype
        .iter()
        .find_map(|n| EncryptionType::from_iana_policy(*n, store.policy.allow_weak_crypto).ok());
    let skey = want
        .and_then(|e| server.key_for(e))
        .or_else(|| server.best_key())
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no server key"))?;
    let mut ticket_cname = enc_tkt.cname.clone();
    let mut ticket_crealm = utf8_realm(&enc_tkt.crealm).to_owned();
    if let Some((user, realm)) = s4u2self_client(&tgt_session, tgs_padata)? {
        ticket_cname = user;
        ticket_crealm = realm;
    } else if let Some(cn) = s4u2proxy_client(store, req, &enc_tkt.cname, tgs_padata)? {
        ticket_cname = cn;
    }
    if utf8_realm(&enc_tkt.crealm) != store.realm() {
        for r in enc_tkt.transited.realms() {
            if store.policy.transited_reject.iter().any(|d| d == &r) {
                return Err(proto(err::PATH_NOT_ACCEPTED, &r));
            }
        }
    }
    let (tkt_key, tkt_kvno, tkt_etype) = if let Some((k, kv, et)) = u2u_session(store, req)? {
        (k, kv, et)
    } else {
        (skey.key.clone(), skey.kvno, skey.etype)
    };
    let mut transited = enc_tkt.transited.clone();
    let cross_realm = (sname.is_krbtgt() && !sname.is_krbtgt_for(store.realm()))
        || utf8_realm(&enc_tkt.crealm) != store.realm();
    // RFC 4120: transited lists intermediate realms, excluding the client's
    // realm and the ticket server realm. A first-hop referral from a local
    // TGT must stay empty; only an incoming foreign TGT names us.
    if utf8_realm(&enc_tkt.crealm) != store.realm() {
        transited = transited.with_realm(store.realm());
    }
    let session = random_key(skey.etype)?;
    let now = KerberosTime::now();
    let mut end = enc_tkt.endtime.clone();
    let life = requested_life(store, server, body);
    if let Ok(capped) = now.add_seconds(i64::try_from(life).unwrap_or(i64::MAX)) {
        if capped.unix_seconds() < end.unix_seconds() {
            end = capped;
        }
    }
    let mut flags = TicketFlags::none();
    if cross_realm {
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
    let krbtgt_key = store
        .krbtgt()
        .and_then(|p| p.best_key())
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    // Referral TGT PAC 16/19/7 must be keyed with the inter-realm key
    // the foreign KDC holds (Windows TDO inbound), not the local krbtgt.
    let pac_kdc = if sname.is_krbtgt() && !sname.is_krbtgt_for(store.realm()) {
        tkt_key.clone()
    } else {
        krbtgt_key.key.clone()
    };
    let include_pac = true;
    let ticket = mint_ticket(
        &tkt_key,
        tkt_kvno,
        tkt_etype,
        &session,
        store.realm(),
        &sname,
        &ticket_crealm,
        &ticket_cname,
        &now,
        &end,
        flags.clone(),
        &pac_kdc,
        transited,
        renew_till_for(store, &now, &flags),
        store,
        include_pac,
    )?;
    let renew_till = renew_till_for(store, &now, &flags);
    let enc_part = enc_rep_part(
        &session,
        body.nonce,
        &now,
        &end,
        store.realm(),
        &sname,
        flags,
        renew_till,
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
    if let Some(client_p) = store.get_name(&ticket_cname) {
        tgs_pa.push(supported_enctypes_pa(client_p));
    }
    let padata = if let Some(f) = tgs_fast {
        let finished = fast_finished(&f.armor_key, &ticket, &ticket_cname, &ticket_crealm)?;
        Some(vec![wrap_fast_rep(
            &f.armor_key,
            tgs_pa,
            None,
            body.nonce,
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

fn requested_life(store: &PrincipalStore, princ: &Principal, body: &krb5_types::KdcReqBody) -> u64 {
    let till = u64::from(body.till.unix_seconds());
    let now = u64::from(KerberosTime::now().unix_seconds());
    let want = till.saturating_sub(now);
    let cap = if princ.max_life > 0 {
        princ.max_life.min(store.policy.max_life)
    } else {
        store.policy.max_life
    };
    if want == 0 {
        cap
    } else {
        want.min(cap)
    }
}

fn decrypt_presented_tgt(
    store: &PrincipalStore,
    ap: &krb5_types::ApReq,
    tkt_etype: EncryptionType,
) -> Result<EncTicketPart, Error> {
    let usage = KeyUsage::new(ku::TICKET)?;
    let cipher = ap.ticket.enc_part.cipher.as_ref();
    let kvno = ap.ticket.enc_part.kvno;
    let mut candidates: Vec<&krb5_crypto::ProtocolKey> = Vec::new();
    if let Some(p) = store.krbtgt() {
        if let Some(v) = kvno {
            if let Some(k) = p.key_for_kvno(tkt_etype, v) {
                candidates.push(&k.key);
            }
        }
    }
    for key in store.krbtgt_keys() {
        candidates.push(key);
    }
    let mut last = proto(err::BAD_INTEGRITY, "TGT decrypt");
    for key in candidates {
        match decrypt(key, usage, cipher) {
            Ok(plain) => {
                if let Ok(part) = decode::<EncTicketPart>(&plain) {
                    return Ok(part);
                }
            }
            Err(e) => last = Error::from(e),
        }
    }
    Err(last)
}

fn check_ticket_times(store: &PrincipalStore, tkt: &EncTicketPart) -> Result<(), Error> {
    let now = KerberosTime::now();
    let skew = store.policy.skew;
    if tkt.flags.invalid() {
        return Err(proto(err::TKT_NYV, "INVALID"));
    }
    if let Some(start) = &tkt.starttime {
        if now.delta_seconds(start) < -skew {
            return Err(proto(err::TKT_NYV, "not yet valid"));
        }
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
    store: &PrincipalStore,
    include_pac: bool,
) -> Result<Ticket, Error> {
    let mut part = EncTicketPart {
        flags,
        key: encryption_key(session),
        crealm: ks(crealm)?,
        cname: cname.clone(),
        transited,
        authtime: authtime.clone(),
        starttime: Some(authtime.clone()),
        endtime: endtime.clone(),
        renew_till,
        caddr: None,
        authorization_data: None,
    };
    if include_pac {
        let placeholder = wrap_win2k_pac(&[0])?;
        part.authorization_data = Some(placeholder);
        let checksum_der = encode(&part)?;
        let ident = store.pac_identity(cname, crealm);
        let pac = sign_pac(
            cname,
            crealm,
            authtime.unix_seconds(),
            service_key,
            kdc_key,
            &checksum_der,
            &ident,
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
        authtime: now.clone(),
        starttime: Some(now.clone()),
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
        if let Ok(e) = EncryptionType::from_iana_policy(*n, allow_weak) {
            if princ.key_for(e).is_some() {
                return Ok(e);
            }
        }
    }
    Err(proto(err::ETYPE_NOSUPP, "no common etype"))
}

fn extract_enc_timestamp(padata: Option<&[PaData]>) -> Option<&OctetString> {
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

fn verify_enc_timestamp(
    store: &PrincipalStore,
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
    if (now - then).abs() > store.policy.skew {
        return Err(proto(err::SKEW, "PA-ENC-TIMESTAMP skew"));
    }
    let rkey = ReplayKey {
        client: client.id(),
        server: format!("krbtgt/{}@{}", store.realm(), store.realm()),
        ctime: ts.patimestamp.unix_seconds(),
        cusec: ts.pausec.map_or(0, Microseconds::get),
        auth_hash: ReplayCache::hash_authenticator(blob),
    };
    if store.pa_replay.check_and_store(rkey) {
        return Err(proto(err::REPEAT, "PA-ENC-TIMESTAMP replay"));
    }
    Ok(())
}

fn preauth_required(store: &PrincipalStore, client: &Principal) -> Error {
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
        padata_value: encode(&info).map(Into::into).unwrap_or_default(),
    };
    let mut method: MethodData = Vec::new();
    method.push(PaData {
        padata_type: pa::SPAKE,
        padata_value: OctetString::from(Vec::<u8>::new()),
    });
    if store.pkinit_ca.is_some() {
        method.push(PaData {
            padata_type: pa::PK_AS_REQ,
            padata_value: OctetString::from(Vec::<u8>::new()),
        });
        method.push(PaData {
            padata_type: pa::TD_DH_PARAMETERS,
            padata_value: krb5_types::pkinit::encode_td_dh_p256().into(),
        });
    }
    method.push(PaData {
        padata_type: pa::ENC_TIMESTAMP,
        padata_value: OctetString::from(Vec::<u8>::new()),
    });
    method.push(etype_info);
    let e_data = encode(&method).unwrap_or_default();
    Error::PreauthRequired { e_data }
}

fn encode_krb_error(
    store: &PrincipalStore,
    code: i32,
    text: Option<&str>,
    e_data: Option<Vec<u8>>,
) -> Vec<u8> {
    let realm = match krb5_types::try_ascii(store.realm()) {
        Ok(r) => r,
        Err(_) => match krb5_types::try_ascii("INVALID") {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        },
    };
    let sname = match PrincipalName::try_new(PrincipalName::NT_SRV_INST, ["krbtgt", store.realm()])
    {
        Ok(n) => n,
        Err(_) => match PrincipalName::try_new(PrincipalName::NT_SRV_INST, ["krbtgt", "INVALID"]) {
            Ok(n) => n,
            Err(_) => return Vec::new(),
        },
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
    store: &PrincipalStore,
    now: &KerberosTime,
    flags: &TicketFlags,
) -> Option<KerberosTime> {
    if !flags.renewable() {
        return None;
    }
    let life = i64::try_from(store.policy.max_renewable_life).unwrap_or(i64::MAX);
    now.add_seconds(life).ok()
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

fn utf8_realm(r: &krb5_types::Realm) -> &str {
    std::str::from_utf8(r.as_bytes()).unwrap_or("KERBER.TEST")
}
