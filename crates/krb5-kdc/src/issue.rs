//! AS and TGS ticket issuance as functions over the principal store.

use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, cksumtype_is_coll_proof, cksumtype_is_known,
    decrypt, encrypt, krb_fx_cf2, parse_enctype_list, verify_checksum_type,
};
use krb5_protocol::{ReplayCache, ReplayKey};
use krb5_types::pac::{PacIdentity, parse_kerb_validation_info};
use krb5_types::{
    AsRep, AsReq, AuthorizationData, AuthorizationDataValue, Checksum, EncKdcRepPart,
    EncTgsRepPart, EncTicketPart, EncryptedData, EncryptionKey, EtypeInfo, EtypeInfo2,
    EtypeInfo2Entry, EtypeInfoEntry, KdcReqBody, KerberosString, KerberosTime, KrbError,
    LastReqValue, MethodData, Microseconds, OctetString, PaData, PaEncTsEnc, PrincipalName, TgsRep,
    TgsReq, Ticket, TicketFlags, TransitedEncoding, err, flag_bit, ku, pa,
};

use crate::ad::{
    S4u2Self, SecondTicket, check_s4u2proxy_policy, check_tgs_s4u2proxy, make_s4u2self_rep,
    pac_client_info_eq, process_s4u2self_req, rbcd_pac_client, update_delegation_info, with_status,
    wrap_win2k_pac,
};
use crate::error::Error;
use crate::kdb::{PrincipalRead, lookup_principal_id};
use crate::kdb_dump::TL_LAST_ADMIN_UNLOCK;
use crate::plugins::{PreauthAction, current_policy, run_as_preauth};
use crate::preauth::{
    FastOk, decode_edata_padata, fast_finished, find_pa, make_cookie, prepare_as_edata, proto,
    proto_d, unwrap_fast, unwrap_fast_tgs, with_fx_cookie, wrap_fast_rep,
};
use crate::status;
use crate::store::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_POSTDATED,
    KDB_DISALLOW_PROXIABLE, KDB_DISALLOW_RENEWABLE, KDB_DISALLOW_SVR, KDB_DISALLOW_TGT_BASED,
    KDB_NO_AUTH_DATA_REQUIRED, KDB_OK_AS_DELEGATE, KDB_OK_TO_AUTH_AS_DELEGATE,
    KDB_PWCHANGE_SERVICE, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PWCHANGE, KeyEntry, Principal,
    random_key,
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
/// Empty, undecodable, and unknown-tag datagrams yield an empty reply
/// (MIT `dispatch.c` + `net-server.c` drop). Other failures are a KRB-ERROR.
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
    if let Ok((bytes, _)) = &result {
        krb5_protocol::capture_pdu("kdc-rep", bytes);
    }
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match result {
        Ok((bytes, detail)) => {
            if bytes.is_empty() {
                return Ok(bytes);
            }
            if bytes.starts_with(&[0x7e]) {
                let (code, mut e_text) = krb_error_log_fields(&bytes);
                if code == err::PREAUTH_REQUIRED && e_text.is_empty() {
                    e_text = "NEEDED_PREAUTH".into();
                }
                log_krb_error(duration_us, code, &e_text, detail.as_deref());
            } else {
                tracing::info!(
                    event = krb5_log::events::KDC_ISSUE,
                    correlation_id = krb5_log::current_correlation_id(),
                    component = "krb5-kdc",
                    duration_us,
                    outcome = "ok",
                );
            }
            Ok(bytes)
        }
        Err(e) => {
            tracing::error!(
                event = krb5_log::events::KDC_ISSUE,
                correlation_id = krb5_log::current_correlation_id(),
                component = "krb5-kdc",
                duration_us,
                outcome = "error",
                error = %e,
            );
            Err(e)
        }
    }
}

fn log_krb_error(duration_us: u64, code: i32, e_text: &str, detail: Option<&str>) {
    if let Some(d) = detail.filter(|s| !s.is_empty()) {
        tracing::info!(
            event = krb5_log::events::KDC_ISSUE,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            duration_us,
            outcome = "krb-error",
            code,
            e_text,
            detail = d,
        );
    } else {
        tracing::info!(
            event = krb5_log::events::KDC_ISSUE,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            duration_us,
            outcome = "krb-error",
            code,
            e_text,
        );
    }
}

fn handle_inner(store: &dyn PrincipalRead, raw: &[u8]) -> Result<(Vec<u8>, Option<String>), Error> {
    // MIT dispatch.c:145-153: not AS/TGS or decode fail → no response.
    if raw.is_empty() {
        return Ok((Vec::new(), None));
    }
    match raw[0] {
        0x6a => match decode::<AsReq>(raw) {
            Ok(req) if req.0.pvno != krb5_types::KdcReq::PVNO => Ok((Vec::new(), None)),
            Ok(req) => as_reply(store, &req, raw),
            Err(_) => Ok((Vec::new(), None)),
        },
        0x6c => match decode::<TgsReq>(raw) {
            Ok(req) if req.0.pvno != krb5_types::KdcReq::PVNO => Ok((Vec::new(), None)),
            Ok(req) => tgs_reply(store, &req, raw),
            Err(_) => Ok((Vec::new(), None)),
        },
        _ => Ok((Vec::new(), None)),
    }
}

/// KRB-ERROR with empty text (`make_too_big_error` / `make_toolong_error`).
#[must_use]
pub fn kdc_error_bytes(store: &dyn PrincipalRead, code: i32) -> Vec<u8> {
    encode_krb_error(store, code, None, None, None)
}

fn as_reply(
    store: &dyn PrincipalRead,
    req: &AsReq,
    raw: &[u8],
) -> Result<(Vec<u8>, Option<String>), Error> {
    let body = Some(&req.0.req_body);
    match issue_as_from(store, req, Some(raw)) {
        Ok(issued) => Ok((encode(&issued.rep)?, None)),
        Err(Error::PreauthRequired { e_data }) => Ok((
            encode_krb_error(
                store,
                err::PREAUTH_REQUIRED,
                Some(status::NEEDED_PREAUTH),
                Some(prepare_as_edata(
                    store,
                    req.0.req_body.cname.as_ref(),
                    &e_data,
                )),
                body,
            ),
            None,
        )),
        Err(Error::Protocol {
            code,
            text,
            e_data,
            detail,
        }) => Ok((
            encode_krb_error(
                store,
                code,
                text.as_deref(),
                e_data.map(|ed| prepare_as_edata(store, req.0.req_body.cname.as_ref(), &ed)),
                body,
            ),
            detail.filter(|s| !s.is_empty()),
        )),
        Err(Error::Crypto(d)) => Ok((
            encode_krb_error(
                store,
                err::PREAUTH_FAILED,
                Some(status::PREAUTH_FAILED),
                None,
                body,
            ),
            Some(d).filter(|s| !s.is_empty()),
        )),
        Err(Error::Asn1(d)) => Ok((
            encode_krb_error(
                store,
                err::GENERIC,
                Some(status::UNKNOWN_REASON),
                None,
                body,
            ),
            Some(d).filter(|s| !s.is_empty()),
        )),
        Err(e) => Ok((
            encode_krb_error(
                store,
                err::GENERIC,
                Some(status::LOOKING_UP_CLIENT),
                None,
                body,
            ),
            Some(e.to_string()).filter(|s| !s.is_empty()),
        )),
    }
}

fn tgs_reply(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    raw: &[u8],
) -> Result<(Vec<u8>, Option<String>), Error> {
    // MIT prepare_error_tgs (do_tgs_req.c:201-204): errpkt.client is the header
    // ticket's client when it decrypts, else NULL. gather_tgs_req_info returns
    // before kdc_process_tgs_req when msg_type != 12, so that error has no
    // cname. The TGS-REQ body carries no cname, so derive it for the error.
    let mut ebody = req.0.req_body.clone();
    ebody.cname = if req.0.msg_type == krb5_types::KdcReq::MSG_TGS_REQ {
        tgs_header_client(store, req)
    } else {
        None
    };
    let body = Some(&ebody);
    match issue_tgs_from(store, req, Some(raw)) {
        Ok(issued) => Ok((encode(&issued.rep)?, None)),
        Err(Error::Protocol {
            code,
            text,
            e_data,
            detail,
        }) => Ok((
            encode_krb_error(store, code, text.as_deref(), e_data, body),
            detail.filter(|s| !s.is_empty()),
        )),
        Err(Error::Crypto(d)) => Ok((
            encode_krb_error(
                store,
                err::BAD_INTEGRITY,
                Some(status::PROCESS_TGS),
                None,
                body,
            ),
            Some(d).filter(|s| !s.is_empty()),
        )),
        Err(Error::Asn1(d)) => Ok((
            encode_krb_error(store, err::GENERIC, Some(status::PROCESS_TGS), None, body),
            Some(d).filter(|s| !s.is_empty()),
        )),
        Err(e) => Ok((
            encode_krb_error(store, err::GENERIC, Some(status::PROCESS_TGS), None, body),
            Some(e.to_string()).filter(|s| !s.is_empty()),
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
    let encoded_fast_body;
    let fast_body: &[u8] = if let Some(slice) = raw.and_then(kdc_req_body_der) {
        slice
    } else {
        encoded_fast_body = encode(outer)?;
        &encoded_fast_body
    };
    if req.0.msg_type != krb5_types::KdcReq::MSG_AS_REQ {
        return Err(proto(err::GENERIC, status::VALIDATE_MESSAGE_TYPE));
    }
    let fast = unwrap_fast(store, req, fast_body)?;
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
    if utf8_realm(&body.realm)? != store.realm() {
        return Err(proto(err::C_PRINCIPAL_UNKNOWN, status::CLIENT_NOT_FOUND));
    }
    let req_cname = body
        .cname
        .clone()
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, status::NULL_CLIENT))?;
    let client = store
        .fetch_name(&req_cname)?
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, status::CLIENT_NOT_FOUND))?;
    let cname = if req_cname.name_type == PrincipalName::NT_ENTERPRISE
        || body.kdc_options.bit(flag_bit::CANONICALIZE)
    {
        client.name.clone()
    } else {
        req_cname.clone()
    };
    let sname = body
        .sname
        .clone()
        .unwrap_or_else(|| PrincipalName::krbtgt(store.realm()));
    let server = store
        .fetch_name(&sname)?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::SERVER_NOT_FOUND))?;
    // MIT validate_as_request runs after the client/server lookups and before
    // preauth (do_as_req.c:630 precedes check_padata at :758).
    validate_as_request(store, &client, &server, body)?;
    let session_etype = select_session_keytype(&server, &body.etype, store.policy())?;
    let ckey = select_client_key(&client, &body.etype)
        .ok_or_else(|| proto(err::ETYPE_NOSUPP, status::CANT_FIND_CLIENT_KEY))?;
    let etype = ckey.etype;
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

    let mut extra_padata: Vec<PaData> = Vec::new();
    let mut as_rep_key = ckey.key.clone();
    let mut skip_timestamp = false;
    let mut hw_preauth = false;
    let mut reply_key_replaced = false;
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
    )
    .map_err(|e| attach_preauth_hint(store, &client, ckey, e))?
    {
        Some(PreauthAction::Pkinit { key, pa }) => {
            as_rep_key = key;
            extra_padata.push(pa);
            skip_timestamp = true;
            hw_preauth = true;
            reply_key_replaced = true;
        }
        Some(PreauthAction::Challenge(e_data)) => {
            // do_as_req.c:439-442,809: status PREAUTH_FAILED even for 91.
            // kdc_preauth.c:1141-1170 maybe_add_etype_info2: add PA-ETYPE-INFO2
            // on a multi-round 91 unless the client already saw a cookie.
            let mut method = decode_edata_padata(&e_data);
            if find_pa(work_padata.as_deref(), pa::FX_COOKIE).is_none()
                && !method.iter().any(|p| p.padata_type == pa::ETYPE_INFO2)
            {
                let salt =
                    KerberosString::try_from(String::from_utf8_lossy(&client.salt).as_ref()).ok();
                let info2: EtypeInfo2 = vec![EtypeInfo2Entry {
                    etype: ckey.etype.to_iana(),
                    salt,
                    s2kparams: None,
                }];
                if let Ok(der) = encode(&info2) {
                    method.push(PaData {
                        padata_type: pa::ETYPE_INFO2,
                        padata_value: der.into(),
                    });
                }
            }
            return Err(Error::Protocol {
                code: err::MORE_PREAUTH_DATA_REQUIRED,
                text: Some(status::PREAUTH_FAILED.to_owned()),
                e_data: Some(encode(&method).unwrap_or(e_data)),
                detail: None,
            });
        }
        Some(PreauthAction::SpakeDone(k)) => {
            as_rep_key = k;
            skip_timestamp = true;
            reply_key_replaced = true;
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
        return Err(preauth_required(store, &client, ckey));
    }
    if attr(&client, KDB_REQUIRES_HW_AUTH) && !hw_preauth {
        return Err(Error::Protocol {
            code: err::PREAUTH_REQUIRED,
            text: Some(status::NEEDED_HW_PREAUTH.to_owned()),
            e_data: Some(preauth_hint_edata(store, &client, ckey)),
            detail: None,
        });
    }
    // do_as_req.c:717-724: REQUEST_ANONYMOUS demands the anonymous principal;
    // a named client asking for anonymity is KRB5KDC_ERR_BADOPTION
    // "VALIDATE_ANONYMOUS_PRINCIPAL". MIT runs this in the reply-building phase
    // after preauth, so a preauth-required client still gets PREAUTH_REQUIRED
    // first. This KDC issues no anonymous tickets, so the client is never the
    // anonymous principal and the option is refused here (validate_as_request
    // deliberately lets the bit through, matching kdc_util.c:727).
    if body.kdc_options.bit(flag_bit::ANONYMOUS) && !is_anonymous_principal(&req_cname) {
        return Err(proto(err::BADOPTION, status::VALIDATE_ANONYMOUS_PRINCIPAL));
    }

    let skey = server
        .first_current_key()
        .ok_or_else(|| proto(err::GENERIC, status::FINDING_SERVER_KEY))?;
    if let Some(from) = &body.from
        && from.unix_seconds() > body.till.unix_seconds()
    {
        return Err(proto(err::NEVER_VALID, status::UNKNOWN_REASON));
    }
    let session = random_key(session_etype)?;
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
    // MIT get_ticket_flags sets TKT_FLG_ENC_PA_REP on every issued ticket
    // (kdc_util.c:824), independent of whether PA-REQ-ENC-PA-REP was sent.
    flags = flags.with_bit(flag_bit::ENC_PA_REP, true);
    let want_enc_pa = find_pa(req.0.padata.as_deref(), pa::REQ_ENC_PA_REP).is_some()
        || fast.is_some_and(|f| find_pa(Some(&f.inner_padata), pa::REQ_ENC_PA_REP).is_some());
    let life = requested_life(store, &client, body, &starttime);
    let end = starttime
        .add_seconds(i64::try_from(life).unwrap_or(i64::MAX))
        .or_else(|_| starttime.add_hours(10))
        .map_err(|_| proto(err::NEVER_VALID, status::UNKNOWN_REASON))?;
    let include_pac = include_pac_for_reply(
        store,
        &server,
        req.0.padata.as_deref(),
        true,
        true,
        flags.bit(flag_bit::ANONYMOUS),
    );
    let krbtgt_p = store
        .fetch_krbtgt()?
        .ok_or_else(|| proto(err::GENERIC, status::GET_LOCAL_TGT))?;
    let krbtgt_key = krbtgt_p
        .first_current_key()
        .ok_or_else(|| proto(err::GENERIC, status::GET_LOCAL_TGT))?;
    let pac_kdc = crate::ad::pac_privsvr_key(
        &server,
        if sname.is_krbtgt_for(store.realm()) {
            &skey.key
        } else {
            &krbtgt_key.key
        },
    )?;
    // do_as_req.c:660-666: with CANONICALIZE a krbtgt request is issued under
    // the canonical DB server name (Windows short-realm aliases), and
    // reply_encpart.server follows the ticket server (do_as_req.c:243). Any
    // other request keeps the requested server name.
    let ticket_sname = if body.kdc_options.bit(flag_bit::CANONICALIZE)
        && sname.is_krbtgt()
        && server.name.is_krbtgt()
    {
        server.name.clone()
    } else {
        sname.clone()
    };
    let ticket = mint_ticket(
        &skey.key,
        skey.kvno,
        skey.etype,
        &session,
        store.realm(),
        &ticket_sname,
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
        None,
    )?;
    let renew_till = renew_till_for(
        store,
        &now,
        &flags,
        Some(&client),
        Some(&server),
        body.rtime.as_ref(),
    );
    let mut reply_key = as_rep_key.clone();
    let mut outer_padata = extra_padata;
    // return_padata add_etype_info/add_pw_salt (kdc_preauth.c:769-829,1487-1495):
    // key-info follows the reply key unless a module replaced it. RFC 4120
    // 5.2.7.5 forbids describing a replaced reply key.
    if !reply_key_replaced {
        outer_padata.extend(as_rep_key_info(&client, ckey, &body.etype));
    }
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
    let mut enc_part = enc_rep_part(
        &session,
        fast.map_or(body.nonce, |f| f.nonce),
        &now,
        &now,
        &starttime,
        &end,
        store.realm(),
        &ticket_sname,
        flags,
        renew_till,
        None,
    )?;
    // The flag is always set; the enc-pa-rep padata is added only when the
    // client asked for it (kdc_handle_protected_negotiation).
    if want_enc_pa && let Some(pkt) = raw {
        enc_part.encrypted_pa_data = Some(enc_pa_rep_padata(&reply_key, pkt)?);
    }
    let enc_der = encode_enc_kdc_rep_part(enc_part)?;
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART)?;
    let cipher = encrypt(&reply_key, usage, &enc_der)?;
    // MIT sets reply.enc_part.kvno only after krb5_encode_kdc_rep (do_as_req.c:329),
    // so the wire AS-REP enc-part carries no kvno.
    let kvno = None;
    let padata = if outer_padata.is_empty() {
        None
    } else {
        Some(outer_padata)
    };
    // do_as_req.c:324: with FAST hide-client-names the outer reply client is
    // the anonymous principal (WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS); the
    // real client is carried only inside the FAST-armored reply. Non-FAST or
    // unset leaves the true cname/crealm.
    let (rep_crealm, rep_cname) = if fast.is_some_and(|f| fast_hides_client(&f.fast_options)) {
        (ks(ANONYMOUS_REALM)?, anonymous_principal_name())
    } else {
        (ks(store.realm())?, cname)
    };
    let rep = AsRep(krb5_types::KdcRep {
        pvno: krb5_types::KdcRep::PVNO,
        msg_type: krb5_types::KdcRep::MSG_AS_REP,
        padata,
        crealm: rep_crealm,
        cname: rep_cname,
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

struct HeaderTgt {
    ap: krb5_types::ApReq,
    enc_tkt: EncTicketPart,
    tgt_key: ProtocolKey,
    session: ProtocolKey,
    authenticator: krb5_types::Authenticator,
    header_realm: String,
    header_server: Principal,
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
    // MIT kdc_process_tgs_req (PROCESS_TGS) before kdc_find_fast.
    if req.0.msg_type != krb5_types::KdcReq::MSG_TGS_REQ {
        return Err(proto(err::GENERIC, status::UNKNOWN_REASON));
    }
    let pa_tgs = extract_pa_tgs(req.0.padata.as_deref())
        .ok_or_else(|| proto(err::PADATA_TYPE_NOSUPP, status::PROCESS_TGS))?;
    let header = process_tgs_header(store, pa_tgs.as_ref(), body_der)?;
    let tgs_fast = unwrap_fast_tgs(
        store,
        req.0.padata.as_deref(),
        pa_tgs.as_ref(),
        header.authenticator.subkey.as_ref(),
        &header.session,
    )?;
    let inner_owned: Option<KdcReqBody> = match tgs_fast.as_ref() {
        Some(f) => Some(decode(&f.inner_body)?),
        None => None,
    };
    let body = inner_owned.as_ref().unwrap_or(outer);
    issue_tgs_body(store, req, body, tgs_fast.as_ref(), header)
        .map_err(|e| wrap_as_fast(store, tgs_fast.as_ref(), e, body))
}

fn process_tgs_header(
    store: &dyn PrincipalRead,
    ap_raw: &[u8],
    body_der: &[u8],
) -> Result<HeaderTgt, Error> {
    let ap: krb5_types::ApReq = decode(ap_raw)?;
    if ap.ap_options.use_session_key() || ap.ap_options.wants_mutual() {
        return Err(proto(err::POLICY, status::PROCESS_TGS));
    }
    let header_realm = utf8_realm(&ap.ticket.realm)?.to_owned();
    let tkt_etype = EncryptionType::from_iana(ap.ticket.enc_part.etype)
        .or_else(|_| EncryptionType::known(ap.ticket.enc_part.etype))?;
    let (enc_tkt, tgt_key, _, header_server) = decrypt_presented_tgt(store, &ap, tkt_etype)?;
    check_header_times_rd_req(store, &enc_tkt)?;
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

fn issue_tgs_body(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    body: &KdcReqBody,
    tgs_fast: Option<&FastOk>,
    header: HeaderTgt,
) -> Result<IssuedTgs, Error> {
    if let Some(f) = tgs_fast {
        check_fast_options(&f.fast_options)?;
    }
    if body.kdc_options.unsupported_bits() != 0 {
        return Err(proto(err::BADOPTION, status::UNKNOWN_REASON));
    }
    let tgs_padata = if let Some(f) = tgs_fast {
        Some(f.inner_padata.as_slice())
    } else {
        req.0.padata.as_deref()
    };
    let HeaderTgt {
        ap,
        enc_tkt,
        tgt_key,
        session: tgt_session,
        authenticator,
        header_realm,
        header_server,
    } = header;
    let renew = body.kdc_options.bit(flag_bit::RENEW);
    let validate = body.kdc_options.bit(flag_bit::VALIDATE);
    if renew && validate {
        return Err(proto(err::BADOPTION, status::TICKET_NOT_RENEWABLE));
    }
    let rkey = ReplayKey {
        client: format!(
            "{}@{}",
            authenticator.cname.components_joined(),
            utf8_realm(&enc_tkt.crealm)?
        ),
        server: format!("krbtgt/{}@{}", store.realm(), store.realm()),
        ctime: authenticator.ctime.unix_seconds(),
        cusec: authenticator.cusec.get(),
        auth_hash: ReplayCache::hash_authenticator(ap.authenticator.cipher.as_ref()),
    };
    if store.tgs_replay().check_and_store(rkey) {
        return Err(proto(err::REPEAT, status::PROCESS_TGS));
    }
    let sname = body
        .sname
        .clone()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::NULL_SERVER))?;
    // MIT get_local_tgt requires krbtgt/<body.realm>@<body.realm> in the KDB
    // before search_sprinc. A single-realm KDC answers 60 GET_LOCAL_TGT.
    let req_realm = utf8_realm(&body.realm)?.to_owned();
    if req_realm != store.realm() {
        return Err(proto(err::GENERIC, status::GET_LOCAL_TGT));
    }
    let header_pac = crate::ad::get_verified_pac(
        &enc_tkt,
        &tgt_key,
        &header_server,
        store.fetch_krbtgt()?.as_ref(),
    )?;
    current_policy().check_tgs(store, &sname)?;
    let mut server = store
        .fetch_name(&sname)?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::LOOKING_UP_SERVER))?;
    check_tgs_constraints_skeleton(
        body,
        &ap.ticket.sname,
        &enc_tkt,
        &sname,
        req_realm.as_str(),
        renew,
        validate,
    )?;
    let tgs_client = store.fetch_name(&enc_tkt.cname)?;
    // MIT TGS checks the server only; a valid TGT still issues after client expiry.
    // MIT runs the service flag rules (deny_opts/deny_all/reqd_flags) before
    // check_tgs_svc_time, so a locked-out or postdate-denied service is caught
    // before an expiry.
    check_tgs_policy_flags(&server, body, ap.ticket.sname.is_krbtgt(), &enc_tkt)?;
    check_db_times(None, &server)?;
    let mut ticket_cname = enc_tkt.cname.clone();
    let mut ticket_crealm = utf8_realm(&enc_tkt.crealm)?.to_owned();
    let mut evidence_logon = None;
    let mut s4u2self = false;
    let mut s4u_x509 = None;
    let mut s4u_referral = false;
    let mut s4u2proxy = false;
    let mut subject_authtime = enc_tkt.authtime.clone();
    let mut subject_pac = header_pac.clone();
    if let Some(s4u) = process_s4u2self_req(
        store,
        &tgt_session,
        authenticator.subkey.as_ref(),
        tgs_padata,
        body.nonce,
    )? {
        let header_cross = utf8_realm(&ap.ticket.realm)? != store.realm();
        let is_referral = sname.is_krbtgt() && !sname.is_krbtgt_for(store.realm());
        let is_self = utf8_realm(&enc_tkt.crealm)? == store.realm()
            && tgs_client
                .as_ref()
                .is_some_and(|c| c.realm == server.realm && c.name == server.name);
        if !is_referral && !is_self {
            return Err(proto(
                err::BADMATCH,
                status::INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH,
            ));
        }
        check_tgs_s4u2self(
            store,
            body,
            &s4u,
            header_cross,
            is_referral,
            &enc_tkt,
            header_pac.as_deref(),
        )?;
        server.attributes &= !KDB_NO_AUTH_DATA_REQUIRED;
        if !is_referral {
            ticket_cname = s4u.user.clone();
            ticket_crealm.clone_from(&s4u.realm);
        }
        s4u_x509 = s4u.x509;
        s4u_referral = is_referral;
        s4u2self = true;
    }
    let is_referral = sname.is_krbtgt() && !sname.is_krbtgt_for(store.realm());
    let is_crossrealm = tgs_header_is_crossrealm(header_realm.as_str(), &server.realm);
    let local_tgt = store.fetch_krbtgt()?;
    let stkt = decrypt_2ndtkt(store, req, local_tgt.as_ref())?;
    if body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) {
        check_tgs_u2u(store, stkt.as_ref(), &server)?;
    }
    if body.kdc_options.bit(flag_bit::CNAME_IN_ADDL_TKT) {
        // MIT `kau_make_tkt_id(stkt)` with a missing additional ticket is
        // EINVAL (`kdc_audit.c:154-155`) → 60 `UNKNOWN_REASON` before
        // `check_tgs_s4u2proxy` (`do_tgs_req.c:731-733`).
        let Some(st) = stkt.as_ref() else {
            return Err(proto(err::GENERIC, status::UNKNOWN_REASON));
        };
        check_tgs_s4u2proxy(
            store,
            body,
            &enc_tkt,
            header_pac.as_deref(),
            Some(st),
            &server.realm,
            is_crossrealm,
            is_referral,
        )?;
        if is_crossrealm {
            let pac = st
                .pac
                .as_deref()
                .ok_or_else(|| proto(err::BADOPTION, status::RBCD_PAC_PRINC))?;
            ticket_cname = rbcd_pac_client(pac)?;
        } else {
            ticket_cname = st.part.cname.clone();
        }
        utf8_realm(&st.part.crealm)?.clone_into(&mut ticket_crealm);
        subject_authtime = st.part.authtime.clone();
        subject_pac.clone_from(&st.pac);
        s4u2proxy = true;
        check_s4u2proxy_policy(
            tgs_padata,
            &sname,
            &enc_tkt.cname,
            &st.server,
            &server,
            is_crossrealm,
            is_referral,
        )?;
    } else if !s4u2self
        && let Some(logon) = header_pac.as_ref().and_then(|p| {
            let parsed = krb5_types::pac::Pac::parse(p).ok()?;
            parsed
                .unique_buffer(krb5_types::pac::PAC_LOGON_INFO)
                .ok()
                .flatten()
                .map(<[u8]>::to_vec)
        })
    {
        evidence_logon = Some(if utf8_realm(&ap.ticket.realm)? == store.realm() {
            logon
        } else {
            crate::ad::filter_cross_realm_logon(&logon, store.domain_sid())?
        });
    }
    if attr(&server, KDB_DISALLOW_DUP_SKEY) && body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) {
        return Err(proto(err::POLICY, status::DUP_SKEY_DISALLOWED));
    }
    let skip_transited = body.kdc_options.bit(flag_bit::DISABLE_TRANSITED_CHECK);
    let u2u = if body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) {
        let st = stkt
            .as_ref()
            .ok_or_else(|| proto(err::BADOPTION, status::NO_2ND_TKT))?;
        let offered = get_2ndtkt_enctype(body, st)?;
        Some((u2u_from_stkt(st)?, offered))
    } else {
        None
    };
    let session_etype = match &u2u {
        Some((_, Some(et))) => *et,
        Some((_, None)) | None => select_session_keytype(&server, &body.etype, store.policy())?,
    };
    let (tkt_key, tkt_kvno, tkt_etype) = if let Some(((k, kv, et), _)) = u2u {
        (k, kv, et)
    } else {
        let skey = server
            .first_current_key()
            .ok_or_else(|| proto(err::GENERIC, status::FINDING_SERVER_KEY))?;
        (skey.key.clone(), skey.kvno, skey.etype)
    };
    let mut transited = enc_tkt.transited.clone();
    let prev_hop = header_realm.as_str();
    let crealm = utf8_realm(&enc_tkt.crealm)?;
    // MIT check_tgs_lineage: a local user on a foreign TGT is POLICY
    // (skipped for S4U2Self).
    if crealm == store.realm() && is_crossrealm && !s4u2self {
        return Err(proto(err::POLICY, status::INVALID_LINEAGE));
    }
    // MIT do_tgs_req.c:787-789: keep the header transited when the header
    // ticket server realm equals the client realm (implicit in the field).
    if is_crossrealm && prev_hop != crealm {
        if transited.tr_type != 1 {
            return Err(proto(err::TRTYPE_NOSUPP, status::VALIDATE_TRANSIT_TYPE));
        }
        transited = transited
            .append_realm(prev_hop, crealm, req_realm.as_str())
            .map_err(|_| proto(err::ILL_CR_TKT, status::ADD_TO_TRANSITED_LIST))?;
    }
    let transit_checked = if crealm == "WELLKNOWN:ANONYMOUS" {
        true
    } else {
        match transited.realms_for(crealm, req_realm.as_str()) {
            Ok(h) => store.policy().transit_allowed(crealm, &req_realm, &h),
            Err(_) => false,
        }
    };
    // MIT do_tgs_req: skip leaves T unset; default reject_bad_transit
    // then POLICY. RENEW/VALIDATE keep the header T (get_ticket_flags).
    let inherited_t = (renew || validate) && enc_tkt.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED);
    let set_transited_flag = !skip_transited && transit_checked;
    if !(inherited_t || set_transited_flag) && store.policy().reject_bad_transit {
        return Err(proto(err::POLICY, status::BAD_TRANSIT));
    }
    let session = random_key(session_etype)?;
    let now = KerberosTime::now();
    let authtime;
    let starttime;
    let mut end;
    let mut flags;
    let ticket_renew_till;
    if renew {
        if !enc_tkt.flags.renewable() {
            return Err(proto(err::BADOPTION, status::TICKET_NOT_RENEWABLE));
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
        authtime = subject_authtime.clone();
        starttime = now.clone();
        end = enc_tkt.endtime.clone();
        let life = requested_life(store, &server, body, &now);
        if let Ok(capped) = now.add_seconds(i64::try_from(life).unwrap_or(i64::MAX))
            && capped.unix_seconds() < end.unix_seconds()
        {
            end = capped;
        }
        flags = TicketFlags::none().with_bit(flag_bit::ENC_PA_REP, true);
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
    if s4u2self && !s4u_referral {
        flags = s4u2self_forwardable(&server, flags);
    }
    let krbtgt_p = store
        .fetch_krbtgt()?
        .ok_or_else(|| proto(err::GENERIC, status::GET_LOCAL_TGT))?;
    let krbtgt_key = krbtgt_p
        .first_current_key()
        .ok_or_else(|| proto(err::GENERIC, status::GET_LOCAL_TGT))?;
    // Referral TGT PAC 16/19/7 must be keyed with the inter-realm key
    // the foreign KDC holds (Windows TDO inbound), not the local krbtgt.
    let pac_kdc = crate::ad::pac_privsvr_key(
        &server,
        if sname.is_krbtgt() && !sname.is_krbtgt_for(store.realm()) {
            &tkt_key
        } else {
            &krbtgt_key.key
        },
    )?;
    if !s4u2self && !s4u2proxy {
        crate::ad::check_normal_tgs_pac(&enc_tkt, header_pac.as_deref(), &server, is_crossrealm)?;
    }
    let include_pac = include_pac_for_reply(
        store,
        &server,
        tgs_padata,
        false,
        subject_pac.is_some(),
        flags.bit(flag_bit::ANONYMOUS),
    );
    if s4u2proxy
        && !is_crossrealm
        && let (Some(raw), Some(st)) = (subject_pac.as_deref(), stkt.as_ref())
    {
        let hop = st.server.name.unparse_with_realm(&st.server.realm);
        subject_pac = Some(update_delegation_info(raw, &sname, &hop)?);
    }
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
        if s4u2self {
            None
        } else {
            subject_pac.as_deref()
        },
    )?;
    let mut s4u_rep_pa = None;
    let mut s4u_enc_pa = None;
    if let Some(ref x509) = s4u_x509 {
        let (pa, enc) = make_s4u2self_rep(x509, &tgt_session, authenticator.subkey.as_ref())?;
        s4u_rep_pa = Some(pa);
        s4u_enc_pa = enc;
    }
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
        s4u_enc_pa,
    )?;
    let enc_der = encode_enc_kdc_rep_part(enc_part)?;
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
    let padata = if let Some(f) = tgs_fast {
        let finished = fast_finished(&f.armor_key, &ticket, &ticket_cname, &ticket_crealm)?;
        let inner: Vec<PaData> = s4u_rep_pa.into_iter().collect();
        Some(vec![wrap_fast_rep(
            &f.armor_key,
            inner,
            None,
            f.nonce,
            Some(finished),
        )?])
    } else {
        s4u_rep_pa.map(|p| vec![p])
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
) -> Result<(EncTicketPart, ProtocolKey, Vec<u8>, Principal), Error> {
    // MIT kdc_get_server_key (kdc_util.c:360-409): ticket.server, DISALLOW → 7.
    // Incoming interrealm keys are stored as krbtgt/<ticket.realm>@<local>.
    let ticket_realm = utf8_realm(&ap.ticket.realm)?;
    let princ = if ticket_realm == store.realm() {
        store.fetch_name(&ap.ticket.sname)?
    } else {
        store
            .fetch(&lookup_principal_id(&ap.ticket.sname, ticket_realm))?
            .map_or_else(
                || {
                    let name = PrincipalName::try_new(
                        PrincipalName::NT_SRV_INST,
                        ["krbtgt", ticket_realm],
                    )
                    .map_err(|_| proto(err::S_PRINCIPAL_UNKNOWN, status::PROCESS_TGS))?;
                    store.fetch_name(&name)
                },
                |p| Ok(Some(p)),
            )?
    };
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
        let last = match find_server_key(&p, search_enctype, kvno) {
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

/// MIT `check_tgs_u2u` (`tgs_policy.c:575-598`).
fn check_tgs_u2u(
    store: &dyn PrincipalRead,
    stkt: Option<&SecondTicket>,
    dest: &Principal,
) -> Result<(), Error> {
    let Some(st) = stkt else {
        return Err(proto(err::BADOPTION, status::NO_2ND_TKT));
    };
    if !st.server.name.is_local_tgs_principal(&st.server.realm)
        || !st.server.name.is_krbtgt_for(&dest.realm)
    {
        return Err(proto(err::POLICY, status::SECOND_TKT_NOT_TGS));
    }
    let crealm = utf8_realm(&st.part.crealm)?;
    let id = lookup_principal_id(&st.part.cname, crealm);
    let Some(client) = store.fetch(&id)? else {
        return Err(proto(err::SERVER_NOMATCH, status::SECOND_TKT_MISMATCH));
    };
    if client.name != dest.name || client.realm != dest.realm {
        return Err(proto(err::SERVER_NOMATCH, status::SECOND_TKT_MISMATCH));
    }
    Ok(())
}

/// MIT `get_2ndtkt_enctype` (`do_tgs_req.c:310-328`).
fn get_2ndtkt_enctype(
    body: &KdcReqBody,
    st: &SecondTicket,
) -> Result<Option<EncryptionType>, Error> {
    let n = st.part.key.keytype;
    let Ok(et) = EncryptionType::known(n) else {
        return Err(proto(err::ETYPE_NOSUPP, status::BAD_ETYPE_IN_2ND_TKT));
    };
    if body.etype.contains(&n) {
        Ok(Some(et))
    } else {
        Ok(None)
    }
}

/// MIT `decrypt_2ndtkt` (`do_tgs_req.c:257-307`).
fn decrypt_2ndtkt(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    local_tgt: Option<&Principal>,
) -> Result<Option<SecondTicket>, Error> {
    let body = &req.0.req_body;
    if !body.kdc_options.bit(flag_bit::CNAME_IN_ADDL_TKT)
        && !body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY)
    {
        return Ok(None);
    }
    let Some(extra) = body.additional_tickets.as_ref().and_then(|v| v.first()) else {
        return Ok(None);
    };
    let server = store
        .fetch_name(&extra.sname)?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::SECOND_TKT_SERVER))?;
    if attr(&server, KDB_DISALLOW_ALL_TIX) || attr(&server, KDB_DISALLOW_SVR) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::SECOND_TKT_SERVER));
    }
    let Ok(tkt_etype) = EncryptionType::from_iana(extra.enc_part.etype)
        .or_else(|_| EncryptionType::known(extra.enc_part.etype))
    else {
        return Err(proto(err::GENERIC, status::SECOND_TKT_SERVER));
    };
    let kvno = extra.enc_part.kvno.unwrap_or(0);
    let (key, _) = find_server_key(&server, Some(tkt_etype), kvno)
        .map_err(|e| with_status(e, status::SECOND_TKT_SERVER))?;
    let usage = KeyUsage::new(ku::TICKET)?;
    let plain = decrypt(&key, usage, extra.enc_part.cipher.as_ref())
        .map_err(|_| proto(err::BAD_INTEGRITY, status::SECOND_TKT_DECRYPT))?;
    let part: EncTicketPart =
        decode(&plain).map_err(|_| proto(err::BAD_INTEGRITY, status::SECOND_TKT_DECRYPT))?;
    if extra.sname.is_krbtgt() {
        let pac = crate::ad::get_verified_pac(&part, &key, &server, None)
            .map_err(|e| with_status(e, status::SECOND_TKT_PAC))?;
        return Ok(Some(SecondTicket { part, server, pac }));
    }
    let Some(tgt) = local_tgt else {
        return Err(proto(err::GENERIC, status::GET_LOCAL_TGT));
    };
    let pac = crate::ad::get_verified_pac(&part, &key, &server, Some(tgt))
        .map_err(|e| with_status(e, status::SECOND_TKT_PAC))?;
    Ok(Some(SecondTicket { part, server, pac }))
}

fn u2u_from_stkt(st: &SecondTicket) -> Result<(ProtocolKey, u32, EncryptionType), Error> {
    let etype = EncryptionType::from_iana(st.part.key.keytype)
        .or_else(|_| EncryptionType::known(st.part.key.keytype))?;
    let key = ProtocolKey::from_bytes(etype, st.part.key.keyvalue.as_ref())?;
    Ok((key, 0, etype))
}

/// MIT `find_server_key` (`kdc_util.c:417-457`). kvno 0 means any kvno.
/// No matching key, or a requested etype that is not similar, is
/// `KRB5_KDB_NO_MATCHING_KEY` / `KRB5_KDB_NO_PERMITTED_KEY` → 60 `PROCESS_TGS`.
fn find_server_key(
    p: &Principal,
    search_enctype: Option<EncryptionType>,
    kvno: u32,
) -> Result<(ProtocolKey, u32), Error> {
    let key = if kvno == 0 {
        match search_enctype {
            Some(e) => p.key_for(e),
            None => p.first_current_key(),
        }
    } else {
        match search_enctype {
            Some(e) => p.keys.iter().find(|k| k.etype == e && k.kvno == kvno),
            None => p.first_key_at_kvno(kvno),
        }
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

/// MIT `krb5int_validate_times` inside `kdc_process_tgs_req` (PROCESS_TGS).
fn check_header_times_rd_req(store: &dyn PrincipalRead, tkt: &EncTicketPart) -> Result<(), Error> {
    let now = KerberosTime::now();
    let skew = store.policy().skew;
    if let Some(start) = &tkt.starttime
        && now.delta_seconds(start) < -skew
    {
        return Err(proto(err::TKT_NYV, status::PROCESS_TGS));
    }
    if tkt.endtime.delta_seconds(&now) < -skew {
        return Err(proto(err::TKT_EXPIRED, status::PROCESS_TGS));
    }
    Ok(())
}

/// MIT `do_tgs_req.c:686`: header ticket server realm ≠ canonical server realm.
#[must_use]
pub fn tgs_header_is_crossrealm(header_server_realm: &str, sprinc_realm: &str) -> bool {
    header_server_realm != sprinc_realm
}

fn non_tgt_option(body: &KdcReqBody) -> bool {
    body.kdc_options.bit(flag_bit::FORWARDED)
        || body.kdc_options.bit(flag_bit::PROXY)
        || body.kdc_options.bit(flag_bit::RENEW)
        || body.kdc_options.bit(flag_bit::VALIDATE)
}

fn check_tgs_constraints_skeleton(
    body: &KdcReqBody,
    header_sname: &PrincipalName,
    enc_tkt: &EncTicketPart,
    req_sname: &PrincipalName,
    req_realm: &str,
    renew: bool,
    validate: bool,
) -> Result<(), Error> {
    if body.kdc_options.bit(flag_bit::FORWARDED) && !enc_tkt.flags.bit(flag_bit::FORWARDABLE) {
        return Err(proto(err::BADOPTION, status::TGT_NOT_FORWARDABLE));
    }
    if body.kdc_options.bit(flag_bit::PROXY) && !enc_tkt.flags.bit(flag_bit::PROXIABLE) {
        return Err(proto(err::BADOPTION, status::TGT_NOT_PROXIABLE));
    }
    if enc_tkt.flags.invalid() && !validate {
        return Err(proto(err::TKT_NYV, status::TICKET_NOT_VALID));
    }
    if validate {
        if !enc_tkt.flags.invalid() {
            return Err(proto(err::BADOPTION, status::VALIDATE_VALID_TICKET));
        }
        let now = KerberosTime::now();
        let start = enc_tkt.starttime.as_ref().unwrap_or(&enc_tkt.authtime);
        if now.delta_seconds(start) < 0 {
            return Err(proto(err::TKT_NYV, status::NOT_YET_VALID));
        }
    }
    if renew {
        if !enc_tkt.flags.renewable() {
            return Err(proto(err::BADOPTION, status::TICKET_NOT_RENEWABLE));
        }
        let now = KerberosTime::now();
        match &enc_tkt.renew_till {
            Some(till) if till.unix_seconds() <= now.unix_seconds() => {
                return Err(proto(err::TKT_EXPIRED, status::TKT_EXPIRED));
            }
            None => return Err(proto(err::TKT_EXPIRED, status::TKT_EXPIRED)),
            Some(_) => {}
        }
    }
    if non_tgt_option(body) {
        if header_sname != req_sname {
            return Err(proto(err::SERVER_NOMATCH, status::RENEW_SERVER_MISMATCH));
        }
        if body.kdc_options.bit(flag_bit::PROXY) && req_sname.is_krbtgt() {
            return Err(proto(err::BADOPTION, status::CANT_PROXY_TGT));
        }
    } else {
        if !header_sname.is_krbtgt() {
            return Err(proto(err::NOT_US, status::BAD_TGS_SERVER_NAME));
        }
        if !header_sname.is_krbtgt_for(req_realm) {
            return Err(proto(err::NOT_US, status::BAD_TGS_SERVER_INSTANCE));
        }
    }
    Ok(())
}

fn include_pac_for_reply(
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
    subject_pac: Option<&[u8]>,
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
            let v = parse_kerb_validation_info(b).map_err(|e| {
                proto_d(
                    err::BAD_INTEGRITY,
                    status::HEADER_PAC,
                    format!("PAC logon: {e}"),
                )
            })?;
            PacIdentity {
                sam: v.effective_name.value,
                realm: crealm.to_owned(),
                domain_sid: v.logon_domain_id,
                rid: v.user_id,
            }
        } else {
            store.pac_identity(cname, crealm)
        };
        let pac = crate::ad::sign_reply_pac(
            cname,
            authtime.unix_seconds(),
            &crate::ad::PacTicket {
                server: service_key,
                kdc: kdc_key,
                enc_tkt_der: &checksum_der,
                is_service_tkt: crate::ad::should_have_ticket_signature(sname),
            },
            &ident,
            logon_override,
            subject_pac,
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
            // MIT DEFOPTIONALZEROTYPE(opt_kvno): 0 is omitted (U2U).
            kvno: (kvno != 0).then_some(kvno),
            cipher: cipher.into(),
        },
    })
}

fn encode_enc_kdc_rep_part(part: EncKdcRepPart) -> Result<Vec<u8>, Error> {
    Ok(encode(&EncTgsRepPart(part))?)
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
    encrypted_pa_data: Option<PaData>,
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
        encrypted_pa_data: encrypted_pa_data.map(|p| vec![p]),
    })
}

/// MIT `kdc_handle_protected_negotiation` (`kdc_util.c:1768-1806`).
fn enc_pa_rep_padata(reply_key: &ProtocolKey, req_pkt: &[u8]) -> Result<Vec<PaData>, Error> {
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

fn encryption_key(key: &ProtocolKey) -> EncryptionKey {
    EncryptionKey {
        keytype: key.etype().to_iana(),
        keyvalue: OctetString::from(key.as_bytes().to_vec()),
    }
}

/// `enctype_requires_etype_info_2` (`kdc_util.c:1663-1674`): every valid
/// enctype except des3-cbc-sha1/raw and rc4-hmac/exp.
fn enctype_requires_etype_info_2(etype: i32) -> bool {
    matches!(
        EncryptionType::known(etype),
        Ok(e) if !matches!(e, EncryptionType::Des3CbcSha1 | EncryptionType::Rc4Hmac)
    )
}

/// AS-REP key-info like `add_etype_info`/`add_pw_salt` (`kdc_preauth.c:769-829`):
/// PA-ETYPE-INFO2 for every client, PA-ETYPE-INFO + PW-SALT added when the
/// request carries only legacy (des3/rc4) enctypes. The single entry's salt is
/// the canonical client's (`_make_etype_info_entry` uses `client->princ`), so a
/// `kinit` under an alias derives the target's key.
fn as_rep_key_info(client: &Principal, ckey: &KeyEntry, requested: &[i32]) -> Vec<PaData> {
    let mut out = Vec::new();
    let salt = KerberosString::try_from(String::from_utf8_lossy(&client.salt).as_ref()).ok();
    let etype = ckey.etype.to_iana();
    if !requested.iter().copied().any(enctype_requires_etype_info_2) {
        let info: EtypeInfo = vec![EtypeInfoEntry {
            etype,
            salt: salt.as_ref().map(|s| s.as_bytes().to_vec().into()),
        }];
        if let Ok(der) = encode(&info) {
            out.push(PaData {
                padata_type: pa::ETYPE_INFO,
                padata_value: der.into(),
            });
        }
        out.push(PaData {
            padata_type: pa::PW_SALT,
            padata_value: client.salt.clone().into(),
        });
    }
    let info2: EtypeInfo2 = vec![EtypeInfo2Entry {
        etype,
        salt,
        s2kparams: None,
    }];
    if let Ok(der) = encode(&info2) {
        out.push(PaData {
            padata_type: pa::ETYPE_INFO2,
            padata_value: der.into(),
        });
    }
    out
}

fn select_client_key<'a>(princ: &'a Principal, requested: &[i32]) -> Option<&'a KeyEntry> {
    for n in requested {
        if let Ok(e) = EncryptionType::known(*n)
            && let Some(k) = princ.key_for(e)
        {
            return Some(k);
        }
    }
    None
}

fn dbentry_supports_enctype(server: &Principal, enctype: EncryptionType, allow_weak: bool) -> bool {
    if let Some((_, raw)) = server
        .string_attrs
        .iter()
        .find(|(k, _)| k == "session_enctypes")
        && !raw.is_empty()
        && let Some(list) = parse_enctype_list(raw, allow_weak)
    {
        return list.contains(&enctype);
    }
    enctype == EncryptionType::Aes256CtsHmacSha196 || server.key_for(enctype).is_some()
}

fn select_session_keytype(
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
        if dbentry_supports_enctype(server, e, policy.allow_weak_crypto) {
            return Ok(e);
        }
    }
    Err(proto(err::ETYPE_NOSUPP, status::BAD_ENCRYPTION_TYPE))
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

/// Header-ticket client for a TGS KRB-ERROR (`prepare_error_tgs`
/// `errpkt.client`): the presented ticket's client when it decrypts, else
/// `None` (MIT's `NULL`).
fn tgs_header_client(store: &dyn PrincipalRead, req: &TgsReq) -> Option<PrincipalName> {
    let pa_tgs = extract_pa_tgs(req.0.padata.as_deref())?;
    let ap: krb5_types::ApReq = decode(pa_tgs.as_ref()).ok()?;
    // MIT kdc_process_tgs_req refuses USE_SESSION_KEY / MUTUAL_REQUIRED
    // before rd_req, so the error has no decrypted client.
    if ap.ap_options.use_session_key() || ap.ap_options.wants_mutual() {
        return None;
    }
    let etype = EncryptionType::from_iana(ap.ticket.enc_part.etype)
        .or_else(|_| EncryptionType::known(ap.ticket.enc_part.etype))
        .ok()?;
    let (enc_tkt, _, _, _) = decrypt_presented_tgt(store, &ap, etype).ok()?;
    Some(enc_tkt.cname)
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
        .map_err(|_| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
    let ts: PaEncTsEnc =
        decode(&plain).map_err(|_| proto(err::PREAUTH_FAILED, status::PREAUTH_FAILED))?;
    if let Some(u) = ts.pausec {
        u.validate()
            .map_err(|_| proto(err::GENERIC, status::PREAUTH_FAILED))?;
    }
    let now = i64::from(KerberosTime::now().unix_seconds());
    let then = i64::from(ts.patimestamp.unix_seconds());
    if (now - then).abs() > store.policy().skew {
        return Err(proto(err::SKEW, status::PREAUTH_FAILED));
    }
    let rkey = ReplayKey {
        client: client.id(),
        server: format!("krbtgt/{}@{}", store.realm(), store.realm()),
        ctime: ts.patimestamp.unix_seconds(),
        cusec: ts.pausec.map_or(0, Microseconds::get),
        auth_hash: ReplayCache::hash_authenticator(blob),
    };
    if store.pa_replay().check_and_store(rkey) {
        return Err(proto(err::REPEAT, status::PREAUTH_FAILED));
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
        u.validate()
            .map_err(|_| proto(err::GENERIC, status::PREAUTH_FAILED))?;
    }
    let now = i64::from(KerberosTime::now().unix_seconds());
    let then = i64::from(ts.patimestamp.unix_seconds());
    if (now - then).abs() > store.policy().skew {
        return Err(proto(err::SKEW, status::PREAUTH_FAILED));
    }
    let rkey = ReplayKey {
        client: client.id(),
        server: format!("krbtgt/{}@{}", store.realm(), store.realm()),
        ctime: ts.patimestamp.unix_seconds(),
        cusec: ts.pausec.map_or(0, Microseconds::get),
        auth_hash: ReplayCache::hash_authenticator(blob),
    };
    if store.pa_replay().check_and_store(rkey) {
        return Err(proto(err::REPEAT, status::PREAUTH_FAILED));
    }
    Ok(())
}

/// RFC 6113 bit 1 (`KRB5_FAST_OPTION_HIDE_CLIENT_NAMES`, MIT 0x40000000): the
/// only non-reserved critical FAST option, honoured rather than refused.
const FAST_HIDE_CLIENT_NAMES_BIT: usize = 1;

fn check_fast_options(opts: &krb5_types::fast::FastOptions) -> Result<(), Error> {
    // MIT fast_util.c:226 rejects only UNSUPPORTED_CRITICAL_FAST_OPTIONS =
    // 0xbfff0000 (RFC bits 0 and 2..15). Bit 1 (hide-client-names) is honoured
    // (kdc_fast_hide_client), so it is skipped here rather than refused.
    let n = opts.len().min(16);
    for i in 0..n {
        if i == FAST_HIDE_CLIENT_NAMES_BIT {
            continue;
        }
        if opts[i] {
            return Err(crate::preauth::proto_fast(
                err::UNKNOWN_CRITICAL_FAST_OPTION,
                "FAST option",
            ));
        }
    }
    Ok(())
}

/// MIT `kdc_fast_hide_client` (fast_util.c:444): the request set RFC 6113
/// bit 1, so the reply's outer client name/realm become the anonymous principal.
fn fast_hides_client(opts: &krb5_types::fast::FastOptions) -> bool {
    opts.len() > FAST_HIDE_CLIENT_NAMES_BIT && opts[FAST_HIDE_CLIENT_NAMES_BIT]
}

/// MIT `KRB5_ANONYMOUS_REALMSTR` (krb5.hin:305): the anonymous principal's realm.
const ANONYMOUS_REALM: &str = "WELLKNOWN:ANONYMOUS";

/// MIT `krb5_anonymous_principal`: `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS`.
/// The realm is [`ANONYMOUS_REALM`].
fn anonymous_principal_name() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_WELLKNOWN, ["WELLKNOWN", "ANONYMOUS"])
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
    let (code, text, inner_ed, as_preauth, detail) = match err {
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
            (err::PREAUTH_REQUIRED, None, inner, Some(method), None)
        }
        Error::Protocol {
            code,
            text,
            e_data,
            detail,
        } => (code, text, e_data.unwrap_or_default(), None, detail),
        Error::Crypto(d) => (
            err::PREAUTH_FAILED,
            Some(status::PREAUTH_FAILED.to_owned()),
            Vec::new(),
            None,
            Some(d).filter(|s| !s.is_empty()),
        ),
        Error::Asn1(d) => (
            err::GENERIC,
            Some(status::UNKNOWN_REASON.to_owned()),
            Vec::new(),
            None,
            Some(d).filter(|s| !s.is_empty()),
        ),
        other => (
            err::GENERIC,
            Some(status::UNKNOWN_REASON.to_owned()),
            Vec::new(),
            None,
            Some(other.to_string()).filter(|s| !s.is_empty()),
        ),
    };
    let mut padata = as_preauth.unwrap_or_else(|| decode_edata_padata(&inner_ed));
    padata = with_fx_cookie(store, body.cname.as_ref(), padata);
    // MIT kdc_fast_handle_error (fast_util.c:384-386): the inner PA-FX-ERROR
    // KRB-ERROR has empty e_data; the caller's e_data (plus cookie) travels
    // as FAST inner padata next to FX-ERROR.
    let inner_err = encode_krb_error(store, code, text.as_deref(), None, Some(body));
    padata.push(PaData {
        padata_type: pa::FX_ERROR,
        padata_value: inner_err.into(),
    });
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
                        detail,
                    }
                }
            }
            Err(e) => e.into(),
        },
        Err(e) => e,
    }
}

/// `get_preauth_hint_list` METHOD-DATA: the advertise list plus one ETYPE-INFO2
/// entry for the selected client key (salt from the canonical client, empty
/// s2kparams, `_make_etype_info_entry`).
fn preauth_hint_edata(store: &dyn PrincipalRead, client: &Principal, ckey: &KeyEntry) -> Vec<u8> {
    let salt =
        krb5_types::KerberosString::try_from(String::from_utf8_lossy(&client.salt).as_ref()).ok();
    let info: EtypeInfo2 = vec![EtypeInfo2Entry {
        etype: ckey.etype.to_iana(),
        salt,
        s2kparams: None,
    }];
    let etype_info = PaData {
        padata_type: pa::ETYPE_INFO2,
        padata_value: encode(&info).map_or_else(|_| Vec::new().into(), Into::into),
    };
    let mut method: MethodData = crate::plugins::advertise_preauth(store, client);
    method.push(etype_info);
    if let Ok(c) = make_cookie(store, &client.name, &[]) {
        method.push(PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: c.into(),
        });
    }
    encode(&method).unwrap_or_default()
}

fn preauth_required(store: &dyn PrincipalRead, client: &Principal, ckey: &KeyEntry) -> Error {
    Error::PreauthRequired {
        e_data: preauth_hint_edata(store, client, ckey),
    }
}

/// MIT `finish_preauth` (`do_as_req.c:443-447`): a PREAUTH_FAILED (24) error
/// carries the same `get_preauth_hint_list` e_data as PREAUTH_REQUIRED, so the
/// client can retry with the right salt/etype. Other preauth codes (e.g. SKEW)
/// carry none.
fn attach_preauth_hint(
    store: &dyn PrincipalRead,
    client: &Principal,
    ckey: &KeyEntry,
    e: Error,
) -> Error {
    match e {
        Error::Protocol {
            code,
            text,
            e_data: None,
            detail,
        } if code == err::PREAUTH_FAILED => Error::Protocol {
            code,
            text,
            e_data: Some(preauth_hint_edata(store, client, ckey)),
            detail,
        },
        other => other,
    }
}

fn krb_error_log_fields(bytes: &[u8]) -> (i32, String) {
    match decode::<KrbError>(bytes) {
        Ok(e) => {
            let text = e
                .e_text
                .as_ref()
                .and_then(|t| std::str::from_utf8(t.as_bytes()).ok())
                .unwrap_or("")
                .to_owned();
            (e.error_code, text)
        }
        Err(_) => (0, String::new()),
    }
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
        .and_then(|b| std::str::from_utf8(b.realm.as_bytes()).ok())
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| store.realm().to_owned());
    let realm = match krb5_types::try_ascii(&realm_s) {
        Ok(r) => r,
        Err(_) => match krb5_types::try_ascii(status::TICKET_NOT_VALID) {
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
                match PrincipalName::try_new(
                    PrincipalName::NT_SRV_INST,
                    ["krbtgt", status::TICKET_NOT_VALID],
                ) {
                    Ok(n) => n,
                    Err(_) => return Vec::new(),
                }
            }
        }
    };
    let cname = body.and_then(|b| b.cname.clone());
    let pdu = KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: code,
        // MIT prepare_error_as echoes request->client. prepare_error_tgs
        // sets errpkt.client from the decrypted header ticket, else NULL;
        // opt_realm_of_principal omits crealm when client is NULL
        // (do_tgs_req.c:201-204, asn1_k_encode.c:919).
        crealm: cname.as_ref().map(|_| realm.clone()),
        cname,
        realm,
        sname,
        e_text: text.and_then(|t| krb5_types::try_ascii(t).ok()),
        e_data: e_data.map(Into::into),
    };
    encode(&pdu).unwrap_or_default()
}

fn ks(s: &str) -> Result<krb5_types::KerberosString, Error> {
    krb5_types::try_ascii(s).map_err(|_| proto(err::GENERIC, status::UNKNOWN_REASON))
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

/// MIT `check_tgs_s4u2self` (`tgs_policy.c:261-358`).
fn check_tgs_s4u2self(
    store: &dyn PrincipalRead,
    body: &krb5_types::KdcReqBody,
    s4u: &S4u2Self,
    header_cross: bool,
    is_referral: bool,
    enc_tkt: &EncTicketPart,
    header_pac: Option<&[u8]>,
) -> Result<(), Error> {
    if s4u2self_as_invalid_options(body) {
        return Err(proto(err::BADOPTION, status::INVALID_S4U2SELF_OPTIONS));
    }
    if !header_cross && is_referral {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::LOOKING_UP_SERVER));
    }
    if s4u.local.is_some() && header_cross && !is_referral {
        return Err(proto(
            err::C_PRINCIPAL_UNKNOWN,
            status::NOT_CROSS_REALM_REQUEST,
        ));
    }
    if s4u.local.is_none() && !header_cross {
        return Err(proto(err::POLICY, status::S4U2SELF_CLIENT_NOT_OURS));
    }
    if s4u.local.is_none() && s4u.user.name_string.is_empty() {
        return Err(proto(err::POLICY, status::INVALID_XREALM_S4U2SELF_REQUEST));
    }
    let Some(raw) = header_pac else {
        return Err(proto(err::TGT_REVOKED, status::S4U2SELF_NO_PAC));
    };
    let parsed = krb5_types::pac::Pac::parse(raw)
        .map_err(|_| proto(err::BADOPTION, status::S4U2SELF_LOCAL_PAC_CLIENT))?;
    let authtime = enc_tkt.authtime.unix_seconds();
    if let Some(ref client) = s4u.local {
        if !pac_client_info_eq(&parsed, authtime, &enc_tkt.cname.components_joined(), None) {
            return Err(proto(err::BADOPTION, status::S4U2SELF_LOCAL_PAC_CLIENT));
        }
        let empty = crate::store::Principal::from_keys(
            PrincipalName::new(PrincipalName::NT_UNKNOWN, std::iter::empty::<&str>()),
            String::new(),
            Vec::new(),
            Vec::new(),
            false,
            0,
            false,
            0,
        );
        validate_as_request(store, client, &empty, body)?;
    } else if !pac_client_info_eq(
        &parsed,
        authtime,
        &s4u.user.components_joined(),
        Some(&s4u.realm),
    ) {
        return Err(proto(err::BADOPTION, status::S4U2SELF_FOREIGN_PAC_CLIENT));
    }
    Ok(())
}

/// MIT `s4u2self_forwardable` (`kdc_util.c:1625-1644`).
fn s4u2self_forwardable(server: &crate::store::Principal, flags: TicketFlags) -> TicketFlags {
    if attr(server, KDB_OK_TO_AUTH_AS_DELEGATE) || server.s4u_allowed_to.is_empty() {
        return flags;
    }
    flags.with_bit(flag_bit::FORWARDABLE, false)
}

/// MIT `krb5_anonymous_principal`: the WELLKNOWN/ANONYMOUS name, compared by
/// components only like `krb5_principal_compare_any_realm` (do_as_req.c:719).
fn is_anonymous_principal(name: &PrincipalName) -> bool {
    name.components_eq(&anonymous_principal_name())
}

fn s4u2self_as_invalid_options(body: &krb5_types::KdcReqBody) -> bool {
    body.kdc_options.bit(flag_bit::FORWARDED)
        || body.kdc_options.bit(flag_bit::PROXY)
        || body.kdc_options.bit(flag_bit::VALIDATE)
        || body.kdc_options.bit(flag_bit::RENEW)
        || body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY)
        || body.kdc_options.bit(flag_bit::CNAME_IN_ADDL_TKT)
}

/// MIT `validate_as_request`: 0 = never; principal expiry before password expiry.
fn check_db_times(client: Option<&Principal>, server: &Principal) -> Result<(), Error> {
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

fn attr(p: &Principal, bit: u32) -> bool {
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
fn validate_as_request(
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
        return current_policy().check_as(store, client);
    }
    if count_locked && in_lockout_window {
        return Err(proto(err::CLIENT_REVOKED, status::CLIENT_LOCKED_OUT));
    }
    current_policy().check_as(store, client)
}

fn check_tgs_policy_flags(
    server: &Principal,
    body: &krb5_types::KdcReqBody,
    header_is_tgt: bool,
    tkt: &EncTicketPart,
) -> Result<(), Error> {
    // MIT `svc_pol_fns` order (`tgs_policy.c:60-63`): deny_opts, then deny_all,
    // then reqd_flags (time is `check_db_times`, run last by the caller). The
    // order is observable when a service sets several attributes at once.
    // deny_opts:
    if attr(server, KDB_DISALLOW_POSTDATED)
        && (body.kdc_options.bit(flag_bit::MAY_POSTDATE)
            || body.kdc_options.bit(flag_bit::POSTDATED))
    {
        return Err(proto(err::CANNOT_POSTDATE, status::NON_POSTDATABLE_TICKET));
    }
    // deny_all:
    if attr(server, KDB_DISALLOW_ALL_TIX) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::SERVER_LOCKED_OUT));
    }
    if attr(server, KDB_DISALLOW_SVR) && !body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) {
        return Err(proto(err::MUST_USE_USER2USER, status::SERVER_NOT_ALLOWED));
    }
    if attr(server, KDB_DISALLOW_TGT_BASED) && header_is_tgt {
        return Err(proto(err::POLICY, status::TGT_BASED_NOT_ALLOWED));
    }
    // reqd_flags:
    if attr(server, KDB_REQUIRES_HW_AUTH) && !tkt.flags.bit(flag_bit::HW_AUTHENT) {
        return Err(proto(err::GENERIC, status::NO_HW_PREAUTH));
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

fn utf8_realm(r: &krb5_types::Realm) -> Result<&str, Error> {
    std::str::from_utf8(r.as_bytes()).map_err(|_| proto(err::GENERIC, status::UNKNOWN_REASON))
}

#[cfg(test)]
mod a2_6_crossrealm {
    use super::tgs_header_is_crossrealm;

    #[test]
    fn is_crossrealm_is_header_realm_vs_server_realm() {
        assert!(!tgs_header_is_crossrealm("KERBER.TEST", "KERBER.TEST"));
        assert!(tgs_header_is_crossrealm("OTHER.TEST", "KERBER.TEST"));
        assert!(!tgs_header_is_crossrealm("OTHER.TEST", "OTHER.TEST"));
        assert!(tgs_header_is_crossrealm("KERBER.TEST", "OTHER.TEST"));
    }
}
