//! AS requests: the client lookup, preauth, and the reply.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt_enc_data, encrypt, krb_fx_cf2};
use krb5_types::{
    AsRep, AsReq, EncryptedData, EncryptionKey, EtypeInfo, EtypeInfo2, EtypeInfo2Entry,
    EtypeInfoEntry, KdcReqBody, KerberosString, KerberosTime, MethodData, OctetString, PaData,
    PaEncTsEnc, PrincipalName, TransitedEncoding, err, flag_bit, ku, pa,
};

use super::fast_util::{check_fast_options, fast_hides_client, wrap_as_fast};
use super::kdc_util::{
    attr, enctype_requires_etype_info_2, get_ticket_flags, include_pac_for_reply,
    kdc_get_ticket_endtime, kdc_get_ticket_renewtime, kdc_req_body_der, ks, select_session_keytype,
    utf8_realm, validate_as_request,
};
use super::reply::{
    MintTicket, TicketPac, enc_rep_part, encode_enc_kdc_rep_part, mint_ticket, return_enc_padata,
};
use crate::ad::{authind_add, check_indicators, handle_authdata};
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::plugins::{
    PreauthAction, PreauthRock, enforce_kdcpolicy_as, finish_verify_padata, run_as_preauth,
};
use crate::preauth::{
    FastOk, decode_edata_padata, fast_finished, find_pa, make_cookie, mint_freshness_token_now,
    pa_cookie_last, proto, unwrap_fast, wrap_fast_rep,
};
use crate::status;
use crate::store::{
    KDB_NO_AUTH_DATA_REQUIRED, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PRE_AUTH, KeyEntry, Principal,
    random_key,
};

#[derive(Debug)]
pub struct IssuedAs {
    pub rep: AsRep,
    pub session_key: ProtocolKey,
    pub as_rep_key: ProtocolKey,
}

// MIT: `process_as_req` (do_as_req.c:577-607)
fn lookup_as_princ(
    store: &dyn PrincipalRead,
    name: &PrincipalName,
    looking_up: &'static str,
) -> Result<Option<crate::store::Principal>, Error> {
    match store.fetch_name(name) {
        Ok(v) => Ok(v),
        Err(e) => {
            let (code, detail) = match e {
                Error::Protocol { code, detail, .. } if code == err::SVC_UNAVAILABLE => {
                    (err::SVC_UNAVAILABLE, detail)
                }
                other => (err::GENERIC, Some(other.to_string())),
            };
            Err(Error::Protocol {
                code,
                text: Some(looking_up.to_owned()),
                e_data: None,
                detail,
            })
        }
    }
}

pub fn issue_as(store: &dyn PrincipalRead, req: &AsReq) -> Result<IssuedAs, Error> {
    issue_as_from(store, req, None)
}

pub(super) fn issue_as_from(
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

struct AsLookup {
    client: Principal,
    cname: PrincipalName,
    sname: PrincipalName,
    server: Principal,
    session_etype: EncryptionType,
    work_padata: Option<Vec<PaData>>,
    req_cname: PrincipalName,
    ckey: Option<KeyEntry>,
}

struct AsPreauth {
    client: Principal,
    cname: PrincipalName,
    sname: PrincipalName,
    server: Principal,
    session_etype: EncryptionType,
    work_padata: Option<Vec<PaData>>,
    ckey: Option<KeyEntry>,
    extra_padata: Vec<PaData>,
    as_rep_key: Option<ProtocolKey>,
    skip_timestamp: bool,
    hw_preauth: bool,
    reply_key_replaced: bool,
    auth_indicators: Vec<String>,
    anonymous_as: bool,
}

// MIT: `finish_process_as_req` (kdc/do_as_req.c:340-365)
// MIT: `process_as_req` (kdc/do_as_req.c:522-526)
fn issue_as_body(
    store: &dyn PrincipalRead,
    req: &AsReq,
    raw: Option<&[u8]>,
    body: &KdcReqBody,
    fast: Option<&FastOk>,
) -> Result<IssuedAs, Error> {
    let kdc_time = crate::store::unix_now_u32();
    let mut client = None;
    let out = issue_as_steps(store, req, raw, body, fast, kdc_time, &mut client);
    if let Some(client) = &client {
        crate::lockout::lockout_audit(store, client, kdc_time, crate::lockout::as_outcome(&out));
    }
    out
}

fn issue_as_steps(
    store: &dyn PrincipalRead,
    req: &AsReq,
    raw: Option<&[u8]>,
    body: &KdcReqBody,
    fast: Option<&FastOk>,
    kdc_time: u32,
    audited: &mut Option<Principal>,
) -> Result<IssuedAs, Error> {
    let lookup = lookup_client(store, req, body, fast, kdc_time, audited)?;
    let pre = finish_preauth(store, req, raw, body, fast, lookup)?;
    finish_process_as_req(store, req, raw, body, fast, pre, kdc_time)
}

// MIT: `process_as_req` (kdc/do_as_req.c:718-733)
/// Preauth is set on the audit copy only, so a success stamps last_success.
fn audit_entry(client: &Principal, body: &KdcReqBody, req_cname: &PrincipalName) -> Principal {
    let mut entry = client.clone();
    if body.kdc_options.bit(flag_bit::ANONYMOUS) && is_anonymous_principal(req_cname) {
        entry.attributes |= KDB_REQUIRES_PRE_AUTH;
    }
    entry
}

// MIT: `lookup_client` (do_as_req.c:134-151)
// MIT: `validate_as_request` (kdc_util.c:716-716)
// MIT: `select_client_key` (do_as_req.c:103-103)
// MIT: `kdc_find_fast` (fast_util.c:226-226)
// MIT: `process_as_req` (do_as_req.c:641-641)
fn lookup_client(
    store: &dyn PrincipalRead,
    req: &AsReq,
    body: &KdcReqBody,
    fast: Option<&FastOk>,
    kdc_time: u32,
    audited: &mut Option<Principal>,
) -> Result<AsLookup, Error> {
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
    let mut client = lookup_as_princ(store, &req_cname, status::LOOKING_UP_CLIENT)?
        .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, status::CLIENT_NOT_FOUND))?;
    store.merge_lockout(&mut client);
    *audited = Some(audit_entry(&client, body, &req_cname));
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
    let server = lookup_as_princ(store, &sname, status::LOOKING_UP_SERVER)?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::SERVER_NOT_FOUND))?;
    // MIT: `process_as_req` (do_as_req.c:630-630)
    validate_as_request(store, &client, &server, body, kdc_time)?;
    let session_etype = select_session_keytype(&server, &body.etype, store.policy())?;
    let work_padata = if let Some(f) = fast {
        Some(f.inner_padata.clone())
    } else {
        req.0.padata.clone()
    };
    // MIT: `have_client_keys` (kdc_preauth.c:442-442)
    // MIT: `process_as_req` (do_as_req.c:736-745)
    // MIT: `finish_process_as_req` (do_as_req.c:259-265)
    // A missing client key waits until after preauth; a module may replace it.
    let ckey = select_client_key(store.policy(), &client, &body.etype).cloned();
    Ok(AsLookup {
        client,
        cname,
        sname,
        server,
        session_etype,
        work_padata,
        req_cname,
        ckey,
    })
}

// MIT: `finish_preauth` (do_as_req.c:434-466)
// MIT: `process_as_req` (do_as_req.c:758-758)
// MIT: `process_as_req` (do_as_req.c:716-734)
fn finish_preauth(
    store: &dyn PrincipalRead,
    req: &AsReq,
    raw: Option<&[u8]>,
    body: &KdcReqBody,
    fast: Option<&FastOk>,
    lookup: AsLookup,
) -> Result<AsPreauth, Error> {
    let AsLookup {
        client,
        mut cname,
        sname,
        server,
        session_etype,
        work_padata,
        req_cname,
        ckey: ckey_owned,
    } = lookup;
    let ckey = ckey_owned.as_ref();
    let armor = fast.map(|f| &f.armor_key);
    let encoded_body;
    let body_der: &[u8] = if let Some(slice) = raw.and_then(kdc_req_body_der) {
        slice
    } else {
        encoded_body = encode(body)?;
        &encoded_body
    };
    let pa_body: &[u8] = match fast {
        Some(f) => f.inner_body.as_slice(),
        None => body_der,
    };
    // MIT: `ec_verify` (kdc_preauth_ec.c:71-76)
    // MIT: `find_pa_system` (kdc_preauth.c:606-619)
    let ec_loaded = crate::plugins::kdcpreauth_loaded(store, "encrypted_challenge");
    if ec_loaded
        && fast.is_none()
        && work_padata
            .as_deref()
            .into_iter()
            .flatten()
            .any(|p| p.padata_type == pa::ENCRYPTED_CHALLENGE)
    {
        return Err(attach_preauth_hint(
            store,
            &client,
            ckey,
            &body.etype,
            None,
            // MIT: `ec_verify` (kdc_preauth_ec.c:71-76)
            finish_verify_padata(
                EC_MODULE,
                Error::PreauthModule {
                    code: ENOENT,
                    message: "Encrypted Challenge used outside of FAST tunnel".to_owned(),
                },
            ),
            work_padata.as_deref(),
        ));
    }
    // MIT: `process_as_req` (do_as_req.c:718-734)
    let mut anonymous_as = false;
    if body.kdc_options.bit(flag_bit::ANONYMOUS) {
        if !is_anonymous_principal(&req_cname) {
            return Err(proto(err::BADOPTION, status::VALIDATE_ANONYMOUS_PRINCIPAL));
        }
        cname = anonymous_principal_name();
        anonymous_as = true;
    }

    let mut extra_padata: Vec<PaData> = Vec::new();
    let mut as_rep_key = ckey.map(|k| k.key.clone());
    let mut skip_timestamp = false;
    let hw_preauth = false;
    let mut reply_key_replaced = false;
    let mut auth_indicators: Vec<String> = Vec::new();
    let as_req_der = match raw {
        Some(r) => r.to_vec(),
        None => encode(req)?,
    };
    match run_as_preauth(&PreauthRock {
        store,
        client: &client,
        padata: work_padata.as_deref(),
        ikey: ckey.map(|k| &k.key),
        etype: ckey.map(|k| k.etype),
        armor_key: armor,
        as_req_der: &as_req_der,
        body_der: pa_body,
        cname: &cname,
    })
    .map_err(|e| {
        attach_preauth_hint(
            store,
            &client,
            ckey,
            &body.etype,
            armor,
            e,
            work_padata.as_deref(),
        )
    })? {
        Some(PreauthAction::Pkinit { key, pa, signed }) => {
            as_rep_key = Some(key);
            extra_padata.push(pa);
            skip_timestamp = true;
            reply_key_replaced = true;
            if signed {
                for ind in &store.policy().pkinit_indicators {
                    authind_add(&mut auth_indicators, ind);
                }
            }
        }
        Some(PreauthAction::Challenge(e_data)) => {
            // MIT: `prepare_error_as` (do_as_req.c:809-809)
            // MIT: `maybe_add_etype_info2` (kdc_preauth.c:1141-1170)
            // MIT: `finish_preauth` (do_as_req.c:439-442)
            // MIT: `prepare_error_as` (do_as_req.c:785-795)
            let mut method = decode_edata_padata(&e_data);
            if let Some(ckey) = ckey
                && find_pa(work_padata.as_deref(), pa::FX_COOKIE).is_none()
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
                e_data: Some(encode(&pa_cookie_last(method)).unwrap_or(e_data)),
                detail: None,
            });
        }
        Some(PreauthAction::Otp { key, indicators }) => {
            // MIT: `on_response` (plugins/preauth/otp/main.c:167-188)
            // MIT: `return_padata` (kdc/kdc_preauth.c:1470-1493)
            as_rep_key = Some(key);
            skip_timestamp = true;
            for ind in &indicators {
                authind_add(&mut auth_indicators, ind);
            }
        }
        Some(PreauthAction::SpakeDone(k)) => {
            // MIT: `verify_response` (spake_kdc.c:464-464)
            // MIT: `replace_reply_key` (kdc_preauth.c:567-580)
            as_rep_key = Some(k);
            skip_timestamp = true;
            for ind in &store.policy().spake_preauth_indicators {
                authind_add(&mut auth_indicators, ind);
            }
        }
        Some(PreauthAction::EncTsOk) => {
            skip_timestamp = true;
        }
        None => {}
    }
    if ec_loaded
        && !skip_timestamp
        && let Some(f) = fast
        && let Some(blob) = find_pa(Some(&f.inner_padata), pa::ENCRYPTED_CHALLENGE)
        && !blob.is_empty()
    {
        // MIT: `ec_verify` (kdc_preauth_ec.c:97-98)
        let Some(ckey) = ckey else {
            return Err(finish_verify_padata(
                EC_MODULE,
                Error::PreauthModule {
                    code: ENOENT,
                    message: "No such file or directory".to_owned(),
                },
            ));
        };
        match verify_encrypted_challenge(store, &ckey.key, &f.armor_key, blob) {
            Ok(()) => {
                skip_timestamp = true;
                extra_padata.push(kdc_encrypted_challenge(&f.armor_key, &ckey.key)?);
                if let Some(ai) = store.policy().encrypted_challenge_indicator.as_deref() {
                    authind_add(&mut auth_indicators, ai);
                }
            }
            Err(e) => return Err(finish_verify_padata(EC_MODULE, e)),
        }
    }
    if (client.requires_preauth() || anonymous_as) && !skip_timestamp {
        return Err(preauth_required(
            store,
            &client,
            ckey,
            &body.etype,
            armor,
            work_padata.as_deref(),
        ));
    }
    if attr(&client, KDB_REQUIRES_HW_AUTH) && !hw_preauth {
        return Err(Error::Protocol {
            code: err::PREAUTH_REQUIRED,
            text: Some(status::NEEDED_HW_PREAUTH.to_owned()),
            e_data: Some(preauth_hint_edata(
                store,
                &client,
                ckey,
                &body.etype,
                armor,
                work_padata.as_deref(),
            )),
            detail: None,
        });
    }
    Ok(AsPreauth {
        client,
        cname,
        sname,
        server,
        session_etype,
        work_padata,
        ckey: ckey_owned,
        extra_padata,
        as_rep_key,
        skip_timestamp,
        hw_preauth,
        reply_key_replaced,
        auth_indicators,
        anonymous_as,
    })
}

// MIT: `finish_process_as_req` (do_as_req.c:194-423)
// MIT: `process_as_req` (do_as_req.c:651-703)
fn finish_process_as_req(
    store: &dyn PrincipalRead,
    req: &AsReq,
    raw: Option<&[u8]>,
    body: &KdcReqBody,
    fast: Option<&FastOk>,
    pre: AsPreauth,
    kdc_time: u32,
) -> Result<IssuedAs, Error> {
    let AsPreauth {
        client,
        cname,
        sname,
        server,
        session_etype,
        work_padata,
        ckey,
        mut extra_padata,
        as_rep_key,
        skip_timestamp,
        hw_preauth,
        reply_key_replaced,
        auth_indicators,
        anonymous_as,
    } = pre;
    let skey = store
        .policy()
        .first_current_key(&server)
        .map_err(|_| proto(err::GENERIC, status::FINDING_SERVER_KEY))?;
    // MIT: `finish_process_as_req` (do_as_req.c:259-265)
    let Some(as_rep_key) = as_rep_key else {
        return Err(proto(err::ETYPE_NOSUPP, status::CANT_FIND_CLIENT_KEY));
    };
    let mut session = random_key(session_etype)?;
    if anonymous_as {
        extra_padata.push(pa_pkinit_kx(&as_rep_key, &session)?);
        session = krb_fx_cf2(&session, &as_rep_key, b"PKINIT", b"KEYEXCHANGE")?;
    }
    // MIT: `process_as_req` (kdc/do_as_req.c:672-672)
    let now = KerberosTime::from_unix_seconds(kdc_time);
    let starttime = if body.kdc_options.bit(flag_bit::POSTDATED) {
        body.from
            .clone()
            .unwrap_or_else(|| KerberosTime::from_unix_seconds(0))
    } else {
        now.clone()
    };
    let mut flags = get_ticket_flags(&body.kdc_options, Some(&client), &server, None)
        .with_bit(flag_bit::PRE_AUTHENT, skip_timestamp)
        .with_bit(flag_bit::HW_AUTHENT, hw_preauth);
    let want_enc_pa = find_pa(req.0.padata.as_deref(), pa::REQ_ENC_PA_REP).is_some()
        || fast.is_some_and(|f| find_pa(Some(&f.inner_padata), pa::REQ_ENC_PA_REP).is_some());
    let mut end =
        kdc_get_ticket_endtime(store, &starttime, None, &body.till, Some(&client), &server)?;
    let mut ticket_renew_till = kdc_get_ticket_renewtime(
        store,
        body,
        None,
        Some(&client),
        &server,
        &mut flags,
        &starttime,
        &end,
    );
    enforce_kdcpolicy_as(
        store,
        body,
        &client,
        &server,
        &auth_indicators,
        &now,
        &mut end,
        &mut ticket_renew_till,
    )?;
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
    let krbtgt_key = store
        .policy()
        .first_current_key(&krbtgt_p)
        .map_err(|_| proto(err::GENERIC, status::GET_LOCAL_TGT))?;
    let pac_kdc = crate::ad::pac_privsvr_key(
        &server,
        if sname.is_krbtgt_for(store.realm()) {
            &skey.key
        } else {
            &krbtgt_key.key
        },
    )?;
    // MIT: `process_as_req` (do_as_req.c:660-666)
    // MIT: `finish_process_as_req` (do_as_req.c:243-243)
    // Canonicalized krbtgt uses the database name, for a short-realm alias.
    let ticket_sname = if body.kdc_options.bit(flag_bit::CANONICALIZE)
        && sname.is_krbtgt()
        && server.name.is_krbtgt()
    {
        server.name.clone()
    } else {
        sname.clone()
    };
    let extra_ad = handle_authdata(
        false,
        flags.bit(flag_bit::ANONYMOUS),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .map_err(|e| crate::ad::authdata_failed("AS_REQ", e))?;
    check_indicators(&server, &auth_indicators)?;
    let issue_crealm = if anonymous_as {
        ANONYMOUS_REALM
    } else {
        store.realm()
    };
    let ticket = mint_ticket(MintTicket {
        service_key: &skey.key,
        kvno: skey.kvno,
        service_etype: skey.etype,
        session: &session,
        srealm: store.realm(),
        sname: &ticket_sname,
        crealm: issue_crealm,
        cname: &cname,
        authtime: &now,
        endtime: &end,
        flags: flags.clone(),
        kdc_key: &pac_kdc,
        transited: TransitedEncoding::empty(),
        renew_till: ticket_renew_till.clone(),
        store,
        // MIT: `handle_pac` (kdc_authdata.c:540-544)
        pac: include_pac.then(|| {
            if crate::ad::pac_has_ad_data(store.policy(), None, true) {
                TicketPac::Ad {
                    logon_override: None,
                    subject_pac: None,
                    s4u_client_info: None,
                    identity: None,
                }
            } else {
                TicketPac::Mit(crate::ad::HandlePac::default())
            }
        }),
        starttime: &starttime,
        caddr: body.addresses.clone(),
        extra_ad,
        indicators: &auth_indicators,
        krbtgt: &krbtgt_p,
        krbtgt_key: &krbtgt_key.key,
        no_auth_data: attr(&server, KDB_NO_AUTH_DATA_REQUIRED),
        kind: "AS_REQ",
    })?;
    let renew_till = ticket_renew_till;
    let mut reply_key = as_rep_key.clone();
    let mut outer_padata = extra_padata;
    // MIT: `add_etype_info` (kdc_preauth.c:769-800)
    // MIT: `add_pw_salt` (kdc_preauth.c:802-824)
    // MIT: `add_freshness_token` (kdc_preauth.c:826-829)
    // MIT: `return_padata` (kdc_preauth.c:1487-1495)
    // A replaced reply key is not described.
    if !reply_key_replaced && ckey.is_some() {
        outer_padata.extend(as_rep_key_info(&client, as_rep_key.etype(), &body.etype));
    }
    if let Some(f) = fast {
        // MIT: `kdc_fast_response_handle_padata` (fast_util.c:292-296)
        let sk = random_key(as_rep_key.etype())?;
        reply_key = krb_fx_cf2(&sk, &as_rep_key, b"strengthenkey", b"replykey")?;
        let finished = fast_finished(&f.armor_key, &ticket, &cname, issue_crealm)?;
        let inner = std::mem::take(&mut outer_padata);
        outer_padata = vec![wrap_fast_rep(
            &f.armor_key,
            inner,
            Some(&sk),
            f.nonce,
            Some(finished),
        )?];
    }
    let enc_part = enc_rep_part(
        &session,
        fast.map_or(body.nonce, |f| f.nonce),
        &now,
        &starttime,
        &end,
        store.realm(),
        &ticket_sname,
        flags,
        renew_till,
        return_enc_padata(raw, work_padata.as_deref(), &reply_key, want_enc_pa, None)?,
        body.addresses.clone(),
        get_key_exp(&client),
    )?;
    let enc_der = encode_enc_kdc_rep_part(enc_part)?;
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART)?;
    let cipher =
        crate::ad::crypto_at(encrypt(&reply_key, usage, &enc_der), status::UNKNOWN_REASON)?;
    // The enc-part kvno stays unset; MIT fills it only after encoding.
    let kvno = None;
    let padata = if outer_padata.is_empty() {
        None
    } else {
        Some(outer_padata)
    };
    // MIT: `finish_process_as_req` (do_as_req.c:324-324)
    let (rep_crealm, rep_cname) = if fast.is_some_and(|f| fast_hides_client(&f.fast_options)) {
        (ks(ANONYMOUS_REALM)?, anonymous_principal_name())
    } else {
        (ks(issue_crealm)?, cname)
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

// MIT: `get_key_exp` (do_as_req.c:83-91)
fn get_key_exp(client: &crate::store::Principal) -> Option<KerberosTime> {
    let exp = client.expiration;
    let pw = client.pw_expire;
    let ts = if exp == 0 {
        pw
    } else if pw == 0 {
        exp
    } else {
        exp.min(pw)
    };
    (ts != 0).then(|| KerberosTime::from_unix_seconds(ts))
}

// MIT: `add_etype_info` (kdc_preauth.c:769-799)
fn etype_info_padata(client: &Principal, etype: EncryptionType, requested: &[i32]) -> Vec<PaData> {
    let mut out = Vec::new();
    let salt = KerberosString::try_from(String::from_utf8_lossy(&client.salt).as_ref()).ok();
    let etype = etype.to_iana();
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

// MIT: `add_etype_info` (kdc_preauth.c:769-800)
// MIT: `add_pw_salt` (kdc_preauth.c:802-824)
fn as_rep_key_info(client: &Principal, etype: EncryptionType, requested: &[i32]) -> Vec<PaData> {
    let mut out = etype_info_padata(client, etype, requested);
    if !requested.iter().copied().any(enctype_requires_etype_info_2) {
        out.push(PaData {
            padata_type: pa::PW_SALT,
            padata_value: client.salt.clone().into(),
        });
    }
    out
}

// MIT: `select_client_key` (do_as_req.c:104-130)
/// Kvno 0 is the highest kvno only.
fn select_client_key<'a>(
    policy: &crate::store::Policy,
    princ: &'a Principal,
    requested: &[i32],
) -> Option<&'a KeyEntry> {
    for n in requested {
        if let Ok(e) = EncryptionType::known(*n)
            && let Ok(k) = policy.find_enctype(princ, Some(e), 0)
        {
            return Some(k);
        }
    }
    None
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

// MIT: `kdcpreauth_encrypted_challenge_initvt` (kdc/kdc_preauth_ec.c:219-219)
const EC_MODULE: &str = "encrypted_challenge";

const ENOENT: i32 = 2;

fn asn1_failure(der: &[u8], first_field_explicit: bool) -> Error {
    crate::asn1_text::preauth_decode_failure(der, first_field_explicit)
}

// MIT: `ec_verify` (kdc/kdc_preauth_ec.c:121-128)
// MIT: `ec_verify` (kdc/kdc_preauth_ec.c:79-81)
// MIT: `ec_verify` (kdc/kdc_preauth_ec.c:114-118)
/// Inside the skew a replay verifies again.
fn verify_encrypted_challenge(
    store: &dyn PrincipalRead,
    long_term: &ProtocolKey,
    armor_key: &ProtocolKey,
    blob: &[u8],
) -> Result<(), Error> {
    let enc: EncryptedData = decode(blob).map_err(|_| asn1_failure(blob, true))?;
    let chal = krb_fx_cf2(
        armor_key,
        long_term,
        b"clientchallengearmor",
        b"challengelongterm",
    )?;
    let usage = KeyUsage::new(ku::ENC_CHALLENGE_CLIENT)?;
    let plain = decrypt_enc_data(&chal, usage, enc.etype, enc.cipher.as_ref()).map_err(|_| {
        Error::PreauthModule {
            code: err::PREAUTH_FAILED,
            message: "Incorrect password in encrypted challenge".to_owned(),
        }
    })?;
    let ts: PaEncTsEnc = decode(&plain).map_err(|_| asn1_failure(&plain, true))?;
    // MIT: `ec_verify` (kdc/kdc_preauth_ec.c:124-124)
    let now = i64::from(KerberosTime::now().unix_seconds());
    let then = i64::from(ts.patimestamp.unix_seconds());
    if (now - then).abs() > store.policy().skew {
        return Err(proto(err::SKEW, status::PREAUTH_FAILED));
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

// MIT: `enc_ts_verify` (kdc/kdc_preauth_encts.c:94-101)
/// Inside the skew a replay verifies again.
pub(crate) fn verify_enc_timestamp(
    store: &dyn PrincipalRead,
    key: &ProtocolKey,
    blob: &[u8],
) -> Result<(), Error> {
    let enc: EncryptedData = decode(blob)?;
    let usage = KeyUsage::new(ku::PA_ENC_TIMESTAMP)?;
    let plain = decrypt_enc_data(key, usage, enc.etype, enc.cipher.as_ref())?;
    let ts: PaEncTsEnc = decode(&plain).map_err(|_| asn1_failure(&plain, true))?;
    // MIT: `enc_ts_verify` (kdc/kdc_preauth_encts.c:97-97)
    let now = i64::from(KerberosTime::now().unix_seconds());
    let then = i64::from(ts.patimestamp.unix_seconds());
    if (now - then).abs() > store.policy().skew {
        return Err(proto(err::SKEW, status::PREAUTH_FAILED));
    }
    Ok(())
}

// MIT: `KRB5_ANONYMOUS_REALMSTR` (krb5.hin:305-305)
pub(super) const ANONYMOUS_REALM: &str = "WELLKNOWN:ANONYMOUS";

pub(super) fn anonymous_principal_name() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_WELLKNOWN, ["WELLKNOWN", "ANONYMOUS"])
}

// MIT: `get_preauth_hint_list` (kdc_preauth.c:974-1014)
fn preauth_hint_edata(
    store: &dyn PrincipalRead,
    client: &Principal,
    ckey: Option<&KeyEntry>,
    requested: &[i32],
    armor: Option<&ProtocolKey>,
    request_padata: Option<&[PaData]>,
) -> Vec<u8> {
    let hint =
        crate::plugins::advertise_preauth(store, client, armor, requested, ckey.map(|k| &k.key));
    let mut method: MethodData = hint.padata;
    // MIT: `add_etype_info` (kdc_preauth.c:776-778)
    if let Some(ckey) = ckey {
        let info = etype_info_padata(client, ckey.etype, requested);
        let at = usize::from(method.first().is_some_and(|p| p.padata_type == pa::FX_FAST));
        for (i, p) in info.into_iter().enumerate() {
            method.insert(at + i, p);
        }
    }
    // MIT: `hint_list_finish` (kdc_preauth.c:895-898)
    // MIT: `add_freshness_token` (kdc_preauth.c:826-871)
    if store.pkinit().is_some()
        && request_padata
            .into_iter()
            .flatten()
            .any(|p| p.padata_type == pa::AS_FRESHNESS)
        && let Ok(tok) = mint_freshness_token_now(store)
    {
        method.push(PaData {
            padata_type: pa::AS_FRESHNESS,
            padata_value: tok.into(),
        });
    }
    // MIT: `kdc_fast_make_cookie` (fast_util.c:655-721)
    if let Ok(c) = make_cookie(store, &client.name, &hint.cookie) {
        method.push(PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: c.into(),
        });
    }
    encode(&method).unwrap_or_default()
}

fn preauth_required(
    store: &dyn PrincipalRead,
    client: &Principal,
    ckey: Option<&KeyEntry>,
    requested: &[i32],
    armor: Option<&ProtocolKey>,
    request_padata: Option<&[PaData]>,
) -> Error {
    Error::PreauthRequired {
        e_data: preauth_hint_edata(store, client, ckey, requested, armor, request_padata),
    }
}

// MIT: `finish_preauth` (do_as_req.c:443-447)
/// A failed or expired preauth carries the hint list so the client can retry.
fn attach_preauth_hint(
    store: &dyn PrincipalRead,
    client: &Principal,
    ckey: Option<&KeyEntry>,
    requested: &[i32],
    armor: Option<&ProtocolKey>,
    e: Error,
    request_padata: Option<&[PaData]>,
) -> Error {
    match e {
        Error::Protocol {
            code,
            text,
            e_data: None,
            detail,
        } if code == err::PREAUTH_FAILED || code == err::PREAUTH_EXPIRED => Error::Protocol {
            code: err::PREAUTH_FAILED,
            text,
            e_data: Some(preauth_hint_edata(
                store,
                client,
                ckey,
                requested,
                armor,
                request_padata,
            )),
            detail,
        },
        other => other,
    }
}

// MIT: `process_as_req` (do_as_req.c:719-719)
/// The anonymous name matches by components, in any realm.
pub(super) fn is_anonymous_principal(name: &PrincipalName) -> bool {
    name.components_eq(&anonymous_principal_name())
}

fn pa_pkinit_kx(reply_key: &ProtocolKey, contrib: &ProtocolKey) -> Result<PaData, Error> {
    let key = EncryptionKey {
        keytype: contrib.etype().to_iana(),
        keyvalue: contrib.as_bytes().to_vec().into(),
    };
    let plain = encode(&key)?;
    let usage = KeyUsage::new(ku::PA_PKINIT_KX)?;
    let cipher = encrypt(reply_key, usage, &plain)?;
    let enc = EncryptedData {
        etype: reply_key.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    };
    Ok(PaData {
        padata_type: pa::PKINIT_KX,
        padata_value: encode(&enc)?.into(),
    })
}
