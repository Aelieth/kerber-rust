//! Issued tickets and KRB-ERROR (`do_as_req.c` / `do_tgs_req.c`
//! `prepare_error_*`, `kdc_preauth.c` `return_enc_padata`):
//! `mint_ticket`, `enc_rep_part`, and the AS/TGS reply wrappers.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_types::pac::{PacIdentity, parse_kerb_validation_info};
use krb5_types::s4u::PaPacOptions;
use krb5_types::{
    AsReq, AuthorizationData, EncKdcRepPart, EncTgsRepPart, EncTicketPart, EncryptedData,
    HostAddress, HostAddresses, KerberosTime, KrbError, LastReqValue, Microseconds, PaData,
    PrincipalName, TgsReq, Ticket, TicketFlags, TransitedEncoding, err, ku, pa,
};

use super::as_req::{ANONYMOUS_REALM, anonymous_principal_name, issue_as_from};
use super::fast_util::{peek_as_hides_client, peek_tgs_hides_client};
use super::kdc_util::{enc_pa_rep_padata, encryption_key, ks, omit_start_if_auth};
use super::tgs_req::{issue_tgs_from, tgs_header_client};
use crate::ad::{add_auth_indicators, wrap_win2k_pac};
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::preauth::{find_pa, prepare_as_edata, proto_d};
use crate::status;
use crate::store::Principal;

/// KRB-ERROR with empty text (`make_too_big_error` / `make_toolong_error`).
#[must_use]
pub fn kdc_error_bytes(store: &dyn PrincipalRead, code: i32) -> Vec<u8> {
    encode_krb_error(store, code, None, None, None, false)
}

pub(super) fn as_reply(
    store: &dyn PrincipalRead,
    req: &AsReq,
    raw: &[u8],
) -> Result<(Vec<u8>, Option<String>), Error> {
    let body = Some(&req.0.req_body);
    let hide = peek_as_hides_client(store, req, raw);
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
                hide,
            ),
            None,
        )),
        Err(Error::Protocol {
            code,
            text,
            e_data,
            detail,
        }) => {
            // do_as_req.c:371-372: `KRB5KDC_ERR_DISCARD` skips
            // `prepare_error_as` (no KRB-ERROR). The filter kept the code
            // (`kdc_preauth.c:1125`); `dispatch.c:78` also drops it.
            if code == err::DISCARD {
                return Ok((Vec::new(), detail.filter(|s| !s.is_empty())));
            }
            Ok((
                encode_krb_error(
                    store,
                    code,
                    text.as_deref(),
                    e_data.map(|ed| prepare_as_edata(store, req.0.req_body.cname.as_ref(), &ed)),
                    body,
                    hide,
                ),
                detail.filter(|s| !s.is_empty()),
            ))
        }
        Err(Error::Crypto(d)) => Ok((
            encode_krb_error(
                store,
                err::PREAUTH_FAILED,
                Some(status::PREAUTH_FAILED),
                None,
                body,
                hide,
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
                hide,
            ),
            Some(d).filter(|s| !s.is_empty()),
        )),
        // do_as_req.c:346-347: an error that set no status of its own is
        // `UNKNOWN_REASON` (the lookups label theirs in `lookup_as_princ`).
        Err(e) => Ok((
            encode_krb_error(
                store,
                err::GENERIC,
                Some(status::UNKNOWN_REASON),
                None,
                body,
                hide,
            ),
            Some(e.to_string()).filter(|s| !s.is_empty()),
        )),
    }
}

pub(super) fn tgs_reply(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    raw: &[u8],
    sender: Option<&HostAddress>,
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
    let hide = peek_tgs_hides_client(store, req, raw, sender);
    match issue_tgs_from(store, req, Some(raw), sender) {
        Ok(issued) => Ok((encode(&issued.rep)?, None)),
        Err(Error::Protocol {
            code,
            text,
            e_data,
            detail,
        }) => Ok((
            encode_krb_error(store, code, text.as_deref(), e_data, body, hide),
            detail.filter(|s| !s.is_empty()),
        )),
        Err(Error::Crypto(d)) => Ok((
            encode_krb_error(
                store,
                err::BAD_INTEGRITY,
                Some(status::PROCESS_TGS),
                None,
                body,
                hide,
            ),
            Some(d).filter(|s| !s.is_empty()),
        )),
        Err(Error::Asn1(d)) => Ok((
            encode_krb_error(
                store,
                err::GENERIC,
                Some(status::PROCESS_TGS),
                None,
                body,
                hide,
            ),
            Some(d).filter(|s| !s.is_empty()),
        )),
        Err(e) => Ok((
            encode_krb_error(
                store,
                err::GENERIC,
                Some(status::PROCESS_TGS),
                None,
                body,
                hide,
            ),
            Some(e.to_string()).filter(|s| !s.is_empty()),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn mint_ticket(
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
    caddr: Option<HostAddresses>,
    s4u_client_info: Option<&str>,
    extra_ad: Option<AuthorizationData>,
    indicators: &[String],
    krbtgt: &Principal,
    krbtgt_key: &ProtocolKey,
    no_auth_data: bool,
) -> Result<Ticket, Error> {
    let mut extra = extra_ad.unwrap_or_default();
    let mut part = EncTicketPart {
        flags,
        key: encryption_key(session),
        crealm: ks(crealm)?,
        cname: cname.clone(),
        transited,
        authtime: authtime.clone(),
        starttime: omit_start_if_auth(starttime, authtime),
        endtime: endtime.clone(),
        renew_till,
        caddr,
        authorization_data: None,
    };
    if !no_auth_data {
        add_auth_indicators(
            &mut extra,
            indicators,
            service_key,
            krbtgt,
            krbtgt_key,
            &part,
        )?;
    }
    if include_pac {
        let placeholder = wrap_win2k_pac(&[0])?;
        let mut checksum_ad = extra.clone();
        checksum_ad.splice(0..0, placeholder);
        part.authorization_data = Some(checksum_ad);
        let checksum_der = encode(&part)?;
        let ident = if let Some(b) = logon_override {
            let v = parse_kerb_validation_info(b).map_err(|e| {
                proto_d(
                    err::BAD_INTEGRITY,
                    status::HANDLE_AUTHDATA,
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
        let pac = crate::ad::sign_reply_pac_s4u(
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
            s4u_client_info,
        )?;
        let mut signed = wrap_win2k_pac(&pac)?;
        signed.extend(extra);
        part.authorization_data = Some(signed);
    } else if !extra.is_empty() {
        part.authorization_data = Some(extra);
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

pub(super) fn encode_enc_kdc_rep_part(part: EncKdcRepPart) -> Result<Vec<u8>, Error> {
    Ok(encode(&EncTgsRepPart(part))?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn enc_rep_part(
    session: &ProtocolKey,
    nonce: u32,
    authtime: &KerberosTime,
    starttime: &KerberosTime,
    end: &KerberosTime,
    realm: &str,
    sname: &PrincipalName,
    flags: TicketFlags,
    renew_till: Option<KerberosTime>,
    encrypted_pa_data: Option<Vec<PaData>>,
    caddr: Option<HostAddresses>,
    key_expiration: Option<KerberosTime>,
) -> Result<EncKdcRepPart, Error> {
    Ok(EncKdcRepPart {
        key: encryption_key(session),
        last_req: vec![LastReqValue {
            lr_type: 0,
            lr_value: KerberosTime::from_unix_seconds(0),
        }],
        nonce,
        key_expiration,
        flags,
        authtime: authtime.clone(),
        starttime: omit_start_if_auth(starttime, authtime),
        endtime: end.clone(),
        renew_till,
        srealm: ks(realm)?,
        sname: sname.clone(),
        caddr,
        encrypted_pa_data,
    })
}

/// MIT `return_enc_padata` (`kdc_preauth.c:1636-1663`): FAST nego then
/// PA-PAC-OPTIONS masked to RBCD. Referral PA-20 is omitted — nothing in
/// 1.22.2 writes `KRB5_TL_SVR_REFERRAL_DATA`.
pub(super) fn return_enc_padata(
    raw: Option<&[u8]>,
    padata: Option<&[PaData]>,
    reply_key: &ProtocolKey,
    want_enc_pa: bool,
    extra: Option<PaData>,
) -> Result<Option<Vec<PaData>>, Error> {
    let mut out = Vec::new();
    if let Some(p) = extra {
        out.push(p);
    }
    if want_enc_pa && let Some(pkt) = raw {
        out.extend(enc_pa_rep_padata(reply_key, pkt)?);
    }
    if let Some(raw_po) = find_pa(padata, pa::PAC_OPTIONS)
        && let Ok(opts) = decode::<PaPacOptions>(raw_po)
        && opts.resource_based_constrained_delegation()
    {
        out.push(PaData {
            padata_type: pa::PAC_OPTIONS,
            padata_value: encode(&PaPacOptions::rbcd())?.into(),
        });
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

pub(super) fn krb_error_log_fields(bytes: &[u8]) -> (i32, String) {
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

pub(super) fn encode_krb_error(
    store: &dyn PrincipalRead,
    code: i32,
    text: Option<&str>,
    e_data: Option<Vec<u8>>,
    body: Option<&krb5_types::KdcReqBody>,
    hide_client: bool,
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
    let mut cname = body.and_then(|b| b.cname.clone());
    let mut crealm = cname.as_ref().map(|_| realm.clone());
    // do_as_req.c:831-832 / do_tgs_req.c:235-236: FAST hide-client on the
    // outer KRB-ERROR. Inner FX-ERROR keeps the real client.
    if hide_client && cname.is_some() {
        cname = Some(anonymous_principal_name());
        crealm = ks(ANONYMOUS_REALM).ok();
    }
    let pdu = KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        // do_as_req.c:804 / do_tgs_req.c:199 `errcode_to_protocol`: only
        // 0..=128 is a protocol code; anything else (a `KdcPolicy` handing
        // back a raw library code) goes out as KRB_ERR_GENERIC 60.
        error_code: crate::error::errcode_to_protocol(code),
        // MIT prepare_error_as echoes request->client. prepare_error_tgs
        // sets errpkt.client from the decrypted header ticket, else NULL;
        // opt_realm_of_principal omits crealm when client is NULL
        // (do_tgs_req.c:201-204, asn1_k_encode.c:919).
        crealm,
        cname,
        realm,
        sname,
        e_text: text.and_then(|t| krb5_types::try_ascii(t).ok()),
        e_data: e_data.map(Into::into),
    };
    encode(&pdu).unwrap_or_default()
}
