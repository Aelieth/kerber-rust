//! Issued tickets and the KRB-ERROR.

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
use crate::ad::{add_auth_indicators, authdata_failed, crypto_at, key_refused_at, wrap_win2k_pac};
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::preauth::{find_pa, prepare_as_edata, proto_d};
use crate::status;
use crate::store::Principal;

#[must_use]
pub(crate) fn kdc_error_bytes(store: &dyn PrincipalRead, code: i32) -> Vec<u8> {
    encode_krb_error(store, code, None, None, None, false)
}

// MIT: `finish_process_as_req` (do_as_req.c:372-373)
pub(super) fn as_reply(
    store: &dyn PrincipalRead,
    req: &AsReq,
    raw: &[u8],
) -> Result<(Vec<u8>, Option<String>), Error> {
    let body = Some(&req.0.req_body);
    let hide = peek_as_hides_client(store, req, raw);
    let issued = issue_as_from(store, req, Some(raw));
    if crate::plugins::otp_park_pending() {
        return Ok((Vec::new(), None));
    }
    match issued {
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
            // MIT: `finish_process_as_req` (do_as_req.c:371-372)
            // MIT: `filter_preauth_error` (kdc_preauth.c:1125-1125)
            // MIT: `finish_dispatch_cache` (dispatch.c:78-78)
            // DISCARD returns empty bytes, not a KRB-ERROR.
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
        // MIT: `finish_process_as_req` (do_as_req.c:346-347)
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

// MIT: `prepare_error_tgs` (do_tgs_req.c:201-204)
pub(super) fn tgs_reply(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    raw: &[u8],
    sender: Option<&HostAddress>,
) -> Result<(Vec<u8>, Option<String>), Error> {
    // MIT: `prepare_error_tgs` (do_tgs_req.c:201-204)
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

// MIT: `krb5_enc_tkt_part` (include/krb5/krb5.hin:1930-1930)
// MIT: `krb5_encrypt_tkt_part` (lib/krb5/krb/encrypt_tk.c:42-42)
pub(super) struct MintTicket<'a> {
    pub service_key: &'a ProtocolKey,
    pub kvno: u32,
    pub service_etype: EncryptionType,
    pub session: &'a ProtocolKey,
    pub srealm: &'a str,
    pub sname: &'a PrincipalName,
    pub crealm: &'a str,
    pub cname: &'a PrincipalName,
    pub authtime: &'a KerberosTime,
    pub endtime: &'a KerberosTime,
    pub flags: TicketFlags,
    pub kdc_key: &'a ProtocolKey,
    pub transited: TransitedEncoding,
    pub renew_till: Option<KerberosTime>,
    pub store: &'a dyn PrincipalRead,
    pub pac: Option<TicketPac<'a>>,
    pub starttime: &'a KerberosTime,
    pub caddr: Option<HostAddresses>,
    pub extra_ad: Option<AuthorizationData>,
    pub indicators: &'a [String],
    pub krbtgt: &'a Principal,
    pub krbtgt_key: &'a ProtocolKey,
    pub no_auth_data: bool,
    pub kind: &'static str,
}

pub(super) enum TicketPac<'a> {
    Mit(crate::ad::HandlePac<'a>),
    Ad {
        logon_override: Option<&'a [u8]>,
        subject_pac: Option<&'a [u8]>,
        s4u_client_info: Option<&'a str>,
        identity: Option<(&'a PrincipalName, &'a str)>,
    },
}

// MIT: `tgs_issue_ticket` (do_tgs_req.c:1056-1060)
pub(super) fn mint_ticket(p: MintTicket<'_>) -> Result<Ticket, Error> {
    let MintTicket {
        service_key,
        kvno,
        service_etype,
        session,
        srealm,
        sname,
        crealm,
        cname,
        authtime,
        endtime,
        flags,
        kdc_key,
        transited,
        renew_till,
        store,
        pac,
        starttime,
        caddr,
        extra_ad,
        indicators,
        krbtgt,
        krbtgt_key,
        no_auth_data,
        kind,
    } = p;
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
        )
        .map_err(|e| authdata_failed(kind, e))?;
    }
    if let Some(pac) = pac {
        // MIT: `krb5_kdc_sign_ticket` (pac_sign.c:389-398)
        let placeholder = wrap_win2k_pac(&[0])?;
        let mut checksum_ad = extra.clone();
        checksum_ad.splice(0..0, placeholder);
        part.authorization_data = Some(checksum_ad);
        let checksum_der = encode(&part)?;
        let ticket = crate::ad::PacTicket {
            server: service_key,
            kdc: kdc_key,
            enc_tkt_der: &checksum_der,
            is_service_tkt: crate::ad::should_have_ticket_signature(sname),
        };
        let pac = match pac {
            TicketPac::Mit(req) => {
                crate::ad::mit_ticket_pac(&req, cname, authtime.unix_seconds(), &ticket)
                    .map_err(|e| authdata_failed(kind, e))?
            }
            TicketPac::Ad {
                logon_override,
                subject_pac,
                s4u_client_info,
                identity,
            } => {
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
                } else if let Some((name, realm)) = identity {
                    store.pac_identity(name, realm)
                } else {
                    store.pac_identity(cname, crealm)
                };
                crate::ad::sign_reply_pac_s4u(
                    cname,
                    authtime.unix_seconds(),
                    &ticket,
                    &ident,
                    logon_override,
                    subject_pac,
                    s4u_client_info,
                )
                .map_err(|e| authdata_failed(kind, e))?
            }
        };
        let mut signed = wrap_win2k_pac(&pac)?;
        signed.extend(extra);
        part.authorization_data = Some(signed);
    } else if !extra.is_empty() {
        part.authorization_data = Some(extra);
    }
    let der = encode(&part)?;
    let usage = KeyUsage::new(ku::TICKET)?;
    let cipher = crypto_at(encrypt(service_key, usage, &der), status::UNKNOWN_REASON)?;
    Ok(Ticket {
        tkt_vno: Ticket::VNO,
        realm: ks(srealm)?,
        sname: sname.clone(),
        enc_part: EncryptedData {
            etype: service_etype.to_iana(),
            // A kvno of 0 is omitted; a user-to-user ticket uses that.
            kvno: (kvno != 0).then_some(kvno),
            cipher: cipher.into(),
        },
    })
}

pub(super) fn encode_enc_kdc_rep_part(part: EncKdcRepPart) -> Result<Vec<u8>, Error> {
    Ok(encode(&EncTgsRepPart(part))?)
}

#[expect(clippy::too_many_arguments, reason = "EncKdcRepPart, not params")]
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

// MIT: `return_enc_padata` (kdc_preauth.c:1636-1663)
/// Encrypted padata is the FAST checksum, plus RBCD when asked.
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
        out.extend(
            enc_pa_rep_padata(reply_key, pkt)
                .map_err(|e| key_refused_at(e, status::KDC_RETURN_ENC_PADATA))?,
        );
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

// MIT: `prepare_error_as` (do_as_req.c:831-832)
pub(super) fn encode_krb_error(
    store: &dyn PrincipalRead,
    code: i32,
    text: Option<&str>,
    e_data: Option<Vec<u8>>,
    body: Option<&krb5_types::KdcReqBody>,
    hide_client: bool,
) -> Vec<u8> {
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
    // MIT: `prepare_error_as` (do_as_req.c:831-832)
    // MIT: `prepare_error_tgs` (do_tgs_req.c:235-236)
    // A hidden client is named the anonymous principal.
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
        // MIT: `prepare_error_as` (do_as_req.c:804-804)
        // MIT: `prepare_error_tgs` (do_tgs_req.c:199-199)
        // A code outside 0 to 128 goes out as 60.
        error_code: crate::error::errcode_to_protocol(code),
        // MIT: `error_7` (asn1_k_encode.c:919-919)
        crealm,
        cname,
        realm,
        sname,
        e_text: text.and_then(|t| krb5_types::try_ascii(t).ok()),
        e_data: e_data.map(Into::into),
    };
    encode(&pdu).unwrap_or_default()
}
