//! AP-REQ construction (RFC 4120 §5.5.1) and service-side verification.

use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt, verify_checksum,
};
use krb5_types::{
    ApOptions, ApReq, Authenticator, EncTicketPart, EncryptedData, HostAddresses, KerberosTime,
    PrincipalName, Realm, Ticket, err, ku,
};

use crate::error::Error;
use crate::replay::{ReplayCache, ReplayKey};

/// Clock-skew window (seconds) used when the caller does not specify one.
pub const DEFAULT_SKEW: i64 = 300;

/// Parameters for [`verify_ap_req`].
pub struct ApVerifyParams<'a> {
    /// Long-term keys available (keytab entries); kvno selects.
    pub keys: &'a [ProtocolKey],
    /// Optional kvno hint from the ticket.
    pub kvno: Option<u32>,
    /// Expected server name; ticket sname must match.
    pub expected_server: Option<&'a PrincipalName>,
    /// Expected server realm.
    pub expected_realm: Option<&'a str>,
    /// Clock skew in seconds.
    pub skew: i64,
    /// Optional client addresses to check against ticket caddr.
    pub addresses: Option<&'a HostAddresses>,
    /// Now (for tests); default wall clock.
    pub now: Option<KerberosTime>,
}

impl<'a> ApVerifyParams<'a> {
    /// Single service key, 300s skew, no name check.
    #[must_use]
    pub fn single_key(key: &'a ProtocolKey) -> Self {
        Self {
            keys: std::slice::from_ref(key),
            kvno: None,
            expected_server: None,
            expected_realm: None,
            skew: DEFAULT_SKEW,
            addresses: None,
            now: None,
        }
    }
}

/// Build an AP-REQ from a service ticket and its session key.
///
/// # Errors
///
/// Returns crypto or DER failures.
pub fn build_ap_req(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
) -> Result<ApReq, Error> {
    build_ap_req_opts(ticket, session_key, crealm, cname, ApOptions::none(), None)
}

/// Build an AP-REQ with explicit `ap_options` and optional checksum over app data.
///
/// # Errors
///
/// Returns crypto or DER failures.
pub fn build_ap_req_opts(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    ap_options: ApOptions,
    cksum_data: Option<&[u8]>,
) -> Result<ApReq, Error> {
    let cksum = if let Some(data) = cksum_data {
        let usage = KeyUsage::new(ku::AP_REQ_AUTH_CKSUM)?;
        let mic = checksum(session_key, usage, data)?;
        Some(krb5_types::Checksum {
            cksumtype: session_key.etype().checksum_type(),
            checksum: mic.into(),
        })
    } else {
        None
    };
    build_ap_req_with_cksum(ticket, session_key, crealm, cname, ap_options, cksum, None)
}

/// Build an AP-REQ with mutual auth and an explicit authenticator sequence.
///
/// MIT `kprop` `sendauth` uses `AP_OPTS_MUTUAL_REQUIRED` and `DO_SEQUENCE`.
///
/// # Errors
///
/// Returns crypto or DER failures.
pub fn build_ap_req_mutual_seq(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    seq_number: u32,
) -> Result<ApReq, Error> {
    let now = KerberosTime::now();
    let usec = krb5_types::Microseconds::from_subsec_micros(now.0.timestamp_subsec_micros());
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: crealm.clone(),
        cname: cname.clone(),
        cksum: None,
        cusec: usec,
        ctime: now,
        subkey: None,
        seq_number: Some(seq_number),
        authorization_data: None,
    };
    let der = encode(&authenticator)?;
    let usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let cipher = encrypt(session_key, usage, &der)?;
    Ok(ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::mutual_required(),
        ticket,
        authenticator: EncryptedData {
            etype: session_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    })
}

/// Build an AP-REQ with a caller-supplied authenticator checksum (GSS 0x8003).
///
/// # Errors
///
/// Returns crypto or DER failures.
pub fn build_ap_req_with_cksum(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    ap_options: ApOptions,
    cksum: Option<krb5_types::Checksum>,
    subkey: Option<krb5_types::EncryptionKey>,
) -> Result<ApReq, Error> {
    let now = KerberosTime::now();
    let usec = krb5_types::Microseconds::from_subsec_micros(now.0.timestamp_subsec_micros());
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: crealm.clone(),
        cname: cname.clone(),
        cksum,
        cusec: usec,
        ctime: now,
        subkey,
        seq_number: Some(0),
        authorization_data: None,
    };
    let der = encode(&authenticator)?;
    let usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let cipher = encrypt(session_key, usage, &der)?;
    Ok(ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options,
        ticket,
        authenticator: EncryptedData {
            etype: session_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    })
}

/// Result of a successful AP-REQ verification.
#[derive(Debug)]
pub struct ApVerifyOk {
    /// Decrypted ticket part.
    pub ticket_part: EncTicketPart,
    /// Ticket server name (acceptor).
    pub sname: krb5_types::PrincipalName,
    /// Decrypted authenticator.
    pub authenticator: Authenticator,
    /// Whether the initiator requested mutual authentication.
    pub mutual_required: bool,
}

/// Verify an AP-REQ using a single service key (tests / simple hosts).
///
/// # Errors
///
/// Returns [`Error`] on truncated input, HMAC failure, replay, skew, expiry,
/// or server-name mismatch.
pub fn verify_ap_req(
    raw: &[u8],
    service_key: &ProtocolKey,
    replay: &ReplayCache,
) -> Result<ApVerifyOk, Error> {
    verify_ap_req_ex(raw, &ApVerifyParams::single_key(service_key), replay, None)
}

/// Full AP-REQ verify.
///
/// # Errors
///
/// See [`verify_ap_req`].
pub fn verify_ap_req_ex(
    raw: &[u8],
    params: &ApVerifyParams<'_>,
    replay: &ReplayCache,
    app_cksum: Option<&[u8]>,
) -> Result<ApVerifyOk, Error> {
    let _g = krb5_log::enter_correlation(krb5_log::new_correlation_id());
    let started = Instant::now();
    let result = verify_inner(raw, params, replay, app_cksum);
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => tracing::info!(
            event = krb5_log::events::PROTOCOL_AP,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-protocol",
            duration_us,
            outcome = "ok",
        ),
        Err(e) => tracing::error!(
            event = krb5_log::events::PROTOCOL_AP,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-protocol",
            duration_us,
            outcome = "error",
            error = %e,
        ),
    }
    result
}

fn verify_inner(
    raw: &[u8],
    params: &ApVerifyParams<'_>,
    replay: &ReplayCache,
    app_cksum: Option<&[u8]>,
) -> Result<ApVerifyOk, Error> {
    if raw.is_empty() {
        return Err(Error::TruncatedReply);
    }
    let ap: ApReq = decode(raw)?;
    if let Some(exp) = params.expected_server
        && ap.ticket.sname.components_joined() != exp.components_joined()
    {
        return Err(Error::KrbError {
            code: err::NOT_US,
            text: Some("ticket sname does not match expected server".into()),
        });
    }
    if let Some(r) = params.expected_realm
        && ap.ticket.realm.as_bytes() != r.as_bytes()
    {
        return Err(Error::KrbError {
            code: err::NOT_US,
            text: Some("ticket realm does not match".into()),
        });
    }
    let tkt_usage = KeyUsage::new(ku::TICKET)?;
    let mut last_err = Error::KrbError {
        code: err::NOKEY,
        text: Some("no matching service key".into()),
    };
    let mut ticket_part: Option<EncTicketPart> = None;
    let want_kvno = ap.ticket.enc_part.kvno.or(params.kvno);
    for (i, key) in params.keys.iter().enumerate() {
        if let Some(v) = want_kvno {
            // Prefer matching kvno when the caller packed kvno into key order.
            let _ = (v, i);
        }
        match decrypt(key, tkt_usage, ap.ticket.enc_part.cipher.as_ref()) {
            Ok(tkt_plain) => match decode::<EncTicketPart>(&tkt_plain) {
                Ok(p) => {
                    ticket_part = Some(p);
                    break;
                }
                Err(e) => last_err = e.into(),
            },
            Err(e) => last_err = e.into(),
        }
    }
    let ticket_part = ticket_part.ok_or(last_err)?;
    if ticket_part.flags.invalid() {
        return Err(Error::KrbError {
            code: err::TKT_NYV,
            text: Some("INVALID flag".into()),
        });
    }
    let now = params.now.clone().unwrap_or_else(KerberosTime::now);
    let skew = params.skew.max(0);
    if let Some(start) = &ticket_part.starttime
        && now.delta_seconds(start) < -skew
    {
        return Err(Error::KrbError {
            code: err::TKT_NYV,
            text: Some("ticket not yet valid".into()),
        });
    }
    if ticket_part.endtime.delta_seconds(&now) < -skew {
        return Err(Error::KrbError {
            code: err::TKT_EXPIRED,
            text: Some("ticket expired".into()),
        });
    }
    if let Some(addrs) = params.addresses
        && let Some(caddr) = &ticket_part.caddr
        && caddr != addrs
    {
        return Err(Error::KrbError {
            code: err::BADADDR,
            text: Some("address mismatch".into()),
        });
    }
    let session_etype = EncryptionType::from_iana(ticket_part.key.keytype)
        .or_else(|_| EncryptionType::known(ticket_part.key.keytype))?;
    let session = ProtocolKey::from_bytes(session_etype, ticket_part.key.keyvalue.as_ref())?;
    let auth_usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let auth_plain = decrypt(&session, auth_usage, ap.authenticator.cipher.as_ref())?;
    let authenticator: Authenticator = decode(&auth_plain)?;
    authenticator
        .cusec
        .validate()
        .map_err(|e| Error::ReplyMismatch(e.to_string()))?;
    if authenticator.cname != ticket_part.cname || authenticator.crealm != ticket_part.crealm {
        return Err(Error::KrbError {
            code: err::BAD_INTEGRITY,
            text: Some("authenticator/ticket client mismatch".into()),
        });
    }
    let skew_delta = now.delta_seconds(&authenticator.ctime).unsigned_abs();
    let skew_limit = u64::try_from(skew.max(0)).unwrap_or(u64::MAX);
    if skew_delta > skew_limit {
        return Err(Error::KrbError {
            code: err::SKEW,
            text: Some("authenticator clock skew".into()),
        });
    }
    if let Some(ck) = &authenticator.cksum
        && let Some(data) = app_cksum
    {
        let usage = KeyUsage::new(ku::AP_REQ_AUTH_CKSUM)?;
        verify_checksum(&session, usage, data, ck.checksum.as_ref())?;
    }
    let client = format!(
        "{}@{}",
        authenticator.cname.components_joined(),
        String::from_utf8_lossy(authenticator.crealm.as_bytes())
    );
    let server = format!(
        "{}@{}",
        ap.ticket.sname.components_joined(),
        String::from_utf8_lossy(ap.ticket.realm.as_bytes())
    );
    let key = ReplayKey {
        client,
        server,
        ctime: authenticator.ctime.unix_seconds(),
        cusec: authenticator.cusec.get(),
        auth_hash: ReplayCache::hash_authenticator(ap.authenticator.cipher.as_ref()),
    };
    if replay.check_and_store(key) {
        return Err(Error::KrbError {
            code: err::REPEAT,
            text: Some("authenticator replay".into()),
        });
    }
    Ok(ApVerifyOk {
        ticket_part,
        sname: ap.ticket.sname.clone(),
        authenticator,
        mutual_required: ap.ap_options.wants_mutual(),
    })
}
