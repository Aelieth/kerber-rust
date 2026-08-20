//! AP-REQ construction (RFC 4120 §5.5.1) and keytab-side verification.

use std::collections::HashSet;
use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{decrypt, encrypt, EncryptionType, KeyUsage, ProtocolKey};
use krb5_types::{
    ku, ApOptions, ApReq, Authenticator, EncTicketPart, EncryptedData, KerberosTime, PrincipalName,
    Realm, Ticket,
};

use crate::error::Error;

/// Replay detector: (client, ctime unix seconds, cusec) must be unique.
#[derive(Clone, Debug, Default)]
pub struct ReplayCache {
    seen: HashSet<(String, u32, u32)>,
}

impl ReplayCache {
    /// Empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Build an AP-REQ from a service ticket and its session key.
///
/// Authenticator is encrypted with key usage 11.
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
    let now = KerberosTime::now();
    let usec = now.0.timestamp_subsec_micros() % 1_000_000;
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: crealm.clone(),
        cname: cname.clone(),
        cksum: None,
        cusec: usec,
        ctime: now,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let der = encode(&authenticator)?;
    let usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let cipher = encrypt(session_key, usage, &der)?;
    Ok(ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
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
    /// Decrypted authenticator.
    pub authenticator: Authenticator,
}

/// Verify an AP-REQ using the service long-term key (typically from a keytab).
///
/// Rejects truncated encodings, HMAC failure (wrong key), and a repeated
/// authenticator `(cname, ctime, cusec)`.
///
/// # Errors
///
/// Returns [`Error`] on any of those failures. Does not panic.
pub fn verify_ap_req(
    raw: &[u8],
    service_key: &ProtocolKey,
    replay: &mut ReplayCache,
) -> Result<ApVerifyOk, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let started = Instant::now();
    let result = verify_inner(raw, service_key, replay);
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => tracing::info!(
            event = krb5_log::events::PROTOCOL_AP,
            correlation_id,
            component = "krb5-protocol",
            duration_us,
            outcome = "ok",
        ),
        Err(e) => tracing::error!(
            event = krb5_log::events::PROTOCOL_AP,
            correlation_id,
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
    service_key: &ProtocolKey,
    replay: &mut ReplayCache,
) -> Result<ApVerifyOk, Error> {
    if raw.is_empty() {
        return Err(Error::TruncatedReply);
    }
    let ap: ApReq = decode(raw)?;
    let tkt_usage = KeyUsage::new(ku::TICKET)?;
    let tkt_plain = decrypt(service_key, tkt_usage, ap.ticket.enc_part.cipher.as_ref())?;
    let ticket_part: EncTicketPart = decode(&tkt_plain)?;
    let session_etype = EncryptionType::from_iana(ticket_part.key.keytype)?;
    let session = ProtocolKey::from_bytes(session_etype, ticket_part.key.keyvalue.as_ref())?;
    let auth_usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let auth_plain = decrypt(&session, auth_usage, ap.authenticator.cipher.as_ref())?;
    let authenticator: Authenticator = decode(&auth_plain)?;
    if authenticator.cname != ticket_part.cname || authenticator.crealm != ticket_part.crealm {
        return Err(Error::KrbError {
            code: krb5_types::err::BAD_INTEGRITY,
            text: Some("authenticator/ticket client mismatch".into()),
        });
    }
    let client = format!(
        "{}@{}",
        authenticator.cname.components_joined(),
        String::from_utf8_lossy(authenticator.crealm.as_bytes())
    );
    let stamp = (
        client,
        authenticator.ctime.unix_seconds(),
        authenticator.cusec,
    );
    if !replay.seen.insert(stamp) {
        return Err(Error::KrbError {
            code: krb5_types::err::REPEAT,
            text: Some("authenticator replay".into()),
        });
    }
    Ok(ApVerifyOk {
        ticket_part,
        authenticator,
    })
}
