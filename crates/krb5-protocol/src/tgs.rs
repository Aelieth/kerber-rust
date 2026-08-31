//! TGS-REQ / TGS-REP using an existing TGT.

use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt};
use krb5_types::{
    ApOptions, ApReq, Authenticator, Checksum, EncKdcRepPart, EncTgsRepPart, EncryptedData,
    KdcOptions, KdcReq, KdcReqBody, KerberosTime, PaData, PrincipalName, TgsRep, TgsReq, Ticket,
    flag_bit, ku, pa,
};

use crate::as_ex::AsOutcome;
use crate::error::Error;

use crate::transport::{KdcAddr, exchange};

/// Successful TGS exchange.
#[derive(Clone, Debug)]
pub struct TgsOutcome {
    /// Service ticket.
    pub ticket: Ticket,
    /// Decrypted EncKDCRepPart.
    pub enc_part: EncKdcRepPart,
    /// Session key for the service.
    pub session_key: ProtocolKey,
}

/// Request a service ticket with a TGT from [`AsOutcome`].
///
/// # Errors
///
/// Returns transport, crypto, or `KRB-ERROR` failures.
#[allow(clippy::needless_pass_by_value)]
pub fn tgs_exchange(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
) -> Result<TgsOutcome, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(correlation_id.clone());
    let started = Instant::now();
    let result = tgs_inner(kdc, tgt, &sname, realm);
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => tracing::info!(
            event = krb5_log::events::PROTOCOL_TGS,
            correlation_id,
            component = "krb5-protocol",
            duration_us,
            outcome = "ok",
        ),
        Err(e) => tracing::error!(
            event = krb5_log::events::PROTOCOL_TGS,
            correlation_id,
            component = "krb5-protocol",
            duration_us,
            outcome = "error",
            error = %e,
        ),
    }
    result
}

/// TGS-REQ with KDC option `renew` for `kinit -R`.
///
/// # Errors
///
/// Transport, crypto, or `KRB-ERROR` failures.
pub fn tgs_renew(kdc: &KdcAddr, tgt: &AsOutcome) -> Result<TgsOutcome, Error> {
    let realm = String::from_utf8_lossy(tgt.crealm.as_bytes()).into_owned();
    let sname = PrincipalName::krbtgt(&realm);
    tgs_once(
        kdc,
        tgt,
        sname,
        &realm,
        KdcOptions::none()
            .with_bit(flag_bit::RENEW, true)
            .with_bit(flag_bit::CANONICALIZE, true),
    )
}

fn tgs_inner(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: &PrincipalName,
    realm: &str,
) -> Result<TgsOutcome, Error> {
    let mut cur_kdc = kdc.clone();
    let mut cur_tgt = tgt.clone();
    let mut hop_realm = realm.to_owned();
    for _ in 0..8 {
        let out = tgs_once(
            &cur_kdc,
            &cur_tgt,
            sname.clone(),
            &hop_realm,
            KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true),
        )?;
        match tgs_hop_decision(sname, &hop_realm, &out)? {
            TgsHop::Done => return Ok(out),
            TgsHop::Referral(foreign) => {
                hop_realm.clone_from(&foreign);
                cur_kdc = kdc_for_realm(&foreign, kdc);
                cur_tgt = AsOutcome {
                    ticket: out.ticket,
                    enc_part: out.enc_part,
                    client_key: cur_tgt.client_key.clone(),
                    session_key: out.session_key,
                    cname: cur_tgt.cname.clone(),
                    crealm: cur_tgt.crealm.clone(),
                };
            }
        }
    }
    Err(Error::Referral)
}

/// RFC 4120 name-type is a hint. Heimdal canonicalize may return NT-SRV-HST
/// for a host principal requested as NT-PRINCIPAL; compare name-strings.
fn tgs_sname_matches(
    requested: &PrincipalName,
    ticket: &PrincipalName,
    enc: &PrincipalName,
) -> bool {
    ticket.name_string == requested.name_string
        || enc.name_string == requested.name_string
        || (ticket.is_krbtgt()
            && !requested.is_krbtgt()
            && requested.components_joined() != ticket.components_joined())
}

fn tgs_sname_ok(
    requested: &PrincipalName,
    ticket: &PrincipalName,
    enc: &PrincipalName,
) -> Result<(), Error> {
    if tgs_sname_matches(requested, ticket, enc) {
        Ok(())
    } else {
        Err(Error::ReplyMismatch(format!(
            "TGS-REP sname mismatch requested={} ticket={}",
            requested.components_joined(),
            ticket.components_joined()
        )))
    }
}

/// One TGS-REQ hop: stay, chase a referral, or reject a bad srealm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TgsHop {
    /// `out` is the requested service ticket.
    Done,
    /// Chase `krbtgt/FOREIGN`; next `body.realm` is this string.
    Referral(String),
}

/// Authenticate `srealm` then decide whether this TGS-REP is a referral hop.
pub(crate) fn tgs_hop_decision(
    requested: &PrincipalName,
    hop_realm: &str,
    out: &TgsOutcome,
) -> Result<TgsHop, Error> {
    authenticate_srealm(out)?;
    if out.ticket.sname.is_krbtgt() && out.ticket.sname != *requested {
        let foreign = referral_hop_realm(&out.ticket.sname).ok_or(Error::Referral)?;
        if foreign.is_empty() || foreign == hop_realm {
            return Err(Error::Referral);
        }
        return Ok(TgsHop::Referral(foreign));
    }
    Ok(TgsHop::Done)
}

/// Next TGS-REQ `realm` after a referral TGT `krbtgt/FOREIGN`.
#[must_use]
pub fn referral_hop_realm(sname: &PrincipalName) -> Option<String> {
    if !sname.is_krbtgt() {
        return None;
    }
    sname
        .name_string
        .get(1)
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
}

fn authenticate_srealm(out: &TgsOutcome) -> Result<(), Error> {
    if out.enc_part.srealm.as_bytes() != out.ticket.realm.as_bytes() {
        return Err(Error::ReplyMismatch(
            "TGS-REP srealm does not match ticket realm".into(),
        ));
    }
    Ok(())
}

fn kdc_for_realm(realm: &str, fallback: &KdcAddr) -> KdcAddr {
    let env_key = format!("KRB5_KDC_{}", realm.replace('.', "_"));
    if let Ok(v) = std::env::var(env_key) {
        if let Some((h, p)) = v.rsplit_once(':')
            && let Ok(port) = p.parse()
        {
            return KdcAddr {
                host: h.to_owned(),
                port,
            };
        }
        return KdcAddr::new(v);
    }
    krb5_config::discover_kdc(realm).map_or_else(
        || fallback.clone(),
        |ep| KdcAddr {
            host: ep.host,
            port: ep.port,
        },
    )
}

fn tgs_once(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    kdc_options: KdcOptions,
) -> Result<TgsOutcome, Error> {
    let nonce = random_nonce31()?;
    let till = KerberosTime(tgt.enc_part.endtime.0);
    let etypes = crate::as_ex::conf_etypes(true);

    let requested = sname.clone();
    let body = KdcReqBody {
        kdc_options,
        cname: None,
        realm: krb5_types::try_ascii(realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?,
        sname: Some(sname),
        from: None,
        till,
        rtime: None,
        nonce,
        etype: etypes,
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let body_der = encode(&body)?;
    let cksum_usage = KeyUsage::new(ku::TGS_REQ_AUTH_CKSUM)?;
    let mic = checksum(&tgt.session_key, cksum_usage, &body_der)?;
    let now = KerberosTime::now();
    let usec = now.0.timestamp_subsec_micros() % 1_000_000;
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: tgt.crealm.clone(),
        cname: tgt.cname.clone(),
        cksum: Some(Checksum {
            cksumtype: tgt.session_key.etype().checksum_type(),
            checksum: mic.into(),
        }),
        cusec: krb5_types::Microseconds::from_subsec_micros(usec),
        ctime: now,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let auth_der = encode(&authenticator)?;
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR)?;
    let auth_cipher = encrypt(&tgt.session_key, auth_usage, &auth_der)?;
    let ap_req = ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
        ticket: tgt.ticket.clone(),
        authenticator: EncryptedData {
            etype: tgt.session_key.etype().to_iana(),
            kvno: None,
            cipher: auth_cipher.into(),
        },
    };
    // FAST armor AP-REQ uses key-usage 11; PA-TGS-REQ uses usage 7. MIT
    // FIND_FAST fails if the armor AP-REQ is the TGS authenticator.
    let padata = vec![PaData {
        padata_type: pa::TGS_REQ,
        padata_value: encode(&ap_req)?.into(),
    }];
    let tgs = TgsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_TGS_REQ,
        padata: Some(padata),
        req_body: body,
    });
    let wire = encode(&tgs)?;
    let reply = exchange(kdc, &wire)?;
    if reply.is_empty() {
        return Err(Error::TruncatedReply);
    }
    if reply[0] == 0x7e {
        let e: krb5_types::KrbError = decode(&reply)?;
        let text = e
            .e_text
            .as_ref()
            .and_then(|s| std::str::from_utf8(s.as_bytes()).ok())
            .map(str::to_owned);
        return Err(Error::KrbError {
            code: e.error_code,
            text,
        });
    }
    if reply[0] != 0x6d {
        return Err(Error::UnexpectedPdu);
    }
    let TgsRep(inner) = decode::<TgsRep>(&reply)?;
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART)?;
    let plain = decrypt(&tgt.session_key, usage, inner.enc_part.cipher.as_ref())?;
    let enc_part = match decode::<EncTgsRepPart>(&plain) {
        Ok(EncTgsRepPart(p)) => p,
        _ => decode::<EncKdcRepPart>(&plain)?,
    };
    if enc_part.nonce != nonce {
        return Err(Error::NonceMismatch);
    }
    tgs_sname_ok(&requested, &inner.ticket.sname, &enc_part.sname)?;
    let session_etype = EncryptionType::from_iana(enc_part.key.keytype)
        .or_else(|_| EncryptionType::known(enc_part.key.keytype))?;
    let session_key = ProtocolKey::from_bytes(session_etype, enc_part.key.keyvalue.as_ref())?;
    Ok(TgsOutcome {
        ticket: inner.ticket,
        enc_part,
        session_key,
    })
}

fn random_nonce31() -> Result<u32, Error> {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|e| Error::transport_msg(e.to_string()))?;
    let n = u32::from_be_bytes(b) & 0x7fff_ffff;
    Ok(if n == 0 { 1 } else { n })
}

#[cfg(test)]
mod tests {
    use krb5_crypto::{EncryptionType, ProtocolKey};
    use krb5_types::{
        EncKdcRepPart, EncryptedData, EncryptionKey, OctetString, PrincipalName, Ticket,
        TicketFlags, ascii,
    };

    use super::*;

    fn session() -> ProtocolKey {
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[7u8; 32]).unwrap()
    }

    fn outcome(ticket_realm: &str, sname: PrincipalName, srealm: &str) -> TgsOutcome {
        let t = KerberosTime::now();
        TgsOutcome {
            ticket: Ticket {
                tkt_vno: Ticket::VNO,
                realm: ascii(ticket_realm),
                sname: sname.clone(),
                enc_part: EncryptedData {
                    etype: 18,
                    kvno: Some(1),
                    cipher: OctetString::from(vec![0u8; 16]),
                },
            },
            enc_part: EncKdcRepPart {
                key: EncryptionKey {
                    keytype: 18,
                    keyvalue: OctetString::from(vec![7u8; 32]),
                },
                last_req: vec![],
                nonce: 1,
                key_expiration: None,
                flags: TicketFlags::none(),
                authtime: t.clone(),
                starttime: None,
                endtime: t,
                renew_till: None,
                srealm: ascii(srealm),
                sname,
                caddr: None,
                encrypted_pa_data: None,
            },
            session_key: session(),
        }
    }

    #[test]
    fn hop_two_uses_foreign_realm() {
        let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.other.test"]);
        let krbtgt = PrincipalName::krbtgt("OTHER.TEST");
        let out = outcome("OTHER.TEST", krbtgt, "OTHER.TEST");
        match tgs_hop_decision(&host, "KERBER.TEST", &out).unwrap() {
            TgsHop::Referral(r) => assert_eq!(r, "OTHER.TEST"),
            TgsHop::Done => panic!("expected referral hop"),
        }
    }

    #[test]
    fn hop_rejects_mismatched_srealm() {
        let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc"]);
        let krbtgt = PrincipalName::krbtgt("OTHER.TEST");
        let out = outcome("OTHER.TEST", krbtgt, "EVIL.TEST");
        let err = tgs_hop_decision(&host, "KERBER.TEST", &out).unwrap_err();
        assert!(matches!(err, Error::ReplyMismatch(_)));
    }

    #[test]
    fn hop_rejects_same_realm_referral() {
        let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc"]);
        let krbtgt = PrincipalName::krbtgt("KERBER.TEST");
        let out = outcome("KERBER.TEST", krbtgt, "KERBER.TEST");
        let err = tgs_hop_decision(&host, "KERBER.TEST", &out).unwrap_err();
        assert!(matches!(err, Error::Referral));
    }

    #[test]
    fn hop_done_for_service_ticket() {
        let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc"]);
        let out = outcome("KERBER.TEST", host.clone(), "KERBER.TEST");
        assert_eq!(
            tgs_hop_decision(&host, "KERBER.TEST", &out).unwrap(),
            TgsHop::Done
        );
    }

    #[test]
    fn tgs_sname_ignores_name_type_rejects_wrong_components() {
        let asked = PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            ["host", "testhost.kerber.test"],
        );
        let heimdal =
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]);
        assert!(tgs_sname_matches(&asked, &heimdal, &heimdal));
        let other = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "other.kerber.test"]);
        assert!(!tgs_sname_matches(&asked, &other, &other));
        let krbtgt = PrincipalName::krbtgt("OTHER.TEST");
        assert!(tgs_sname_matches(&asked, &krbtgt, &krbtgt));
        tgs_sname_ok(&asked, &krbtgt, &krbtgt).unwrap();
    }

    #[test]
    fn tgs_sname_flat_krbtgt_is_reply_mismatch() {
        let two = PrincipalName::krbtgt("KERBER.TEST");
        let flat = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["krbtgt/KERBER.TEST"]);
        assert_eq!(two.components_joined(), flat.components_joined());
        assert!(matches!(
            tgs_sname_ok(&two, &flat, &flat),
            Err(Error::ReplyMismatch(_))
        ));
        assert!(matches!(
            tgs_sname_ok(&flat, &two, &two),
            Err(Error::ReplyMismatch(_))
        ));
    }
}
