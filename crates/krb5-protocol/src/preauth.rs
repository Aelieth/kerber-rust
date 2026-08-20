//! Client builders for FAST, SPAKE, and PKINIT padata.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    checksum, decrypt, encrypt, key_from_shared, krb_fx_cf2, octetstring2key, p256_generate,
    p256_shared, spake_finish, spake_public, EncryptionType, KeyUsage, ProtocolKey,
};
use krb5_types::{
    ascii, ku, pa, ApOptions, ApReq, AsReq, Authenticator, Checksum, EncryptedData, EncryptionKey,
    KerberosTime, Microseconds, PaData, PrincipalName, Realm, Ticket,
};

use crate::error::Error;

/// Mix a FAST subkey with the armor ticket session key (RFC 6113).
///
/// # Errors
///
/// CF2 failures.
pub fn armor_key(
    session: &ProtocolKey,
    subkey: Option<&ProtocolKey>,
) -> Result<ProtocolKey, Error> {
    match subkey {
        Some(sub) => krb_fx_cf2(sub, session, b"subkeyarmor", b"ticketarmor").map_err(Into::into),
        None => Ok(session.clone()),
    }
}

/// AP-REQ used as FAST AP-REQUEST armor, with an optional authenticator subkey.
///
/// # Errors
///
/// Crypto or DER failures.
pub fn build_fast_armor(
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    subkey: Option<&ProtocolKey>,
) -> Result<ApReq, Error> {
    let now = KerberosTime::now();
    let usec = Microseconds::from_subsec_micros(now.0.timestamp_subsec_micros());
    let sub = subkey.map(|k| EncryptionKey {
        keytype: k.etype().to_iana(),
        keyvalue: k.as_bytes().to_vec().into(),
    });
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: crealm.clone(),
        cname: cname.clone(),
        cksum: None,
        cusec: usec,
        ctime: now,
        subkey: sub,
        seq_number: None,
        authorization_data: None,
    };
    let der = encode(&authenticator)?;
    let usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let cipher = encrypt(session, usage, &der)?;
    Ok(ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
        ticket,
        authenticator: EncryptedData {
            etype: session.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    })
}

/// Replace outer padata with PA-FX-FAST wrapping `inner_padata`.
///
/// # Errors
///
/// Crypto or DER failures.
pub fn attach_fast(
    req: &mut AsReq,
    armor: &ApReq,
    armor_key: &ProtocolKey,
    inner_padata: Vec<PaData>,
) -> Result<(), Error> {
    req.0.padata = Some(vec![fx_fast_padata(
        Some(armor),
        armor_key,
        &req.0.req_body,
        inner_padata,
    )?]);
    Ok(())
}

/// PA-FX-FAST wrapping `inner_padata` and a copy of `req_body`.
///
/// TGS FAST omits `armor` when PA-TGS-REQ is present (RFC 6113).
///
/// # Errors
///
/// Crypto or DER failures.
pub fn fx_fast_padata(
    armor: Option<&ApReq>,
    armor_key: &ProtocolKey,
    req_body: &krb5_types::KdcReqBody,
    inner_padata: Vec<PaData>,
) -> Result<PaData, Error> {
    let body_der = encode(req_body)?;
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    let mic = checksum(armor_key, ck_usage, &body_der)?;
    let inner = krb5_types::fast::KrbFastReq {
        fast_options: krb5_types::fast::fast_options_none(),
        padata: inner_padata,
        req_body: req_body.clone(),
    };
    let inner_der = encode(&inner)?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let cipher = encrypt(armor_key, enc_usage, &inner_der)?;
    let armor_seq = match armor {
        Some(ap) => Some(krb5_types::fast::KrbFastArmor {
            armor_type: krb5_types::fast::ARMOR_AP_REQUEST,
            armor_value: encode(ap)?.into(),
        }),
        None => None,
    };
    let armored = krb5_types::fast::KrbFastArmoredReq {
        armor: armor_seq,
        req_checksum: Checksum {
            cksumtype: armor_key.etype().checksum_type(),
            checksum: mic.into(),
        },
        enc_fast_req: EncryptedData {
            etype: armor_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    Ok(PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))?.into(),
    })
}

/// Decrypt PA-FX-FAST on an AS-REP into [`krb5_types::fast::KrbFastResponse`].
///
/// # Errors
///
/// Missing padata, crypto, or DER failures.
pub fn unwrap_fast_rep(
    armor_key: &ProtocolKey,
    padata: &Option<Vec<PaData>>,
) -> Result<krb5_types::fast::KrbFastResponse, Error> {
    let raw = padata
        .as_ref()
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::FX_FAST))
        .ok_or_else(|| Error::ReplyMismatch("missing PA-FX-FAST".into()))?;
    let armored = if let Ok(krb5_types::fast::PaFxFastRep::ArmoredData(w)) =
        decode::<krb5_types::fast::PaFxFastRep>(raw.padata_value.as_ref())
    {
        w
    } else {
        decode::<krb5_types::fast::KrbFastArmoredRep>(raw.padata_value.as_ref())?
    };
    let usage = KeyUsage::new(ku::FAST_REP)?;
    let plain = decrypt(armor_key, usage, armored.enc_fast_rep.cipher.as_ref())?;
    decode(&plain).map_err(Error::from)
}

/// Mix the FAST strengthen-key with the base reply key.
///
/// # Errors
///
/// CF2 or key-length failures.
pub fn apply_strengthen(
    strengthen: &EncryptionKey,
    base: &ProtocolKey,
) -> Result<ProtocolKey, Error> {
    let et = EncryptionType::from_iana(strengthen.keytype)
        .or_else(|_| EncryptionType::known(strengthen.keytype))?;
    let sk = ProtocolKey::from_bytes(et, strengthen.keyvalue.as_ref())?;
    krb_fx_cf2(&sk, base, b"strengthenkey", b"replykey").map_err(Into::into)
}

/// PA-SPAKE support advertisement (P-256).
#[must_use]
pub fn pa_spake_support() -> PaData {
    let msg = krb5_types::spake::PaSpake {
        support: Some(krb5_types::spake::SpakeSupport {
            groups: vec![krb5_types::spake::GROUP_P256],
        }),
        challenge: None,
        response: None,
        enc_data: None,
    };
    PaData {
        padata_type: pa::SPAKE,
        padata_value: encode(&msg).unwrap_or_default().into(),
    }
}

/// Build a PA-SPAKE response from a KDC challenge public share.
///
/// Returns the padata and the SPAKE-derived reply key.
///
/// # Errors
///
/// Curve or encrypt failures.
pub fn pa_spake_response(
    w: &[u8; 32],
    challenge_pubkey: &[u8],
    etype: EncryptionType,
) -> Result<(PaData, ProtocolKey), Error> {
    let kp = p256_generate()?;
    let pub_x = spake_public(w, &kp.secret, false)?;
    let shared = spake_finish(w, &kp.secret, challenge_pubkey, false)?;
    let key = key_from_shared(etype, &shared)?;
    let usage = KeyUsage::new(ku::PA_ENC_TIMESTAMP)?;
    let factor_ct = encrypt(&key, usage, &[1u8])?;
    let msg = krb5_types::spake::PaSpake {
        support: None,
        challenge: None,
        response: Some(krb5_types::spake::SpakeResponse {
            pubkey: pub_x.into(),
            factor: EncryptedData {
                etype: etype.to_iana(),
                kvno: None,
                cipher: factor_ct.into(),
            },
        }),
        enc_data: None,
    };
    Ok((
        PaData {
            padata_type: pa::SPAKE,
            padata_value: encode(&msg)?.into(),
        },
        key,
    ))
}

/// PA-PK-AS-REQ: AuthPack inside CMS SignedData (`signedAuthPack`).
///
/// # Errors
///
/// DER failures.
pub fn pa_pk_as_req(
    client_public: &[u8],
    ca: &krb5_types::pkinit::PkinitCa,
) -> Result<PaData, Error> {
    let pack = krb5_types::pkinit::AuthPack {
        pk_authenticator: krb5_types::pkinit::PkAuthenticator {
            cusec: Microseconds::ZERO,
            ctime: KerberosTime::now(),
            nonce: 1,
            pa_checksum: None,
        },
        client_public_value: Some(client_public.to_vec().into()),
        supported_cms_types: None,
    };
    let inner = encode(&pack)?;
    let signed = krb5_types::pkinit::cms_wrap(&inner, ca)
        .map_err(|e| Error::ReplyMismatch(format!("PKINIT CMS wrap: {e}")))?;
    let req = krb5_types::pkinit::PaPkAsReq {
        signed_auth_pack: signed.into(),
        trusted_certifiers: None,
        kdc_pk_id: None,
    };
    Ok(PaData {
        padata_type: pa::PK_AS_REQ,
        padata_value: encode(&req)?.into(),
    })
}

/// Derive the PKINIT reply key from PA-PK-AS-REP `dh_signed_data` (CMS or raw P-256).
///
/// # Errors
///
/// Missing padata, ECDH, or key-length failures.
pub fn pkinit_reply_key(
    client_secret: &[u8; 32],
    padata: &Option<Vec<PaData>>,
    etype: EncryptionType,
    kdc_trust_anchor: &[u8],
) -> Result<ProtocolKey, Error> {
    let raw = padata
        .as_ref()
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::PK_AS_REP))
        .ok_or_else(|| Error::ReplyMismatch("missing PA-PK-AS-REP".into()))?;
    let rep: krb5_types::pkinit::PaPkAsRep = decode(raw.padata_value.as_ref())?;
    let pub_kdc = rep
        .dh_info
        .as_ref()
        .ok_or_else(|| Error::ReplyMismatch("PKINIT missing dhInfo".into()))?;
    let kdc_pub = krb5_types::pkinit::cms_verify(pub_kdc.dh_signed_data.as_ref(), kdc_trust_anchor)
        .map_err(|e| Error::ReplyMismatch(format!("PKINIT KDC CMS: {e}")))?;
    let shared = p256_shared(client_secret, &kdc_pub)?;
    octetstring2key(etype, &shared).map_err(Into::into)
}

/// PA-FOR-USER (S4U2Self) checksummed with the TGT session key (usage 17).
///
/// # Errors
///
/// Checksum failures.
pub fn pa_for_user(
    session: &ProtocolKey,
    user: PrincipalName,
    realm: &str,
) -> Result<PaData, Error> {
    let pkg = "Kerberos";
    let data = krb5_types::s4u::pa_for_user_cksum_data(&user, realm, pkg);
    let usage = KeyUsage::new(ku::PA_FOR_USER)?;
    let mic = checksum(session, usage, &data)?;
    let for_user = krb5_types::s4u::PaForUser {
        user_name: user,
        user_realm: ascii(realm),
        cksum: Checksum {
            cksumtype: session.etype().checksum_type(),
            checksum: mic.into(),
        },
        auth_package: ascii(pkg),
    };
    Ok(PaData {
        padata_type: pa::FOR_USER,
        padata_value: encode(&for_user)?.into(),
    })
}
