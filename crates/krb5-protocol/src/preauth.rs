//! Client builders for FAST, SPAKE, and PKINIT padata.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, SPAKE_GROUP_P256, checksum, decrypt, encrypt,
    krb_fx_cf2, octetstring2key, p256_generate, p256_shared, pkinit_kdf_agile, spake_derive_key,
    spake_public_wbytes, spake_result_wbytes, spake_thash_update, spake_wbytes,
    verify_checksum_type,
};
use krb5_types::{
    ApOptions, ApReq, AsReq, Authenticator, Checksum, EncKdcRepPart, EncryptedData, EncryptionKey,
    KerberosFlags, KerberosTime, Microseconds, PaData, PrincipalName, Realm, Ticket, ku, pa,
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

/// MIT `fast.c:543-551`: verify `KrbFastFinished.ticket_checksum` over the ticket DER.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] when the checksum is absent or does not match.
pub fn verify_fast_finished(
    armor_key: &ProtocolKey,
    ticket: &Ticket,
    finished: &krb5_types::fast::KrbFastFinished,
) -> Result<(), Error> {
    let tder = encode(ticket)?;
    let usage = KeyUsage::new(ku::FAST_FINISHED)?;
    verify_checksum_type(
        armor_key,
        usage,
        &tder,
        finished.ticket_checksum.cksumtype,
        finished.ticket_checksum.checksum.as_ref(),
    )
    .map_err(|_| Error::ReplyMismatch("Ticket modified in KDC reply".into()))
}

/// MIT `fast.c:648-664`: PA-REQ-ENC-PA-REP over the AS-REQ when `enc-pa-rep` is set.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] (`KRB5_KDCREP_MODIFIED`) on a missing or bad checksum.
pub fn verify_req_enc_pa_rep(
    enc: &EncKdcRepPart,
    key: &ProtocolKey,
    as_req: &[u8],
) -> Result<(), Error> {
    if !enc.flags.enc_pa_rep() {
        return Ok(());
    }
    let pa = enc
        .encrypted_pa_data
        .as_ref()
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::REQ_ENC_PA_REP))
        .ok_or_else(|| Error::ReplyMismatch("Ticket modified in KDC reply".into()))?;
    let ck: Checksum = decode(pa.padata_value.as_ref())?;
    let usage = KeyUsage::new(ku::AS_REQ)?;
    verify_checksum_type(key, usage, as_req, ck.cksumtype, ck.checksum.as_ref())
        .map_err(|_| Error::ReplyMismatch("Ticket modified in KDC reply".into()))
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
    let armored = match decode::<krb5_types::fast::PaFxFastRep>(raw.padata_value.as_ref()) {
        Ok(krb5_types::fast::PaFxFastRep::ArmoredData(w)) => w,
        _ => decode::<krb5_types::fast::KrbFastArmoredRep>(raw.padata_value.as_ref())?,
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
    let msg = krb5_types::spake::PaSpake::Support(krb5_types::spake::SpakeSupport {
        groups: vec![krb5_types::spake::GROUP_P256],
    });
    PaData {
        padata_type: pa::SPAKE,
        padata_value: encode(&msg).unwrap_or_default().into(),
    }
}

/// Build a PA-SPAKE response matching MIT 1.22.2 (`K'[0]` reply key).
///
/// `support_der` is the client's PA-SPAKE support encoding (empty if none).
/// `challenge_der` is the KDC PA-SPAKE challenge encoding. `body_der` is
/// the KDC-REQ-BODY of the response AS-REQ.
///
/// # Errors
///
/// Curve, PRF, or encrypt failures.
pub fn pa_spake_response(
    ikey: &ProtocolKey,
    support_der: &[u8],
    challenge_der: &[u8],
    challenge_pubkey: &[u8],
    body_der: &[u8],
) -> Result<(PaData, ProtocolKey), Error> {
    let wbytes = spake_wbytes(ikey, SPAKE_GROUP_P256)?;
    let kp = p256_generate()?;
    let pub_x = spake_public_wbytes(&wbytes, &kp.secret, false)?;
    let result = spake_result_wbytes(&wbytes, &kp.secret, challenge_pubkey, false)?;
    let z = [0u8; 32];
    let thash = spake_thash_update(&z, support_der, challenge_der);
    let thash = spake_thash_update(&thash, &pub_x, &[]);
    let k0 = spake_derive_key(
        ikey,
        SPAKE_GROUP_P256,
        &wbytes,
        &result,
        &thash,
        body_der,
        0,
    )?;
    let k1 = spake_derive_key(
        ikey,
        SPAKE_GROUP_P256,
        &wbytes,
        &result,
        &thash,
        body_der,
        1,
    )?;
    let factor = krb5_types::spake::SpakeSecondFactor {
        factor_type: 1,
        data: None,
    };
    let factor_der = encode(&factor)?;
    let usage = KeyUsage::new(ku::SPAKE)?;
    let factor_ct = encrypt(&k1, usage, &factor_der)?;
    let msg = krb5_types::spake::PaSpake::Response(krb5_types::spake::SpakeResponse {
        pubkey: pub_x.into(),
        factor: EncryptedData {
            etype: ikey.etype().to_iana(),
            kvno: None,
            cipher: factor_ct.into(),
        },
    });
    Ok((
        PaData {
            padata_type: pa::SPAKE,
            padata_value: encode(&msg)?.into(),
        },
        k0,
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
    body_sha1: Option<&[u8]>,
) -> Result<PaData, Error> {
    pa_pk_as_req_spki(
        &krb5_types::pkinit::encode_ec_spki(client_public),
        ca,
        body_sha1,
    )
}

/// PA-PK-AS-REQ whose `clientPublicValue` is an already-encoded SPKI
/// (ECDH P-256 or MODP DH).
///
/// # Errors
///
/// DER or CMS wrap failures.
pub fn pa_pk_as_req_spki(
    spki: &[u8],
    ca: &krb5_types::pkinit::PkinitCa,
    body_sha1: Option<&[u8]>,
) -> Result<PaData, Error> {
    pa_pk_as_req_spki_cn(spki, ca, "user", body_sha1)
}

/// PA-PK-AS-REQ signed as `cn` (SAN / EKU follow that identity).
///
/// # Errors
///
/// DER or CMS wrap failures.
pub fn pa_pk_as_req_cn(
    client_public: &[u8],
    ca: &krb5_types::pkinit::PkinitCa,
    cn: &str,
    body_sha1: Option<&[u8]>,
) -> Result<PaData, Error> {
    pa_pk_as_req_spki_cn(
        &krb5_types::pkinit::encode_ec_spki(client_public),
        ca,
        cn,
        body_sha1,
    )
}

fn pa_pk_as_req_spki_cn(
    spki: &[u8],
    ca: &krb5_types::pkinit::PkinitCa,
    cn: &str,
    body_sha1: Option<&[u8]>,
) -> Result<PaData, Error> {
    let pack = krb5_types::pkinit::AuthPack {
        pk_authenticator: krb5_types::pkinit::PkAuthenticator {
            cusec: Microseconds::ZERO,
            ctime: KerberosTime::now(),
            nonce: 1,
            pa_checksum: body_sha1.map(|s| s.to_vec().into()),
        },
        client_public_value: Some(spki.to_vec().into()),
        supported_cms_types: None,
    };
    let inner = encode(&pack)?;
    let signed = ca
        .sign_cms(&inner, cn)
        .ok_or_else(|| Error::ReplyMismatch("PKINIT CMS wrap".into()))?;
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

/// PA-PK-AS-REQ advertising RFC 8636 SHA-256 `supportedKDFs`.
///
/// # Errors
///
/// DER or CMS wrap failures.
pub fn pa_pk_as_req_agile(
    client_public: &[u8],
    ca: &krb5_types::pkinit::PkinitCa,
    body_sha1: Option<&[u8]>,
) -> Result<PaData, Error> {
    let spki = krb5_types::pkinit::encode_ec_spki(client_public);
    let pack = krb5_types::pkinit::AuthPack {
        pk_authenticator: krb5_types::pkinit::PkAuthenticator {
            cusec: Microseconds::ZERO,
            ctime: KerberosTime::now(),
            nonce: 1,
            pa_checksum: body_sha1.map(|s| s.to_vec().into()),
        },
        client_public_value: Some(spki.into()),
        supported_cms_types: None,
    };
    let inner = encode(&pack)?;
    let inner = krb5_types::pkinit::authpack_with_sha256_kdf(&inner)
        .ok_or_else(|| Error::ReplyMismatch("AuthPack kdf".into()))?;
    let signed = ca
        .sign_cms(&inner, "user")
        .ok_or_else(|| Error::ReplyMismatch("PKINIT CMS wrap".into()))?;
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

/// PA-PK-AS-REQ signed with a client identity (RFC 4556 + RFC 8636 SHA-256 KDF).
///
/// `body_sha1` is the SHA-1 of the encoded KDC-REQ-BODY (`paChecksum`).
///
/// # Errors
///
/// DER or CMS wrap failures.
pub fn pa_pk_as_req_signed(
    client_public: &[u8],
    cert_der: &[u8],
    leaf_secret: &[u8; 32],
    nonce: u32,
    body_sha1: &[u8],
) -> Result<PaData, Error> {
    let now = KerberosTime::now();
    let usec = now.0.timestamp_subsec_micros() % 1_000_000;
    let pk_auth = krb5_types::pkinit::PkAuthenticator {
        cusec: Microseconds::from_subsec_micros(usec),
        ctime: now,
        nonce,
        pa_checksum: Some(body_sha1.to_vec().into()),
    };
    let spki = krb5_types::pkinit::encode_ec_spki(client_public);
    let inner = krb5_types::pkinit::encode_client_authpack(&pk_auth, &spki)
        .ok_or_else(|| Error::ReplyMismatch("AuthPack kdf".into()))?;
    let signed = krb5_types::pkinit::cms_sign_leaf(
        &inner,
        cert_der,
        leaf_secret,
        krb5_types::pkinit::ECONTENT_AUTHDATA,
    )
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

/// Verify the KDC CMS, then require KPKdc + SAN `krbtgt/REALM@REALM` and
/// `id-pkinit-DHKeyData` before any ECDH.
fn verify_kdc_pkinit_cms(
    cms: &[u8],
    kdc_trust_anchor: &[u8],
    realm: &str,
) -> Result<Vec<u8>, Error> {
    let v = krb5_types::pkinit::cms_verify_full(cms, kdc_trust_anchor)
        .map_err(|e| Error::ReplyMismatch(format!("PKINIT KDC CMS: {e}")))?;
    krb5_types::pkinit::require_kdc_pkinit_cert(&v.cert, realm)
        .map_err(|e| Error::ReplyMismatch(format!("PKINIT KDC CMS: {e}")))?;
    if v.e_content_type.as_slice() != krb5_types::pkinit::ECONTENT_DHKEY {
        return Err(Error::ReplyMismatch("PKINIT eContentType".into()));
    }
    Ok(v.e_content)
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
    realm: &str,
) -> Result<ProtocolKey, Error> {
    let raw = padata
        .as_ref()
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::PK_AS_REP))
        .ok_or_else(|| Error::ReplyMismatch("missing PA-PK-AS-REP".into()))?;
    let rep: krb5_types::pkinit::PaPkAsRep = decode(raw.padata_value.as_ref())?;
    let pub_kdc = match &rep {
        krb5_types::pkinit::PaPkAsRep::DhInfo(info) => info,
        krb5_types::pkinit::PaPkAsRep::EncKeyPack(_) => {
            return Err(Error::ReplyMismatch("PKINIT encKeyPack unsupported".into()));
        }
    };
    let inner = verify_kdc_pkinit_cms(pub_kdc.dh_signed_data.as_ref(), kdc_trust_anchor, realm)?;
    let kdc_pub = krb5_types::pkinit::decode_kdc_dh_point(&inner)
        .or_else(|| krb5_types::pkinit::decode_ec_spki(&inner))
        .ok_or_else(|| Error::ReplyMismatch("PKINIT KDC DH".into()))?;
    let shared = p256_shared(client_secret, &kdc_pub)?;
    if let Some(oid) = krb5_types::pkinit::pa_pk_as_rep_kdf_oid(raw.padata_value.as_ref())
        && oid.as_slice() == krb5_types::pkinit::KDF_AH_SHA256_OID
    {
        return Err(Error::ReplyMismatch(
            "PKINIT RFC 8636 KDF requires pkinit_reply_key_agile".into(),
        ));
    }
    octetstring2key(etype, &shared).map_err(Into::into)
}

/// Derive the PKINIT reply key using RFC 8636 when `kdf` is in PA-PK-AS-REP.
///
/// # Errors
///
/// Missing padata, ECDH, or KDF failures.
pub fn pkinit_reply_key_agile(
    client_secret: &[u8; 32],
    padata: &Option<Vec<PaData>>,
    etype: EncryptionType,
    kdc_trust_anchor: &[u8],
    as_req: &[u8],
    client: &PrincipalName,
    realm: &str,
) -> Result<ProtocolKey, Error> {
    let raw = padata
        .as_ref()
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::PK_AS_REP))
        .ok_or_else(|| Error::ReplyMismatch("missing PA-PK-AS-REP".into()))?;
    let cms = krb5_types::pkinit::pa_pk_as_rep_dh_signed_data(raw.padata_value.as_ref())
        .ok_or_else(|| Error::ReplyMismatch("PKINIT dhSignedData".into()))?;
    let inner = verify_kdc_pkinit_cms(&cms, kdc_trust_anchor, realm)?;
    let kdc_pub = krb5_types::pkinit::decode_kdc_dh_point(&inner)
        .or_else(|| krb5_types::pkinit::decode_ec_spki(&inner))
        .ok_or_else(|| Error::ReplyMismatch("PKINIT KDC DH".into()))?;
    let shared = p256_shared(client_secret, &kdc_pub)?;
    let Some(oid) = krb5_types::pkinit::pa_pk_as_rep_kdf_oid(raw.padata_value.as_ref()) else {
        return octetstring2key(etype, &shared).map_err(Into::into);
    };
    if oid.as_slice() != krb5_types::pkinit::KDF_AH_SHA256_OID {
        return Err(Error::ReplyMismatch("PKINIT unknown kdf".into()));
    }
    let parts: Vec<String> = client
        .name_string
        .iter()
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
        .collect();
    let prefs: Vec<&str> = parts.iter().map(String::as_str).collect();
    let party_u = krb5_types::pkinit::encode_krb5_principal_name(realm, client.name_type, &prefs);
    let party_v = krb5_types::pkinit::encode_krb5_principal_name(
        realm,
        PrincipalName::NT_SRV_INST,
        &["krbtgt", realm],
    );
    let supp = krb5_types::pkinit::encode_pkinit_supp_pub_info(
        etype.to_iana(),
        as_req,
        raw.padata_value.as_ref(),
    );
    let other = krb5_types::pkinit::encode_rfc8636_other_info(
        krb5_types::pkinit::KDF_AH_SHA256_OID,
        &party_u,
        &party_v,
        &supp,
    );
    pkinit_kdf_agile(etype, &shared, &other).map_err(Into::into)
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
        user_realm: krb5_types::try_ascii(realm)
            .map_err(|e| Error::ReplyMismatch(e.to_string()))?,
        cksum: Checksum {
            cksumtype: session.etype().checksum_type(),
            checksum: mic.into(),
        },
        auth_package: krb5_types::try_ascii(pkg)
            .map_err(|e| Error::ReplyMismatch(e.to_string()))?,
    };
    Ok(PaData {
        padata_type: pa::FOR_USER,
        padata_value: encode(&for_user)?.into(),
    })
}

/// PA-PAC-OPTIONS (padata 167). `rbcd` sets MS-KILE bit 3.
///
/// # Errors
///
/// DER encode.
pub fn pa_pac_options(rbcd: bool) -> Result<PaData, Error> {
    let body = if rbcd {
        krb5_types::s4u::PaPacOptions::rbcd()
    } else {
        krb5_types::s4u::PaPacOptions {
            flags: KerberosFlags::repeat(false, 32),
        }
    };
    Ok(PaData {
        padata_type: pa::PAC_OPTIONS,
        padata_value: encode(&body)?.into(),
    })
}
