//! Client padata for FAST, SPAKE, PKINIT, and S4U, and the client checks on the KDC's reply.
//! The builders make padata. They do not send it. The AS and TGS exchanges do. A builder that fails returns the error. It does not emit an empty padata list and continue. The verifiers (`verify_fast_finished`, `verify_req_enc_pa_rep`, `unwrap_fast_rep_checked`, `pkinit_reply_key`,

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, SpakeGroup, checksum, cksumtype_is_keyed,
    decrypt_enc_data, encrypt, hmac_md5_arcfour_checksum, krb_fx_cf2, octetstring2key,
    pkinit_kdf_agile, spake_derive_key, spake_keygen, spake_result, spake_thash_update,
    spake_wbytes, verify_checksum_type,
};
use krb5_types::{
    ApOptions, ApReq, AsReq, Authenticator, Checksum, EncKdcRepPart, EncryptedData, EncryptionKey,
    KerberosFlags, KerberosTime, Microseconds, PaData, PrincipalName, Realm, Ticket, err, ku, pa,
    principal_compare,
};

use krb5_types::pkinit::KxKey;

use crate::error::Error;
use crate::trace;

const CKSUMTYPE_HMAC_MD5_ARCFOUR: i32 = -138;

/// Mix a FAST subkey with the armor ticket session key (RFC 6113).
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
pub fn build_fast_armor(
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    subkey: Option<&ProtocolKey>,
) -> Result<ApReq, Error> {
    // MIT: `generate_authenticator` (lib/krb5/krb/mk_req_ext.c:327-327)
    // the armor authenticator's time and microseconds, from `krb5_us_timeofday`.
    let (now, usec) = crate::auth_con::us_timeofday();
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
pub fn attach_fast(
    req: &mut AsReq,
    armor: &ApReq,
    armor_key: &ProtocolKey,
    inner_padata: Vec<PaData>,
) -> Result<(), Error> {
    attach_fast_with_options(
        req,
        armor,
        armor_key,
        inner_padata,
        &krb5_types::fast::fast_options_none(),
    )
}

/// [`attach_fast`] with an explicit `FastOptions` (RFC 6113 bit 1 hide-client-names, etc.). The KDC honours hide-client-names by returning the anonymous principal as the outer reply client (MIT `kdc_fast_hide_client`).
pub fn attach_fast_with_options(
    req: &mut AsReq,
    armor: &ApReq,
    armor_key: &ProtocolKey,
    inner_padata: Vec<PaData>,
    fast_options: &krb5_types::fast::FastOptions,
) -> Result<(), Error> {
    // MIT: `restart_init_creds_loop` (get_in_tkt.c:836-838)
    // takes the `krb5int_fast_prep_req_body` snapshot of the outer body.
    // MIT: `krb5int_fast_prep_req_body` (fast.c:157-161)
    // the snapshot is the request without its padata.
    // MIT: `init_creds_step_request` (get_in_tkt.c:1278-1280)
    // resets the request times with `set_request_times` on each step, after that snapshot.
    // MIT: `krb5int_fast_prep_req` (fast.c:310-313)
    // `req_checksum` is over the snapshotted outer body.
    let mut inner = inner_padata;
    inner.extend(req.0.padata.take().unwrap_or_default());
    let inner_body = req.0.req_body.clone();
    req.0.req_body.till = KerberosTime::from_unix_seconds(0);
    req.0.req_body.from = None;
    req.0.req_body.rtime = None;
    let outer_der = encode(&req.0.req_body)?;
    req.0.padata = Some(vec![fx_fast_padata_over(
        Some(armor),
        armor_key,
        &outer_der,
        &inner_body,
        inner,
        fast_options,
    )?]);
    Ok(())
}

/// PA-FX-FAST wrapping `inner_padata` and a copy of `req_body`.
pub fn fx_fast_padata(
    armor: Option<&ApReq>,
    armor_key: &ProtocolKey,
    req_body: &krb5_types::KdcReqBody,
    inner_padata: Vec<PaData>,
    fast_options: &krb5_types::fast::FastOptions,
) -> Result<PaData, Error> {
    let body_der = encode(req_body)?;
    fx_fast_padata_over(
        armor,
        armor_key,
        &body_der,
        req_body,
        inner_padata,
        fast_options,
    )
}

/// [`fx_fast_padata`] with an explicit FAST req_checksum input.
/// the FAST encode path, whose req_checksum is over the caller's `to_be_checksummed` bytes.
// MIT: `k5_make_tgs_req` (send_tgs.c:279-279)
/// passes the PA-TGS-REQ AP-REQ as those bytes.
pub fn fx_fast_padata_over(
    armor: Option<&ApReq>,
    armor_key: &ProtocolKey,
    checksum_over: &[u8],
    req_body: &krb5_types::KdcReqBody,
    inner_padata: Vec<PaData>,
    fast_options: &krb5_types::fast::FastOptions,
) -> Result<PaData, Error> {
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    let mic = checksum(armor_key, ck_usage, checksum_over)?;
    let inner = krb5_types::fast::KrbFastReq {
        fast_options: fast_options.clone(),
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

/// Verify `KrbFastFinished.ticket_checksum` over the ticket DER.
// MIT: `krb5int_fast_process_response` (fast.c:543-551)
/// the ticket checksum is verified under the armor key over the encoded ticket; a mismatch is "Ticket modified in KDC reply".
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

/// PA-REQ-ENC-PA-REP over the AS-REQ when `enc-pa-rep` is set.
// MIT: `krb5int_fast_verify_nego` (fast.c:648-664)
/// with `enc-pa-rep` set, a missing or bad PA-REQ-ENC-PA-REP checksum over the AS-REQ is `KRB5_KDCREP_MODIFIED`.
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
    let plain = decrypt_enc_data(
        armor_key,
        usage,
        armored.enc_fast_rep.etype,
        armored.enc_fast_rep.cipher.as_ref(),
    )?;
    decode(&plain).map_err(Error::from)
}

// MIT: `decrypt_fast_reply` (fast.c:397-402)
/// `local_resp->nonce != state->nonce` is `KRB5_KDCREP_MODIFIED` ("nonce modified in FAST response").
pub fn unwrap_fast_rep_checked(
    armor_key: &ProtocolKey,
    padata: &Option<Vec<PaData>>,
    expected_nonce: u32,
) -> Result<krb5_types::fast::KrbFastResponse, Error> {
    let fast = unwrap_fast_rep(armor_key, padata)?;
    if fast.nonce != expected_nonce {
        return Err(Error::ReplyMismatch(
            "nonce modified in FAST response: KDC response modified".into(),
        ));
    }
    Ok(fast)
}

/// Mix the FAST strengthen-key with the base reply key.
pub fn apply_strengthen(
    strengthen: &EncryptionKey,
    base: &ProtocolKey,
) -> Result<ProtocolKey, Error> {
    let et = EncryptionType::known(strengthen.keytype)?;
    let sk = ProtocolKey::from_bytes(et, strengthen.keyvalue.as_ref())?;
    krb_fx_cf2(&sk, base, b"strengthenkey", b"replykey").map_err(Into::into)
}

// MIT: `send_support` (spake_client.c:155-167)
/// the client's permitted groups, in configuration order.
#[must_use]
pub fn pa_spake_support(groups: &[SpakeGroup]) -> PaData {
    let msg = krb5_types::spake::PaSpake::Support(krb5_types::spake::SpakeSupport {
        groups: groups.iter().map(|g| g.number()).collect(),
    });
    PaData {
        padata_type: pa::SPAKE,
        padata_value: encode(&msg).unwrap_or_default().into(),
    }
}

/// A PA-SPAKE response to a challenge in `group`, and the reply key `K'[0]`.
// MIT: `process_challenge` (spake_client.c:210-282)
/// the transcript is the support message, the challenge and the client's element; the SF-NONE factor is encrypted in `K'[1]`.
pub fn pa_spake_response(
    ikey: &ProtocolKey,
    group: SpakeGroup,
    support_der: &[u8],
    challenge_der: &[u8],
    challenge_pubkey: &[u8],
    body_der: &[u8],
) -> Result<(PaData, ProtocolKey), Error> {
    let wbytes = spake_wbytes(ikey, group)?;
    let (secret, pub_x) = spake_keygen(group, &wbytes, false)?;
    // MIT: `group_keygen` (plugins/preauth/spake/groups.c:333-371)
    // the public value is traced.
    crate::trace::spake_keygen(&pub_x);
    let result = spake_result(group, &wbytes, &secret, challenge_pubkey, false)?;
    // MIT: `group_result` (plugins/preauth/spake/groups.c:374-412)
    // the result is traced, which `trace::spake_result` prints as a hash only.
    crate::trace::spake_result(&result);
    let thash = spake_thash_update(group, &[], support_der, challenge_der);
    let thash = spake_thash_update(group, &thash, &pub_x, &[]);
    crate::trace::spake_client_thash(&thash);
    let k0 = spake_derive_key(ikey, group, &wbytes, &result, &thash, body_der, 0)?;
    let k1 = spake_derive_key(ikey, group, &wbytes, &result, &thash, body_der, 1)?;
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
    crate::trace::spake_send_response();
    Ok((
        PaData {
            padata_type: pa::SPAKE,
            padata_value: encode(&msg)?.into(),
        },
        k0,
    ))
}

#[cfg(any(test, feature = "test-ca"))]
/// PA-PK-AS-REQ: AuthPack inside CMS SignedData (`signedAuthPack`).
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

#[cfg(any(test, feature = "test-ca"))]
/// PA-PK-AS-REQ whose `clientPublicValue` is an already-encoded SPKI (ECDH P-256 or MODP DH).
pub fn pa_pk_as_req_spki(
    spki: &[u8],
    ca: &krb5_types::pkinit::PkinitCa,
    body_sha1: Option<&[u8]>,
) -> Result<PaData, Error> {
    pa_pk_as_req_spki_cn(spki, ca, "user", body_sha1)
}

#[cfg(any(test, feature = "test-ca"))]
/// PA-PK-AS-REQ signed as `cn` (SAN / EKU follow that identity).
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

#[cfg(any(test, feature = "test-ca"))]
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
            freshness_token: None,
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

#[cfg(any(test, feature = "test-ca"))]
/// PA-PK-AS-REQ advertising RFC 8636 SHA-256 `supportedKDFs`.
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
            freshness_token: None,
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
pub fn pa_pk_as_req_signed(
    client_public: &[u8],
    cert_der: &[u8],
    leaf_key: &krb5_types::pkinit::IdentityKey,
    nonce: u32,
    body_sha1: &[u8],
    freshness: Option<&[u8]>,
) -> Result<PaData, Error> {
    pa_pk_as_req_signed_at(
        &krb5_types::pkinit::encode_ec_spki(client_public),
        cert_der,
        leaf_key,
        nonce,
        body_sha1,
        freshness,
        crate::auth_con::us_timeofday(),
    )
}

/// [`pa_pk_as_req_signed`] with the authenticator's time given: the AS exchange's clock.
pub(crate) fn pa_pk_as_req_signed_at(
    spki: &[u8],
    cert_der: &[u8],
    leaf_key: &krb5_types::pkinit::IdentityKey,
    nonce: u32,
    body_sha1: &[u8],
    freshness: Option<&[u8]>,
    now: (KerberosTime, Microseconds),
) -> Result<PaData, Error> {
    let (now, usec) = now;
    let pk_auth = krb5_types::pkinit::PkAuthenticator {
        cusec: usec,
        ctime: now,
        nonce,
        pa_checksum: Some(body_sha1.to_vec().into()),
        freshness_token: freshness.map(|t| t.to_vec().into()),
    };
    let inner = krb5_types::pkinit::encode_client_authpack(&pk_auth, spki)
        .ok_or_else(|| Error::ReplyMismatch("AuthPack kdf".into()))?;
    let signed = krb5_types::pkinit::cms_sign_leaf(
        &inner,
        cert_der,
        leaf_key,
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

/// Unsigned AuthPack (RFC 6112 anonymous PKINIT ContentInfo).
pub fn pa_pk_as_req_unsigned(
    client_public: &[u8],
    nonce: u32,
    body_sha1: &[u8],
    freshness: Option<&[u8]>,
) -> Result<PaData, Error> {
    pa_pk_as_req_unsigned_at(
        &krb5_types::pkinit::encode_ec_spki(client_public),
        nonce,
        body_sha1,
        freshness,
        crate::auth_con::us_timeofday(),
    )
}

/// [`pa_pk_as_req_unsigned`] with the authenticator's time given: the AS exchange's clock.
pub(crate) fn pa_pk_as_req_unsigned_at(
    spki: &[u8],
    nonce: u32,
    body_sha1: &[u8],
    freshness: Option<&[u8]>,
    now: (KerberosTime, Microseconds),
) -> Result<PaData, Error> {
    let (now, usec) = now;
    let pk_auth = krb5_types::pkinit::PkAuthenticator {
        cusec: usec,
        ctime: now,
        nonce,
        pa_checksum: Some(body_sha1.to_vec().into()),
        freshness_token: freshness.map(|t| t.to_vec().into()),
    };
    let inner = krb5_types::pkinit::encode_client_authpack(&pk_auth, spki)
        .ok_or_else(|| Error::ReplyMismatch("AuthPack kdf".into()))?;
    let wrapped = krb5_types::pkinit::cms_wrap_unsigned(&inner);
    let req = krb5_types::pkinit::PaPkAsReq {
        signed_auth_pack: wrapped.into(),
        trusted_certifiers: None,
        kdc_pk_id: None,
    };
    Ok(PaData {
        padata_type: pa::PK_AS_REQ,
        padata_value: encode(&req)?.into(),
    })
}

#[derive(Clone, Copy)]
pub struct KdcTrust<'a> {
    pub anchors: &'a [Vec<u8>],
    pub pool: &'a [Vec<u8>],
    pub hostnames: &'a [String],
    pub require_eku: bool,
    pub accept_secondary_eku: bool,
}

impl<'a> KdcTrust<'a> {
    #[must_use]
    pub fn anchor(cert: &'a Vec<u8>) -> Self {
        Self {
            anchors: std::slice::from_ref(cert),
            pool: &[],
            hostnames: &[],
            require_eku: true,
            accept_secondary_eku: false,
        }
    }
}

/// Verifies the KDC's CMS, then requires the id-pkinit-KPKdc EKU, the SAN `krbtgt/REALM@REALM` and `id-pkinit-DHKeyData`, all before any ECDH (MIT `pkinit_as_rep_parse`).
fn verify_kdc_pkinit_cms(cms: &[u8], trust: KdcTrust<'_>, realm: &str) -> Result<Vec<u8>, Error> {
    let pack = krb5_types::pkinit::cms_signeddata_verify(
        cms,
        trust.anchors,
        trust.pool,
        krb5_types::pkinit::CmsSigner::Server,
    )
    .map_err(|fault| {
        trace::pkinit_client_rep_dh_fail();
        Error::PkinitReply {
            code: trace::kdc_code(fault.code()),
            text: fault.message(),
        }
    })?;
    trace::pkinit_client_rep_dh();
    verify_kdc_cert(&pack.signer.unwrap_or_default(), trust, realm)?;
    Ok(pack.e_content)
}

// MIT verify_kdc_san; see docs/parity/b1-client-preauth.md. The KDC's SAN must name `krbtgt/<realm>@<realm>`, or `pkinit_kdc_hostname`'s host when that's set.
fn verify_kdc_cert(cert: &[u8], trust: KdcTrust<'_>, realm: &str) -> Result<(), Error> {
    let refuse = |code: i32| {
        let code = trace::kdc_code(code);
        Error::PkinitReply {
            code,
            text: trace::error_message(code),
        }
    };
    for host in trust.hostnames {
        trace::pkinit_client_san_config_dnsname(host);
    }
    let Some(sans) = krb5_types::pkinit::cert_sans(cert, false) else {
        trace::pkinit_client_san_err();
        return Err(refuse(err::KDC_NAME_MISMATCH));
    };
    let tgs = PrincipalName::krbtgt(realm);
    let mut named = false;
    for (san_realm, name_type, parts) in &sans.principals {
        let san = PrincipalName::new(*name_type, parts.iter().map(String::as_str));
        trace::pkinit_client_san_kdccert_princ(trace::Princ::new(&san, san_realm.as_bytes()));
        named |= san_realm == realm && san.name_string == tgs.name_string;
    }
    let hosts: &[String] = if trust.hostnames.is_empty() {
        &[]
    } else {
        &sans.dns_names
    };
    for host in hosts {
        trace::pkinit_client_san_kdccert_dnsname(host);
    }
    if named {
        trace::pkinit_client_san_match_princ(trace::Princ::new(&tgs, realm.as_bytes()));
        return Ok(());
    }
    if hosts.is_empty() {
        return Err(refuse(err::KDC_NAME_MISMATCH));
    }
    let Some(host) = hosts
        .iter()
        .find(|h| trust.hostnames.iter().any(|c| c.eq_ignore_ascii_case(h)))
    else {
        trace::pkinit_client_san_match_none();
        return Err(refuse(err::KDC_NAME_MISMATCH));
    };
    trace::pkinit_client_san_match_dnsname(host);
    // MIT verify_kdc_eku; see docs/parity/b1-client-preauth.md. id-pkinit-KPKdc unless `pkinit_eku_checking` relaxes it.
    if !trust.require_eku {
        trace::pkinit_client_eku_skip();
        trace::pkinit_client_eku_accept();
        return Ok(());
    }
    match krb5_types::pkinit::cert_eku(cert, true, trust.accept_secondary_eku) {
        krb5_types::pkinit::EkuCheck::Accepted => {
            trace::pkinit_eku();
            trace::pkinit_client_eku_accept();
            Ok(())
        }
        found => {
            if found == krb5_types::pkinit::EkuCheck::NoDigitalSignature {
                trace::pkinit_eku_no_ku();
            }
            trace::pkinit_client_eku_reject();
            Err(refuse(err::INCONSISTENT_KEY_PURPOSE))
        }
    }
}

/// Derive the PKINIT reply key from PA-PK-AS-REP `dh_signed_data` (CMS or raw P-256).
pub fn pkinit_reply_key(
    key: &KxKey,
    padata: &Option<Vec<PaData>>,
    etype: EncryptionType,
    trust: KdcTrust<'_>,
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
    let inner = verify_kdc_pkinit_cms(pub_kdc.dh_signed_data.as_ref(), trust, realm)?;
    let kdc_pub = krb5_types::pkinit::decode_kdc_dh_point(&inner)
        .ok_or_else(|| Error::ReplyMismatch("PKINIT KDC DH".into()))?;
    let shared = key
        .shared(&kdc_pub)
        .ok_or_else(|| Error::Crypto("PKINIT key exchange".into()))?;
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
pub fn pkinit_reply_key_agile(
    key: &KxKey,
    padata: &Option<Vec<PaData>>,
    etype: EncryptionType,
    trust: KdcTrust<'_>,
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
    let inner = verify_kdc_pkinit_cms(&cms, trust, realm)?;
    let kdc_pub = krb5_types::pkinit::decode_kdc_dh_point(&inner)
        .ok_or_else(|| Error::ReplyMismatch("PKINIT KDC DH".into()))?;
    let shared = key
        .shared(&kdc_pub)
        .ok_or_else(|| Error::Crypto("PKINIT key exchange".into()))?;
    let Some(oid) = krb5_types::pkinit::pa_pk_as_rep_kdf_oid(raw.padata_value.as_ref()) else {
        return octetstring2key(etype, &shared).map_err(Into::into);
    };
    if oid.as_slice() != krb5_types::pkinit::KDF_AH_SHA256_OID {
        return Err(Error::ReplyMismatch("PKINIT unknown kdf".into()));
    }
    let party_u = krb5_types::pkinit::encode_party_u(client, realm);
    let party_v = decode::<AsReq>(as_req)
        .ok()
        .and_then(|r| krb5_types::pkinit::encode_party_v(&r.0.req_body))
        .ok_or_else(|| Error::ReplyMismatch("PKINIT AS-REQ sname".into()))?;
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
// MIT: `make_pa_for_user_checksum` (lib/krb5/krb/s4u_creds.c:130-133)
/// the checksum is HMAC-MD5 (`CKSUMTYPE_HMAC_MD5_ARCFOUR`, -138) whatever the key's type, as MS-SFU specifies.
pub fn pa_for_user(
    session: &ProtocolKey,
    user: PrincipalName,
    realm: &str,
) -> Result<PaData, Error> {
    let pkg = "Kerberos";
    let data = krb5_types::s4u::pa_for_user_cksum_data(&user, realm, pkg);
    let mic = hmac_md5_arcfour_checksum(
        session.as_bytes(),
        ku::PA_FOR_USER,
        &data,
        CKSUMTYPE_HMAC_MD5_ARCFOUR,
    )?;
    let for_user = krb5_types::s4u::PaForUser {
        user_name: user,
        user_realm: krb5_types::try_ascii(realm)
            .map_err(|e| Error::ReplyMismatch(e.to_string()))?,
        cksum: Checksum {
            cksumtype: CKSUMTYPE_HMAC_MD5_ARCFOUR,
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

/// PA-S4U-X509-USER (padata 130). Checksum is ku 26 over the encoded user-id.
pub fn pa_s4u_x509_user(
    key: &ProtocolKey,
    user: PrincipalName,
    realm: &str,
    nonce: u32,
) -> Result<PaData, Error> {
    let user_id = krb5_types::s4u::S4uUserId {
        nonce: nonce.cast_signed(),
        user: Some(user),
        realm: krb5_types::try_ascii(realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?,
        subject_cert: None,
        options: Some(krb5_types::s4u::s4u_reply_key_usage_flags()),
    };
    let der = encode(&user_id)?;
    let usage = KeyUsage::new(ku::PA_S4U_X509_USER_REQUEST)?;
    let mic = checksum(key, usage, &der)?;
    let body = krb5_types::s4u::PaS4uX509User {
        user_id,
        cksum: Checksum {
            cksumtype: key.etype().checksum_type(),
            checksum: mic.into(),
        },
    };
    Ok(PaData {
        padata_type: pa::FOR_X509_USER,
        padata_value: encode(&body)?.into(),
    })
}

fn find_pa_raw(padata: Option<&[PaData]>, ty: i32) -> Option<&[u8]> {
    padata?
        .iter()
        .find(|p| p.padata_type == ty)
        .map(|p| p.padata_value.as_ref())
}

fn s4u_not_newer(etype: EncryptionType) -> bool {
    matches!(etype, EncryptionType::Des3CbcSha1 | EncryptionType::Rc4Hmac)
}

// MIT: `verify_s4u2self_reply` (s4u_creds.c:273-397)
/// missing 130 on both the (FAST-swapped) reply padata and enc-padata is accepted. Enc-only 130, a nonce/user/checksum mismatch, or an unkeyed reply checksum on a modern etype is refused.
pub fn verify_s4u2self_reply(
    subkey: &ProtocolKey,
    req: &krb5_types::s4u::PaS4uX509User,
    rep_padata: Option<&[PaData]>,
    enc_padata: Option<&[PaData]>,
) -> Result<(), Error> {
    let enc_s4u = find_pa_raw(enc_padata, pa::FOR_X509_USER);
    let Some(rep_raw) = find_pa_raw(rep_padata, pa::FOR_X509_USER) else {
        return if enc_s4u.is_some() {
            Err(Error::ReplyMismatch("KDC response modified".into()))
        } else {
            Ok(())
        };
    };
    let rep: krb5_types::s4u::PaS4uX509User =
        decode(rep_raw).map_err(|e| Error::Asn1(e.to_string()))?;
    if rep.user_id.nonce != req.user_id.nonce {
        return Err(Error::ReplyMismatch("KDC response modified".into()));
    }
    let der = encode(&rep.user_id)?;
    let usage = KeyUsage::new(if rep.user_id.use_reply_key_usage() {
        ku::PA_S4U_X509_USER_REPLY
    } else {
        ku::PA_S4U_X509_USER_REQUEST
    })?;
    if verify_checksum_type(
        subkey,
        usage,
        &der,
        rep.cksum.cksumtype,
        rep.cksum.checksum.as_ref(),
    )
    .is_err()
    {
        return Err(Error::ReplyMismatch("KDC response modified".into()));
    }
    let Some(rep_user) = rep.user_id.user.as_ref() else {
        return Err(Error::ReplyMismatch("KDC response modified".into()));
    };
    if rep_user.name_string.is_empty() {
        return Err(Error::ReplyMismatch("KDC response modified".into()));
    }
    let req_user = req
        .user_id
        .user
        .as_ref()
        .ok_or_else(|| Error::ReplyMismatch("KDC response modified".into()))?;
    let req_realm = std::str::from_utf8(req.user_id.realm.as_bytes()).unwrap_or("");
    let rep_realm = std::str::from_utf8(rep.user_id.realm.as_bytes()).unwrap_or("");
    if !principal_compare(req_user, req_realm, rep_user, rep_realm) {
        return Err(Error::ReplyMismatch("KDC response modified".into()));
    }
    if s4u_not_newer(subkey.etype()) {
        if let Some(enc) = enc_s4u {
            let want = [req.cksum.checksum.as_ref(), rep.cksum.checksum.as_ref()].concat();
            if enc != want.as_slice() {
                return Err(Error::ReplyMismatch("KDC response modified".into()));
            }
        } else if rep.user_id.use_reply_key_usage() {
            return Err(Error::ReplyMismatch("KDC response modified".into()));
        }
    } else if !cksumtype_is_keyed(rep.cksum.cksumtype) {
        return Err(Error::KrbError {
            code: err::INAPP_CKSUM,
            text: Some("Inappropriate type of checksum in message".into()),
        });
    }
    Ok(())
}

/// PA-PAC-OPTIONS (padata 167). `rbcd` sets MS-KILE bit 3.
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
