//! FAST, SPAKE, and PKINIT processing on the KDC.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    checksum, decrypt, encrypt, key_from_shared, krb_fx_cf2, p256_generate, p256_shared,
    spake_finish, spake_public, spake_w, verify_checksum, EncryptionType, KeyUsage, ProtocolKey,
};
use krb5_types::{
    err, ku, pa, AsReq, EncryptedData, EncryptionKey, KerberosTime, MethodData, Microseconds,
    PaData, PrincipalName,
};

use crate::error::Error;
use crate::store::{Principal, PrincipalStore};

pub(crate) struct FastOk {
    pub armor_key: ProtocolKey,
    pub inner_padata: Vec<PaData>,
}

/// Unwrap PA-FX-FAST from an AS-REQ.
pub(crate) fn unwrap_fast(store: &PrincipalStore, req: &AsReq) -> Result<Option<FastOk>, Error> {
    let Some(raw) = find_pa(req.0.padata.as_deref(), pa::FX_FAST) else {
        return Ok(None);
    };
    let armored = if let Ok(w) = decode::<krb5_types::fast::PaFxFast>(raw) {
        w.armored_data
    } else {
        decode::<krb5_types::fast::KrbFastArmoredReq>(raw)?
    };
    let armor_key = armor_key_from(store, &armored)?;
    let body_der = encode(&req.0.req_body)?;
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM)?;
    verify_checksum(
        &armor_key,
        ck_usage,
        &body_der,
        armored.req_checksum.checksum.as_ref(),
    )
    .map_err(|_| proto(err::INAPP_CKSUM, "FAST req-checksum"))?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC)?;
    let plain = decrypt(&armor_key, enc_usage, armored.enc_fast_req.cipher.as_ref())?;
    let inner: krb5_types::fast::KrbFastReq = decode(&plain)?;
    Ok(Some(FastOk {
        armor_key,
        inner_padata: inner.padata,
    }))
}

fn armor_key_from(
    store: &PrincipalStore,
    armored: &krb5_types::fast::KrbFastArmoredReq,
) -> Result<ProtocolKey, Error> {
    let armor = armored
        .armor
        .as_ref()
        .ok_or_else(|| proto(err::PREAUTH_FAILED, "FAST armor required"))?;
    if armor.armor_type != krb5_types::fast::ARMOR_AP_REQUEST {
        return Err(proto(err::PREAUTH_FAILED, "unsupported FAST armor"));
    }
    let ap: krb5_types::ApReq = decode(armor.armor_value.as_ref())?;
    let krbtgt = store
        .krbtgt()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let tgt_key = krbtgt
        .best_key()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt key"))?;
    let tkt_usage = KeyUsage::new(ku::TICKET)?;
    let tkt_plain = decrypt(&tgt_key.key, tkt_usage, ap.ticket.enc_part.cipher.as_ref())?;
    let enc_tkt: krb5_types::EncTicketPart = decode(&tkt_plain)?;
    let etype = EncryptionType::from_iana(enc_tkt.key.keytype)
        .or_else(|_| EncryptionType::known(enc_tkt.key.keytype))?;
    let session = ProtocolKey::from_bytes(etype, enc_tkt.key.keyvalue.as_ref())?;
    if let Some(sub) = {
        let auth_usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
        let auth_plain = decrypt(&session, auth_usage, ap.authenticator.cipher.as_ref())?;
        let authenticator: krb5_types::Authenticator = decode(&auth_plain)?;
        authenticator.subkey
    } {
        let st = EncryptionType::from_iana(sub.keytype)
            .or_else(|_| EncryptionType::known(sub.keytype))?;
        let subk = ProtocolKey::from_bytes(st, sub.keyvalue.as_ref())?;
        return krb_fx_cf2(&subk, &session, b"subkeyarmor", b"ticketarmor").map_err(Error::from);
    }
    Ok(session)
}

/// Encrypt a FAST cookie (client id + SPAKE secret or empty).
pub(crate) fn make_cookie(store: &PrincipalStore, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let krbtgt = store
        .krbtgt()
        .and_then(Principal::best_key)
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let usage = KeyUsage::new(ku::FAST_COOKIE)?;
    encrypt(&krbtgt.key, usage, payload).map_err(Error::from)
}

pub(crate) fn open_cookie(store: &PrincipalStore, blob: &[u8]) -> Result<Vec<u8>, Error> {
    let krbtgt = store
        .krbtgt()
        .and_then(Principal::best_key)
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let usage = KeyUsage::new(ku::FAST_COOKIE)?;
    decrypt(&krbtgt.key, usage, blob).map_err(|_| proto(err::PREAUTH_FAILED, "bad cookie"))
}

/// Wrap KrbFastResponse into PA-FX-FAST padata.
pub(crate) fn wrap_fast_rep(
    armor_key: &ProtocolKey,
    padata: Vec<PaData>,
    strengthen: Option<&ProtocolKey>,
    nonce: u32,
    finished: Option<krb5_types::fast::KrbFastFinished>,
) -> Result<PaData, Error> {
    let sk = strengthen.map(|k| EncryptionKey {
        keytype: k.etype().to_iana(),
        keyvalue: k.as_bytes().to_vec().into(),
    });
    let resp = krb5_types::fast::KrbFastResponse {
        padata,
        strengthen_key: sk,
        finished,
        nonce,
    };
    let der = encode(&resp)?;
    let usage = KeyUsage::new(ku::FAST_REP)?;
    let cipher = encrypt(armor_key, usage, &der)?;
    let armored = krb5_types::fast::KrbFastArmoredRep {
        enc_fast_rep: EncryptedData {
            etype: armor_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    Ok(PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFastRep {
            armored_data: armored,
        })?
        .into(),
    })
}

/// SPAKE: support → challenge; response → shared key.
pub(crate) enum SpakeStep {
    /// Need a challenge (PREAUTH_REQUIRED).
    Challenge(Vec<u8>),
    /// Finished; key encrypts AS-REP.
    Done(ProtocolKey),
}

pub(crate) fn process_spake(
    store: &PrincipalStore,
    client: &Principal,
    padata: Option<&[PaData]>,
    etype: EncryptionType,
) -> Result<Option<SpakeStep>, Error> {
    let Some(raw) = find_pa(padata, pa::SPAKE) else {
        return Ok(None);
    };
    let msg: krb5_types::spake::PaSpake = decode(raw)?;
    if let Some(resp) = msg.response.as_ref() {
        let cookie = find_pa(padata, pa::FX_COOKIE)
            .ok_or_else(|| proto(err::PREAUTH_FAILED, "SPAKE cookie"))?;
        let secret = open_cookie(store, cookie)?;
        if secret.len() != 32 {
            return Err(proto(err::PREAUTH_FAILED, "SPAKE cookie"));
        }
        let mut sec = [0u8; 32];
        sec.copy_from_slice(&secret);
        let w = spake_w_from_client(client);
        let shared = spake_finish(&w, &sec, resp.pubkey.as_ref(), true)?;
        let key = key_from_shared(etype, &shared)?;
        let usage = KeyUsage::new(ku::PA_ENC_TIMESTAMP)?;
        decrypt(&key, usage, resp.factor.cipher.as_ref())
            .map_err(|_| proto(err::PREAUTH_FAILED, "SPAKE factor"))?;
        return Ok(Some(SpakeStep::Done(key)));
    }
    if msg.support.is_some() {
        let kp = krb5_crypto::p256_generate()?;
        let w = spake_w_from_client(client);
        let pub_y = spake_public(&w, &kp.secret, true)?;
        let cookie = make_cookie(store, &kp.secret)?;
        let challenge = krb5_types::spake::PaSpake {
            support: None,
            challenge: Some(krb5_types::spake::SpakeChallenge {
                group: krb5_types::spake::GROUP_P256,
                pubkey: pub_y.into(),
                factors: vec![krb5_types::spake::SpakeSecondFactor {
                    factor_type: 1,
                    data: None,
                }],
            }),
            response: None,
            enc_data: None,
        };
        let method: MethodData = vec![
            PaData {
                padata_type: pa::SPAKE,
                padata_value: encode(&challenge)?.into(),
            },
            PaData {
                padata_type: pa::FX_COOKIE,
                padata_value: cookie.into(),
            },
        ];
        return Ok(Some(SpakeStep::Challenge(encode(&method)?)));
    }
    Ok(None)
}

fn spake_w_from_client(client: &Principal) -> [u8; 32] {
    client.spake_w
}

/// Client-side SPAKE `w` matching the KDC: SHA-256 of the long-term key bytes and salt.
#[must_use]
pub fn spake_w_from_key(key: &ProtocolKey, salt: &[u8]) -> [u8; 32] {
    spake_w(key.as_bytes(), salt)
}

/// PKINIT: ECDH reply key from PA-PK-AS-REQ.
pub(crate) fn process_pkinit(
    padata: Option<&[PaData]>,
    etype: EncryptionType,
) -> Result<Option<(ProtocolKey, PaData)>, Error> {
    let Some(raw) = find_pa(padata, pa::PK_AS_REQ) else {
        return Ok(None);
    };
    let req: krb5_types::pkinit::PaPkAsReq = decode(raw)?;
    let inner = krb5_types::pkinit::cms_unwrap(req.signed_auth_pack.as_ref());
    let pack: krb5_types::pkinit::AuthPack = decode(&inner)?;
    let Some(client_pub) = pack.client_public_value else {
        return Err(proto(err::PREAUTH_FAILED, "PKINIT missing public"));
    };
    let kp = p256_generate()?;
    let shared = p256_shared(&kp.secret, client_pub.as_ref())?;
    let reply_key = key_from_shared(etype, &shared)?;
    let wrapped_pub = krb5_types::pkinit::cms_wrap(&kp.public);
    let rep = krb5_types::pkinit::PaPkAsRep {
        dh_info: Some(krb5_types::pkinit::DhRepInfo {
            dh_signed_data: wrapped_pub.into(),
            server_dh_nonce: None,
        }),
        enc_key_pack: None,
    };
    let pa = PaData {
        padata_type: pa::PK_AS_REP,
        padata_value: encode(&rep)?.into(),
    };
    Ok(Some((reply_key, pa)))
}

pub(crate) fn find_pa(padata: Option<&[PaData]>, ty: i32) -> Option<&[u8]> {
    padata?.iter().find_map(|p| {
        if p.padata_type == ty {
            Some(p.padata_value.as_ref())
        } else {
            None
        }
    })
}

pub(crate) fn proto(code: i32, text: &str) -> Error {
    Error::Protocol {
        code,
        text: Some(text.to_owned()),
    }
}

/// FAST finished checksum of the ticket DER.
pub(crate) fn fast_finished(
    armor_key: &ProtocolKey,
    ticket: &krb5_types::Ticket,
    cname: &PrincipalName,
    crealm: &str,
) -> Result<krb5_types::fast::KrbFastFinished, Error> {
    let tder = encode(ticket)?;
    let usage = KeyUsage::new(ku::FAST_FINISHED)?;
    let mic = checksum(armor_key, usage, &tder)?;
    Ok(krb5_types::fast::KrbFastFinished {
        timestamp: KerberosTime::now(),
        usec: Microseconds::ZERO,
        crealm: krb5_types::ascii(crealm),
        cname: cname.clone(),
        ticket_checksum: krb5_types::Checksum {
            cksumtype: armor_key.etype().checksum_type(),
            checksum: mic.into(),
        },
    })
}
