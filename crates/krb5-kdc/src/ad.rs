//! PAC issuance and S4U2Self / S4U2Proxy / U2U.

use krb5_asn1::{decode, encode};
use krb5_crypto::{checksum, decrypt, EncryptionType, KeyUsage, ProtocolKey};
use krb5_types::{
    err, ku, pa, AuthorizationDataValue, EncTicketPart, PaData, PrincipalName, TgsReq, Ticket,
};

use crate::error::Error;
use crate::preauth::{find_pa, proto};
use crate::store::PrincipalStore;

/// Build AD-IF-RELEVANT wrapping a signed PAC.
pub(crate) fn ticket_authz(
    store: &PrincipalStore,
    cname: &PrincipalName,
    crealm: &str,
    authtime: &krb5_types::KerberosTime,
    service_key: &ProtocolKey,
) -> Result<Option<krb5_types::AuthorizationData>, Error> {
    let krbtgt = store
        .krbtgt()
        .and_then(|p| p.best_key())
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let pac = sign_pac(
        cname,
        crealm,
        authtime.unix_seconds(),
        service_key,
        &krbtgt.key,
    )?;
    let inner = vec![AuthorizationDataValue {
        ad_type: pa::AD_WIN2K_PAC,
        ad_data: pac.into(),
    }];
    let wrapped = encode(&inner)?;
    Ok(Some(vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: wrapped.into(),
    }]))
}

/// Sign a PAC with service then KDC checksums (key usage 2 as a keyed checksum).
pub fn sign_pac(
    cname: &PrincipalName,
    crealm: &str,
    authtime: u32,
    server: &ProtocolKey,
    kdc: &ProtocolKey,
) -> Result<Vec<u8>, Error> {
    let cksumtype = server.etype().checksum_type();
    let mac_len = server.etype().hmac_output_len();
    let zeros = vec![0u8; mac_len];
    let mut pac = krb5_types::pac::Pac {
        version: 0,
        buffers: vec![
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_LOGON_INFO,
                data: krb5_types::pac::logon_info_buffer(&cname.components_joined(), crealm),
            },
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_CLIENT_INFO,
                data: krb5_types::pac::client_info_buffer(authtime, &cname.components_joined()),
            },
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_SERVER_CHECKSUM,
                data: krb5_types::pac::signature_buffer(cksumtype, &zeros),
            },
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_PRIVSVR_CHECKSUM,
                data: krb5_types::pac::signature_buffer(cksumtype, &zeros),
            },
        ],
    };
    let usage = KeyUsage::new(ku::TICKET)?;
    let zeroed = pac.bytes_for_checksum();
    let server_mac = checksum(server, usage, &zeroed)?;
    let kdc_mac = checksum(kdc, usage, &server_mac)?;
    for b in &mut pac.buffers {
        if b.kind == krb5_types::pac::PAC_SERVER_CHECKSUM {
            b.data = krb5_types::pac::signature_buffer(cksumtype, &server_mac);
        }
        if b.kind == krb5_types::pac::PAC_PRIVSVR_CHECKSUM {
            b.data = krb5_types::pac::signature_buffer(cksumtype, &kdc_mac);
        }
    }
    Ok(pac.to_bytes())
}

/// Verify PAC server checksum with `server` and KDC checksum with `kdc`.
///
/// # Errors
///
/// PAC parse or integrity failure.
pub fn verify_pac(pac_bytes: &[u8], server: &ProtocolKey, kdc: &ProtocolKey) -> Result<(), Error> {
    let pac = krb5_types::pac::Pac::parse(pac_bytes)
        .map_err(|e| proto(err::BAD_INTEGRITY, &format!("PAC parse: {e}")))?;
    let usage = KeyUsage::new(ku::TICKET)?;
    let zeroed = pac.bytes_for_checksum();
    let server_mac = checksum(server, usage, &zeroed)?;
    krb5_types::pac::verify_server_checksum(&pac, &server_mac)
        .map_err(|_| proto(err::BAD_INTEGRITY, "PAC server checksum"))?;
    let kdc_mac = checksum(kdc, usage, &server_mac)?;
    let got = pac
        .kdc_checksum()
        .ok_or_else(|| proto(err::BAD_INTEGRITY, "PAC kdc checksum missing"))?;
    if got.len() < 4 + kdc_mac.len() || got[4..4 + kdc_mac.len()] != kdc_mac {
        return Err(proto(err::BAD_INTEGRITY, "PAC kdc checksum"));
    }
    Ok(())
}

/// Extract PAC bytes from EncTicketPart authorization-data.
pub fn pac_from_ticket_part(part: &EncTicketPart) -> Option<Vec<u8>> {
    let ad = part.authorization_data.as_ref()?;
    for el in ad {
        if el.ad_type == pa::AD_WIN2K_PAC {
            return Some(el.ad_data.to_vec());
        }
        if el.ad_type == pa::AD_IF_RELEVANT {
            if let Ok(inner) = decode::<krb5_types::AuthorizationData>(el.ad_data.as_ref()) {
                for i in inner {
                    if i.ad_type == pa::AD_WIN2K_PAC {
                        return Some(i.ad_data.to_vec());
                    }
                }
            }
        }
    }
    None
}

/// S4U2Self: PA-FOR-USER impersonation.
pub(crate) fn s4u2self_client(
    tgt_session: &ProtocolKey,
    padata: &Option<Vec<PaData>>,
) -> Result<Option<(PrincipalName, String)>, Error> {
    let Some(raw) = find_pa(padata, pa::FOR_USER) else {
        return Ok(None);
    };
    let pa: krb5_types::s4u::PaForUser = decode(raw)?;
    let realm = utf8(&pa.user_realm);
    let pkg = utf8(&pa.auth_package);
    let data = krb5_types::s4u::pa_for_user_cksum_data(&pa.user_name, realm, pkg);
    let usage = KeyUsage::new(ku::PA_FOR_USER)?;
    let mic = checksum(tgt_session, usage, &data)?;
    if mic.as_slice() != pa.cksum.checksum.as_ref() {
        return Err(proto(err::INAPP_CKSUM, "PA-FOR-USER"));
    }
    Ok(Some((pa.user_name, realm.to_owned())))
}

/// S4U2Proxy: evidence ticket in additional-tickets, cname from evidence.
pub(crate) fn s4u2proxy_client(
    store: &PrincipalStore,
    tgs: &TgsReq,
    tgt_cname: &PrincipalName,
) -> Result<Option<PrincipalName>, Error> {
    if !tgs
        .0
        .req_body
        .kdc_options
        .bit(krb5_types::flag_bit::CNAME_IN_ADDL_TKT)
    {
        return Ok(None);
    }
    let extra = tgs
        .0
        .req_body
        .additional_tickets
        .as_ref()
        .and_then(|v| v.first())
        .ok_or_else(|| proto(err::BADOPTION, "S4U2Proxy needs additional-ticket"))?;
    if extra.sname != *tgt_cname {
        return Err(proto(
            err::BADOPTION,
            "evidence sname must match TGT client",
        ));
    }
    let server = store
        .get_name(&extra.sname)
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "evidence server"))?;
    let skey = server
        .best_key()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "evidence key"))?;
    let usage = KeyUsage::new(ku::TICKET)?;
    let plain = decrypt(&skey.key, usage, extra.enc_part.cipher.as_ref())?;
    let part: EncTicketPart = decode(&plain)?;
    Ok(Some(part.cname))
}

/// U2U: encrypt ticket with additional-ticket session key.
pub(crate) fn u2u_session(
    store: &PrincipalStore,
    tgs: &TgsReq,
) -> Result<Option<(ProtocolKey, u32, EncryptionType)>, Error> {
    if !tgs
        .0
        .req_body
        .kdc_options
        .bit(krb5_types::flag_bit::ENC_TKT_IN_SKEY)
    {
        return Ok(None);
    }
    let extra = tgs
        .0
        .req_body
        .additional_tickets
        .as_ref()
        .and_then(|v| v.first())
        .ok_or_else(|| proto(err::BADOPTION, "U2U needs additional-ticket"))?;
    let krbtgt = store
        .krbtgt()
        .and_then(|p| p.best_key())
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let usage = KeyUsage::new(ku::TICKET)?;
    let plain = decrypt(&krbtgt.key, usage, extra.enc_part.cipher.as_ref())?;
    let part: EncTicketPart = decode(&plain)?;
    let etype = EncryptionType::from_iana(part.key.keytype)
        .or_else(|_| EncryptionType::known(part.key.keytype))?;
    let key = ProtocolKey::from_bytes(etype, part.key.keyvalue.as_ref())?;
    Ok(Some((key, 0, etype)))
}

fn utf8(s: &krb5_types::KerberosString) -> &str {
    std::str::from_utf8(s.as_bytes()).unwrap_or("")
}

/// Decrypt a service ticket for PAC extraction in tests.
pub fn decrypt_ticket_part(key: &ProtocolKey, ticket: &Ticket) -> Result<EncTicketPart, Error> {
    let usage = KeyUsage::new(ku::TICKET)?;
    let plain = decrypt(key, usage, ticket.enc_part.cipher.as_ref())?;
    decode(&plain).map_err(Error::from)
}
