//! PAC issuance and S4U2Self / S4U2Proxy / U2U.

use krb5_asn1::{decode, encode};
use krb5_crypto::{checksum, decrypt, EncryptionType, KeyUsage, ProtocolKey};
use krb5_types::{
    err, ku, pa, AuthorizationDataValue, EncTicketPart, PaData, PrincipalName, TgsReq, Ticket,
};

use crate::error::Error;
use crate::preauth::{find_pa, proto};
use crate::store::PrincipalStore;

/// AD-IF-RELEVANT wrapping AD-WIN2K-PAC `pac_bytes`.
///
/// # Errors
///
/// DER encode of the inner authorization-data.
pub fn wrap_win2k_pac(pac_bytes: &[u8]) -> Result<krb5_types::AuthorizationData, Error> {
    let inner = vec![AuthorizationDataValue {
        ad_type: pa::AD_WIN2K_PAC,
        ad_data: pac_bytes.to_vec().into(),
    }];
    let wrapped = encode(&inner)?;
    Ok(vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: wrapped.into(),
    }])
}

/// Sign a PAC: ticket (16), full (19), server (6), KDC (7). Key usage 17.
///
/// # Errors
///
/// Crypto or DER failures while building checksums.
pub fn sign_pac(
    cname: &PrincipalName,
    authtime: u32,
    server: &ProtocolKey,
    kdc: &ProtocolKey,
    enc_tkt_der: &[u8],
    identity: &krb5_types::pac::PacIdentity,
    logon_override: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let server_type = server.etype().checksum_type();
    let kdc_type = kdc.etype().checksum_type();
    let server_zeros = vec![0u8; server.etype().hmac_output_len()];
    let kdc_zeros = vec![0u8; kdc.etype().hmac_output_len()];
    let logon = match logon_override {
        Some(b) => b.to_vec(),
        None => krb5_types::pac::logon_info_buffer(
            &identity.sam,
            &identity.realm,
            &identity.domain_sid,
            identity.rid,
        ),
    };
    let mut pac = krb5_types::pac::Pac {
        version: 0,
        buffers: vec![
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_LOGON_INFO,
                data: logon,
            },
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_CLIENT_INFO,
                data: krb5_types::pac::client_info_buffer(authtime, &cname.components_joined()),
            },
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_UPN_DNS_INFO,
                data: krb5_types::pac::upn_dns_buffer(identity),
            },
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_ATTRIBUTES_INFO,
                data: krb5_types::pac::attributes_info_buffer(),
            },
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_REQUESTER_SID,
                data: krb5_types::pac::requester_sid_buffer(&identity.client_sid()),
            },
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_TICKET_CHECKSUM,
                data: krb5_types::pac::signature_buffer(kdc_type, &kdc_zeros),
            },
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_FULL_CHECKSUM,
                data: krb5_types::pac::signature_buffer(kdc_type, &kdc_zeros),
            },
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_SERVER_CHECKSUM,
                data: krb5_types::pac::signature_buffer(server_type, &server_zeros),
            },
            krb5_types::pac::PacBuffer {
                kind: krb5_types::pac::PAC_PRIVSVR_CHECKSUM,
                data: krb5_types::pac::signature_buffer(kdc_type, &kdc_zeros),
            },
        ],
    };
    let usage = KeyUsage::new(ku::KERB_NON_KERB_CKSUM_SALT)?;
    // 1. Ticket checksum over EncTicketPart with PAC ad-data = 0x00.
    let ticket_mac = checksum(kdc, usage, enc_tkt_der)?;
    set_sig(
        &mut pac,
        krb5_types::pac::PAC_TICKET_CHECKSUM,
        kdc_type,
        &ticket_mac,
    );
    // 2. Full PAC checksum over PAC with 6, 7, 19 zeroed (16 filled).
    let full_mac = checksum(kdc, usage, &pac.bytes_for_full_checksum())?;
    set_sig(
        &mut pac,
        krb5_types::pac::PAC_FULL_CHECKSUM,
        kdc_type,
        &full_mac,
    );
    // 3. Server checksum over PAC with 6, 7 zeroed (16 and 19 filled).
    let server_mac = checksum(server, usage, &pac.bytes_for_checksum())?;
    set_sig(
        &mut pac,
        krb5_types::pac::PAC_SERVER_CHECKSUM,
        server_type,
        &server_mac,
    );
    // 4. KDC checksum over the server MAC bytes.
    let kdc_mac = checksum(kdc, usage, &server_mac)?;
    set_sig(
        &mut pac,
        krb5_types::pac::PAC_PRIVSVR_CHECKSUM,
        kdc_type,
        &kdc_mac,
    );
    Ok(pac.to_bytes())
}

fn set_sig(pac: &mut krb5_types::pac::Pac, kind: u32, cksumtype: i32, mac: &[u8]) {
    for b in &mut pac.buffers {
        if b.kind == kind {
            b.data = krb5_types::pac::signature_buffer(cksumtype, mac);
        }
    }
}

/// Verify PAC server checksum with `server` and KDC checksum with `kdc`.
///
/// # Errors
///
/// PAC parse or integrity failure.
pub fn verify_pac(pac_bytes: &[u8], server: &ProtocolKey, kdc: &ProtocolKey) -> Result<(), Error> {
    verify_pac_signatures(pac_bytes, server, Some(kdc), None)
}

/// Verify PAC signatures. Server is always checked. KDC / ticket / full
/// require `kdc`. Ticket checksum requires `enc_tkt_der` (PAC ad-data = 0x00).
///
/// # Errors
///
/// PAC parse or integrity failure.
pub fn verify_pac_signatures(
    pac_bytes: &[u8],
    server: &ProtocolKey,
    kdc: Option<&ProtocolKey>,
    enc_tkt_der: Option<&[u8]>,
) -> Result<(), Error> {
    let pac = krb5_types::pac::Pac::parse(pac_bytes)
        .map_err(|e| proto(err::BAD_INTEGRITY, &format!("PAC parse: {e}")))?;
    let usage = KeyUsage::new(ku::KERB_NON_KERB_CKSUM_SALT)?;
    let server_mac = checksum(server, usage, &pac.bytes_for_checksum())?;
    krb5_types::pac::verify_server_checksum(&pac, &server_mac)
        .map_err(|_| proto(err::BAD_INTEGRITY, "PAC server checksum"))?;
    let Some(kdc) = kdc else {
        return Ok(());
    };
    let kdc_mac = checksum(kdc, usage, &server_mac)?;
    krb5_types::pac::verify_sig_buf(pac.kdc_checksum(), &kdc_mac)
        .map_err(|_| proto(err::BAD_INTEGRITY, "PAC kdc checksum"))?;
    if let Some(der) = enc_tkt_der {
        let ticket_mac = checksum(kdc, usage, der)?;
        krb5_types::pac::verify_sig_buf(pac.ticket_checksum(), &ticket_mac)
            .map_err(|_| proto(err::BAD_INTEGRITY, "PAC ticket checksum"))?;
        let full_mac = checksum(kdc, usage, &pac.bytes_for_full_checksum())?;
        krb5_types::pac::verify_sig_buf(pac.full_checksum(), &full_mac)
            .map_err(|_| proto(err::BAD_INTEGRITY, "PAC full checksum"))?;
    }
    Ok(())
}

/// DER of `part` with PAC `ad-data` replaced by a single zero byte.
///
/// # Errors
///
/// DER encode.
pub fn ticket_checksum_der(part: &EncTicketPart) -> Result<Vec<u8>, Error> {
    let mut clone = part.clone();
    if let Some(ad) = clone.authorization_data.take() {
        clone.authorization_data = Some(krb5_types::pac::authorization_with_zeroed_pac(&ad));
    }
    encode(&clone).map_err(Error::from)
}

/// Type-16 input over the decrypted EncTicketPart bytes, PAC ad-data = 0x00.
pub(crate) fn ticket_checksum_input(plain: &[u8], part: &EncTicketPart) -> Result<Vec<u8>, Error> {
    if let Some(pac) = pac_from_ticket_part(part) {
        if let Some(z) = krb5_types::pac::zero_pac_ad_data(plain, &pac) {
            return Ok(z);
        }
    }
    ticket_checksum_der(part)
}

/// If the TGT carries a PAC, verify it with `ticket_key` (the key that
/// opened the ticket) and return LOGON_INFO. Missing PAC is `Ok(None)`
/// so MIT TGTs still work. Foreign TGTs: server checksum plus type-16
/// over the original EncTicketPart bytes (KDC/19 use the issuing krbtgt).
pub(crate) fn presented_tgt_logon(
    part: &EncTicketPart,
    ticket_key: &ProtocolKey,
    enc_tkt_plain: &[u8],
    realm: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let Some(pac) = pac_from_ticket_part(part) else {
        return Ok(None);
    };
    verify_pac_signatures(&pac, ticket_key, None, None)?;
    let parsed = krb5_types::pac::Pac::parse(&pac)
        .map_err(|e| proto(err::BAD_INTEGRITY, &format!("TGT PAC: {e}")))?;
    let der = ticket_checksum_input(enc_tkt_plain, part)?;
    if utf8(&part.crealm) == realm {
        if verify_pac_signatures(&pac, ticket_key, Some(ticket_key), Some(&der)).is_err() {
            let re = ticket_checksum_der(part)?;
            verify_pac_signatures(&pac, ticket_key, Some(ticket_key), Some(&re))?;
        }
    } else if parsed.ticket_checksum().is_some()
        && checksum_ticket_sig(&parsed, ticket_key, &der).is_err()
    {
        let re = ticket_checksum_der(part)?;
        checksum_ticket_sig(&parsed, ticket_key, &re)?;
    }
    let logon = parsed
        .buffer(krb5_types::pac::PAC_LOGON_INFO)
        .ok_or_else(|| proto(err::BAD_INTEGRITY, "TGT PAC logon"))?
        .to_vec();
    Ok(Some(logon))
}

fn checksum_ticket_sig(
    pac: &krb5_types::pac::Pac,
    key: &ProtocolKey,
    der: &[u8],
) -> Result<(), Error> {
    let usage = KeyUsage::new(ku::KERB_NON_KERB_CKSUM_SALT)?;
    let mac = checksum(key, usage, der)?;
    krb5_types::pac::verify_sig_buf(pac.ticket_checksum(), &mac)
        .map_err(|_| proto(err::BAD_INTEGRITY, "PAC ticket checksum"))
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
    padata: Option<&[PaData]>,
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
    let hmac_md5 =
        krb5_crypto::hmac_md5_arcfour_checksum(tgt_session.as_bytes(), ku::PA_FOR_USER, &data)?;
    let got = pa.cksum.checksum.as_ref();
    if got != mic.as_slice() && got != hmac_md5.as_slice() {
        return Err(proto(err::INAPP_CKSUM, "PA-FOR-USER"));
    }
    Ok(Some((pa.user_name, realm.to_owned())))
}

/// S4U2Proxy: evidence ticket in additional-tickets, cname from evidence.
///
/// MS-SFU: the evidence ticket MUST be forwardable. PA-PAC-OPTIONS (167),
/// when present, is decoded; a truncated or non-DER value is `BADOPTION`.
/// The RBCD bit is read so the field is not ignored.
pub(crate) fn s4u2proxy_client(
    store: &PrincipalStore,
    tgs: &TgsReq,
    tgt_cname: &PrincipalName,
    padata: Option<&[PaData]>,
) -> Result<Option<(PrincipalName, Vec<u8>)>, Error> {
    if !tgs
        .0
        .req_body
        .kdc_options
        .bit(krb5_types::flag_bit::CNAME_IN_ADDL_TKT)
    {
        return Ok(None);
    }
    let mut rbcd = false;
    if let Some(raw) = find_pa(padata, pa::PAC_OPTIONS) {
        let opts: krb5_types::s4u::PaPacOptions =
            decode(raw).map_err(|_| proto(err::BADOPTION, "PA-PAC-OPTIONS"))?;
        rbcd = opts.resource_based_constrained_delegation();
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
    if !part.flags.forwardable() {
        return Err(proto(
            err::BADOPTION,
            "S4U2Proxy evidence ticket is not forwardable",
        ));
    }
    let dest = tgs
        .0
        .req_body
        .sname
        .as_ref()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "S4U2Proxy sname"))?;
    if rbcd {
        let target = store
            .get_name(dest)
            .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "S4U2Proxy target"))?;
        let from = extra.sname.components_joined();
        if !target.s4u_allowed_from.iter().any(|n| n == &from) {
            return Err(proto(err::BADOPTION, "RBCD not allowed"));
        }
    } else {
        let want = dest.components_joined();
        if !server.s4u_allowed_to.iter().any(|n| n == &want) {
            return Err(proto(err::BADOPTION, "constrained delegation not allowed"));
        }
    }
    let pac = pac_from_ticket_part(&part)
        .ok_or_else(|| proto(err::BAD_INTEGRITY, "S4U2Proxy evidence PAC"))?;
    let krbtgt = store
        .krbtgt()
        .and_then(|p| p.best_key())
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, "no krbtgt"))?;
    let der = ticket_checksum_input(&plain, &part)?;
    verify_pac_signatures(&pac, &skey.key, Some(&krbtgt.key), Some(&der))?;
    let parsed = krb5_types::pac::Pac::parse(&pac)
        .map_err(|e| proto(err::BAD_INTEGRITY, &format!("evidence PAC: {e}")))?;
    let logon = parsed
        .buffer(krb5_types::pac::PAC_LOGON_INFO)
        .ok_or_else(|| proto(err::BAD_INTEGRITY, "evidence PAC logon"))?
        .to_vec();
    Ok(Some((part.cname, logon)))
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
///
/// # Errors
///
/// Decrypt or DER failures.
pub fn decrypt_ticket_part(key: &ProtocolKey, ticket: &Ticket) -> Result<EncTicketPart, Error> {
    let usage = KeyUsage::new(ku::TICKET)?;
    let plain = decrypt(key, usage, ticket.enc_part.cipher.as_ref())?;
    decode(&plain).map_err(Error::from)
}
