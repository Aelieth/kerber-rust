//! PAC issuance and S4U2Self / S4U2Proxy / U2U.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, checksum_output_size, cksumtype_is_keyed,
    decrypt, verify_checksum_keyed, verify_checksum_type,
};
use krb5_types::pac::{
    PAC_FULL_CHECKSUM, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, PAC_TICKET_CHECKSUM,
};
use krb5_types::{
    AuthorizationDataValue, EncTicketPart, PaData, PrincipalName, TgsReq, Ticket, err, ku, pa,
};

use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::preauth::{find_pa, proto, proto_d};
use crate::status;

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

/// The ticket a PAC is signed into: its service key, the privsvr (KDC) key,
/// the EncTicketPart DER with the PAC ad-data zeroed, and whether it is a
/// service ticket (`k5_pac_should_have_ticket_signature`).
#[derive(Clone, Copy)]
pub struct PacTicket<'a> {
    /// Key the ticket is encrypted with; signs the server checksum.
    pub server: &'a ProtocolKey,
    /// Local TGT key; signs privsvr, full and ticket checksums.
    pub kdc: &'a ProtocolKey,
    /// EncTicketPart DER with the PAC ad-data replaced by one zero byte.
    pub enc_tkt_der: &'a [u8],
    /// Service tickets carry the ticket and full checksums; TGTs do not.
    pub is_service_tkt: bool,
}

/// Sign a PAC: ticket (16), full (19), server (6), KDC (7). Key usage 17.
///
/// # Errors
///
/// Crypto or DER failures while building checksums.
pub fn sign_pac(
    cname: &PrincipalName,
    authtime: u32,
    ticket: &PacTicket<'_>,
    identity: &krb5_types::pac::PacIdentity,
    logon_override: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let PacTicket {
        server,
        kdc,
        enc_tkt_der,
        is_service_tkt,
    } = *ticket;
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
    let mut pac = krb5_types::pac::Pac::built(
        0,
        vec![
            krb5_types::pac::PacBuffer::new(krb5_types::pac::PAC_LOGON_INFO, logon),
            krb5_types::pac::PacBuffer::new(
                krb5_types::pac::PAC_CLIENT_INFO,
                krb5_types::pac::client_info_buffer(authtime, &cname.components_joined()),
            ),
            krb5_types::pac::PacBuffer::new(
                krb5_types::pac::PAC_UPN_DNS_INFO,
                krb5_types::pac::upn_dns_buffer(identity),
            ),
            krb5_types::pac::PacBuffer::new(
                krb5_types::pac::PAC_ATTRIBUTES_INFO,
                krb5_types::pac::attributes_info_buffer(),
            ),
            krb5_types::pac::PacBuffer::new(
                krb5_types::pac::PAC_REQUESTER_SID,
                krb5_types::pac::requester_sid_buffer(&identity.client_sid()),
            ),
        ],
    );
    if is_service_tkt {
        pac.buffers.push(krb5_types::pac::PacBuffer::new(
            krb5_types::pac::PAC_TICKET_CHECKSUM,
            krb5_types::pac::signature_buffer(kdc_type, &kdc_zeros),
        ));
        pac.buffers.push(krb5_types::pac::PacBuffer::new(
            krb5_types::pac::PAC_FULL_CHECKSUM,
            krb5_types::pac::signature_buffer(kdc_type, &kdc_zeros),
        ));
    }
    pac.buffers.push(krb5_types::pac::PacBuffer::new(
        krb5_types::pac::PAC_SERVER_CHECKSUM,
        krb5_types::pac::signature_buffer(server_type, &server_zeros),
    ));
    pac.buffers.push(krb5_types::pac::PacBuffer::new(
        krb5_types::pac::PAC_PRIVSVR_CHECKSUM,
        krb5_types::pac::signature_buffer(kdc_type, &kdc_zeros),
    ));
    let usage = KeyUsage::new(ku::KERB_NON_KERB_CKSUM_SALT)?;
    if is_service_tkt {
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
    }
    // 3. Server checksum over PAC with 6, 7 zeroed (16 and 19 filled).
    let server_mac = checksum(server, usage, &pac.bytes_for_checksum())?;
    set_sig(
        &mut pac,
        krb5_types::pac::PAC_SERVER_CHECKSUM,
        server_type,
        &server_mac,
    );
    let server_buf = pac
        .server_checksum()
        .map_err(|e| map_pac_err(&e))?
        .ok_or_else(|| proto(err::GENERIC, status::HEADER_PAC))?;
    if server_buf.len() < 4 {
        return Err(proto(err::GENERIC, status::HEADER_PAC));
    }
    let kdc_mac = checksum(kdc, usage, &server_buf[4..])?;
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

/// MIT `k5_pac_should_have_ticket_signature`: ticket and full checksums
/// belong to service tickets, never to TGTs or `kadmin/changepw` tickets.
#[must_use]
pub fn should_have_ticket_signature(sname: &PrincipalName) -> bool {
    let changepw = sname.name_string.len() == 2
        && sname.name_string[0].as_bytes() == b"kadmin"
        && sname.name_string[1].as_bytes() == b"changepw";
    !(sname.is_krbtgt() || changepw)
}

/// Verify PAC server checksum with `server` and KDC checksum with `kdc`;
/// `is_service_tkt` also requires the full checksum.
///
/// # Errors
///
/// PAC parse or integrity failure.
pub fn verify_pac(
    pac_bytes: &[u8],
    server: &ProtocolKey,
    kdc: &ProtocolKey,
    is_service_tkt: bool,
) -> Result<(), Error> {
    verify_pac_signatures(pac_bytes, server, Some(kdc), None, is_service_tkt)
}

/// MIT `krb5_kdc_verify_ticket`: the server checksum always; with `kdc` the
/// privsvr checksum, and for a service ticket the full checksum and — given
/// `enc_tkt_der` (PAC ad-data = 0x00) — the ticket checksum.
///
/// # Errors
///
/// PAC parse or integrity failure.
pub fn verify_pac_signatures(
    pac_bytes: &[u8],
    server: &ProtocolKey,
    kdc: Option<&ProtocolKey>,
    enc_tkt_der: Option<&[u8]>,
    is_service_tkt: bool,
) -> Result<(), Error> {
    let pac = krb5_types::pac::Pac::parse(pac_bytes).map_err(|e| {
        proto_d(
            err::BAD_INTEGRITY,
            status::HEADER_PAC,
            format!("PAC parse: {e}"),
        )
    })?;
    if let (Some(kdc), Some(der), true) = (kdc, enc_tkt_der, is_service_tkt) {
        let buf = pac.ticket_checksum().map_err(|e| map_pac_err(&e))?;
        verify_pac_sig(kdc, der, buf, PAC_TICKET_CHECKSUM)?;
    }
    verify_pac_checksums(&pac, server, kdc, is_service_tkt)
}

fn map_pac_err(e: &krb5_types::pac::PacError) -> Error {
    match e {
        krb5_types::pac::PacError::MissingBuffer | krb5_types::pac::PacError::Truncated => {
            proto(err::GENERIC, status::HEADER_PAC)
        }
        krb5_types::pac::PacError::Integrity => proto(err::MODIFIED, status::HEADER_PAC),
        krb5_types::pac::PacError::Malformed => proto(err::GENERIC, status::HEADER_PAC),
    }
}

fn verify_pac_checksums(
    pac: &krb5_types::pac::Pac,
    server: &ProtocolKey,
    kdc: Option<&ProtocolKey>,
    expect_full: bool,
) -> Result<(), Error> {
    let mut copy = pac
        .received_zeroed(&[PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM])
        .map_err(|e| map_pac_err(&e))?;
    let server_sig = pac.server_checksum().map_err(|e| map_pac_err(&e))?;
    let mut last = verify_pac_sig(server, &copy, server_sig, PAC_SERVER_CHECKSUM).map(|_| ());
    let Some(kdc) = kdc else {
        return last;
    };
    if expect_full {
        copy = pac
            .received_zeroed(&[PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM, PAC_FULL_CHECKSUM])
            .map_err(|e| map_pac_err(&e))?;
        let full_sig = pac.full_checksum().map_err(|e| map_pac_err(&e))?;
        last = verify_pac_sig(kdc, &copy, full_sig, PAC_FULL_CHECKSUM).map(|_| ());
        last?;
    }
    let server_buf = pac
        .server_checksum()
        .map_err(|e| map_pac_err(&e))?
        .ok_or_else(|| proto(err::GENERIC, status::HEADER_PAC))?;
    if server_buf.len() < 4 {
        return Err(proto(err::GENERIC, status::HEADER_PAC));
    }
    let kdc_sig = pac.kdc_checksum().map_err(|e| map_pac_err(&e))?;
    last = verify_pac_sig(kdc, &server_buf[4..], kdc_sig, PAC_PRIVSVR_CHECKSUM).map(|_| ());
    last
}

/// MIT `pac.c:478-514` `verify_checksum`: SignatureType, SHA-1-on-server, keyed, length.
fn verify_pac_sig<'a>(
    key: &ProtocolKey,
    data: &[u8],
    buf: Option<&'a [u8]>,
    buffer_type: u32,
) -> Result<&'a [u8], Error> {
    let Some(buf) = buf else {
        return Err(proto(err::GENERIC, status::HEADER_PAC));
    };
    if buf.len() < 4 {
        return Err(proto(err::GENERIC, status::HEADER_PAC));
    }
    let cksumtype = i32::from_le_bytes(
        buf[0..4]
            .try_into()
            .map_err(|_| proto(err::GENERIC, status::HEADER_PAC))?,
    );
    if buffer_type == PAC_SERVER_CHECKSUM && cksumtype == 14 {
        return Err(proto(err::SUMTYPE_NOSUPP, status::HEADER_PAC));
    }
    if !cksumtype_is_keyed(cksumtype) {
        return Err(proto(err::GENERIC, status::HEADER_PAC));
    }
    let Some(want) = checksum_output_size(cksumtype) else {
        return Err(proto(err::GENERIC, status::HEADER_PAC));
    };
    if want > buf.len() - 4 {
        return Err(proto(err::GENERIC, status::HEADER_PAC));
    }
    let mac = &buf[4..4 + want];
    let usage = KeyUsage::new(ku::KERB_NON_KERB_CKSUM_SALT)?;
    verify_checksum_type(key, usage, data, cksumtype, mac).map_err(|e| match e {
        krb5_crypto::Error::Integrity => proto(err::MODIFIED, status::HEADER_PAC),
        _ => proto(err::GENERIC, status::HEADER_PAC),
    })?;
    Ok(mac)
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
    if let Some(pac) = pac_from_ticket_part(part)
        && let Some(z) = krb5_types::pac::zero_pac_ad_data(plain, &pac)
    {
        return Ok(z);
    }
    ticket_checksum_der(part)
}

/// MIT `get_verified_pac` for a TGS principal: only the server signature is
/// checked with the key that opened the ticket (`kdc_util.c:597-602`).
/// LOGON_INFO is returned when the PAC carries one; a missing PAC or a
/// minimal PAC without it (MIT's db2 backend issues those) is `Ok(None)`.
pub(crate) fn presented_tgt_logon(
    part: &EncTicketPart,
    ticket_key: &ProtocolKey,
) -> Result<Option<Vec<u8>>, Error> {
    let Some(pac) = pac_from_ticket_part(part) else {
        return Ok(None);
    };
    verify_pac_signatures(&pac, ticket_key, None, None, false)?;
    let parsed = krb5_types::pac::Pac::parse(&pac).map_err(|e| {
        proto_d(
            err::BAD_INTEGRITY,
            status::HEADER_PAC,
            format!("TGT PAC: {e}"),
        )
    })?;
    Ok(parsed
        .unique_buffer(krb5_types::pac::PAC_LOGON_INFO)
        .map_err(|e| map_pac_err(&e))?
        .map(<[u8]>::to_vec))
}

/// Extract PAC bytes from EncTicketPart authorization-data.
pub fn pac_from_ticket_part(part: &EncTicketPart) -> Option<Vec<u8>> {
    let ad = part.authorization_data.as_ref()?;
    for el in ad {
        if el.ad_type == pa::AD_WIN2K_PAC {
            return Some(el.ad_data.to_vec());
        }
        if el.ad_type == pa::AD_IF_RELEVANT
            && let Ok(inner) = decode::<krb5_types::AuthorizationData>(el.ad_data.as_ref())
        {
            for i in inner {
                if i.ad_type == pa::AD_WIN2K_PAC {
                    return Some(i.ad_data.to_vec());
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
    verify_checksum_keyed(
        tgt_session,
        usage,
        &data,
        pa.cksum.cksumtype,
        pa.cksum.checksum.as_ref(),
    )
    .map_err(|e| match e {
        krb5_crypto::Error::InappChecksum => {
            proto(err::INAPP_CKSUM, status::INVALID_S4U2SELF_CHECKSUM)
        }
        krb5_crypto::Error::Integrity => proto(err::MODIFIED, status::INVALID_S4U2SELF_CHECKSUM),
        _ => proto(err::GENERIC, status::INVALID_S4U2SELF_CHECKSUM),
    })?;
    Ok(Some((pa.user_name, realm.to_owned())))
}

/// S4U2Proxy: evidence ticket in additional-tickets, cname from evidence.
///
/// MS-SFU: the evidence ticket MUST be forwardable. PA-PAC-OPTIONS (167),
/// when present, is decoded; a truncated or non-DER value is `BADOPTION`.
/// The RBCD bit is read so the field is not ignored.
pub(crate) fn s4u2proxy_client(
    store: &dyn PrincipalRead,
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
            decode(raw).map_err(|_| proto(err::BADOPTION, status::INVALID_S4U2PROXY_OPTIONS))?;
        rbcd = opts.resource_based_constrained_delegation();
    }
    let extra = tgs
        .0
        .req_body
        .additional_tickets
        .as_ref()
        .and_then(|v| v.first())
        .ok_or_else(|| proto(err::BADOPTION, status::NO_2ND_TKT))?;
    if extra.sname != *tgt_cname {
        return Err(proto(err::BADOPTION, status::EVIDENCE_TICKET_MISMATCH));
    }
    let server = store
        .fetch_name(&extra.sname)?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::SECOND_TKT_SERVER))?;
    let skey = server
        .best_key()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::SECOND_TKT_SERVER))?;
    let usage = KeyUsage::new(ku::TICKET)?;
    let plain = decrypt(&skey.key, usage, extra.enc_part.cipher.as_ref())?;
    let part: EncTicketPart = decode(&plain)?;
    if !part.flags.forwardable() {
        return Err(proto(err::BADOPTION, status::EVIDENCE_TKT_NOT_FORWARDABLE));
    }
    let dest = tgs
        .0
        .req_body
        .sname
        .as_ref()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::EVIDENCE_TICKET_MISMATCH))?;
    if rbcd {
        let target = store.fetch_name(dest)?.ok_or_else(|| {
            proto(
                err::S_PRINCIPAL_UNKNOWN,
                status::UNSUPPORTED_S4U2PROXY_REQUEST,
            )
        })?;
        let from = extra.sname.components_joined();
        if !target.s4u_allowed_from.iter().any(|n| n == &from) {
            return Err(proto(err::BADOPTION, status::INVALID_S4U2PROXY_OPTIONS));
        }
    } else {
        let want = dest.components_joined();
        if !server.s4u_allowed_to.iter().any(|n| n == &want) {
            return Err(proto(err::BADOPTION, status::NOT_ALLOWED_TO_DELEGATE));
        }
    }
    let pac = pac_from_ticket_part(&part)
        .ok_or_else(|| proto(err::BAD_INTEGRITY, status::S4U2PROXY_NO_STKT_PAC))?;
    let krbtgt_p = store
        .fetch_krbtgt()?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::GET_LOCAL_TGT))?;
    let krbtgt = krbtgt_p
        .first_current_key()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::GET_LOCAL_TGT))?;
    let der = ticket_checksum_input(&plain, &part)?;
    let service = should_have_ticket_signature(&extra.sname);
    let mut verified =
        verify_pac_signatures(&pac, &skey.key, Some(&krbtgt.key), Some(&der), service);
    let mut kvno = krbtgt.kvno.saturating_sub(1);
    let mut tries = 2;
    while let Err(Error::Protocol { code, .. }) = &verified
        && *code == err::MODIFIED
        && tries > 0
        && kvno > 0
    {
        let Some(old) = krbtgt_p.first_key_at_kvno(kvno) else {
            break;
        };
        verified = verify_pac_signatures(&pac, &skey.key, Some(&old.key), Some(&der), service);
        tries -= 1;
        kvno -= 1;
    }
    verified?;
    let parsed = krb5_types::pac::Pac::parse(&pac).map_err(|e| {
        proto_d(
            err::BAD_INTEGRITY,
            status::SECOND_TKT_PAC,
            format!("evidence PAC: {e}"),
        )
    })?;
    let logon = parsed
        .buffer(krb5_types::pac::PAC_LOGON_INFO)
        .ok_or_else(|| proto(err::BAD_INTEGRITY, status::SECOND_TKT_PAC))?
        .to_vec();
    Ok(Some((part.cname, logon)))
}

/// U2U: encrypt ticket with additional-ticket session key.
pub(crate) fn u2u_session(
    store: &dyn PrincipalRead,
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
        .ok_or_else(|| proto(err::BADOPTION, status::NO_2ND_TKT))?;
    let krbtgt_p = store
        .fetch_krbtgt()?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::GET_LOCAL_TGT))?;
    let krbtgt = krbtgt_p
        .best_key()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::GET_LOCAL_TGT))?;
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
