//! PAC issuance and S4U2Self / S4U2Proxy / U2U.

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, checksum_output_size, cksumtype_is_keyed,
    decrypt, derive_prfplus_enctype, verify_checksum_keyed, verify_checksum_type,
};
use krb5_types::pac::{
    PAC_CLIENT_INFO, PAC_FULL_CHECKSUM, PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM,
    PAC_TICKET_CHECKSUM, parse_client_info,
};
use krb5_types::{
    AuthorizationDataValue, EncTicketPart, EncryptionKey, PaData, PrincipalName, Ticket, err, ku,
    pa,
};

use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::preauth::{find_pa, proto, proto_d};
use crate::status;
use crate::store::Principal;

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

fn is_pac_signature(kind: u32) -> bool {
    matches!(
        kind,
        PAC_SERVER_CHECKSUM | PAC_PRIVSVR_CHECKSUM | PAC_TICKET_CHECKSUM | PAC_FULL_CHECKSUM
    )
}

/// Sign a PAC: ticket (16), full (19), server (6), KDC (7). Key usage 17.
///
/// A regular TGS (`handle_pac`) copies the subject's non-checksum buffers and
/// re-signs; `subject_pac` `None` mints a new AS/S4U PAC.
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
    sign_reply_pac(cname, authtime, ticket, identity, logon_override, None)
}

/// # Errors
///
/// Crypto or DER failures while building checksums.
pub fn sign_reply_pac(
    cname: &PrincipalName,
    authtime: u32,
    ticket: &PacTicket<'_>,
    identity: &krb5_types::pac::PacIdentity,
    logon_override: Option<&[u8]>,
    subject_pac: Option<&[u8]>,
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
    let mut pac = if let Some(raw) = subject_pac {
        let parsed = krb5_types::pac::Pac::parse(raw).map_err(|e| map_pac_err(&e))?;
        let mut buffers: Vec<krb5_types::pac::PacBuffer> = parsed
            .buffers
            .into_iter()
            .filter(|b| !is_pac_signature(b.kind))
            .map(|b| krb5_types::pac::PacBuffer::new(b.kind, b.data))
            .collect();
        if let Some(logon) = logon_override {
            match buffers.iter_mut().find(|b| b.kind == PAC_LOGON_INFO) {
                Some(b) => b.data = logon.to_vec(),
                None => {
                    buffers.insert(
                        0,
                        krb5_types::pac::PacBuffer::new(PAC_LOGON_INFO, logon.to_vec()),
                    );
                }
            }
        }
        krb5_types::pac::Pac::built(0, buffers)
    } else {
        let logon = match logon_override {
            Some(b) => b.to_vec(),
            None => krb5_types::pac::logon_info_buffer(
                &identity.sam,
                &identity.realm,
                &identity.domain_sid,
                identity.rid,
            ),
        };
        krb5_types::pac::Pac::built(
            0,
            vec![
                krb5_types::pac::PacBuffer::new(PAC_LOGON_INFO, logon),
                krb5_types::pac::PacBuffer::new(
                    PAC_CLIENT_INFO,
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
        )
    };
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

/// MIT `get_verified_pac` (`kdc_util.c:589-630`): TGS header → server
/// signature only; service header → privsvr + kvno−1/−2 retry.
pub(crate) fn get_verified_pac(
    part: &EncTicketPart,
    ticket_key: &ProtocolKey,
    header_server: &Principal,
    local_tgt: Option<&Principal>,
) -> Result<Option<Vec<u8>>, Error> {
    let Some(pac) = pac_from_ticket_part(part) else {
        return Ok(None);
    };
    if header_server.name.is_krbtgt() {
        verify_pac_signatures(&pac, ticket_key, None, None, false)?;
        return Ok(Some(pac));
    }
    let Some(tgt) = local_tgt else {
        return Err(proto(err::GENERIC, status::HEADER_PAC));
    };
    let Some(cur) = tgt.first_current_key() else {
        return Err(proto(err::GENERIC, status::HEADER_PAC));
    };
    let der = ticket_checksum_der(part)?;
    let first = try_verify_pac(&pac, ticket_key, header_server, &cur.key, &der);
    if !pac_verify_retryable(&first) {
        first?;
        return Ok(Some(pac));
    }
    let mut kvno = cur.kvno.saturating_sub(1);
    let mut tries = 2u32;
    while tries > 0 && kvno > 0 {
        let Some(old) = tgt
            .first_key_at_kvno(kvno)
            .or_else(|| tgt.key_history.iter().find(|k| k.kvno == kvno))
        else {
            return Err(proto(err::MODIFIED, status::HEADER_PAC));
        };
        if try_verify_pac(&pac, ticket_key, header_server, &old.key, &der).is_ok() {
            return Ok(Some(pac));
        }
        kvno = kvno.saturating_sub(1);
        tries -= 1;
    }
    Err(proto(err::MODIFIED, status::HEADER_PAC))
}

fn pac_verify_retryable(r: &Result<(), Error>) -> bool {
    matches!(r, Err(Error::Protocol { code, .. }) if *code == err::MODIFIED)
}

fn try_verify_pac(
    pac: &[u8],
    server_key: &ProtocolKey,
    header_server: &Principal,
    tgt_key: &ProtocolKey,
    enc_der: &[u8],
) -> Result<(), Error> {
    let privsvr = pac_privsvr_key(header_server, tgt_key)?;
    let is_svc = should_have_ticket_signature(&header_server.name);
    verify_pac_signatures(pac, server_key, Some(&privsvr), Some(enc_der), is_svc)
}

pub(crate) fn pac_privsvr_key(
    server: &Principal,
    tgt_key: &ProtocolKey,
) -> Result<ProtocolKey, Error> {
    let Some((_, val)) = server
        .string_attrs
        .iter()
        .find(|(k, _)| k == "pac_privsvr_enctype")
    else {
        return Ok(tgt_key.clone());
    };
    let et =
        EncryptionType::from_mit_name(val).map_err(|_| proto(err::GENERIC, status::HEADER_PAC))?;
    if tgt_key.etype() == et {
        return Ok(tgt_key.clone());
    }
    derive_prfplus_enctype(tgt_key, b"pac_privsvr", et)
        .map_err(|_| proto(err::GENERIC, status::HEADER_PAC))
}

/// MIT `check_normal_tgs_pac` (`tgs_policy.c:601-624`). Missing PAC is ok.
pub(crate) fn check_normal_tgs_pac(
    enc_tkt: &EncTicketPart,
    pac: Option<&[u8]>,
    server: &Principal,
    is_crossrealm: bool,
) -> Result<(), Error> {
    let Some(raw) = pac else {
        return Ok(());
    };
    let parsed = krb5_types::pac::Pac::parse(raw).map_err(|e| map_pac_err(&e))?;
    if pac_client_matches(&parsed, enc_tkt) {
        return Ok(());
    }
    if is_crossrealm
        && server.name.is_cross_tgs_principal(&server.realm)
        && verify_deleg_pac(&parsed, enc_tkt, None)
    {
        return Ok(());
    }
    Err(proto(err::BADOPTION, status::HEADER_PAC))
}

fn pac_client_matches(pac: &krb5_types::pac::Pac, enc_tkt: &EncTicketPart) -> bool {
    pac_client_info_eq(
        pac,
        enc_tkt.authtime.unix_seconds(),
        &enc_tkt.cname.components_joined(),
        None,
    )
}

/// `k5_pac_validate_client`: `with_realm` compares `name@REALM`.
pub(crate) fn pac_client_info_eq(
    pac: &krb5_types::pac::Pac,
    authtime: u32,
    name: &str,
    realm: Option<&str>,
) -> bool {
    let Ok(Some(buf)) = pac.unique_buffer(PAC_CLIENT_INFO) else {
        return false;
    };
    let Some((got_time, got_name)) = parse_client_info(buf) else {
        return false;
    };
    let want = match realm {
        Some(r) => format!("{name}@{r}"),
        None => name.to_owned(),
    };
    got_time == authtime && got_name == want
}

/// MS-PAC 4.1.2.2 SID filtering for a cross-realm subject: a trusted realm may
/// assert only its own SIDs, never SIDs from the local domain. Returns the
/// subject's `LOGON_INFO` with every local-domain SID removed from the extra
/// SIDs and resource groups (the foreign realm's own SIDs and well-known SIDs
/// such as `S-1-18-1` are kept); `Err(POLICY)` when the base identity itself
/// claims the local domain, since nothing foreign is left to keep.
///
/// # Errors
///
/// [`Error::Proto`] `POLICY` when the `LOGON_INFO` is undecodable or its base
/// domain is the local domain.
pub(crate) fn filter_cross_realm_logon(
    logon: &[u8],
    local_domain: &krb5_types::pac::RpcSid,
) -> Result<Vec<u8>, Error> {
    let mut kvi = krb5_types::pac::parse_kerb_validation_info(logon).map_err(|e| {
        proto_d(
            err::POLICY,
            status::INVALID_LINEAGE,
            format!("cross-realm PAC: {e}"),
        )
    })?;
    if kvi.logon_domain_id.is_in_domain(local_domain) {
        return Err(proto(err::POLICY, status::INVALID_LINEAGE));
    }
    kvi.extra_sids.retain(|e| !e.sid.is_in_domain(local_domain));
    if kvi
        .resource_group_domain_sid
        .as_ref()
        .is_some_and(|s| s.is_in_domain(local_domain))
    {
        kvi.resource_group_domain_sid = None;
        kvi.resource_groups.clear();
    }
    Ok(kvi.to_ndr())
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

/// Result of `kdc_process_s4u2self_req` (`kdc_util.c:1556-1621`).
pub(crate) struct S4u2Self {
    pub user: PrincipalName,
    pub realm: String,
    pub local: Option<Principal>,
    pub x509: Option<krb5_types::s4u::PaS4uX509User>,
}

/// S4U2Self: 130 wins over 129 (`kdc_util.c:1570-1586`).
pub(crate) fn process_s4u2self_req(
    store: &dyn PrincipalRead,
    tgt_session: &ProtocolKey,
    tgs_subkey: Option<&EncryptionKey>,
    padata: Option<&[PaData]>,
    nonce: u32,
) -> Result<Option<S4u2Self>, Error> {
    if let Some(raw) = find_pa(padata, pa::FOR_X509_USER) {
        let x509 = process_s4u_x509_user(raw, tgt_session, tgs_subkey, nonce)?;
        let id = x509.user_id.clone();
        return Ok(Some(s4u_from_userid(store, &id, Some(x509))?));
    }
    if let Some(raw) = find_pa(padata, pa::FOR_USER) {
        let pa: krb5_types::s4u::PaForUser =
            decode(raw).map_err(|_| proto(err::GENERIC, status::DECODE_PA_FOR_USER))?;
        verify_for_user_checksum(tgt_session, &pa)?;
        let id = krb5_types::s4u::S4uUserId {
            nonce: 0,
            user: Some(pa.user_name),
            realm: pa.user_realm,
            subject_cert: None,
            options: None,
        };
        return Ok(Some(s4u_from_userid(store, &id, None)?));
    }
    Ok(None)
}

fn verify_for_user_checksum(
    tgt_session: &ProtocolKey,
    pa: &krb5_types::s4u::PaForUser,
) -> Result<(), Error> {
    if !cksumtype_is_keyed(pa.cksum.cksumtype) {
        return Err(proto(err::INAPP_CKSUM, status::INVALID_S4U2SELF_CHECKSUM));
    }
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
    .map_err(|e| map_s4u_cksum(&e))
}

fn process_s4u_x509_user(
    raw: &[u8],
    tgt_session: &ProtocolKey,
    tgs_subkey: Option<&EncryptionKey>,
    nonce: u32,
) -> Result<krb5_types::s4u::PaS4uX509User, Error> {
    let req: krb5_types::s4u::PaS4uX509User =
        decode(raw).map_err(|_| proto(err::GENERIC, status::DECODE_PA_S4U_X509_USER))?;
    let key = x509_cksum_key(tgt_session, tgs_subkey)?;
    if etype_requires_info2(key.etype()) && !cksumtype_is_keyed(req.cksum.cksumtype) {
        return Err(proto(err::INAPP_CKSUM, status::INVALID_S4U2SELF_CHECKSUM));
    }
    if req.user_id.nonce.cast_unsigned() != nonce {
        return Err(proto(err::MODIFIED, status::INVALID_S4U2SELF_CHECKSUM));
    }
    let usage = KeyUsage::new(ku::PA_S4U_X509_USER_REQUEST)?;
    let mut ok = false;
    if let Some(scratch) = userid_der_from_pa(raw) {
        ok = verify_checksum_keyed(
            &key,
            usage,
            scratch,
            req.cksum.cksumtype,
            req.cksum.checksum.as_ref(),
        )
        .is_ok();
    }
    if !ok {
        let data = encode(&req.user_id)?;
        verify_checksum_keyed(
            &key,
            usage,
            &data,
            req.cksum.cksumtype,
            req.cksum.checksum.as_ref(),
        )
        .map_err(|e| map_s4u_cksum(&e))?;
    }
    let empty_user = req
        .user_id
        .user
        .as_ref()
        .is_none_or(|n| n.name_string.is_empty());
    let empty_cert = req
        .user_id
        .subject_cert
        .as_ref()
        .is_none_or(|c| c.is_empty());
    if empty_user && empty_cert {
        return Err(proto(
            err::C_PRINCIPAL_UNKNOWN,
            status::INVALID_S4U2SELF_REQUEST,
        ));
    }
    Ok(req)
}

fn s4u_from_userid(
    store: &dyn PrincipalRead,
    id: &krb5_types::s4u::S4uUserId,
    x509: Option<krb5_types::s4u::PaS4uX509User>,
) -> Result<S4u2Self, Error> {
    let realm = utf8(&id.realm).to_owned();
    let user = id.user.clone().unwrap_or_else(|| {
        PrincipalName::new(PrincipalName::NT_UNKNOWN, std::iter::empty::<&str>())
    });
    let has_cert = id.subject_cert.as_ref().is_some_and(|c| !c.is_empty());
    let mut local = None;
    if realm == store.realm() {
        if has_cert {
            return Err(proto(err::GENERIC, status::LOOKING_UP_S4U2SELF_PRINCIPAL));
        }
        let mut p = store
            .fetch_name(&user)?
            .ok_or_else(|| proto(err::C_PRINCIPAL_UNKNOWN, status::UNKNOWN_S4U2SELF_PRINCIPAL))?;
        p.pw_expire = 0;
        p.attributes &= !crate::store::KDB_REQUIRES_PWCHANGE;
        local = Some(p);
    }
    Ok(S4u2Self {
        user,
        realm,
        local,
        x509,
    })
}

fn map_s4u_cksum(e: &krb5_crypto::Error) -> Error {
    match e {
        krb5_crypto::Error::InappChecksum => {
            proto(err::INAPP_CKSUM, status::INVALID_S4U2SELF_CHECKSUM)
        }
        krb5_crypto::Error::Integrity => proto(err::MODIFIED, status::INVALID_S4U2SELF_CHECKSUM),
        _ => proto(err::GENERIC, status::INVALID_S4U2SELF_CHECKSUM),
    }
}

fn x509_cksum_key(
    tgt_session: &ProtocolKey,
    tgs_subkey: Option<&EncryptionKey>,
) -> Result<ProtocolKey, Error> {
    if let Some(sub) = tgs_subkey {
        let et = EncryptionType::from_iana(sub.keytype)
            .or_else(|_| EncryptionType::known(sub.keytype))?;
        return Ok(ProtocolKey::from_bytes(et, sub.keyvalue.as_ref())?);
    }
    Ok(tgt_session.clone())
}

fn etype_requires_info2(etype: EncryptionType) -> bool {
    !matches!(etype, EncryptionType::Des3CbcSha1 | EncryptionType::Rc4Hmac)
}

fn userid_der_from_pa(raw: &[u8]) -> Option<&[u8]> {
    let (_, seq, _) = take_der_slice(raw)?;
    let mut cur = seq;
    while !cur.is_empty() {
        let (tag, inner, rest) = take_der_slice(cur)?;
        if tag == 0xa0 {
            return Some(inner);
        }
        cur = rest;
    }
    None
}

fn take_der_slice(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (hlen, ln) = if first < 128 {
        (1usize, usize::from(first))
    } else if first == 0x81 && input.len() >= 3 {
        (2, usize::from(input[2]))
    } else if first == 0x82 && input.len() >= 4 {
        (3, usize::from(u16::from_be_bytes([input[2], input[3]])))
    } else {
        return None;
    };
    let start = 1 + hlen;
    let end = start.checked_add(ln)?;
    Some((tag, input.get(start..end)?, input.get(end..)?))
}

/// Reply PA-S4U-X509-USER (`kdc_make_s4u2self_rep`).
pub(crate) fn make_s4u2self_rep(
    req: &krb5_types::s4u::PaS4uX509User,
    tgt_session: &ProtocolKey,
    tgs_subkey: Option<&EncryptionKey>,
) -> Result<(PaData, Option<PaData>), Error> {
    let key = x509_cksum_key(tgt_session, tgs_subkey)?;
    let mut user_id = req.user_id.clone();
    if user_id.use_reply_key_usage() {
        user_id.options = Some(krb5_types::s4u::s4u_reply_key_usage_flags());
    } else {
        user_id.options = None;
    }
    let der_id = encode(&user_id)?;
    let usage = KeyUsage::new(if user_id.use_reply_key_usage() {
        ku::PA_S4U_X509_USER_REPLY
    } else {
        ku::PA_S4U_X509_USER_REQUEST
    })?;
    let mic = checksum(&key, usage, &der_id)?;
    let rep = krb5_types::s4u::PaS4uX509User {
        user_id,
        cksum: krb5_types::Checksum {
            cksumtype: req.cksum.cksumtype,
            checksum: mic.into(),
        },
    };
    let der = encode(&rep)?;
    let pa = PaData {
        padata_type: pa::FOR_X509_USER,
        padata_value: der.into(),
    };
    let enc = if etype_requires_info2(key.etype()) {
        None
    } else {
        let mut bytes = req.cksum.checksum.as_ref().to_vec();
        bytes.extend_from_slice(rep.cksum.checksum.as_ref());
        Some(PaData {
            padata_type: pa::FOR_X509_USER,
            padata_value: bytes.into(),
        })
    };
    Ok((pa, enc))
}

/// Decrypted second ticket (`decrypt_2ndtkt`).
pub(crate) struct SecondTicket {
    pub part: EncTicketPart,
    pub server: Principal,
    pub pac: Option<Vec<u8>>,
}

/// MIT `verify_deleg_pac` (`tgs_policy.c:366-421`).
pub(crate) fn verify_deleg_pac(
    pac: &krb5_types::pac::Pac,
    enc_tkt: &EncTicketPart,
    target: Option<&PrincipalName>,
) -> bool {
    let Some((_, _, authtime)) = pac_princ_with_realm(pac) else {
        return false;
    };
    if authtime != enc_tkt.authtime.unix_seconds() {
        return false;
    }
    let Ok(Some(buf)) = pac.unique_buffer(krb5_types::pac::PAC_DELEGATION_INFO) else {
        return false;
    };
    let Ok(di) = krb5_types::pac::parse_delegation_info(buf) else {
        return false;
    };
    if let Some(server) = target
        && di.proxy_target != server.unparse()
    {
        return false;
    }
    let Some(last) = di.transited_services.last() else {
        return false;
    };
    let crealm = std::str::from_utf8(enc_tkt.crealm.as_bytes()).unwrap_or("");
    *last == enc_tkt.cname.unparse_with_realm(crealm)
}

fn pac_princ_with_realm(pac: &krb5_types::pac::Pac) -> Option<(String, String, u32)> {
    let buf = pac.unique_buffer(PAC_CLIENT_INFO).ok().flatten()?;
    let (authtime, name) = parse_client_info(buf)?;
    let n = name.bytes().filter(|&b| b == b'@').count();
    if n != 1 && n != 2 {
        return None;
    }
    let (user, realm) = name.rsplit_once('@')?;
    Some((user.to_owned(), realm.to_owned(), authtime))
}

/// MIT `check_tgs_s4u2proxy` (`tgs_policy.c:424-518`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_tgs_s4u2proxy(
    store: &dyn PrincipalRead,
    body: &krb5_types::KdcReqBody,
    header: &EncTicketPart,
    header_pac: Option<&[u8]>,
    stkt: Option<&SecondTicket>,
    dest_realm: &str,
    is_crossrealm: bool,
    is_referral: bool,
) -> Result<(), Error> {
    let Some(st) = stkt else {
        return Err(proto(err::BADOPTION, status::NO_2ND_TKT));
    };
    if !st.part.flags.forwardable() {
        return Err(proto(err::BADOPTION, status::EVIDENCE_TKT_NOT_FORWARDABLE));
    }
    if non_tgt_or_u2u(body) {
        return Err(proto(err::BADOPTION, status::INVALID_S4U2PROXY_OPTIONS));
    }
    if body.sname.as_ref().is_some_and(PrincipalName::is_krbtgt) {
        return Err(proto(err::POLICY, status::NOT_ALLOWED_TO_DELEGATE));
    }
    let Some(hpac) = header_pac else {
        return Err(proto(err::TGT_REVOKED, status::S4U2PROXY_NO_HEADER_PAC));
    };
    let header_parsed = krb5_types::pac::Pac::parse(hpac)
        .map_err(|_| proto(err::BADOPTION, status::S4U2PROXY_HEADER_PAC))?;
    if !pac_client_info_eq(
        &header_parsed,
        header.authtime.unix_seconds(),
        &header.cname.components_joined(),
        None,
    ) {
        return Err(proto(err::BADOPTION, status::S4U2PROXY_HEADER_PAC));
    }
    let Some(spac) = st.pac.as_deref() else {
        return Err(proto(err::MODIFIED, status::S4U2PROXY_NO_STKT_PAC));
    };
    let st_parsed = krb5_types::pac::Pac::parse(spac)
        .map_err(|_| proto(err::BADOPTION, status::S4U2PROXY_LOCAL_STKT_PAC))?;
    if is_crossrealm {
        let inst = st
            .server
            .name
            .name_string
            .get(1)
            .and_then(|i| std::str::from_utf8(i.as_bytes()).ok())
            .unwrap_or("");
        if is_referral
            || !st.server.name.is_cross_tgs_principal(&st.server.realm)
            || inst != dest_realm
            || st.part.cname != header.cname
        {
            return Err(proto(
                err::BADOPTION,
                status::XREALM_EVIDENCE_TICKET_MISMATCH,
            ));
        }
        if !verify_deleg_pac(&st_parsed, &st.part, body.sname.as_ref()) {
            return Err(proto(err::BADOPTION, status::S4U2PROXY_CROSS_STKT_PAC));
        }
    } else {
        if !is_client_db_alias(store, &st.server, &header.cname) {
            return Err(proto(err::SERVER_NOMATCH, status::EVIDENCE_TICKET_MISMATCH));
        }
        if !pac_client_info_eq(
            &st_parsed,
            st.part.authtime.unix_seconds(),
            &st.part.cname.components_joined(),
            None,
        ) {
            return Err(proto(err::BADOPTION, status::S4U2PROXY_LOCAL_STKT_PAC));
        }
    }
    Ok(())
}

fn non_tgt_or_u2u(body: &krb5_types::KdcReqBody) -> bool {
    body.kdc_options.bit(krb5_types::flag_bit::FORWARDED)
        || body.kdc_options.bit(krb5_types::flag_bit::PROXY)
        || body.kdc_options.bit(krb5_types::flag_bit::RENEW)
        || body.kdc_options.bit(krb5_types::flag_bit::VALIDATE)
        || body.kdc_options.bit(krb5_types::flag_bit::ENC_TKT_IN_SKEY)
}

fn is_client_db_alias(store: &dyn PrincipalRead, entry: &Principal, princ: &PrincipalName) -> bool {
    store
        .fetch_name(princ)
        .ok()
        .flatten()
        .is_some_and(|p| p.name == entry.name && p.realm == entry.realm)
}

/// MIT `check_s4u2proxy_policy` (`tgs_policy.c:522-572`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_s4u2proxy_policy(
    padata: Option<&[PaData]>,
    dest: &PrincipalName,
    impersonator_name: &PrincipalName,
    impersonator: &Principal,
    resource: &Principal,
    is_crossrealm: bool,
    is_referral: bool,
) -> Result<(), Error> {
    let support_rbcd = pa_pac_rbcd(padata)?;
    if is_referral {
        if !support_rbcd {
            return Err(proto(err::BADOPTION, status::UNSUPPORTED_S4U2PROXY_REQUEST));
        }
        return Ok(());
    }
    let mut policy_denial = false;
    if support_rbcd {
        if allowed_to_delegate_from(resource, impersonator_name) {
            return Ok(());
        }
        policy_denial = true;
    }
    if !is_crossrealm {
        if check_allowed_to_delegate(impersonator, dest) {
            return Ok(());
        }
        policy_denial = true;
    }
    Err(proto(
        err::BADOPTION,
        if policy_denial {
            status::NOT_ALLOWED_TO_DELEGATE
        } else {
            status::UNSUPPORTED_S4U2PROXY_REQUEST
        },
    ))
}

fn pa_pac_rbcd(padata: Option<&[PaData]>) -> Result<bool, Error> {
    let Some(raw) = find_pa(padata, pa::PAC_OPTIONS) else {
        return Ok(false);
    };
    let opts: krb5_types::s4u::PaPacOptions =
        decode(raw).map_err(|_| proto(err::BADOPTION, status::INVALID_S4U2PROXY_OPTIONS))?;
    Ok(opts.resource_based_constrained_delegation())
}

fn allowed_to_delegate_from(resource: &Principal, impersonator: &PrincipalName) -> bool {
    let from = impersonator.components_joined();
    resource.s4u_allowed_from.iter().any(|n| n == &from)
}

fn check_allowed_to_delegate(impersonator: &Principal, resource: &PrincipalName) -> bool {
    let want = resource.components_joined();
    impersonator.s4u_allowed_to.iter().any(|n| n == &want)
}

/// First-hop `update_delegation_info` (`kdc_authdata.c:382-439`).
pub(crate) fn update_delegation_info(
    subject_pac: &[u8],
    proxy_target: &PrincipalName,
    transited: &str,
) -> Result<Vec<u8>, Error> {
    let parsed = krb5_types::pac::Pac::parse(subject_pac).map_err(|e| map_pac_err(&e))?;
    let mut di = match parsed.unique_buffer(krb5_types::pac::PAC_DELEGATION_INFO) {
        Ok(Some(buf)) => {
            krb5_types::pac::parse_delegation_info(buf).map_err(|e| map_pac_err(&e))?
        }
        _ => krb5_types::pac::S4uDelegationInfo {
            proxy_target: String::new(),
            transited_services: Vec::new(),
        },
    };
    di.proxy_target = proxy_target.unparse();
    di.transited_services.push(transited.to_owned());
    let buf = krb5_types::pac::delegation_info_buffer(&di);
    let mut buffers: Vec<krb5_types::pac::PacBuffer> = parsed
        .buffers
        .into_iter()
        .filter(|b| b.kind != krb5_types::pac::PAC_DELEGATION_INFO)
        .collect();
    buffers.push(krb5_types::pac::PacBuffer::new(
        krb5_types::pac::PAC_DELEGATION_INFO,
        buf,
    ));
    Ok(krb5_types::pac::Pac::built(0, buffers).to_bytes())
}

/// MIT `get_pac_princ_with_realm` for cross-realm S4U2Proxy (`do_tgs_req.c:737-745`).
pub(crate) fn rbcd_pac_client(pac: &[u8]) -> Result<PrincipalName, Error> {
    let parsed = krb5_types::pac::Pac::parse(pac)
        .map_err(|_| proto(err::BADOPTION, status::RBCD_PAC_PRINC))?;
    let Some((user, _, _)) = pac_princ_with_realm(&parsed) else {
        return Err(proto(err::BADOPTION, status::RBCD_PAC_PRINC));
    };
    Ok(PrincipalName::new(
        PrincipalName::NT_MS_PRINCIPAL,
        [user.as_str()],
    ))
}

pub(crate) fn with_status(e: Error, st: &'static str) -> Error {
    match e {
        Error::Protocol {
            code,
            e_data,
            detail,
            ..
        } => Error::Protocol {
            code,
            text: Some(st.to_owned()),
            e_data,
            detail,
        },
        other => other,
    }
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
