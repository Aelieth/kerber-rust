use std::collections::BTreeMap;
use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    ENCTYPE_UNKNOWN, EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt_enc_data, encrypt,
    verify_checksum_type,
};
use krb5_types::transited;
use krb5_types::{
    ApOptions, ApReq, Authenticator, AuthorizationDataValue, EncTicketPart, EncryptedData,
    HostAddress, HostAddresses, KerberosTime, PrincipalName, Realm, Ticket, err, ku, pa,
    principal_compare,
};

use crate::auth_con::check_ticket_etype;
use crate::error::Error;
use crate::replay::{ReplayCache, ReplayKey};
use crate::trace::{ERROR_TABLE_BASE_KRB5, error_message};

pub const DEFAULT_SKEW: i64 = 300;

pub struct ApVerifyParams<'a> {
    pub keys: &'a [ProtocolKey],
    pub key_kvnos: Option<&'a [u32]>,
    pub key_principals: Option<&'a [(PrincipalName, Realm)]>,
    pub kvno: Option<u32>,
    pub permitted: &'a [EncryptionType],
    /// Non-host-based name: its own keytab entry only.
    pub expected_server: Option<&'a PrincipalName>,
    pub expected_realm: Option<&'a str>,
    pub get_entry: Option<KeytabGetEntry<'a>>,
    /// Negative skew fails every time check.
    pub skew: i64,
    pub ignore_acceptor_hostname: bool,
    pub capaths: &'a BTreeMap<String, BTreeMap<String, Vec<String>>>,
    /// Ticket's caddr must hold it; None skips it (MIT: unset remote).
    pub remote_addr: Option<&'a HostAddress>,
    pub now: Option<KerberosTime>,
}

static NO_CAPATHS: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
static DEFAULT_PERMITTED: [EncryptionType; 4] = EncryptionType::preferred();

impl<'a> ApVerifyParams<'a> {
    #[must_use]
    pub fn single_key(key: &'a ProtocolKey) -> Self {
        Self {
            keys: std::slice::from_ref(key),
            key_kvnos: None,
            key_principals: None,
            kvno: None,
            permitted: &DEFAULT_PERMITTED,
            expected_server: None,
            expected_realm: None,
            get_entry: None,
            skew: DEFAULT_SKEW,
            ignore_acceptor_hostname: false,
            capaths: &NO_CAPATHS,
            remote_addr: None,
            now: None,
        }
    }
}

// MIT: `keytab_fetch_error` (lib/krb5/krb/rd_req_dec.c:118-148)
#[derive(Debug)]
pub enum KeytabLookup {
    NotFound,
    KvnoNotFound,
    Other(Error),
}

pub type KeytabGetEntry<'a> =
    &'a dyn Fn(&PrincipalName, &str, u32, i32) -> Result<ProtocolKey, KeytabLookup>;

// MIT: `krb5_address_search` (lib/krb5/krb/addr_srch.c:48-65)
/// No list, or one NetBIOS address: any address matches.
#[must_use]
pub fn address_search(addr: &HostAddress, list: Option<&HostAddresses>) -> bool {
    list.is_none_or(|l| address_in_list(addr, l))
}

pub(crate) fn address_in_list(addr: &HostAddress, list: &[HostAddress]) -> bool {
    if list.len() == 1 && list[0].addr_type == HostAddress::ADDRTYPE_NETBIOS {
        return true;
    }
    list.iter().any(|a| a == addr)
}

pub fn build_ap_req(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
) -> Result<ApReq, Error> {
    build_ap_req_in(ticket, session_key, crealm, cname, None)
}

pub(crate) fn build_ap_req_in(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    profile: Option<&krb5_config::Krb5Conf>,
) -> Result<ApReq, Error> {
    ap_req_with_cksum(
        ticket,
        session_key,
        crealm,
        cname,
        ApOptions::none(),
        None,
        None,
        profile,
    )
}

pub fn build_ap_req_opts(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    ap_options: ApOptions,
    cksum_data: Option<&[u8]>,
) -> Result<ApReq, Error> {
    let cksum = if let Some(data) = cksum_data {
        let usage = KeyUsage::new(ku::AP_REQ_AUTH_CKSUM)?;
        let mic = checksum(session_key, usage, data)?;
        Some(krb5_types::Checksum {
            cksumtype: session_key.etype().checksum_type(),
            checksum: mic.into(),
        })
    } else {
        None
    };
    ap_req_with_cksum(
        ticket,
        session_key,
        crealm,
        cname,
        ap_options,
        cksum,
        None,
        None,
    )
}

pub struct ApAuthenticator<'a> {
    pub crealm: &'a Realm,
    pub cname: &'a PrincipalName,
    pub cksum: Option<krb5_types::Checksum>,
    pub subkey: Option<krb5_types::EncryptionKey>,
    pub sequence: Option<u32>,
    pub time_offset: i64,
    pub cbt: bool,
    pub desired_etypes: &'a [i32],
    pub ticket_etype: i32,
    pub profile: Option<&'a krb5_config::Krb5Conf>,
}

// MIT: `generate_authenticator` (lib/krb5/krb/mk_req_ext.c:301-327)
// MIT: `krb5_us_timeofday` (lib/krb5/os/ustime.c:66-78)
pub fn generate_ap_authenticator(auth: ApAuthenticator<'_>) -> Result<Authenticator, Error> {
    if auth
        .profile
        .is_some_and(|p| p.client_aware_channel_bindings_invalid)
    {
        return Err(Error::BadBoolean);
    }
    let aware = auth.cbt
        || auth
            .profile
            .is_some_and(|p| p.client_aware_channel_bindings);
    // MIT: `authenticator_7` (lib/krb5/asn.1/asn1_k_encode.c:693-693)
    let sequence = auth.sequence.filter(|n| *n != 0);
    let (now, usec) = stamped(auth.time_offset);
    Ok(Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: auth.crealm.clone(),
        cname: auth.cname.clone(),
        cksum: auth.cksum,
        cusec: usec,
        ctime: now,
        subkey: auth.subkey,
        seq_number: sequence,
        authorization_data: ap_authdata(auth.desired_etypes, auth.ticket_etype, aware)?,
    })
}

pub(crate) fn stamped(offset: i64) -> (KerberosTime, krb5_types::Microseconds) {
    let (now, usec) = crate::auth_con::us_timeofday();
    if offset == 0 {
        return (now, usec);
    }
    let sec = i64::from(now.unix_seconds()).saturating_add(offset);
    let sec = u32::try_from(sec.clamp(0, i64::from(u32::MAX))).unwrap_or(u32::MAX);
    (KerberosTime::from_unix_seconds(sec), usec)
}

// MIT: `make_etype_list` (lib/krb5/krb/mk_req_ext.c:341-350)
fn etype_list(desired: &[i32], ticket_etype: i32) -> Option<Vec<i32>> {
    let first = *desired.first()?;
    if first == ticket_etype {
        return None;
    }
    let end = desired
        .iter()
        .position(|etype| *etype == ticket_etype)
        .map_or(desired.len(), |i| i + 1);
    Some(desired[..end].to_vec())
}

// MIT: `make_ap_authdata` (lib/krb5/krb/mk_req_ext.c:373-393)
fn ap_authdata(
    desired: &[i32],
    ticket_etype: i32,
    cbt: bool,
) -> Result<Option<Vec<AuthorizationDataValue>>, Error> {
    const AD_AP_OPTIONS: i32 = 143;
    const KERB_AP_OPTIONS_CBT: u32 = 0x4000;
    let mut inner = Vec::new();
    if let Some(list) = etype_list(desired, ticket_etype) {
        let der = encode(&krb5_types::EtypeList(list))?;
        inner.push(AuthorizationDataValue {
            ad_type: pa::AD_ETYPE_NEGOTIATION,
            ad_data: der.into(),
        });
    }
    if cbt {
        inner.push(AuthorizationDataValue {
            ad_type: AD_AP_OPTIONS,
            ad_data: KERB_AP_OPTIONS_CBT.to_le_bytes().to_vec().into(),
        });
    }
    if inner.is_empty() {
        return Ok(None);
    }
    let der = encode(&inner)?;
    Ok(Some(vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: der.into(),
    }]))
}

pub fn build_ap_req_mutual_seq(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    seq_number: u32,
) -> Result<ApReq, Error> {
    let authenticator = generate_ap_authenticator(ApAuthenticator {
        crealm,
        cname,
        cksum: None,
        subkey: None,
        sequence: Some(seq_number),
        time_offset: 0,
        cbt: false,
        desired_etypes: &[],
        ticket_etype: session_key.etype().to_iana(),
        profile: None,
    })?;
    let der = encode(&authenticator)?;
    let usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let cipher = encrypt(session_key, usage, &der)?;
    Ok(ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::mutual_required(),
        ticket,
        authenticator: EncryptedData {
            etype: session_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    })
}

pub fn build_ap_req_with_cksum(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    ap_options: ApOptions,
    cksum: Option<krb5_types::Checksum>,
    subkey: Option<krb5_types::EncryptionKey>,
) -> Result<ApReq, Error> {
    ap_req_with_cksum(
        ticket,
        session_key,
        crealm,
        cname,
        ap_options,
        cksum,
        subkey,
        None,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the AP-REQ pieces and the caller's profile"
)]
fn ap_req_with_cksum(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    ap_options: ApOptions,
    cksum: Option<krb5_types::Checksum>,
    subkey: Option<krb5_types::EncryptionKey>,
    profile: Option<&krb5_config::Krb5Conf>,
) -> Result<ApReq, Error> {
    let authenticator = generate_ap_authenticator(ApAuthenticator {
        crealm,
        cname,
        cksum,
        subkey,
        sequence: Some(0),
        time_offset: 0,
        cbt: false,
        desired_etypes: &[],
        ticket_etype: session_key.etype().to_iana(),
        profile,
    })?;
    build_ap_req_from_authenticator(ticket, session_key, ap_options, &authenticator)
}

pub fn build_ap_req_from_authenticator(
    ticket: Ticket,
    session_key: &ProtocolKey,
    ap_options: ApOptions,
    authenticator: &Authenticator,
) -> Result<ApReq, Error> {
    let der = encode(authenticator)?;
    let usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let cipher = encrypt(session_key, usage, &der)?;
    Ok(ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options,
        ticket,
        authenticator: EncryptedData {
            etype: session_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    })
}

#[derive(Debug)]
pub struct ApVerifyOk {
    pub ticket_part: EncTicketPart,
    pub sname: krb5_types::PrincipalName,
    pub srealm: krb5_types::Realm,
    pub authenticator: Authenticator,
    pub mutual_required: bool,
    pub ticket_etype: i32,
}

pub fn verify_ap_req(
    raw: &[u8],
    service_key: &ProtocolKey,
    replay: &ReplayCache,
) -> Result<ApVerifyOk, Error> {
    verify_ap_req_ex(raw, &ApVerifyParams::single_key(service_key), replay, None)
}

pub fn verify_ap_req_ex(
    raw: &[u8],
    params: &ApVerifyParams<'_>,
    replay: &ReplayCache,
    app_cksum: Option<&[u8]>,
) -> Result<ApVerifyOk, Error> {
    let _g = krb5_log::enter_correlation(krb5_log::new_correlation_id());
    let started = Instant::now();
    let result = verify_inner(raw, params, replay, app_cksum);
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => tracing::debug!(
            event = krb5_log::events::PROTOCOL_AP,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-protocol",
            duration_us,
            outcome = "ok",
        ),
        Err(e) => tracing::error!(
            event = krb5_log::events::PROTOCOL_AP,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-protocol",
            duration_us,
            outcome = "error",
            error = %e,
        ),
    }
    result
}

// MIT: `decrypt_try_server` (rd_req_dec.c:373-386)
fn server_looked_up(
    ap: &ApReq,
    params: &ApVerifyParams<'_>,
    explicit: bool,
) -> (PrincipalName, String) {
    let tkt_realm = || String::from_utf8_lossy(ap.ticket.realm.as_bytes()).into_owned();
    if !explicit {
        return (ap.ticket.sname.clone(), tkt_realm());
    }
    let realm = params.expected_realm.map_or_else(tkt_realm, str::to_owned);
    let name = params
        .expected_server
        .cloned()
        .unwrap_or_else(|| ap.ticket.sname.clone());
    (name, realm)
}

// MIT: `try_one_entry` (rd_req_dec.c:290-320)
// MIT: `krb5_decrypt_tkt_part` (lib/krb5/krb/decrypt_tk.c:46-50)
fn decrypt_ticket_part(
    ap: &ApReq,
    key: &ProtocolKey,
    tkt_usage: KeyUsage,
    permitted: &[EncryptionType],
) -> Result<EncTicketPart, Error> {
    check_ticket_etype(ap.ticket.enc_part.etype, permitted)?;
    let plain = decrypt_enc_data(
        key,
        tkt_usage,
        ap.ticket.enc_part.etype,
        ap.ticket.enc_part.cipher.as_ref(),
    )
    .map_err(|e| decrypt_code(&e).map_or_else(|| e.into(), refused))?;
    Ok(decode::<EncTicketPart>(&plain)?)
}

// MIT: `try_one_princ` (rd_req_dec.c:325-347)
fn decrypt_for_server(
    ap: &ApReq,
    params: &ApVerifyParams<'_>,
    ignore_host: bool,
    tkt_usage: KeyUsage,
) -> Result<EncTicketPart, Error> {
    let lookup = params.get_entry.is_some();
    let explicit = !is_matching(params.expected_server, params.expected_realm, ignore_host);
    // No-principal keys match only if the ticket's server is named.
    if !lookup
        && !sname_match(
            params.expected_server,
            params.expected_realm,
            &ap.ticket.sname,
            ap.ticket.realm.as_bytes(),
            ignore_host,
        )
    {
        return Err(Error::KrbError {
            code: err::NOT_US,
            text: Some("ticket sname does not match expected server".into()),
        });
    }
    let tkt_realm = String::from_utf8_lossy(ap.ticket.realm.as_bytes()).into_owned();
    if lookup
        && !explicit
        && !sname_match(
            params.expected_server,
            params.expected_realm,
            &ap.ticket.sname,
            ap.ticket.realm.as_bytes(),
            ignore_host,
        )
    {
        let server = params
            .expected_server
            .map(|s| s.unparse_with_realm(params.expected_realm.unwrap_or_default()))
            .unwrap_or_default();
        return Err(Error::KrbError {
            code: err::NOT_US,
            text: Some(format!(
                "Server principal {server} does not match request ticket server {}",
                ap.ticket.sname.unparse_with_realm(&tkt_realm)
            )),
        });
    }
    let (name, realm) = server_looked_up(ap, params, explicit);
    let mut last_err = Error::KrbError {
        code: err::NOKEY,
        text: Some("no matching service key".into()),
    };
    let mut ticket_part: Option<EncTicketPart> = None;
    let want_kvno = ap
        .ticket
        .enc_part
        .kvno
        .filter(|&v| v != 0)
        .or(params.kvno.filter(|&v| v != 0));
    let tkt_etype = ap.ticket.enc_part.etype;
    // MIT: `krb5_ktfile_get_entry` (kt_file.c:355-384)
    let mut found_wrong_kvno = false;
    let mut tried_any = false;
    let mut not_found = false;
    if let Some(get_entry) = params.get_entry {
        match get_entry(
            &name,
            &realm,
            ap.ticket.enc_part.kvno.unwrap_or(0),
            tkt_etype,
        ) {
            Ok(key) => {
                tried_any = true;
                match decrypt_ticket_part(ap, &key, tkt_usage, params.permitted) {
                    Ok(p) => ticket_part = Some(p),
                    Err(e) => last_err = e,
                }
            }
            Err(KeytabLookup::NotFound) => not_found = true,
            Err(KeytabLookup::KvnoNotFound) => found_wrong_kvno = true,
            Err(KeytabLookup::Other(e)) => return Err(e),
        }
    } else {
        for (i, key) in params.keys.iter().enumerate() {
            if key.etype().to_iana() != tkt_etype {
                continue;
            }
            if let Some(want) = want_kvno
                && let Some(have) = params.key_kvnos.and_then(|v| v.get(i)).copied()
                && have != 0
                && have != want
            {
                found_wrong_kvno = true;
                continue;
            }
            tried_any = true;
            match decrypt_ticket_part(ap, key, tkt_usage, params.permitted) {
                Ok(p) => {
                    ticket_part = Some(p);
                    break;
                }
                Err(e) => last_err = e,
            }
        }
    }
    let Some(ticket_part) = ticket_part else {
        let same_princ = principal_compare(&name, &realm, &ap.ticket.sname, &tkt_realm);
        if found_wrong_kvno && !tried_any && (lookup || params.expected_server.is_some()) {
            let sname = ap
                .ticket
                .sname
                .name_string
                .iter()
                .map(|c| String::from_utf8_lossy(c.as_bytes()).into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let want = want_kvno.unwrap_or(0);
            return Err(if same_princ {
                Error::KrbError {
                    code: err::BADKEYVER,
                    text: Some(format!("Cannot find key for {sname} kvno {want} in keytab")),
                }
            } else {
                Error::KrbError {
                    code: err::NOT_US,
                    text: Some(format!(
                        "Server principal does not match request ticket server {sname}"
                    )),
                }
            });
        }
        // MIT: `integrity_error` (rd_req_dec.c:162-181)
        // Non-decrypting: BAD_INTEGRITY if the ticket's server is named, else NOT_US.
        if tried_any
            && matches!(last_err, Error::KrbError { code, .. } if code == err::BAD_INTEGRITY)
        {
            return Err(Error::KrbError {
                code: if same_princ {
                    err::BAD_INTEGRITY
                } else {
                    err::NOT_US
                },
                text: Some(format!(
                    "Cannot decrypt ticket for {} using keytab key for {}",
                    ap.ticket.sname.unparse_with_realm(&tkt_realm),
                    name.unparse_with_realm(&realm)
                )),
            });
        }
        if not_found && !explicit {
            return Err(Error::KrbError {
                code: err::NOT_US,
                text: Some("Wrong principal in request".into()),
            });
        }
        return Err(last_err);
    };
    Ok(ticket_part)
}

// MIT: `is_matching` (rd_req_dec.c:279-286)
fn is_matching(server: Option<&PrincipalName>, realm: Option<&str>, ignore_host: bool) -> bool {
    let Some(server) = server else {
        return true;
    };
    server.name_type == PrincipalName::NT_SRV_HST
        && server.name_string.len() == 2
        && (realm.is_none_or(str::is_empty)
            || server.name_string[1].as_bytes().is_empty()
            || ignore_host)
}

fn decrypt_by_keytab_walk(
    ap: &ApReq,
    params: &ApVerifyParams<'_>,
    ignore_host: bool,
    tkt_usage: KeyUsage,
) -> Result<EncTicketPart, Error> {
    let tkt_kvno = ap.ticket.enc_part.kvno.unwrap_or(0);
    let tkt_etype = ap.ticket.enc_part.etype;
    let tkt_realm = String::from_utf8_lossy(ap.ticket.realm.as_bytes()).into_owned();
    let mut walk = KeytabWalk::default();
    for (i, key) in params.keys.iter().enumerate() {
        // No-principal slot: the ticket server's; the caller holds its keys.
        let (ename, erealm) = params
            .key_principals
            .and_then(|p| p.get(i))
            .map_or((&ap.ticket.sname, tkt_realm.clone()), |(n, r)| {
                (n, String::from_utf8_lossy(r.as_bytes()).into_owned())
            });
        let is_tkt_server = principal_compare(ename, &erealm, &ap.ticket.sname, &tkt_realm);
        if !sname_match(
            params.expected_server,
            params.expected_realm,
            ename,
            erealm.as_bytes(),
            ignore_host,
        ) {
            walk.tkt_server_mismatch |= is_tkt_server;
            continue;
        }
        walk.found_server_match = true;
        let similar_enctype = key.etype().to_iana() == tkt_etype;
        if is_tkt_server {
            walk.found_tkt_server = true;
            let kvno = params
                .key_kvnos
                .and_then(|v| v.get(i))
                .copied()
                .unwrap_or(tkt_kvno);
            if kvno == tkt_kvno {
                walk.found_kvno = true;
                walk.found_enctype |= similar_enctype;
            } else if kvno > tkt_kvno {
                walk.found_higher_kvno = true;
            }
        }
        if similar_enctype
            && check_ticket_etype(tkt_etype, params.permitted).is_ok()
            && let Ok(plain) = decrypt_enc_data(
                key,
                tkt_usage,
                tkt_etype,
                ap.ticket.enc_part.cipher.as_ref(),
            )
            && let Ok(part) = decode::<EncTicketPart>(&plain)
        {
            return Ok(part);
        }
    }
    Err(iteration_error(params, ap, &tkt_realm, tkt_kvno, &walk))
}

#[derive(Default)]
struct KeytabWalk {
    tkt_server_mismatch: bool,
    found_server_match: bool,
    found_tkt_server: bool,
    found_kvno: bool,
    found_higher_kvno: bool,
    found_enctype: bool,
}

// MIT: `iteration_error` (rd_req_dec.c:208-275)
fn iteration_error(
    params: &ApVerifyParams<'_>,
    ap: &ApReq,
    tkt_realm: &str,
    tkt_kvno: u32,
    walk: &KeytabWalk,
) -> Error {
    let tsname = ap.ticket.sname.unparse_with_realm(tkt_realm);
    let sname = params
        .expected_server
        .map(|s| s.unparse_with_realm(params.expected_realm.unwrap_or_default()));
    let etype = ap.ticket.enc_part.etype;
    let encname =
        crate::trace::enctype_shortest_name(etype).map_or_else(|| etype.to_string(), str::to_owned);
    let (code, text) = if !walk.found_server_match {
        (
            err::NOKEY,
            sname.map_or_else(
                || "No keys in keytab".to_string(),
                |s| format!("Server principal {s} does not match any keys in keytab"),
            ),
        )
    } else if walk.tkt_server_mismatch {
        (
            err::NOT_US,
            format!(
                "Request ticket server {tsname} found in keytab but does not match server principal {}",
                sname.unwrap_or_default()
            ),
        )
    } else if !walk.found_tkt_server {
        (
            err::NOT_US,
            format!("Request ticket server {tsname} not found in keytab (ticket kvno {tkt_kvno})"),
        )
    } else if !walk.found_kvno {
        let why = if walk.found_higher_kvno {
            "ticket is likely out of date"
        } else {
            "keytab is likely out of date"
        };
        (
            err::BADKEYVER,
            format!("Request ticket server {tsname} kvno {tkt_kvno} not found in keytab; {why}"),
        )
    } else if !walk.found_enctype {
        (
            err::BADKEYVER,
            format!(
                "Request ticket server {tsname} kvno {tkt_kvno} found in keytab but not with enctype {encname}"
            ),
        )
    } else {
        (
            err::BAD_INTEGRITY,
            format!(
                "Request ticket server {tsname} kvno {tkt_kvno} enctype {encname} found in keytab but cannot decrypt ticket"
            ),
        )
    };
    Error::KrbError {
        code,
        text: Some(text),
    }
}

// MIT: `rd_req_decoded_opt` (rd_req_dec.c:472-787)
fn verify_inner(
    raw: &[u8],
    params: &ApVerifyParams<'_>,
    replay: &ReplayCache,
    app_cksum: Option<&[u8]>,
) -> Result<ApVerifyOk, Error> {
    if raw.is_empty() {
        return Err(Error::TruncatedReply);
    }
    let ap: ApReq = decode(raw)?;
    let ignore_host = params.ignore_acceptor_hostname;
    let tkt_usage = KeyUsage::new(ku::TICKET)?;
    let explicit = !is_matching(params.expected_server, params.expected_realm, ignore_host);
    let by_lookup = params.get_entry.is_some();
    let ticket_part = if by_lookup || explicit {
        decrypt_for_server(&ap, params, ignore_host, tkt_usage)?
    } else {
        decrypt_by_keytab_walk(&ap, params, ignore_host, tkt_usage)?
    };
    let (sname, srealm) = if by_lookup {
        let (name, realm) = server_looked_up(&ap, params, explicit);
        let realm = krb5_types::try_ascii(&realm).unwrap_or_else(|_| ap.ticket.realm.clone());
        (name, realm)
    } else {
        (ap.ticket.sname.clone(), ap.ticket.realm.clone())
    };
    let tkt_etype = ap.ticket.enc_part.etype;
    let auth_usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let (session, auth_plain) = session_key(&ticket_part.key, &ap.authenticator)
        .and_then(|session| {
            let plain = decrypt_enc_data(
                &session,
                auth_usage,
                ap.authenticator.etype,
                ap.authenticator.cipher.as_ref(),
            )?;
            Ok((session, plain))
        })
        .map_err(|e| decrypt_code(&e).map_or_else(|| e.into(), refused))?;
    let authenticator: Authenticator = decode(&auth_plain)?;
    if !authenticator.cname.components_eq(&ticket_part.cname)
        || authenticator.crealm != ticket_part.crealm
    {
        return Err(refused(err::BADMATCH));
    }
    if let Some(remote) = params.remote_addr
        && !address_search(remote, ticket_part.caddr.as_ref())
    {
        return Err(refused(err::BADADDR));
    }
    let srealm_text = String::from_utf8_lossy(srealm.as_bytes());
    transited::check_transited(&ticket_part, &srealm_text, params.capaths).map_err(refused)?;
    let key = EncryptionType::known(ap.authenticator.etype)
        .ok()
        .and_then(|et| ReplayKey::from_ciphertext(et, ap.authenticator.cipher.as_ref()))
        .ok_or_else(|| Error::Crypto("ciphertext shorter than its checksum".into()))?
        .file2();
    if replay.check_and_store(key, params.skew) {
        return Err(refused(err::REPEAT));
    }
    let now = params.now.clone().unwrap_or_else(KerberosTime::now);
    // MIT: `krb5_init_context_profile` (lib/krb5/krb/init_ctx.c:250-252)
    let skew = params.skew;
    // MIT: `krb5int_validate_times` (valid_times.c:36-57)
    // No starttime: gated by authtime, not unchecked.
    let start = ticket_part
        .starttime
        .as_ref()
        .unwrap_or(&ticket_part.authtime);
    if now.delta_seconds(start) < skew.saturating_neg() {
        return Err(refused(err::TKT_NYV));
    }
    if ticket_part.endtime.delta_seconds(&now) < skew.saturating_neg() {
        return Err(refused(err::TKT_EXPIRED));
    }
    // MIT: `krb5_check_clockskew` (lib/krb5/os/timeofday.c:55-67)
    let skew_delta = now.delta_seconds(&authenticator.ctime).unsigned_abs();
    if !u64::try_from(skew).is_ok_and(|limit| skew_delta <= limit) {
        return Err(refused(err::SKEW));
    }
    if ticket_part.flags.invalid() {
        return Err(refused(err::TKT_INVALID));
    }
    if let Some(ck) = &authenticator.cksum
        && let Some(data) = app_cksum
        && ck.cksumtype != 0x8003
    {
        let usage = KeyUsage::new(ku::AP_REQ_AUTH_CKSUM)?;
        verify_checksum_type(&session, usage, data, ck.cksumtype, ck.checksum.as_ref())?;
    }
    Ok(ApVerifyOk {
        ticket_part,
        sname,
        srealm,
        authenticator,
        mutual_required: ap.ap_options.wants_mutual(),
        ticket_etype: tkt_etype,
    })
}

// MIT: `krb5_k_decrypt` (lib/crypto/krb/decrypt.c:30-85)
#[must_use]
pub fn decrypt_code(e: &krb5_crypto::Error) -> Option<i32> {
    match e {
        krb5_crypto::Error::Integrity => Some(err::BAD_INTEGRITY),
        krb5_crypto::Error::CiphertextTooShort => Some(err::BAD_MSIZE),
        krb5_crypto::Error::BadEnctype(_) | krb5_crypto::Error::UnsupportedEtype(_) => {
            Some(err::BAD_ENCTYPE)
        }
        krb5_crypto::Error::InvalidKeyLength => Some(err::CRYPTO_INTERNAL),
        _ => None,
    }
}

// MIT: `krb5_k_decrypt` (lib/crypto/krb/decrypt.c:41-55)
fn session_key(
    key: &krb5_types::EncryptionKey,
    data: &EncryptedData,
) -> Result<ProtocolKey, krb5_crypto::Error> {
    let etype = EncryptionType::known(key.keytype)?;
    if data.etype != ENCTYPE_UNKNOWN && data.etype != key.keytype {
        return Err(krb5_crypto::Error::BadEnctype(data.etype));
    }
    if data.cipher.as_ref().len() < etype.min_ciphertext_len() {
        return Err(krb5_crypto::Error::CiphertextTooShort);
    }
    ProtocolKey::from_bytes(etype, key.keyvalue.as_ref())
}

fn refused(code: i32) -> Error {
    Error::KrbError {
        code,
        text: Some(error_message(ERROR_TABLE_BASE_KRB5 + i64::from(code))),
    }
}

// MIT: `krb5_sname_match` (sname_match.c:30-57)
#[must_use]
pub fn sname_match(
    matching: Option<&PrincipalName>,
    matching_realm: Option<&str>,
    princ: &PrincipalName,
    princ_realm: &[u8],
    ignore_acceptor_hostname: bool,
) -> bool {
    let Some(matching) = matching else {
        return true;
    };
    let realm_ok = matching_realm.is_none_or(|r| r.is_empty() || r.as_bytes() == princ_realm);
    if matching.name_type != PrincipalName::NT_SRV_HST || matching.name_string.len() != 2 {
        return matching.name_string == princ.name_string && realm_ok;
    }
    if princ.name_string.len() != 2 {
        return false;
    }
    if !realm_ok {
        return false;
    }
    if matching.name_string[0].as_bytes() != princ.name_string[0].as_bytes() {
        return false;
    }
    let host = matching.name_string[1].as_bytes();
    if !host.is_empty() && !ignore_acceptor_hostname && host != princ.name_string[1].as_bytes() {
        return false;
    }
    true
}
