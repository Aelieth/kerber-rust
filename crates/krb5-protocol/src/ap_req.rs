//! AP-REQ construction (RFC 4120 §5.5.1) and service-side verification.

use std::collections::BTreeMap;
use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt_enc_data, encrypt,
    verify_checksum_type,
};
use krb5_types::transited::hierarchical_walk_realms;
use krb5_types::{
    ApOptions, ApReq, Authenticator, EncTicketPart, EncryptedData, HostAddress, HostAddresses,
    KerberosTime, PrincipalName, Realm, Ticket, err, flag_bit, ku, principal_compare,
};

use crate::error::Error;
use crate::replay::{ReplayCache, ReplayKey};

pub const DEFAULT_SKEW: i64 = 300;

pub struct ApVerifyParams<'a> {
    pub keys: &'a [ProtocolKey],
    pub key_kvnos: Option<&'a [u32]>,
    pub key_principals: Option<&'a [(PrincipalName, Realm)]>,
    pub kvno: Option<u32>,
    /// A name that is not host-based tries only its own keytab entry.
    pub expected_server: Option<&'a PrincipalName>,
    pub expected_realm: Option<&'a str>,
    /// A keytab that cannot be walked is looked up, not iterated.
    pub get_entry: Option<KeytabGetEntry<'a>>,
    /// A negative skew fails every time check.
    pub skew: i64,
    /// A host-based name matches that service on any host.
    pub ignore_acceptor_hostname: bool,
    pub capaths: &'a BTreeMap<String, BTreeMap<String, Vec<String>>>,
    /// The ticket's caddr must hold it; None skips the check, as MIT's unset remote address.
    pub remote_addr: Option<&'a HostAddress>,
    pub now: Option<KerberosTime>,
}

static NO_CAPATHS: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();

impl<'a> ApVerifyParams<'a> {
    #[must_use]
    pub fn single_key(key: &'a ProtocolKey) -> Self {
        Self {
            keys: std::slice::from_ref(key),
            key_kvnos: None,
            key_principals: None,
            kvno: None,
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
/// No list, or one NetBIOS address, holds any address.
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
    build_ap_req_opts(ticket, session_key, crealm, cname, ApOptions::none(), None)
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
    build_ap_req_with_cksum(ticket, session_key, crealm, cname, ap_options, cksum, None)
}

pub fn build_ap_req_mutual_seq(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    seq_number: u32,
) -> Result<ApReq, Error> {
    // MIT: `generate_authenticator` (lib/krb5/krb/mk_req_ext.c:327-327)
    // the time and its microseconds, from `krb5_us_timeofday`.
    let (now, usec) = crate::auth_con::us_timeofday();
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: crealm.clone(),
        cname: cname.clone(),
        cksum: None,
        cusec: usec,
        ctime: now,
        subkey: None,
        seq_number: Some(seq_number),
        authorization_data: None,
    };
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
    let (now, usec) = crate::auth_con::us_timeofday();
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: crealm.clone(),
        cname: cname.clone(),
        cksum,
        cusec: usec,
        ctime: now,
        subkey,
        seq_number: Some(0),
        authorization_data: None,
    };
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
        Ok(_) => tracing::info!(
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
fn decrypt_ticket_part(
    ap: &ApReq,
    key: &ProtocolKey,
    tkt_usage: KeyUsage,
) -> Result<EncTicketPart, Error> {
    let plain = decrypt_enc_data(
        key,
        tkt_usage,
        ap.ticket.enc_part.etype,
        ap.ticket.enc_part.cipher.as_ref(),
    )?;
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
    // keys with no principal match only when the ticket server is the named one.
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
    // Another kvno for that principal is KVNONOTFOUND when nothing matched.
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
                match decrypt_ticket_part(ap, &key, tkt_usage) {
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
            match decrypt_ticket_part(ap, key, tkt_usage) {
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
        // a key that does not decrypt the ticket is BAD_INTEGRITY when the named server is the ticket's, else NOT_US.
        if tried_any && !same_princ && matches!(last_err, Error::Crypto(_)) {
            return Err(Error::KrbError {
                code: err::NOT_US,
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
/// A host-based name with no host walks the keytab.
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
        // A slot with no principal is taken as the ticket server's: the caller holds that service's keys.
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
    let encname = EncryptionType::from_iana(etype)
        .or_else(|_| EncryptionType::known(etype))
        .map_or_else(|_| etype.to_string(), |e| e.to_mit_name().to_string());
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

// MIT: `rd_req_decoded_opt` (rd_req_dec.c:634-638)
/// The invalid flag is tested only after the ticket times.
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
    let now = params.now.clone().unwrap_or_else(KerberosTime::now);
    // MIT: `krb5_init_context_profile` (lib/krb5/krb/init_ctx.c:250-252)
    // the skew is the profile's integer as written, a negative one too.
    let skew = params.skew;
    // MIT: `krb5int_validate_times` (valid_times.c:36-57)
    // No starttime is gated by authtime, not left unchecked.
    let start = ticket_part
        .starttime
        .as_ref()
        .unwrap_or(&ticket_part.authtime);
    if now.delta_seconds(start) < skew.saturating_neg() {
        return Err(Error::KrbError {
            code: err::TKT_NYV,
            text: Some("ticket not yet valid".into()),
        });
    }
    if ticket_part.endtime.delta_seconds(&now) < skew.saturating_neg() {
        return Err(Error::KrbError {
            code: err::TKT_EXPIRED,
            text: Some("ticket expired".into()),
        });
    }
    if ticket_part.flags.invalid() {
        return Err(Error::KrbError {
            code: err::TKT_INVALID,
            text: Some("Ticket has invalid flag set".into()),
        });
    }
    if let Some(remote) = params.remote_addr
        && !address_search(remote, ticket_part.caddr.as_ref())
    {
        return Err(Error::KrbError {
            code: err::BADADDR,
            text: Some("Incorrect net address".into()),
        });
    }
    let srealm_text = String::from_utf8_lossy(srealm.as_bytes()).into_owned();
    check_ap_req_transited(&ticket_part, &srealm_text, params.capaths)?;
    let session_etype = EncryptionType::known(ticket_part.key.keytype)?;
    let session = ProtocolKey::from_bytes(session_etype, ticket_part.key.keyvalue.as_ref())?;
    let auth_usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let auth_plain = decrypt_enc_data(
        &session,
        auth_usage,
        ap.authenticator.etype,
        ap.authenticator.cipher.as_ref(),
    )?;
    let authenticator: Authenticator = decode(&auth_plain)?;
    if !authenticator.cname.components_eq(&ticket_part.cname)
        || authenticator.crealm != ticket_part.crealm
    {
        return Err(Error::KrbError {
            code: err::BADMATCH,
            text: Some("authenticator/ticket client mismatch".into()),
        });
    }
    // MIT: `krb5_check_clockskew` (lib/krb5/os/timeofday.c:55-67)
    // `ts_within` the skew, which a negative skew never is.
    let skew_delta = now.delta_seconds(&authenticator.ctime).unsigned_abs();
    if !u64::try_from(skew).is_ok_and(|limit| skew_delta <= limit) {
        return Err(Error::KrbError {
            code: err::SKEW,
            text: Some("authenticator clock skew".into()),
        });
    }
    if let Some(ck) = &authenticator.cksum
        && let Some(data) = app_cksum
        && ck.cksumtype != 0x8003
    {
        let usage = KeyUsage::new(ku::AP_REQ_AUTH_CKSUM)?;
        verify_checksum_type(&session, usage, data, ck.cksumtype, ck.checksum.as_ref())?;
    }
    let key = EncryptionType::known(ap.authenticator.etype)
        .ok()
        .and_then(|et| ReplayKey::from_ciphertext(et, ap.authenticator.cipher.as_ref()))
        .ok_or_else(|| Error::Crypto("ciphertext shorter than its checksum".into()))?
        .file2();
    if replay.check_and_store(key, params.skew) {
        return Err(Error::KrbError {
            code: err::REPEAT,
            text: Some("authenticator replay".into()),
        });
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

// MIT: `krb5_check_transited_list` (chk_trans.c:309-355)
/// Anonymous crealm skips the transited check.
fn check_ap_req_transited(
    part: &EncTicketPart,
    srealm: &str,
    capaths: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
) -> Result<(), Error> {
    if part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED) {
        return Ok(());
    }
    let raw = part.transited.contents.as_ref();
    if raw.is_empty() || raw[0] == 0 {
        return Ok(());
    }
    let crealm = String::from_utf8_lossy(part.crealm.as_bytes());
    if crealm == "WELLKNOWN:ANONYMOUS" {
        return Ok(());
    }
    let hops = part
        .transited
        .realms_for(&crealm, srealm)
        .map_err(|_| Error::KrbError {
            code: err::ILL_CR_TKT,
            text: Some("ill-formed transited list".into()),
        })?;
    let allowed = walk_realm_tree(capaths, &crealm, srealm);
    for h in hops {
        if !allowed.iter().any(|a| a == &h) {
            return Err(Error::KrbError {
                code: err::ILL_CR_TKT,
                text: Some("transited realm not in hierarchy".into()),
            });
        }
    }
    Ok(())
}

// MIT: `krb5_walk_realm_tree` (walk_rtree.c:96-120)
/// `[capaths]` if present, else the hierarchical realm tree.
fn walk_realm_tree(
    capaths: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
    client: &str,
    server: &str,
) -> Vec<String> {
    if client == server {
        return Vec::new();
    }
    if let Some(vals) = capaths.get(client).and_then(|m| m.get(server)) {
        let mut out = vec![client.to_owned()];
        if !(vals.len() == 1 && vals[0] == ".") {
            for v in vals {
                if v != "." {
                    out.push(v.clone());
                }
            }
        }
        out.push(server.to_owned());
        return out;
    }
    hierarchical_walk_realms(client, server)
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
