//! AP-REQ construction (RFC 4120 §5.5.1) and service-side verification.
//!
//! Every verify takes its skew window from `ApVerifyParams::skew`, a
//! required field; `ApVerifyParams::single_key` and `verify_init_creds`
//! pass `DEFAULT_SKEW`, 300 seconds. A ticket whose start (starttime,
//! else authtime) or end lies outside that window, or an authenticator
//! whose ctime does, is not a successful verify.

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

/// Clock-skew window in seconds, passed by [`ApVerifyParams::single_key`], `verify_init_creds`,
/// the GSS acceptor (`krb5-gss`) and the kpasswd listener (`krb5-admin`).
pub const DEFAULT_SKEW: i64 = 300;

/// Parameters for [`verify_ap_req`].
pub struct ApVerifyParams<'a> {
    /// Long-term keys available (keytab entries); kvno selects.
    pub keys: &'a [ProtocolKey],
    /// Optional kvno per `keys` slot (`krb5_kt_get_entry` / KDB keytab).
    pub key_kvnos: Option<&'a [u32]>,
    /// Optional principal per `keys` slot (a keytab entry's name and realm), for the keytab walk
    /// MIT makes when no server is named. A slot without one is taken as the ticket server's.
    pub key_principals: Option<&'a [(PrincipalName, Realm)]>,
    /// Optional kvno hint from the ticket.
    pub kvno: Option<u32>,
    /// The server named, as MIT's `krb5_rd_req` takes one: a name that is not host-based (or
    /// has a realm and a host) makes its keytab entry the only key tried. With `get_entry` the
    /// ticket's own server name is replaced by it once the ticket decrypts; `keys` name no
    /// principal, so with them the ticket's server must be the named one. `None`, or a
    /// host-based name that matches several keytab principals, walks the keytab.
    pub expected_server: Option<&'a PrincipalName>,
    /// The named server's realm; `None` takes the ticket's.
    pub expected_realm: Option<&'a str>,
    /// For a named server: the lookup MIT's `krb5_kt_get_entry` makes in the keytab type at hand
    /// (the KDB's, for kpasswd), in place of `keys` and `key_kvnos`.
    pub get_entry: Option<KeytabGetEntry<'a>>,
    /// Clock skew in seconds.
    pub skew: i64,
    /// The sender's address, which the ticket's caddr must hold (MIT's auth context remote
    /// address, see [`address_search`]); `None` checks no address.
    pub remote_addr: Option<&'a HostAddress>,
    /// Now (for tests); default wall clock.
    pub now: Option<KerberosTime>,
}

impl<'a> ApVerifyParams<'a> {
    /// Single service key, 300s skew, no name check.
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
            remote_addr: None,
            now: None,
        }
    }
}

/// Why a keytab lookup for the named server found no key.
/// MIT `keytab_fetch_error` (`lib/krb5/krb/rd_req_dec.c:118-148`): `KRB5_KT_NOTFOUND` (no entry) and `KRB5_KT_KVNONOTFOUND` (entries, none at the ticket's kvno) are the two codes of `krb5_kt_get_entry` it names; any other code is passed on as it is.
#[derive(Debug)]
pub enum KeytabLookup {
    /// `KRB5_KT_NOTFOUND`.
    NotFound,
    /// `KRB5_KT_KVNONOTFOUND`.
    KvnoNotFound,
    /// Any other code.
    Other(Error),
}

/// A keytab lookup for the named server: the ticket's kvno (0 when it names none) and enctype in,
/// the entry's key out.
pub type KeytabGetEntry<'a> = &'a dyn Fn(u32, i32) -> Result<ProtocolKey, KeytabLookup>;

/// Whether a ticket whose address list is `list` may come from `addr`.
/// MIT `krb5_address_search` (`lib/krb5/krb/addr_srch.c:48-65`): a ticket with no list, or whose
/// list is one NetBIOS address, holds any address; otherwise `addr` must be one of the list's.
#[must_use]
pub fn address_search(addr: &HostAddress, list: Option<&HostAddresses>) -> bool {
    let Some(list) = list else {
        return true;
    };
    if list.len() == 1 && list[0].addr_type == HostAddress::ADDRTYPE_NETBIOS {
        return true;
    }
    list.iter().any(|a| a == addr)
}

/// Build an AP-REQ from a service ticket and its session key.
///
/// # Errors
///
/// [`Error::Asn1`] when the authenticator does not encode, and [`Error::Crypto`] when encrypting
/// it under `session_key` fails.
pub fn build_ap_req(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
) -> Result<ApReq, Error> {
    build_ap_req_opts(ticket, session_key, crealm, cname, ApOptions::none(), None)
}

/// Build an AP-REQ with explicit `ap_options` and optional checksum over app data.
///
/// # Errors
///
/// [`Error::Asn1`] when the authenticator does not encode, and [`Error::Crypto`] when the
/// checksum over `cksum_data` or the encryption under `session_key` fails.
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

/// Build an AP-REQ with mutual auth and an explicit authenticator sequence.
///
/// MIT `kprop` `sendauth` uses `AP_OPTS_MUTUAL_REQUIRED` and `DO_SEQUENCE`.
///
/// # Errors
///
/// [`Error::Asn1`] when the authenticator does not encode, and [`Error::Crypto`] when encrypting
/// it under `session_key` fails.
pub fn build_ap_req_mutual_seq(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    seq_number: u32,
) -> Result<ApReq, Error> {
    // MIT `generate_authenticator` (`lib/krb5/krb/mk_req_ext.c:327-327`): the time and its microseconds, from `krb5_us_timeofday`.
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

/// Build an AP-REQ with a caller-supplied authenticator checksum (GSS 0x8003).
///
/// # Errors
///
/// [`Error::Asn1`] when the authenticator does not encode, and [`Error::Crypto`] when encrypting
/// it under `session_key` fails.
pub fn build_ap_req_with_cksum(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    ap_options: ApOptions,
    cksum: Option<krb5_types::Checksum>,
    subkey: Option<krb5_types::EncryptionKey>,
) -> Result<ApReq, Error> {
    // MIT `generate_authenticator` (`lib/krb5/krb/mk_req_ext.c:327-327`): the time and its microseconds, from `krb5_us_timeofday`.
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

/// Build an AP-REQ around a caller-made authenticator, which the caller keeps to check the
/// AP-REP's `ctime` / `cusec` against.
///
/// # Errors
///
/// [`Error::Asn1`] when the authenticator does not encode, and [`Error::Crypto`] when encrypting
/// it under `session_key` fails.
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

/// Result of a successful AP-REQ verification.
#[derive(Debug)]
pub struct ApVerifyOk {
    /// Decrypted ticket part.
    pub ticket_part: EncTicketPart,
    /// Ticket server name (acceptor).
    pub sname: krb5_types::PrincipalName,
    /// Ticket realm (acceptor).
    pub srealm: krb5_types::Realm,
    /// Decrypted authenticator.
    pub authenticator: Authenticator,
    /// Whether the initiator requested mutual authentication.
    pub mutual_required: bool,
    /// `Ticket.enc-part.etype` — the service key that decrypted the ticket
    /// (MIT `ticket->enc_part.enctype`, what kpropd's `authorized_principal`
    /// compares an ACL enctype against).
    pub ticket_etype: i32,
}

/// Verify an AP-REQ using a single service key (tests / simple hosts).
///
/// # Errors
///
/// [`Error::KrbError`] with the code of the failed check: `NOKEY` (`service_key` is not the
/// ticket's etype), `TKT_NYV` / `TKT_EXPIRED` (outside 300 seconds), `TKT_INVALID`, `ILL_CR_TKT`
/// (transited), `BADMATCH` (authenticator client), `SKEW`, `REPEAT` (replay).
/// [`Error::Crypto`] when the ticket or the authenticator does not decrypt or the session key is
/// unusable; [`Error::Asn1`] when a part does not decode; [`Error::TruncatedReply`] for an empty
/// `raw`.
pub fn verify_ap_req(
    raw: &[u8],
    service_key: &ProtocolKey,
    replay: &ReplayCache,
) -> Result<ApVerifyOk, Error> {
    verify_ap_req_ex(raw, &ApVerifyParams::single_key(service_key), replay, None)
}

/// Full AP-REQ verify.
///
/// # Errors
///
/// [`Error::KrbError`] with the code of the failed check: `NOT_US` (not the expected server),
/// `NOKEY` / `BADKEYVER` (no key for the etype or kvno), `TKT_NYV` / `TKT_EXPIRED` (outside
/// `params.skew`), `TKT_INVALID`, `BADADDR`, `ILL_CR_TKT` (transited), `BADMATCH`
/// (authenticator client), `SKEW`, `REPEAT` (replay). [`Error::Crypto`] when the ticket or the
/// authenticator does not decrypt, the session key is unusable, or the checksum over `app_cksum`
/// does not verify; [`Error::Asn1`] when a part does not decode; [`Error::TruncatedReply`] for an
/// empty `raw`.
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

/// The named server's name and realm (the ticket's realm when none is named).
fn named_server(ap: &ApReq, params: &ApVerifyParams<'_>) -> (PrincipalName, String) {
    let realm = params.expected_realm.map_or_else(
        || String::from_utf8_lossy(ap.ticket.realm.as_bytes()).into_owned(),
        str::to_owned,
    );
    let name = params
        .expected_server
        .cloned()
        .unwrap_or_else(|| ap.ticket.sname.clone());
    (name, realm)
}

/// The ticket's enc-part decrypted under one key, as `try_one_entry` does.
/// MIT `try_one_entry` (`rd_req_dec.c:290-320`): `krb5_decrypt_tkt_part` under the entry's key; a ticket that decrypts but does not decode fails with the decoder's code.
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

/// The ticket's enc-part decrypted for a server named explicitly: its own key at the ticket's
/// kvno and enctype, whatever server name the ticket's cleartext carries.
/// MIT `try_one_princ` (`rd_req_dec.c:325-347`): the server's keytab entry at the ticket's kvno and enctype (`krb5_kt_get_entry`, here `params.get_entry` or the `keys`), then `keytab_fetch_error` when there is none and `integrity_error` when its key does not decrypt the ticket; `try_one_entry` then makes the keytab principal the ticket's server.
fn decrypt_for_server(
    ap: &ApReq,
    params: &ApVerifyParams<'_>,
    ignore_host: bool,
    tkt_usage: KeyUsage,
) -> Result<EncTicketPart, Error> {
    // The caller's `keys` carry no principal, so they are taken for the named server's only when the
    // ticket's own server is the named one; a keytab lookup (`get_entry`) is for the named server by
    // construction, and its ticket's cleartext server is not looked at, as MIT's is not.
    if params.get_entry.is_none()
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
    // MIT `krb5_ktfile_get_entry` (`kt_file.c:355-384`): an entry for the principal and enctype
    // at another kvno is `found_wrong_kvno` → KRB5_KT_KVNONOTFOUND when nothing matched.
    let mut found_wrong_kvno = false;
    let mut tried_any = false;
    if let Some(get_entry) = params.get_entry {
        match get_entry(ap.ticket.enc_part.kvno.unwrap_or(0), tkt_etype) {
            Ok(key) => {
                tried_any = true;
                match decrypt_ticket_part(ap, &key, tkt_usage) {
                    Ok(p) => ticket_part = Some(p),
                    Err(e) => last_err = e,
                }
            }
            Err(KeytabLookup::NotFound) => {}
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
        let (name, realm) = named_server(ap, params);
        let tkt_realm = String::from_utf8_lossy(ap.ticket.realm.as_bytes()).into_owned();
        let same_princ = principal_compare(&name, &realm, &ap.ticket.sname, &tkt_realm);
        // MIT `keytab_fetch_error` (`rd_req_dec.c:118-148`): KVNONOTFOUND is
        // KRB5KRB_AP_ERR_BADKEYVER "Cannot find key for %s kvno %d in keytab" when the named
        // server is the ticket's (`krb5_principal_compare`, name type ignored), else NOT_US; no
        // entry at all stays NOKEY.
        if found_wrong_kvno && !tried_any && params.expected_server.is_some() {
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
        // MIT `integrity_error` (`rd_req_dec.c:162-181`): a key that does not decrypt the ticket
        // is BAD_INTEGRITY when the named server is the ticket's, else NOT_US.
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
        return Err(last_err);
    };
    Ok(ticket_part)
}

/// MIT `is_matching` (`rd_req_dec.c:279-286`): no server, or a host-based one with no realm or no host (or with acceptor hostnames ignored), matches several keytab principals, so the keytab is walked.
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

/// The ticket's enc-part decrypted by walking every key that may be the server's.
/// MIT `decrypt_try_server` (`rd_req_dec.c:355-443`): each entry whose principal the server matches is tried when its enctype is the ticket's, whatever its kvno, and what the walk found picks the error.
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
        // MIT `try_one_entry` (`rd_req_dec.c:290-320`): a key that does not decrypt the ticket, or a ticket that then does not decode, is passed over.
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

/// What a keytab walk found, in MIT's names.
#[derive(Default)]
struct KeytabWalk {
    tkt_server_mismatch: bool,
    found_server_match: bool,
    found_tkt_server: bool,
    found_kvno: bool,
    found_higher_kvno: bool,
    found_enctype: bool,
}

/// MIT `iteration_error` (`rd_req_dec.c:208-275`): the code and text for a keytab walk that decrypted nothing, chosen by what it found.
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

/// MIT `rd_req_decoded_opt` (`rd_req_dec.c:634-638`): the invalid flag is tested only after the
/// ticket times. A ticket outside the caller skew, using starttime or else authtime, is not a
/// successful verify.
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
    let ignore_host = krb5_config::load_krb5_conf().is_some_and(|c| c.ignore_acceptor_hostname);
    let tkt_usage = KeyUsage::new(ku::TICKET)?;
    let named = !is_matching(params.expected_server, params.expected_realm, ignore_host);
    let ticket_part = if named {
        decrypt_for_server(&ap, params, ignore_host, tkt_usage)?
    } else {
        decrypt_by_keytab_walk(&ap, params, ignore_host, tkt_usage)?
    };
    // MIT `try_one_entry` (`rd_req_dec.c:315-317`): the keytab principal becomes the ticket's server, so for a keytab lookup the cleartext
    // name and realm of a ticket that decrypted under the named server's key are not kept.
    let (sname, srealm) = if named && params.get_entry.is_some() {
        let (name, realm) = named_server(&ap, params);
        let realm = krb5_types::try_ascii(&realm).unwrap_or_else(|_| ap.ticket.realm.clone());
        (name, realm)
    } else {
        (ap.ticket.sname.clone(), ap.ticket.realm.clone())
    };
    let tkt_etype = ap.ticket.enc_part.etype;
    let now = params.now.clone().unwrap_or_else(KerberosTime::now);
    let skew = params.skew.max(0);
    // MIT `krb5int_validate_times` (`valid_times.c:36-57`): use starttime, else authtime, for
    // the not-yet-valid test — a ticket with no starttime is gated by its authtime, not left
    // unchecked.
    let start = ticket_part
        .starttime
        .as_ref()
        .unwrap_or(&ticket_part.authtime);
    if now.delta_seconds(start) < -skew {
        return Err(Error::KrbError {
            code: err::TKT_NYV,
            text: Some("ticket not yet valid".into()),
        });
    }
    if ticket_part.endtime.delta_seconds(&now) < -skew {
        return Err(Error::KrbError {
            code: err::TKT_EXPIRED,
            text: Some("ticket expired".into()),
        });
    }
    // MIT `rd_req_decoded_opt` (`rd_req_dec.c:634-638`): checks the INVALID flag after
    // krb5int_validate_times and returns KRB5KRB_AP_ERR_TKT_INVALID, not TKT_NYV.
    if ticket_part.flags.invalid() {
        return Err(Error::KrbError {
            code: err::TKT_INVALID,
            text: Some("Ticket has invalid flag set".into()),
        });
    }
    // MIT `rd_req_decoded_opt` (`rd_req_dec.c:536-540`): with a remote address set, the ticket's
    // address list must hold it.
    if let Some(remote) = params.remote_addr
        && !address_search(remote, ticket_part.caddr.as_ref())
    {
        return Err(Error::KrbError {
            code: err::BADADDR,
            text: Some("Incorrect net address".into()),
        });
    }
    let srealm_text = String::from_utf8_lossy(srealm.as_bytes()).into_owned();
    check_ap_req_transited(&ticket_part, &srealm_text)?;
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
    // MIT `rd_req_decoded_opt` (`lib/krb5/krb/rd_req_dec.c:631-631`): only the authenticator's ctime is checked, against the clock skew; its cusec is taken as it is, past 999999 too.
    // MIT `rd_req_decoded_opt` (`rd_req_dec.c:530-532`): `krb5_principal_compare` (realm and
    // components, not the name type) or KRB5KRB_AP_ERR_BADMATCH.
    if !authenticator.cname.components_eq(&ticket_part.cname)
        || authenticator.crealm != ticket_part.crealm
    {
        return Err(Error::KrbError {
            code: err::BADMATCH,
            text: Some("authenticator/ticket client mismatch".into()),
        });
    }
    let skew_delta = now.delta_seconds(&authenticator.ctime).unsigned_abs();
    let skew_limit = u64::try_from(skew.max(0)).unwrap_or(u64::MAX);
    if skew_delta > skew_limit {
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
    let client = format!(
        "{}@{}",
        authenticator.cname.components_joined(),
        String::from_utf8_lossy(authenticator.crealm.as_bytes())
    );
    let server = format!("{}@{}", sname.components_joined(), srealm_text);
    let key = ReplayKey {
        client,
        server,
        ctime: authenticator.ctime.unix_seconds(),
        cusec: authenticator.cusec.get(),
        auth_hash: ReplayCache::hash_authenticator(ap.authenticator.cipher.as_ref()),
    };
    if replay.check_and_store(key) {
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

/// MIT `rd_req_decoded_opt` (`rd_req_dec.c:590-610`): when `TRANSITED_POLICY_CHECKED` is unset
/// and the transited field is non-empty, `krb5_check_transited_list` checks the transited list.
/// MIT `krb5_check_transited_list` (`chk_trans.c:309-355`): requires every hop in the
/// `krb5_walk_realm_tree` list. Anonymous crealm skips the check.
fn check_ap_req_transited(part: &EncTicketPart, srealm: &str) -> Result<(), Error> {
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
    let capaths = krb5_config::load_krb5_conf()
        .map(|c| c.capaths)
        .unwrap_or_default();
    let allowed = walk_realm_tree(&capaths, &crealm, srealm);
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

/// MIT `krb5_walk_realm_tree` (`walk_rtree.c:96-120`): `[capaths]` if
/// present, else `rtree_hier_realms`. Same-realm is empty.
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

/// MIT `krb5_sname_match` (`sname_match.c:30-57`): whether `princ` matches the `matching` name.
///
/// `matching == NULL` accepts any ticket server. A two-component
/// `NT-SRV-HST` matching name checks realm (when present), the service
/// component, and the hostname unless `ignore_acceptor_hostname` or the
/// matching hostname is empty. Other name-types use
/// `krb5_principal_compare` (name-string + realm; name-type ignored).
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
