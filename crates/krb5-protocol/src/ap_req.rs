//! AP-REQ construction (RFC 4120 §5.5.1) and service-side verification.

use std::collections::BTreeMap;
use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt, verify_checksum_type,
};
use krb5_types::transited::hierarchical_walk_realms;
use krb5_types::{
    ApOptions, ApReq, Authenticator, EncTicketPart, EncryptedData, HostAddresses, KerberosTime,
    PrincipalName, Realm, Ticket, err, flag_bit, ku,
};

use crate::error::Error;
use crate::replay::{ReplayCache, ReplayKey};

/// Clock-skew window (seconds) used when the caller does not specify one.
pub const DEFAULT_SKEW: i64 = 300;

/// Parameters for [`verify_ap_req`].
pub struct ApVerifyParams<'a> {
    /// Long-term keys available (keytab entries); kvno selects.
    pub keys: &'a [ProtocolKey],
    /// Optional kvno per `keys` slot (`krb5_kt_get_entry` / KDB keytab).
    pub key_kvnos: Option<&'a [u32]>,
    /// Optional kvno hint from the ticket.
    pub kvno: Option<u32>,
    /// Expected server name; ticket sname must match.
    pub expected_server: Option<&'a PrincipalName>,
    /// Expected server realm.
    pub expected_realm: Option<&'a str>,
    /// Clock skew in seconds.
    pub skew: i64,
    /// Optional client addresses to check against ticket caddr.
    pub addresses: Option<&'a HostAddresses>,
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
            kvno: None,
            expected_server: None,
            expected_realm: None,
            skew: DEFAULT_SKEW,
            addresses: None,
            now: None,
        }
    }
}

/// Build an AP-REQ from a service ticket and its session key.
///
/// # Errors
///
/// Returns crypto or DER failures.
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
/// Returns crypto or DER failures.
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
/// Returns crypto or DER failures.
pub fn build_ap_req_mutual_seq(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    seq_number: u32,
) -> Result<ApReq, Error> {
    let now = KerberosTime::now();
    let usec = krb5_types::Microseconds::from_subsec_micros(now.0.timestamp_subsec_micros());
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
/// Returns crypto or DER failures.
pub fn build_ap_req_with_cksum(
    ticket: Ticket,
    session_key: &ProtocolKey,
    crealm: &Realm,
    cname: &PrincipalName,
    ap_options: ApOptions,
    cksum: Option<krb5_types::Checksum>,
    subkey: Option<krb5_types::EncryptionKey>,
) -> Result<ApReq, Error> {
    let now = KerberosTime::now();
    let usec = krb5_types::Microseconds::from_subsec_micros(now.0.timestamp_subsec_micros());
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
    let der = encode(&authenticator)?;
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
/// Returns [`Error`] on truncated input, HMAC failure, replay, skew, expiry,
/// or server-name mismatch.
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
/// See [`verify_ap_req`].
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
    if !sname_match(
        params.expected_server,
        params.expected_realm,
        &ap.ticket.sname,
        ap.ticket.realm.as_bytes(),
        ignore_host,
    ) {
        return Err(Error::KrbError {
            code: err::NOT_US,
            text: Some("ticket sname does not match expected server".into()),
        });
    }
    let tkt_usage = KeyUsage::new(ku::TICKET)?;
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
    // MIT kt_file.c:355-384 `krb5_ktfile_get_entry`: an entry for the
    // principal and enctype at another kvno is `found_wrong_kvno` →
    // KRB5_KT_KVNONOTFOUND when nothing matched.
    let mut found_wrong_kvno = false;
    let mut tried_any = false;
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
        match decrypt(key, tkt_usage, ap.ticket.enc_part.cipher.as_ref()) {
            Ok(tkt_plain) => match decode::<EncTicketPart>(&tkt_plain) {
                Ok(p) => {
                    ticket_part = Some(p);
                    break;
                }
                Err(e) => last_err = e.into(),
            },
            Err(e) => last_err = e.into(),
        }
    }
    let Some(ticket_part) = ticket_part else {
        // MIT rd_req_dec.c:118-148 `keytab_fetch_error`: KVNONOTFOUND is
        // KRB5KRB_AP_ERR_BADKEYVER "Cannot find key for %s kvno %d in
        // keytab" when the pinned name is the ticket's server
        // (`krb5_principal_compare`, name type ignored), else NOT_US;
        // no entry at all stays NOKEY.
        if found_wrong_kvno && !tried_any && params.expected_server.is_some() {
            let same_princ = params
                .expected_server
                .is_some_and(|s| s.name_string == ap.ticket.sname.name_string)
                && params
                    .expected_realm
                    .is_none_or(|r| r.as_bytes() == ap.ticket.realm.as_bytes());
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
        return Err(last_err);
    };
    let now = params.now.clone().unwrap_or_else(KerberosTime::now);
    let skew = params.skew.max(0);
    // MIT krb5int_validate_times (valid_times.c:36-58): use starttime, else
    // authtime, for the not-yet-valid test — a ticket with no starttime is
    // gated by its authtime, not left unchecked.
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
    // MIT rd_req_dec.c:634-638 checks the INVALID flag after krb5int_validate_times
    // and returns KRB5KRB_AP_ERR_TKT_INVALID, not TKT_NYV.
    if ticket_part.flags.invalid() {
        return Err(Error::KrbError {
            code: err::TKT_INVALID,
            text: Some("Ticket has invalid flag set".into()),
        });
    }
    if let Some(addrs) = params.addresses
        && let Some(caddr) = &ticket_part.caddr
        && caddr != addrs
    {
        return Err(Error::KrbError {
            code: err::BADADDR,
            text: Some("address mismatch".into()),
        });
    }
    let srealm = String::from_utf8_lossy(ap.ticket.realm.as_bytes());
    check_ap_req_transited(&ticket_part, &srealm)?;
    let session_etype = EncryptionType::known(ticket_part.key.keytype)?;
    let session = ProtocolKey::from_bytes(session_etype, ticket_part.key.keyvalue.as_ref())?;
    let auth_usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR)?;
    let auth_plain = decrypt(&session, auth_usage, ap.authenticator.cipher.as_ref())?;
    let authenticator: Authenticator = decode(&auth_plain)?;
    authenticator
        .cusec
        .validate()
        .map_err(|e| Error::ReplyMismatch(e.to_string()))?;
    if authenticator.cname != ticket_part.cname || authenticator.crealm != ticket_part.crealm {
        return Err(Error::KrbError {
            code: err::BAD_INTEGRITY,
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
    let server = format!(
        "{}@{}",
        ap.ticket.sname.components_joined(),
        String::from_utf8_lossy(ap.ticket.realm.as_bytes())
    );
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
        sname: ap.ticket.sname.clone(),
        srealm: ap.ticket.realm.clone(),
        authenticator,
        mutual_required: ap.ap_options.wants_mutual(),
        ticket_etype: tkt_etype,
    })
}

/// MIT `rd_req_dec.c:590-610`: when `TRANSITED_POLICY_CHECKED` is unset
/// and the transited field is non-empty, `krb5_check_transited_list`
/// (`chk_trans.c:309-355`) requires every hop in the
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

/// MIT `sname_match.c:30-57` `krb5_sname_match`.
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
