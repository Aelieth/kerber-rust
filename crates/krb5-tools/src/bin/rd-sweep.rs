//! The application side of the decode sweep, for `scripts/rd-priv-oracle-gate.sh`: an AP-REQ, a
//! KRB-PRIV and a KRB-SAFE whose authenticator, `EncKrbPrivPart` and KRB-SAFE-BODY are broken as
//! the decode sweep breaks a message (`der_breaks.rs`), each re-encrypted or re-signed so only the
//! break is wrong, and the three messages themselves broken the same way. MIT 1.22.2's
//! `krb5_rd_req`, `krb5_rd_priv` and `krb5_rd_safe` (the rd-priv oracle under `scripts/oracle`)
//! answer each; the Rust acceptor must answer as MIT does.
//!
//! - `rd-sweep cases`: the service key line, then `id<TAB>req|priv|safe<TAB>ap-req<TAB>msg|-`.
//! - `rd-sweep judge <cases> <mit>`: the Rust answers to the same cases against MIT's
//!   (`id<TAB>code`); exit 1 when any parts from MIT's.
//! - `rd-sweep kpasswd <keytab> <client> [setpw] [raddr=IP] [entry=N]`: the same cases as RFC 3244
//!   kpasswd frames for the realm's `kadmin/changepw`, whose ticket key, enctype and kvno are entry
//!   N's of the keytab (0 unless given): `id<TAB>frame-hex`, `[plen][vno][aplen][AP-REQ][KRB-PRIV]`.
//!   The `ap-req/*` cases carry the pristine KRB-PRIV, the `krb-priv/*` cases the pristine AP-REQ;
//!   KRB-SAFE is not read by kpasswd. With `setpw` the version is 0xff80 and the user data a
//!   ChangePasswdData for `<client>`, and the `setpw/*` cases break that. `raddr=IP` is the
//!   receiver address each KRB-PRIV carries (none by default).
//! - `rd-sweep judge-explicit <frames> <mit> <dump> <master-password>`: the answer of kadmind's
//!   kpasswd acceptor (`handle_kpasswd_rfc3244` over the realm of the MIT dump) to each frame
//!   against MIT's (`id<TAB>0|req[:detail]|priv[:detail]|drop`) from the rd-priv oracle's `kpasswd`
//!   mode; exit 1 when any parts from MIT's.
//! - `rd-sweep kadmind <keytab> <client>`: AP-REQs for the keytab's service principals (as `ktadd` made it:
//!   `kadmin/admin`, `kadmin/changepw`, `kadmin/history`, a host), each sealed in each of its keys, and in its
//!   first with the kvno wrong or the cleartext server another's: `id<TAB>ap-req-hex`.
//! - `rd-sweep judge-kdb <cases> <mit> <dump> <master-password>`: what kadmind's GSS acceptor reads from the
//!   KDB keytab (`kdb_rd_req` over the realm of the MIT dump) for each case, with no name (RPCSEC_GSS), as
//!   `kadmin/admin` and as `kadmin/changepw` (AUTH_GSSAPI's names), against MIT's `krb5_rd_req`
//!   (`id<TAB>noname<TAB>admin<TAB>changepw`, each `0` or the code) from the oracle's `kadmind` mode, the
//!   three answers joined by `|` in the `SAME` and `PART` lines; exit 1 when any parts from MIT's.
//! - `rd-sweep kadmind-init <host:port> <keytab> <client> [service=P] [entry=N] [flavor=rpcsec|agss]`: an
//!   INIT call to a kadmind with a ticket forged in the Nth key of the keytab's service (`kadmin/admin`,
//!   entry 0 by default; RPCSEC_GSS, or AUTH_GSSAPI with `flavor=agss`), and one line saying what it got:
//!   `ACCEPTED gss_major=<n> <label>` (AUTH_GSSAPI answers a refused context so, GSS_S_FAILURE) or
//!   `DENIED auth_stat=<n> <label>`. MIT's kadmind and ours take the first key
//!   alone, so entry 1 and later are refused (the gates and the lab show both).

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

include!("../der_breaks.rs");

use std::process::ExitCode;

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum, encrypt};
use krb5_protocol::{
    AcceptorAuthContext, AcceptorConfig, ApVerifyParams, Error, Keytab, ReplayCache,
    unwrap_krb_priv_ex, verify_ap_req_ex,
};
use krb5_types::{
    ApOptions, ApReq, Authenticator, AuthorizationDataValue, ChangePasswdData, Checksum,
    EncKrbPrivPart, EncTicketPart, EncryptedData, EncryptionKey, HostAddress, KerberosTime,
    KrbError, KrbPriv, Microseconds, OctetString, PrincipalName, Ticket, TicketFlags,
    TransitedEncoding, ascii, ku,
};

/// The service the tickets are for, its key and kvno (the oracle puts them in a MEMORY keytab).
const SERVICE: &str = "host/oracle.kerber.test@KERBER.TEST";
const SERVICE_KEY: [u8; 32] = [0x43; 32];
const SESSION_KEY: [u8; 32] = [0x44; 32];
const SUBKEY: [u8; 32] = [0x45; 32];
/// The sender's (127.0.0.1) and the receiver's (10.0.0.1) addresses, as the rd-safe oracle's.
const SENDER: [u8; 4] = [127, 0, 0, 1];
const RECEIVER: [u8; 4] = [10, 0, 0, 1];

fn addr(octets: [u8; 4]) -> HostAddress {
    HostAddress {
        addr_type: 2,
        address: OctetString::from(octets.to_vec()),
    }
}

fn key(bytes: &[u8]) -> Result<ProtocolKey, String> {
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, bytes).map_err(|e| e.to_string())
}

fn usage(n: u32) -> Result<KeyUsage, String> {
    KeyUsage::new(n).map_err(|e| e.to_string())
}

macro_rules! der {
    ($v:expr) => {
        encode($v).map_err(|e| e.to_string())
    };
}

fn root(bytes: &[u8]) -> Result<Der, String> {
    der_parse(bytes)
        .and_then(|mut v| (v.len() == 1).then(|| v.remove(0)))
        .ok_or_else(|| "not one DER element".to_string())
}

/// The AP-REQ for `authenticator` (its DER as given), in a ticket for [`SERVICE`].
fn ap_req(authenticator: &[u8], now: &KerberosTime) -> Result<Vec<u8>, String> {
    let client = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let part = EncTicketPart {
        flags: TicketFlags::from_u32(0x4000_0000),
        key: EncryptionKey {
            keytype: 18,
            keyvalue: OctetString::from(SESSION_KEY.to_vec()),
        },
        crealm: ascii("KERBER.TEST"),
        cname: client,
        transited: TransitedEncoding::empty(),
        authtime: now.add_seconds(-60).map_err(|e| e.to_string())?,
        starttime: None,
        endtime: now.add_seconds(3600).map_err(|e| e.to_string())?,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let ticket = Ticket {
        tkt_vno: Ticket::VNO,
        realm: ascii("KERBER.TEST"),
        sname: PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "oracle.kerber.test"]),
        enc_part: EncryptedData {
            etype: 18,
            kvno: Some(1),
            cipher: encrypt(&key(&SERVICE_KEY)?, usage(ku::TICKET)?, &der!(&part)?)
                .map_err(|e| e.to_string())?
                .into(),
        },
    };
    let ap = ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
        ticket,
        authenticator: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: encrypt(
                &key(&SESSION_KEY)?,
                usage(ku::AP_REQ_AUTHENTICATOR)?,
                authenticator,
            )
            .map_err(|e| e.to_string())?
            .into(),
        },
    };
    der!(&ap)
}

/// A KRB-PRIV around `part` (its DER as given), encrypted in the authenticator's subkey.
fn krb_priv(part: &[u8]) -> Result<Vec<u8>, String> {
    let msg = KrbPriv {
        pvno: KrbPriv::PVNO,
        msg_type: KrbPriv::MSG_TYPE,
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: encrypt(&key(&SUBKEY)?, usage(ku::KRB_PRIV_ENC_PART)?, part)
                .map_err(|e| e.to_string())?
                .into(),
        },
    };
    der!(&msg)
}

/// A KRB-SAFE around `body` (its DER as given), its checksum over those octets in the subkey.
fn krb_safe(body: &[u8]) -> Result<Vec<u8>, String> {
    let mac =
        checksum(&key(&SUBKEY)?, usage(ku::KRB_SAFE_CKSUM)?, body).map_err(|e| e.to_string())?;
    let cksum = Checksum {
        cksumtype: 16,
        checksum: mac.into(),
    };
    let int = |v: u8| Der::Prim(0x02, vec![v]);
    let body = root(body).unwrap_or(Der::Raw(body.to_vec()));
    let safe = Der::Cons(
        0x74,
        vec![Der::Cons(
            0x30,
            vec![
                Der::Cons(0xa0, vec![int(5)]),
                Der::Cons(0xa1, vec![int(20)]),
                Der::Cons(0xa2, vec![body]),
                Der::Cons(0xa3, vec![root(&der!(&cksum)?)?]),
            ],
        )],
    );
    Ok(safe.bytes())
}

/// One case: its id, what the acceptor reads (`req`, `priv` or `safe`), the AP-REQ, and the
/// KRB-PRIV or KRB-SAFE after it.
type RdCase = (String, &'static str, Vec<u8>, Option<Vec<u8>>);

/// Every case: the pristine AP-REQ, KRB-PRIV and KRB-SAFE; each with its authenticator,
/// `EncKrbPrivPart` or KRB-SAFE-BODY broken each way; then each itself broken each way.
fn cases() -> Result<Vec<RdCase>, String> {
    let now = KerberosTime::now();
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: ascii("KERBER.TEST"),
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        cksum: Some(Checksum {
            cksumtype: 16,
            checksum: OctetString::from(vec![0xcc; 12]),
        }),
        cusec: Microseconds(COUNTER),
        ctime: now.clone(),
        subkey: Some(EncryptionKey {
            keytype: 18,
            keyvalue: OctetString::from(SUBKEY.to_vec()),
        }),
        seq_number: Some(COUNTER),
        authorization_data: Some(vec![
            AuthorizationDataValue {
                ad_type: 600,
                ad_data: OctetString::from(b"a".to_vec()),
            },
            AuthorizationDataValue {
                ad_type: 601,
                ad_data: OctetString::from(b"b".to_vec()),
            },
        ]),
    };
    let part = EncKrbPrivPart {
        user_data: OctetString::from(b"rd-sweep".to_vec()),
        timestamp: Some(now.clone()),
        usec: Some(Microseconds(COUNTER)),
        seq_number: Some(COUNTER),
        s_address: addr(SENDER),
        r_address: Some(addr(RECEIVER)),
    };
    let body = krb5_types::KrbSafeBody {
        user_data: OctetString::from(b"rd-sweep".to_vec()),
        timestamp: Some(now.clone()),
        usec: Some(Microseconds(COUNTER)),
        seq_number: Some(COUNTER),
        s_address: addr(SENDER),
        r_address: Some(addr(RECEIVER)),
    };
    let auth_der = der!(&authenticator)?;
    let ap = ap_req(&auth_der, &now)?;
    let part_der = der!(&part)?;
    let body_der = der!(&body)?;
    let mut out = vec![
        ("ap-req/pristine".to_string(), "req", ap.clone(), None),
        (
            "krb-priv/pristine".to_string(),
            "priv",
            ap.clone(),
            Some(krb_priv(&part_der)?),
        ),
        (
            "krb-safe/pristine".to_string(),
            "safe",
            ap.clone(),
            Some(krb_safe(&body_der)?),
        ),
    ];
    for (place, broken) in all_breaks(&root(&auth_der)?) {
        out.push((
            format!("ap-req/{place}"),
            "req",
            ap_req(&broken.bytes(), &now)?,
            None,
        ));
    }
    for (place, broken) in all_breaks(&root(&part_der)?) {
        out.push((
            format!("krb-priv/{place}"),
            "priv",
            ap.clone(),
            Some(krb_priv(&broken.bytes())?),
        ));
    }
    for (place, broken) in all_breaks(&root(&body_der)?) {
        out.push((
            format!("krb-safe/{place}"),
            "safe",
            ap.clone(),
            Some(krb_safe(&broken.bytes())?),
        ));
    }
    // The AP-REQ, KRB-PRIV and KRB-SAFE themselves broken as sent: nothing is re-encrypted or
    // re-signed, so a KRB-SAFE-BODY broken here also fails its checksum.
    for (place, broken) in all_breaks(&root(&ap)?) {
        out.push((format!("ap-req/{place}"), "req", broken.bytes(), None));
    }
    for (place, broken) in all_breaks(&root(&krb_priv(&part_der)?)?) {
        out.push((
            format!("krb-priv/{place}"),
            "priv",
            ap.clone(),
            Some(broken.bytes()),
        ));
    }
    for (place, broken) in all_breaks(&root(&krb_safe(&body_der)?)?) {
        out.push((
            format!("krb-safe/{place}"),
            "safe",
            ap.clone(),
            Some(broken.bytes()),
        ));
    }
    Ok(out)
}

/// An answer as the oracle prints MIT's: `0` accepted, `asn1` an ASN.1 decode error, `krb5:<n>`
/// the protocol code `n`.
fn rust_answer(kind: &str, ap: &[u8], msg: Option<&[u8]>) -> String {
    let class = |e: &Error| match e {
        Error::Asn1(_) => "asn1".to_string(),
        Error::KrbError { code, .. } => format!("krb5:{code}"),
        Error::Crypto(_) => "krb5:31".to_string(),
        Error::ProgEtypeNosupp => "krb5:150".to_string(),
        Error::ProgSumtypeNosupp => "krb5:153".to_string(),
        Error::BadEnctype => "krb5:188".to_string(),
        Error::NopermEtype(_) => "krb5:236".to_string(),
        other => format!("other:{other}"),
    };
    let Ok(service_key) = key(&SERVICE_KEY) else {
        return "other:key".into();
    };
    let replay = ReplayCache::new();
    // The oracle's MEMORY keytab: one entry, the service at kvno 1. No server is named, so the
    // acceptor walks the keytab as MIT's `krb5_rd_req` with a NULL server does.
    let keys = [service_key];
    let principal = [(
        PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "oracle.kerber.test"]),
        ascii("KERBER.TEST"),
    )];
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: Some(&[1]),
        key_principals: Some(&principal),
        ..ApVerifyParams::single_key(&keys[0])
    };
    let ok = match verify_ap_req_ex(ap, &params, &replay, None) {
        Ok(ok) => ok,
        Err(e) => return class(&e),
    };
    // `krb5_rd_req` sets up the auth context too (`rd_req_decoded_opt`).
    let conf = AcceptorConfig {
        permitted_enctypes: EncryptionType::preferred().to_vec(),
        ..AcceptorConfig::default()
    };
    let mut ac = match AcceptorAuthContext::from_ap_req(&ok, &conf) {
        Ok(ac) => ac,
        Err(e) => return class(&e),
    };
    let (Some(msg), "priv" | "safe") = (msg, kind) else {
        return "0".into();
    };
    ac.set_addrs(Some(addr(RECEIVER)), Some(addr(SENDER)));
    let got = if kind == "priv" {
        ac.rd_priv(msg)
    } else {
        ac.rd_safe(msg)
    };
    got.map_or_else(|e| class(&e), |_| "0".into())
}

fn unhex(h: &str) -> Option<Vec<u8>> {
    (0..h.len())
        .step_by(2)
        .map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

/// What the `kpasswd` cases are made for: the realm's `kadmin/changepw` as a keytab entry holds it, and
/// the client the ticket is for.
struct KpEnv {
    realm: String,
    kvno: u32,
    svc: ProtocolKey,
    etype: i32,
    client: String,
    setpw: bool,
    raddr: Option<[u8; 4]>,
}

/// What a service ticket is made of: who it is for, the server its cleartext names (in the ticket's realm) and
/// the key, enctype and kvno it is sealed in.
struct TicketSpec {
    realm: String,
    client: String,
    srealm: String,
    sname: PrincipalName,
    kvno: Option<u32>,
    etype: i32,
    svc: ProtocolKey,
}

/// The INITIAL ticket `spec` says, its session key `SESSION_KEY`.
fn forged_ticket(spec: &TicketSpec, now: &KerberosTime) -> Result<Ticket, String> {
    let part = EncTicketPart {
        flags: TicketFlags::initial_preauth(),
        key: EncryptionKey {
            keytype: 18,
            keyvalue: OctetString::from(SESSION_KEY.to_vec()),
        },
        crealm: ascii(&spec.realm),
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [spec.client.as_str()]),
        transited: TransitedEncoding::empty(),
        authtime: now.add_seconds(-60).map_err(|e| e.to_string())?,
        starttime: None,
        endtime: now.add_seconds(3600).map_err(|e| e.to_string())?,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    Ok(Ticket {
        tkt_vno: Ticket::VNO,
        realm: ascii(&spec.srealm),
        sname: spec.sname.clone(),
        enc_part: EncryptedData {
            etype: spec.etype,
            kvno: spec.kvno,
            cipher: encrypt(&spec.svc, usage(ku::TICKET)?, &der!(&part)?)
                .map_err(|e| e.to_string())?
                .into(),
        },
    })
}

/// The AP-REQ for `authenticator` (its DER as given), in an INITIAL ticket as `spec` says.
fn ticket_ap_req(
    spec: &TicketSpec,
    authenticator: &[u8],
    now: &KerberosTime,
) -> Result<Vec<u8>, String> {
    let ap = ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
        ticket: forged_ticket(spec, now)?,
        authenticator: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: encrypt(
                &key(&SESSION_KEY)?,
                usage(ku::AP_REQ_AUTHENTICATOR)?,
                authenticator,
            )
            .map_err(|e| e.to_string())?
            .into(),
        },
    };
    der!(&ap)
}

/// The AP-REQ for `authenticator` (its DER as given), in an INITIAL ticket for `kadmin/changepw`
/// sealed in the keytab entry's key.
fn kp_ap_req(env: &KpEnv, authenticator: &[u8], now: &KerberosTime) -> Result<Vec<u8>, String> {
    ticket_ap_req(
        &TicketSpec {
            realm: env.realm.clone(),
            client: env.client.clone(),
            srealm: env.realm.clone(),
            sname: PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]),
            kvno: Some(env.kvno),
            etype: env.etype,
            svc: env.svc.clone(),
        },
        authenticator,
        now,
    )
}

/// A kpasswd request: `[plen:2][vno:2][aplen:2][AP-REQ][KRB-PRIV]` (RFC 3244 section 2).
fn kp_frame(vno: u16, ap: &[u8], msg: &[u8]) -> Vec<u8> {
    let aplen = u16::try_from(ap.len()).unwrap_or(u16::MAX);
    let plen = u16::try_from(6 + ap.len() + msg.len()).unwrap_or(u16::MAX);
    let mut out = Vec::new();
    out.extend_from_slice(&plen.to_be_bytes());
    out.extend_from_slice(&vno.to_be_bytes());
    out.extend_from_slice(&aplen.to_be_bytes());
    out.extend_from_slice(ap);
    out.extend_from_slice(msg);
    out
}

/// The authenticator every request case starts from: the client, a checksum, a subkey and a sequence number.
fn pristine_authenticator(realm: &str, client: &str, now: &KerberosTime) -> Authenticator {
    Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: ascii(realm),
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [client]),
        cksum: Some(Checksum {
            cksumtype: 16,
            checksum: OctetString::from(vec![0xcc; 12]),
        }),
        cusec: Microseconds(COUNTER),
        ctime: now.clone(),
        subkey: Some(EncryptionKey {
            keytype: 18,
            keyvalue: OctetString::from(SUBKEY.to_vec()),
        }),
        seq_number: Some(COUNTER),
        authorization_data: Some(vec![
            AuthorizationDataValue {
                ad_type: 600,
                ad_data: OctetString::from(b"a".to_vec()),
            },
            AuthorizationDataValue {
                ad_type: 601,
                ad_data: OctetString::from(b"b".to_vec()),
            },
        ]),
    }
}

/// Every kpasswd case as a frame: the pristine request (twice, as `ap-req/pristine` and
/// `krb-priv/pristine`); the authenticator and the `EncKrbPrivPart` broken each way and re-encrypted;
/// the AP-REQ and the KRB-PRIV themselves broken each way; and, for `setpw`, the ChangePasswdData
/// broken each way and one that names no target.
fn kp_cases(env: &KpEnv) -> Result<Vec<(String, Vec<u8>)>, String> {
    let now = KerberosTime::now();
    let vno: u16 = if env.setpw { 0xff80 } else { 1 };
    let authenticator = pristine_authenticator(&env.realm, &env.client, &now);
    let user_data: Vec<u8> = if env.setpw {
        let cpd = ChangePasswdData {
            newpasswd: OctetString::from(b"rd-sweep".to_vec()),
            targname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [env.client.as_str()]),
            targrealm: ascii(&env.realm),
        };
        der!(&cpd)?
    } else {
        b"rd-sweep".to_vec()
    };
    let part_of = |ud: &[u8]| EncKrbPrivPart {
        user_data: OctetString::from(ud.to_vec()),
        timestamp: Some(now.clone()),
        usec: Some(Microseconds(COUNTER)),
        seq_number: Some(COUNTER),
        s_address: addr(SENDER),
        r_address: env.raddr.map(addr),
    };
    let auth_der = der!(&authenticator)?;
    let ap = kp_ap_req(env, &auth_der, &now)?;
    let part_der = der!(&part_of(&user_data))?;
    let priv_ok = krb_priv(&part_der)?;
    let mut out = vec![
        ("ap-req/pristine".to_string(), kp_frame(vno, &ap, &priv_ok)),
        (
            "krb-priv/pristine".to_string(),
            kp_frame(vno, &ap, &priv_ok),
        ),
    ];
    for (place, broken) in all_breaks(&root(&auth_der)?) {
        out.push((
            format!("ap-req/{place}"),
            kp_frame(vno, &kp_ap_req(env, &broken.bytes(), &now)?, &priv_ok),
        ));
    }
    for (place, broken) in all_breaks(&root(&part_der)?) {
        out.push((
            format!("krb-priv/{place}"),
            kp_frame(vno, &ap, &krb_priv(&broken.bytes())?),
        ));
    }
    for (place, broken) in all_breaks(&root(&ap)?) {
        out.push((
            format!("ap-req/{place}"),
            kp_frame(vno, &broken.bytes(), &priv_ok),
        ));
    }
    for (place, broken) in all_breaks(&root(&priv_ok)?) {
        out.push((
            format!("krb-priv/{place}"),
            kp_frame(vno, &ap, &broken.bytes()),
        ));
    }
    if env.setpw {
        for (place, broken) in all_breaks(&root(&user_data)?) {
            let p = der!(&part_of(&broken.bytes()))?;
            out.push((format!("setpw/{place}"), kp_frame(vno, &ap, &krb_priv(&p)?)));
        }
        // A ChangePasswdData with no target (MIT refuses it: the target is required).
        let no_target = Der::Cons(
            0x30,
            vec![Der::Cons(0xa0, vec![Der::Prim(0x04, b"rd-sweep".to_vec())])],
        );
        let p = der!(&part_of(&no_target.bytes()))?;
        out.push((
            "setpw/no-target".to_string(),
            kp_frame(vno, &ap, &krb_priv(&p)?),
        ));
    }
    Ok(out)
}

/// `rd-sweep kpasswd <keytab> <client> [setpw] [raddr=IP] [entry=N]`: the frames, one `id<TAB>hex`
/// line each.
fn kpasswd(keytab: &str, client: &str, opts: &[String]) -> Result<(), String> {
    let (mut setpw, mut raddr, mut pick) = (false, None, 0usize);
    for o in opts {
        if o == "setpw" {
            setpw = true;
        } else if let Some(v) = o.strip_prefix("raddr=") {
            let octets: Vec<u8> = v.split('.').filter_map(|x| x.parse().ok()).collect();
            if v.split('.').count() != 4 {
                return Err(format!("bad raddr {v}"));
            }
            raddr = Some(<[u8; 4]>::try_from(octets).map_err(|_| format!("bad raddr {v}"))?);
        } else if let Some(n) = o.strip_prefix("entry=") {
            pick = n.parse().map_err(|_| format!("bad entry {n}"))?;
        } else {
            return Err(format!("unknown option {o}"));
        }
    }
    let bytes = std::fs::read(keytab).map_err(|e| format!("{keytab}: {e}"))?;
    let kt = Keytab::parse(&bytes).map_err(|e| format!("{keytab}: {e}"))?;
    let entry = kt.entries.get(pick).ok_or("no such keytab entry")?;
    eprintln!(
        "rd-sweep: entry {pick} of {}: etype {} kvno {}",
        kt.entries.len(),
        entry.key.etype().to_iana(),
        entry.kvno
    );
    let env = KpEnv {
        realm: String::from_utf8_lossy(entry.realm.as_bytes()).into_owned(),
        kvno: entry.kvno,
        svc: entry.key.clone(),
        etype: entry.key.etype().to_iana(),
        client: client.to_owned(),
        setpw,
        raddr,
    };
    for (id, frame) in kp_cases(&env)? {
        println!("{id}\t{}", hex(&frame));
    }
    Ok(())
}

/// How kadmind's kpasswd answers a frame, as far as `krb5_rd_req` and `krb5_rd_priv` decide it: `req`
/// when the AP-REQ is refused (AUTHERROR "Failed reading application request"), `priv` when the
/// KRB-PRIV is (HARDERROR "Failed decrypting request"), `0` when both are read, `drop` when no
/// reply is made.
fn explicit_answer(
    shared: &krb5_kdc::SharedDump,
    acl: &krb5_kdc::Acl,
    conf: &AcceptorConfig,
    frame: &[u8],
) -> String {
    let Ok(rep) = krb5_admin::handle_kpasswd_rfc3244(shared, acl, conf, &ReplayCache::new(), frame)
    else {
        return "drop".into();
    };
    if rep.len() < 6 {
        return "other:short".into();
    }
    if rep[4..6] == [0, 0] {
        // A framed KRB-ERROR: its e-data is the result code (3) and the text.
        let e_data = krb5_asn1::decode::<KrbError>(&rep[6..])
            .ok()
            .and_then(|e| e.e_data);
        return match e_data.as_ref().map(AsRef::as_ref) {
            Some([0, 3, ..]) => "req".into(),
            other => format!("other:krb-error {other:?}"),
        };
    }
    let Ok((_, priv_der)) = krb5_admin::parse_kpasswd_rep(&rep) else {
        return "other:reply".into();
    };
    // The reply is sealed in the authenticator's subkey, else the ticket's session key.
    for k in [SUBKEY, SESSION_KEY] {
        let Ok(k) = key(&k) else { continue };
        if let Ok(d) = unwrap_krb_priv_ex(&k, &priv_der, &ReplayCache::new(), false, false) {
            return if d.starts_with(&[0, 2]) && d[2..] == *b"Failed decrypting request" {
                "priv".into()
            } else {
                "0".into()
            };
        }
    }
    "other:reply".into()
}

/// kadmind's acceptor profile values: the KDC context's profile, kdc.conf and then the krb5.conf
/// files, read once.
fn kdc_context_conf() -> AcceptorConfig {
    let mut files = vec![krb5_config::kdc_conf_path()];
    files.extend(krb5_config::krb5_conf_paths());
    krb5_config::load_krb5_conf_paths(files)
        .as_ref()
        .map_or_else(
            |_| AcceptorConfig::default(),
            AcceptorConfig::from_krb5_conf,
        )
}

/// `rd-sweep judge-explicit <frames> <mit> <dump> <master-password>`.
fn judge_explicit(frames: &str, mit: &str, dump: &str, password: &str) -> Result<bool, String> {
    let frames = std::fs::read_to_string(frames).map_err(|e| format!("{frames}: {e}"))?;
    let mit = std::fs::read_to_string(mit).map_err(|e| format!("{mit}: {e}"))?;
    let mit: std::collections::HashMap<&str, &str> =
        mit.lines().filter_map(|l| l.split_once('\t')).collect();
    let store = krb5_kdc::load_dump_path(std::path::Path::new(dump), password.as_bytes())
        .map_err(|e| format!("{dump}: {e}"))?;
    let shared = krb5_kdc::shared_dump(store);
    let acl = krb5_kdc::Acl::new();
    let conf = kdc_context_conf();
    let (mut n, mut parts) = (0, 0);
    for line in frames.lines().filter(|l| !l.starts_with('#')) {
        let Some((id, hexed)) = line.split_once('\t') else {
            return Err(format!("bad frame line {line}"));
        };
        let frame = unhex(hexed).ok_or("bad frame hex")?;
        let ours = explicit_answer(&shared, &acl, &conf, &frame);
        let theirs = mit.get(id).copied().unwrap_or("none");
        n += 1;
        if theirs.split(':').next() == Some(ours.as_str()) {
            println!("SAME\t{id}\t{theirs}");
        } else {
            parts += 1;
            println!("PART\t{id}\tMIT {theirs}\tRust {ours}");
        }
    }
    println!("{parts} of {n} cases part from MIT");
    Ok(parts == 0)
}

/// A service principal of the keytab and its keys, as the entries hold them.
struct KaService {
    realm: String,
    name: PrincipalName,
    keys: Vec<(i32, u32, ProtocolKey)>,
}

/// The services of a keytab, in order of first appearance, with each one's entries in file order.
fn ka_services(kt: &Keytab) -> Vec<KaService> {
    let mut out: Vec<KaService> = Vec::new();
    for e in &kt.entries {
        let realm = String::from_utf8_lossy(e.realm.as_bytes()).into_owned();
        let entry = (e.key.etype().to_iana(), e.kvno, e.key.clone());
        match out
            .iter_mut()
            .find(|s| s.realm == realm && s.name.name_string == e.name.name_string)
        {
            Some(s) => s.keys.push(entry),
            None => out.push(KaService {
                realm,
                name: e.name.clone(),
                keys: vec![entry],
            }),
        }
    }
    out
}

/// Every `kadmind` case as an AP-REQ: for each service of the keytab, a ticket sealed in each of its keys at
/// that key's kvno (`<service>` for the first, `<service>/key<N>` for the others), and, for its first key,
/// one with the kvno 0, one at kvno 99, ones sealed in a key of an enctype the keytab lacks
/// (`<service>/etype=<n>`: des3, rc4, camellia) and, for `kadmin/admin` and `kadmin/changepw`, ones whose
/// cleartext server is each other service, `nosuch/service`, or in another realm.
fn ka_cases(client: &str, services: &[KaService]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let now = KerberosTime::now();
    let mut out = Vec::new();
    for svc in services {
        let name = svc.name.unparse();
        let authenticator = der!(&pristine_authenticator(&svc.realm, client, &now))?;
        let ticket = |sname: &PrincipalName, srealm: &str, kvno: Option<u32>, k: usize| {
            let (etype, _, ref key) = *svc.keys.get(k).ok_or("no such key")?;
            ticket_ap_req(
                &TicketSpec {
                    realm: svc.realm.clone(),
                    client: client.to_owned(),
                    srealm: srealm.to_owned(),
                    sname: sname.clone(),
                    kvno,
                    etype,
                    svc: key.clone(),
                },
                &authenticator,
                &now,
            )
        };
        for (k, (_, kvno, _)) in svc.keys.iter().enumerate() {
            let id = if k == 0 {
                name.clone()
            } else {
                format!("{name}/key{k}")
            };
            out.push((id, ticket(&svc.name, &svc.realm, Some(*kvno), k)?));
        }
        out.push((
            format!("{name}/kvno0"),
            ticket(&svc.name, &svc.realm, Some(0), 0)?,
        ));
        out.push((
            format!("{name}/kvno99"),
            ticket(&svc.name, &svc.realm, Some(99), 0)?,
        ));
        // A key in an enctype no entry of the keytab has, at the first key's kvno.
        let first = svc.keys.first().map(|k| k.1);
        for (etype, len) in [
            (EncryptionType::Des3CbcSha1, 24),
            (EncryptionType::Rc4Hmac, 16),
            (EncryptionType::Camellia128CtsCmac, 16),
            (EncryptionType::Camellia256CtsCmac, 32),
        ] {
            let spec = TicketSpec {
                realm: svc.realm.clone(),
                client: client.to_owned(),
                srealm: svc.realm.clone(),
                sname: svc.name.clone(),
                kvno: first,
                etype: etype.to_iana(),
                svc: ProtocolKey::from_bytes(etype, &vec![0x43; len]).map_err(|e| e.to_string())?,
            };
            out.push((
                format!("{name}/etype={}", etype.to_iana()),
                ticket_ap_req(&spec, &authenticator, &now)?,
            ));
        }
        let names = svc
            .name
            .name_string
            .iter()
            .map(|c| String::from_utf8_lossy(c.as_bytes()).into_owned())
            .collect::<Vec<_>>();
        if names == ["kadmin", "admin"] || names == ["kadmin", "changepw"] {
            for other in services
                .iter()
                .filter(|o| o.name.name_string != svc.name.name_string)
            {
                out.push((
                    format!("{name}/as={}", other.name.unparse()),
                    ticket(&other.name, &other.realm, first, 0)?,
                ));
            }
            let nosuch = PrincipalName::new(PrincipalName::NT_SRV_INST, ["nosuch", "service"]);
            out.push((
                format!("{name}/as=nosuch/service"),
                ticket(&nosuch, &svc.realm, first, 0)?,
            ));
            out.push((
                format!("{name}/realm=OTHER.REALM"),
                ticket(&svc.name, "OTHER.REALM", first, 0)?,
            ));
        }
    }
    Ok(out)
}

/// `rd-sweep kadmind <keytab> <client>`: the cases, one `id<TAB>hex` line each.
fn kadmind(keytab: &str, client: &str) -> Result<(), String> {
    let bytes = std::fs::read(keytab).map_err(|e| format!("{keytab}: {e}"))?;
    let kt = Keytab::parse(&bytes).map_err(|e| format!("{keytab}: {e}"))?;
    let services = ka_services(&kt);
    if services.is_empty() {
        return Err("no keytab entry".into());
    }
    for (id, ap) in ka_cases(client, &services)? {
        println!("{id}\t{}", hex(&ap));
    }
    Ok(())
}

/// How the verifier's refusal reads in the rd-priv oracle's words: `0`, `krb5:<n>` for code n of the krb5 table,
/// `other:<n>` for another table's.
fn kdb_answer(e: &Result<krb5_protocol::ApVerifyOk, Error>) -> String {
    match e {
        Ok(_) => "0".into(),
        Err(Error::KrbError { code, .. }) => format!("krb5:{code}"),
        // `KRB5KRB_AP_ERR_BAD_INTEGRITY`: the ticket does not decrypt under the key it was given.
        Err(Error::Crypto(_)) => "krb5:31".into(),
        // `KRB5_KDB_NO_PERMITTED_KEY`.
        Err(Error::KdbNoPermittedKey) => "other:-1780008418".into(),
        Err(Error::Asn1(_)) => "asn1".into(),
        Err(other) => format!("other:{other}"),
    }
}

/// `rd-sweep judge-kdb <cases> <mit> <dump> <master-password>`.
fn judge_kdb(cases: &str, mit: &str, dump: &str, password: &str) -> Result<bool, String> {
    let cases = std::fs::read_to_string(cases).map_err(|e| format!("{cases}: {e}"))?;
    let mit = std::fs::read_to_string(mit).map_err(|e| format!("{mit}: {e}"))?;
    let mit: std::collections::HashMap<&str, [&str; 3]> = mit
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let [id, a, b, c] = f.as_slice() else {
                return None;
            };
            Some((*id, [*a, *b, *c]))
        })
        .collect();
    let store = krb5_kdc::load_dump_path(std::path::Path::new(dump), password.as_bytes())
        .map_err(|e| format!("{dump}: {e}"))?;
    let realm = store.realm().to_owned();
    let shared = krb5_kdc::shared_dump(store);
    let conf = kdc_context_conf();
    let acceptors = [
        None,
        Some(krb5_kdc::principals::kadmin_admin()),
        Some(krb5_kdc::principals::kadmin_changepw()),
    ];
    let (mut n, mut parts) = (0, 0);
    for line in cases.lines().filter(|l| !l.starts_with('#')) {
        let Some((id, hexed)) = line.split_once('\t') else {
            return Err(format!("bad case line {line}"));
        };
        let ap = unhex(hexed).ok_or("bad AP-REQ hex")?;
        let ours: Vec<String> = acceptors
            .iter()
            .map(|acceptor| {
                kdb_answer(&krb5_admin::kdb_rd_req(
                    &shared,
                    &realm,
                    acceptor.as_ref(),
                    &conf,
                    &ap,
                    &ReplayCache::new(),
                ))
            })
            .collect();
        let theirs = mit
            .get(id)
            .map_or_else(|| "none".to_owned(), |t| t.join("|"));
        let ours = ours.join("|");
        n += 1;
        if theirs == ours {
            println!("SAME\t{id}\t{theirs}");
        } else {
            parts += 1;
            println!("PART\t{id}\tMIT {theirs}\tRust {ours}");
        }
    }
    println!("{parts} of {n} cases part from MIT");
    Ok(parts == 0)
}

/// A big-endian word.
fn word(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

/// An XDR opaque: its length, the octets, and the padding to a multiple of four.
fn opaque(b: &[u8]) -> Vec<u8> {
    let mut v = word(u32::try_from(b.len()).unwrap_or(u32::MAX)).to_vec();
    v.extend_from_slice(b);
    v.resize(v.len() + (4 - b.len() % 4) % 4, 0);
    v
}

/// The words of a reply record, read in order.
struct Words<'a>(&'a [u8]);

impl Words<'_> {
    fn u32(&mut self) -> Option<u32> {
        let (w, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_be_bytes(*w))
    }

    fn opaque(&mut self) -> Option<Vec<u8>> {
        let n = usize::try_from(self.u32()?).ok()?;
        let padded = n.checked_add((4 - n % 4) % 4)?;
        let v = self.0.get(..n)?.to_vec();
        self.0 = self.0.get(padded..)?;
        Some(v)
    }
}

/// `auth_stat` in MIT's words.
fn auth_label(why: u32) -> &'static str {
    match why {
        1 => "AUTH_BADCRED",
        2 => "AUTH_REJECTEDCRED",
        3 => "AUTH_BADVERF",
        4 => "AUTH_REJECTEDVERF",
        5 => "AUTH_TOOWEAK",
        7 => "AUTH_FAILED",
        13 => "RPCSEC_GSS_CREDPROBLEM",
        14 => "RPCSEC_GSS_CTXPROBLEM",
        _ => "AUTH_ERROR",
    }
}

/// One INIT call to a kadmind: RPC program 2112 version 2, procedure 0 for RPCSEC_GSS and AUTH_GSSAPI's
/// procedure 1 (an auth message), as MIT's client sends them. The record ends in the GSS token. What it
/// got: the RPC layer's refusal, or the GSS major status the flavor answered with.
fn init_call(
    stream: &mut std::net::TcpStream,
    agss: bool,
    gss_token: &[u8],
) -> Result<String, String> {
    use std::io::{Read as _, Write as _};
    let xid = 0x4b41_494e_u32;
    let call = if agss {
        // Credential version 2, an auth message, no client handle; init_arg version 4.
        let cred = [word(2).to_vec(), word(1).to_vec(), opaque(&[])].concat();
        [
            [xid, 0, 2, 2112, 2, 1, 300_001].map(word).concat(),
            opaque(&cred),
            word(0).to_vec(),
            opaque(&[]),
            word(4).to_vec(),
            opaque(gss_token),
        ]
        .concat()
    } else {
        // RPCSEC_GSS_VERS_1, RPCSEC_GSS_INIT, sequence 0, rpc_gss_svc_none, no handle.
        let cred = [[1, 1, 0, 1].map(word).concat(), opaque(&[])].concat();
        [
            [xid, 0, 2, 2112, 2, 0, 6].map(word).concat(),
            opaque(&cred),
            word(0).to_vec(),
            opaque(&[]),
            opaque(gss_token),
        ]
        .concat()
    };
    let mut record =
        word(u32::try_from(call.len()).map_err(|e| e.to_string())? | 0x8000_0000).to_vec();
    record.extend_from_slice(&call);
    stream
        .write_all(&record)
        .map_err(|e| format!("send: {e}"))?;
    let mut mark = [0u8; 4];
    stream
        .read_exact(&mut mark)
        .map_err(|e| format!("reply: {e}"))?;
    let n = usize::try_from(u32::from_be_bytes(mark) & 0x7fff_ffff).map_err(|e| e.to_string())?;
    let mut body = vec![0u8; n];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("reply: {e}"))?;
    let mut r = Words(&body);
    let parsed = (|| {
        if r.u32()? != xid || r.u32()? != 1 {
            return Some("OTHER not a reply to the call".to_string());
        }
        if r.u32()? == 1 {
            // MSG_DENIED: RPC_MISMATCH 0 or AUTH_ERROR 1, then the auth_stat.
            return Some(if r.u32()? == 1 {
                let why = r.u32()?;
                format!("DENIED auth_stat={why} {}", auth_label(why))
            } else {
                "OTHER rpc version mismatch".to_string()
            });
        }
        // MSG_ACCEPTED: the verifier, then the accept_stat.
        let _flavor = r.u32()?;
        let _verifier = r.opaque()?;
        let accept = r.u32()?;
        if accept != 0 {
            return Some(format!("OTHER accept_stat={accept}"));
        }
        let (handle, major) = if agss {
            let _version = r.u32()?;
            let handle = r.opaque()?;
            (handle, r.u32()?)
        } else {
            let handle = r.opaque()?;
            (handle, r.u32()?)
        };
        let label = match major {
            0 => "GSS_S_COMPLETE",
            0x000d_0000 => "GSS_S_FAILURE",
            _ => "GSS_S_OTHER",
        };
        Some(format!(
            "ACCEPTED gss_major={major} {label} handle={}B",
            handle.len()
        ))
    })();
    Ok(parsed.unwrap_or_else(|| "OTHER short reply".to_string()))
}

/// `rd-sweep kadmind-init <host:port> <keytab> <client> [service=<principal>] [entry=N] [flavor=rpcsec|agss]`:
/// an INIT call to a kadmind, for a ticket forged in the keytab's Nth key of the service (`kadmin/admin`, the
/// first key by default), and the line saying what it got. The ticket is sealed in that entry's enctype and
/// kvno; MIT's and our kadmind take the first key alone and refuse the rest.
fn kadmind_init(addr: &str, keytab: &str, client: &str, opts: &[String]) -> Result<(), String> {
    let (mut service, mut entry, mut agss) = ("kadmin/admin".to_owned(), 0usize, false);
    for o in opts {
        match o.split_once('=') {
            Some(("service", v)) => v.clone_into(&mut service),
            Some(("entry", v)) => entry = v.parse().map_err(|_| format!("bad entry {v}"))?,
            Some(("flavor", "agss")) => agss = true,
            Some(("flavor", "rpcsec")) => agss = false,
            _ => return Err(format!("unknown option {o}")),
        }
    }
    let bytes = std::fs::read(keytab).map_err(|e| format!("{keytab}: {e}"))?;
    let kt = Keytab::parse(&bytes).map_err(|e| format!("{keytab}: {e}"))?;
    let services = ka_services(&kt);
    let svc = services
        .iter()
        .find(|s| s.name.unparse() == service)
        .ok_or_else(|| format!("no keytab entry for {service}"))?;
    let (etype, kvno, ref skey) = *svc
        .keys
        .get(entry)
        .ok_or_else(|| format!("{service} has {} keys, no entry {entry}", svc.keys.len()))?;
    let now = KerberosTime::now();
    let ticket = forged_ticket(
        &TicketSpec {
            realm: svc.realm.clone(),
            client: client.to_owned(),
            srealm: svc.realm.clone(),
            sname: svc.name.clone(),
            kvno: Some(kvno),
            etype,
            svc: skey.clone(),
        },
        &now,
    )?;
    let who = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [client]);
    let (_ctx, token) = krb5_gss::GssContext::init_sec_context(
        ticket,
        &key(&SESSION_KEY)?,
        &ascii(&svc.realm),
        &who,
        true,
        None,
        None,
    )
    .map_err(|e| e.to_string())?;
    let mut stream = std::net::TcpStream::connect(addr).map_err(|e| format!("{addr}: {e}"))?;
    let timeout = Some(std::time::Duration::from_secs(10));
    stream
        .set_read_timeout(timeout)
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(timeout)
        .map_err(|e| e.to_string())?;
    let flavor = if agss { "agss" } else { "rpcsec" };
    let got = init_call(&mut stream, agss, &token)?;
    println!(
        "kadmind-init service={service} entry={entry} etype={etype} kvno={kvno} flavor={flavor}: {got}"
    );
    Ok(())
}

fn run(args: &[String]) -> Result<bool, String> {
    match args {
        [cmd] if cmd == "cases" => {
            println!("#key 18 1 {} {SERVICE}", hex(&SERVICE_KEY));
            for (id, kind, ap, msg) in cases()? {
                let msg = msg.as_deref().map_or_else(|| "-".to_string(), hex);
                println!("{id}\t{kind}\t{}\t{msg}", hex(&ap));
            }
            Ok(true)
        }
        [cmd, cases, mit] if cmd == "judge" => {
            let cases = std::fs::read_to_string(cases).map_err(|e| format!("{cases}: {e}"))?;
            let mit = std::fs::read_to_string(mit).map_err(|e| format!("{mit}: {e}"))?;
            let mit: std::collections::HashMap<&str, &str> =
                mit.lines().filter_map(|l| l.split_once('\t')).collect();
            let (mut n, mut parts) = (0, 0);
            for line in cases.lines().filter(|l| !l.starts_with('#')) {
                let f: Vec<&str> = line.split('\t').collect();
                let [id, kind, ap, msg] = f.as_slice() else {
                    return Err(format!("bad case line {line}"));
                };
                let ap = unhex(ap).ok_or("bad AP-REQ hex")?;
                let msg = if *msg == "-" {
                    None
                } else {
                    Some(unhex(msg).ok_or("bad message hex")?)
                };
                let ours = rust_answer(kind, &ap, msg.as_deref());
                let theirs = mit.get(id).copied().unwrap_or("none");
                n += 1;
                if ours == theirs {
                    println!("SAME\t{id}\t{theirs}");
                } else {
                    parts += 1;
                    println!("PART\t{id}\tMIT {theirs}\tRust {ours}");
                }
            }
            println!("{parts} of {n} cases part from MIT");
            Ok(parts == 0)
        }
        [cmd, keytab, client, opts @ ..] if cmd == "kpasswd" => {
            kpasswd(keytab, client, opts)?;
            Ok(true)
        }
        [cmd, frames, mit, dump, password] if cmd == "judge-explicit" => {
            judge_explicit(frames, mit, dump, password)
        }
        [cmd, keytab, client] if cmd == "kadmind" => {
            kadmind(keytab, client)?;
            Ok(true)
        }
        [cmd, cases, mit, dump, password] if cmd == "judge-kdb" => {
            judge_kdb(cases, mit, dump, password)
        }
        [cmd, addr, keytab, client, opts @ ..] if cmd == "kadmind-init" => {
            kadmind_init(addr, keytab, client, opts)?;
            Ok(true)
        }
        _ => Err(
            "usage: rd-sweep cases | judge <cases> <mit> | kpasswd <keytab> <client> \
                  [setpw] [raddr=IP] [entry=N] | judge-explicit <frames> <mit> <dump> <password> | \
                  kadmind <keytab> <client> | judge-kdb <cases> <mit> <dump> <password> | \
                  kadmind-init <host:port> <keytab> <client> [service=P] [entry=N] [flavor=rpcsec|agss]"
                .into(),
        ),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("rd-sweep: {e}");
            ExitCode::from(2)
        }
    }
}
