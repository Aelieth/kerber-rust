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

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

include!("../der_breaks.rs");

use std::process::ExitCode;

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum, encrypt};
use krb5_protocol::{
    AcceptorAuthContext, ApVerifyParams, Error, Keytab, ReplayCache, unwrap_krb_priv_ex,
    verify_ap_req_ex,
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
    let permitted = EncryptionType::preferred();
    let mut ac = match AcceptorAuthContext::from_ap_req(&ok, &permitted) {
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

/// The AP-REQ for `authenticator` (its DER as given), in an INITIAL ticket for `kadmin/changepw`
/// sealed in the keytab entry's key.
fn kp_ap_req(env: &KpEnv, authenticator: &[u8], now: &KerberosTime) -> Result<Vec<u8>, String> {
    let part = EncTicketPart {
        flags: TicketFlags::initial_preauth(),
        key: EncryptionKey {
            keytype: 18,
            keyvalue: OctetString::from(SESSION_KEY.to_vec()),
        },
        crealm: ascii(&env.realm),
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [env.client.as_str()]),
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
        realm: ascii(&env.realm),
        sname: PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]),
        enc_part: EncryptedData {
            etype: env.etype,
            kvno: Some(env.kvno),
            cipher: encrypt(&env.svc, usage(ku::TICKET)?, &der!(&part)?)
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

/// Every kpasswd case as a frame: the pristine request (twice, as `ap-req/pristine` and
/// `krb-priv/pristine`); the authenticator and the `EncKrbPrivPart` broken each way and re-encrypted;
/// the AP-REQ and the KRB-PRIV themselves broken each way; and, for `setpw`, the ChangePasswdData
/// broken each way and one that names no target.
fn kp_cases(env: &KpEnv) -> Result<Vec<(String, Vec<u8>)>, String> {
    let now = KerberosTime::now();
    let vno: u16 = if env.setpw { 0xff80 } else { 1 };
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: ascii(&env.realm),
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [env.client.as_str()]),
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
fn explicit_answer(shared: &krb5_kdc::SharedDump, acl: &krb5_kdc::Acl, frame: &[u8]) -> String {
    let Ok(service_key) = key(&SERVICE_KEY) else {
        return "other:key".into();
    };
    let Ok(rep) =
        krb5_admin::handle_kpasswd_rfc3244(shared, acl, &service_key, &ReplayCache::new(), frame)
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
    let (mut n, mut parts) = (0, 0);
    for line in frames.lines().filter(|l| !l.starts_with('#')) {
        let Some((id, hexed)) = line.split_once('\t') else {
            return Err(format!("bad frame line {line}"));
        };
        let frame = unhex(hexed).ok_or("bad frame hex")?;
        let ours = explicit_answer(&shared, &acl, &frame);
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
        _ => Err(
            "usage: rd-sweep cases | judge <cases> <mit> | kpasswd <keytab> <client> \
                  [setpw] [raddr=IP] [entry=N] | judge-explicit <frames> <mit> <dump> <password>"
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
