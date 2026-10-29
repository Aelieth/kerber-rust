#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

include!("../der_breaks.rs");

use std::process::ExitCode;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt};
use krb5_protocol::{
    AcceptorAuthContext, AcceptorConfig, ApVerifyParams, Error, Keytab, ReplayCache,
    unwrap_krb_priv_ex, verify_ap_req_ex,
};
use krb5_types::{
    ApOptions, ApReq, Authenticator, AuthorizationDataValue, ChangePasswdData, Checksum,
    EncKrbPrivPart, EncTicketPart, EncryptedData, EncryptionKey, HostAddress, KerberosTime,
    KrbError, KrbPriv, Microseconds, OctetString, PrincipalName, Ticket, TicketFlags,
    TransitedEncoding, ascii, flag_bit, ku,
};

const SERVICE: &str = "host/oracle.kerber.test@KERBER.TEST";
const SERVICE_KEY: [u8; 32] = [0x43; 32];
const SERVICE_KEY_128: [u8; 16] = [0x47; 16];
const SESSION_KEY: [u8; 32] = [0x44; 32];
const SUBKEY: [u8; 32] = [0x45; 32];
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

fn ap_req(authenticator: &[u8], now: &KerberosTime) -> Result<Vec<u8>, String> {
    ap_req_with(authenticator, now, |_| {})
}

fn ap_req_with(
    authenticator: &[u8],
    now: &KerberosTime,
    tkt: impl FnOnce(&mut EncTicketPart),
) -> Result<Vec<u8>, String> {
    let client = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let mut part = EncTicketPart {
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
    tkt(&mut part);
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

type RdCase = (String, &'static str, Vec<u8>, Option<Vec<u8>>);

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
    // AP-REQ, KRB-PRIV and KRB-SAFE are broken as sent,
    // so a broken KRB-SAFE-BODY fails its checksum.
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

#[derive(Clone, Copy)]
enum Seal {
    Session,
    OtherKey,
    Etype(i32),
    Short,
}

struct OrderCase {
    id: &'static str,
    seal: Seal,
    session_type: i32,
    session_len: usize,
    crealm: &'static str,
    transited: &'static [u8],
    checked: bool,
    invalid: bool,
    start: Option<i64>,
    end: i64,
    ctime: i64,
    cname: &'static str,
    resend: bool,
    tkt_aes128: bool,
    tkt_kvno: u32,
    tkt_etype: i32,
    named: bool,
    matching: bool,
}

const HOUR: i64 = 3600;
const PRISTINE: OrderCase = OrderCase {
    id: "order/pristine",
    seal: Seal::Session,
    session_type: 18,
    session_len: 32,
    crealm: "KERBER.TEST",
    transited: b"",
    checked: false,
    invalid: false,
    start: None,
    end: HOUR,
    ctime: 0,
    cname: "user",
    resend: false,
    tkt_aes128: false,
    tkt_kvno: 1,
    tkt_etype: 0,
    named: false,
    matching: false,
};

fn order_cases() -> Result<Vec<RdCase>, String> {
    let now = KerberosTime::now();
    let at = |s: i64| now.add_seconds(s).map_err(|e| e.to_string());
    let foreign = OrderCase {
        crealm: "OTHER.TEST",
        transited: b"KERBER.TEST",
        ..PRISTINE
    };
    let cases = [
        PRISTINE,
        OrderCase {
            id: "text/nyv",
            start: Some(2 * HOUR),
            end: 3 * HOUR,
            ..PRISTINE
        },
        OrderCase {
            id: "text/expired",
            end: -2 * HOUR,
            ..PRISTINE
        },
        OrderCase {
            id: "text/skew",
            ctime: -HOUR,
            ..PRISTINE
        },
        OrderCase {
            id: "text/badmatch",
            cname: "other",
            ..PRISTINE
        },
        OrderCase {
            id: "text/invalid",
            invalid: true,
            ..PRISTINE
        },
        OrderCase {
            id: "text/replay",
            resend: true,
            ..PRISTINE
        },
        OrderCase {
            id: "transit/server-realm",
            ..foreign
        },
        OrderCase {
            id: "transit/one-realm",
            transited: b"OTHER.TEST",
            ..PRISTINE
        },
        OrderCase {
            id: "transit/client-realm",
            transited: b"OTHER.TEST",
            ..foreign
        },
        OrderCase {
            id: "transit/checked",
            checked: true,
            ..foreign
        },
        OrderCase {
            id: "transit/nul-led",
            transited: b"\0KERBER.TEST",
            ..foreign
        },
        OrderCase {
            id: "decrypt/authenticator-key",
            seal: Seal::OtherKey,
            ..PRISTINE
        },
        OrderCase {
            id: "decrypt/authenticator-etype",
            seal: Seal::Etype(17),
            ..PRISTINE
        },
        OrderCase {
            id: "decrypt/authenticator-short",
            seal: Seal::Short,
            ..PRISTINE
        },
        OrderCase {
            id: "decrypt/session-key-size",
            session_len: 16,
            ..PRISTINE
        },
        OrderCase {
            id: "decrypt/session-etype",
            session_type: 99,
            ..PRISTINE
        },
        OrderCase {
            id: "decrypt/session-key-size-etype",
            session_len: 16,
            seal: Seal::Etype(17),
            ..PRISTINE
        },
        OrderCase {
            id: "decrypt/session-key-size-short",
            session_len: 16,
            seal: Seal::Short,
            ..PRISTINE
        },
        OrderCase {
            id: "order/pristine-named",
            named: true,
            ..PRISTINE
        },
        OrderCase {
            id: "keytab/kvno-miss-named",
            tkt_kvno: 2,
            named: true,
            ..PRISTINE
        },
        OrderCase {
            id: "keytab/kvno-miss",
            tkt_kvno: 2,
            ..PRISTINE
        },
        OrderCase {
            id: "keytab/not-found-named",
            tkt_etype: 16,
            named: true,
            ..PRISTINE
        },
        OrderCase {
            id: "keytab/not-found",
            tkt_etype: 16,
            ..PRISTINE
        },
        OrderCase {
            id: "keytab/kvno-miss-matching",
            tkt_kvno: 2,
            matching: true,
            ..PRISTINE
        },
        OrderCase {
            id: "keytab/not-found-matching",
            tkt_etype: 16,
            matching: true,
            ..PRISTINE
        },
        OrderCase {
            id: "etype/ticket-noperm",
            tkt_aes128: true,
            ..PRISTINE
        },
        OrderCase {
            id: "etype/ticket-noperm-named",
            tkt_aes128: true,
            named: true,
            ..PRISTINE
        },
        OrderCase {
            id: "order/ticket-noperm-expired",
            tkt_aes128: true,
            named: true,
            end: -2 * HOUR,
            ..PRISTINE
        },
        OrderCase {
            id: "order/ticket-noperm-replay",
            tkt_aes128: true,
            named: true,
            resend: true,
            ..PRISTINE
        },
        OrderCase {
            id: "order/authenticator-key-expired",
            seal: Seal::OtherKey,
            end: -2 * HOUR,
            ..PRISTINE
        },
        OrderCase {
            id: "order/expired-badmatch",
            end: -2 * HOUR,
            cname: "other",
            ..PRISTINE
        },
        OrderCase {
            id: "order/expired-transit",
            end: -2 * HOUR,
            ..foreign
        },
        OrderCase {
            id: "order/invalid-skew",
            invalid: true,
            ctime: -HOUR,
            ..PRISTINE
        },
        OrderCase {
            id: "order/expired-replay",
            end: -2 * HOUR,
            resend: true,
            ..PRISTINE
        },
        OrderCase {
            id: "order/skew-replay",
            ctime: -HOUR,
            resend: true,
            ..PRISTINE
        },
        OrderCase {
            id: "order/transit-replay",
            resend: true,
            ..foreign
        },
    ];
    let mut out = Vec::new();
    for c in cases {
        let authenticator = Authenticator {
            authenticator_vno: Authenticator::VNO,
            crealm: ascii(c.crealm),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [c.cname]),
            cksum: None,
            cusec: Microseconds(0),
            ctime: at(c.ctime)?,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };
        let (start, end) = (c.start.map(at).transpose()?, at(c.end)?);
        let auth_der = der!(&authenticator)?;
        let mut ap = ap_req_with(&auth_der, &now, |p| {
            p.key = EncryptionKey {
                keytype: c.session_type,
                keyvalue: OctetString::from(SESSION_KEY[..c.session_len].to_vec()),
            };
            p.crealm = ascii(c.crealm);
            p.transited.contents = OctetString::from(c.transited.to_vec());
            p.flags = p
                .flags
                .clone()
                .with_bit(flag_bit::TRANSITED_POLICY_CHECKED, c.checked)
                .with_bit(flag_bit::INVALID, c.invalid);
            p.starttime = start;
            p.endtime = end;
        })?;
        if c.tkt_aes128 || c.tkt_kvno != 1 || c.tkt_etype != 0 || !matches!(c.seal, Seal::Session) {
            let mut req: ApReq = decode(&ap).map_err(|e| e.to_string())?;
            if c.tkt_aes128 {
                let tkt_usage = usage(ku::TICKET)?;
                let part = decrypt(
                    &key(&SERVICE_KEY)?,
                    tkt_usage,
                    req.ticket.enc_part.cipher.as_ref(),
                )
                .map_err(|e| e.to_string())?;
                let aes128 =
                    ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &SERVICE_KEY_128)
                        .map_err(|e| e.to_string())?;
                req.ticket.enc_part.etype = 17;
                req.ticket.enc_part.cipher = encrypt(&aes128, tkt_usage, &part)
                    .map_err(|e| e.to_string())?
                    .into();
            }
            req.ticket.enc_part.kvno = Some(c.tkt_kvno);
            if c.tkt_etype != 0 {
                req.ticket.enc_part.etype = c.tkt_etype;
            }
            match c.seal {
                Seal::OtherKey => {
                    req.authenticator.cipher =
                        encrypt(&key(&SUBKEY)?, usage(ku::AP_REQ_AUTHENTICATOR)?, &auth_der)
                            .map_err(|e| e.to_string())?
                            .into();
                }
                Seal::Etype(n) => req.authenticator.etype = n,
                Seal::Short => req.authenticator.cipher = OctetString::from(vec![0; 16]),
                Seal::Session => {}
            }
            ap = der!(&req)?;
        }
        let kind = if c.named {
            "req-named"
        } else if c.matching {
            "req-matching"
        } else {
            "req"
        };
        if c.resend {
            out.push((c.id.to_string(), kind, ap.clone(), None));
            out.push((format!("{}-again", c.id), kind, ap, None));
        } else {
            out.push((c.id.to_string(), kind, ap, None));
        }
    }
    Ok(out)
}

// Oracle FILE keytab: the service's keys at kvno 1, walked (NULL server) unless named.
fn oracle_verify(
    ap: &[u8],
    replay: &ReplayCache,
    keys: &[ProtocolKey],
    kind: &str,
    permitted: &[EncryptionType],
) -> Result<krb5_protocol::ApVerifyOk, Error> {
    let name = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "oracle.kerber.test"]);
    let matching = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", ""]);
    let pinned = kind.starts_with("req-");
    let principals: Vec<_> = keys
        .iter()
        .map(|_| (name.clone(), ascii("KERBER.TEST")))
        .collect();
    let kvnos = vec![1; keys.len()];
    let params = ApVerifyParams {
        keys,
        key_kvnos: Some(&kvnos),
        key_principals: (!pinned).then_some(principals.as_slice()),
        expected_server: pinned.then_some(if kind == "req-matching" {
            &matching
        } else {
            &name
        }),
        expected_realm: pinned.then_some("KERBER.TEST"),
        permitted,
        ..ApVerifyParams::single_key(&keys[0])
    };
    verify_ap_req_ex(ap, &params, replay, None)
}

/// An answer as the oracle prints MIT's: `0` accepted, `asn1` an ASN.1 decode error, `krb5:<n>`
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
    let Ok(service) = key(&SERVICE_KEY) else {
        return "other:key".into();
    };
    let preferred = EncryptionType::preferred();
    let ok = match oracle_verify(ap, &ReplayCache::new(), &[service], "req", &preferred) {
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

fn print_cases(cases: Vec<RdCase>) {
    for (id, kind, ap, msg) in cases {
        let msg = msg.as_deref().map_or_else(|| "-".to_string(), hex);
        println!("{id}\t{kind}\t{}\t{msg}", hex(&ap));
    }
}

fn judge(
    cases: &str,
    mit: &str,
    mut answer: impl FnMut(&str, &[u8], Option<&[u8]>) -> String,
) -> Result<bool, String> {
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
        let ours = answer(kind, &ap, msg.as_deref());
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

fn unhex(h: &str) -> Option<Vec<u8>> {
    (0..h.len())
        .step_by(2)
        .map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

struct KpEnv {
    realm: String,
    kvno: u32,
    svc: ProtocolKey,
    etype: i32,
    client: String,
    setpw: bool,
    raddr: Option<[u8; 4]>,
}

struct TicketSpec {
    realm: String,
    client: String,
    srealm: String,
    sname: PrincipalName,
    kvno: Option<u32>,
    etype: i32,
    svc: ProtocolKey,
}

fn forged_ticket(spec: &TicketSpec, now: &KerberosTime) -> Result<Ticket, String> {
    forged_ticket_with(spec, now, |_| {})
}

fn forged_ticket_with(
    spec: &TicketSpec,
    now: &KerberosTime,
    tkt: impl FnOnce(&mut EncTicketPart),
) -> Result<Ticket, String> {
    let mut part = EncTicketPart {
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
    tkt(&mut part);
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

fn ticket_ap_req(
    spec: &TicketSpec,
    authenticator: &[u8],
    now: &KerberosTime,
    ap_options: ApOptions,
) -> Result<Vec<u8>, String> {
    let ap = ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options,
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
        ApOptions::none(),
    )
}

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

fn explicit_answer(
    shared: &krb5_kdc::SharedDump,
    acl: &krb5_kdc::Acl,
    conf: &AcceptorConfig,
    frame: &[u8],
) -> String {
    let authcfg = krb5_admin::Kadm5AuthConfig::from_acl(acl.clone());
    let Ok(rep) = krb5_admin::handle_kpasswd_from(
        shared,
        &authcfg,
        conf,
        &ReplayCache::new(),
        frame,
        "127.0.0.1",
        Some(std::net::IpAddr::from([127, 0, 0, 1])),
    ) else {
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

struct KaService {
    realm: String,
    name: PrincipalName,
    keys: Vec<(i32, u32, ProtocolKey)>,
}

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
                ApOptions::none(),
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
                ticket_ap_req(&spec, &authenticator, &now, ApOptions::none())?,
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

fn word(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

fn opaque(b: &[u8]) -> Vec<u8> {
    let mut v = word(u32::try_from(b.len()).unwrap_or(u32::MAX)).to_vec();
    v.extend_from_slice(b);
    v.resize(v.len() + (4 - b.len() % 4) % 4, 0);
    v
}

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

/// procedure 1, as MIT's client sends them. The record ends in the GSS token. What it
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

fn service_spec(keytab: &str, service: &str, crealm: Option<&str>) -> Result<TicketSpec, String> {
    let bytes = std::fs::read(keytab).map_err(|e| format!("{keytab}: {e}"))?;
    let kt = Keytab::parse(&bytes).map_err(|e| format!("{keytab}: {e}"))?;
    let services = ka_services(&kt);
    let svc = services
        .iter()
        .find(|s| s.name.unparse() == service)
        .ok_or_else(|| format!("no keytab entry for {service}"))?;
    let (etype, kvno, ref skey) = *svc.keys.first().ok_or("no key")?;
    Ok(TicketSpec {
        realm: crealm.unwrap_or(&svc.realm).to_owned(),
        client: "user".to_owned(),
        srealm: svc.realm.clone(),
        sname: svc.name.clone(),
        kvno: Some(kvno),
        etype,
        svc: skey.clone(),
    })
}

fn gss_transit(keytab: &str, service: &str) -> Result<(), String> {
    let crealm = "OTHER.TEST";
    let spec = service_spec(keytab, service, Some(crealm))?;
    let ticket = forged_ticket_with(&spec, &KerberosTime::now(), |p| {
        p.transited.contents = OctetString::from(spec.srealm.as_bytes().to_vec());
    })?;
    let who = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let (_ctx, token) = krb5_gss::GssContext::init_sec_context(
        ticket,
        &key(&SESSION_KEY)?,
        &ascii(crealm),
        &who,
        krb5_gss::GSS_C_MUTUAL,
        None,
        None,
        None,
        0,
    )
    .map_err(|e| e.to_string())?;
    println!("{}", hex(&token));
    Ok(())
}

fn gss_errtok(keytab: &str, service: &str) -> Result<(), String> {
    let spec = service_spec(keytab, service, None)?;
    let now = KerberosTime::now();
    let gss = |flags: u32, tail: &[u8]| {
        let v = [&[16, 0, 0, 0][..], &[0; 16], &flags.to_le_bytes(), tail].concat();
        Checksum {
            cksumtype: krb5_gss::GSS_CHECKSUM_TYPE,
            checksum: v.into(),
        }
    };
    let ad_ap_options = || AuthorizationDataValue {
        ad_type: 143,
        ad_data: OctetString::from(vec![0; 4]),
    };
    let nested = AuthorizationDataValue {
        ad_type: krb5_types::pa::AD_IF_RELEVANT,
        ad_data: der!(&vec![ad_ap_options()])?.into(),
    };
    let dup = Some(vec![ad_ap_options(), nested]);
    let (mutual, deleg, dce, cb) = (
        krb5_gss::GSS_C_MUTUAL,
        krb5_gss::GSS_C_DELEG,
        krb5_gss::GSS_C_DCE,
        krb5_gss::GSS_C_CHANNEL_BOUND,
    );
    let (bad_id, finished) = ([2, 0, 0, 0], [0, 0, 0, 2, 0, 0, 0, 0]);
    let samba = Checksum {
        cksumtype: 16,
        checksum: OctetString::from(vec![0xff; 12]),
    };
    let cases = [
        ("deleg-id", true, false, gss(mutual | deleg, &bad_id), None),
        ("deleg-id-nomutual", true, false, gss(deleg, &bad_id), None),
        ("finished", true, false, gss(mutual, &finished), None),
        ("cbt-dup", true, false, gss(mutual, &[]), dup),
        ("raw-nodce", false, false, gss(mutual, &[]), None),
        ("framed-dce", true, false, gss(mutual | dce, &[]), None),
        ("samba-bad", true, true, samba, None),
        ("cb-flag", true, false, gss(mutual | cb, &[]), None),
    ];
    for (usec, (name, framed, mutual_required, cksum, authorization_data)) in (1..).zip(cases) {
        let authenticator = Authenticator {
            authenticator_vno: Authenticator::VNO,
            crealm: ascii(&spec.realm),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [spec.client.as_str()]),
            cksum: Some(cksum),
            cusec: Microseconds(usec),
            ctime: now.clone(),
            subkey: None,
            seq_number: None,
            authorization_data,
        };
        let options = if mutual_required {
            ApOptions::mutual_required()
        } else {
            ApOptions::none()
        };
        let ap = ticket_ap_req(&spec, &der!(&authenticator)?, &now, options)?;
        let token = if framed { gss_framed(&ap) } else { ap };
        println!("{name} {}", hex(&token));
    }
    Ok(())
}

fn gss_framed(ap: &[u8]) -> Vec<u8> {
    let body = [&[0x06, 0x09][..], krb5_gss::KRB5_OID, &[0x01, 0x00], ap].concat();
    let mut out = vec![0x60];
    der_len(&mut out, body.len());
    out.extend(body);
    out
}

/// MIT's and our kadmind take the first key alone and refuse the rest.
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
        krb5_gss::GSS_C_MUTUAL | krb5_gss::GSS_C_REPLAY,
        None,
        None,
        None,
        0,
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
            print_cases(cases()?);
            Ok(true)
        }
        [cmd, cases, mit] if cmd == "judge" => judge(cases, mit, rust_answer),
        [cmd] if cmd == "order" => {
            println!("#key 18 1 {} {SERVICE}", hex(&SERVICE_KEY));
            println!("#key 17 1 {} {SERVICE}", hex(&SERVICE_KEY_128));
            print_cases(order_cases()?);
            Ok(true)
        }
        [cmd, cases, mit] if cmd == "judge-order" => {
            let replay = ReplayCache::new();
            let keys = [
                key(&SERVICE_KEY)?,
                ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &SERVICE_KEY_128)
                    .map_err(|e| e.to_string())?,
            ];
            let permitted = [EncryptionType::Aes256CtsHmacSha196];
            judge(cases, mit, |kind, ap, _| {
                match oracle_verify(ap, &replay, &keys, kind, &permitted) {
                    Ok(_) => "0".into(),
                    Err(Error::KrbError { code, text }) => {
                        format!("krb5:{code}\t{}", text.unwrap_or_default())
                    }
                    Err(Error::NopermEtype(text)) => format!("krb5:236\t{text}"),
                    Err(e) => format!("other:{e}"),
                }
            })
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
        [cmd, keytab, service] if cmd == "gss-transit" => {
            gss_transit(keytab, service)?;
            Ok(true)
        }
        [cmd, keytab, service] if cmd == "gss-errtok" => {
            gss_errtok(keytab, service)?;
            Ok(true)
        }
        [cmd, addr, keytab, client, opts @ ..] if cmd == "kadmind-init" => {
            kadmind_init(addr, keytab, client, opts)?;
            Ok(true)
        }
        _ => Err(
            "usage: rd-sweep cases | judge <cases> <mit> | order | judge-order <cases> <mit> | \
                  kpasswd <keytab> <client> \
                  [setpw] [raddr=IP] [entry=N] | judge-explicit <frames> <mit> <dump> <password> | \
                  kadmind <keytab> <client> | judge-kdb <cases> <mit> <dump> <password> | \
                  kadmind-init <host:port> <keytab> <client> [service=P] [entry=N] \
                  [flavor=rpcsec|agss] | gss-transit <keytab> <service> | \
                  gss-errtok <keytab> <service>"
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
