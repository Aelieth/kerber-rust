// Decode sweep (`asn1-sweep`, `tests/asn1_sweep.rs`, `include!`).
// One `decode_krb5_<type>` value: OPTIONALs set, SEQUENCE OF length 2.
// Break each `[n]`, SEQUENCE OF element and 32-bit counter (0x01020304, MIT's edges).
// Rust refuses exactly when MIT's oracle does, else re-encodes as MIT does.

use krb5_types::cammac::{AdKdcIssued, Cammac, VerifierMac};
use krb5_types::fast::{
    KrbFastArmor, KrbFastArmoredRep, KrbFastArmoredReq, KrbFastFinished, KrbFastReq,
    KrbFastResponse, PaFxFast, PaFxFastRep, SecureCookie, fast_options_none,
};
use krb5_types::s4u::{PaForUser, PaPacOptions, PaS4uX509User, S4uUserId};
use krb5_types::spake::{PaSpake, SpakeChallenge, SpakeResponse, SpakeSecondFactor, SpakeSupport};
use krb5_types::{
    ApOptions, ApRep, ApReq, AsRep, AsReq, Authenticator, AuthorizationData,
    AuthorizationDataValue, BitString, ChangePasswdData, Checksum, EncApRepPart, EncKdcRepPart,
    EncKrbCredPart, EncKrbPrivPart, EncTgsRepPart, EncTicketPart, EncryptedData, EncryptionKey,
    EtypeInfo, EtypeInfo2, EtypeInfo2Entry, EtypeInfoEntry, HostAddress, KdcOptions, KdcRep,
    KdcReq, KdcReqBody, KerberosTime, KrbCred, KrbCredInfo, KrbError, KrbPriv, KrbSafe,
    KrbSafeBody, LastReqValue, MethodData, Microseconds, OctetString, PaData, PaEncTsEnc,
    PaPacRequest, PrincipalName, Realm, TgsRep, TgsReq, Ticket, TicketFlags, TransitedEncoding,
    TypedData, TypedDataList, ascii,
};

include!("der_breaks.rs");

#[derive(Clone, Debug)]
struct Case {
    id: String,
    mit: &'static str,
    der: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Verdict {
    Refused,
    Decoded(Vec<u8>),
}

macro_rules! verdict {
    ($t:ty) => {
        |der: &[u8]| match krb5_asn1::decode::<$t>(der) {
            Ok(v) => Verdict::Decoded(krb5_asn1::encode(&v).unwrap_or_default()),
            Err(_) => Verdict::Refused,
        }
    };
}

/// `decode_krb5_enc_kdc_rep_part` takes `[APPLICATION 26]` or `25`; MIT re-encodes 26.
fn verdict_enc_kdc_rep_part(der: &[u8]) -> Verdict {
    match krb5_asn1::decode_enc_kdc_rep_part(der) {
        Ok(v) => Verdict::Decoded(krb5_asn1::encode(&EncTgsRepPart(v)).unwrap_or_default()),
        Err(_) => Verdict::Refused,
    }
}

/// A message type: name, MIT decoder (`decode_krb5_<mit>`), DER and `Debug`,
struct Message {
    name: &'static str,
    mit: &'static str,
    der: Vec<u8>,
    debug: String,
    judge: fn(&[u8]) -> Verdict,
}

macro_rules! message {
    ($name:literal, $mit:literal, $t:ty, $value:expr) => {{
        let value: $t = $value;
        Message {
            name: $name,
            mit: $mit,
            der: krb5_asn1::encode(&value).unwrap_or_default(),
            debug: format!("{value:?}"),
            judge: verdict!($t),
        }
    }};
}

fn t(s: &str) -> KerberosTime {
    krb5_types::kerberos_time_from_utc_z(s).unwrap_or_else(|_| KerberosTime::from_unix_seconds(0))
}
fn realm() -> Realm {
    ascii("KERBER.TEST")
}
fn pn(parts: [&str; 2]) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, parts)
}
fn krbtgt() -> PrincipalName {
    PrincipalName::krbtgt("KERBER.TEST")
}
fn octets(fill: u8, len: usize) -> OctetString {
    OctetString::from(vec![fill; len])
}
fn usec() -> Microseconds {
    Microseconds(COUNTER)
}
fn enc() -> EncryptedData {
    EncryptedData {
        etype: 18,
        kvno: Some(COUNTER),
        cipher: octets(0xee, 16),
    }
}
fn key() -> EncryptionKey {
    EncryptionKey {
        keytype: 18,
        keyvalue: octets(0x11, 32),
    }
}
fn cksum() -> Checksum {
    Checksum {
        cksumtype: 16,
        checksum: octets(0xcc, 12),
    }
}
fn addr(last: u8) -> HostAddress {
    HostAddress {
        addr_type: 2,
        address: OctetString::from(vec![192, 0, 2, last]),
    }
}
fn addrs() -> Vec<HostAddress> {
    vec![addr(1), addr(2)]
}
fn authdata() -> AuthorizationData {
    vec![
        AuthorizationDataValue {
            ad_type: 1,
            ad_data: octets(0xad, 4),
        },
        AuthorizationDataValue {
            ad_type: 128,
            ad_data: octets(0xae, 4),
        },
    ]
}
fn padata() -> Vec<PaData> {
    vec![
        PaData {
            padata_type: 2,
            padata_value: octets(0x01, 4),
        },
        PaData {
            padata_type: 149,
            padata_value: octets(0x02, 4),
        },
    ]
}
fn ticket() -> Ticket {
    Ticket {
        tkt_vno: Ticket::VNO,
        realm: realm(),
        sname: krbtgt(),
        enc_part: enc(),
    }
}
/// Forwardable and renewable: MIT omits zero flags, and a renew-till that is not renewable.
fn flags() -> TicketFlags {
    TicketFlags::from_u32(0x4080_0000)
}
/// One bit set: MIT leaves out zero S4U options.
fn kerberos_flags() -> BitString {
    let mut bits = BitString::repeat(false, 32);
    bits.set(2, true);
    bits
}
fn req_body() -> KdcReqBody {
    KdcReqBody {
        kdc_options: KdcOptions::none(),
        cname: Some(pn(["user", "admin"])),
        realm: realm(),
        sname: Some(krbtgt()),
        from: Some(t("20261005120000Z")),
        till: t("20261006120000Z"),
        rtime: Some(t("20261012120000Z")),
        nonce: COUNTER,
        etype: vec![18, 17],
        addresses: Some(addrs()),
        enc_authorization_data: Some(enc()),
        additional_tickets: Some(vec![ticket(), ticket()]),
    }
}
fn kdc_req(msg_type: i32) -> KdcReq {
    KdcReq {
        pvno: KdcReq::PVNO,
        msg_type,
        padata: Some(padata()),
        req_body: req_body(),
    }
}
fn kdc_rep(msg_type: i32) -> KdcRep {
    KdcRep {
        pvno: KdcRep::PVNO,
        msg_type,
        padata: Some(padata()),
        crealm: realm(),
        cname: pn(["user", "admin"]),
        ticket: ticket(),
        enc_part: enc(),
    }
}
fn enc_kdc_rep_part() -> EncKdcRepPart {
    EncKdcRepPart {
        key: key(),
        last_req: vec![
            LastReqValue {
                lr_type: 0,
                lr_value: t("20261005120000Z"),
            },
            LastReqValue {
                lr_type: 6,
                lr_value: t("20261005120001Z"),
            },
        ],
        nonce: COUNTER,
        key_expiration: Some(t("20270101000000Z")),
        flags: flags(),
        authtime: t("20261005120000Z"),
        starttime: Some(t("20261005120000Z")),
        endtime: t("20261006120000Z"),
        renew_till: Some(t("20261012120000Z")),
        srealm: realm(),
        sname: krbtgt(),
        caddr: Some(addrs()),
        encrypted_pa_data: Some(padata()),
    }
}
fn cred_info() -> KrbCredInfo {
    KrbCredInfo {
        key: key(),
        prealm: Some(realm()),
        pname: Some(pn(["user", "admin"])),
        flags: Some(flags()),
        authtime: Some(t("20261005120000Z")),
        starttime: Some(t("20261005120000Z")),
        endtime: Some(t("20261006120000Z")),
        renew_till: Some(t("20261012120000Z")),
        srealm: Some(realm()),
        sname: Some(krbtgt()),
        caddr: Some(addrs()),
    }
}
fn verifier() -> VerifierMac {
    VerifierMac {
        identifier: Some(krbtgt()),
        kvno: Some(COUNTER),
        enctype: Some(18),
        mac: cksum(),
    }
}
fn spake_factors() -> Vec<SpakeSecondFactor> {
    vec![
        SpakeSecondFactor {
            factor_type: 1,
            data: Some(octets(0x5f, 4)),
        },
        SpakeSecondFactor {
            factor_type: 2,
            data: Some(octets(0x6f, 4)),
        },
    ]
}

/// Every message type the sweep breaks, with MIT's decoder for it.
#[allow(clippy::too_many_lines)]
fn messages() -> Vec<Message> {
    let mut out = vec![
        message!(
            "as-req",
            "as_req",
            AsReq,
            AsReq(kdc_req(KdcReq::MSG_AS_REQ))
        ),
        message!(
            "tgs-req",
            "tgs_req",
            TgsReq,
            TgsReq(kdc_req(KdcReq::MSG_TGS_REQ))
        ),
        message!("kdc-req-body", "kdc_req_body", KdcReqBody, req_body()),
        message!(
            "ap-req",
            "ap_req",
            ApReq,
            ApReq {
                pvno: ApReq::PVNO,
                msg_type: ApReq::MSG_TYPE,
                ap_options: ApOptions::none(),
                ticket: ticket(),
                authenticator: enc(),
            }
        ),
        message!(
            "authenticator",
            "authenticator",
            Authenticator,
            Authenticator {
                authenticator_vno: Authenticator::VNO,
                crealm: realm(),
                cname: pn(["user", "admin"]),
                cksum: Some(cksum()),
                cusec: usec(),
                ctime: t("20261005120000Z"),
                subkey: Some(key()),
                seq_number: Some(COUNTER),
                authorization_data: Some(authdata()),
            }
        ),
        message!(
            "ap-rep",
            "ap_rep",
            ApRep,
            ApRep {
                pvno: ApRep::PVNO,
                msg_type: ApRep::MSG_TYPE,
                enc_part: enc(),
            }
        ),
        message!(
            "enc-ap-rep-part",
            "ap_rep_enc_part",
            EncApRepPart,
            EncApRepPart {
                ctime: t("20261005120000Z"),
                cusec: usec(),
                subkey: Some(key()),
                seq_number: Some(COUNTER),
            }
        ),
        message!(
            "as-rep",
            "as_rep",
            AsRep,
            AsRep(kdc_rep(KdcRep::MSG_AS_REP))
        ),
        message!(
            "tgs-rep",
            "tgs_rep",
            TgsRep,
            TgsRep(kdc_rep(KdcRep::MSG_TGS_REP))
        ),
        message!(
            "enc-tkt-part",
            "enc_tkt_part",
            EncTicketPart,
            EncTicketPart {
                flags: flags(),
                key: key(),
                crealm: realm(),
                cname: pn(["user", "admin"]),
                transited: TransitedEncoding::empty(),
                authtime: t("20261005120000Z"),
                starttime: Some(t("20261005120000Z")),
                endtime: t("20261006120000Z"),
                renew_till: Some(t("20261012120000Z")),
                caddr: Some(addrs()),
                authorization_data: Some(authdata()),
            }
        ),
        message!("ticket", "ticket", Ticket, ticket()),
        message!(
            "krb-error",
            "error",
            KrbError,
            KrbError {
                pvno: KrbError::PVNO,
                msg_type: KrbError::MSG_TYPE,
                ctime: Some(t("20261005120000Z")),
                cusec: Some(usec()),
                stime: t("20261005120001Z"),
                susec: usec(),
                error_code: 25,
                crealm: Some(realm()),
                cname: Some(pn(["user", "admin"])),
                realm: realm(),
                sname: krbtgt(),
                e_text: Some(ascii("NEEDED_PREAUTH")),
                e_data: Some(octets(0x30, 4)),
            }
        ),
        message!(
            "krb-safe",
            "safe",
            KrbSafe,
            KrbSafe {
                pvno: KrbSafe::PVNO,
                msg_type: KrbSafe::MSG_TYPE,
                safe_body: KrbSafeBody {
                    user_data: octets(0x55, 3),
                    timestamp: Some(t("20261005120000Z")),
                    usec: Some(usec()),
                    seq_number: Some(COUNTER),
                    s_address: addr(1),
                    r_address: Some(addr(2)),
                },
                cksum: cksum(),
            }
        ),
        message!(
            "krb-priv",
            "priv",
            KrbPriv,
            KrbPriv {
                pvno: KrbPriv::PVNO,
                msg_type: KrbPriv::MSG_TYPE,
                enc_part: enc(),
            }
        ),
        message!(
            "enc-krb-priv-part",
            "enc_priv_part",
            EncKrbPrivPart,
            EncKrbPrivPart {
                user_data: octets(0x55, 3),
                timestamp: Some(t("20261005120000Z")),
                usec: Some(usec()),
                seq_number: Some(COUNTER),
                s_address: addr(1),
                r_address: Some(addr(2)),
            }
        ),
        message!(
            "krb-cred",
            "cred",
            KrbCred,
            KrbCred {
                pvno: 5,
                msg_type: 22,
                tickets: vec![ticket(), ticket()],
                enc_part: enc(),
            }
        ),
        message!(
            "enc-krb-cred-part",
            "enc_cred_part",
            EncKrbCredPart,
            EncKrbCredPart {
                ticket_info: vec![cred_info(), cred_info()],
                nonce: Some(COUNTER),
                timestamp: Some(t("20261005120000Z")),
                usec: Some(usec()),
                s_address: Some(addr(1)),
                r_address: Some(addr(2)),
            }
        ),
        message!(
            "pa-enc-ts-enc",
            "pa_enc_ts",
            PaEncTsEnc,
            PaEncTsEnc {
                patimestamp: t("20261005120000Z"),
                pausec: Some(usec()),
            }
        ),
        message!(
            "etype-info2",
            "etype_info2",
            EtypeInfo2,
            vec![
                EtypeInfo2Entry {
                    etype: 18,
                    salt: Some(ascii("KERBER.TESTuser")),
                    s2kparams: Some(OctetString::from(vec![0, 0, 0x10, 0])),
                },
                EtypeInfo2Entry {
                    etype: 17,
                    salt: Some(ascii("KERBER.TESTuser")),
                    s2kparams: Some(OctetString::from(vec![0, 0, 0x10, 0])),
                },
            ]
        ),
        message!(
            "etype-info",
            "etype_info",
            EtypeInfo,
            vec![
                EtypeInfoEntry {
                    etype: 23,
                    salt: Some(OctetString::from(b"KERBER.TESTuser".to_vec())),
                },
                EtypeInfoEntry {
                    etype: 3,
                    salt: Some(OctetString::from(b"KERBER.TESTuser".to_vec())),
                },
            ]
        ),
        message!("method-data", "padata_sequence", MethodData, padata()),
        message!(
            "pa-for-user",
            "pa_for_user",
            PaForUser,
            PaForUser {
                user_name: pn(["user", "admin"]),
                user_realm: realm(),
                cksum: cksum(),
                auth_package: ascii("Kerberos"),
            }
        ),
        message!(
            "pa-s4u-x509-user",
            "pa_s4u_x509_user",
            PaS4uX509User,
            PaS4uX509User {
                user_id: S4uUserId {
                    nonce: i32::try_from(COUNTER).unwrap_or_default(),
                    user: Some(pn(["user", "admin"])),
                    realm: realm(),
                    subject_cert: Some(octets(0x30, 8)),
                    options: Some(kerberos_flags()),
                },
                cksum: cksum(),
            }
        ),
        message!(
            "pa-pac-options",
            "pa_pac_options",
            PaPacOptions,
            PaPacOptions {
                flags: kerberos_flags(),
            }
        ),
        message!(
            "pa-pac-request",
            "pa_pac_req",
            PaPacRequest,
            PaPacRequest { include_pac: true }
        ),
        message!(
            "krb-fast-req",
            "fast_req",
            KrbFastReq,
            KrbFastReq {
                fast_options: fast_options_none(),
                padata: padata(),
                req_body: req_body(),
            }
        ),
        message!(
            "pa-fx-fast-request",
            "pa_fx_fast_request",
            PaFxFast,
            PaFxFast::ArmoredData(KrbFastArmoredReq {
                armor: Some(KrbFastArmor {
                    armor_type: 1,
                    armor_value: octets(0x6e, 8),
                }),
                req_checksum: cksum(),
                enc_fast_req: enc(),
            })
        ),
        message!(
            "pa-fx-fast-reply",
            "pa_fx_fast_reply",
            PaFxFastRep,
            PaFxFastRep::ArmoredData(KrbFastArmoredRep {
                enc_fast_rep: enc(),
            })
        ),
        message!(
            "krb-fast-response",
            "fast_response",
            KrbFastResponse,
            KrbFastResponse {
                padata: padata(),
                strengthen_key: Some(key()),
                finished: Some(KrbFastFinished {
                    timestamp: t("20261005120000Z"),
                    usec: usec(),
                    crealm: realm(),
                    cname: pn(["user", "admin"]),
                    ticket_checksum: cksum(),
                }),
                nonce: COUNTER,
            }
        ),
        message!(
            "secure-cookie",
            "secure_cookie",
            SecureCookie,
            SecureCookie {
                time: 1_791_201_600,
                data: padata(),
            }
        ),
        message!(
            "pa-spake-support",
            "pa_spake",
            PaSpake,
            PaSpake::Support(SpakeSupport { groups: vec![1, 2] })
        ),
        message!(
            "pa-spake-challenge",
            "pa_spake",
            PaSpake,
            PaSpake::Challenge(SpakeChallenge {
                group: 2,
                pubkey: octets(0x04, 8),
                factors: spake_factors(),
            })
        ),
        message!(
            "pa-spake-response",
            "pa_spake",
            PaSpake,
            PaSpake::Response(SpakeResponse {
                pubkey: octets(0x04, 8),
                factor: enc(),
            })
        ),
        message!(
            "spake-factor",
            "spake_factor",
            SpakeSecondFactor,
            SpakeSecondFactor {
                factor_type: 1,
                data: Some(octets(0x5f, 4)),
            }
        ),
        message!(
            "cammac",
            "cammac",
            Cammac,
            Cammac {
                elements: authdata(),
                kdc_verifier: Some(verifier()),
                svc_verifier: Some(verifier()),
                other_verifiers: Some(vec![verifier(), verifier()]),
            }
        ),
        message!(
            "ad-kdcissued",
            "ad_kdcissued",
            AdKdcIssued,
            AdKdcIssued {
                ad_checksum: cksum(),
                i_realm: Some(realm()),
                i_sname: Some(krbtgt()),
                elements: authdata(),
            }
        ),
        message!(
            "typed-data",
            "typed_data",
            TypedDataList,
            vec![
                TypedData {
                    data_type: 1,
                    data_value: octets(0x01, 4),
                },
                TypedData {
                    data_type: 2,
                    data_value: octets(0x02, 4),
                },
            ]
        ),
        message!("authdata", "authdata", AuthorizationData, authdata()),
        message!(
            "setpw-req",
            "setpw_req",
            ChangePasswdData,
            ChangePasswdData {
                newpasswd: octets(0x70, 8),
                targname: pn(["user", "admin"]),
                targrealm: realm(),
            }
        ),
        message!("enc-data", "enc_data", EncryptedData, enc()),
    ];
    let value = EncTgsRepPart(enc_kdc_rep_part());
    out.push(Message {
        name: "enc-kdc-rep-part",
        mit: "enc_kdc_rep_part",
        der: krb5_asn1::encode(&value).unwrap_or_default(),
        debug: format!("{value:?}"),
        judge: verdict_enc_kdc_rep_part,
    });
    out
}

fn corpus(messages: &[Message]) -> Vec<Case> {
    let mut out = Vec::new();
    for m in messages {
        let Some(root) = der_parse(&m.der).and_then(|mut v| (v.len() == 1).then(|| v.remove(0)))
        else {
            continue;
        };
        out.push(Case {
            id: format!("{}/pristine", m.name),
            mit: m.mit,
            der: m.der.clone(),
        });
        for (place, broken) in all_breaks(&root) {
            out.push(Case {
                id: format!("{}/{place}", m.name),
                mit: m.mit,
                der: broken.bytes(),
            });
        }
    }
    out
}

fn fnv64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn corpus_text(cases: &[Case]) -> String {
    cases.iter().fold(String::new(), |mut out, c| {
        let _ = writeln!(out, "{}\t{}\t{}", c.id, c.mit, hex(&c.der));
        out
    })
}

/// Cases the Rust decoder accepts, re-encoded so MIT compares the two values (same ids).
fn rust_text(messages: &[Message], cases: &[Case]) -> String {
    cases.iter().fold(String::new(), |mut out, c| {
        if let Some(Verdict::Decoded(der)) = judge_case(messages, c) {
            let _ = writeln!(out, "{}\t{}\t{}", c.id, c.mit, hex(&der));
        }
        out
    })
}

fn judge_case(messages: &[Message], c: &Case) -> Option<Verdict> {
    let name = c.id.split('/').next()?;
    let m = messages.iter().find(|m| m.name == name)?;
    Some((m.judge)(&c.der))
}

/// MIT's decoder on one case: refused, or decoded (hash of what MIT's encoder
#[derive(Clone, Debug, PartialEq, Eq)]
enum Mit {
    Refused,
    Decoded(Option<u64>),
}

fn parse_mit(text: &str) -> std::collections::HashMap<String, Mit> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            let id = f.next()?.to_string();
            let v = match (f.next()?, f.next()) {
                ("ERR", _) => Mit::Refused,
                ("OK", Some(h)) => Mit::Decoded(u64::from_str_radix(h, 16).ok()),
                ("OK", None) => Mit::Decoded(None),
                _ => return None,
            };
            Some((id, v))
        })
        .collect()
}

/// Golden: MIT's verdict and the re-encoding hash (`-` refuses, `?` parts).
/// Line 1 names the corpus.
fn golden_text(
    messages: &[Message],
    cases: &[Case],
    mit: &std::collections::HashMap<String, Mit>,
    mit_of_rust: &std::collections::HashMap<String, Mit>,
) -> (String, Vec<String>) {
    let mut text = format!("# corpus {:016x}\n", fnv64(corpus_text(cases).as_bytes()));
    let mut parts = Vec::new();
    for c in cases {
        let ours = judge_case(messages, c);
        let line = match (mit.get(&c.id), &ours) {
            (Some(Mit::Refused), Some(Verdict::Refused)) => "refused\t-".to_string(),
            (Some(Mit::Decoded(case_hash)), Some(Verdict::Decoded(der))) => {
                let agree = match (case_hash, mit_of_rust.get(&c.id)) {
                    (None, _) => true,
                    (Some(h), Some(Mit::Decoded(Some(r)))) => h == r,
                    _ => false,
                };
                if agree {
                    format!("decoded\t{:016x}", fnv64(der))
                } else {
                    parts.push(format!(
                        "{}\tMIT and Rust decode it to different values",
                        c.id
                    ));
                    "decoded\t?".to_string()
                }
            }
            (Some(Mit::Refused), Some(Verdict::Decoded(_))) => {
                parts.push(format!("{}\tMIT refuses it, Rust decodes it", c.id));
                "refused\t?".to_string()
            }
            (Some(Mit::Decoded(_)), Some(Verdict::Refused)) => {
                parts.push(format!("{}\tMIT decodes it, Rust refuses it", c.id));
                "decoded\t?".to_string()
            }
            _ => {
                parts.push(format!("{}\tno verdict", c.id));
                "?\t?".to_string()
            }
        };
        let _ = writeln!(text, "{}\t{line}", c.id);
    }
    (text, parts)
}

fn check_golden(messages: &[Message], cases: &[Case], golden: &str) -> Vec<String> {
    let mut lines = golden.lines();
    let want = format!("# corpus {:016x}", fnv64(corpus_text(cases).as_bytes()));
    if lines.next() != Some(want.as_str()) {
        return vec![format!(
            "the golden is for another corpus ({want} expected): regenerate it with scripts/asn1-decode-oracle-gate.sh"
        )];
    }
    let by_id: std::collections::HashMap<&str, (&str, &str)> = lines
        .filter_map(|l| {
            let mut f = l.split('\t');
            Some((f.next()?, (f.next()?, f.next()?)))
        })
        .collect();
    let mut parts = Vec::new();
    for c in cases {
        let Some(&(verdict, hash)) = by_id.get(c.id.as_str()) else {
            parts.push(format!("{}\tnot in the golden", c.id));
            continue;
        };
        let ours = judge_case(messages, c);
        let agree = match (verdict, &ours) {
            ("refused", Some(Verdict::Refused)) => hash != "?",
            ("decoded", Some(Verdict::Decoded(der))) => hash == format!("{:016x}", fnv64(der)),
            _ => false,
        };
        if !agree {
            let ours = match ours {
                Some(Verdict::Refused) => "refuses it".to_string(),
                Some(Verdict::Decoded(der)) => format!("decodes it to {:016x}", fnv64(&der)),
                None => "has no message for it".to_string(),
            };
            parts.push(format!("{}\tMIT {verdict} it ({hash}); Rust {ours}", c.id));
        }
    }
    parts
}
