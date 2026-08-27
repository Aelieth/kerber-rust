//! Dual-send driver: encode each AS/TGS case once, `exchange_on_tcp` to both KDCs.
//!
//! Usage: diffsend <rust-host:port> <mit-host:port> [out-dir]
//!
//! Env: `KRB5_PASSWORD`, `KERBER_PAUSER_PASSWORD`, `KERBER_DIFF_REALM`,
//! `KERBER_KRBTGT_KEYTAB`, `KERBER_HOST_KEYTAB`.

#![forbid(unsafe_code)]

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt, string_to_key};
use krb5_protocol::{
    KdcAddr, Keytab, Whitelist, as_req, as_req_sname, compare_krb_error, compare_stable_rep,
    decode_enc_kdc_rep, exchange_on_tcp, pa_enc_timestamp, pa_enc_timestamp_at, tgs_req,
};
use krb5_types::{
    AsRep, EncTicketPart, EncryptedData, EncryptionKey, KerberosTime, KrbError, PrincipalName,
    TgsRep, Ticket, TicketFlags, TransitedEncoding, err, ku,
};
use sha1::{Digest, Sha1};

struct Cfg {
    rust: KdcAddr,
    mit: KdcAddr,
    out: PathBuf,
    realm: String,
    user_pw: Vec<u8>,
    pauser_pw: Vec<u8>,
    krbtgt: Option<Keytab>,
    host: Option<Keytab>,
}

fn parse_addr(s: &str) -> KdcAddr {
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse() {
            return KdcAddr {
                host: h.to_owned(),
                port,
            };
        }
    }
    KdcAddr::new(s)
}

fn sha1_hex(bytes: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn write_der(dir: &Path, name: &str, bytes: &[u8]) {
    let _ = fs::create_dir_all(dir);
    let _ = fs::write(dir.join(name), bytes);
}

fn send_both(cfg: &Cfg, case: &str, req: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    write_der(&cfg.out, &format!("{case}.req.der"), req);
    println!(
        r#"{{"event":"diffsend","case":"{case}","req_sha1":"{}","req_len":{},"same_request_bytes":true}}"#,
        sha1_hex(req),
        req.len()
    );
    let rust = exchange_on_tcp(&cfg.rust, req).map_err(|e| format!("{case} rust: {e}"))?;
    let mit = exchange_on_tcp(&cfg.mit, req).map_err(|e| format!("{case} mit: {e}"))?;
    write_der(&cfg.out, &format!("{case}.rust.der"), &rust);
    write_der(&cfg.out, &format!("{case}.mit.der"), &mit);
    Ok((rust, mit))
}

fn expect_error(cfg: &Cfg, case: &str, req: &[u8], code: i32) -> Result<(), String> {
    let (rust, mit) = send_both(cfg, case, req)?;
    if rust.first() != Some(&0x7e) {
        return Err(format!(
            "{case}: rust tag {:02x} want 0x7e",
            rust.first().unwrap_or(&0)
        ));
    }
    if mit.first() != Some(&0x7e) {
        return Err(format!(
            "{case}: mit tag {:02x} want 0x7e",
            mit.first().unwrap_or(&0)
        ));
    }
    let re: KrbError = decode(&rust).map_err(|e| format!("{case} rust decode: {e}"))?;
    let me: KrbError = decode(&mit).map_err(|e| format!("{case} mit decode: {e}"))?;
    if re.error_code != code {
        return Err(format!(
            "{case}: rust error_code {} want {code}",
            re.error_code
        ));
    }
    compare_krb_error(&re, &me).map_err(|e| format!("{case}: {e}"))?;
    println!(
        r#"{{"event":"diffsend","case":"{case}","outcome":"ok","error_code":{},"rust_tag":"0x7e","mit_tag":"0x7e"}}"#,
        re.error_code
    );
    Ok(())
}

fn expect_garbage(cfg: &Cfg, req: &[u8]) -> Result<(), String> {
    write_der(&cfg.out, "garbage-pdu.req.der", req);
    println!(
        r#"{{"event":"diffsend","case":"garbage-pdu","req_sha1":"{}","req_len":{},"same_request_bytes":true}}"#,
        sha1_hex(req),
        req.len()
    );
    let rust = exchange_on_tcp(&cfg.rust, req).map_err(|e| format!("garbage-pdu rust: {e}"))?;
    write_der(&cfg.out, "garbage-pdu.rust.der", &rust);
    if rust.first() != Some(&0x7e) {
        return Err(format!(
            "garbage-pdu: rust tag {:02x} want 0x7e",
            rust.first().unwrap_or(&0)
        ));
    }
    let re: KrbError = decode(&rust).map_err(|e| format!("garbage-pdu rust decode: {e}"))?;
    if re.error_code != err::GENERIC {
        return Err(format!(
            "garbage-pdu: rust error_code {} want GENERIC",
            re.error_code
        ));
    }
    match exchange_on_tcp(&cfg.mit, req) {
        Ok(mit) => {
            write_der(&cfg.out, "garbage-pdu.mit.der", &mit);
            if mit.first() != Some(&0x7e) {
                return Err(format!(
                    "garbage-pdu: mit tag {:02x} want 0x7e",
                    mit.first().unwrap_or(&0)
                ));
            }
            let me: KrbError = decode(&mit).map_err(|e| format!("garbage-pdu mit decode: {e}"))?;
            compare_krb_error(&re, &me).map_err(|e| format!("garbage-pdu: {e}"))?;
            println!(
                r#"{{"event":"diffsend","case":"garbage-pdu","outcome":"ok","error_code":60,"rust_tag":"0x7e","mit_tag":"0x7e"}}"#
            );
        }
        Err(_) => {
            // MIT 1.22.2 closes TCP on truncated DER instead of KRB-ERROR.
            println!(
                r#"{{"event":"diffsend","case":"garbage-pdu","outcome":"ok","error_code":60,"rust_tag":"0x7e","mit_tag":"drop","whitelist":["mit-drop-garbage-pdu"]}}"#
            );
        }
    }
    Ok(())
}

fn client_key(
    etype: i32,
    pw: &[u8],
    cname: &PrincipalName,
    realm: &str,
) -> Result<ProtocolKey, String> {
    let et = EncryptionType::from_iana(etype)
        .or_else(|_| EncryptionType::known(etype))
        .map_err(|e| e.to_string())?;
    string_to_key(et, pw, &cname.default_salt(realm), None).map_err(|e| e.to_string())
}

fn load_keytab(path: &str) -> Result<Keytab, String> {
    let bytes = fs::read(path).map_err(|e| format!("keytab {path}: {e}"))?;
    Keytab::parse(&bytes).map_err(|e| format!("keytab parse: {e}"))
}

fn keytab_for(kt: &Keytab, etype: i32) -> Result<(&ProtocolKey, u32), String> {
    kt.entries
        .iter()
        .find(|e| e.key.etype().to_iana() == etype)
        .or_else(|| kt.entries.first())
        .map(|e| (&e.key, e.kvno))
        .ok_or_else(|| "empty keytab".to_string())
}

fn decrypt_as(
    raw: &[u8],
    pw: &[u8],
    cname: &PrincipalName,
    realm: &str,
    tkt_kt: &Keytab,
) -> Result<
    (
        krb5_types::KdcRep,
        krb5_types::EncKdcRepPart,
        EncTicketPart,
        bool,
        ProtocolKey,
    ),
    String,
> {
    if raw.first() != Some(&0x6b) {
        return Err(format!(
            "want AS-REP 0x6b got {:02x}",
            raw.first().unwrap_or(&0)
        ));
    }
    let AsRep(rep) = decode::<AsRep>(raw).map_err(|e| e.to_string())?;
    let ckey = client_key(rep.enc_part.etype, pw, cname, realm)?;
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).map_err(|e| e.to_string())?;
    let plain = decrypt(&ckey, usage, rep.enc_part.cipher.as_ref()).map_err(|e| e.to_string())?;
    let (enc, app26) = decode_enc_kdc_rep(&plain).map_err(|e| e.to_string())?;
    let t_usage = KeyUsage::new(ku::TICKET).map_err(|e| e.to_string())?;
    let (tkt_key, _) = keytab_for(tkt_kt, rep.ticket.enc_part.etype)?;
    let tplain = decrypt(tkt_key, t_usage, rep.ticket.enc_part.cipher.as_ref())
        .map_err(|e| format!("ticket decrypt: {e}"))?;
    let tkt: EncTicketPart = decode(&tplain).map_err(|e| e.to_string())?;
    let sess_et = EncryptionType::from_iana(enc.key.keytype)
        .or_else(|_| EncryptionType::known(enc.key.keytype))
        .map_err(|e| e.to_string())?;
    let session =
        ProtocolKey::from_bytes(sess_et, enc.key.keyvalue.as_ref()).map_err(|e| e.to_string())?;
    Ok((rep, enc, tkt, app26, session))
}

fn decrypt_tgs(
    raw: &[u8],
    session: &ProtocolKey,
    svc_kt: &Keytab,
) -> Result<(krb5_types::KdcRep, krb5_types::EncKdcRepPart, EncTicketPart), String> {
    if raw.first() != Some(&0x6d) {
        if raw.first() == Some(&0x7e) {
            if let Ok(e) = decode::<KrbError>(raw) {
                let text = e
                    .e_text
                    .as_ref()
                    .and_then(|s| std::str::from_utf8(s.as_bytes()).ok())
                    .unwrap_or("");
                return Err(format!(
                    "want TGS-REP 0x6d got KRB-ERROR {} {text}",
                    e.error_code
                ));
            }
        }
        return Err(format!(
            "want TGS-REP 0x6d got {:02x}",
            raw.first().unwrap_or(&0)
        ));
    }
    let TgsRep(rep) = decode::<TgsRep>(raw).map_err(|e| e.to_string())?;
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART).map_err(|e| e.to_string())?;
    let plain = decrypt(session, usage, rep.enc_part.cipher.as_ref()).map_err(|e| e.to_string())?;
    let (enc, _) = decode_enc_kdc_rep(&plain).map_err(|e| e.to_string())?;
    let t_usage = KeyUsage::new(ku::TICKET).map_err(|e| e.to_string())?;
    let (svc_key, _) = keytab_for(svc_kt, rep.ticket.enc_part.etype)?;
    let tplain = decrypt(svc_key, t_usage, rep.ticket.enc_part.cipher.as_ref())
        .map_err(|e| format!("service ticket decrypt: {e}"))?;
    let tkt: EncTicketPart = decode(&tplain).map_err(|e| e.to_string())?;
    Ok((rep, enc, tkt))
}

fn expect_as_ok(
    cfg: &Cfg,
    case: &str,
    req: &[u8],
    cname: &PrincipalName,
) -> Result<(ProtocolKey, Ticket, ProtocolKey, Ticket), String> {
    let tkt_kt = cfg
        .krbtgt
        .as_ref()
        .ok_or_else(|| "KERBER_KRBTGT_KEYTAB required for success compare".to_string())?;
    let (rust, mit) = send_both(cfg, case, req)?;
    let (rr, re, rt, r26, session) = decrypt_as(&rust, &cfg.user_pw, cname, &cfg.realm, tkt_kt)?;
    let (mr, me, mt, m26, mit_session) = decrypt_as(&mit, &cfg.user_pw, cname, &cfg.realm, tkt_kt)?;
    let wl = Whitelist::default();
    let mut ok = compare_stable_rep(&rr, &re, &rt, &mr, &me, &mt, &wl)
        .map_err(|e| format!("{case}: {e}"))?;
    if m26 && !r26 {
        ok.whitelisted.push("mit-as-enc-app-26");
        ok.mit_as_enc_app26 = true;
    }
    println!(
        r#"{{"event":"diffsend","case":"{case}","outcome":"ok","rust_tag":"0x6b","mit_tag":"0x6b","whitelist":{:?}}}"#,
        ok.whitelisted
    );
    Ok((session, rr.ticket, mit_session, mr.ticket))
}

#[allow(clippy::too_many_arguments)]
fn mint_tgt(
    krbtgt: &ProtocolKey,
    kvno: u32,
    cname: &PrincipalName,
    realm: &str,
    sname: &PrincipalName,
    session: &ProtocolKey,
    window: (KerberosTime, KerberosTime),
    flags: TicketFlags,
) -> Result<Ticket, String> {
    let (start, end) = window;
    let part = EncTicketPart {
        flags,
        key: EncryptionKey {
            keytype: session.etype().to_iana(),
            keyvalue: session.as_bytes().to_vec().into(),
        },
        crealm: krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        cname: cname.clone(),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: Vec::<u8>::new().into(),
        },
        authtime: start.clone(),
        starttime: Some(start),
        endtime: end,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let der = encode(&part).map_err(|e| e.to_string())?;
    let usage = KeyUsage::new(ku::TICKET).map_err(|e| e.to_string())?;
    let cipher = encrypt(krbtgt, usage, &der).map_err(|e| e.to_string())?;
    Ok(Ticket {
        tkt_vno: Ticket::VNO,
        realm: krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        sname: sname.clone(),
        enc_part: EncryptedData {
            etype: krbtgt.etype().to_iana(),
            kvno: Some(kvno),
            cipher: cipher.into(),
        },
    })
}

fn random_session(etype: EncryptionType) -> Result<ProtocolKey, String> {
    let mut buf = vec![0u8; etype.key_len()];
    getrandom::getrandom(&mut buf).map_err(|e| e.to_string())?;
    ProtocolKey::from_bytes(etype, &buf).map_err(|e| e.to_string())
}

fn load_cfg() -> Result<Cfg, String> {
    let mut args = env::args().skip(1);
    let rust = args
        .next()
        .ok_or_else(|| "usage: diffsend <rust-host:port> <mit-host:port> [out-dir]".to_string())?;
    let mit = args
        .next()
        .ok_or_else(|| "missing mit-host:port".to_string())?;
    let out = PathBuf::from(args.next().unwrap_or_else(|| "/tmp/diff-corpus".into()));
    let realm = env::var("KERBER_DIFF_REALM").unwrap_or_else(|_| "KERBER.TEST".into());
    let user_pw = env::var("KRB5_PASSWORD")
        .unwrap_or_else(|_| "userpassword".into())
        .into_bytes();
    let pauser_pw = env::var("KERBER_PAUSER_PASSWORD")
        .unwrap_or_else(|_| "preauthpw".into())
        .into_bytes();
    let krbtgt = match env::var("KERBER_KRBTGT_KEYTAB") {
        Ok(p) => Some(load_keytab(&p)?),
        Err(_) => None,
    };
    let host = match env::var("KERBER_HOST_KEYTAB") {
        Ok(p) => Some(load_keytab(&p)?),
        Err(_) => None,
    };
    let _ = fs::create_dir_all(&out);
    Ok(Cfg {
        rust: parse_addr(&rust),
        mit: parse_addr(&mit),
        out,
        realm,
        user_pw,
        pauser_pw,
        krbtgt,
        host,
    })
}

fn run() -> Result<(), String> {
    let cfg = load_cfg()?;
    let realm = cfg.realm.as_str();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let pauser = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pauser"]);
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]);
    let etypes: Vec<i32> = EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect();

    let req = encode(
        &as_req(
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosuchuser"]),
            realm,
            0x1000_0001,
            None,
        )
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    expect_error(&cfg, "unknown-cname", &req, err::C_PRINCIPAL_UNKNOWN)?;

    let req = encode(
        &as_req_sname(
            user.clone(),
            realm,
            0x1000_0002,
            None,
            PrincipalName::krbtgt(realm),
            vec![99, 98],
        )
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    expect_error(&cfg, "etype-nosupp", &req, err::ETYPE_NOSUPP)?;

    let req =
        encode(&as_req(user.clone(), "OTHER.TEST", 0x1000_0003, None).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    expect_error(&cfg, "wrong-realm", &req, err::C_PRINCIPAL_UNKNOWN)?;

    let req = encode(&as_req(pauser.clone(), realm, 0x1000_0004, None).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    expect_error(&cfg, "pauser-no-preauth", &req, err::PREAUTH_REQUIRED)?;

    let pkey = client_key(18, &cfg.pauser_pw, &pauser, realm)?;
    let old = KerberosTime::now()
        .add_seconds(-3600)
        .unwrap_or_else(|_| KerberosTime::now());
    let pa = pa_enc_timestamp_at(&pkey, &old).map_err(|e| e.to_string())?;
    let req = encode(
        &as_req(pauser.clone(), realm, 0x1000_0005, Some(vec![pa])).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    expect_error(&cfg, "skewed-timestamp", &req, err::SKEW)?;

    let req = encode(
        &as_req_sname(
            user.clone(),
            realm,
            0x1000_0006,
            None,
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "no-such.kerber.test"]),
            etypes.clone(),
        )
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    expect_error(&cfg, "unknown-sname", &req, err::S_PRINCIPAL_UNKNOWN)?;

    let mut garbage =
        encode(&as_req(user.clone(), realm, 0x1000_0007, None).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    garbage.truncate(6);
    expect_garbage(&cfg, &garbage)?;

    let ukey = client_key(18, &cfg.user_pw, &user, realm)?;
    let pa = pa_enc_timestamp(&ukey).map_err(|e| e.to_string())?;
    let as_req_ok = encode(
        &as_req(user.clone(), realm, 0x1000_0010, Some(vec![pa])).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let _ = expect_as_ok(&cfg, "as-success", &as_req_ok, &user)?;

    let tkt_kt = cfg
        .krbtgt
        .as_ref()
        .ok_or_else(|| "KERBER_KRBTGT_KEYTAB required".to_string())?;
    let (tkt_key, tkt_kvno) = keytab_for(tkt_kt, 20)?;
    let now = KerberosTime::now();
    let sess = random_session(EncryptionType::Aes256CtsHmacSha196)?;
    let krbtgt_sname = PrincipalName::krbtgt(realm);
    let valid_tgt = mint_tgt(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        (
            now.clone(),
            now.add_hours(10).unwrap_or_else(|_| now.clone()),
        ),
        TicketFlags::initial_preauth()
            .with_bit(krb5_types::flag_bit::FORWARDABLE, true)
            .with_bit(krb5_types::flag_bit::CANONICALIZE, true),
    )?;
    let tgs = tgs_req(
        valid_tgt,
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_0011,
    )
    .map_err(|e| e.to_string())?;
    let tgs_bytes = encode(&tgs).map_err(|e| e.to_string())?;
    decode::<krb5_types::TgsReq>(&tgs_bytes).map_err(|e| format!("tgs-req self-decode: {e}"))?;
    let (tr, tm) = send_both(&cfg, "tgs-success", &tgs_bytes)?;
    let svc = cfg
        .host
        .as_ref()
        .ok_or_else(|| "KERBER_HOST_KEYTAB required for TGS compare".to_string())?;
    let (rr, re, rt) = decrypt_tgs(&tr, &sess, svc)?;
    let (mr, me, mt) = decrypt_tgs(&tm, &sess, svc)?;
    let wl = Whitelist::default();
    let ok = compare_stable_rep(&rr, &re, &rt, &mr, &me, &mt, &wl)
        .map_err(|e| format!("tgs-success: {e}"))?;
    println!(
        r#"{{"event":"diffsend","case":"tgs-success","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","whitelist":{:?}}}"#,
        ok.whitelisted
    );

    let (hkey, hkvno) = keytab_for(svc, 20)?;
    let not_tgt_tkt = mint_tgt(
        hkey,
        hkvno,
        &user,
        realm,
        &host,
        &sess,
        (
            now.clone(),
            now.add_hours(10).unwrap_or_else(|_| now.clone()),
        ),
        TicketFlags::initial_preauth(),
    )?;
    let not_tgt = tgs_req(
        not_tgt_tkt,
        &sess,
        realm,
        &user,
        krbtgt_sname.clone(),
        realm,
        0x1000_0008,
    )
    .map_err(|e| e.to_string())?;
    expect_error(
        &cfg,
        "tgs-not-a-tgt",
        &encode(&not_tgt).map_err(|e| e.to_string())?,
        err::NOT_US,
    )?;

    let expired = mint_tgt(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        (
            now.add_seconds(-7200).unwrap_or_else(|_| now.clone()),
            now.add_seconds(-3600).unwrap_or_else(|_| now.clone()),
        ),
        TicketFlags::initial_preauth(),
    )?;
    let tgs_exp = tgs_req(
        expired,
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_0009,
    )
    .map_err(|e| e.to_string())?;
    expect_error(
        &cfg,
        "tgt-expired",
        &encode(&tgs_exp).map_err(|e| e.to_string())?,
        err::TKT_EXPIRED,
    )?;

    let nyv = mint_tgt(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        (
            now.add_seconds(3600).unwrap_or_else(|_| now.clone()),
            now.add_seconds(7200).unwrap_or_else(|_| now.clone()),
        ),
        TicketFlags::initial_preauth(),
    )?;
    let tgs_nyv =
        tgs_req(nyv, &sess, realm, &user, host, realm, 0x1000_000a).map_err(|e| e.to_string())?;
    expect_error(
        &cfg,
        "tgt-nyv",
        &encode(&tgs_nyv).map_err(|e| e.to_string())?,
        err::TKT_NYV,
    )?;

    println!(r#"{{"event":"diffsend","outcome":"ok","cases":12}}"#);
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("FATAL: {e}");
        process::exit(1);
    }
}
