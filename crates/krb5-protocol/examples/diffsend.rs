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
use krb5_kdc::{PacTicket, pac_from_ticket_part, sign_pac, ticket_checksum_der, wrap_win2k_pac};
use krb5_protocol::{
    KdcAddr, Keytab, armor_key, as_req, as_req_sname, attach_fast, build_fast_armor,
    compare_krb_error, compare_stable_rep, decode_enc_kdc_rep, exchange_on_tcp, pa_enc_timestamp,
    pa_enc_timestamp_at, pa_for_user, pa_s4u_x509_user, pa_spake_support, tgs_req, tgs_req_ex,
};
use krb5_types::pac::{PAC_SERVER_CHECKSUM, Pac, PacIdentity, RpcSid};
use krb5_types::{
    ApOptions, ApReq, AsRep, AuthorizationDataValue, EncTicketPart, EncryptedData, EncryptionKey,
    KdcOptions, KerberosTime, KrbError, PaData, PaPacRequest, PrincipalName, TgsRep, Ticket,
    TicketFlags, TransitedEncoding, err, flag_bit, ku, pa,
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
    if let Some((h, p)) = s.rsplit_once(':')
        && let Ok(port) = p.parse()
    {
        return KdcAddr {
            host: h.to_owned(),
            port,
        };
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
    expect_error_client(cfg, case, req, code, true)
}

// AS errors echo the requested client (prepare_error_as); a TGS error uses the
// decrypted header ticket's client. tgs-not-a-tgt decrypts a service header
// and compares cname (check_client=true).
fn expect_error_client(
    cfg: &Cfg,
    case: &str,
    req: &[u8],
    code: i32,
    check_client: bool,
) -> Result<(), String> {
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
    let et = |e: &KrbError| {
        e.e_text
            .as_ref()
            .and_then(|t| std::str::from_utf8(t.as_bytes()).ok())
            .unwrap_or("")
            .to_owned()
    };
    let rust_text = et(&re);
    compare_krb_error(&re, &me).map_err(|e| format!("{case}: {e}"))?;
    if check_client {
        let cn = |e: &KrbError| e.cname.as_ref().map(PrincipalName::components_joined);
        let cr = |e: &KrbError| {
            e.crealm
                .as_ref()
                .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned())
        };
        if cn(&re) != cn(&me) || cr(&re) != cr(&me) {
            return Err(format!(
                "{case}: client rust=({:?},{:?}) mit=({:?},{:?})",
                cr(&re),
                cn(&re),
                cr(&me),
                cn(&me)
            ));
        }
    }
    let edata_types = |e: &KrbError| -> String {
        let Some(ed) = e.e_data.as_ref() else {
            return String::new();
        };
        let mut types: Vec<i32> = if let Ok(m) = decode::<krb5_types::MethodData>(ed.as_ref())
            && !m.is_empty()
        {
            m.iter().map(|p| p.padata_type).collect()
        } else if let Ok(td) = decode::<krb5_types::TypedDataList>(ed.as_ref()) {
            td.iter().map(|t| t.data_type).collect()
        } else {
            Vec::new()
        };
        types.sort_unstable();
        let mut s = String::from("[");
        for (i, t) in types.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(s, "{t}");
        }
        s.push(']');
        s
    };
    let types = edata_types(&re);
    if types.is_empty() {
        println!(
            r#"{{"event":"diffsend","case":"{case}","outcome":"ok","error_code":{},"e_text":"{rust_text}","rust_tag":"0x7e","mit_tag":"0x7e"}}"#,
            re.error_code
        );
    } else {
        println!(
            r#"{{"event":"diffsend","case":"{case}","outcome":"ok","error_code":{},"e_text":"{rust_text}","e_data_types":{types},"rust_tag":"0x7e","mit_tag":"0x7e"}}"#,
            re.error_code
        );
    }
    Ok(())
}

fn tcp_or_drop(addr: &KdcAddr, req: &[u8]) -> Option<Vec<u8>> {
    match exchange_on_tcp(addr, req) {
        Ok(b) if b.is_empty() => None,
        Ok(b) => Some(b),
        Err(_) => None,
    }
}

fn expect_garbage(cfg: &Cfg, req: &[u8]) -> Result<(), String> {
    write_der(&cfg.out, "garbage-pdu.req.der", req);
    println!(
        r#"{{"event":"diffsend","case":"garbage-pdu","req_sha1":"{}","req_len":{},"same_request_bytes":true}}"#,
        sha1_hex(req),
        req.len()
    );
    let rust = tcp_or_drop(&cfg.rust, req);
    let mit = tcp_or_drop(&cfg.mit, req);
    if let Some(ref b) = rust {
        write_der(&cfg.out, "garbage-pdu.rust.der", b);
    }
    if let Some(ref b) = mit {
        write_der(&cfg.out, "garbage-pdu.mit.der", b);
    }
    match (rust.as_deref(), mit.as_deref()) {
        (None, None) => {
            println!(
                r#"{{"event":"diffsend","case":"garbage-pdu","outcome":"ok","rust_tag":"drop","mit_tag":"drop"}}"#
            );
            Ok(())
        }
        (r, m) => Err(format!(
            "garbage-pdu: want both drop, rust={} mit={}",
            r.map_or_else(
                || "drop".into(),
                |b| format!("{:02x}", b.first().unwrap_or(&0))
            ),
            m.map_or_else(
                || "drop".into(),
                |b| format!("{:02x}", b.first().unwrap_or(&0))
            ),
        )),
    }
}

fn expect_drop(cfg: &Cfg, case: &str, req: &[u8]) -> Result<(), String> {
    write_der(&cfg.out, &format!("{case}.req.der"), req);
    println!(
        r#"{{"event":"diffsend","case":"{case}","req_sha1":"{}","req_len":{},"same_request_bytes":true}}"#,
        sha1_hex(req),
        req.len()
    );
    let rust = tcp_or_drop(&cfg.rust, req);
    let mit = tcp_or_drop(&cfg.mit, req);
    if let Some(ref b) = rust {
        write_der(&cfg.out, &format!("{case}.rust.der"), b);
    }
    if let Some(ref b) = mit {
        write_der(&cfg.out, &format!("{case}.mit.der"), b);
    }
    match (rust.as_deref(), mit.as_deref()) {
        (None, None) => {
            println!(
                r#"{{"event":"diffsend","case":"{case}","outcome":"ok","rust_tag":"drop","mit_tag":"drop"}}"#
            );
            Ok(())
        }
        (r, m) => Err(format!(
            "{case}: want both drop, rust={} mit={}",
            r.map_or_else(
                || "drop".into(),
                |b| format!("{:02x}", b.first().unwrap_or(&0))
            ),
            m.map_or_else(
                || "drop".into(),
                |b| format!("{:02x}", b.first().unwrap_or(&0))
            ),
        )),
    }
}

fn expect_tgs_rep(cfg: &Cfg, case: &str, req: &[u8]) -> Result<(), String> {
    let (rust, mit) = send_both(cfg, case, req)?;
    if rust.first() != Some(&0x6d) {
        return Err(format!(
            "{case}: rust tag {:02x} want 0x6d",
            rust.first().unwrap_or(&0)
        ));
    }
    if mit.first() != Some(&0x6d) {
        return Err(format!(
            "{case}: mit tag {:02x} want 0x6d",
            mit.first().unwrap_or(&0)
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"{case}","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d"}}"#
    );
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
        u8,
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
    let enc = decode_enc_kdc_rep(&plain).map_err(|e| e.to_string())?;
    let enc_tag = plain.first().copied().unwrap_or(0);
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
    Ok((rep, enc, tkt, enc_tag, session))
}

fn decrypt_tgs(
    raw: &[u8],
    session: &ProtocolKey,
    svc_kt: &Keytab,
) -> Result<
    (
        krb5_types::KdcRep,
        krb5_types::EncKdcRepPart,
        EncTicketPart,
        u8,
    ),
    String,
> {
    if raw.first() != Some(&0x6d) {
        if raw.first() == Some(&0x7e)
            && let Ok(e) = decode::<KrbError>(raw)
        {
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
        return Err(format!(
            "want TGS-REP 0x6d got {:02x}",
            raw.first().unwrap_or(&0)
        ));
    }
    let TgsRep(rep) = decode::<TgsRep>(raw).map_err(|e| e.to_string())?;
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART).map_err(|e| e.to_string())?;
    let plain = decrypt(session, usage, rep.enc_part.cipher.as_ref()).map_err(|e| e.to_string())?;
    let enc = decode_enc_kdc_rep(&plain).map_err(|e| e.to_string())?;
    let enc_tag = plain.first().copied().unwrap_or(0);
    let t_usage = KeyUsage::new(ku::TICKET).map_err(|e| e.to_string())?;
    let (svc_key, _) = keytab_for(svc_kt, rep.ticket.enc_part.etype)?;
    let tplain = decrypt(svc_key, t_usage, rep.ticket.enc_part.cipher.as_ref())
        .map_err(|e| format!("service ticket decrypt: {e}"))?;
    let tkt: EncTicketPart = decode(&tplain).map_err(|e| e.to_string())?;
    Ok((rep, enc, tkt, enc_tag))
}

// MIT kdc/replay.c lookaside (dispatch.c:114-140): the identical request resent
// is answered from the cache, so the second reply is byte-for-byte the first on
// both legs. Without the cache a fresh AS-REP carries a new random session key.
fn expect_retransmit(cfg: &Cfg, case: &str, req: &[u8]) -> Result<(), String> {
    let (r1, m1) = send_both(cfg, case, req)?;
    let r2 = exchange_on_tcp(&cfg.rust, req).map_err(|e| format!("{case} rust#2: {e}"))?;
    let m2 = exchange_on_tcp(&cfg.mit, req).map_err(|e| format!("{case} mit#2: {e}"))?;
    if r1.first() != Some(&0x6b) {
        return Err(format!(
            "{case}: rust first reply tag {:02x} want AS-REP 0x6b",
            r1.first().unwrap_or(&0)
        ));
    }
    if m1.first() != Some(&0x6b) {
        return Err(format!(
            "{case}: mit first reply tag {:02x} want AS-REP 0x6b",
            m1.first().unwrap_or(&0)
        ));
    }
    if r2 != r1 {
        return Err(format!(
            "{case}: rust retransmit differs (len {} vs {})",
            r2.len(),
            r1.len()
        ));
    }
    if m2 != m1 {
        return Err(format!(
            "{case}: mit retransmit differs (len {} vs {})",
            m2.len(),
            m1.len()
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"{case}","outcome":"ok","rust_retransmit_identical":true,"mit_retransmit_identical":true,"reply_tag":"0x6b"}}"#
    );
    Ok(())
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
    let (rr, re, rt, rtag, session) = decrypt_as(&rust, &cfg.user_pw, cname, &cfg.realm, tkt_kt)?;
    let (mr, me, mt, mtag, mit_session) =
        decrypt_as(&mit, &cfg.user_pw, cname, &cfg.realm, tkt_kt)?;
    compare_stable_rep(&rr, &re, &rt, &mr, &me, &mt).map_err(|e| format!("{case}: {e}"))?;
    if rtag != 0x7a || mtag != 0x7a {
        return Err(format!(
            "{case}: enc-part tag rust=0x{rtag:02x} mit=0x{mtag:02x} want 0x7a"
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"{case}","outcome":"ok","rust_tag":"0x6b","mit_tag":"0x6b","rust_enc_tag":"0x7a","mit_enc_tag":"0x7a"}}"#
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
    mint_tgt_ad(
        krbtgt, kvno, cname, realm, sname, session, window, flags, None,
    )
}

#[allow(clippy::too_many_arguments)]
fn mint_tgt_ad(
    krbtgt: &ProtocolKey,
    kvno: u32,
    cname: &PrincipalName,
    realm: &str,
    sname: &PrincipalName,
    session: &ProtocolKey,
    window: (KerberosTime, KerberosTime),
    flags: TicketFlags,
    authorization_data: Option<krb5_types::AuthorizationData>,
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
        authorization_data,
    };
    seal_ticket(krbtgt, kvno, realm, sname, part)
}

fn seal_ticket(
    key: &ProtocolKey,
    kvno: u32,
    realm: &str,
    sname: &PrincipalName,
    part: EncTicketPart,
) -> Result<Ticket, String> {
    let der = encode(&part).map_err(|e| e.to_string())?;
    let usage = KeyUsage::new(ku::TICKET).map_err(|e| e.to_string())?;
    let cipher = encrypt(key, usage, &der).map_err(|e| e.to_string())?;
    Ok(Ticket {
        tkt_vno: Ticket::VNO,
        realm: krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        sname: sname.clone(),
        enc_part: EncryptedData {
            etype: key.etype().to_iana(),
            kvno: Some(kvno),
            cipher: cipher.into(),
        },
    })
}

fn dummy_ident(sam: &str, realm: &str) -> PacIdentity {
    PacIdentity {
        sam: sam.to_owned(),
        realm: realm.to_owned(),
        domain_sid: RpcSid::dummy_domain(),
        rid: 1000,
    }
}

fn mint_signed_header(
    key: &ProtocolKey,
    kvno: u32,
    cname: &PrincipalName,
    realm: &str,
    sname: &PrincipalName,
    session: &ProtocolKey,
    window: (KerberosTime, KerberosTime),
    flags: TicketFlags,
    pac_cname: &PrincipalName,
    flip_server: bool,
    renew_till: Option<KerberosTime>,
) -> Result<Ticket, String> {
    let (start, end) = window;
    let mut part = EncTicketPart {
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
        starttime: Some(start.clone()),
        endtime: end,
        renew_till,
        caddr: None,
        authorization_data: Some(wrap_win2k_pac(&[0]).map_err(|e| e.to_string())?),
    };
    let der = ticket_checksum_der(&part).map_err(|e| e.to_string())?;
    let mut pac = sign_pac(
        pac_cname,
        start.unix_seconds(),
        &PacTicket {
            server: key,
            kdc: key,
            enc_tkt_der: &der,
            is_service_tkt: !sname.is_krbtgt(),
        },
        &dummy_ident(&pac_cname.components_joined(), realm),
        None,
    )
    .map_err(|e| e.to_string())?;
    if flip_server {
        let mut parsed = Pac::parse(&pac).map_err(|e| e.to_string())?;
        if let Some(buf) = parsed
            .buffers
            .iter_mut()
            .find(|b| b.kind == PAC_SERVER_CHECKSUM)
            && buf.data.len() > 4
        {
            buf.data[4] ^= 0xff;
        }
        pac = parsed.to_bytes();
    }
    part.authorization_data = Some(wrap_win2k_pac(&pac).map_err(|e| e.to_string())?);
    seal_ticket(key, kvno, realm, sname, part)
}

fn ad_types(part: &EncTicketPart) -> Vec<i32> {
    let mut out = Vec::new();
    let Some(ad) = part.authorization_data.as_ref() else {
        return out;
    };
    for el in ad {
        out.push(el.ad_type);
        if el.ad_type == pa::AD_IF_RELEVANT
            && let Ok(inner) = decode::<krb5_types::AuthorizationData>(el.ad_data.as_ref())
        {
            for i in inner {
                out.push(i.ad_type);
            }
        }
    }
    out
}

fn tgs_pa_types(raw: &[u8]) -> Result<Vec<i32>, String> {
    let rep: TgsRep = decode(raw).map_err(|e| format!("TgsRep: {e}"))?;
    Ok(rep
        .0
        .padata
        .unwrap_or_default()
        .iter()
        .map(|p| p.padata_type)
        .collect())
}

fn expect_tgs_ad(
    cfg: &Cfg,
    case: &str,
    req: &[u8],
    session: &ProtocolKey,
    want_pac: bool,
) -> Result<(), String> {
    expect_tgs_ad_pa(cfg, case, req, session, want_pac, None)
}

fn expect_tgs_ad_pa(
    cfg: &Cfg,
    case: &str,
    req: &[u8],
    session: &ProtocolKey,
    want_pac: bool,
    want_pa: Option<i32>,
) -> Result<(), String> {
    let (tr, tm) = send_both(cfg, case, req)?;
    let svc = cfg
        .host
        .as_ref()
        .ok_or_else(|| format!("{case}: KERBER_HOST_KEYTAB required"))?;
    let (_, _, rt, _) = decrypt_tgs(&tr, session, svc)?;
    let (_, _, mt, _) = decrypt_tgs(&tm, session, svc)?;
    let rp = pac_from_ticket_part(&rt).is_some();
    let mp = pac_from_ticket_part(&mt).is_some();
    if rp != want_pac || mp != want_pac {
        return Err(format!("{case}: PAC rust={rp} mit={mp} want {want_pac}"));
    }
    if ad_types(&rt) != ad_types(&mt) {
        return Err(format!(
            "{case}: authdata types rust={:?} mit={:?}",
            ad_types(&rt),
            ad_types(&mt)
        ));
    }
    if let Some(pt) = want_pa {
        let rpa = tgs_pa_types(&tr).map_err(|e| format!("{case} rust {e}"))?;
        let mpa = tgs_pa_types(&tm).map_err(|e| format!("{case} mit {e}"))?;
        if !rpa.contains(&pt) || !mpa.contains(&pt) {
            return Err(format!(
                "{case}: reply padata rust={rpa:?} mit={mpa:?} want {pt}"
            ));
        }
        println!(
            r#"{{"event":"diffsend","case":"{case}","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","issued_pac":{want_pac},"reply_padata":{pt}}}"#
        );
    } else {
        println!(
            r#"{{"event":"diffsend","case":"{case}","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","issued_pac":{want_pac}}}"#
        );
    }
    Ok(())
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

    let req = encode(
        &as_req_sname(
            user.clone(),
            realm,
            0x1000_000c,
            None,
            PrincipalName::krbtgt(realm),
            vec![23],
        )
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    expect_error(&cfg, "as-session-enctype", &req, err::ETYPE_NOSUPP)?;

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

    // pwchgu has REQUIRES_PWCHANGE and no preauth; a bare AS-REQ is
    // validate_as_request "REQUIRED PWCHANGE" / KEY_EXP (23) on both legs, with
    // its own status distinct from a lapsed pw_expire's "CLIENT KEY EXPIRED".
    let pwchgu = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pwchgu"]);
    let req = encode(&as_req(pwchgu, realm, 0x1000_000f, None).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    expect_error(&cfg, "as-needchange", &req, err::KEY_EXPIRED)?;

    // MIT AS_INVALID_OPTIONS (kdc_util.h:456-463): a TGS-only option (RENEW) in
    // an AS-REQ is INVALID AS OPTIONS / BADOPTION (13) on both legs.
    let mut inv = as_req(user.clone(), realm, 0x1000_0010, None).map_err(|e| e.to_string())?;
    inv.0.req_body.kdc_options = inv
        .0
        .req_body
        .kdc_options
        .with_bit(krb5_types::flag_bit::RENEW, true);
    let req = encode(&inv).map_err(|e| e.to_string())?;
    expect_error(&cfg, "as-invalid-opts", &req, err::BADOPTION)?;

    // pwprau requires preauth AND needs a password change. MIT validate_as_request
    // (do_as_req.c:630) runs before check_padata (:758), so a bare AS-REQ is
    // "REQUIRED PWCHANGE" / KEY_EXP (23), not "NEEDED_PREAUTH" (25), on both legs.
    let pwprau = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pwprau"]);
    let req = encode(&as_req(pwprau, realm, 0x1000_0011, None).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    expect_error(&cfg, "as-validate-before-preauth", &req, err::KEY_EXPIRED)?;

    // PA-ENC-TIMESTAMP declaring des3 (etype 16), which pauser has no key for:
    // enc_ts_verify krb5_dbe_search_enctype misses -> KRB5_KDB_NO_MATCHING_KEY
    // -> KDC_ERR_PREAUTH_FAILED (24) on both legs.
    let ed = EncryptedData {
        etype: 16,
        kvno: None,
        cipher: vec![0u8; 32].into(),
    };
    let enc_ts_pa = PaData {
        padata_type: pa::ENC_TIMESTAMP,
        padata_value: encode(&ed).map_err(|e| e.to_string())?.into(),
    };
    let req = encode(
        &as_req(pauser.clone(), realm, 0x1000_000e, Some(vec![enc_ts_pa]))
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    expect_error(
        &cfg,
        "as-optimistic-encts-wrong-etype",
        &req,
        err::PREAUTH_FAILED,
    )?;

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

    // A distinct preauth AS-REQ (fresh nonce) sent twice: the lookaside resends
    // the first reply, so the retransmit is identical on both legs.
    let pa_rt = pa_enc_timestamp(&ukey).map_err(|e| e.to_string())?;
    let as_req_rt = encode(
        &as_req(user.clone(), realm, 0x1000_0012, Some(vec![pa_rt])).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    expect_retransmit(&cfg, "as-retransmit", &as_req_rt)?;

    // do_as_req.c:717-724: REQUEST_ANONYMOUS with a named (non-anonymous)
    // client is KRB5KDC_ERR_BADOPTION "VALIDATE_ANONYMOUS_PRINCIPAL", reached
    // only after preauth because validate_as_request tests AS_INVALID_OPTIONS
    // only (kdc_util.c:727) and lets the bit through, unlike the TGS-only
    // options in as-invalid-opts. Both legs send code 13 with the same wire
    // status; before R2-P3 the Rust KDC refused the bit early as "INVALID AS
    // OPTIONS", so the e_text diverged from MIT here.
    let pa_anon = pa_enc_timestamp(&ukey).map_err(|e| e.to_string())?;
    let mut anon =
        as_req(user.clone(), realm, 0x1000_0013, Some(vec![pa_anon])).map_err(|e| e.to_string())?;
    anon.0.req_body.kdc_options = anon
        .0
        .req_body
        .kdc_options
        .with_bit(krb5_types::flag_bit::ANONYMOUS, true);
    let req = encode(&anon).map_err(|e| e.to_string())?;
    expect_error(&cfg, "as-request-anonymous", &req, err::BADOPTION)?;

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
    let (rr, re, rt, rtag) = decrypt_tgs(&tr, &sess, svc)?;
    let (mr, me, mt, mtag) = decrypt_tgs(&tm, &sess, svc)?;
    compare_stable_rep(&rr, &re, &rt, &mr, &me, &mt).map_err(|e| format!("tgs-success: {e}"))?;
    if rtag != 0x7a || mtag != 0x7a {
        return Err(format!(
            "tgs-success: enc-part tag rust=0x{rtag:02x} mit=0x{mtag:02x} want 0x7a"
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-success","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","rust_enc_tag":"0x7a","mit_enc_tag":"0x7a"}}"#
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
    expect_error_client(
        &cfg,
        "tgs-not-a-tgt",
        &encode(&not_tgt).map_err(|e| e.to_string())?,
        err::NOT_US,
        true,
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
    expect_error_client(
        &cfg,
        "tgt-expired",
        &encode(&tgs_exp).map_err(|e| e.to_string())?,
        err::TKT_EXPIRED,
        true,
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
    let tgs_nyv = tgs_req(nyv, &sess, realm, &user, host.clone(), realm, 0x1000_000a)
        .map_err(|e| e.to_string())?;
    expect_error_client(
        &cfg,
        "tgt-nyv",
        &encode(&tgs_nyv).map_err(|e| e.to_string())?,
        err::TKT_NYV,
        true,
    )?;

    // A′-1 item 1: AS FAST AP-REQ armor without authenticator subkey.
    // MIT armor_ap_request (fast_util.c:70-77) → 12 FIND_FAST. MIT clients
    // always send a subkey, so this forge is the both-legs oracle.
    let armor_tkt = mint_tgt(
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
        TicketFlags::initial_preauth(),
    )?;
    let armor_ap = build_fast_armor(
        armor_tkt,
        &sess,
        &krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        &user,
        None,
    )
    .map_err(|e| e.to_string())?;
    let akey = armor_key(&sess, None).map_err(|e| e.to_string())?;
    let mut fast_req = as_req(user.clone(), realm, 0x1000_0020, None).map_err(|e| e.to_string())?;
    attach_fast(&mut fast_req, &armor_ap, &akey, Vec::new()).map_err(|e| e.to_string())?;
    expect_error(
        &cfg,
        "fast-armor-no-subkey",
        &encode(&fast_req).map_err(|e| e.to_string())?,
        err::POLICY,
    )?;

    // A′-1 item 3: header ticket or authenticator carrying AD-FX-ARMOR 71.
    // MIT kdc_util.c:217-229 → 12 PROCESS_TGS. Nothing in 1.22.2 emits 71.
    let inner_ad = encode(&vec![AuthorizationDataValue {
        ad_type: pa::AD_FX_ARMOR,
        ad_data: Vec::<u8>::new().into(),
    }])
    .map_err(|e| e.to_string())?;
    let fx_ad = vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: inner_ad.into(),
    }];
    let fx_tgt = mint_tgt_ad(
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
        TicketFlags::initial_preauth(),
        Some(fx_ad),
    )?;
    let fx_tgs = tgs_req(
        fx_tgt,
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_0021,
    )
    .map_err(|e| e.to_string())?;
    expect_error_client(
        &cfg,
        "armor-ap-req-as-pa-tgs-req",
        &encode(&fx_tgs).map_err(|e| e.to_string())?,
        err::POLICY,
        true,
    )?;

    let auth_tgt = mint_tgt(
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
        TicketFlags::initial_preauth(),
    )?;
    let mut auth_tgs = tgs_req(
        auth_tgt,
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_0022,
    )
    .map_err(|e| e.to_string())?;
    let pa_tgs = auth_tgs
        .0
        .padata
        .as_mut()
        .and_then(|p| p.iter_mut().find(|x| x.padata_type == pa::TGS_REQ))
        .ok_or_else(|| "no PA-TGS-REQ".to_string())?;
    let mut ap: ApReq = decode(pa_tgs.padata_value.as_ref()).map_err(|e| e.to_string())?;
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).map_err(|e| e.to_string())?;
    let auth_plain =
        decrypt(&sess, auth_usage, ap.authenticator.cipher.as_ref()).map_err(|e| e.to_string())?;
    let mut authenticator: krb5_types::Authenticator =
        decode(&auth_plain).map_err(|e| e.to_string())?;
    authenticator.authorization_data = Some(vec![AuthorizationDataValue {
        ad_type: pa::AD_FX_ARMOR,
        ad_data: Vec::<u8>::new().into(),
    }]);
    let auth_der = encode(&authenticator).map_err(|e| e.to_string())?;
    ap.authenticator.cipher = encrypt(&sess, auth_usage, &auth_der)
        .map_err(|e| e.to_string())?
        .into();
    pa_tgs.padata_value = encode(&ap).map_err(|e| e.to_string())?.into();
    expect_error_client(
        &cfg,
        "tgs-ad-fx-armor-authenticator",
        &encode(&auth_tgs).map_err(|e| e.to_string())?,
        err::POLICY,
        true,
    )?;

    // A′-1 item 4: AS/TGS entry validation (do_as_req.c:513-517, dispatch.c:145-158,
    // do_tgs_req.c:609-610, kdc_util.c:179-184,790-793, kdc_rd_ap_req kvno 0).
    let mut bad_as = as_req(user.clone(), realm, 0x1000_0023, None).map_err(|e| e.to_string())?;
    bad_as.0.msg_type = krb5_types::KdcReq::MSG_TGS_REQ;
    expect_error(
        &cfg,
        "as-bad-msg-type",
        &encode(&bad_as).map_err(|e| e.to_string())?,
        err::GENERIC,
    )?;

    let mut bad_pv = as_req(user.clone(), realm, 0x1000_0024, None).map_err(|e| e.to_string())?;
    bad_pv.0.pvno = 4;
    expect_drop(
        &cfg,
        "as-bad-pvno",
        &encode(&bad_pv).map_err(|e| e.to_string())?,
    )?;

    let mut bad_tgs = tgs_req(
        mint_tgt(
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
            TicketFlags::initial_preauth(),
        )?,
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_0025,
    )
    .map_err(|e| e.to_string())?;
    bad_tgs.0.msg_type = krb5_types::KdcReq::MSG_AS_REQ;
    expect_error_client(
        &cfg,
        "tgs-bad-msg-type",
        &encode(&bad_tgs).map_err(|e| e.to_string())?,
        err::GENERIC,
        true,
    )?;

    let nosvr = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosvr"]);
    expect_error(
        &cfg,
        "as-service-not-allowed",
        &encode(
            &as_req_sname(
                user.clone(),
                realm,
                0x1000_0026,
                None,
                nosvr,
                etypes.clone(),
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::MUST_USE_USER2USER,
    )?;

    let mut opt_tgs = tgs_req(
        mint_tgt(
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
            TicketFlags::initial_preauth(),
        )?,
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_0027,
    )
    .map_err(|e| e.to_string())?;
    let opt_pa = opt_tgs
        .0
        .padata
        .as_mut()
        .and_then(|p| p.iter_mut().find(|x| x.padata_type == pa::TGS_REQ))
        .ok_or_else(|| "no PA-TGS-REQ".to_string())?;
    let mut opt_ap: ApReq = decode(opt_pa.padata_value.as_ref()).map_err(|e| e.to_string())?;
    opt_ap.ap_options = ApOptions::mutual_required();
    opt_pa.padata_value = encode(&opt_ap).map_err(|e| e.to_string())?.into();
    expect_error_client(
        &cfg,
        "tgs-ap-options",
        &encode(&opt_tgs).map_err(|e| e.to_string())?,
        err::POLICY,
        true,
    )?;

    let mut z_tkt = mint_tgt(
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
        TicketFlags::initial_preauth(),
    )?;
    z_tkt.enc_part.kvno = Some(0);
    let z_tgs = tgs_req(z_tkt, &sess, realm, &user, host.clone(), realm, 0x1000_0028)
        .map_err(|e| e.to_string())?;
    expect_tgs_rep(
        &cfg,
        "tgs-header-kvno-zero",
        &encode(&z_tgs).map_err(|e| e.to_string())?,
    )?;

    let hwuser = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["hwuser"]);
    expect_error(
        &cfg,
        "as-hw-preauth",
        &encode(&as_req(hwuser, realm, 0x1000_0029, None).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?,
        err::PREAUTH_REQUIRED,
    )?;

    // kdc_preauth.c:1141-1170: SPAKE support → 91 + ETYPE-INFO2 (no cookie yet).
    expect_error(
        &cfg,
        "as-spake-round1",
        &encode(
            &as_req(
                user.clone(),
                realm,
                0x1000_002a,
                Some(vec![pa_spake_support()]),
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::MORE_PREAUTH_DATA_REQUIRED,
    )?;

    let second = mint_tgt(
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
        TicketFlags::initial_preauth(),
    )?;
    let u2u_tgs = |extra: Ticket, nonce: u32| -> Result<krb5_types::TgsReq, String> {
        let opts = KdcOptions::forwardable().with_bit(krb5_types::flag_bit::ENC_TKT_IN_SKEY, true);
        tgs_req_ex(
            mint_tgt(
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
                TicketFlags::initial_preauth(),
            )?,
            &sess,
            realm,
            &user,
            user.clone(),
            realm,
            nonce,
            opts,
            Some(vec![extra]),
            Vec::new(),
            etypes.clone(),
        )
        .map_err(|e| e.to_string())
    };

    let mut unk = second.clone();
    unk.sname = PrincipalName::new(PrincipalName::NT_SRV_INST, ["nosuch", "x"]);
    expect_error(
        &cfg,
        "u2u-2nd-ticket-unknown-server",
        &encode(&u2u_tgs(unk, 0x1000_002b)?).map_err(|e| e.to_string())?,
        err::S_PRINCIPAL_UNKNOWN,
    )?;

    let mut bad_et = second.clone();
    bad_et.enc_part.etype = 99;
    expect_error(
        &cfg,
        "u2u-2nd-ticket-bad-etype",
        &encode(&u2u_tgs(bad_et, 0x1000_002c)?).map_err(|e| e.to_string())?,
        err::GENERIC,
    )?;

    let mut cor = second;
    let mut cipher = cor.enc_part.cipher.as_ref().to_vec();
    if let Some(b) = cipher.last_mut() {
        *b ^= 1;
    }
    cor.enc_part.cipher = cipher.into();
    expect_error(
        &cfg,
        "u2u-2nd-ticket-corrupt",
        &encode(&u2u_tgs(cor, 0x1000_002d)?).map_err(|e| e.to_string())?,
        err::BAD_INTEGRITY,
    )?;

    let other = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["other"]);
    let unknown = PrincipalName::new(PrincipalName::NT_SRV_INST, ["nosuch", "x"]);
    let window10 = (
        now.clone(),
        now.add_hours(10).unwrap_or_else(|_| now.clone()),
    );
    let renew_till = now.add_hours(24).unwrap_or_else(|_| now.clone());

    let mismatch = mint_signed_header(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth(),
        &other,
        false,
        None,
    )?;
    expect_error(
        &cfg,
        "tgs-pac-client-mismatch",
        &encode(
            &tgs_req(
                mismatch,
                &sess,
                realm,
                &user,
                host.clone(),
                realm,
                0x1000_0030,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADOPTION,
    )?;

    let corrupt = mint_signed_header(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth(),
        &user,
        true,
        None,
    )?;
    expect_error(
        &cfg,
        "tgs-pac-corrupt-before-sname",
        &encode(
            &tgs_req(
                corrupt,
                &sess,
                realm,
                &user,
                unknown.clone(),
                realm,
                0x1000_0031,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::MODIFIED,
    )?;

    let pac_tkt = mint_signed_header(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth(),
        &user,
        false,
        None,
    )?;
    let pac_req = encode(&PaPacRequest { include_pac: false }).map_err(|e| e.to_string())?;
    expect_tgs_ad(
        &cfg,
        "tgs-pac-request-false",
        &encode(
            &tgs_req_ex(
                pac_tkt,
                &sess,
                realm,
                &user,
                host.clone(),
                realm,
                0x1000_0032,
                KdcOptions::forwardable(),
                None,
                vec![PaData {
                    padata_type: pa::PAC_REQUEST,
                    padata_value: pac_req.into(),
                }],
                EncryptionType::preferred()
                    .iter()
                    .map(|e| e.to_iana())
                    .collect(),
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        &sess,
        true,
    )?;

    let pacless = mint_tgt(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth(),
    )?;
    expect_tgs_ad(
        &cfg,
        "tgs-from-pacless-tgt",
        &encode(
            &tgs_req(
                pacless,
                &sess,
                realm,
                &user,
                host.clone(),
                realm,
                0x1000_0033,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        &sess,
        false,
    )?;

    let (hkey, hkvno) = keytab_for(svc, 20)?;
    let svc_part = EncTicketPart {
        flags: TicketFlags::initial_preauth().with_bit(flag_bit::RENEWABLE, true),
        key: EncryptionKey {
            keytype: sess.etype().to_iana(),
            keyvalue: sess.as_bytes().to_vec().into(),
        },
        crealm: krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        cname: user.clone(),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: Vec::<u8>::new().into(),
        },
        authtime: now.clone(),
        starttime: Some(now.clone()),
        endtime: now.add_hours(10).unwrap_or_else(|_| now.clone()),
        renew_till: Some(renew_till.clone()),
        caddr: None,
        authorization_data: None,
    };
    let svc_renew = seal_ticket(hkey, hkvno, realm, &host, svc_part)?;
    expect_tgs_rep(
        &cfg,
        "tgs-renew-service-ticket",
        &encode(
            &tgs_req_ex(
                svc_renew,
                &sess,
                realm,
                &user,
                host.clone(),
                realm,
                0x1000_0034,
                KdcOptions::forwardable()
                    .with_bit(flag_bit::RENEWABLE, true)
                    .with_bit(flag_bit::RENEW, true),
                None,
                Vec::new(),
                EncryptionType::preferred()
                    .iter()
                    .map(|e| e.to_iana())
                    .collect(),
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
    )?;

    let proxy_tgt = mint_tgt(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth().with_bit(flag_bit::PROXIABLE, true),
    )?;
    expect_error(
        &cfg,
        "tgs-proxy-krbtgt",
        &encode(
            &tgs_req_ex(
                proxy_tgt,
                &sess,
                realm,
                &user,
                krbtgt_sname.clone(),
                realm,
                0x1000_0035,
                KdcOptions::forwardable().with_bit(flag_bit::PROXY, true),
                None,
                Vec::new(),
                EncryptionType::preferred()
                    .iter()
                    .map(|e| e.to_iana())
                    .collect(),
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADOPTION,
    )?;

    let can_part = EncTicketPart {
        flags: TicketFlags::initial_preauth().with_bit(flag_bit::RENEWABLE, true),
        key: EncryptionKey {
            keytype: sess.etype().to_iana(),
            keyvalue: sess.as_bytes().to_vec().into(),
        },
        crealm: krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        cname: user.clone(),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: Vec::<u8>::new().into(),
        },
        authtime: now.clone(),
        starttime: Some(now.clone()),
        endtime: now.add_hours(10).unwrap_or_else(|_| now.clone()),
        renew_till: Some(renew_till),
        caddr: None,
        authorization_data: None,
    };
    let can_tgt = seal_ticket(tkt_key, tkt_kvno, realm, &krbtgt_sname, can_part)?;
    expect_tgs_rep(
        &cfg,
        "tgs-canonicalize-renew",
        &encode(
            &tgs_req_ex(
                can_tgt,
                &sess,
                realm,
                &user,
                krbtgt_sname.clone(),
                realm,
                0x1000_0036,
                KdcOptions::forwardable()
                    .with_bit(flag_bit::RENEWABLE, true)
                    .with_bit(flag_bit::RENEW, true)
                    .with_bit(flag_bit::CANONICALIZE, true),
                None,
                Vec::new(),
                EncryptionType::preferred()
                    .iter()
                    .map(|e| e.to_iana())
                    .collect(),
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
    )?;

    let expired_unknown = mint_tgt(
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
    expect_error_client(
        &cfg,
        "tgs-expired-vs-unknown-sname",
        &encode(
            &tgs_req(
                expired_unknown,
                &sess,
                realm,
                &user,
                unknown,
                realm,
                0x1000_0037,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::TKT_EXPIRED,
        true,
    )?;

    let host_flags = TicketFlags::initial_preauth().with_bit(flag_bit::FORWARDABLE, true);
    let host_hdr = |pac_cname: &PrincipalName, flip: bool| -> Result<Ticket, String> {
        mint_signed_header(
            tkt_key,
            tkt_kvno,
            &host,
            realm,
            &krbtgt_sname,
            &sess,
            window10.clone(),
            host_flags.clone(),
            pac_cname,
            flip,
            None,
        )
    };
    let s4u_req = |tkt: Ticket, extra: Vec<PaData>, nonce: u32| -> Result<Vec<u8>, String> {
        encode(
            &tgs_req_ex(
                tkt,
                &sess,
                realm,
                &host,
                host.clone(),
                realm,
                nonce,
                KdcOptions::forwardable(),
                None,
                extra,
                etypes.clone(),
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    };

    let pacless_host = mint_tgt(
        tkt_key,
        tkt_kvno,
        &host,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        host_flags.clone(),
    )?;
    expect_error(
        &cfg,
        "s4u2self-no-pac",
        &s4u_req(
            pacless_host,
            vec![pa_for_user(&sess, user.clone(), realm).map_err(|e| e.to_string())?],
            0x1000_0040,
        )?,
        err::TGT_REVOKED,
    )?;

    expect_error(
        &cfg,
        "s4u2self-pac-client-mismatch",
        &s4u_req(
            host_hdr(&user, false)?,
            vec![pa_for_user(&sess, user.clone(), realm).map_err(|e| e.to_string())?],
            0x1000_0041,
        )?,
        err::BADOPTION,
    )?;

    let mut bad130 =
        pa_s4u_x509_user(&sess, user.clone(), realm, 0x1000_0042).map_err(|e| e.to_string())?;
    let mut x509: krb5_types::s4u::PaS4uX509User =
        decode(bad130.padata_value.as_ref()).map_err(|e| e.to_string())?;
    let mut ck = x509.cksum.checksum.to_vec();
    if let Some(b) = ck.first_mut() {
        *b ^= 0xff;
    }
    x509.cksum.checksum = ck.into();
    bad130.padata_value = encode(&x509).map_err(|e| e.to_string())?.into();
    expect_error(
        &cfg,
        "pa-s4u-x509-user-bad-checksum",
        &s4u_req(host_hdr(&host, false)?, vec![bad130], 0x1000_0042)?,
        err::MODIFIED,
    )?;

    expect_error(
        &cfg,
        "pa-s4u-x509-user-nonce",
        &s4u_req(
            host_hdr(&host, false)?,
            vec![pa_s4u_x509_user(&sess, user.clone(), realm, 0xdead).map_err(|e| e.to_string())?],
            0x1000_0043,
        )?,
        err::MODIFIED,
    )?;

    expect_tgs_ad(
        &cfg,
        "pa-for-user-only",
        &s4u_req(
            host_hdr(&host, false)?,
            vec![pa_for_user(&sess, user.clone(), realm).map_err(|e| e.to_string())?],
            0x1000_0044,
        )?,
        &sess,
        true,
    )?;

    let empty = PrincipalName::new(PrincipalName::NT_UNKNOWN, std::iter::empty::<&str>());
    expect_error(
        &cfg,
        "pa-s4u-x509-user-empty",
        &s4u_req(
            host_hdr(&host, false)?,
            vec![pa_s4u_x509_user(&sess, empty, realm, 0x1000_0045).map_err(|e| e.to_string())?],
            0x1000_0045,
        )?,
        err::C_PRINCIPAL_UNKNOWN,
    )?;

    expect_error(
        &cfg,
        "pa-for-user-undecodable",
        &s4u_req(
            host_hdr(&host, false)?,
            vec![PaData {
                padata_type: pa::FOR_USER,
                padata_value: b"\x30\x03\x01\x01".to_vec().into(),
            }],
            0x1000_0046,
        )?,
        err::GENERIC,
    )?;

    expect_tgs_ad_pa(
        &cfg,
        "pa-s4u-x509-user",
        &s4u_req(
            host_hdr(&host, false)?,
            vec![
                pa_s4u_x509_user(&sess, user.clone(), realm, 0x1000_0047)
                    .map_err(|e| e.to_string())?,
            ],
            0x1000_0047,
        )?,
        &sess,
        true,
        Some(pa::FOR_X509_USER),
    )?;

    println!(r#"{{"event":"diffsend","outcome":"ok","cases":49}}"#);
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("FATAL: {e}");
        process::exit(1);
    }
}
