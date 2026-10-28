#![forbid(unsafe_code)]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use krb5_asn1::{decode, encode};
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt, krb_fx_cf2, p256_generate,
    string_to_key,
};
use krb5_kdc::testrealm::{GREET_AD_TYPE, GREET_TEXT};
use krb5_kdc::{PacTicket, pac_from_ticket_part, sign_pac, ticket_checksum_der, wrap_win2k_pac};
use krb5_protocol::{
    KdcAddr, Keytab, TgsReqParams, armor_key, as_req, as_req_sname, attach_fast,
    attach_fast_with_options, build_fast_armor, compare_krb_error, compare_stable_rep,
    decode_enc_kdc_rep, exchange_on_tcp, pa_enc_timestamp, pa_enc_timestamp_at, pa_for_user,
    pa_pac_options, pa_pk_as_req_signed, pa_pk_as_req_unsigned, pa_s4u_x509_user, pa_spake_support,
    stable_krb_error, tgs_req, tgs_req_ex,
};
use krb5_types::cammac::AdKdcIssued;
use krb5_types::pac::{PAC_SERVER_CHECKSUM, Pac, PacIdentity, RpcSid};
use krb5_types::{
    ApOptions, ApReq, AsRep, AuthorizationData, AuthorizationDataValue, Checksum, EncTicketPart,
    EncryptedData, EncryptionKey, HostAddress, KdcOptions, KerberosTime, KrbError, PaData,
    PaPacRequest, PrincipalName, TgsRep, Ticket, TicketFlags, TransitedEncoding, err, flag_bit, ku,
    pa,
};
use sha1::{Digest, Sha1};

#[allow(dead_code)]
mod der {
    include!("../der_breaks.rs");
}

struct Cfg {
    rust: KdcAddr,
    mit: KdcAddr,
    out: PathBuf,
    realm: String,
    user_pw: Vec<u8>,
    pauser_pw: Vec<u8>,
    krbtgt: Option<Keytab>,
    host: Option<Keytab>,
    b17lab: bool,
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

fn expect_error_no_edata(cfg: &Cfg, case: &str, req: &[u8], code: i32) -> Result<(), String> {
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
    if stable_krb_error(&re) != stable_krb_error(&me) {
        return Err(format!("{case}: krb-error stable mismatch"));
    }
    if re.e_data.is_some() || me.e_data.is_some() {
        return Err(format!("{case}: e_data present"));
    }
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
    let rust_text = re
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok())
        .unwrap_or("");
    println!(
        r#"{{"event":"diffsend","case":"{case}","outcome":"ok","error_code":{},"e_text":"{rust_text}","e_data":"absent","rust_tag":"0x7e","mit_tag":"0x7e"}}"#,
        re.error_code
    );
    Ok(())
}

fn expect_hidden_client_error(cfg: &Cfg, case: &str, req: &[u8], code: i32) -> Result<(), String> {
    expect_error_client(cfg, case, req, code, true)?;
    for leg in ["rust", "mit"] {
        let der = std::fs::read(cfg.out.join(format!("{case}.{leg}.der")))
            .map_err(|e| format!("{case} {leg} der: {e}"))?;
        let err: KrbError = decode(&der).map_err(|e| format!("{case} {leg} decode: {e}"))?;
        let cn = err.cname.as_ref().map(PrincipalName::components_joined);
        let cr = err
            .crealm
            .as_ref()
            .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned());
        if cn.as_deref() != Some("WELLKNOWN/ANONYMOUS")
            || cr.as_deref() != Some("WELLKNOWN:ANONYMOUS")
        {
            return Err(format!(
                "{case}: outer client {leg}=({cr:?},{cn:?}) want WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS"
            ));
        }
    }
    Ok(())
}

fn wrap_tgs_fast_hide(
    req: &mut krb5_types::TgsReq,
    session: &ProtocolKey,
    inner_body: krb5_types::KdcReqBody,
) -> Result<(), String> {
    let padata = req.0.padata.as_mut().ok_or("no padata")?;
    let pa_tgs = padata
        .iter_mut()
        .find(|x| x.padata_type == pa::TGS_REQ)
        .ok_or("no PA-TGS-REQ")?;
    let mut ap: ApReq = decode(pa_tgs.padata_value.as_ref()).map_err(|e| e.to_string())?;
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).map_err(|e| e.to_string())?;
    let auth_plain = decrypt(session, auth_usage, ap.authenticator.cipher.as_ref())
        .map_err(|e| e.to_string())?;
    let mut authenticator: krb5_types::Authenticator =
        decode(&auth_plain).map_err(|e| e.to_string())?;
    let subkey =
        ProtocolKey::from_bytes(session.etype(), &[0x51u8; 32]).map_err(|e| e.to_string())?;
    authenticator.subkey = Some(EncryptionKey {
        keytype: subkey.etype().to_iana(),
        keyvalue: subkey.as_bytes().to_vec().into(),
    });
    let auth_der = encode(&authenticator).map_err(|e| e.to_string())?;
    ap.authenticator.cipher = encrypt(session, auth_usage, &auth_der)
        .map_err(|e| e.to_string())?
        .into();
    pa_tgs.padata_value = encode(&ap).map_err(|e| e.to_string())?.into();
    let ap_raw = pa_tgs.padata_value.as_ref().to_vec();
    let akey =
        krb_fx_cf2(&subkey, session, b"subkeyarmor", b"ticketarmor").map_err(|e| e.to_string())?;
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM).map_err(|e| e.to_string())?;
    let mic = checksum(&akey, ck_usage, &ap_raw).map_err(|e| e.to_string())?;
    let mut opts = krb5_types::fast::fast_options_none();
    opts.set(1, true);
    let inner = krb5_types::fast::KrbFastReq {
        fast_options: opts,
        padata: Vec::new(),
        req_body: inner_body,
    };
    let inner_der = encode(&inner).map_err(|e| e.to_string())?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC).map_err(|e| e.to_string())?;
    let cipher = encrypt(&akey, enc_usage, &inner_der).map_err(|e| e.to_string())?;
    let armored = krb5_types::fast::KrbFastArmoredReq {
        armor: None,
        req_checksum: Checksum {
            cksumtype: akey.etype().checksum_type(),
            checksum: mic.into(),
        },
        enc_fast_req: EncryptedData {
            etype: akey.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    req.0.padata.get_or_insert_with(Vec::new).push(PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
            .map_err(|e| e.to_string())?
            .into(),
    });
    Ok(())
}

fn expect_hidden_tgs_rep(cfg: &Cfg, case: &str, req: &[u8]) -> Result<(), String> {
    let (rust, mit) = send_both(cfg, case, req)?;
    for (leg, raw) in [("rust", rust.as_slice()), ("mit", mit.as_slice())] {
        if raw.first() != Some(&0x6d) {
            return Err(format!(
                "{case}: {leg} tag {:02x} want 0x6d",
                raw.first().unwrap_or(&0)
            ));
        }
        let rep: TgsRep = decode(raw).map_err(|e| format!("{case} {leg}: {e}"))?;
        let cn = rep.0.cname.components_joined();
        let cr = String::from_utf8_lossy(rep.0.crealm.as_bytes());
        if cn != "WELLKNOWN/ANONYMOUS" || cr != "WELLKNOWN:ANONYMOUS" {
            return Err(format!(
                "{case}: outer client {leg}=({cr},{cn}) want WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS"
            ));
        }
    }
    println!(
        r#"{{"event":"diffsend","case":"{case}","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","hidden":true}}"#
    );
    Ok(())
}

// AS errors echo the client. A TGS error uses the header client.
// tgs-not-a-tgt compares cname (check_client).
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
    let names = |leg: &str, raw: &[u8]| -> Result<[String; 6], String> {
        if raw.first() != Some(&0x6d) {
            return Err(format!(
                "{case}: {leg} tag {:02x} want 0x6d",
                raw.first().unwrap_or(&0)
            ));
        }
        let TgsRep(rep) = decode(raw).map_err(|e| format!("{case} {leg}: {e}"))?;
        Ok([
            String::from_utf8_lossy(rep.crealm.as_bytes()).into_owned(),
            rep.cname.components_joined(),
            String::from_utf8_lossy(rep.ticket.realm.as_bytes()).into_owned(),
            rep.ticket.sname.components_joined(),
            rep.cname.name_type.to_string(),
            rep.ticket.sname.name_type.to_string(),
        ])
    };
    let (r, m) = (names("rust", &rust)?, names("mit", &mit)?);
    if r != m {
        return Err(format!(
            "{case}: crealm, cname, ticket realm, sname, name types rust={r:?} mit={m:?}"
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
    string_to_key(et, pw, cname.default_salt(realm), None).map_err(|e| e.to_string())
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

fn ad_has_payload(ad: &[AuthorizationDataValue], ad_type: i32, payload: &[u8]) -> bool {
    for e in ad {
        if e.ad_type == pa::AD_IF_RELEVANT {
            if let Ok(inner) = decode::<AuthorizationData>(e.ad_data.as_ref())
                && ad_has_payload(&inner, ad_type, payload)
            {
                return true;
            }
        } else if e.ad_type == pa::AD_KDC_ISSUED {
            if let Ok(issued) = decode::<AdKdcIssued>(e.ad_data.as_ref())
                && ad_has_payload(&issued.elements, ad_type, payload)
            {
                return true;
            }
        } else if e.ad_type == ad_type && e.ad_data.as_ref() == payload {
            return true;
        }
    }
    false
}

fn ad_has_exact(ad: &[AuthorizationDataValue], want: &AuthorizationDataValue) -> bool {
    ad.iter()
        .any(|e| e.ad_type == want.ad_type && e.ad_data.as_ref() == want.ad_data.as_ref())
}

fn first_is_pac(ad: &[AuthorizationDataValue]) -> bool {
    let Some(e) = ad.first() else {
        return false;
    };
    if e.ad_type != pa::AD_IF_RELEVANT {
        return false;
    }
    let Ok(inner) = decode::<AuthorizationData>(e.ad_data.as_ref()) else {
        return false;
    };
    inner.first().is_some_and(|i| i.ad_type == pa::AD_WIN2K_PAC)
}

fn enc_ad_usage(
    key: &ProtocolKey,
    usage: u32,
    ad: &[AuthorizationDataValue],
) -> Result<EncryptedData, String> {
    let usage = KeyUsage::new(usage).map_err(|e| e.to_string())?;
    let cipher = encrypt(
        key,
        usage,
        &encode(&ad.to_vec()).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(EncryptedData {
        etype: key.etype().to_iana(),
        kvno: None,
        cipher: cipher.into(),
    })
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
    decrypt_tgs_enc(raw, session, ku::TGS_REP_ENC_PART, svc_kt)
}

fn decrypt_tgs_enc(
    raw: &[u8],
    enc_key: &ProtocolKey,
    enc_usage: u32,
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
    let usage = KeyUsage::new(enc_usage).map_err(|e| e.to_string())?;
    let plain = decrypt(enc_key, usage, rep.enc_part.cipher.as_ref()).map_err(|e| e.to_string())?;
    let enc = decode_enc_kdc_rep(&plain).map_err(|e| e.to_string())?;
    let enc_tag = plain.first().copied().unwrap_or(0);
    let t_usage = KeyUsage::new(ku::TICKET).map_err(|e| e.to_string())?;
    let (svc_key, _) = keytab_for(svc_kt, rep.ticket.enc_part.etype)?;
    let tplain = decrypt(svc_key, t_usage, rep.ticket.enc_part.cipher.as_ref())
        .map_err(|e| format!("service ticket decrypt: {e}"))?;
    let tkt: EncTicketPart = decode(&tplain).map_err(|e| e.to_string())?;
    Ok((rep, enc, tkt, enc_tag))
}

// MIT: `tgs_issue_ticket` (kdc/do_tgs_req.c:953-1139)
fn decrypt_u2u(
    raw: &[u8],
    header_session: &ProtocolKey,
    stkt_session: &ProtocolKey,
) -> Result<(krb5_types::EncKdcRepPart, Ticket, EncTicketPart), String> {
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
    let plain =
        decrypt(header_session, usage, rep.enc_part.cipher.as_ref()).map_err(|e| e.to_string())?;
    let enc = decode_enc_kdc_rep(&plain).map_err(|e| e.to_string())?;
    let t_usage = KeyUsage::new(ku::TICKET).map_err(|e| e.to_string())?;
    let tplain = decrypt(stkt_session, t_usage, rep.ticket.enc_part.cipher.as_ref())
        .map_err(|e| format!("u2u ticket decrypt: {e}"))?;
    let tkt: EncTicketPart = decode(&tplain).map_err(|e| e.to_string())?;
    Ok((enc, rep.ticket, tkt))
}

// A cached AS-REQ is resent, so the second reply matches. No cache: a new session key.
// MIT: `dispatch` (kdc/dispatch.c:89-175)
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
    if re.last_req.len() != 1
        || me.last_req.len() != 1
        || re.last_req[0].lr_type != 0
        || me.last_req[0].lr_type != 0
        || re.last_req[0].lr_value.unix_seconds() != 0
        || me.last_req[0].lr_value.unix_seconds() != 0
    {
        return Err(format!(
            "{case}: last_req rust={:?} mit={:?} want [{{0, epoch}}]",
            re.last_req
                .iter()
                .map(|e| (e.lr_type, e.lr_value.unix_seconds()))
                .collect::<Vec<_>>(),
            me.last_req
                .iter()
                .map(|e| (e.lr_type, e.lr_value.unix_seconds()))
                .collect::<Vec<_>>()
        ));
    }
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

#[expect(clippy::too_many_arguments, reason = "diffsend ticket forge helper")]
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

#[expect(clippy::too_many_arguments, reason = "diffsend ticket forge helper")]
fn mint_tgt_caddr(
    krbtgt: &ProtocolKey,
    kvno: u32,
    cname: &PrincipalName,
    realm: &str,
    sname: &PrincipalName,
    session: &ProtocolKey,
    window: (KerberosTime, KerberosTime),
    flags: TicketFlags,
    caddr: Option<Vec<HostAddress>>,
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
        caddr,
        authorization_data: None,
    };
    seal_ticket(krbtgt, kvno, realm, sname, &part)
}

#[expect(clippy::too_many_arguments, reason = "diffsend ticket forge helper")]
fn mint_tgt_times(
    krbtgt: &ProtocolKey,
    kvno: u32,
    cname: &PrincipalName,
    realm: &str,
    sname: &PrincipalName,
    session: &ProtocolKey,
    authtime: KerberosTime,
    starttime: Option<KerberosTime>,
    endtime: KerberosTime,
    flags: TicketFlags,
) -> Result<Ticket, String> {
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
        authtime,
        starttime,
        endtime,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    seal_ticket(krbtgt, kvno, realm, sname, &part)
}

#[expect(clippy::too_many_arguments, reason = "diffsend ticket forge helper")]
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
    seal_ticket(krbtgt, kvno, realm, sname, &part)
}

fn seal_ticket(
    key: &ProtocolKey,
    kvno: u32,
    realm: &str,
    sname: &PrincipalName,
    part: &EncTicketPart,
) -> Result<Ticket, String> {
    let der = encode(part).map_err(|e| e.to_string())?;
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

#[expect(clippy::too_many_arguments, reason = "diffsend ticket forge helper")]
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
    mint_signed_header_ex(
        key,
        kvno,
        cname,
        realm,
        sname,
        session,
        window,
        flags,
        pac_cname,
        flip_server,
        renew_till,
        None,
    )
}

#[expect(clippy::too_many_arguments, reason = "diffsend ticket forge helper")]
fn mint_signed_header_ex(
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
    server_cksumtype: Option<i32>,
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
    if let Some(ct) = server_cksumtype {
        let mut parsed = Pac::parse(&pac).map_err(|e| e.to_string())?;
        if let Some(buf) = parsed
            .buffers
            .iter_mut()
            .find(|b| b.kind == PAC_SERVER_CHECKSUM)
            && buf.data.len() >= 4
        {
            buf.data[..4].copy_from_slice(&ct.to_le_bytes());
        }
        pac = parsed.to_bytes();
    }
    part.authorization_data = Some(wrap_win2k_pac(&pac).map_err(|e| e.to_string())?);
    seal_ticket(key, kvno, realm, sname, &part)
}

#[expect(clippy::too_many_arguments, reason = "diffsend ticket forge helper")]
fn mint_signed_stkt(
    server: &ProtocolKey,
    server_kvno: u32,
    kdc: &ProtocolKey,
    cname: &PrincipalName,
    realm: &str,
    sname: &PrincipalName,
    session: &ProtocolKey,
    window: (KerberosTime, KerberosTime),
    flags: TicketFlags,
    pac_cname: &PrincipalName,
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
        renew_till: None,
        caddr: None,
        authorization_data: Some(wrap_win2k_pac(&[0]).map_err(|e| e.to_string())?),
    };
    let der = ticket_checksum_der(&part).map_err(|e| e.to_string())?;
    let pac = sign_pac(
        pac_cname,
        start.unix_seconds(),
        &PacTicket {
            server,
            kdc,
            enc_tkt_der: &der,
            is_service_tkt: true,
        },
        &dummy_ident(&pac_cname.components_joined(), realm),
        None,
    )
    .map_err(|e| e.to_string())?;
    part.authorization_data = Some(wrap_win2k_pac(&pac).map_err(|e| e.to_string())?);
    seal_ticket(server, server_kvno, realm, sname, &part)
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
    ProtocolKey::random(etype).map_err(|e| e.to_string())
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
    // A 4th positional `b17lab` runs only the lab-only provider-signature-failure cases.
    let b17lab = args.next().as_deref() == Some("b17lab");
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
        b17lab,
    })
}

fn run() -> Result<(), String> {
    let cfg = load_cfg()?;
    let realm = cfg.realm.as_str();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    if cfg.b17lab {
        return b17_lab_cases(&cfg, realm, &user);
    }
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

    // hintu aes128-only vs aes256: no keys, so 25, no PA 2, ETYPE-INFO2 or PA 151.
    // MIT: `have_client_keys` (kdc/kdc_preauth.c:434-447)
    let hintu = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["hintu"]);
    let req = encode(
        &as_req_sname(
            hintu,
            realm,
            0x1000_0012,
            None,
            PrincipalName::krbtgt(realm),
            vec![18],
        )
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    expect_error(
        &cfg,
        "as-needpreauth-hints-unpermitted",
        &req,
        err::PREAUTH_REQUIRED,
    )?;

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

    // pwchgu REQUIRES_PWCHANGE, no preauth: KEY_EXP (23) "REQUIRED PWCHANGE",
    // not "CLIENT KEY EXPIRED".
    let pwchgu = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pwchgu"]);
    let req = encode(&as_req(pwchgu, realm, 0x1000_000f, None).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    expect_error(&cfg, "as-needchange", &req, err::KEY_EXPIRED)?;

    // RENEW is BADOPTION 13. Also ENC_TKT_IN_SKEY and CNAME_IN_ADDL_TKT.
    // MIT: `AS_INVALID_OPTIONS` (kdc/kdc_util.h:463-463)
    // MIT: `NON_TGT_OPTION` (kdc/kdc_util.h:456-457)
    // MIT: `NO_REFERRAL_OPTION` (kdc/kdc_util.h:460-460)
    let mut inv = as_req(user.clone(), realm, 0x1000_0010, None).map_err(|e| e.to_string())?;
    inv.0.req_body.kdc_options = inv
        .0
        .req_body
        .kdc_options
        .with_bit(krb5_types::flag_bit::RENEW, true);
    let req = encode(&inv).map_err(|e| e.to_string())?;
    expect_error(&cfg, "as-invalid-opts", &req, err::BADOPTION)?;

    // pwprau needs preauth and a password change: KEY_EXP (23),
    // not "NEEDED_PREAUTH" (25). check_padata.
    let pwprau = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pwprau"]);
    let req = encode(&as_req(pwprau, realm, 0x1000_0011, None).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    expect_error(&cfg, "as-validate-before-preauth", &req, err::KEY_EXPIRED)?;

    // lockedu past maxfailure 1, no expiry: CLIENT_REVOKED (18) "LOCKED_OUT" before preauth.
    let lockedu = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["lockedu"]);
    let req = encode(&as_req(lockedu, realm, 0x1000_0097, None).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    expect_error(&cfg, "as-locked-out", &req, err::CLIENT_REVOKED)?;

    // PA-ENC-TIMESTAMP etype 16, absent for pauser:
    // KRB5_KDB_NO_MATCHING_KEY, PREAUTH_FAILED (24).
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

    // A fresh-nonce preauth AS-REQ sent twice: the lookaside resends the first reply.
    let pa_rt = pa_enc_timestamp(&ukey).map_err(|e| e.to_string())?;
    let as_req_rt = encode(
        &as_req(user.clone(), realm, 0x1000_0012, Some(vec![pa_rt])).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    expect_retransmit(&cfg, "as-retransmit", &as_req_rt)?;

    // Non-anonymous VALIDATE is BADOPTION "VALIDATE_ANONYMOUS_PRINCIPAL" after preauth.
    // Early "INVALID AS OPTIONS" is an e_text MIT does not send.
    // MIT: `validate_as_request` (kdc/kdc_util.c:715-804)
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

    // Bit 17 is outside AS_INVALID_OPTIONS, so a bare pauser AS-REQ stays code 25.
    // MIT: `validate_as_request` (kdc/kdc_util.c:715-804)
    let mut reserved =
        as_req(pauser.clone(), realm, 0x1000_00ad, None).map_err(|e| e.to_string())?;
    reserved.0.req_body.kdc_options = reserved.0.req_body.kdc_options.with_bit(17, true);
    let req = encode(&reserved).map_err(|e| e.to_string())?;
    expect_error(&cfg, "as-reserved-option-bit", &req, err::PREAUTH_REQUIRED)?;

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

    // Forged TGT, future authtime, no starttime: PROCESS_TGS (33).
    // MIT: `krb5int_validate_times` (lib/krb5/krb/valid_times.c:35-57)
    // MIT: `rd_req_decoded_opt` (lib/krb5/krb/rd_req_dec.c:472-787)
    let nyv_no_start = mint_tgt_times(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        now.add_seconds(3600).unwrap_or_else(|_| now.clone()),
        None,
        now.add_seconds(7200).unwrap_or_else(|_| now.clone()),
        TicketFlags::initial_preauth(),
    )?;
    let tgs_nyv_no_start = tgs_req(
        nyv_no_start,
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_000b,
    )
    .map_err(|e| e.to_string())?;
    expect_error_client(
        &cfg,
        "tgt-nyv-no-starttime",
        &encode(&tgs_nyv_no_start).map_err(|e| e.to_string())?,
        err::TKT_NYV,
        true,
    )?;

    let local = EncTicketPart {
        flags: TicketFlags::initial_preauth(),
        key: EncryptionKey {
            keytype: sess.etype().to_iana(),
            keyvalue: sess.as_bytes().to_vec().into(),
        },
        crealm: krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        cname: user.clone(),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: b"OTHER.TEST".to_vec().into(),
        },
        authtime: now.clone(),
        starttime: Some(now.clone()),
        endtime: now.add_hours(10).unwrap_or_else(|_| now.clone()),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let transited_tgs = tgs_req(
        seal_ticket(tkt_key, tkt_kvno, realm, &krbtgt_sname, &local)?,
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_0329,
    )
    .map_err(|e| e.to_string())?;
    expect_error_client(
        &cfg,
        "tgs-transited-local",
        &encode(&transited_tgs).map_err(|e| e.to_string())?,
        err::GENERIC,
        true,
    )?;

    // FAST armor AP-REQ with no subkey. MIT always sends one; this forge is the oracle.
    // MIT: `armor_ap_request` (kdc/fast_util.c:35-90)
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

    // AD-FX-ARMOR 71 is PROCESS_TGS (12); 1.22.2 never emits it.
    // MIT: `kdc_process_tgs_req` (kdc/kdc_util.c:142-280)
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

    // kvno 0: bad MSG_TYPE -> KRB5_BADMSGTYPE; unserved realm -> WRONG_REALM;
    // MUTUAL_REQUIRED -> POLICY; else MUST_USE_USER2USER.
    // MIT: `gather_tgs_req_info` (kdc/do_tgs_req.c:583-807)
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

    // An expired server is SERVICE EXPIRED on a bare AS-REQ, before preauth.
    // MIT: `validate_as_request` (kdc/kdc_util.c:715-804)
    let expired_server = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["expiredsvc"]);
    expect_error(
        &cfg,
        "as-service-expired",
        &encode(
            &as_req_sname(
                user.clone(),
                realm,
                0x1000_00ae,
                None,
                expired_server,
                etypes.clone(),
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::SERVICE_EXP,
    )?;

    // DISALLOW_ALL_TIX is SERVICE LOCKED OUT on a bare AS-REQ, before preauth.
    // MIT: `validate_as_request` (kdc/kdc_util.c:715-804)
    let locked_server = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["lockedsvc"]);
    expect_error(
        &cfg,
        "as-service-locked",
        &encode(
            &as_req_sname(
                user.clone(),
                realm,
                0x1000_00af,
                None,
                locked_server,
                etypes.clone(),
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::S_PRINCIPAL_UNKNOWN,
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

    // MIT: `maybe_add_etype_info2` (kdc/kdc_preauth.c:1136-1171)
    expect_error(
        &cfg,
        "as-spake-round1",
        &encode(
            &as_req(
                user.clone(),
                realm,
                0x1000_002a,
                Some(vec![pa_spake_support(&[krb5_crypto::SpakeGroup::P256])]),
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
        tgs_req_ex(TgsReqParams {
            ticket: mint_tgt(
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
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: user.clone(),
            realm,
            nonce,
            kdc_options: opts,
            additional_tickets: Some(vec![extra]),
            extra_padata: Vec::new(),
            etypes: etypes.clone(),
            addresses: None,
            from: None,
            enc_authorization_data: None,
            till: None,
            subkey: None,
            time_offset: 0,
        })
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
            &tgs_req_ex(TgsReqParams {
                ticket: pac_tkt,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: host.clone(),
                realm,
                nonce: 0x1000_0032,
                kdc_options: KdcOptions::forwardable(),
                additional_tickets: None,
                extra_padata: vec![PaData {
                    padata_type: pa::PAC_REQUEST,
                    padata_value: pac_req.into(),
                }],
                etypes: EncryptionType::preferred()
                    .iter()
                    .map(|e| e.to_iana())
                    .collect(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
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
    let svc_renew = seal_ticket(hkey, hkvno, realm, &host, &svc_part)?;
    expect_tgs_rep(
        &cfg,
        "tgs-renew-service-ticket",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: svc_renew,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: host.clone(),
                realm,
                nonce: 0x1000_0034,
                kdc_options: KdcOptions::forwardable()
                    .with_bit(flag_bit::RENEWABLE, true)
                    .with_bit(flag_bit::RENEW, true),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: EncryptionType::preferred()
                    .iter()
                    .map(|e| e.to_iana())
                    .collect(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
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
            &tgs_req_ex(TgsReqParams {
                ticket: proxy_tgt,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: krbtgt_sname.clone(),
                realm,
                nonce: 0x1000_0035,
                kdc_options: KdcOptions::forwardable().with_bit(flag_bit::PROXY, true),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: EncryptionType::preferred()
                    .iter()
                    .map(|e| e.to_iana())
                    .collect(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
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
        renew_till: Some(renew_till.clone()),
        caddr: None,
        authorization_data: None,
    };
    let can_tgt = seal_ticket(tkt_key, tkt_kvno, realm, &krbtgt_sname, &can_part)?;
    expect_tgs_rep(
        &cfg,
        "tgs-canonicalize-renew",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: can_tgt,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: krbtgt_sname.clone(),
                realm,
                nonce: 0x1000_0036,
                kdc_options: KdcOptions::forwardable()
                    .with_bit(flag_bit::RENEWABLE, true)
                    .with_bit(flag_bit::RENEW, true)
                    .with_bit(flag_bit::CANONICALIZE, true),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: EncryptionType::preferred()
                    .iter()
                    .map(|e| e.to_iana())
                    .collect(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
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
            &tgs_req_ex(TgsReqParams {
                ticket: tkt,
                session: &sess,
                crealm: realm,
                cname: &host,
                sname: host.clone(),
                realm,
                nonce,
                kdc_options: KdcOptions::forwardable(),
                additional_tickets: None,
                extra_padata: extra,
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
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

    let svc = cfg
        .host
        .as_ref()
        .ok_or_else(|| "KERBER_HOST_KEYTAB required for S4U2Proxy".to_string())?;
    let (hkey, hkvno) = keytab_for(svc, 20)?;
    let ev_flags = TicketFlags::initial_preauth().with_bit(flag_bit::FORWARDABLE, true);
    let ev_ok = mint_signed_stkt(
        hkey,
        hkvno,
        tkt_key,
        &user,
        realm,
        &host,
        &sess,
        window10.clone(),
        ev_flags.clone(),
        &user,
    )?;
    let proxy_req = |header: Ticket,
                     extra: Option<Vec<Ticket>>,
                     dest: PrincipalName,
                     opts: KdcOptions,
                     nonce: u32|
     -> Result<Vec<u8>, String> {
        encode(
            &tgs_req_ex(TgsReqParams {
                ticket: header,
                session: &sess,
                crealm: realm,
                cname: &host,
                sname: dest,
                realm,
                nonce,
                kdc_options: opts,
                additional_tickets: extra,
                extra_padata: Vec::new(),
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    };
    let addl = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);

    expect_error(
        &cfg,
        "s4u2proxy-no-2nd-tkt",
        &proxy_req(
            host_hdr(&host, false)?,
            None,
            host.clone(),
            addl.clone(),
            0x1000_0050,
        )?,
        err::GENERIC,
    )?;
    let ev_nf = mint_signed_stkt(
        hkey,
        hkvno,
        tkt_key,
        &user,
        realm,
        &host,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth(),
        &user,
    )?;
    expect_error(
        &cfg,
        "s4u2proxy-not-forwardable",
        &proxy_req(
            host_hdr(&host, false)?,
            Some(vec![ev_nf]),
            host.clone(),
            addl.clone(),
            0x1000_0051,
        )?,
        err::BADOPTION,
    )?;
    expect_error(
        &cfg,
        "s4u2proxy-u2u-combo",
        &proxy_req(
            host_hdr(&host, false)?,
            Some(vec![host_hdr(&host, false)?]),
            host.clone(),
            addl.clone().with_bit(flag_bit::ENC_TKT_IN_SKEY, true),
            0x1000_0052,
        )?,
        err::BADOPTION,
    )?;
    expect_error(
        &cfg,
        "s4u2proxy-tgs-target",
        &proxy_req(
            host_hdr(&host, false)?,
            Some(vec![ev_ok.clone()]),
            krbtgt_sname.clone(),
            addl.clone(),
            0x1000_0053,
        )?,
        err::POLICY,
    )?;
    expect_error(
        &cfg,
        "s4u2proxy-no-header-pac",
        &proxy_req(
            mint_tgt(
                tkt_key,
                tkt_kvno,
                &host,
                realm,
                &krbtgt_sname,
                &sess,
                window10.clone(),
                host_flags.clone(),
            )?,
            Some(vec![ev_ok.clone()]),
            host.clone(),
            addl.clone(),
            0x1000_0054,
        )?,
        err::TGT_REVOKED,
    )?;
    expect_error(
        &cfg,
        "s4u2proxy-header-pac",
        &proxy_req(
            host_hdr(&user, false)?,
            Some(vec![ev_ok.clone()]),
            host.clone(),
            addl.clone(),
            0x1000_0055,
        )?,
        err::BADOPTION,
    )?;
    let ev_nopac = mint_tgt(
        hkey,
        hkvno,
        &user,
        realm,
        &host,
        &sess,
        window10.clone(),
        ev_flags.clone(),
    )?;
    expect_error(
        &cfg,
        "s4u2proxy-no-stkt-pac",
        &proxy_req(
            host_hdr(&host, false)?,
            Some(vec![ev_nopac]),
            host.clone(),
            addl.clone(),
            0x1000_0056,
        )?,
        err::MODIFIED,
    )?;
    expect_error(
        &cfg,
        "s4u2proxy-evidence-mismatch",
        &proxy_req(
            host_hdr(&host, false)?,
            Some(vec![mint_signed_header(
                tkt_key,
                tkt_kvno,
                &user,
                realm,
                &krbtgt_sname,
                &sess,
                window10.clone(),
                ev_flags.clone(),
                &user,
                false,
                None,
            )?]),
            host.clone(),
            addl.clone(),
            0x1000_0057,
        )?,
        err::SERVER_NOMATCH,
    )?;
    expect_error(
        &cfg,
        "s4u2proxy-local-stkt-pac",
        &proxy_req(
            host_hdr(&host, false)?,
            Some(vec![mint_signed_stkt(
                hkey,
                hkvno,
                tkt_key,
                &user,
                realm,
                &host,
                &sess,
                window10.clone(),
                ev_flags,
                &host,
            )?]),
            host.clone(),
            addl,
            0x1000_0058,
        )?,
        err::BADOPTION,
    )?;

    let u2u_opts = KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    let u2u_to =
        |dest: PrincipalName, extra: Option<Vec<Ticket>>, nonce: u32| -> Result<Vec<u8>, String> {
            encode(
                &tgs_req_ex(TgsReqParams {
                    ticket: mint_tgt(
                        tkt_key,
                        tkt_kvno,
                        &user,
                        realm,
                        &krbtgt_sname,
                        &sess,
                        window10.clone(),
                        TicketFlags::initial_preauth(),
                    )?,
                    session: &sess,
                    crealm: realm,
                    cname: &user,
                    sname: dest,
                    realm,
                    nonce,
                    kdc_options: u2u_opts.clone(),
                    additional_tickets: extra,
                    extra_padata: Vec::new(),
                    etypes: etypes.clone(),
                    addresses: None,
                    from: None,
                    enc_authorization_data: None,
                    till: None,
                    subkey: None,
                    time_offset: 0,
                })
                .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        };

    expect_error(
        &cfg,
        "u2u-no-2nd-tkt",
        &u2u_to(user.clone(), None, 0x1000_0059)?,
        err::BADOPTION,
    )?;
    expect_error(
        &cfg,
        "u2u-2nd-ticket-not-tgs",
        &u2u_to(
            user.clone(),
            Some(vec![mint_signed_stkt(
                hkey,
                hkvno,
                tkt_key,
                &user,
                realm,
                &host,
                &sess,
                window10.clone(),
                TicketFlags::initial_preauth(),
                &user,
            )?]),
            0x1000_005a,
        )?,
        err::POLICY,
    )?;
    expect_error(
        &cfg,
        "u2u-2nd-ticket-mismatch",
        &u2u_to(
            host.clone(),
            Some(vec![mint_tgt(
                tkt_key,
                tkt_kvno,
                &user,
                realm,
                &krbtgt_sname,
                &sess,
                window10.clone(),
                TicketFlags::initial_preauth(),
            )?]),
            0x1000_005b,
        )?,
        err::SERVER_NOMATCH,
    )?;
    expect_error(
        &cfg,
        "u2u-2nd-ticket-bad-pac",
        &u2u_to(
            user.clone(),
            Some(vec![mint_signed_header(
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
            )?]),
            0x1000_005c,
        )?,
        err::MODIFIED,
    )?;
    let bad_sess = EncTicketPart {
        flags: TicketFlags::initial_preauth(),
        key: EncryptionKey {
            keytype: 99,
            keyvalue: sess.as_bytes().to_vec().into(),
        },
        crealm: krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        cname: user.clone(),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: Vec::<u8>::new().into(),
        },
        authtime: window10.0.clone(),
        starttime: Some(window10.0.clone()),
        endtime: window10.1.clone(),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    expect_error(
        &cfg,
        "u2u-bad-etype",
        &u2u_to(
            user.clone(),
            Some(vec![seal_ticket(
                tkt_key,
                tkt_kvno,
                realm,
                &krbtgt_sname,
                &bad_sess,
            )?]),
            0x1000_005d,
        )?,
        err::ETYPE_NOSUPP,
    )?;
    // AES128 offered, AES256 stkt session: ticket key is the session;
    // reply key is select_session_keytype.
    let stkt_sess = random_session(EncryptionType::Aes256CtsHmacSha196)?;
    let u2u_ok_etypes = vec![EncryptionType::Aes128CtsHmacSha196.to_iana()];
    let u2u_ok = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: mint_tgt(
                tkt_key,
                tkt_kvno,
                &user,
                realm,
                &krbtgt_sname,
                &sess,
                window10.clone(),
                TicketFlags::initial_preauth(),
            )?,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: host.clone(),
            realm,
            nonce: 0x1000_005e,
            kdc_options: u2u_opts.clone(),
            additional_tickets: Some(vec![mint_tgt(
                tkt_key,
                tkt_kvno,
                &host,
                realm,
                &krbtgt_sname,
                &stkt_sess,
                window10.clone(),
                TicketFlags::initial_preauth(),
            )?]),
            extra_padata: Vec::new(),
            etypes: u2u_ok_etypes,
            addresses: None,
            from: None,
            enc_authorization_data: None,
            till: None,
            subkey: None,
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "u2u-success", &u2u_ok)?;
    let (re, rtkt, _) = decrypt_u2u(&tr, &sess, &stkt_sess)?;
    let (me, mtkt, _) = decrypt_u2u(&tm, &sess, &stkt_sess)?;
    let want_reply = EncryptionType::Aes128CtsHmacSha196.to_iana();
    let want_tkt = stkt_sess.etype().to_iana();
    if rtkt.enc_part.kvno.is_some() || mtkt.enc_part.kvno.is_some() {
        return Err(format!(
            "u2u-success: ticket kvno rust={:?} mit={:?} want none",
            rtkt.enc_part.kvno, mtkt.enc_part.kvno
        ));
    }
    if rtkt.enc_part.etype != want_tkt || mtkt.enc_part.etype != want_tkt {
        return Err(format!(
            "u2u-success: ticket etype rust={} mit={} want {want_tkt}",
            rtkt.enc_part.etype, mtkt.enc_part.etype
        ));
    }
    if re.key.keytype != want_reply || me.key.keytype != want_reply {
        return Err(format!(
            "u2u-success: reply session rust={} mit={} want {want_reply}",
            re.key.keytype, me.key.keytype
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"u2u-success","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","ticket_etype":{want_tkt},"reply_session_etype":{want_reply}}}"#
    );

    let mismatch = mint_tgt_caddr(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth(),
        Some(vec![HostAddress {
            addr_type: HostAddress::ADDRTYPE_INET,
            address: vec![10, 0, 0, 1].into(),
        }]),
    )?;
    expect_error(
        &cfg,
        "tgs-addr-mismatch",
        &encode(
            &tgs_req(
                mismatch,
                &sess,
                realm,
                &user,
                host.clone(),
                realm,
                0x1000_0060,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADADDR,
    )?;

    let (hkey, hkvno) = keytab_for(
        cfg.host
            .as_ref()
            .ok_or_else(|| "KERBER_HOST_KEYTAB required".to_string())?,
        20,
    )?;
    let fwd_addrs = vec![HostAddress {
        addr_type: HostAddress::ADDRTYPE_INET,
        address: vec![192, 0, 2, 1].into(),
    }];
    let fwd_tkt = mint_tgt(
        hkey,
        hkvno,
        &user,
        realm,
        &host,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth().with_bit(flag_bit::FORWARDABLE, true),
    )?;
    let fwd = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: fwd_tkt,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: host.clone(),
            realm,
            nonce: 0x1000_0061,
            kdc_options: KdcOptions::none().with_bit(flag_bit::FORWARDED, true),
            additional_tickets: None,
            extra_padata: Vec::new(),
            etypes: etypes.clone(),
            addresses: Some(fwd_addrs.clone()),
            from: None,
            enc_authorization_data: None,
            till: None,
            subkey: None,
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-forwarded-addresses", &fwd)?;
    let svc = cfg
        .host
        .as_ref()
        .ok_or_else(|| "KERBER_HOST_KEYTAB required".to_string())?;
    let (_, re, rt, _) = decrypt_tgs(&tr, &sess, svc)?;
    let (_, me, mt, _) = decrypt_tgs(&tm, &sess, svc)?;
    if rt.caddr.as_ref() != Some(&fwd_addrs) || mt.caddr.as_ref() != Some(&fwd_addrs) {
        return Err(format!(
            "tgs-forwarded-addresses: ticket caddr rust={:?} mit={:?}",
            rt.caddr, mt.caddr
        ));
    }
    if re.caddr.as_ref() != Some(&fwd_addrs) || me.caddr.as_ref() != Some(&fwd_addrs) {
        return Err(format!(
            "tgs-forwarded-addresses: reply caddr rust={:?} mit={:?}",
            re.caddr, me.caddr
        ));
    }
    if !rt.flags.bit(flag_bit::FORWARDED) || !mt.flags.bit(flag_bit::FORWARDED) {
        return Err(format!(
            "tgs-forwarded-addresses: FORWARDED rust={} mit={}",
            rt.flags.bit(flag_bit::FORWARDED),
            mt.flags.bit(flag_bit::FORWARDED)
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-forwarded-addresses","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","forwarded":true}}"#
    );

    let mut foreign_stkt = mint_tgt(
        tkt_key,
        tkt_kvno,
        &host,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth(),
    )?;
    foreign_stkt.realm = krb5_types::try_ascii("OTHER.TEST").map_err(|e| e.to_string())?;
    expect_error(
        &cfg,
        "u2u-2nd-ticket-foreign-realm",
        &u2u_to(host.clone(), Some(vec![foreign_stkt]), 0x1000_0062)?,
        err::S_PRINCIPAL_UNKNOWN,
    )?;

    expect_error(
        &cfg,
        "s4u2self-renew-options",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: host_hdr(&host, false)?,
                session: &sess,
                crealm: realm,
                cname: &host,
                sname: host.clone(),
                realm,
                nonce: 0x1000_0063,
                kdc_options: KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true),
                additional_tickets: None,
                extra_padata: vec![
                    pa_for_user(&sess, user.clone(), realm).map_err(|e| e.to_string())?,
                ],
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADOPTION,
    )?;
    expect_error(
        &cfg,
        "pa-s4u-x509-user-truncated",
        &s4u_req(
            host_hdr(&host, false)?,
            vec![PaData {
                padata_type: pa::FOR_X509_USER,
                padata_value: b"\x30\x03\x01\x01".to_vec().into(),
            }],
            0x1000_0064,
        )?,
        err::GENERIC,
    )?;
    let other_tgs = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "OTHER.TEST"]);
    expect_error(
        &cfg,
        "s4u2self-krbtgt-other",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: host_hdr(&host, false)?,
                session: &sess,
                crealm: realm,
                cname: &host,
                sname: other_tgs,
                realm,
                nonce: 0x1000_0065,
                kdc_options: KdcOptions::forwardable(),
                additional_tickets: None,
                extra_padata: vec![
                    pa_for_user(&sess, user.clone(), realm).map_err(|e| e.to_string())?,
                ],
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADMATCH,
    )?;

    let locked = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "locked.kerber.test"]);
    expect_error(
        &cfg,
        "tgs-locked-pac-mismatch",
        &encode(
            &tgs_req(
                mint_signed_header(
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
                )?,
                &sess,
                realm,
                &user,
                locked,
                realm,
                0x1000_0066,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADOPTION,
    )?;

    let dups = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "dupskey.kerber.test"]);
    expect_error(
        &cfg,
        "u2u-dup-skey-tgt-based",
        &u2u_to(
            dups.clone(),
            Some(vec![mint_tgt(
                tkt_key,
                tkt_kvno,
                &dups,
                realm,
                &krbtgt_sname,
                &sess,
                window10.clone(),
                TicketFlags::initial_preauth(),
            )?]),
            0x1000_0067,
        )?,
        err::POLICY,
    )?;

    let expired_win = (
        now.add_seconds(-7200).unwrap_or_else(|_| now.clone()),
        now.add_seconds(-3600).unwrap_or_else(|_| now.clone()),
    );
    expect_error(
        &cfg,
        "tgs-expired-addr-mismatch",
        &encode(
            &tgs_req(
                mint_tgt_caddr(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    expired_win.clone(),
                    TicketFlags::initial_preauth(),
                    Some(vec![HostAddress {
                        addr_type: HostAddress::ADDRTYPE_INET,
                        address: vec![10, 0, 0, 1].into(),
                    }]),
                )?,
                &sess,
                realm,
                &user,
                host.clone(),
                realm,
                0x1000_0068,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADADDR,
    )?;

    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    expect_error(
        &cfg,
        "tgs-expired-badmatch",
        &encode(
            &tgs_req(
                mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    expired_win,
                    TicketFlags::initial_preauth(),
                )?,
                &sess,
                realm,
                &admin,
                host.clone(),
                realm,
                0x1000_0069,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADMATCH,
    )?;

    let mut kvno_miss = mint_tgt(
        tkt_key,
        tkt_kvno,
        &host,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth(),
    )?;
    kvno_miss.enc_part.kvno = Some(99);
    expect_error(
        &cfg,
        "u2u-2nd-ticket-kvno-miss",
        &u2u_to(host.clone(), Some(vec![kvno_miss]), 0x1000_006a)?,
        err::GENERIC,
    )?;

    let nosvr = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "nosvr.kerber.test"]);
    expect_error(
        &cfg,
        "u2u-2nd-ticket-disallow-svr",
        &u2u_to(
            host.clone(),
            Some(vec![mint_tgt(
                tkt_key,
                tkt_kvno,
                &host,
                realm,
                &nosvr,
                &sess,
                window10.clone(),
                TicketFlags::initial_preauth(),
            )?]),
            0x1000_006b,
        )?,
        err::S_PRINCIPAL_UNKNOWN,
    )?;

    let cert_id = krb5_types::s4u::S4uUserId {
        nonce: 0x1000_006c,
        user: None,
        realm: krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        subject_cert: Some(b"cert".to_vec().into()),
        options: Some(krb5_types::s4u::s4u_reply_key_usage_flags()),
    };
    let cert_der = encode(&cert_id).map_err(|e| e.to_string())?;
    let cert_usage = KeyUsage::new(ku::PA_S4U_X509_USER_REQUEST).map_err(|e| e.to_string())?;
    let cert_mic = checksum(&sess, cert_usage, &cert_der).map_err(|e| e.to_string())?;
    let cert_pa = PaData {
        padata_type: pa::FOR_X509_USER,
        padata_value: encode(&krb5_types::s4u::PaS4uX509User {
            user_id: cert_id,
            cksum: Checksum {
                cksumtype: sess.etype().checksum_type(),
                checksum: cert_mic.into(),
            },
        })
        .map_err(|e| e.to_string())?
        .into(),
    };
    expect_error(
        &cfg,
        "s4u2self-cert-only",
        &s4u_req(host_hdr(&host, false)?, vec![cert_pa], 0x1000_006c)?,
        err::GENERIC,
    )?;

    expect_error(
        &cfg,
        "tgs-pac-server-cksum-wrong-enctype",
        &encode(
            &tgs_req(
                mint_signed_header_ex(
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
                    Some(15),
                )?,
                &sess,
                realm,
                &user,
                host.clone(),
                realm,
                0x1000_006e,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::GENERIC,
    )?;
    expect_error(
        &cfg,
        "u2u-2nd-ticket-pac-wrong-enctype",
        &u2u_to(
            user.clone(),
            Some(vec![mint_signed_header_ex(
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
                Some(15),
            )?]),
            0x1000_006f,
        )?,
        err::GENERIC,
    )?;
    let stkt_offered = random_session(EncryptionType::Aes256CtsHmacSha196)?;
    let u2u_offered = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: mint_tgt(
                tkt_key,
                tkt_kvno,
                &user,
                realm,
                &krbtgt_sname,
                &sess,
                window10.clone(),
                TicketFlags::initial_preauth(),
            )?,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: host.clone(),
            realm,
            nonce: 0x1000_0070,
            kdc_options: u2u_opts.clone(),
            additional_tickets: Some(vec![mint_tgt(
                tkt_key,
                tkt_kvno,
                &host,
                realm,
                &krbtgt_sname,
                &stkt_offered,
                window10.clone(),
                TicketFlags::initial_preauth(),
            )?]),
            extra_padata: Vec::new(),
            etypes: vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
            addresses: None,
            from: None,
            enc_authorization_data: None,
            till: None,
            subkey: None,
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "u2u-success-offered", &u2u_offered)?;
    let (re, rtkt, _) = decrypt_u2u(&tr, &sess, &stkt_offered)?;
    let (me, mtkt, _) = decrypt_u2u(&tm, &sess, &stkt_offered)?;
    let want_offered = EncryptionType::Aes256CtsHmacSha196.to_iana();
    if rtkt.enc_part.kvno.is_some() || mtkt.enc_part.kvno.is_some() {
        return Err(format!(
            "u2u-success-offered: ticket kvno rust={:?} mit={:?}",
            rtkt.enc_part.kvno, mtkt.enc_part.kvno
        ));
    }
    if rtkt.enc_part.etype != want_offered || mtkt.enc_part.etype != want_offered {
        return Err(format!(
            "u2u-success-offered: ticket etype rust={} mit={} want {want_offered}",
            rtkt.enc_part.etype, mtkt.enc_part.etype
        ));
    }
    if re.key.keytype != want_offered || me.key.keytype != want_offered {
        return Err(format!(
            "u2u-success-offered: reply session rust={} mit={} want {want_offered}",
            re.key.keytype, me.key.keytype
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"u2u-success-offered","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","ticket_etype":{want_offered},"reply_session_etype":{want_offered}}}"#
    );

    let ftgt_addrs = vec![HostAddress {
        addr_type: HostAddress::ADDRTYPE_INET,
        address: vec![192, 0, 2, 2].into(),
    }];
    let ftgt = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: mint_tgt(
                tkt_key,
                tkt_kvno,
                &user,
                realm,
                &krbtgt_sname,
                &sess,
                window10.clone(),
                TicketFlags::initial_preauth().with_bit(flag_bit::FORWARDABLE, true),
            )?,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: krbtgt_sname.clone(),
            realm,
            nonce: 0x1000_006d,
            kdc_options: KdcOptions::none().with_bit(flag_bit::FORWARDED, true),
            additional_tickets: None,
            extra_padata: Vec::new(),
            etypes: etypes.clone(),
            addresses: Some(ftgt_addrs.clone()),
            from: None,
            enc_authorization_data: None,
            till: None,
            subkey: None,
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-forwarded-tgt-addresses", &ftgt)?;
    let (_, re, rt, _) = decrypt_tgs(&tr, &sess, tkt_kt)?;
    let (_, me, mt, _) = decrypt_tgs(&tm, &sess, tkt_kt)?;
    if rt.caddr.as_ref() != Some(&ftgt_addrs) || mt.caddr.as_ref() != Some(&ftgt_addrs) {
        return Err(format!(
            "tgs-forwarded-tgt-addresses: ticket caddr rust={:?} mit={:?}",
            rt.caddr, mt.caddr
        ));
    }
    if re.caddr.as_ref() != Some(&ftgt_addrs) || me.caddr.as_ref() != Some(&ftgt_addrs) {
        return Err(format!(
            "tgs-forwarded-tgt-addresses: reply caddr rust={:?} mit={:?}",
            re.caddr, me.caddr
        ));
    }
    if !rt.flags.bit(flag_bit::FORWARDED) || !mt.flags.bit(flag_bit::FORWARDED) {
        return Err(format!(
            "tgs-forwarded-tgt-addresses: FORWARDED rust={} mit={}",
            rt.flags.bit(flag_bit::FORWARDED),
            mt.flags.bit(flag_bit::FORWARDED)
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-forwarded-tgt-addresses","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","forwarded":true}}"#
    );

    let no_f = mint_tgt(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth(),
    )?;
    expect_error(
        &cfg,
        "tgs-forwarded-on-non-f-tgt",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: no_f,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: host.clone(),
                realm,
                nonce: 0x1000_0070,
                kdc_options: KdcOptions::none().with_bit(flag_bit::FORWARDED, true),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADOPTION,
    )?;

    let no_p = mint_tgt(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth(),
    )?;
    expect_error(
        &cfg,
        "tgs-proxy-on-non-p-tgt",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: no_p,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: host.clone(),
                realm,
                nonce: 0x1000_0071,
                kdc_options: KdcOptions::none().with_bit(flag_bit::PROXY, true),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADOPTION,
    )?;

    let mut bare = tgs_req(
        mint_tgt(
            tkt_key,
            tkt_kvno,
            &user,
            realm,
            &krbtgt_sname,
            &sess,
            window10.clone(),
            TicketFlags::initial_preauth(),
        )?,
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_00a0,
    )
    .map_err(|e| e.to_string())?;
    bare.0.padata = None;
    expect_error(
        &cfg,
        "tgs-missing-pa-tgs-req",
        &encode(&bare).map_err(|e| e.to_string())?,
        err::PADATA_TYPE_NOSUPP,
    )?;

    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    expect_error(
        &cfg,
        "tgs-authenticator-cname-mismatch",
        &encode(
            &tgs_req(
                mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    window10.clone(),
                    TicketFlags::initial_preauth(),
                )?,
                &sess,
                realm,
                &admin,
                host.clone(),
                realm,
                0x1000_00a1,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADMATCH,
    )?;

    expect_error(
        &cfg,
        "tgs-authenticator-crealm-mismatch",
        &encode(
            &tgs_req(
                mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    window10.clone(),
                    TicketFlags::initial_preauth(),
                )?,
                &sess,
                "OTHER.TEST",
                &user,
                host.clone(),
                realm,
                0x1000_00a2,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADMATCH,
    )?;

    expect_error(
        &cfg,
        "tgs-server-locked-out",
        &encode(
            &tgs_req(
                mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    window10.clone(),
                    TicketFlags::initial_preauth(),
                )?,
                &sess,
                realm,
                &user,
                PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "locked.kerber.test"]),
                realm,
                0x1000_00a3,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::S_PRINCIPAL_UNKNOWN,
    )?;

    expect_error(
        &cfg,
        "tgs-disallow-tgt-based",
        &encode(
            &tgs_req(
                mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    window10.clone(),
                    TicketFlags::initial_preauth(),
                )?,
                &sess,
                realm,
                &user,
                PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "dupskey.kerber.test"]),
                realm,
                0x1000_00a4,
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::POLICY,
    )?;

    let first = tgs_req(
        mint_tgt(
            tkt_key,
            tkt_kvno,
            &user,
            realm,
            &krbtgt_sname,
            &sess,
            window10.clone(),
            TicketFlags::initial_preauth(),
        )?,
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_00a5,
    )
    .map_err(|e| e.to_string())?;
    let mut second = first.clone();
    second.0.padata.get_or_insert_with(Vec::new).push(PaData {
        padata_type: pa::ENC_UNIX_TIME,
        padata_value: Vec::<u8>::new().into(),
    });
    let replay = encode(&first).map_err(|e| e.to_string())?;
    let again = encode(&second).map_err(|e| e.to_string())?;
    let svc_kt = cfg
        .host
        .as_ref()
        .ok_or_else(|| "KERBER_HOST_KEYTAB required".to_string())?;
    let (r1, m1) = send_both(&cfg, "tgs-authenticator-replay", &replay)?;
    let (r2, m2) = send_both(&cfg, "tgs-authenticator-replay", &again)?;
    let (_, r1e, _, _) = decrypt_tgs(&r1, &sess, svc_kt)?;
    let (_, r2e, _, _) = decrypt_tgs(&r2, &sess, svc_kt)?;
    let (_, m1e, _, _) = decrypt_tgs(&m1, &sess, svc_kt)?;
    let (_, m2e, _, _) = decrypt_tgs(&m2, &sess, svc_kt)?;
    if r1e.key.keyvalue.as_ref() == r2e.key.keyvalue.as_ref()
        || m1e.key.keyvalue.as_ref() == m2e.key.keyvalue.as_ref()
    {
        return Err("tgs-authenticator-replay: second ticket reused the session key".to_string());
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-authenticator-replay","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","replay_session_differs":true}}"#
    );

    expect_error(
        &cfg,
        "tgs-postdate-on-non-postdatable",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    window10.clone(),
                    TicketFlags::initial_preauth(),
                )?,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: host.clone(),
                realm,
                nonce: 0x1000_0072,
                kdc_options: KdcOptions::none().with_bit(flag_bit::MAY_POSTDATE, true),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADOPTION,
    )?;

    expect_error(
        &cfg,
        "tgs-server-disallow-postdated",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    window10.clone(),
                    TicketFlags::initial_preauth().with_bit(flag_bit::MAY_POSTDATE, true),
                )?,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: PrincipalName::new(
                    PrincipalName::NT_SRV_HST,
                    ["host", "nopost.kerber.test"],
                ),
                realm,
                nonce: 0x1000_00a6,
                kdc_options: KdcOptions::none().with_bit(flag_bit::MAY_POSTDATE, true),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::CANNOT_POSTDATE,
    )?;

    let expuser = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["expuser"]);
    let lockuser = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["lockuser"]);
    expect_error(
        &cfg,
        "s4u2self-client-expired",
        &s4u_req(
            host_hdr(&host, false)?,
            vec![pa_for_user(&sess, expuser, realm).map_err(|e| e.to_string())?],
            0x1000_00a7,
        )?,
        err::NAME_EXP,
    )?;
    expect_error(
        &cfg,
        "s4u2self-client-locked-out",
        &s4u_req(
            host_hdr(&host, false)?,
            vec![pa_for_user(&sess, lockuser, realm).map_err(|e| e.to_string())?],
            0x1000_00a8,
        )?,
        err::CLIENT_REVOKED,
    )?;

    let mut fast_bad = tgs_req(
        mint_tgt(
            tkt_key,
            tkt_kvno,
            &user,
            realm,
            &krbtgt_sname,
            &sess,
            window10.clone(),
            TicketFlags::initial_preauth(),
        )?,
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_00a9,
    )
    .map_err(|e| e.to_string())?;
    let fast_inner = fast_bad.0.req_body.clone();
    wrap_tgs_fast_hide(&mut fast_bad, &sess, fast_inner)?;
    let fx = fast_bad
        .0
        .padata
        .as_mut()
        .and_then(|p| p.iter_mut().find(|x| x.padata_type == pa::FX_FAST))
        .ok_or_else(|| "no PA-FX-FAST".to_string())?;
    let krb5_types::fast::PaFxFast::ArmoredData(mut armored) =
        decode::<krb5_types::fast::PaFxFast>(fx.padata_value.as_ref())
            .map_err(|e| e.to_string())?;
    armored.req_checksum.cksumtype = 7;
    armored.req_checksum.checksum = vec![0xff; 16].into();
    fx.padata_value = encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
        .map_err(|e| e.to_string())?
        .into();
    expect_error(
        &cfg,
        "tgs-fast-unkeyed-bad-checksum",
        &encode(&fast_bad).map_err(|e| e.to_string())?,
        err::MODIFIED,
    )?;

    let mut explicit = tgs_req(
        mint_tgt(
            tkt_key,
            tkt_kvno,
            &user,
            realm,
            &krbtgt_sname,
            &sess,
            window10.clone(),
            TicketFlags::initial_preauth(),
        )?,
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_00aa,
    )
    .map_err(|e| e.to_string())?;
    let explicit_inner = explicit.0.req_body.clone();
    wrap_tgs_fast_hide(&mut explicit, &sess, explicit_inner)?;
    let pa_tgs = explicit
        .0
        .padata
        .as_ref()
        .and_then(|p| p.iter().find(|x| x.padata_type == pa::TGS_REQ))
        .map(|p| p.padata_value.clone())
        .ok_or_else(|| "no PA-TGS-REQ".to_string())?;
    let fx = explicit
        .0
        .padata
        .as_mut()
        .and_then(|p| p.iter_mut().find(|x| x.padata_type == pa::FX_FAST))
        .ok_or_else(|| "no PA-FX-FAST".to_string())?;
    let krb5_types::fast::PaFxFast::ArmoredData(mut armored) =
        decode(fx.padata_value.as_ref()).map_err(|e| e.to_string())?;
    armored.armor = Some(krb5_types::fast::KrbFastArmor {
        armor_type: krb5_types::fast::ARMOR_AP_REQUEST,
        armor_value: pa_tgs,
    });
    fx.padata_value = encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
        .map_err(|e| e.to_string())?
        .into();
    expect_error_no_edata(
        &cfg,
        "tgs-fast-explicit-armor",
        &encode(&explicit).map_err(|e| e.to_string())?,
        err::PREAUTH_FAILED,
    )?;

    let armor_tkt = mint_tgt(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth(),
    )?;
    let mut accepted = tgs_req(
        armor_tkt.clone(),
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_00ab,
    )
    .map_err(|e| e.to_string())?;
    let accepted_inner = accepted.0.req_body.clone();
    let pa_tgs_bytes = accepted
        .0
        .padata
        .as_ref()
        .and_then(|p| p.iter().find(|x| x.padata_type == pa::TGS_REQ))
        .map(|p| p.padata_value.as_ref().to_vec())
        .ok_or_else(|| "no PA-TGS-REQ".to_string())?;
    let armor_sub =
        ProtocolKey::from_bytes(sess.etype(), &[0x53u8; 32]).map_err(|e| e.to_string())?;
    let armor_ap = build_fast_armor(
        armor_tkt,
        &sess,
        &krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        &user,
        Some(&armor_sub),
    )
    .map_err(|e| e.to_string())?;
    let akey = armor_key(&sess, Some(&armor_sub)).map_err(|e| e.to_string())?;
    let ck_usage = KeyUsage::new(ku::FAST_REQ_CHKSUM).map_err(|e| e.to_string())?;
    let mic = checksum(&akey, ck_usage, &pa_tgs_bytes).map_err(|e| e.to_string())?;
    let inner = krb5_types::fast::KrbFastReq {
        fast_options: krb5_types::fast::fast_options_none(),
        padata: Vec::new(),
        req_body: accepted_inner,
    };
    let inner_der = encode(&inner).map_err(|e| e.to_string())?;
    let enc_usage = KeyUsage::new(ku::FAST_ENC).map_err(|e| e.to_string())?;
    let cipher = encrypt(&akey, enc_usage, &inner_der).map_err(|e| e.to_string())?;
    let armor_der = encode(&armor_ap).map_err(|e| e.to_string())?;
    let armored = krb5_types::fast::KrbFastArmoredReq {
        armor: Some(krb5_types::fast::KrbFastArmor {
            armor_type: krb5_types::fast::ARMOR_AP_REQUEST,
            armor_value: armor_der.into(),
        }),
        req_checksum: Checksum {
            cksumtype: akey.etype().checksum_type(),
            checksum: mic.into(),
        },
        enc_fast_req: EncryptedData {
            etype: akey.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    accepted.0.padata.get_or_insert_with(Vec::new).push(PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
            .map_err(|e| e.to_string())?
            .into(),
    });
    expect_tgs_rep(
        &cfg,
        "tgs-fast-armor-no-tgs-subkey",
        &encode(&accepted).map_err(|e| e.to_string())?,
    )?;

    let bare_tkt = mint_tgt(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth(),
    )?;
    let mut bare = tgs_req(
        bare_tkt.clone(),
        &sess,
        realm,
        &user,
        host.clone(),
        realm,
        0x1000_00ac,
    )
    .map_err(|e| e.to_string())?;
    let bare_inner = bare.0.req_body.clone();
    let bare_pa = bare
        .0
        .padata
        .as_ref()
        .and_then(|p| p.iter().find(|x| x.padata_type == pa::TGS_REQ))
        .map(|p| p.padata_value.as_ref().to_vec())
        .ok_or_else(|| "no PA-TGS-REQ".to_string())?;
    let bare_ap = build_fast_armor(
        bare_tkt,
        &sess,
        &krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        &user,
        None,
    )
    .map_err(|e| e.to_string())?;
    let bare_key = armor_key(&sess, None).map_err(|e| e.to_string())?;
    let bare_ck = KeyUsage::new(ku::FAST_REQ_CHKSUM).map_err(|e| e.to_string())?;
    let bare_mic = checksum(&bare_key, bare_ck, &bare_pa).map_err(|e| e.to_string())?;
    let bare_fast = krb5_types::fast::KrbFastReq {
        fast_options: krb5_types::fast::fast_options_none(),
        padata: Vec::new(),
        req_body: bare_inner,
    };
    let bare_der = encode(&bare_fast).map_err(|e| e.to_string())?;
    let bare_enc = KeyUsage::new(ku::FAST_ENC).map_err(|e| e.to_string())?;
    let bare_cipher = encrypt(&bare_key, bare_enc, &bare_der).map_err(|e| e.to_string())?;
    let bare_armor = encode(&bare_ap).map_err(|e| e.to_string())?;
    let bare_armored = krb5_types::fast::KrbFastArmoredReq {
        armor: Some(krb5_types::fast::KrbFastArmor {
            armor_type: krb5_types::fast::ARMOR_AP_REQUEST,
            armor_value: bare_armor.into(),
        }),
        req_checksum: Checksum {
            cksumtype: bare_key.etype().checksum_type(),
            checksum: bare_mic.into(),
        },
        enc_fast_req: EncryptedData {
            etype: bare_key.etype().to_iana(),
            kvno: None,
            cipher: bare_cipher.into(),
        },
    };
    bare.0.padata.get_or_insert_with(Vec::new).push(PaData {
        padata_type: pa::FX_FAST,
        padata_value: encode(&krb5_types::fast::PaFxFast::ArmoredData(bare_armored))
            .map_err(|e| e.to_string())?
            .into(),
    });
    expect_error(
        &cfg,
        "tgs-fast-armor-no-subkey",
        &encode(&bare).map_err(|e| e.to_string())?,
        err::POLICY,
    )?;

    let from = now.add_seconds(60).unwrap_or_else(|_| now.clone());
    let post_tgt = mint_tgt(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &sess,
        window10.clone(),
        TicketFlags::initial_preauth().with_bit(flag_bit::MAY_POSTDATE, true),
    )?;
    let postdated = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: post_tgt,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: host.clone(),
            realm,
            nonce: 0x1000_0073,
            kdc_options: KdcOptions::none()
                .with_bit(flag_bit::MAY_POSTDATE, true)
                .with_bit(flag_bit::POSTDATED, true),
            additional_tickets: None,
            extra_padata: Vec::new(),
            etypes: etypes.clone(),
            addresses: None,
            from: Some(from),
            enc_authorization_data: None,
            till: None,
            subkey: None,
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-postdated-is-invalid", &postdated)?;
    let svc = cfg
        .host
        .as_ref()
        .ok_or_else(|| "KERBER_HOST_KEYTAB required".to_string())?;
    let (_, _, rt, _) = decrypt_tgs(&tr, &sess, svc)?;
    let (_, _, mt, _) = decrypt_tgs(&tm, &sess, svc)?;
    if !rt.flags.invalid()
        || !mt.flags.invalid()
        || !rt.flags.bit(flag_bit::POSTDATED)
        || !mt.flags.bit(flag_bit::POSTDATED)
    {
        return Err(format!(
            "tgs-postdated-is-invalid: rust invalid={} postdated={} mit invalid={} postdated={}",
            rt.flags.invalid(),
            rt.flags.bit(flag_bit::POSTDATED),
            mt.flags.invalid(),
            mt.flags.bit(flag_bit::POSTDATED)
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-postdated-is-invalid","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","invalid":true,"postdated":true}}"#
    );

    expect_error(
        &cfg,
        "tgs-validate-invalid-non-renewable",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    window10.clone(),
                    TicketFlags::none()
                        .with_bit(flag_bit::INITIAL, true)
                        .with_bit(flag_bit::INVALID, true),
                )?,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: PrincipalName::krbtgt(realm),
                realm,
                nonce: 0x1000_0076,
                kdc_options: KdcOptions::none().with_bit(flag_bit::RENEW, true),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::BADOPTION,
    )?;

    let pauser = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pauser"]);
    expect_error(
        &cfg,
        "tgs-no-preauth-flag",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    window10.clone(),
                    TicketFlags::none().with_bit(flag_bit::INITIAL, true),
                )?,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: pauser,
                realm,
                nonce: 0x1000_0074,
                kdc_options: KdcOptions::none(),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::GENERIC,
    )?;

    let hwuser = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["hwuser"]);
    expect_error(
        &cfg,
        "tgs-hw-preauth-flag",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    window10.clone(),
                    TicketFlags::initial_preauth(),
                )?,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: hwuser,
                realm,
                nonce: 0x1000_0075,
                kdc_options: KdcOptions::none(),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::GENERIC,
    )?;

    let nyv_from = now.add_seconds(60).unwrap_or_else(|_| now.clone());
    expect_error(
        &cfg,
        "tgs-nyv-inside-skew",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    (
                        nyv_from.clone(),
                        nyv_from
                            .add_seconds(3600)
                            .unwrap_or_else(|_| nyv_from.clone()),
                    ),
                    TicketFlags::initial_preauth()
                        .with_bit(flag_bit::POSTDATED, true)
                        .with_bit(flag_bit::INVALID, true),
                )?,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: host.clone(),
                realm,
                nonce: 0x1000_0076,
                kdc_options: KdcOptions::none().with_bit(flag_bit::VALIDATE, true),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::TKT_NYV,
    )?;

    let copy_blob = b"kerber-ad-copy";
    let copy_ad = vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: encode(&vec![AuthorizationDataValue {
            ad_type: pa::AD_AND_OR,
            ad_data: copy_blob.to_vec().into(),
        }])
        .map_err(|e| e.to_string())?
        .into(),
    }];
    let copy_enc = enc_ad_usage(&sess, ku::TGS_REQ_AD_SESSKEY, &copy_ad)?;
    let copy_req = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: mint_signed_header(
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
            )?,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: host.clone(),
            realm,
            nonce: 0x1000_0077,
            kdc_options: KdcOptions::none(),
            additional_tickets: None,
            extra_padata: Vec::new(),
            etypes: etypes.clone(),
            addresses: None,
            from: None,
            enc_authorization_data: Some(copy_enc),
            till: None,
            subkey: None,
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-body-authdata", &copy_req)?;
    let svc = cfg
        .host
        .as_ref()
        .ok_or_else(|| "KERBER_HOST_KEYTAB required".to_string())?;
    let (_, _, rt, _) = decrypt_tgs(&tr, &sess, svc)?;
    let (_, _, mt, _) = decrypt_tgs(&tm, &sess, svc)?;
    let want = &copy_ad[0];
    let rust_ad = rt.authorization_data.as_deref().unwrap_or(&[]);
    let mit_ad = mt.authorization_data.as_deref().unwrap_or(&[]);
    if !ad_has_exact(rust_ad, want) || !ad_has_exact(mit_ad, want) {
        return Err(format!(
            "tgs-body-authdata: rust_der={} mit_der={}",
            ad_has_exact(rust_ad, want),
            ad_has_exact(mit_ad, want)
        ));
    }
    if !first_is_pac(rust_ad) || !first_is_pac(mit_ad) {
        return Err(format!(
            "tgs-body-authdata: pac_first rust={} mit={}",
            first_is_pac(rust_ad),
            first_is_pac(mit_ad)
        ));
    }
    if !ad_has_payload(rust_ad, GREET_AD_TYPE, GREET_TEXT)
        || !ad_has_payload(mit_ad, GREET_AD_TYPE, GREET_TEXT)
    {
        return Err(format!(
            "tgs-body-authdata: greet rust={} mit={}",
            ad_has_payload(rust_ad, GREET_AD_TYPE, GREET_TEXT),
            ad_has_payload(mit_ad, GREET_AD_TYPE, GREET_TEXT)
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-body-authdata","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","copied":true,"greet":true,"pac_first":true}}"#
    );

    let mandatory = vec![AuthorizationDataValue {
        ad_type: pa::AD_MANDATORY_FOR_KDC,
        ad_data: Vec::<u8>::new().into(),
    }];
    let mand_enc = {
        let usage = KeyUsage::new(ku::TGS_REQ_AD_SESSKEY).map_err(|e| e.to_string())?;
        let cipher = encrypt(
            &sess,
            usage,
            &encode(&mandatory).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        EncryptedData {
            etype: sess.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        }
    };
    expect_error(
        &cfg,
        "tgs-ad-mandatory-for-kdc",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    window10.clone(),
                    TicketFlags::initial_preauth(),
                )?,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: host.clone(),
                realm,
                nonce: 0x1000_0078,
                kdc_options: KdcOptions::none(),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: Some(mand_enc),
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::POLICY,
    )?;

    let keep_blob = b"keep-me";
    let strip_ad = vec![
        AuthorizationDataValue {
            ad_type: pa::AD_IF_RELEVANT,
            ad_data: encode(&vec![AuthorizationDataValue {
                ad_type: pa::AD_WIN2K_PAC,
                ad_data: b"dummy-pac".to_vec().into(),
            }])
            .map_err(|e| e.to_string())?
            .into(),
        },
        AuthorizationDataValue {
            ad_type: pa::AD_IF_RELEVANT,
            ad_data: encode(&vec![AuthorizationDataValue {
                ad_type: pa::AD_AND_OR,
                ad_data: keep_blob.to_vec().into(),
            }])
            .map_err(|e| e.to_string())?
            .into(),
        },
    ];
    let strip_enc = {
        let usage = KeyUsage::new(ku::TGS_REQ_AD_SESSKEY).map_err(|e| e.to_string())?;
        let cipher = encrypt(&sess, usage, &encode(&strip_ad).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        EncryptedData {
            etype: sess.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        }
    };
    let strip_req = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: mint_tgt(
                tkt_key,
                tkt_kvno,
                &user,
                realm,
                &krbtgt_sname,
                &sess,
                window10.clone(),
                TicketFlags::initial_preauth(),
            )?,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: host.clone(),
            realm,
            nonce: 0x1000_0079,
            kdc_options: KdcOptions::none(),
            additional_tickets: None,
            extra_padata: Vec::new(),
            etypes: etypes.clone(),
            addresses: None,
            from: None,
            enc_authorization_data: Some(strip_enc),
            till: None,
            subkey: None,
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-body-authdata-kdc-issued-stripped", &strip_req)?;
    let (_, _, rt, _) = decrypt_tgs(&tr, &sess, svc)?;
    let (_, _, mt, _) = decrypt_tgs(&tm, &sess, svc)?;
    let has_keep = |tkt: &EncTicketPart| {
        tkt.authorization_data
            .as_ref()
            .is_some_and(|ad| ad_has_payload(ad, pa::AD_AND_OR, keep_blob))
    };
    let has_dummy = |tkt: &EncTicketPart| {
        tkt.authorization_data
            .as_ref()
            .is_some_and(|ad| ad_has_payload(ad, pa::AD_WIN2K_PAC, b"dummy-pac"))
    };
    if !has_keep(&rt) || !has_keep(&mt) || has_dummy(&rt) || has_dummy(&mt) {
        return Err(format!(
            "tgs-body-authdata-kdc-issued-stripped: rust_keep={} mit_keep={} rust_dummy={} mit_dummy={}",
            has_keep(&rt),
            has_keep(&mt),
            has_dummy(&rt),
            has_dummy(&mt)
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-body-authdata-kdc-issued-stripped","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","kept":true,"dummy_stripped":true}}"#
    );

    let sub_blob = b"kerber-ad-subkey";
    let sub_ad = vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: encode(&vec![AuthorizationDataValue {
            ad_type: pa::AD_AND_OR,
            ad_data: sub_blob.to_vec().into(),
        }])
        .map_err(|e| e.to_string())?
        .into(),
    }];
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32])
        .map_err(|e| e.to_string())?;
    let sub_enc = enc_ad_usage(&sub, ku::TGS_REQ_AD_SUBKEY, &sub_ad)?;
    let sub_req = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: mint_tgt(
                tkt_key,
                tkt_kvno,
                &user,
                realm,
                &krbtgt_sname,
                &sess,
                window10.clone(),
                TicketFlags::initial_preauth(),
            )?,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: host.clone(),
            realm,
            nonce: 0x1000_0080,
            kdc_options: KdcOptions::none(),
            additional_tickets: None,
            extra_padata: Vec::new(),
            etypes: etypes.clone(),
            addresses: None,
            from: None,
            enc_authorization_data: Some(sub_enc),
            till: None,
            subkey: Some(&sub),
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-body-authdata-subkey", &sub_req)?;
    let (_, _, rt, _) = decrypt_tgs_enc(&tr, &sub, ku::TGS_REP_ENC_PART_SUBKEY, svc)?;
    let (_, _, mt, _) = decrypt_tgs_enc(&tm, &sub, ku::TGS_REP_ENC_PART_SUBKEY, svc)?;
    let rust_ad = rt.authorization_data.as_deref().unwrap_or(&[]);
    let mit_ad = mt.authorization_data.as_deref().unwrap_or(&[]);
    if !ad_has_exact(rust_ad, &sub_ad[0]) || !ad_has_exact(mit_ad, &sub_ad[0]) {
        return Err(format!(
            "tgs-body-authdata-subkey: rust_der={} mit_der={}",
            ad_has_exact(rust_ad, &sub_ad[0]),
            ad_has_exact(mit_ad, &sub_ad[0])
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-body-authdata-subkey","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","copied":true}}"#
    );

    let ku5_blob = b"kerber-ad-sess-ku5";
    let ku5_ad = vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: encode(&vec![AuthorizationDataValue {
            ad_type: pa::AD_AND_OR,
            ad_data: ku5_blob.to_vec().into(),
        }])
        .map_err(|e| e.to_string())?
        .into(),
    }];
    let ku5_enc = enc_ad_usage(&sess, ku::TGS_REQ_AD_SUBKEY, &ku5_ad)?;
    let ku5_req = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: mint_tgt(
                tkt_key,
                tkt_kvno,
                &user,
                realm,
                &krbtgt_sname,
                &sess,
                window10.clone(),
                TicketFlags::initial_preauth(),
            )?,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: host.clone(),
            realm,
            nonce: 0x1000_0081,
            kdc_options: KdcOptions::none(),
            additional_tickets: None,
            extra_padata: Vec::new(),
            etypes: etypes.clone(),
            addresses: None,
            from: None,
            enc_authorization_data: Some(ku5_enc),
            till: None,
            subkey: None,
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-body-authdata-session-ku5", &ku5_req)?;
    let (_, _, rt, _) = decrypt_tgs(&tr, &sess, svc)?;
    let (_, _, mt, _) = decrypt_tgs(&tm, &sess, svc)?;
    let rust_ad = rt.authorization_data.as_deref().unwrap_or(&[]);
    let mit_ad = mt.authorization_data.as_deref().unwrap_or(&[]);
    if !ad_has_exact(rust_ad, &ku5_ad[0]) || !ad_has_exact(mit_ad, &ku5_ad[0]) {
        return Err(format!(
            "tgs-body-authdata-session-ku5: rust_der={} mit_der={}",
            ad_has_exact(rust_ad, &ku5_ad[0]),
            ad_has_exact(mit_ad, &ku5_ad[0])
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-body-authdata-session-ku5","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","copied":true}}"#
    );

    let keep_tgt = b"tgt-keep-half";
    let dummy_tgt_pac = b"dummy-tgt-pac";
    let signed_tgt = mint_signed_header(
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
    let t_usage = KeyUsage::new(ku::TICKET).map_err(|e| e.to_string())?;
    let mut keep_part: EncTicketPart = decode(
        &decrypt(tkt_key, t_usage, signed_tgt.enc_part.cipher.as_ref())
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let mut keep_ad = keep_part.authorization_data.take().unwrap_or_default();
    keep_ad.push(AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: encode(&vec![AuthorizationDataValue {
            ad_type: pa::AD_WIN2K_PAC,
            ad_data: dummy_tgt_pac.to_vec().into(),
        }])
        .map_err(|e| e.to_string())?
        .into(),
    });
    keep_ad.push(AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: encode(&vec![AuthorizationDataValue {
            ad_type: pa::AD_AND_OR,
            ad_data: keep_tgt.to_vec().into(),
        }])
        .map_err(|e| e.to_string())?
        .into(),
    });
    keep_part.authorization_data = Some(keep_ad);
    let keep_req = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: seal_ticket(tkt_key, tkt_kvno, realm, &krbtgt_sname, &keep_part)?,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: host.clone(),
            realm,
            nonce: 0x1000_0082,
            kdc_options: KdcOptions::none(),
            additional_tickets: None,
            extra_padata: Vec::new(),
            etypes: etypes.clone(),
            addresses: None,
            from: None,
            enc_authorization_data: None,
            till: None,
            subkey: None,
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-tgt-and-or-kept", &keep_req)?;
    let (_, _, rt, _) = decrypt_tgs(&tr, &sess, svc)?;
    let (_, _, mt, _) = decrypt_tgs(&tm, &sess, svc)?;
    let rust_ad = rt.authorization_data.as_deref().unwrap_or(&[]);
    let mit_ad = mt.authorization_data.as_deref().unwrap_or(&[]);
    let rust_keep = ad_has_payload(rust_ad, pa::AD_AND_OR, keep_tgt);
    let mit_keep = ad_has_payload(mit_ad, pa::AD_AND_OR, keep_tgt);
    let rust_dummy = ad_has_payload(rust_ad, pa::AD_WIN2K_PAC, b"dummy-tgt-pac");
    let mit_dummy = ad_has_payload(mit_ad, pa::AD_WIN2K_PAC, b"dummy-tgt-pac");
    if !rust_keep || !mit_keep || rust_dummy || mit_dummy {
        return Err(format!(
            "tgs-tgt-and-or-kept: rust_keep={rust_keep} mit_keep={mit_keep} rust_dummy={rust_dummy} mit_dummy={mit_dummy}"
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-tgt-and-or-kept","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","kept":true,"dummy_stripped":true}}"#
    );

    let cammac_ad = vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: encode(&vec![AuthorizationDataValue {
            ad_type: pa::AD_CAMMAC,
            ad_data: b"truncated".to_vec().into(),
        }])
        .map_err(|e| e.to_string())?
        .into(),
    }];
    expect_error(
        &cfg,
        "tgs-truncated-cammac",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: mint_tgt_ad(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    window10.clone(),
                    TicketFlags::initial_preauth(),
                    Some(cammac_ad),
                )?,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: host.clone(),
                realm,
                nonce: 0x1000_007a,
                kdc_options: KdcOptions::none(),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::GENERIC,
    )?;

    expect_error(
        &cfg,
        "ec-outside-fast",
        &encode(
            &as_req(
                user.clone(),
                realm,
                0x1000_007b,
                Some(vec![PaData {
                    padata_type: pa::ENCRYPTED_CHALLENGE,
                    padata_value: b"outside-fast".to_vec().into(),
                }]),
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::PREAUTH_FAILED,
    )?;

    let past = now.add_seconds(-60).unwrap_or_else(|_| now.clone());
    let till_past = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: mint_tgt(
                tkt_key,
                tkt_kvno,
                &user,
                realm,
                &krbtgt_sname,
                &sess,
                window10.clone(),
                TicketFlags::initial_preauth(),
            )?,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: host.clone(),
            realm,
            nonce: 0x1000_007d,
            kdc_options: KdcOptions::none(),
            additional_tickets: None,
            extra_padata: Vec::new(),
            etypes: etypes.clone(),
            addresses: None,
            from: None,
            enc_authorization_data: None,
            till: Some(past.clone()),
            subkey: None,
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-till-in-past", &till_past)?;
    let svc = cfg
        .host
        .as_ref()
        .ok_or_else(|| "KERBER_HOST_KEYTAB required".to_string())?;
    let (_, _, rt, _) = decrypt_tgs(&tr, &sess, svc)?;
    let (_, _, mt, _) = decrypt_tgs(&tm, &sess, svc)?;
    if rt.endtime.unix_seconds() != past.unix_seconds()
        || mt.endtime.unix_seconds() != past.unix_seconds()
    {
        return Err(format!(
            "tgs-till-in-past rust={} mit={} want={}",
            rt.endtime.unix_seconds(),
            mt.endtime.unix_seconds(),
            past.unix_seconds()
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-till-in-past","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","endtime":{}}}"#,
        past.unix_seconds()
    );

    let expiredsvc = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["expiredsvc"]);
    expect_error(
        &cfg,
        "tgs-service-expired-require-auth",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: mint_tgt(
                    tkt_key,
                    tkt_kvno,
                    &user,
                    realm,
                    &krbtgt_sname,
                    &sess,
                    window10.clone(),
                    TicketFlags::initial_preauth(),
                )?,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: expiredsvc,
                realm,
                nonce: 0x1000_007e,
                kdc_options: KdcOptions::none(),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: etypes.clone(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::SERVICE_EXP,
    )?;

    let from_past = tgs_req_ex(TgsReqParams {
        ticket: mint_tgt(
            tkt_key,
            tkt_kvno,
            &user,
            realm,
            &krbtgt_sname,
            &sess,
            window10.clone(),
            TicketFlags::initial_preauth().with_bit(flag_bit::MAY_POSTDATE, true),
        )?,
        session: &sess,
        crealm: realm,
        cname: &user,
        sname: host.clone(),
        realm,
        nonce: 0x1000_007f,
        kdc_options: KdcOptions::none()
            .with_bit(flag_bit::MAY_POSTDATE, true)
            .with_bit(flag_bit::POSTDATED, true),
        additional_tickets: None,
        extra_padata: Vec::new(),
        etypes: etypes.clone(),
        addresses: None,
        from: None,
        enc_authorization_data: None,
        till: None,
        subkey: None,
        time_offset: 0,
    })
    .map_err(|e| e.to_string())?;
    let from_past = encode(&from_past).map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-postdated-from", &from_past)?;
    let (_, _, rt, _) = decrypt_tgs(&tr, &sess, svc)?;
    let (_, _, mt, _) = decrypt_tgs(&tm, &sess, svc)?;
    if rt.starttime.is_some() || mt.starttime.is_some() {
        return Err(format!(
            "tgs-postdated-from rust={:?} mit={:?} want omitted (from=0)",
            rt.starttime.as_ref().map(KerberosTime::unix_seconds),
            mt.starttime.as_ref().map(KerberosTime::unix_seconds)
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-postdated-from","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","starttime_omitted":true}}"#
    );

    let past_end = now.add_seconds(-60).unwrap_or_else(|_| now.clone());
    let (hkey, hkvno) = keytab_for(svc, 20)?;
    let inverted = EncTicketPart {
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
        endtime: past_end,
        renew_till: Some(now.add_hours(24).unwrap_or_else(|_| now.clone())),
        caddr: None,
        authorization_data: None,
    };
    let inverted_svc = seal_ticket(hkey, hkvno, realm, &host, &inverted)?;
    let renew_inv = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: inverted_svc,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: host.clone(),
            realm,
            nonce: 0x1000_0080,
            kdc_options: KdcOptions::forwardable()
                .with_bit(flag_bit::RENEWABLE, true)
                .with_bit(flag_bit::RENEW, true),
            additional_tickets: None,
            extra_padata: Vec::new(),
            etypes: etypes.clone(),
            addresses: None,
            from: None,
            enc_authorization_data: None,
            till: None,
            subkey: None,
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-renew-header-end-before-start", &renew_inv)?;
    let (_, _, rt, _) = decrypt_tgs(&tr, &sess, svc)?;
    let (_, _, mt, _) = decrypt_tgs(&tm, &sess, svc)?;
    let life = |p: &EncTicketPart| {
        let start = p.starttime.as_ref().unwrap_or(&p.authtime).unix_seconds();
        i64::from(p.endtime.unix_seconds()) - i64::from(start)
    };
    let rl = life(&rt);
    let ml = life(&mt);
    if rl != -60 || ml != -60 {
        return Err(format!(
            "tgs-renew-header-end-before-start rust_life={rl} mit_life={ml} want=-60"
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-renew-header-end-before-start","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","life":-60}}"#
    );

    let pac_opts = pa_pac_options(true).map_err(|e| e.to_string())?;
    let rbcd_req = encode(
        &tgs_req_ex(TgsReqParams {
            ticket: mint_tgt(
                tkt_key,
                tkt_kvno,
                &user,
                realm,
                &krbtgt_sname,
                &sess,
                window10.clone(),
                TicketFlags::initial_preauth(),
            )?,
            session: &sess,
            crealm: realm,
            cname: &user,
            sname: host,
            realm,
            nonce: 0x1000_007c,
            kdc_options: KdcOptions::none(),
            additional_tickets: None,
            extra_padata: vec![pac_opts],
            etypes: etypes.clone(),
            addresses: None,
            from: None,
            enc_authorization_data: None,
            till: None,
            subkey: None,
            time_offset: 0,
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-rbcd-pac-options", &rbcd_req)?;
    let svc = cfg
        .host
        .as_ref()
        .ok_or_else(|| "KERBER_HOST_KEYTAB required".to_string())?;
    let (_, re, _, _) = decrypt_tgs(&tr, &sess, svc)?;
    let (_, me, _, _) = decrypt_tgs(&tm, &sess, svc)?;
    let pa_types = |enc: &krb5_types::EncKdcRepPart| -> Vec<i32> {
        enc.encrypted_pa_data
            .as_ref()
            .into_iter()
            .flatten()
            .map(|p| p.padata_type)
            .collect()
    };
    let rt = pa_types(&re);
    let mt = pa_types(&me);
    if !rt.contains(&pa::PAC_OPTIONS) || rt != mt {
        return Err(format!(
            "tgs-rbcd-pac-options enc_padata rust={rt:?} mit={mt:?}"
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-rbcd-pac-options","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","pac_options":true}}"#
    );

    let kp = p256_generate().map_err(|e| e.to_string())?;
    let mut unsigned_named =
        as_req(user.clone(), realm, 0x1000_0090, None).map_err(|e| e.to_string())?;
    let body_der = encode(&unsigned_named.0.req_body).map_err(|e| e.to_string())?;
    let mut h = Sha1::new();
    h.update(&body_der);
    let sha1 = h.finalize();
    unsigned_named.0.padata = Some(vec![
        pa_pk_as_req_unsigned(&kp.public, 0x1000_0090, &sha1, None).map_err(|e| e.to_string())?,
    ]);
    expect_error(
        &cfg,
        "as-anonymous-unsigned-authpack-named-client",
        &encode(&unsigned_named).map_err(|e| e.to_string())?,
        err::PREAUTH_FAILED,
    )?;

    // MIT: `prepare_error_as` (kdc/do_as_req.c:769-849)
    let hide_sess = random_session(EncryptionType::Aes256CtsHmacSha196)?;
    let hide_tkt = mint_tgt(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &hide_sess,
        (
            now.clone(),
            now.add_hours(10).unwrap_or_else(|_| now.clone()),
        ),
        TicketFlags::initial_preauth(),
    )?;
    let hide_sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x41u8; 32])
        .map_err(|e| e.to_string())?;
    let hide_ap = build_fast_armor(
        hide_tkt,
        &hide_sess,
        &krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        &user,
        Some(&hide_sub),
    )
    .map_err(|e| e.to_string())?;
    let hide_key = armor_key(&hide_sess, Some(&hide_sub)).map_err(|e| e.to_string())?;
    let mut hide_opts = krb5_types::fast::fast_options_none();
    hide_opts.set(1, true);
    let hide_client = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pauser"]);
    let mut hide_req = as_req(hide_client, realm, 0x1000_0091, None).map_err(|e| e.to_string())?;
    attach_fast_with_options(&mut hide_req, &hide_ap, &hide_key, Vec::new(), &hide_opts)
        .map_err(|e| e.to_string())?;
    expect_hidden_client_error(
        &cfg,
        "as-fast-hide-error-client",
        &encode(&hide_req).map_err(|e| e.to_string())?,
        err::PREAUTH_REQUIRED,
    )?;

    let hide_tgs_tgt = mint_tgt(
        tkt_key,
        tkt_kvno,
        &user,
        realm,
        &krbtgt_sname,
        &hide_sess,
        (
            now.clone(),
            now.add_hours(10).unwrap_or_else(|_| now.clone()),
        ),
        TicketFlags::initial_preauth(),
    )?;
    let hide_host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]);
    let mut hide_tgs = tgs_req(
        hide_tgs_tgt,
        &hide_sess,
        realm,
        &user,
        hide_host,
        realm,
        0x1000_0092,
    )
    .map_err(|e| e.to_string())?;
    let hide_inner = hide_tgs.0.req_body.clone();
    wrap_tgs_fast_hide(&mut hide_tgs, &hide_sess, hide_inner)?;
    expect_hidden_tgs_rep(
        &cfg,
        "tgs-fast-hide-client",
        &encode(&hide_tgs).map_err(|e| e.to_string())?,
    )?;

    // RFC 8070: stale AuthPack [4] is internal 90 → wire 24 + a fresh token.
    let pem_path = env::var("KERBER_PKINIT_USER").unwrap_or_else(|_| "/tmp/pkinit/user.pem".into());
    let pem =
        fs::read_to_string(&pem_path).map_err(|e| format!("pkinit user pem {pem_path}: {e}"))?;
    let (cert, leaf) =
        krb5_types::pkinit::parse_identity_pem(&pem).ok_or_else(|| format!("parse {pem_path}"))?;
    let leaf = krb5_types::pkinit::IdentityKey::p256(leaf);
    let stale_kp = p256_generate().map_err(|e| e.to_string())?;
    let mut stale_req =
        as_req(user.clone(), realm, 0x1000_0093, None).map_err(|e| e.to_string())?;
    let stale_body = encode(&stale_req.0.req_body).map_err(|e| e.to_string())?;
    let mut h = Sha1::new();
    h.update(&stale_body);
    let stale_sha1 = h.finalize();
    let stale_ts = KerberosTime::now().unix_seconds().saturating_sub(601);
    let mut stale_tok = stale_ts.to_be_bytes().to_vec();
    stale_tok.extend_from_slice(&1u32.to_be_bytes());
    stale_tok.extend_from_slice(&[0u8; 12]);
    stale_req.0.padata = Some(vec![
        pa_pk_as_req_signed(
            &stale_kp.public,
            &cert,
            &leaf,
            0x1000_0093,
            &stale_sha1,
            Some(&stale_tok),
        )
        .map_err(|e| e.to_string())?,
        PaData {
            padata_type: pa::AS_FRESHNESS,
            padata_value: Vec::<u8>::new().into(),
        },
    ]);
    expect_error(
        &cfg,
        "pkinit-stale-freshness",
        &encode(&stale_req).map_err(|e| e.to_string())?,
        err::PREAUTH_FAILED,
    )?;

    b17_cms_cases(&cfg, realm, &user)?;

    let nodot = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "nodot"]);
    let nodot_tgt = mint_tgt(
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
    expect_error(
        &cfg,
        "tgs-referral-no-dot",
        &encode(
            &tgs_req_ex(TgsReqParams {
                ticket: nodot_tgt,
                session: &sess,
                crealm: realm,
                cname: &user,
                sname: nodot,
                realm,
                nonce: 0x1000_0094,
                kdc_options: KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true),
                additional_tickets: None,
                extra_padata: Vec::new(),
                etypes: EncryptionType::preferred()
                    .iter()
                    .map(|e| e.to_iana())
                    .collect(),
                addresses: None,
                from: None,
                enc_authorization_data: None,
                till: None,
                subkey: None,
                time_offset: 0,
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        err::S_PRINCIPAL_UNKNOWN,
    )?;

    let hier_tgt = mint_tgt(
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
    let hier_req = encode(
        &tgs_req(
            hier_tgt,
            &sess,
            realm,
            &user,
            PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "X.SUB.KERBER.TEST"]),
            realm,
            0x1000_0096,
        )
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (hr, hm) = send_both(&cfg, "tgs-alternate-tgs-hierarchical", &hier_req)?;
    if hr.first() != Some(&0x6d) || hm.first() != Some(&0x6d) {
        return Err(format!(
            "tgs-alternate-tgs-hierarchical rust={:02x} mit={:02x} want 0x6d",
            hr.first().unwrap_or(&0),
            hm.first().unwrap_or(&0)
        ));
    }
    let want_hier = "krbtgt/SUB.KERBER.TEST";
    for (leg, raw) in [("rust", hr.as_slice()), ("mit", hm.as_slice())] {
        let TgsRep(rep) = decode::<TgsRep>(raw).map_err(|e| e.to_string())?;
        let ticket_sname = rep.ticket.sname.components_joined();
        if ticket_sname != want_hier {
            return Err(format!(
                "tgs-alternate-tgs-hierarchical {leg} ticket.sname={ticket_sname} want {want_hier}"
            ));
        }
        let usage = KeyUsage::new(ku::TGS_REP_ENC_PART).map_err(|e| e.to_string())?;
        let plain = decrypt(&sess, usage, rep.enc_part.cipher.as_ref())
            .map_err(|e| format!("tgs-alternate-tgs-hierarchical {leg} enc-part: {e}"))?;
        let enc = decode_enc_kdc_rep(&plain).map_err(|e| e.to_string())?;
        let enc_sname = enc.sname.components_joined();
        if enc_sname != want_hier {
            return Err(format!(
                "tgs-alternate-tgs-hierarchical {leg} enc.sname={enc_sname} want {want_hier}"
            ));
        }
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-alternate-tgs-hierarchical","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","sname":"{want_hier}"}}"#
    );

    let from = now.add_seconds(3600).unwrap_or_else(|_| now.clone());
    let renew_pd_part = EncTicketPart {
        flags: TicketFlags::initial_preauth()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::MAY_POSTDATE, true),
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
        endtime: window10.1.clone(),
        renew_till: Some(renew_till.clone()),
        caddr: None,
        authorization_data: None,
    };
    let renew_from = tgs_req_ex(TgsReqParams {
        ticket: seal_ticket(tkt_key, tkt_kvno, realm, &krbtgt_sname, &renew_pd_part)?,
        session: &sess,
        crealm: realm,
        cname: &user,
        sname: krbtgt_sname.clone(),
        realm,
        nonce: 0x1000_0095,
        kdc_options: KdcOptions::none()
            .with_bit(flag_bit::RENEW, true)
            .with_bit(flag_bit::POSTDATED, true),
        additional_tickets: None,
        extra_padata: Vec::new(),
        etypes: etypes.clone(),
        addresses: None,
        from: Some(from.clone()),
        enc_authorization_data: None,
        till: None,
        subkey: None,
        time_offset: 0,
    })
    .map_err(|e| e.to_string())?;
    let renew_from = encode(&renew_from).map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(&cfg, "tgs-renew-postdated-from", &renew_from)?;
    let (_, _, rt, _) = decrypt_tgs(&tr, &sess, tkt_kt)?;
    let (_, _, mt, _) = decrypt_tgs(&tm, &sess, tkt_kt)?;
    let rstart = rt.starttime.as_ref().unwrap_or(&rt.authtime).unix_seconds();
    let mstart = mt.starttime.as_ref().unwrap_or(&mt.authtime).unix_seconds();
    if rstart != from.unix_seconds() || mstart != from.unix_seconds() {
        return Err(format!(
            "tgs-renew-postdated-from start rust={rstart} mit={mstart} want={}",
            from.unix_seconds()
        ));
    }
    if rt.endtime.unix_seconds() != mt.endtime.unix_seconds() {
        return Err(format!(
            "tgs-renew-postdated-from end rust={} mit={}",
            rt.endtime.unix_seconds(),
            mt.endtime.unix_seconds()
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-renew-postdated-from","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","starttime":{},"endtime":{}}}"#,
        rstart,
        rt.endtime.unix_seconds()
    );

    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]);
    ra_cases(&cfg, realm, &user, &host)?;
    fa_cases(&cfg, realm, &user, &host)?;

    println!(r#"{{"event":"diffsend","outcome":"ok","cases":192}}"#);
    Ok(())
}

fn expect_both_tag(cfg: &Cfg, case: &str, req: &[u8], tag: u8) -> Result<(), String> {
    let (rust, mit) = send_both(cfg, case, req)?;
    for (leg, raw) in [("rust", &rust), ("mit", &mit)] {
        if raw.first() != Some(&tag) {
            return Err(format!(
                "{case}: {leg} tag {:02x} want {tag:02x}",
                raw.first().unwrap_or(&0)
            ));
        }
    }
    println!(
        r#"{{"event":"diffsend","case":"{case}","outcome":"ok","rust_tag":"0x{tag:02x}","mit_tag":"0x{tag:02x}"}}"#
    );
    Ok(())
}

fn tgs_rep_nonce(raw: &[u8], session: &ProtocolKey) -> Result<Vec<u8>, String> {
    let rep: TgsRep = decode(raw).map_err(|e| e.to_string())?;
    let usage = KeyUsage::new(ku::TGS_REP_ENC_PART).map_err(|e| e.to_string())?;
    let plain =
        decrypt(session, usage, rep.0.enc_part.cipher.as_ref()).map_err(|e| e.to_string())?;
    let root = ra_root(&plain)?;
    let der::Der::Cons(_, kids) = &root else {
        return Err("enc-part not constructed".into());
    };
    let Some(der::Der::Cons(_, fields)) = kids.first() else {
        return Err("enc-part has no SEQUENCE".into());
    };
    match fields.iter().find(|f| f.tag() == 0xa2) {
        Some(der::Der::Cons(_, inner)) => match inner.first() {
            Some(der::Der::Prim(0x02, content)) => Ok(content.clone()),
            _ => Err("nonce is not an INTEGER".into()),
        },
        _ => Err("enc-part has no nonce".into()),
    }
}

/// B17: refused signedAuthPacks whose reason matches on OpenSSL 3.0 and 3.5.
/// The rest are lab cells.
fn b17_cms_cases(cfg: &Cfg, realm: &str, user: &PrincipalName) -> Result<(), String> {
    let base_cms = |nonce: u32| -> Result<Vec<u8>, String> {
        let pem_path =
            env::var("KERBER_PKINIT_USER").unwrap_or_else(|_| "/tmp/pkinit/user.pem".into());
        let pem = fs::read_to_string(&pem_path)
            .map_err(|e| format!("pkinit user pem {pem_path}: {e}"))?;
        let (cert, leaf) = krb5_types::pkinit::parse_identity_pem(&pem)
            .ok_or_else(|| format!("parse {pem_path}"))?;
        let leaf = krb5_types::pkinit::IdentityKey::p256(leaf);
        let kp = p256_generate().map_err(|e| e.to_string())?;
        let req = as_req(user.clone(), realm, nonce, None).map_err(|e| e.to_string())?;
        let body = encode(&req.0.req_body).map_err(|e| e.to_string())?;
        let mut h = Sha1::new();
        h.update(&body);
        let pa = pa_pk_as_req_signed(&kp.public, &cert, &leaf, nonce, &h.finalize(), None)
            .map_err(|e| e.to_string())?;
        let req = decode::<krb5_types::pkinit::PaPkAsReq>(&pa.padata_value)
            .map_err(|e| format!("decode PaPkAsReq: {e}"))?;
        Ok(req.signed_auth_pack.as_ref().to_vec())
    };
    let as_with = |nonce: u32, cms: Vec<u8>| -> Result<Vec<u8>, String> {
        let mut req = as_req(user.clone(), realm, nonce, None).map_err(|e| e.to_string())?;
        let pa_req = krb5_types::pkinit::PaPkAsReq {
            signed_auth_pack: cms.into(),
            trusted_certifiers: None,
            kdc_pk_id: None,
        };
        req.0.padata = Some(vec![PaData {
            padata_type: pa::PK_AS_REQ,
            padata_value: encode(&pa_req).map_err(|e| e.to_string())?.into(),
        }]);
        encode(&req).map_err(|e| e.to_string())
    };
    let edit_sd = |cms: &[u8], f: &dyn Fn(&mut Vec<der::Der>)| -> Result<Vec<u8>, String> {
        let root = ra_root(cms)?;
        let der::Der::Cons(_, ci) = &root else {
            return Err("CMS not a SEQUENCE".into());
        };
        let der::Der::Cons(_, ex) = ci.get(1).ok_or("no content [0]")? else {
            return Err("content [0] not constructed".into());
        };
        let der::Der::Cons(sd_tag, sd) = ex.first().ok_or("no SignedData")? else {
            return Err("SignedData not a SEQUENCE".into());
        };
        let mut kids = sd.clone();
        f(&mut kids);
        let new_sd = der::Der::Cons(*sd_tag, kids);
        Ok(der::edit(&root, &[1, 0], Some(&new_sd)).bytes())
    };
    let set_sig = |cms: &[u8], sig: Vec<u8>| -> Result<Vec<u8>, String> {
        edit_sd(cms, &move |kids: &mut Vec<der::Der>| {
            if let Some(der::Der::Cons(_, infos)) = kids.iter_mut().rev().find(|k| k.tag() == 0x31)
                && let Some(der::Der::Cons(_, si)) = infos.first_mut()
                && let Some(s) = si.iter_mut().find(|k| k.tag() == 0x04)
            {
                *s = der::Der::Prim(0x04, sig.clone());
            }
        })
    };

    expect_error(
        cfg,
        "pkinit-cms-too-small",
        &as_with(0x1000_0220, vec![])?,
        err::PREAUTH_FAILED,
    )?;
    expect_error(
        cfg,
        "pkinit-cms-header-too-long",
        &as_with(0x1000_0221, vec![0x30])?,
        err::PREAUTH_FAILED,
    )?;
    expect_error(
        cfg,
        "pkinit-cms-too-long",
        &as_with(0x1000_0222, vec![0x30, 0x05, 0x06])?,
        err::PREAUTH_FAILED,
    )?;
    expect_error(
        cfg,
        "pkinit-cms-wrong-tag",
        &as_with(0x1000_0223, vec![0x30, 0x03, 0x02, 0x01, 0x00])?,
        err::PREAUTH_FAILED,
    )?;
    expect_error(
        cfg,
        "pkinit-cms-field-missing",
        &as_with(0x1000_0224, vec![0x30, 0x00])?,
        err::PREAUTH_FAILED,
    )?;

    let sd_trailing = edit_sd(&base_cms(0x1000_022a)?, &|kids: &mut Vec<der::Der>| {
        kids.push(der::Der::Prim(0x05, Vec::new()));
    })?;
    expect_error(
        cfg,
        "pkinit-cms-signeddata-trailing",
        &as_with(0x1000_022a, sd_trailing)?,
        err::PREAUTH_FAILED,
    )?;
    let algid_tag = edit_sd(&base_cms(0x1000_022b)?, &|kids: &mut Vec<der::Der>| {
        if let Some(der::Der::Cons(_, algs)) = kids.iter_mut().find(|k| k.tag() == 0x31)
            && let Some(der::Der::Cons(_, alg)) = algs.first_mut()
            && let Some(der::Der::Prim(tag, _)) = alg.first_mut()
        {
            *tag = 0x05;
        }
    })?;
    expect_error(
        cfg,
        "pkinit-cms-algid-wrong-tag",
        &as_with(0x1000_022b, algid_tag)?,
        err::PREAUTH_FAILED,
    )?;

    // oerr() cases first; krb5_set_error_message refusals last, so none leaves a stale reason.
    let not_der = set_sig(
        &base_cms(0x1000_0228)?,
        vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
    )?;
    expect_error(
        cfg,
        "pkinit-sig-not-der",
        &as_with(0x1000_0228, not_der)?,
        err::DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED,
    )?;
    let r_zero = set_sig(
        &base_cms(0x1000_0229)?,
        vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x05],
    )?;
    expect_error(
        cfg,
        "pkinit-sig-r-zero",
        &as_with(0x1000_0229, r_zero)?,
        err::DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED,
    )?;

    let wrong_oid = vec![
        0x30, 0x0f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x02,
        0x04, 0x00,
    ];
    expect_error(
        cfg,
        "pkinit-cms-wrong-oid",
        &as_with(0x1000_0225, wrong_oid)?,
        err::PREAUTH_FAILED,
    )?;

    let not_octets = vec![
        0x30, 0x0d, 0x06, 0x07, 0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01, 0xa0, 0x02, 0x05, 0x00,
    ];
    expect_error(
        cfg,
        "pkinit-authpack-not-octet-string",
        &as_with(0x1000_0226, not_octets)?,
        err::PREAUTH_FAILED,
    )?;

    let no_cert = edit_sd(&base_cms(0x1000_0227)?, &|kids: &mut Vec<der::Der>| {
        kids.retain(|k| k.tag() != 0xa0);
    })?;
    expect_error(
        cfg,
        "pkinit-cms-no-signer-cert",
        &as_with(0x1000_0227, no_cert)?,
        err::PREAUTH_FAILED,
    )?;

    Ok(())
}

/// Seven ECDSA faults. OpenSSL 3.5 says `provider signature failure`,
/// 3.0 `verification failure`; CI gates code 80.
fn b17_lab_cases(cfg: &Cfg, realm: &str, user: &PrincipalName) -> Result<(), String> {
    let labuser = match env::var("KERBER_DIFF_B17_PRINC") {
        Ok(p) => PrincipalName::new(PrincipalName::NT_PRINCIPAL, [p.as_str()]),
        Err(_) => user.clone(),
    };
    let user = &labuser;
    let base_cms = |nonce: u32| -> Result<Vec<u8>, String> {
        let pem_path =
            env::var("KERBER_PKINIT_USER").unwrap_or_else(|_| "/tmp/pkinit/user.pem".into());
        let pem = fs::read_to_string(&pem_path)
            .map_err(|e| format!("pkinit user pem {pem_path}: {e}"))?;
        let (cert, leaf) = krb5_types::pkinit::parse_identity_pem(&pem)
            .ok_or_else(|| format!("parse {pem_path}"))?;
        let leaf = krb5_types::pkinit::IdentityKey::p256(leaf);
        let kp = p256_generate().map_err(|e| e.to_string())?;
        let req = as_req(user.clone(), realm, nonce, None).map_err(|e| e.to_string())?;
        let body = encode(&req.0.req_body).map_err(|e| e.to_string())?;
        let mut h = Sha1::new();
        h.update(&body);
        let pa = pa_pk_as_req_signed(&kp.public, &cert, &leaf, nonce, &h.finalize(), None)
            .map_err(|e| e.to_string())?;
        let req = decode::<krb5_types::pkinit::PaPkAsReq>(&pa.padata_value)
            .map_err(|e| format!("decode PaPkAsReq: {e}"))?;
        Ok(req.signed_auth_pack.as_ref().to_vec())
    };
    let as_with = |nonce: u32, cms: Vec<u8>| -> Result<Vec<u8>, String> {
        let mut req = as_req(user.clone(), realm, nonce, None).map_err(|e| e.to_string())?;
        let pa_req = krb5_types::pkinit::PaPkAsReq {
            signed_auth_pack: cms.into(),
            trusted_certifiers: None,
            kdc_pk_id: None,
        };
        req.0.padata = Some(vec![PaData {
            padata_type: pa::PK_AS_REQ,
            padata_value: encode(&pa_req).map_err(|e| e.to_string())?.into(),
        }]);
        encode(&req).map_err(|e| e.to_string())
    };
    let edit_sd = |cms: &[u8], f: &dyn Fn(&mut Vec<der::Der>)| -> Result<Vec<u8>, String> {
        let root = ra_root(cms)?;
        let new_sd = {
            let sd = der::at(&root, &[1, 0]).ok_or("no SignedData")?;
            let der::Der::Cons(sd_tag, sd) = sd else {
                return Err("SignedData not a SEQUENCE".into());
            };
            let mut kids = sd.clone();
            f(&mut kids);
            der::Der::Cons(*sd_tag, kids)
        };
        Ok(der::edit(&root, &[1, 0], Some(&new_sd)).bytes())
    };
    let get_sig = |cms: &[u8]| -> Result<Vec<u8>, String> {
        let root = ra_root(cms)?;
        let der::Der::Cons(_, sd) = der::at(&root, &[1, 0]).ok_or("no SignedData")? else {
            return Err("SignedData not a SEQUENCE".into());
        };
        let Some(der::Der::Cons(_, infos)) = sd.iter().rev().find(|k| k.tag() == 0x31) else {
            return Err("no signerInfos".into());
        };
        let Some(der::Der::Cons(_, si)) = infos.first() else {
            return Err("no signerInfo".into());
        };
        match si.iter().find(|k| k.tag() == 0x04) {
            Some(der::Der::Prim(_, sig)) => Ok(sig.clone()),
            _ => Err("no signature".into()),
        }
    };
    let set_sig = |cms: &[u8], sig: Vec<u8>| -> Result<Vec<u8>, String> {
        edit_sd(cms, &move |kids: &mut Vec<der::Der>| {
            if let Some(der::Der::Cons(_, infos)) = kids.iter_mut().rev().find(|k| k.tag() == 0x31)
                && let Some(der::Der::Cons(_, si)) = infos.first_mut()
                && let Some(s) = si.iter_mut().find(|k| k.tag() == 0x04)
            {
                *s = der::Der::Prim(0x04, sig.clone());
            }
        })
    };
    let drop_attrs = |cms: &[u8]| -> Result<Vec<u8>, String> {
        edit_sd(cms, &|kids: &mut Vec<der::Der>| {
            if let Some(der::Der::Cons(_, infos)) = kids.iter_mut().rev().find(|k| k.tag() == 0x31)
                && let Some(der::Der::Cons(_, si)) = infos.first_mut()
            {
                si.retain(|k| k.tag() != 0xa0);
            }
        })
    };
    let flip = |mut sig: Vec<u8>| {
        if let Some(b) = sig.last_mut() {
            *b ^= 0x01;
        }
        sig
    };
    let trail = |mut sig: Vec<u8>| {
        sig.push(0x00);
        sig
    };
    // A short ECDSA-Sig-Value (r = s = 1): valid DER, not the signature.
    let truncated = || vec![0x30u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

    let mut reqs: Vec<(&str, Vec<u8>)> = Vec::new();
    let n = 0x1000_0230;
    reqs.push((
        "pkinit-provider-attrs-empty",
        as_with(n, set_sig(&base_cms(n)?, Vec::new())?)?,
    ));
    let n = 0x1000_0231;
    let base = base_cms(n)?;
    let flipped = flip(get_sig(&base)?);
    reqs.push((
        "pkinit-provider-attrs-bit-flip",
        as_with(n, set_sig(&base, flipped)?)?,
    ));
    let n = 0x1000_0232;
    reqs.push((
        "pkinit-provider-attrs-truncated",
        as_with(n, set_sig(&base_cms(n)?, truncated())?)?,
    ));
    let n = 0x1000_0233;
    reqs.push((
        "pkinit-provider-noattrs-empty",
        as_with(n, set_sig(&drop_attrs(&base_cms(n)?)?, Vec::new())?)?,
    ));
    let n = 0x1000_0234;
    let base = drop_attrs(&base_cms(n)?)?;
    let trailing = trail(get_sig(&base)?);
    reqs.push((
        "pkinit-provider-noattrs-non-der",
        as_with(n, set_sig(&base, trailing)?)?,
    ));
    let n = 0x1000_0235;
    let base = drop_attrs(&base_cms(n)?)?;
    let flipped = flip(get_sig(&base)?);
    reqs.push((
        "pkinit-provider-noattrs-bit-flip",
        as_with(n, set_sig(&base, flipped)?)?,
    ));
    let n = 0x1000_0236;
    reqs.push((
        "pkinit-provider-noattrs-truncated",
        as_with(n, set_sig(&drop_attrs(&base_cms(n)?)?, truncated())?)?,
    ));

    let mut ok = 0;
    for (case, req) in &reqs {
        b17_lab_send(cfg, case, req)?;
        ok += 1;
    }
    println!("b17lab cases={} ok={ok}", reqs.len());
    Ok(())
}

fn b17_lab_send(cfg: &Cfg, case: &str, req: &[u8]) -> Result<(), String> {
    write_der(&cfg.out, &format!("{case}.req.der"), req);
    let raw = exchange_on_tcp(&cfg.rust, req).map_err(|e| format!("{case}: send: {e}"))?;
    if raw.first() != Some(&0x7e) {
        return Err(format!(
            "{case}: tag {:02x} want 0x7e",
            raw.first().unwrap_or(&0)
        ));
    }
    let ke: KrbError = decode(&raw).map_err(|e| format!("{case} decode: {e}"))?;
    if ke.error_code != err::DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED {
        return Err(format!("{case}: error_code {} want 80", ke.error_code));
    }
    write_der(&cfg.out, &format!("{case}.rep.der"), &raw);
    let etext = ke
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok())
        .unwrap_or("");
    println!(
        r#"{{"event":"diffsend","case":"{case}","outcome":"ok","error_code":{},"e_text":"{etext}","req_sha1":"{}"}}"#,
        ke.error_code,
        sha1_hex(req)
    );
    Ok(())
}

fn ra_root(der: &[u8]) -> Result<der::Der, String> {
    der::der_parse(der)
        .and_then(|mut v| (v.len() == 1).then(|| v.remove(0)))
        .ok_or_else(|| "not one DER element".to_string())
}

fn ra_body_path(root: &der::Der) -> Result<Vec<usize>, String> {
    let der::Der::Cons(_, kids) = root else {
        return Err("KDC-REQ not constructed".into());
    };
    let Some(der::Der::Cons(0x30, fields)) = kids.first() else {
        return Err("KDC-REQ has no SEQUENCE".into());
    };
    let i = fields
        .iter()
        .position(|f| f.tag() == 0xa4)
        .ok_or("KDC-REQ has no req-body")?;
    Ok(vec![0, i, 0])
}

/// The RA cases: a KDC-REQ, or a PA-TGS-REQ authenticator, with a field MIT's decoder refuses,
fn ra_cases(
    cfg: &Cfg,
    realm: &str,
    user: &PrincipalName,
    host: &PrincipalName,
) -> Result<(), String> {
    // An AS-REQ whose KDC-REQ-BODY addresses [9] holds a SET where a SEQUENCE OF belongs.
    let mut req = as_req(user.clone(), realm, 0x1000_0201, None).map_err(|e| e.to_string())?;
    req.0.req_body.addresses = Some(vec![HostAddress {
        addr_type: 2,
        address: vec![127, 0, 0, 1].into(),
    }]);
    let root = ra_root(&encode(&req).map_err(|e| e.to_string())?)?;
    let body = ra_body_path(&root)?;
    let broken = der::all_breaks(&root)
        .into_iter()
        .find(|(place, _)| {
            place.starts_with(&der::path_name(&root, &body)) && place.ends_with(":a9/tag")
        })
        .ok_or("no addresses field to break")?;
    expect_drop(cfg, "as-req-malformed-addresses", &broken.1.bytes())?;

    // An AS-REQ whose KDC-REQ-BODY ends with a field no version of KDC-REQ-BODY has, [12].
    let req = as_req(user.clone(), realm, 0x1000_0202, None).map_err(|e| e.to_string())?;
    let root = ra_root(&encode(&req).map_err(|e| e.to_string())?)?;
    let body = ra_body_path(&root)?;
    let Some(der::Der::Cons(tag, mut fields)) = der::at(&root, &body).cloned() else {
        return Err("no KDC-REQ-BODY".into());
    };
    fields.push(der::Der::Cons(0xac, vec![der::Der::Prim(0x02, vec![0])]));
    let req = der::edit(&root, &body, Some(&der::Der::Cons(tag, fields))).bytes();
    // MIT: `decode_sequence` (lib/krb5/asn.1/asn1_encode.c:1399-1455)
    expect_both_tag(cfg, "as-req-trailing-body-field", &req, 0x6b)?;

    let tkt_kt = cfg.krbtgt.as_ref().ok_or("KERBER_KRBTGT_KEYTAB required")?;
    let (tkt_key, tkt_kvno) = keytab_for(tkt_kt, 20)?;
    let now = KerberosTime::now();
    let window = (
        now.clone(),
        now.add_hours(10).unwrap_or_else(|_| now.clone()),
    );
    let tgs_for = |nonce: u32, sess: &ProtocolKey| -> Result<krb5_types::TgsReq, String> {
        let tgt = mint_tgt(
            tkt_key,
            tkt_kvno,
            user,
            realm,
            &PrincipalName::krbtgt(realm),
            sess,
            window.clone(),
            TicketFlags::initial_preauth().with_bit(krb5_types::flag_bit::FORWARDABLE, true),
        )?;
        tgs_req(tgt, sess, realm, user, host.clone(), realm, nonce).map_err(|e| e.to_string())
    };

    let sess = random_session(EncryptionType::Aes256CtsHmacSha196)?;
    let req = encode(&tgs_for(0x8000_0000, &sess)?).map_err(|e| e.to_string())?;
    let (tr, tm) = send_both(cfg, "tgs-req-nonce-int32-min", &req)?;
    let svc = cfg.host.as_ref().ok_or("KERBER_HOST_KEYTAB required")?;
    let (rr, re, rt, _) = decrypt_tgs(&tr, &sess, svc)?;
    let (mr, me, mt, _) = decrypt_tgs(&tm, &sess, svc)?;
    compare_stable_rep(&rr, &re, &rt, &mr, &me, &mt)
        .map_err(|e| format!("tgs-req-nonce-int32-min: {e}"))?;
    let (rn, mn) = (tgs_rep_nonce(&tr, &sess)?, tgs_rep_nonce(&tm, &sess)?);
    if rn != [0x80, 0, 0, 0] || mn != [0x80, 0, 0, 0] {
        return Err(format!(
            "tgs-req-nonce-int32-min: reply nonce rust={rn:02x?} mit={mn:02x?} want 80 00 00 00"
        ));
    }
    println!(
        r#"{{"event":"diffsend","case":"tgs-req-nonce-int32-min","outcome":"ok","rust_tag":"0x6d","mit_tag":"0x6d","nonce":"80000000"}}"#
    );

    // A TGS-REQ whose PA-TGS-REQ authenticator is rewritten by `authenticator`, then re-encrypted.
    let with_authenticator = |nonce: u32,
                              sess: &ProtocolKey,
                              f: &dyn Fn(der::Der) -> Result<der::Der, String>|
     -> Result<Vec<u8>, String> {
        let mut req = tgs_for(nonce, sess)?;
        let padata = req.0.padata.as_mut().ok_or("no padata")?;
        let pa_tgs = padata
            .iter_mut()
            .find(|x| x.padata_type == pa::TGS_REQ)
            .ok_or("no PA-TGS-REQ")?;
        let mut ap: ApReq = decode(pa_tgs.padata_value.as_ref()).map_err(|e| e.to_string())?;
        let usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).map_err(|e| e.to_string())?;
        let plain =
            decrypt(sess, usage, ap.authenticator.cipher.as_ref()).map_err(|e| e.to_string())?;
        let mut authenticator: krb5_types::Authenticator =
            decode(&plain).map_err(|e| e.to_string())?;
        authenticator.subkey = Some(EncryptionKey {
            keytype: sess.etype().to_iana(),
            keyvalue: vec![0x52u8; 32].into(),
        });
        let root = ra_root(&encode(&authenticator).map_err(|e| e.to_string())?)?;
        let rewritten = f(root)?.bytes();
        ap.authenticator.cipher = encrypt(sess, usage, &rewritten)
            .map_err(|e| e.to_string())?
            .into();
        pa_tgs.padata_value = encode(&ap).map_err(|e| e.to_string())?.into();
        encode(&req).map_err(|e| e.to_string())
    };

    // Its subkey [6] holds a SET where an EncryptionKey (a SEQUENCE) belongs.
    let req = with_authenticator(0x1000_0204, &sess, &|root| {
        der::all_breaks(&root)
            .into_iter()
            .find(|(place, _)| place.ends_with(":a6/tag"))
            .map(|(_, d)| d)
            .ok_or_else(|| "no subkey to break".to_string())
    })?;
    // MIT: `errcode_to_protocol` (kdc/kdc_util.c:690-698)
    expect_error(
        cfg,
        "tgs-authenticator-malformed-subkey",
        &req,
        err::GENERIC,
    )?;

    // It ends with a field no version of Authenticator has, [9].
    let req = with_authenticator(0x1000_0205, &sess, &|root| {
        let der::Der::Cons(app, kids) = root else {
            return Err("authenticator not constructed".into());
        };
        let Some(der::Der::Cons(seq, mut fields)) = kids.into_iter().next() else {
            return Err("authenticator has no SEQUENCE".into());
        };
        fields.push(der::Der::Cons(0xa9, vec![der::Der::Prim(0x02, vec![0])]));
        Ok(der::Der::Cons(app, vec![der::Der::Cons(seq, fields)]))
    })?;
    expect_tgs_rep(cfg, "tgs-authenticator-trailing-field", &req)?;

    // Its crealm [1] has octets that are not ASCII (UTF-8 `KERBER.TEß`).
    let req = with_authenticator(0x1000_0206, &sess, &|root| {
        let place = der::all_breaks(&root)
            .into_iter()
            .find(|(place, _)| place.ends_with(":a1/tag"))
            .map(|(p, _)| p)
            .ok_or("no crealm")?;
        let path: Vec<usize> = place
            .split('.')
            .skip(1)
            .filter_map(|step| step.split(':').next()?.parse().ok())
            .collect();
        let realm = der::Der::Cons(
            0xa1,
            vec![der::Der::Prim(0x1b, "KERBER.TEß".as_bytes().to_vec())],
        );
        Ok(der::edit(&root, &path, Some(&realm)))
    })?;
    expect_error(cfg, "tgs-authenticator-crealm-octets", &req, err::BADMATCH)?;

    // PA-SPAKE holds an element no alternative takes, [4].
    // MIT: `decode_cntype` (lib/krb5/asn.1/asn1_encode.c:1245-1300)
    // MIT: `spake_verify` (plugins/preauth/spake/spake_kdc.c:501-539)
    let spake = PaData {
        padata_type: pa::SPAKE,
        padata_value: vec![0xa4, 0x02, 0x30, 0x00].into(),
    };
    let req =
        as_req(user.clone(), realm, 0x1000_0207, Some(vec![spake])).map_err(|e| e.to_string())?;
    expect_error(
        cfg,
        "as-spake-unknown-choice",
        &encode(&req).map_err(|e| e.to_string())?,
        err::PREAUTH_FAILED,
    )?;

    let req = with_authenticator(0x1000_0208, &sess, &|root| {
        let mut authenticator: krb5_types::Authenticator =
            decode(&root.bytes()).map_err(|e| e.to_string())?;
        authenticator.cusec = krb5_types::Microseconds(1_000_000);
        ra_root(&encode(&authenticator).map_err(|e| e.to_string())?)
    })?;
    expect_tgs_rep(cfg, "tgs-authenticator-cusec-out-of-range", &req)?;

    // PA-ENC-TIMESTAMP pausec past 999999.
    // MIT: `enc_ts_verify` (kdc/kdc_preauth_encts.c:46-119)
    let ukey = client_key(18, &cfg.user_pw, user, realm)?;
    let ts = krb5_types::PaEncTsEnc {
        patimestamp: KerberosTime::now(),
        pausec: Some(krb5_types::Microseconds(1_000_000)),
    };
    let usage = KeyUsage::new(ku::PA_ENC_TIMESTAMP).map_err(|e| e.to_string())?;
    let ts_der = encode(&ts).map_err(|e| e.to_string())?;
    let enc = EncryptedData {
        etype: 18,
        kvno: None,
        cipher: encrypt(&ukey, usage, &ts_der)
            .map_err(|e| e.to_string())?
            .into(),
    };
    let pa_ts = PaData {
        padata_type: pa::ENC_TIMESTAMP,
        padata_value: encode(&enc).map_err(|e| e.to_string())?.into(),
    };
    let req =
        as_req(user.clone(), realm, 0x1000_0209, Some(vec![pa_ts])).map_err(|e| e.to_string())?;
    let _ = expect_as_ok(
        cfg,
        "as-enc-timestamp-pausec-out-of-range",
        &encode(&req).map_err(|e| e.to_string())?,
        user,
    )?;

    // Authenticator EncryptedData says aes128 for an aes256 session key.
    // MIT: `krb5_k_decrypt` (lib/crypto/krb/decrypt.c:30-85)
    let mut tgs = tgs_for(0x1000_020a, &sess)?;
    let padata = tgs.0.padata.as_mut().ok_or("no padata")?;
    let pa_tgs = padata
        .iter_mut()
        .find(|x| x.padata_type == pa::TGS_REQ)
        .ok_or("no PA-TGS-REQ")?;
    let mut ap: ApReq = decode(pa_tgs.padata_value.as_ref()).map_err(|e| e.to_string())?;
    ap.authenticator.etype = 17;
    pa_tgs.padata_value = encode(&ap).map_err(|e| e.to_string())?.into();
    expect_error(
        cfg,
        "tgs-authenticator-etype-mismatch",
        &encode(&tgs).map_err(|e| e.to_string())?,
        err::GENERIC,
    )?;

    // enc-fast-req says aes128 for an aes256 armor key.
    // MIT: `kdc_find_fast` (kdc/fast_util.c:120-247)
    let armor_sess = random_session(EncryptionType::Aes256CtsHmacSha196)?;
    let armor_sub = random_session(EncryptionType::Aes256CtsHmacSha196)?;
    let armor_tkt = mint_tgt(
        tkt_key,
        tkt_kvno,
        user,
        realm,
        &PrincipalName::krbtgt(realm),
        &armor_sess,
        window.clone(),
        TicketFlags::initial_preauth(),
    )?;
    let armor_ap = build_fast_armor(
        armor_tkt,
        &armor_sess,
        &krb5_types::try_ascii(realm).map_err(|e| e.to_string())?,
        user,
        Some(&armor_sub),
    )
    .map_err(|e| e.to_string())?;
    let akey = armor_key(&armor_sess, Some(&armor_sub)).map_err(|e| e.to_string())?;
    let mut fast_req = as_req(user.clone(), realm, 0x1000_020b, None).map_err(|e| e.to_string())?;
    attach_fast(&mut fast_req, &armor_ap, &akey, Vec::new()).map_err(|e| e.to_string())?;
    let fx = fast_req
        .0
        .padata
        .as_mut()
        .and_then(|p| p.iter_mut().find(|x| x.padata_type == pa::FX_FAST))
        .ok_or("no PA-FX-FAST")?;
    let krb5_types::fast::PaFxFast::ArmoredData(mut armored) =
        decode(fx.padata_value.as_ref()).map_err(|e| e.to_string())?;
    armored.enc_fast_req.etype = 17;
    fx.padata_value = encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
        .map_err(|e| e.to_string())?
        .into();
    expect_error(
        cfg,
        "as-fast-armored-data-etype-mismatch",
        &encode(&fast_req).map_err(|e| e.to_string())?,
        err::GENERIC,
    )?;
    Ok(())
}

fn fa_edit(
    req: &mut krb5_types::AsReq,
    edit: impl FnOnce(&mut krb5_types::fast::KrbFastArmoredReq),
) -> Result<(), String> {
    let fx = req
        .0
        .padata
        .as_mut()
        .and_then(|p| p.iter_mut().find(|x| x.padata_type == pa::FX_FAST))
        .ok_or("no PA-FX-FAST")?;
    let krb5_types::fast::PaFxFast::ArmoredData(mut armored) =
        decode(fx.padata_value.as_ref()).map_err(|e| e.to_string())?;
    edit(&mut armored);
    fx.padata_value = encode(&krb5_types::fast::PaFxFast::ArmoredData(armored))
        .map_err(|e| e.to_string())?
        .into();
    Ok(())
}

// MIT: `armor_ap_request` (kdc/fast_util.c:35-90)
// MIT: `rd_req_decoded_opt` (lib/krb5/krb/rd_req_dec.c:472-787)
// MIT: `kdc_find_fast` (kdc/fast_util.c:126-247)
fn fa_cases(
    cfg: &Cfg,
    realm: &str,
    user: &PrincipalName,
    host: &PrincipalName,
) -> Result<(), String> {
    let tkt_kt = cfg.krbtgt.as_ref().ok_or("KERBER_KRBTGT_KEYTAB required")?;
    let (tkt_key, tkt_kvno) = keytab_for(tkt_kt, 20)?;
    let svc = cfg.host.as_ref().ok_or("KERBER_HOST_KEYTAB required")?;
    let (hkey, hkvno) = keytab_for(svc, 20)?;
    let crealm = krb5_types::try_ascii(realm).map_err(|e| e.to_string())?;
    let krbtgt = PrincipalName::krbtgt(realm);
    let pauser = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pauser"]);
    let now = KerberosTime::now();
    let at = |secs: i64| now.add_seconds(secs).unwrap_or_else(|_| now.clone());
    let sess = random_session(EncryptionType::Aes256CtsHmacSha196)?;
    let sub = random_session(EncryptionType::Aes256CtsHmacSha196)?;
    let wrong = random_session(EncryptionType::Aes256CtsHmacSha196)?;
    let akey = armor_key(&sess, Some(&sub)).map_err(|e| e.to_string())?;
    let part = EncTicketPart {
        flags: TicketFlags::initial_preauth(),
        key: EncryptionKey {
            keytype: sess.etype().to_iana(),
            keyvalue: sess.as_bytes().to_vec().into(),
        },
        crealm: crealm.clone(),
        cname: user.clone(),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: Vec::<u8>::new().into(),
        },
        authtime: now.clone(),
        starttime: Some(now.clone()),
        endtime: at(36_000),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let tgt = |p: &EncTicketPart| seal_ticket(tkt_key, tkt_kvno, realm, &krbtgt, p);
    let ap = |t: Ticket, cname: &PrincipalName| {
        build_fast_armor(t, &sess, &crealm, cname, Some(&sub)).map_err(|e| e.to_string())
    };
    let expect_fa = |cfg: &Cfg,
                     case: &str,
                     nonce: u32,
                     client: &PrincipalName,
                     armor: &ApReq,
                     edit: Option<&dyn Fn(&mut krb5_types::fast::KrbFastArmoredReq)>,
                     code: i32|
     -> Result<(), String> {
        let mut req = as_req(client.clone(), realm, nonce, None).map_err(|e| e.to_string())?;
        attach_fast(&mut req, armor, &akey, Vec::new()).map_err(|e| e.to_string())?;
        if let Some(edit) = edit {
            fa_edit(&mut req, edit)?;
        }
        expect_error(cfg, case, &encode(&req).map_err(|e| e.to_string())?, code)
    };
    let good = ap(tgt(&part)?, user)?;

    expect_fa(
        cfg,
        "fa-armor-badmatch",
        0x1000_0301,
        user,
        &ap(tgt(&part)?, &pauser)?,
        None,
        err::BADMATCH,
    )?;
    let mut invalid = part.clone();
    invalid.flags = invalid.flags.with_bit(flag_bit::INVALID, true);
    expect_fa(
        cfg,
        "fa-armor-invalid",
        0x1000_0302,
        user,
        &ap(tgt(&invalid)?, user)?,
        None,
        err::GENERIC,
    )?;
    // Expired inside the skew: the armor holds; pauser gets 25.
    let mut stale = part.clone();
    stale.authtime = at(-7200);
    stale.starttime = Some(at(-7200));
    stale.endtime = at(-60);
    expect_fa(
        cfg,
        "fa-armor-expired-in-skew",
        0x1000_0303,
        &pauser,
        &ap(tgt(&stale)?, user)?,
        None,
        err::PREAUTH_REQUIRED,
    )?;
    let mut odd = part.clone();
    odd.key.keytype = 99;
    expect_fa(
        cfg,
        "fa-armor-session-etype",
        0x1000_0304,
        user,
        &ap(tgt(&odd)?, user)?,
        None,
        err::GENERIC,
    )?;
    expect_fa(
        cfg,
        "fa-armor-not-ap-req",
        0x1000_0305,
        user,
        &good,
        Some(&|w| {
            if let Some(a) = w.armor.as_mut() {
                a.armor_value = vec![0x30, 0x00].into();
            }
        }),
        err::MSG_TYPE,
    )?;
    let mut short_key = part.clone();
    short_key.key.keyvalue = vec![0x5a; 16].into();
    expect_fa(
        cfg,
        "fa-armor-session-key-size",
        0x1000_0316,
        user,
        &ap(tgt(&short_key)?, user)?,
        None,
        err::GENERIC,
    )?;
    let mut short_sub = good.clone();
    let sub_usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR).map_err(|e| e.to_string())?;
    let sub_plain = decrypt(&sess, sub_usage, short_sub.authenticator.cipher.as_ref())
        .map_err(|e| e.to_string())?;
    let mut sub_auth: krb5_types::Authenticator = decode(&sub_plain).map_err(|e| e.to_string())?;
    if let Some(k) = sub_auth.subkey.as_mut() {
        k.keyvalue = vec![0x5a; 16].into();
    }
    short_sub.authenticator.cipher = encrypt(
        &sess,
        sub_usage,
        &encode(&sub_auth).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?
    .into();
    expect_fa(
        cfg,
        "fa-armor-subkey-size",
        0x1000_0317,
        user,
        &short_sub,
        None,
        err::GENERIC,
    )?;
    let mut v4 = good.clone();
    v4.pvno = 4;
    expect_fa(
        cfg,
        "fa-armor-pvno",
        0x1000_0306,
        user,
        &v4,
        None,
        err::BAD_PVNO,
    )?;
    let nosvr = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "nosvr.kerber.test"]);
    expect_fa(
        cfg,
        "fa-armor-disallow-svr",
        0x1000_0307,
        user,
        &ap(seal_ticket(tkt_key, tkt_kvno, realm, &nosvr, &part)?, user)?,
        None,
        err::NOT_US,
    )?;
    let mut short = tgt(&part)?;
    short.enc_part.cipher = vec![0u8; 5].into();
    expect_fa(
        cfg,
        "fa-armor-ticket-short",
        0x1000_0308,
        user,
        &ap(short, user)?,
        None,
        err::GENERIC,
    )?;
    let usage = KeyUsage::new(ku::TICKET).map_err(|e| e.to_string())?;
    let mut junk = tgt(&part)?;
    junk.enc_part.cipher = encrypt(tkt_key, usage, b"not a ticket")
        .map_err(|e| e.to_string())?
        .into();
    expect_fa(
        cfg,
        "fa-armor-ticket-junk",
        0x1000_0309,
        user,
        &ap(junk, user)?,
        None,
        err::GENERIC,
    )?;
    let mut via = part.clone();
    via.transited.contents = b"OTHER.TEST".to_vec().into();
    expect_fa(
        cfg,
        "fa-armor-transited",
        0x1000_030a,
        user,
        &ap(tgt(&via)?, user)?,
        None,
        err::GENERIC,
    )?;
    // A foreign client realm: this hop is off its realm tree.
    let other_realm = krb5_types::try_ascii("OTHER.TEST").map_err(|e| e.to_string())?;
    let mut far = via.clone();
    far.crealm = other_realm.clone();
    far.transited.contents = b"SOMEWHERE.ELSE".to_vec().into();
    let far_ap = build_fast_armor(tgt(&far)?, &sess, &other_realm, user, Some(&sub))
        .map_err(|e| e.to_string())?;
    expect_fa(
        cfg,
        "fa-armor-transited-cross",
        0x1000_031a,
        user,
        &far_ap,
        None,
        err::ILL_CR_TKT,
    )?;
    // A NUL-led list is not checked; pauser gets 25.
    let mut nul = part.clone();
    nul.transited.contents = b"\0OTHER.TEST".to_vec().into();
    expect_fa(
        cfg,
        "fa-armor-transited-nul",
        0x1000_0321,
        &pauser,
        &ap(tgt(&nul)?, user)?,
        None,
        err::PREAUTH_REQUIRED,
    )?;
    let mut srv = far.clone();
    srv.transited.contents = b"KERBER.TEST".to_vec().into();
    let srv_ap = build_fast_armor(tgt(&srv)?, &sess, &other_realm, user, Some(&sub))
        .map_err(|e| e.to_string())?;
    expect_fa(
        cfg,
        "fa-armor-transited-srv",
        0x1000_0328,
        &pauser,
        &srv_ap,
        None,
        err::ILL_CR_TKT,
    )?;
    let mut kv = tgt(&part)?;
    kv.enc_part.kvno = Some(99);
    expect_fa(
        cfg,
        "fa-armor-kvno",
        0x1000_030b,
        user,
        &ap(kv, user)?,
        None,
        err::BADKEYVER,
    )?;
    let other = random_session(EncryptionType::Aes256CtsHmacSha384192)?;
    expect_fa(
        cfg,
        "fa-armor-ticket-key",
        0x1000_030c,
        user,
        &ap(seal_ticket(&other, tkt_kvno, realm, &krbtgt, &part)?, user)?,
        None,
        err::BAD_INTEGRITY,
    )?;
    let mut early = part.clone();
    early.starttime = Some(at(3600));
    expect_fa(
        cfg,
        "fa-armor-nyv",
        0x1000_030d,
        user,
        &ap(tgt(&early)?, user)?,
        None,
        err::TKT_NYV,
    )?;
    let mut old = stale.clone();
    old.endtime = at(-3600);
    expect_fa(
        cfg,
        "fa-armor-expired",
        0x1000_030e,
        user,
        &ap(tgt(&old)?, user)?,
        None,
        err::TKT_EXPIRED,
    )?;
    let mut skewed = good.clone();
    let auth_usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR).map_err(|e| e.to_string())?;
    let plain = decrypt(&sess, auth_usage, skewed.authenticator.cipher.as_ref())
        .map_err(|e| e.to_string())?;
    let mut authenticator: krb5_types::Authenticator = decode(&plain).map_err(|e| e.to_string())?;
    authenticator.ctime = at(-3600);
    let auth_der = encode(&authenticator).map_err(|e| e.to_string())?;
    skewed.authenticator.cipher = encrypt(&sess, auth_usage, &auth_der)
        .map_err(|e| e.to_string())?
        .into();
    expect_fa(
        cfg,
        "fa-armor-skew",
        0x1000_030f,
        user,
        &skewed,
        None,
        err::SKEW,
    )?;
    let bad_auth = build_fast_armor(tgt(&part)?, &wrong, &crealm, user, Some(&sub))
        .map_err(|e| e.to_string())?;
    expect_fa(
        cfg,
        "fa-armor-authenticator-key",
        0x1000_0310,
        user,
        &bad_auth,
        None,
        err::BAD_INTEGRITY,
    )?;
    expect_fa(
        cfg,
        "fa-armor-host-ticket",
        0x1000_0311,
        user,
        &ap(seal_ticket(hkey, hkvno, realm, host, &part)?, user)?,
        None,
        err::SERVER_NOMATCH,
    )?;

    let mut req = as_req(user.clone(), realm, 0x1000_0312, None).map_err(|e| e.to_string())?;
    attach_fast(&mut req, &good, &wrong, Vec::new()).map_err(|e| e.to_string())?;
    expect_error(
        cfg,
        "fa-fast-req-key",
        &encode(&req).map_err(|e| e.to_string())?,
        err::BAD_INTEGRITY,
    )?;
    expect_fa(
        cfg,
        "fa-fast-req-short",
        0x1000_0313,
        user,
        &good,
        Some(&|w| w.enc_fast_req.cipher = vec![0u8; 5].into()),
        err::GENERIC,
    )?;
    expect_fa(
        cfg,
        "fa-fast-cksum-type",
        0x1000_0314,
        user,
        &good,
        Some(&|w| w.req_checksum.cksumtype = 99),
        err::GENERIC,
    )?;
    expect_fa(
        cfg,
        "fa-fast-cksum-size",
        0x1000_0318,
        user,
        &good,
        Some(&|w| w.req_checksum.checksum = vec![0u8; 4].into()),
        err::GENERIC,
    )?;
    // Bare, without PA-FX-FAST's CHOICE tag.
    let mut req = as_req(user.clone(), realm, 0x1000_0319, None).map_err(|e| e.to_string())?;
    attach_fast(&mut req, &good, &akey, Vec::new()).map_err(|e| e.to_string())?;
    let fx = req
        .0
        .padata
        .as_mut()
        .and_then(|p| p.iter_mut().find(|x| x.padata_type == pa::FX_FAST))
        .ok_or("no PA-FX-FAST")?;
    let krb5_types::fast::PaFxFast::ArmoredData(armored) =
        decode(fx.padata_value.as_ref()).map_err(|e| e.to_string())?;
    fx.padata_value = encode(&armored).map_err(|e| e.to_string())?.into();
    expect_error(
        cfg,
        "fa-fast-bare-armored-req",
        &encode(&req).map_err(|e| e.to_string())?,
        err::GENERIC,
    )?;
    expect_fa(
        cfg,
        "fa-fast-cksum-crc32",
        0x1000_031b,
        user,
        &good,
        Some(&|w| w.req_checksum.cksumtype = 1),
        err::GENERIC,
    )?;
    expect_fa(
        cfg,
        "fa-fast-cksum-md5-bytes",
        0x1000_031c,
        user,
        &good,
        Some(&|w| {
            w.req_checksum.cksumtype = 7;
            w.req_checksum.checksum = vec![0xff; 16].into();
        }),
        err::MODIFIED,
    )?;
    expect_fa(
        cfg,
        "fa-fast-cksum-md5-short",
        0x1000_031d,
        user,
        &good,
        Some(&|w| {
            w.req_checksum.cksumtype = 7;
            w.req_checksum.checksum = vec![0xff; 12].into();
        }),
        err::GENERIC,
    )?;
    expect_fa(
        cfg,
        "fa-fast-cksum-hmac-md5",
        0x1000_031e,
        user,
        &good,
        Some(&|w| {
            w.req_checksum.cksumtype = -138;
            w.req_checksum.checksum = vec![0xff; 16].into();
        }),
        err::MODIFIED,
    )?;
    let sess128 = random_session(EncryptionType::Aes128CtsHmacSha196)?;
    let sub128 = random_session(EncryptionType::Aes128CtsHmacSha196)?;
    let mut part128 = part.clone();
    part128.key = EncryptionKey {
        keytype: sess128.etype().to_iana(),
        keyvalue: sess128.as_bytes().to_vec().into(),
    };
    let ap128 = build_fast_armor(tgt(&part128)?, &sess128, &crealm, user, Some(&sub128))
        .map_err(|e| e.to_string())?;
    let akey128 = armor_key(&sess128, Some(&sub128)).map_err(|e| e.to_string())?;
    let mut req = as_req(user.clone(), realm, 0x1000_031f, None).map_err(|e| e.to_string())?;
    attach_fast(&mut req, &ap128, &akey128, Vec::new()).map_err(|e| e.to_string())?;
    fa_edit(&mut req, |w| {
        w.req_checksum.cksumtype = 19;
        w.req_checksum.checksum = vec![0xff; 16].into();
    })?;
    expect_error(
        cfg,
        "fa-fast-cksum-same-provider",
        &encode(&req).map_err(|e| e.to_string())?,
        err::MODIFIED,
    )?;
    expect_fa(
        cfg,
        "fa-fast-cksum-cross-enc",
        0x1000_0322,
        user,
        &good,
        Some(&|w| w.req_checksum.cksumtype = 15),
        err::GENERIC,
    )?;
    expect_fa(
        cfg,
        "fa-fast-cksum-type-zero",
        0x1000_0323,
        user,
        &good,
        Some(&|w| w.req_checksum.cksumtype = 0),
        err::POLICY,
    )?;
    let mut req = as_req(user.clone(), realm, 0x1000_0324, None).map_err(|e| e.to_string())?;
    attach_fast(&mut req, &good, &akey, Vec::new()).map_err(|e| e.to_string())?;
    let md5 =
        krb5_crypto::unkeyed_checksum(7, &encode(&req.0.req_body).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    fa_edit(&mut req, |w| {
        w.req_checksum.cksumtype = 7;
        w.req_checksum.checksum = md5.into();
    })?;
    expect_error(
        cfg,
        "fa-fast-cksum-md5-body",
        &encode(&req).map_err(|e| e.to_string())?,
        err::POLICY,
    )?;
    let mut req = as_req(user.clone(), realm, 0x1000_0325, None).map_err(|e| e.to_string())?;
    attach_fast(&mut req, &good, &akey, Vec::new()).map_err(|e| e.to_string())?;
    fa_edit(&mut req, |w| {
        if let Some(a) = w.armor.as_mut() {
            a.armor_type = 99;
        }
    })?;
    expect_error_no_edata(
        cfg,
        "fa-armor-type-unknown",
        &encode(&req).map_err(|e| e.to_string())?,
        err::PREAUTH_FAILED,
    )?;
    let mut bit0 = krb5_types::fast::fast_options_none();
    bit0.set(0, true);
    let mut req = as_req(user.clone(), realm, 0x1000_0320, None).map_err(|e| e.to_string())?;
    attach_fast_with_options(&mut req, &good, &akey, Vec::new(), &bit0)
        .map_err(|e| e.to_string())?;
    expect_error(
        cfg,
        "fa-fast-option-bit0",
        &encode(&req).map_err(|e| e.to_string())?,
        err::UNKNOWN_CRITICAL_FAST_OPTION,
    )?;
    let mut hide = krb5_types::fast::fast_options_none();
    hide.set(1, true);
    let ukey = client_key(18, &cfg.user_pw, user, realm)?;
    let mut req = as_req(user.clone(), realm, 0x1000_0326, None).map_err(|e| e.to_string())?;
    let ts = pa_enc_timestamp(&ukey).map_err(|e| e.to_string())?;
    attach_fast_with_options(&mut req, &good, &akey, vec![ts], &hide).map_err(|e| e.to_string())?;
    let (rust, mit) = send_both(
        cfg,
        "fa-fast-hide-client-rep",
        &encode(&req).map_err(|e| e.to_string())?,
    )?;
    let mut outer = Vec::new();
    for (leg, b) in [("rust", &rust), ("mit", &mit)] {
        let rep: AsRep = decode(b).map_err(|e| format!("fa-fast-hide-client-rep {leg}: {e}"))?;
        let fin = krb5_protocol::unwrap_fast_rep(&akey, &rep.0.padata)
            .map_err(|e| format!("fa-fast-hide-client-rep {leg} unwrap: {e}"))?
            .finished
            .ok_or_else(|| format!("fa-fast-hide-client-rep {leg}: no finished"))?;
        let real = format!(
            "{}@{}",
            fin.cname.components_joined(),
            String::from_utf8_lossy(fin.crealm.as_bytes())
        );
        if real != "user@KERBER.TEST" {
            return Err(format!(
                "fa-fast-hide-client-rep {leg}: finished names {real}"
            ));
        }
        outer.push(format!(
            "{}@{}",
            rep.0.cname.components_joined(),
            String::from_utf8_lossy(rep.0.crealm.as_bytes())
        ));
    }
    if outer[0] != outer[1] || outer[1] != "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS" {
        return Err(format!(
            "fa-fast-hide-client-rep: outer client rust={} mit={}",
            outer[0], outer[1]
        ));
    }
    println!(
        concat!(
            r#"{{"event":"diffsend","case":"fa-fast-hide-client-rep","outcome":"ok","#,
            r#""rust_tag":"0x6b","mit_tag":"0x6b","outer_client":"{}","#,
            r#""finished":"user@KERBER.TEST"}}"#
        ),
        outer[1]
    );

    let mut req = as_req(pauser.clone(), realm, 0x1000_0327, None).map_err(|e| e.to_string())?;
    attach_fast(&mut req, &good, &akey, Vec::new()).map_err(|e| e.to_string())?;
    let (rust, mit) = send_both(
        cfg,
        "fa-fast-error-inner",
        &encode(&req).map_err(|e| e.to_string())?,
    )?;
    let mut inner = Vec::new();
    for (leg, b) in [("rust", &rust), ("mit", &mit)] {
        let e: KrbError = decode(b).map_err(|e| format!("fa-fast-error-inner {leg}: {e}"))?;
        let md: krb5_types::MethodData = decode(e.e_data.as_ref().ok_or("no e_data")?.as_ref())
            .map_err(|e| format!("fa-fast-error-inner {leg} e_data: {e}"))?;
        let fast = krb5_protocol::unwrap_fast_rep(&akey, &Some(md))
            .map_err(|e| format!("fa-fast-error-inner {leg} unwrap: {e}"))?;
        let types: Vec<i32> = fast.padata.iter().map(|p| p.padata_type).collect();
        let last = fast.padata.last().ok_or("no inner padata")?;
        let fx: KrbError = decode(last.padata_value.as_ref())
            .map_err(|e| format!("fa-fast-error-inner {leg} FX-ERROR: {e}"))?;
        if last.padata_type != pa::FX_ERROR
            || !types.contains(&pa::FX_COOKIE)
            || fx.e_data.is_some()
            || fast.strengthen_key.is_some()
        {
            return Err(format!(
                "fa-fast-error-inner {leg}: types {types:?}, FX-ERROR e_data {}, strengthen {}",
                fx.e_data.is_some(),
                fast.strengthen_key.is_some()
            ));
        }
        inner.push(types);
    }
    if inner[0] != inner[1] {
        return Err(format!(
            "fa-fast-error-inner: inner types rust={:?} mit={:?}",
            inner[0], inner[1]
        ));
    }
    println!(
        concat!(
            r#"{{"event":"diffsend","case":"fa-fast-error-inner","outcome":"ok","#,
            r#""rust_tag":"0x7e","mit_tag":"0x7e","inner_types":"{:?}"}}"#
        ),
        inner[1]
    );
    let mut opts = krb5_types::fast::fast_options_none();
    opts.set(2, true);
    let mut req = as_req(user.clone(), realm, 0x1000_0315, None).map_err(|e| e.to_string())?;
    attach_fast_with_options(&mut req, &good, &akey, Vec::new(), &opts)
        .map_err(|e| e.to_string())?;
    expect_error(
        cfg,
        "fa-fast-critical-option",
        &encode(&req).map_err(|e| e.to_string())?,
        err::UNKNOWN_CRITICAL_FAST_OPTION,
    )
}

fn main() {
    if let Err(e) = run() {
        eprintln!("FATAL: {e}");
        process::exit(1);
    }
}
