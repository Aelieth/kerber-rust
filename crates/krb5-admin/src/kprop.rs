use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_kdc::{
    LoadLog, PrincipalStore, Ulog, UlogLast, dump_store, dump_store_with_key, save_store_fresh,
};
use krb5_log::klog::{self, Severity};
use krb5_protocol::trace::{ERROR_TABLE_BASE_KRB5, error_message, kdc_code};
use krb5_protocol::{
    AUTH_CONTEXT_DO_SEQUENCE, AcceptorAuthContext, AcceptorConfig, ApVerifyParams, FileLock,
    KeytabEntry, RemoteSeq, ReplayCache, build_ap_req_mutual_seq, build_krb_safe_from,
    local_host_address, us_timeofday, verify_ap_req_ex,
};
use krb5_types::{
    ApReq, EncTicketPart, EncryptedData, EncryptionKey, HostAddress, KerberosTime, KrbError,
    NameError, PrincipalName, Ticket, TicketFlags, TransitedEncoding, err, ku,
};
use nix::sys::socket::{setsockopt, sockopt};

use crate::Error;

mod poll;
mod send;

pub use poll::{IpropWake, KpropdIprop, kpropd_do_iprop};
pub(crate) use send::is_app_tag;
pub use send::service_port as kprop_service_port;
pub use send::{
    KPROP_SERVICE, KpropCreds, KpropDump, KpropError, RemoteError, kprop_get_tickets,
    kprop_open_connection, kprop_sendauth, kprop_update_last_prop_file, kprop_xmit_database,
};

const KPROP_PROT_VERSION: &[u8] = b"kprop5_01\0";
const SENDAUTH_VERSION: &[u8] = b"KRB5_SENDAUTH_V1.0\0";
const KPROP_BUFSIZ: usize = 32_768;

pub fn kprop_dump_bytes(store: &PrincipalStore, master_password: &[u8]) -> Result<Vec<u8>, Error> {
    dump_store(store, master_password)
        .map(String::into_bytes)
        .map_err(|e| Error::Inner(e.to_string()))
}

// MIT: `load_db` (kadmin/dbutil/dump.c:1497-1501)
#[must_use]
pub fn is_iprop_dump(dump: &[u8]) -> bool {
    dump.starts_with(b"ipropx ") || dump.starts_with(b"iprop ")
}

// MIT: `krb5_write_message` (lib/krb5/os/write_msg.c:73-76)
fn write_message<S: Write>(stream: &mut S, data: &[u8]) -> io::Result<()> {
    krb5_protocol::write_messages(stream, &[data])
}

fn read_message<S: Read>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr)?;
    let n = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(0);
    if n > 8 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kprop message too large",
        ));
    }
    let mut buf = vec![0u8; n];
    if n > 0 {
        stream.read_exact(&mut buf)?;
    }
    Ok(buf)
}

// MIT: `encode_database_size` (kprop/kprop_util.c:59-73)
fn encode_database_size(size: u64) -> Vec<u8> {
    match u32::try_from(size) {
        Ok(n) if n > 0 => n.to_be_bytes().to_vec(),
        _ => {
            let mut b = vec![0u8; 12];
            b[4..12].copy_from_slice(&size.to_be_bytes());
            b
        }
    }
}

// MIT: `decode_database_size` (kprop/kprop_util.c:75-99)
fn decode_database_size(buf: &[u8]) -> Result<u64, Error> {
    let bad = || Error::Inner("Generic error (see e-text)".into());
    match buf.len() {
        4 => Ok(u64::from(u32::from_be_bytes(
            buf.try_into().map_err(|_| bad())?,
        ))),
        12 => {
            if buf[..4] != [0, 0, 0, 0] {
                return Err(bad());
            }
            let size = u64::from_be_bytes(buf[4..12].try_into().map_err(|_| bad())?);
            if size > 0 && u32::try_from(size).is_ok() {
                return Err(bad());
            }
            Ok(size)
        }
        _ => Err(bad()),
    }
}

fn protocol_key_from_enc(kt: &krb5_types::EncryptionKey) -> Result<ProtocolKey, Error> {
    let etype = EncryptionType::from_iana(kt.keytype)
        .or_else(|_| EncryptionType::known(kt.keytype))
        .map_err(|e| Error::Inner(e.to_string()))?;
    ProtocolKey::from_bytes(etype, kt.keyvalue.as_ref()).map_err(|e| Error::Inner(e.to_string()))
}

fn session_from_ticket(ok: &krb5_protocol::ApVerifyOk) -> Result<ProtocolKey, Error> {
    if let Some(sk) = &ok.authenticator.subkey {
        return protocol_key_from_enc(sk);
    }
    protocol_key_from_enc(&ok.ticket_part.key)
}

fn mit_safe_dummy_der(msg: &krb5_types::KrbSafe) -> Result<Vec<u8>, Error> {
    let mut dummy = msg.clone();
    dummy.cksum = krb5_types::Checksum {
        cksumtype: 0,
        checksum: Vec::new().into(),
    };
    encode(&dummy).map_err(|e| Error::Inner(e.to_string()))
}

fn build_mit_safe(
    session: &ProtocolKey,
    user_data: &[u8],
    seq: u32,
    s_address: &HostAddress,
) -> Result<Vec<u8>, Error> {
    let safe = build_krb_safe_from(session, user_data, Some(seq), false, s_address)
        .map_err(|e| Error::Inner(e.to_string()))?;
    let dummy = mit_safe_dummy_der(&safe)?;
    let usage = krb5_crypto::KeyUsage::new(krb5_types::ku::KRB_SAFE_CKSUM)
        .map_err(|e| Error::Inner(e.to_string()))?;
    let mic =
        krb5_crypto::checksum(session, usage, &dummy).map_err(|e| Error::Inner(e.to_string()))?;
    let mut out = safe;
    out.cksum = krb5_types::Checksum {
        cksumtype: session.etype().checksum_type(),
        checksum: mic.into(),
    };
    encode(&out).map_err(|e| Error::Inner(e.to_string()))
}

pub struct KpropAuth {
    session: ProtocolKey,
    local_seq: u32,
    remote: RemoteSeq,
    local_addr: HostAddress,
    acceptor: Option<AcceptorAuthContext>,
    names: Option<KpropdNames>,
    sender: Option<send::SenderNames>,
}

struct KpropdNames {
    server: PrincipalName,
    realm: String,
    client: PrincipalName,
    crealm: krb5_types::Realm,
}

impl KpropAuth {
    fn next_local_seq(&mut self) -> u32 {
        let s = self.local_seq;
        self.local_seq = self.local_seq.wrapping_add(1);
        s
    }

    fn acceptor(&mut self) -> Result<&mut AcceptorAuthContext, krb5_protocol::Error> {
        self.acceptor
            .as_mut()
            .ok_or_else(|| krb5_protocol::Error::ReplyMismatch("not kpropd's context".into()))
    }

    // MIT: `send_error` (kprop/kpropd.c:1476-1510)
    fn send_error<S: Write>(&self, stream: &mut S, e: &krb5_protocol::Error, text: &str) {
        let Some(names) = &self.names else {
            return;
        };
        let (code, text) = match e {
            krb5_protocol::Error::KrbError { code, .. } if *code <= 127 => (*code, text.to_owned()),
            krb5_protocol::Error::Crypto(_) => (err::BAD_INTEGRITY, text.to_owned()),
            krb5_protocol::Error::Asn1(m) => (err::GENERIC, format!("{} {text}", asn1_com_err(m))),
            other => (err::GENERIC, format!("{other} {text}")),
        };
        let Ok(realm) = krb5_types::try_ascii(names.realm.as_str()) else {
            return;
        };
        let (stime, susec) = us_timeofday();
        let pdu = KrbError {
            pvno: KrbError::PVNO,
            msg_type: KrbError::MSG_TYPE,
            ctime: None,
            cusec: None,
            stime,
            susec,
            error_code: code,
            crealm: Some(names.crealm.clone()),
            cname: Some(names.client.clone()),
            realm,
            sname: names.server.clone(),
            e_text: e_text_with_nul(&text),
            e_data: None,
        };
        if let Ok(der) = encode(&pdu) {
            let _ = write_message(stream, &der);
        }
    }
}

fn com_err_text(e: &krb5_protocol::Error) -> String {
    match e {
        krb5_protocol::Error::KrbError { code, .. } => error_message(kdc_code(*code)),
        krb5_protocol::Error::Crypto(_) => error_message(kdc_code(err::BAD_INTEGRITY)),
        krb5_protocol::Error::Asn1(m) => asn1_com_err(m),
        other => other.to_string(),
    }
}

// MIT: `doit` (kpropd.c:528-546)
pub fn kpropd_recvauth(
    stream: &mut TcpStream,
    host_keys: &[ProtocolKey],
    expected_server: Option<&PrincipalName>,
    expected_realm: Option<&str>,
    acl_lines: Option<&[String]>,
    replay: &ReplayCache,
    conf: &AcceptorConfig,
) -> Result<KpropAuth, Error> {
    let keys = RecvauthKeys {
        keys: host_keys,
        keytab: None,
    };
    let (auth, client, etype) =
        recvauth_with(stream, &keys, expected_server, expected_realm, replay, conf)?;
    if !kpropd_authorized_principal(acl_lines, &client, etype) {
        return Err(Error::KpropUnauthorized(client));
    }
    Ok(auth)
}

struct RecvauthKeys<'a> {
    keys: &'a [ProtocolKey],
    keytab: Option<&'a KpropdKeys>,
}

fn recvauth_with<S: Read + Write + PeerAddr>(
    stream: &mut S,
    keys: &RecvauthKeys<'_>,
    expected_server: Option<&PrincipalName>,
    expected_realm: Option<&str>,
    replay: &ReplayCache,
    conf: &AcceptorConfig,
) -> Result<(KpropAuth, String, i32), Error> {
    let ver = read_message(stream).map_err(|e| Error::Inner(e.to_string()))?;
    if ver.as_slice() != SENDAUTH_VERSION {
        let _ = stream.write_all(&[1u8]);
        return Err(Error::Inner("sendauth version".into()));
    }
    let appl = read_message(stream).map_err(|e| Error::Inner(e.to_string()))?;
    if appl.as_slice() != KPROP_PROT_VERSION {
        let _ = stream.write_all(&[2u8]);
        return Err(Error::Inner("kprop appl version".into()));
    }
    stream
        .write_all(&[0u8])
        .map_err(|e| Error::Inner(e.to_string()))?;
    let ap_raw = read_message(stream).map_err(|e| Error::Inner(e.to_string()))?;
    let chosen: [ProtocolKey; 1];
    let (verify_keys, verify_server, verify_realm) = match keys.keytab {
        Some(kt) => match kpropd_ticket_key(&ap_raw, kt, expected_server, expected_realm, conf) {
            Ok(key) => {
                chosen = [key];
                (&chosen[..], None, None)
            }
            Err((der, text)) => {
                let _ = write_message(stream, &der);
                return Err(Error::Inner(text));
            }
        },
        None => (keys.keys, expected_server, expected_realm),
    };
    let params = ApVerifyParams {
        keys: verify_keys,
        key_kvnos: None,
        key_principals: None,
        kvno: None,
        permitted: conf.permitted().unwrap_or_default(),
        expected_server: verify_server,
        expected_realm: verify_realm,
        get_entry: None,
        skew: i64::from(conf.clockskew),
        ignore_acceptor_hostname: conf.ignore_acceptor_hostname,
        capaths: &conf.capaths,
        remote_addr: None,
        now: None,
    };
    // MIT: `recvauth_common` (recvauth.c:139-205)
    // MIT: `parse_args` (kprop/kpropd.c:1056-1058)
    // The KDC profile's clockskew and permitted enctypes, ahead of krb5.conf.
    let checked = verify_ap_req_ex(&ap_raw, &params, replay, None).and_then(|ok| {
        let ac = AcceptorAuthContext::from_ap_req(&ok, conf)?;
        Ok((ok, ac))
    });
    let (ok, mut ac) = match checked {
        Ok(v) => v,
        Err(e) => {
            let der = kprop_rd_req_error(&ap_raw, &e, expected_realm, expected_server);
            let _ = write_message(stream, &der);
            return Err(Error::Inner(e.to_string()));
        }
    };
    // MIT: `kerberos_authenticate` (kpropd.c:1221-1229)
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    let local_addr = local_host_address(stream.peer_addr().ok().map(|a| a.ip()));
    ac.set_addrs(Some(local_addr.clone()), None);
    write_message(stream, &[]).map_err(|e| Error::Inner(e.to_string()))?;
    let session = session_from_ticket(&ok)?;
    if ok.mutual_required {
        let ap_rep = ac.mk_rep().map_err(|e| Error::Inner(e.to_string()))?;
        let der = encode(&ap_rep).map_err(|e| Error::Inner(e.to_string()))?;
        write_message(stream, &der).map_err(|e| Error::Inner(e.to_string()))?;
    }
    let local_seq = ac.local_seq();
    let crealm = String::from_utf8_lossy(ok.authenticator.crealm.as_bytes());
    let client = ok.authenticator.cname.unparse_with_realm(&crealm);
    let auth = KpropAuth {
        session,
        local_seq,
        remote: RemoteSeq::new(ac.remote_seq()),
        local_addr,
        acceptor: Some(ac),
        names: Some(KpropdNames {
            server: expected_server.cloned().unwrap_or_else(kpropd_error_server),
            realm: expected_realm.unwrap_or("????").to_owned(),
            client: ok.authenticator.cname.clone(),
            crealm: ok.authenticator.crealm.clone(),
        }),
        sender: None,
    };
    Ok((auth, client, ok.ticket_etype))
}

// MIT: `authorized_principal` (kpropd.c:1298-1348)
#[must_use]
pub fn kpropd_authorized_principal(
    acl_lines: Option<&[String]>,
    name: &str,
    auth_etype: i32,
) -> bool {
    let c_isspace = |c: char| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r');
    let Some(lines) = acl_lines else {
        return false;
    };
    for line in lines {
        let Some(rest) = line.strip_prefix(name) else {
            continue;
        };
        if rest.chars().next().is_some_and(|c| !c_isspace(c)) {
            continue;
        }
        let etype_str = rest.trim_start_matches(c_isspace);
        if !etype_str.is_empty() && kpropd_acl_string_to_enctype(etype_str) != Some(auth_etype) {
            continue;
        }
        return true;
    }
    false
}

// MIT: `krb5_string_to_enctype` (enctype_util.c:89-114)
fn kpropd_acl_string_to_enctype(s: &str) -> Option<i32> {
    if s.is_empty()
        || s.chars().all(|c| c.is_ascii_digit())
        || s.contains(|c: char| c.is_whitespace())
    {
        return None;
    }
    EncryptionType::from_mit_name(s)
        .ok()
        .map(EncryptionType::to_iana)
}

// MIT: `krb5int_is_app_tag` (k5-int.h:1334-1336)
fn is_ap_req(raw: &[u8]) -> bool {
    raw.first().is_some_and(|b| b & !0x20 == 0x4e)
}

fn recvauth_error_fields(raw: &[u8], e: &krb5_protocol::Error) -> (i32, String) {
    if !is_ap_req(raw) {
        return (err::MSG_TYPE, "Invalid message type".into());
    }
    match e {
        krb5_protocol::Error::NopermEtype(_) => {
            (err::GENERIC, "Encryption type not permitted".into())
        }
        krb5_protocol::Error::KrbError { code, .. } if *code > 127 => {
            (err::GENERIC, recvauth_protocol_text(*code))
        }
        krb5_protocol::Error::KrbError { code, .. } => (*code, recvauth_protocol_text(*code)),
        krb5_protocol::Error::Asn1(s) => (err::GENERIC, asn1_com_err(s)),
        _ => (err::GENERIC, e.to_string()),
    }
}

fn asn1_com_err(s: &str) -> String {
    let l = s.to_ascii_lowercase();
    if l.contains("missing") {
        "ASN.1 structure is missing a required field".into()
    } else if l.contains("overrun")
        || l.contains("ended unexpectedly")
        || l.contains("eof")
        || l.contains("end of")
        || l.contains("truncated")
        || l.contains("need more data")
        || l.contains("size(")
    {
        "ASN.1 encoding ended unexpectedly".into()
    } else if l.contains("indefinite") {
        "ASN.1 indefinite encoding".into()
    } else {
        "ASN.1 parse error".into()
    }
}

fn recvauth_protocol_text(code: i32) -> String {
    error_message(ERROR_TABLE_BASE_KRB5 + i64::from(code))
}

/// Endtime is 400s ago, past the 300s skew.
pub fn kprop_expired_ap_req(
    host_key: &ProtocolKey,
    kvno: u32,
    host: &PrincipalName,
    realm: &str,
) -> Result<Vec<u8>, Error> {
    let now = KerberosTime::now();
    let past = now
        .add_seconds(-400)
        .map_err(|e| Error::Inner(e.to_string()))?;
    let session = ProtocolKey::random(host_key.etype()).map_err(|e| Error::Inner(e.to_string()))?;
    let realm_ks = krb5_types::try_ascii(realm).map_err(|e| Error::Inner(e.to_string()))?;
    let part = EncTicketPart {
        flags: TicketFlags::initial_preauth(),
        key: EncryptionKey {
            keytype: session.etype().to_iana(),
            keyvalue: session.as_bytes().to_vec().into(),
        },
        crealm: realm_ks.clone(),
        cname: host.clone(),
        transited: TransitedEncoding::empty(),
        authtime: past.clone(),
        starttime: Some(past.clone()),
        endtime: past,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let der = encode(&part).map_err(|e| Error::Inner(e.to_string()))?;
    let usage = KeyUsage::new(ku::TICKET).map_err(|e| Error::Inner(e.to_string()))?;
    let cipher = encrypt(host_key, usage, &der).map_err(|e| Error::Inner(e.to_string()))?;
    let ticket = Ticket {
        tkt_vno: Ticket::VNO,
        realm: realm_ks.clone(),
        sname: host.clone(),
        enc_part: EncryptedData {
            etype: host_key.etype().to_iana(),
            kvno: Some(kvno),
            cipher: cipher.into(),
        },
    };
    let ap = build_ap_req_mutual_seq(ticket, &session, &realm_ks, host, 1)
        .map_err(|e| Error::Inner(e.to_string()))?;
    encode(&ap).map_err(|e| Error::Inner(e.to_string()))
}

fn e_text_with_nul(text: &str) -> Option<krb5_types::KerberosString> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    krb5_types::kerberos_string_from_bytes(&bytes).ok()
}

pub fn kpropd_server_name(profile: &krb5_config::Krb5Conf) -> Result<PrincipalName, NameError> {
    kpropd_server_name_for(&krb5_config::this_host(), profile)
}

// MIT: `sn2princ_realm` (kprop/kprop_util.c:33-55)
// MIT: `krb5_sname_to_principal` (lib/krb5/os/sn2princ.c:365-376)
/// `fallback` keeps the name; lookup expands it when the ticket arrives.
pub fn kpropd_server_name_for(
    host: &str,
    profile: &krb5_config::Krb5Conf,
) -> Result<PrincipalName, NameError> {
    let host = if profile.dns_canonicalize_hostname == krb5_config::CanonHost::Fallback {
        host.to_owned()
    } else {
        krb5_config::expand_hostname(host, profile)
    };
    PrincipalName::try_new(PrincipalName::NT_SRV_HST, ["host", host.as_str()])
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum KpropdLookup {
    #[default]
    Server,
    Name(PrincipalName),
    Unnamed,
}

// MIT: `k5_canonprinc` (lib/krb5/os/sn2princ.c:281-307)
fn kpropd_lookup_name(
    server: &PrincipalName,
    fallback: bool,
    expand: impl FnOnce(&str) -> String,
) -> KpropdLookup {
    match server.name_string.as_slice() {
        [service, host]
            if fallback
                && server.name_type == PrincipalName::NT_SRV_HST
                && !host.as_bytes().is_empty() =>
        {
            let host = expand(&String::from_utf8_lossy(host.as_bytes()));
            let service = String::from_utf8_lossy(service.as_bytes()).into_owned();
            match PrincipalName::try_new(PrincipalName::NT_SRV_HST, [service, host]) {
                Ok(name) if name == *server => KpropdLookup::Server,
                Ok(name) => KpropdLookup::Name(name),
                Err(_) => KpropdLookup::Unnamed,
            }
        }
        _ => KpropdLookup::Server,
    }
}

fn kpropd_error_server() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["????"])
}

fn kprop_rd_req_error(
    raw: &[u8],
    e: &krb5_protocol::Error,
    realm: Option<&str>,
    server: Option<&PrincipalName>,
) -> Vec<u8> {
    let (code, text) = recvauth_error_fields(raw, e);
    kprop_krb_error(code, &text, realm, server)
}

fn kprop_krb_error(
    code: i32,
    text: &str,
    realm: Option<&str>,
    server: Option<&PrincipalName>,
) -> Vec<u8> {
    let realm_s = realm.unwrap_or("????");
    let realm_ks = match krb5_types::try_ascii(realm_s) {
        Ok(r) => r,
        Err(_) => match krb5_types::try_ascii("INVALID") {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        },
    };
    let sname = server.cloned().unwrap_or_else(kpropd_error_server);
    let (stime, susec) = us_timeofday();
    let pdu = KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime,
        susec,
        error_code: code,
        crealm: None,
        cname: None,
        realm: realm_ks,
        sname,
        e_text: e_text_with_nul(text),
        e_data: None,
    };
    encode(&pdu).unwrap_or_default()
}

// MIT: `krb5_rd_req` (lib/krb5/krb/rd_req.c:56-84)
// MIT: `decrypt_ticket` (lib/krb5/krb/rd_req_dec.c:454-456)
// MIT: `decrypt_try_server` (lib/krb5/krb/rd_req_dec.c:373-377)
// MIT: `try_one_princ` (lib/krb5/krb/rd_req_dec.c:335-346)
// MIT: `keytab_fetch_error` (lib/krb5/krb/rd_req_dec.c:126-148)
// MIT: `integrity_error` (lib/krb5/krb/rd_req_dec.c:173-174)
/// No entry is NOKEY. Own server: missing kvno BADKEYVER, bad decrypt BAD_INTEGRITY; else NOT_US.
fn kpropd_ticket_key(
    raw: &[u8],
    kt: &KpropdKeys,
    server: Option<&PrincipalName>,
    realm: Option<&str>,
    conf: &AcceptorConfig,
) -> Result<ProtocolKey, (Vec<u8>, String)> {
    let refuse = |code: i32| {
        let text = recvauth_protocol_text(code);
        (kprop_krb_error(code, &text, realm, server), text)
    };
    let ap: ApReq = decode(raw).map_err(|e| {
        let e = krb5_protocol::Error::from(e);
        (kprop_rd_req_error(raw, &e, realm, server), e.to_string())
    })?;
    let generic = |text: &str| {
        (
            kprop_krb_error(err::GENERIC, text, realm, server),
            text.to_owned(),
        )
    };
    if let Some(KpropdKeytabError::Resolve(text)) = &kt.error {
        return Err(generic(text));
    }
    // MIT: `krb5_is_permitted_enctype` (lib/krb5/krb/init_ctx.c:603-605)
    // A permitted list that can't be read permits nothing.
    let permitted = conf.permitted().unwrap_or_default();
    let ticket = &ap.ticket;
    let realm_b = realm.unwrap_or_default().as_bytes();
    let (tkt_kvno, tkt_etype) = (ticket.enc_part.kvno.unwrap_or(0), ticket.enc_part.etype);
    let is_tkt_server = |name: &PrincipalName, name_realm: &[u8]| {
        name.name_string == ticket.sname.name_string && name_realm == ticket.realm.as_bytes()
    };
    let explicit = server.filter(|s| {
        // MIT: `is_matching` (lib/krb5/krb/rd_req_dec.c:283-285)
        !(s.name_type == PrincipalName::NT_SRV_HST
            && s.name_string.len() == 2
            && (realm_b.is_empty()
                || s.name_string[1].as_bytes().is_empty()
                || kt.ignore_acceptor_hostname))
    });
    if let Some(KpropdKeytabError::Read(text)) = &kt.error {
        if explicit.is_none() {
            return Err(refuse(err::NOKEY));
        }
        return Err(generic(text));
    }
    if let Some(name) = explicit {
        let name = match &kt.lookup {
            KpropdLookup::Server => name,
            KpropdLookup::Name(canonical) => canonical,
            KpropdLookup::Unnamed => return Err(refuse(err::NOKEY)),
        };
        let own = is_tkt_server(name, realm_b);
        let entry = match kt_get_entry(&kt.entries, name, realm_b, tkt_kvno, tkt_etype) {
            KtGet::Found(e) => e,
            KtGet::KvnoNotFound if own => return Err(refuse(err::BADKEYVER)),
            KtGet::KvnoNotFound => return Err(refuse(err::NOT_US)),
            KtGet::NotFound => return Err(refuse(err::NOKEY)),
        };
        return match decrypt_ticket_part(&entry.key, ticket, permitted) {
            Ok(()) => Ok(entry.key.clone()),
            Err(TicketPart::Integrity) if own => Err(refuse(err::BAD_INTEGRITY)),
            Err(TicketPart::Integrity) => Err(refuse(err::NOT_US)),
            Err(TicketPart::Size) => {
                Err(generic("Message size is incompatible with encryption type"))
            }
            Err(TicketPart::Other(e)) => {
                Err((kprop_rd_req_error(raw, &e, realm, server), e.to_string()))
            }
        };
    }
    let (mut mismatch, mut matched, mut tkt_server, mut kvno, mut enctype) =
        (false, false, false, false, false);
    for e in &kt.entries {
        let named = is_tkt_server(&e.name, e.realm.as_bytes());
        let wanted = krb5_protocol::sname_match(
            server,
            realm,
            &e.name,
            e.realm.as_bytes(),
            kt.ignore_acceptor_hostname,
        );
        if !wanted {
            mismatch |= named;
            continue;
        }
        matched = true;
        let similar = e.key.etype().to_iana() == tkt_etype;
        if named {
            tkt_server = true;
            kvno |= e.kvno == tkt_kvno;
            enctype |= e.kvno == tkt_kvno && similar;
        }
        if similar && decrypt_ticket_part(&e.key, ticket, permitted).is_ok() {
            return Ok(e.key.clone());
        }
    }
    // MIT: `iteration_error` (lib/krb5/krb/rd_req_dec.c:222-270)
    Err(refuse(if !matched {
        err::NOKEY
    } else if mismatch || !tkt_server {
        err::NOT_US
    } else if !kvno || !enctype {
        err::BADKEYVER
    } else {
        err::BAD_INTEGRITY
    }))
}

enum TicketPart {
    Integrity,
    Size,
    Other(krb5_protocol::Error),
}

// MIT: `try_one_entry` (lib/krb5/krb/rd_req_dec.c:297-299)
// MIT: `krb5_decrypt_tkt_part` (lib/krb5/krb/decrypt_tk.c:46-50)
// MIT: `krb5_k_decrypt` (lib/crypto/krb/decrypt.c:48-52)
fn decrypt_ticket_part(
    key: &ProtocolKey,
    ticket: &Ticket,
    permitted: &[EncryptionType],
) -> Result<(), TicketPart> {
    krb5_protocol::check_ticket_etype(ticket.enc_part.etype, permitted)
        .map_err(TicketPart::Other)?;
    let usage = KeyUsage::new(ku::TICKET).map_err(|e| TicketPart::Other(e.into()))?;
    let plain = decrypt(key, usage, ticket.enc_part.cipher.as_ref()).map_err(|e| match e {
        krb5_crypto::Error::Integrity => TicketPart::Integrity,
        krb5_crypto::Error::CiphertextTooShort => TicketPart::Size,
        other => TicketPart::Other(other.into()),
    })?;
    decode::<EncTicketPart>(&plain).map_err(|e| TicketPart::Other(e.into()))?;
    Ok(())
}

enum KtGet<'a> {
    Found(&'a KeytabEntry),
    KvnoNotFound,
    NotFound,
}

// MIT: `krb5_ktfile_get_entry` (lib/krb5/keytab/kt_file.c:333-391)
/// kvno 0 keeps the newest; a low-8 match is only the first; another kvno is missing.
fn kt_get_entry<'a>(
    entries: &'a [KeytabEntry],
    name: &PrincipalName,
    realm: &[u8],
    kvno: u32,
    enctype: i32,
) -> KtGet<'a> {
    let mut cur: Option<&KeytabEntry> = None;
    let mut wrong_kvno = false;
    for e in entries {
        if e.name.name_string != name.name_string || e.realm.as_bytes() != realm {
            continue;
        }
        if enctype != 0 && e.key.etype().to_iana() != enctype {
            continue;
        }
        if kvno == 0 || e.kvno == 0 {
            if cur.is_none_or(|c| more_recent(e, c)) {
                cur = Some(e);
            }
        } else if e.kvno == kvno {
            cur = Some(e);
            break;
        } else if e.kvno == kvno & 0xff && cur.is_none() {
            cur = Some(e);
        } else {
            wrong_kvno = true;
        }
    }
    match cur {
        Some(e) => KtGet::Found(e),
        None if wrong_kvno => KtGet::KvnoNotFound,
        None => KtGet::NotFound,
    }
}

// MIT: `more_recent` (lib/krb5/keytab/kt_file.c:267-275)
/// Above 240 against below 128 is the wrap; otherwise the higher kvno.
fn more_recent(k1: &KeytabEntry, k2: &KeytabEntry) -> bool {
    if k2.timestamp <= k1.timestamp && k1.kvno < 128 && k2.kvno > 240 {
        return true;
    }
    if k1.timestamp <= k2.timestamp && k1.kvno > 240 && k2.kvno < 128 {
        return false;
    }
    k1.kvno > k2.kvno
}

// MIT: `recv_database` (kprop/kpropd.c:1356-1473)
/// MIT streams the dump with no bound. mit-deviations.
const MAX_DUMP_SIZE: u64 = 1 << 32;

/// Idle bound, the kadm5 loop's `RPC_READ_WAIT`.
pub const KPROPD_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(35);

struct DeadlineStream<'a> {
    inner: &'a mut TcpStream,
    deadline: Option<std::time::Instant>,
}

const TIMED_OUT: &str = "Full propagation timed out";

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, TIMED_OUT)
}

fn expired(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::TimedOut && e.to_string() == TIMED_OUT
}

impl DeadlineStream<'_> {
    fn arm(&self) -> io::Result<()> {
        let Some(d) = self.deadline else {
            return Ok(());
        };
        let remaining = d
            .checked_duration_since(std::time::Instant::now())
            .filter(|r| !r.is_zero());
        let Some(remaining) = remaining else {
            return Err(timed_out());
        };
        let t = remaining.min(KPROPD_IO_TIMEOUT);
        self.inner.set_read_timeout(Some(t))?;
        self.inner.set_write_timeout(Some(t))?;
        Ok(())
    }

    fn mapped(&self, e: io::Error) -> io::Error {
        if matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) && self
            .deadline
            .is_some_and(|d| std::time::Instant::now() >= d)
        {
            timed_out()
        } else {
            e
        }
    }
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm()?;
        match self.inner.read(buf) {
            Ok(n) => Ok(n),
            Err(e) => Err(self.mapped(e)),
        }
    }
}

impl Write for DeadlineStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm()?;
        match self.inner.write(buf) {
            Ok(n) => Ok(n),
            Err(e) => Err(self.mapped(e)),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

trait PeerAddr {
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr>;
}

impl PeerAddr for TcpStream {
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        TcpStream::peer_addr(self)
    }
}

impl PeerAddr for DeadlineStream<'_> {
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
}

pub fn kpropd_recv_dump<S: Read + Write>(
    stream: &mut S,
    auth: &mut KpropAuth,
) -> Result<Vec<u8>, Error> {
    let log = poll::Log {
        progname: "kpropd",
        debug: false,
    };
    let mut dump = Vec::new();
    recv_database(stream, &mut dump, auth, &log)?;
    Ok(dump)
}

// MIT: `recv_database` (kprop/kpropd.c:1356-1473)
fn recv_database<S: Read + Write, W: Write>(
    stream: &mut S,
    out: &mut W,
    auth: &mut KpropAuth,
    log: &poll::Log<'_>,
) -> Result<u64, Error> {
    let generic = krb5_protocol::Error::KrbError {
        code: err::GENERIC,
        text: None,
    };
    let size_raw = match read_message(stream) {
        Ok(raw) => raw,
        Err(e) if expired(&e) => return Err(Error::Inner(e.to_string())),
        Err(e) => {
            let t = send::os_text(&e);
            auth.send_error(
                stream,
                &generic,
                &format!("{t} while reading database size"),
            );
            log.com_err(Some(&t), "while reading size of database from client");
            return Err(Error::Reported);
        }
    };
    if is_app_tag(&size_raw, 30) {
        return Err(recv_error(&size_raw, log));
    }
    let size_plain = match auth.acceptor().and_then(|ac| ac.rd_safe(&size_raw)) {
        Ok(p) => p,
        Err(e) => {
            auth.send_error(stream, &e, "while decoding database size");
            log.com_err(
                Some(&com_err_text(&e)),
                "while decoding database size from client",
            );
            return Err(Error::Reported);
        }
    };
    let Ok(want) = decode_database_size(&size_plain) else {
        auth.send_error(stream, &generic, "malformed database size message");
        let t = error_message(kdc_code(err::GENERIC));
        log.com_err(Some(&t), "malformed database size message from client");
        return Err(Error::Reported);
    };
    if want > MAX_DUMP_SIZE {
        auth.send_error(stream, &generic, "database size exceeds the limit");
        let text = format!("database size {want} exceeds the {MAX_DUMP_SIZE}-byte limit");
        log.com_err(None, &text);
        return Err(Error::Reported);
    }
    auth.acceptor()
        .map_err(|e| Error::Inner(e.to_string()))?
        .init_ivector();
    log.debug("Full propagation transfer started.");
    let mut received = 0u64;
    while received < want {
        let chunk_raw = match read_message(stream) {
            Ok(raw) => raw,
            Err(e) if expired(&e) => return Err(Error::Inner(e.to_string())),
            Err(e) => {
                let t = send::os_text(&e);
                let what = format!("while reading database block starting at offset {received}");
                log.com_err(Some(&t), &what);
                auth.send_error(stream, &generic, &format!("{t} {what}"));
                return Err(Error::Reported);
            }
        };
        if is_app_tag(&chunk_raw, 30) {
            return Err(recv_error(&chunk_raw, log));
        }
        let chunk = match auth.acceptor().and_then(|ac| ac.rd_priv(&chunk_raw)) {
            Ok(c) => c,
            Err(e) => {
                let what = format!("while decoding database block starting at offset {received}");
                log.com_err(Some(&com_err_text(&e)), &what);
                auth.send_error(stream, &e, &what);
                return Err(Error::Reported);
            }
        };
        let failed = match out.write(&chunk) {
            Err(e) => Some(format!(
                "{} while writing database block starting at offset {received}",
                klog::os_error_text(&e)
            )),
            Ok(n) if n != chunk.len() => Some(format!(
                "incomplete write while writing database block starting at \noffset {received} \
                 ({n} written, {} expected)",
                chunk.len()
            )),
            Ok(_) => None,
        };
        if let Some(text) = failed {
            auth.send_error(stream, &generic, &text);
        }
        received += chunk.len() as u64;
    }
    if received > want {
        let text = format!("Received {received} bytes, expected {want} bytes for database file");
        auth.send_error(stream, &generic, &text);
    }
    log.debug("Full propagation transfer finished.");
    Ok(want)
}

// MIT: `recv_error` (kprop/kpropd.c:1513-1538)
fn recv_error(raw: &[u8], log: &poll::Log<'_>) -> Error {
    match decode::<KrbError>(raw) {
        Err(e) => log.com_err(
            Some(&asn1_com_err(&e.to_string())),
            "while decoding error packet from client",
        ),
        Ok(pdu) => {
            let remote = send::RemoteError::from_krb_error(&pdu);
            if remote.code == err::GENERIC {
                if let Some(t) = &remote.text {
                    eprintln!("Generic remote error: {t}");
                }
            } else if remote.code != 0 {
                let t = error_message(kdc_code(remote.code));
                log.com_err(Some(&t), "signaled from server");
                if let Some(t) = &remote.text {
                    eprintln!("Error text from client: {t}");
                }
            }
        }
    }
    Error::Reported
}

pub fn kpropd_send_ack<S: Write>(
    stream: &mut S,
    auth: &mut KpropAuth,
    size: u64,
) -> Result<(), Error> {
    let seq = auth.next_local_seq();
    let body = encode_database_size(size);
    let der = build_mit_safe(&auth.session, &body, seq, &auth.local_addr)?;
    write_message(stream, &der).map_err(|e| Error::Inner(klog::os_error_text(&e)))?;
    Ok(())
}

#[derive(Debug, Default)]
pub struct KpropdKeys {
    pub entries: Vec<KeytabEntry>,
    pub error: Option<KpropdKeytabError>,
    pub ignore_acceptor_hostname: bool,
    pub lookup: KpropdLookup,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KpropdKeytabError {
    Resolve(String),
    Read(String),
}

// MIT: `krb5_ktfileint_open` (lib/krb5/keytab/kt_file.c:785-804)
pub fn kpropd_keytab_keys(
    keytab: Option<&str>,
    server: Option<&PrincipalName>,
    ctx: &krb5_config::ClientContext,
) -> Result<KpropdKeys, &'static str> {
    let profile = &ctx.profile;
    let fallback = profile.dns_canonicalize_hostname == krb5_config::CanonHost::Fallback;
    let lookup = server.map_or(KpropdLookup::Server, |s| {
        kpropd_lookup_name(s, fallback, |h| krb5_config::expand_hostname(h, profile))
    });
    let empty = KpropdKeys {
        ignore_acceptor_hostname: profile.ignore_acceptor_hostname,
        lookup,
        ..KpropdKeys::default()
    };
    let path = match crate::kadmin_cli::keytab_file_of(keytab, ctx) {
        Ok(Some(path)) => path,
        Ok(None) => return Ok(empty),
        Err(e) if keytab.is_none() => {
            return Ok(KpropdKeys {
                error: Some(KpropdKeytabError::Resolve(e.to_owned())),
                ..empty
            });
        }
        Err(e) => return Err(e),
    };
    let bytes = match krb5_protocol::read_secret_file(&path) {
        Ok(bytes) => bytes,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(empty);
        }
        Err(e) => {
            return Ok(KpropdKeys {
                error: Some(KpropdKeytabError::Read(krb5_log::klog::os_error_text(&e))),
                ..empty
            });
        }
    };
    if bytes.len() < 2 || bytes[0] != 0x05 || !matches!(bytes[1], 0x01 | 0x02) {
        return Ok(KpropdKeys {
            error: Some(KpropdKeytabError::Read(
                "Unsupported key table format version number".to_owned(),
            )),
            ..empty
        });
    }
    Ok(KpropdKeys {
        entries: krb5_protocol::Keytab::parse(&bytes)
            .map(|kt| kt.entries)
            .unwrap_or_default(),
        ..empty
    })
}

// MIT: `acl_file_name` (kpropd.c:137-137)
#[derive(Clone, Copy)]
pub struct KpropdConfig<'a> {
    pub host_keys: &'a [ProtocolKey],
    pub keytab: Option<&'a KpropdKeys>,
    pub expected_server: Option<&'a PrincipalName>,
    pub expected_realm: Option<&'a str>,
    pub allowed_clients: Option<&'a [String]>,
    pub iprop: Option<&'a krb5_config::IpropParams>,
    /// Whole-transfer deadline (`iprop_resync_timeout`). mit-deviations.
    pub resync_timeout: std::time::Duration,
    pub conf: &'a AcceptorConfig,
    pub load: KpropdLoad<'a>,
}

// MIT: `file` (kpropd.c:133-133)
// MIT: `kdb5_util` (kpropd.c:135-135)
// MIT: `realm` (kpropd.c:131-131)
// MIT: `kerb_database` (kpropd.c:136-136)
#[derive(Clone, Copy)]
pub struct KpropdLoad<'a> {
    pub progname: &'a str,
    pub debug: bool,
    pub file: &'a Path,
    pub kdb5_util: &'a Path,
    pub realm: Option<&'a str>,
    pub database: Option<&'a Path>,
}

#[must_use]
pub fn iprop_dump_last(dump: &[u8]) -> Option<UlogLast> {
    let line = dump.split(|&b| b == b'\n').next()?;
    krb5_kdc::parse_iprop_header(std::str::from_utf8(line).ok()?)
        .ok()
        .map(|(_, last)| last)
}

/// Iprop keeps the replica's non-replicated attributes; a plain load keeps the dump's.
pub fn load_replica(
    store: &PrincipalStore,
    db: &Path,
    stash: &Path,
    iprop: Option<(&krb5_config::IpropParams, UlogLast)>,
) -> Result<(), Error> {
    let Some((params, last)) = iprop else {
        return save_store_fresh(store, db, stash, false, None)
            .map_err(|e| Error::Inner(e.to_string()));
    };
    let log = Ulog::map(&params.logfile, params.ulogsize)
        .map_err(|_| Error::Inner("Could not open iprop ulog".into()))?;
    let log = LoadLog {
        ulog: &log,
        last: Some(last),
    };
    save_store_fresh(store, db, stash, true, Some(log)).map_err(|e| Error::Inner(e.to_string()))
}

pub fn kpropd_handle_conn(stream: &mut TcpStream, cfg: &KpropdConfig<'_>, replay: &ReplayCache) {
    let log = poll::Log {
        progname: cfg.load.progname,
        debug: cfg.load.debug,
    };
    match doit(stream, cfg, replay, &log) {
        Ok(()) | Err(Error::Reported) => {}
        // MIT: `alarm_handler` (kprop/kpropd.c:213-219)
        Err(Error::Inner(t)) if t == TIMED_OUT => eprintln!("{t}"),
        Err(e) => log.com_err(None, &e.to_string()),
    }
}

// MIT: `doit` (kprop/kpropd.c:480-601)
fn doit(
    stream: &mut TcpStream,
    cfg: &KpropdConfig<'_>,
    replay: &ReplayCache,
    log: &poll::Log<'_>,
) -> Result<(), Error> {
    let KpropdConfig {
        host_keys,
        keytab,
        expected_server,
        expected_realm,
        allowed_clients,
        iprop,
        resync_timeout,
        conf,
        load,
    } = *cfg;
    let deadline = (!resync_timeout.is_zero()).then(|| std::time::Instant::now() + resync_timeout);
    let peer = match stream.peer_addr() {
        Ok(peer) => peer,
        Err(e) => {
            eprintln!(
                "{}: getpeername: {}",
                load.progname,
                klog::os_error_text(&e)
            );
            return Err(Error::Reported);
        }
    };
    if let Err(e) = setsockopt(&*stream, sockopt::KeepAlive, &true) {
        log.com_err(Some(e.desc()), "while attempting setsockopt (SO_KEEPALIVE)");
    }
    let host = krb5_config::name_of_addr(peer.ip());
    klog::syslog(Severity::Info, &format!("Connection from {host}"));
    log.debug(&format!("Connection from {host}"));
    // MIT: `kerberos_authenticate` (kprop/kpropd.c:1185-1295)
    if let Some(server) = expected_server.filter(|_| load.debug) {
        let server = server.unparse_with_realm(expected_realm.unwrap_or_default());
        eprintln!(
            "krb5_recvauth({}, kprop5_01, {server}, ...)",
            stream.as_raw_fd()
        );
    }
    let mut ds = DeadlineStream {
        inner: stream,
        deadline,
    };
    let keys = RecvauthKeys {
        keys: host_keys,
        keytab,
    };
    let (mut auth, client, etype) = recvauth_with(
        &mut ds,
        &keys,
        expected_server,
        expected_realm,
        replay,
        conf,
    )?;
    if load.debug {
        let name = EncryptionType::known(etype).map_or("", EncryptionType::to_mit_name);
        eprintln!("authenticated client: {client} (etype == {name})");
    }
    if !kpropd_authorized_principal(allowed_clients, &client, etype) {
        let text = format!("Rejected connection from unauthorized principal {client}");
        log.debug(&text);
        klog::syslog(Severity::Warning, &text);
        return Err(Error::Reported);
    }
    let mut temp = load.file.as_os_str().to_owned();
    temp.push(".temp");
    let temp = std::path::PathBuf::from(temp);
    let lock_err = |e: &str, what: &str| {
        log.com_err(Some(e), &format!("{what} '{}'", temp.display()));
        Error::Reported
    };
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&temp);
    // MIT locks the -1 a failed open returns; refusing a link is ours.
    let mut file = match opened {
        Ok(file) => file,
        Err(e) if e.raw_os_error() == Some(nix::libc::ELOOP) => {
            return Err(lock_err(&klog::os_error_text(&e), "while trying to lock"));
        }
        Err(_) => {
            return Err(lock_err(
                nix::errno::Errno::EBADF.desc(),
                "while trying to lock",
            ));
        }
    };
    let mut flocked = None;
    krb5_protocol::lock_file_how(&file, FileLock::Exclusive, &mut flocked, false)
        .map_err(|e| lock_err(e.desc(), "while trying to lock"))?;
    if let Err(e) = file.set_len(0) {
        let text = format!("while opening database file, '{}'", temp.display());
        log.com_err(Some(&klog::os_error_text(&e)), &text);
        return Err(Error::Reported);
    }
    let size = recv_database(&mut ds, &mut file, &mut auth, log)?;
    if let Err(e) = std::fs::rename(&temp, load.file) {
        let text = format!(
            "while renaming {} to {}",
            temp.display(),
            load.file.display()
        );
        log.com_err(Some(&klog::os_error_text(&e)), &text);
        return Err(Error::Reported);
    }
    krb5_protocol::lock_file(&file, FileLock::Shared, &mut flocked)
        .map_err(|e| lock_err(e.desc(), "while downgrading lock on"))?;
    load_database(&load, iprop.is_some(), deadline, log)?;
    krb5_protocol::lock_file(&file, FileLock::Unlock, &mut flocked)
        .map_err(|e| lock_err(e.desc(), "while unlocking"))?;
    drop(file);
    let acked = kpropd_send_ack(&mut ds, &mut auth, size);
    if let Err(Error::Inner(t)) = &acked
        && t != TIMED_OUT
    {
        log.com_err(Some(t), "while sending # of received bytes");
        return Err(Error::Reported);
    }
    acked
}

// MIT: `load_database` (kprop/kpropd.c:1541-1609)
fn load_database(
    load: &KpropdLoad<'_>,
    iprop: bool,
    deadline: Option<std::time::Instant>,
    log: &poll::Log<'_>,
) -> Result<(), Error> {
    log.debug("calling kdb5_util to load database");
    let util = load.kdb5_util.display().to_string();
    let mut cmd = std::process::Command::new(load.kdb5_util);
    if let Some(realm) = load.realm {
        cmd.args(["-r", realm]);
    }
    cmd.arg("load");
    if let Some(db) = load.database {
        cmd.arg("-d").arg(db);
    }
    if iprop {
        cmd.arg("-i");
    }
    cmd.arg(load.file);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            log.com_err(
                Some(&klog::os_error_text(&e)),
                &format!("while trying to exec {util}"),
            );
            log.com_err(None, &format!("{util} returned a bad exit status (1)"));
            return Err(Error::Reported);
        }
    };
    log.debug(&format!("Load PID is {}", child.id()));
    // MIT's `doit` alarm also bounds the load; on expiry kdb5_util runs on.
    let waited = match deadline {
        None => child.wait(),
        Some(d) => loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if std::time::Instant::now() < d => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Ok(None) => {
                    std::thread::spawn(move || child.wait());
                    return Err(Error::Inner(timed_out().to_string()));
                }
                Err(e) => break Err(e),
            }
        },
    };
    match waited {
        Err(e) => {
            log.com_err(
                Some(&klog::os_error_text(&e)),
                &format!("while waiting for {util}"),
            );
        }
        Ok(status) => match status.code() {
            Some(0) => return Ok(()),
            None => log.com_err(None, &format!("{util} load terminated")),
            Some(code) => log.com_err(None, &format!("{util} returned a bad exit status ({code})")),
        },
    }
    Err(Error::Reported)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpropPoll {
    Applied(usize),
    Nil,
    FullResync(u32),
}

// MIT: `ulog_replay` (lib/kdb/kdb_log.c:474-476)
pub fn iprop_poll_once(master: &PrincipalStore, slave: &mut PrincipalStore) -> IpropPoll {
    let last = slave.ulog_last().unwrap_or_default();
    let got = master.ulog_get_entries(last);
    match got.status {
        krb5_kdc::IPROP_NIL => return IpropPoll::Nil,
        krb5_kdc::IPROP_OK => {}
        _ => return IpropPoll::FullResync(master.serial()),
    }
    let mkey = slave.iprop_master_key();
    let mut updates = Vec::with_capacity(got.updates.len());
    for u in &got.updates {
        match krb5_kdc::decode_incr_update(u, mkey.as_ref()) {
            Ok((update, _)) => updates.push(update),
            Err(_) => return IpropPoll::FullResync(master.serial()),
        }
    }
    match slave.apply_updates(&updates) {
        Ok(()) => IpropPoll::Applied(updates.len()),
        Err(_) => IpropPoll::FullResync(master.serial()),
    }
}

pub fn kprop_send_dump(
    stream: &mut TcpStream,
    auth: &mut KpropAuth,
    dump: &[u8],
) -> Result<(), KpropError> {
    kprop_xmit_database(stream, auth, &mut &dump[..], dump.len() as u64, false)
}

pub fn kprop_send_store(
    stream: &mut TcpStream,
    store: &PrincipalStore,
    master: &ProtocolKey,
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &krb5_types::Realm,
    cname: &PrincipalName,
) -> Result<(), Error> {
    let dump = dump_store_with_key(store, master)
        .map(String::into_bytes)
        .map_err(|e| Error::Inner(e.to_string()))?;
    let creds = KpropCreds {
        ticket,
        session: session.clone(),
        client: cname.clone(),
        crealm: crealm.clone(),
        time_offset: 0,
        client_aware: false,
        client_aware_invalid: false,
    };
    let local = stream.local_addr().ok().map(|a| a.ip());
    let mut auth = kprop_sendauth(stream, &creds, local_host_address(local))
        .map_err(|e| Error::Inner(e.to_string()))?;
    kprop_send_dump(stream, &mut auth, &dump).map_err(|e| Error::Inner(e.to_string()))
}

#[cfg(all(test, feature = "test-hooks"))]
#[allow(
    clippy::disallowed_methods,
    reason = "a test sets up its own profile and environment"
)]
mod tests {
    use super::*;
    use krb5_crypto::CipherState;
    use krb5_kdc::testrealm::bootstrap_documented;
    use krb5_protocol::build_krb_priv_chained;

    use krb5_types::PrincipalName;

    fn kt_entry(name: &PrincipalName, kvno: u32, timestamp: u32, key: ProtocolKey) -> KeytabEntry {
        KeytabEntry {
            realm: krb5_types::ascii(krb5_kdc::testrealm::TEST_REALM),
            name: name.clone(),
            timestamp,
            kvno,
            key,
        }
    }

    fn aes(byte: u8) -> ProtocolKey {
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[byte; 32]).unwrap()
    }

    #[test]
    fn a_keytab_entry_is_chosen_as_mits_file_keytab_chooses_it() {
        let realm = krb5_kdc::testrealm::TEST_REALM.as_bytes();
        let kdc = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "kdc.kerber.test"]);
        let other = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.kerber.test"]);
        let entries = [
            kt_entry(&other, 7, 10, aes(7)),
            kt_entry(&kdc, 1, 10, aes(1)),
            kt_entry(&kdc, 3, 20, aes(3)),
            kt_entry(&kdc, 2, 30, aes(2)),
            kt_entry(&kdc, 257, 40, aes(9)),
        ];
        let got = |kvno: u32, etype: i32| match kt_get_entry(&entries, &kdc, realm, kvno, etype) {
            KtGet::Found(e) => Some(e.key.as_bytes()[0]),
            KtGet::KvnoNotFound => Some(0),
            KtGet::NotFound => None,
        };
        assert_eq!(got(3, 18), Some(3), "the matching kvno");
        assert_eq!(
            got(257, 18),
            Some(9),
            "a matching kvno beats a low-8-bit one"
        );
        assert_eq!(
            got(513, 18),
            Some(1),
            "the first entry of the low eight bits"
        );
        assert_eq!(got(0, 18), Some(9), "kvno 0: the most recent");
        assert_eq!(got(7, 18), Some(0), "another kvno: KVNONOTFOUND");
        assert_eq!(got(3, 17), None, "another enctype: no entry");
        assert_eq!(got(3, 0), Some(3), "enctype 0 is any");
        let wrapped = [
            kt_entry(&kdc, 250, 10, aes(250)),
            kt_entry(&kdc, 3, 20, aes(3)),
        ];
        let pick = |e: &[KeytabEntry], kvno| match kt_get_entry(e, &kdc, realm, kvno, 18) {
            KtGet::Found(e) => e.key.as_bytes()[0],
            _ => 0,
        };
        assert_eq!(
            pick(&wrapped, 0),
            3,
            "a small kvno written after a large one has wrapped"
        );
        let older = [
            kt_entry(&kdc, 250, 30, aes(250)),
            kt_entry(&kdc, 3, 20, aes(3)),
        ];
        assert_eq!(
            pick(&older, 0),
            250,
            "a small kvno written before a large one has not"
        );
        let zero = [kt_entry(&kdc, 0, 10, aes(5)), kt_entry(&kdc, 4, 10, aes(4))];
        assert_eq!(pick(&zero, 6), 5, "an entry of kvno 0 serves any kvno");
        assert_eq!(pick(&zero, 4), 4, "but a matching kvno ends the scan");
    }

    fn kdc_profile() -> krb5_config::ClientContext {
        let mut paths = vec![krb5_config::kdc_conf_path()];
        paths.extend(krb5_config::krb5_conf_paths());
        krb5_config::ClientContext::new(
            krb5_config::load_krb5_conf_paths(paths)
                .unwrap_or_else(|_| krb5_config::Krb5Conf::new()),
        )
    }

    #[test]
    fn kpropd_server_name_child() {
        if std::env::var_os("KERBER_KPROPD_NAME_CHILD").is_some() {
            let profile = kdc_profile().profile;
            for host in ["kdc2", "KDC2"] {
                match kpropd_server_name_for(host, &profile) {
                    Ok(name) => println!("{host}=[{}]", name.components_joined()),
                    Err(e) => println!("{host}=error {e}"),
                }
            }
        }
    }

    // MIT: `qualify_shortname` (lib/krb5/os/sn2princ.c:66-80)
    /// kpropd's context reads kdc.conf before krb5.conf, so kdc.conf's `qualify_shortname` qualifies a hostname without a dot, then krb5.conf's, then `LOCALDOMAIN`'s; under `fallback` the name stays as given, and a name this port cannot hold is an error.
    #[test]
    fn kpropd_names_itself_with_its_profiles_qualify_shortname() {
        let dir = krb5_testkit::scratch_dir("kpropd-own-name");
        let (kdc_q, kdc_plain, krb5_q, krb5_plain) = (
            dir.join("kdc-q.conf"),
            dir.join("kdc.conf"),
            dir.join("krb5-q.conf"),
            dir.join("krb5.conf"),
        );
        std::fs::write(&kdc_q, "[libdefaults]\n    qualify_shortname = kdc.test\n").unwrap();
        std::fs::write(&kdc_plain, "[kdcdefaults]\n").unwrap();
        std::fs::write(
            &krb5_q,
            "[libdefaults]\n    qualify_shortname = KRB5.test\n",
        )
        .unwrap();
        std::fs::write(&krb5_plain, "[libdefaults]\n    default_realm = R.TEST\n").unwrap();
        let krb5_fallback = dir.join("krb5-fallback.conf");
        std::fs::write(
            &krb5_fallback,
            "[libdefaults]\n    dns_canonicalize_hostname = fallback\n",
        )
        .unwrap();
        let run = |kdc: &std::path::Path, krb5: &std::path::Path, localdomain: &str| {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "kprop::tests::kpropd_server_name_child",
                    "--exact",
                    "--nocapture",
                ])
                .env("KERBER_KPROPD_NAME_CHILD", "1")
                .env("KRB5_KDC_PROFILE", kdc)
                .env("KRB5_CONFIG", krb5)
                .env("LOCALDOMAIN", localdomain)
                .env_remove("KRB5_KDC_CONF")
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        for (kdc, krb5, localdomain, want) in [
            (&kdc_q, &krb5_q, "env.test", "host/kdc2.kdc.test"),
            (&kdc_plain, &krb5_q, "env.test", "host/kdc2.krb5.test"),
            (&kdc_plain, &krb5_plain, "env.test", "host/kdc2.env.test"),
            (&kdc_q, &krb5_fallback, "env.test", "host/kdc2"),
        ] {
            let out = run(kdc, krb5, localdomain);
            assert!(out.contains(&format!("kdc2=[{want}]")), "{want}: {out}");
        }
        let out = run(&kdc_plain, &krb5_plain, "env.test");
        assert!(out.contains("KDC2=[host/kdc2.env.test]"), "{out}");
        let out = run(&kdc_plain, &krb5_fallback, "env.test");
        assert!(out.contains("KDC2=[host/KDC2]"), "{out}");
        let out = run(&kdc_plain, &krb5_plain, "\u{e9}.test");
        assert!(out.contains("kdc2=error "), "{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recvauth_tkt_expired_is_mit_error_message() {
        assert_eq!(recvauth_protocol_text(err::TKT_EXPIRED), "Ticket expired");
        assert_eq!(
            recvauth_protocol_text(err::NOKEY),
            "Service key not available"
        );
        assert_eq!(
            recvauth_protocol_text(err::BADMATCH),
            "Ticket/authenticator don't match"
        );
    }

    // MIT: `krb5_c_make_random_key` (lib/crypto/krb/make_random_key.c:31-76)
    /// `keybytes` random octets through the enctype's random-to-key, which gives des3 its parity.
    #[test]
    fn the_session_key_of_an_expired_ap_req_under_a_des3_host_key_has_odd_parity() {
        use krb5_asn1::decode;
        let host_key = ProtocolKey::random(EncryptionType::Des3CbcSha1).unwrap();
        let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "des3.kerber.test"]);
        for _ in 0..32 {
            let der = kprop_expired_ap_req(&host_key, 1, &host, "KERBER.TEST").unwrap();
            let ap: ApReq = decode(&der).unwrap();
            let usage = KeyUsage::new(ku::TICKET).unwrap();
            let plain = decrypt(&host_key, usage, ap.ticket.enc_part.cipher.as_ref()).unwrap();
            let part: EncTicketPart = decode(&plain).unwrap();
            assert_eq!(part.key.keytype, EncryptionType::Des3CbcSha1.to_iana());
            let key = part.key.keyvalue.as_ref();
            assert_eq!(key.len(), 24);
            assert!(key.iter().all(|b| b.count_ones() % 2 == 1), "{key:02x?}");
        }
    }

    #[test]
    fn kpropd_expired_ticket_is_32_ticket_expired() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_asn1::decode;
        use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented, documented_host};

        use krb5_protocol::ReplayCache;

        let (store, _) = bootstrap_documented().unwrap();
        let host = documented_host();
        let host_ent = store.get_name(&host).unwrap();
        let host_key = host_ent.best_key().unwrap().key.clone();
        let kvno = host_ent.best_key().unwrap().kvno;
        let ap = kprop_expired_ap_req(&host_key, kvno, &host, TEST_REALM).unwrap();
        let host_keys: Vec<_> = host_ent.keys.iter().map(|k| k.key.clone()).collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host_for_server = host.clone();
        let join = thread::spawn(move || {
            krb5_config::isolate_test_krb5();
            let (mut stream, _) = listener.accept().unwrap();
            kpropd_recvauth(
                &mut stream,
                &host_keys,
                Some(&host_for_server),
                Some(TEST_REALM),
                None,
                &ReplayCache::new(),
                &AcceptorConfig::default(),
            )
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = TcpStream::connect(addr).unwrap();
        write_message(&mut client, SENDAUTH_VERSION).unwrap();
        write_message(&mut client, KPROP_PROT_VERSION).unwrap();
        let mut ack = [0u8; 1];
        client.read_exact(&mut ack).unwrap();
        assert_eq!(ack[0], 0);
        write_message(&mut client, &ap).unwrap();
        let err_msg = read_message(&mut client).unwrap();
        assert_eq!(err_msg.first().copied(), Some(0x7e), "recvauth KRB-ERROR");
        let e: KrbError = decode(&err_msg).expect("KRB-ERROR");
        assert_eq!(e.error_code, err::TKT_EXPIRED);
        assert_eq!(
            e.e_text.as_ref().map(krb5_types::KerberosString::as_bytes),
            Some(b"Ticket expired\0".as_slice())
        );
        assert!(
            join.join().expect("thread").is_err(),
            "recvauth must fail after expired AP-REQ"
        );
    }

    #[test]
    fn kpropd_ap_req_fail_is_krb_error() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_asn1::decode;
        use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented, documented_host};

        use krb5_protocol::ReplayCache;

        let (store, _) = bootstrap_documented().unwrap();
        let host = documented_host();
        let host_keys: Vec<_> = store
            .get_name(&host)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.key.clone())
            .collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host_for_server = host.clone();
        let join = thread::spawn(move || {
            krb5_config::isolate_test_krb5();
            let (mut stream, _) = listener.accept().unwrap();
            kpropd_recvauth(
                &mut stream,
                &host_keys,
                Some(&host_for_server),
                Some(TEST_REALM),
                None,
                &ReplayCache::new(),
                &AcceptorConfig::default(),
            )
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = TcpStream::connect(addr).unwrap();
        write_message(&mut client, SENDAUTH_VERSION).unwrap();
        write_message(&mut client, KPROP_PROT_VERSION).unwrap();
        let mut ack = [0u8; 1];
        client.read_exact(&mut ack).unwrap();
        assert_eq!(ack[0], 0);
        write_message(&mut client, &[0xff, 0x00, 0x01]).unwrap();
        let err_msg = read_message(&mut client).unwrap();
        assert_eq!(err_msg.first().copied(), Some(0x7e), "recvauth KRB-ERROR");
        let e: KrbError = decode(&err_msg).expect("KRB-ERROR");
        assert_eq!(e.error_code, err::MSG_TYPE);
        assert_eq!(
            e.e_text.as_ref().map(krb5_types::KerberosString::as_bytes),
            Some(b"Invalid message type\0".as_slice())
        );
        assert!(
            join.join().expect("thread").is_err(),
            "recvauth must fail after junk AP-REQ"
        );
    }

    fn kprop_ticket() -> (Vec<ProtocolKey>, PrincipalName, krb5_kdc::IssuedTgs) {
        let (host_keys, admin, tgs) = kprop_ticket_kvnos();
        (host_keys.into_iter().map(|(k, _)| k).collect(), admin, tgs)
    }

    fn kprop_ticket_kvnos() -> (Vec<(ProtocolKey, u32)>, PrincipalName, krb5_kdc::IssuedTgs) {
        use krb5_kdc::testrealm::{TEST_REALM, documented_host};
        use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

        let (store, _) = bootstrap_documented().unwrap();
        let host = documented_host();
        let host_ent = store.get_name(&host).unwrap();
        let host_keys = host_ent
            .keys
            .iter()
            .map(|k| (k.key.clone(), k.kvno))
            .collect();
        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
        let admin_key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let pa = vec![pa_enc_timestamp(&admin_key).unwrap()];
        let as_out = krb5_kdc::issue_as(
            &store,
            &as_req(admin.clone(), TEST_REALM, 91, Some(pa)).unwrap(),
        )
        .unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &admin,
            host.clone(),
            TEST_REALM,
            92,
        )
        .unwrap();
        (host_keys, admin, krb5_kdc::issue_tgs(&store, &tgs).unwrap())
    }

    fn kprop_sends_ap_req(
        addr: std::net::SocketAddr,
        tgs: &krb5_kdc::IssuedTgs,
        admin: &PrincipalName,
    ) -> TcpStream {
        use std::io::Read;

        let mut client = TcpStream::connect(addr).unwrap();
        write_message(&mut client, SENDAUTH_VERSION).unwrap();
        write_message(&mut client, KPROP_PROT_VERSION).unwrap();
        let mut ack = [0u8; 1];
        client.read_exact(&mut ack).unwrap();
        assert_eq!(ack[0], 0);
        let realm = krb5_types::ascii(krb5_kdc::testrealm::TEST_REALM);
        let ap = build_ap_req_mutual_seq(
            tgs.rep.0.ticket.clone(),
            &tgs.session_key,
            &realm,
            admin,
            4242,
        )
        .unwrap();
        write_message(&mut client, &encode(&ap).unwrap()).unwrap();
        client
    }

    fn kpropd_with_keytab(
        keytab: impl FnOnce(&[(ProtocolKey, u32)], &Ticket) -> KpropdKeys,
        server: &PrincipalName,
    ) -> Option<KrbError> {
        kpropd_with_profile(None, keytab, server)
    }

    fn kpropd_with_profile(
        kdc_conf: Option<&'static str>,
        keytab: impl FnOnce(&[(ProtocolKey, u32)], &Ticket) -> KpropdKeys,
        server: &PrincipalName,
    ) -> Option<KrbError> {
        use std::net::TcpListener;
        use std::thread;

        use krb5_asn1::decode;
        use krb5_kdc::testrealm::TEST_REALM;

        let (host_keys, admin, tgs) = kprop_ticket_kvnos();
        let kt = keytab(&host_keys, &tgs.rep.0.ticket);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = server.clone();
        let join = thread::spawn(move || {
            krb5_config::isolate_test_krb5();
            let conf = kdc_conf.map_or_else(AcceptorConfig::default, |text| {
                let profile = krb5_config::Krb5Conf::parse_files(&[text]).unwrap();
                AcceptorConfig::from_krb5_conf(&profile)
            });
            let (mut stream, _) = listener.accept().unwrap();
            let keys = RecvauthKeys {
                keys: &[],
                keytab: Some(&kt),
            };
            recvauth_with(
                &mut stream,
                &keys,
                Some(&server),
                Some(TEST_REALM),
                &ReplayCache::new(),
                &conf,
            )
            .map(|_| ())
        });
        let mut client = kprop_sends_ap_req(addr, &tgs, &admin);
        let msg = read_message(&mut client).unwrap();
        drop(client);
        let _ = join.join().unwrap();
        (!msg.is_empty()).then(|| decode(&msg).expect("KRB-ERROR"))
    }

    fn e_text(e: &KrbError) -> &[u8] {
        e.e_text
            .as_ref()
            .map_or(b"", krb5_types::KerberosString::as_bytes)
    }

    fn host_entries(keys: &[(ProtocolKey, u32)]) -> Vec<KeytabEntry> {
        let host = krb5_kdc::testrealm::documented_host();
        keys.iter()
            .map(|(k, kvno)| kt_entry(&host, *kvno, 1, k.clone()))
            .collect()
    }

    fn wrong_key(ticket: &Ticket) -> ProtocolKey {
        let etype = EncryptionType::from_iana(ticket.enc_part.etype).unwrap();
        ProtocolKey::from_bytes(etype, &vec![9u8; etype.key_len()]).unwrap()
    }

    fn keytab(entries: Vec<KeytabEntry>, ignore_acceptor_hostname: bool) -> KpropdKeys {
        KpropdKeys {
            entries,
            error: None,
            ignore_acceptor_hostname,
            lookup: KpropdLookup::Server,
        }
    }

    #[test]
    fn kpropd_answers_only_as_its_own_host_principal() {
        let own = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "kdc9.kerber.test"]);
        let ticket_kvno = |t: &Ticket| t.enc_part.kvno.unwrap_or(0);
        let e = kpropd_with_keytab(
            |keys, t| {
                let mut entries = host_entries(keys);
                entries.push(kt_entry(&own, ticket_kvno(t), 1, wrong_key(t)));
                keytab(entries, false)
            },
            &own,
        )
        .unwrap();
        assert_eq!(e.error_code, err::NOT_US);
        assert_eq!(e_text(&e), b"The ticket isn't for us\0");
        assert_eq!(e.sname, own, "the KRB-ERROR names kpropd's own principal");
        let e = kpropd_with_keytab(
            |keys, t| {
                let mut entries = host_entries(keys);
                entries.push(kt_entry(&own, ticket_kvno(t) + 1, 1, wrong_key(t)));
                keytab(entries, false)
            },
            &own,
        )
        .unwrap();
        assert_eq!(
            e.error_code,
            err::NOT_US,
            "another kvno of kpropd's own key"
        );
        let e = kpropd_with_keytab(
            |keys, t| {
                let mut entries = host_entries(keys);
                let other = if t.enc_part.etype == 17 { 18 } else { 17 };
                let etype = EncryptionType::from_iana(other).unwrap();
                let key = ProtocolKey::from_bytes(etype, &vec![9u8; etype.key_len()]).unwrap();
                entries.push(kt_entry(&own, ticket_kvno(t), 1, key));
                keytab(entries, false)
            },
            &own,
        )
        .unwrap();
        assert_eq!(
            e.error_code,
            err::NOKEY,
            "no own entry of the ticket's enctype"
        );
        assert_eq!(e_text(&e), b"Service key not available\0");
        let host = krb5_kdc::testrealm::documented_host();
        for server in [&own, &host] {
            let e = kpropd_with_keytab(|_, _| keytab(Vec::new(), false), server).unwrap();
            assert_eq!(e.error_code, err::NOKEY, "{server:?}");
        }
    }

    #[test]
    fn kpropd_looks_its_entry_up_under_the_name_fallback_expands() {
        let raw = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "KDC2"]);
        let expand = |h: &str| format!("{}.kerber.test", h.to_ascii_lowercase());
        let want = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "kdc2.kerber.test"]);
        assert_eq!(
            kpropd_lookup_name(&raw, true, expand),
            KpropdLookup::Name(want)
        );
        assert_eq!(
            kpropd_lookup_name(&raw, false, expand),
            KpropdLookup::Server
        );
        let plain = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["host", "KDC2"]);
        assert_eq!(
            kpropd_lookup_name(&plain, true, expand),
            KpropdLookup::Server
        );
        let empty = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", ""]);
        assert_eq!(
            kpropd_lookup_name(&empty, true, expand),
            KpropdLookup::Server
        );
        let accented = |h: &str| format!("{h}.\u{e9}.test");
        assert_eq!(
            kpropd_lookup_name(&raw, true, accented),
            KpropdLookup::Unnamed,
            "a name this port cannot hold"
        );
        let host = krb5_kdc::testrealm::documented_host();
        let e = kpropd_with_keytab(
            |_, _| KpropdKeys {
                lookup: KpropdLookup::Name(host.clone()),
                ..keytab(Vec::new(), false)
            },
            &raw,
        )
        .unwrap();
        assert_eq!(e.error_code, err::NOKEY);
        assert_eq!(
            e.sname, raw,
            "the KRB-ERROR names the principal as kpropd made it"
        );
        assert_eq!(
            kpropd_with_keytab(
                |keys, _| KpropdKeys {
                    lookup: KpropdLookup::Name(host.clone()),
                    ..keytab(host_entries(keys), false)
                },
                &raw,
            ),
            None,
            "the entry of the expanded name takes the ticket"
        );
        let e = kpropd_with_keytab(
            |keys, _| KpropdKeys {
                lookup: KpropdLookup::Unnamed,
                ..keytab(host_entries(keys), false)
            },
            &raw,
        )
        .unwrap();
        assert_eq!(
            e.error_code,
            err::NOKEY,
            "an expanded name no entry can have"
        );
    }

    #[test]
    fn kpropd_checks_the_ticket_enctype_before_it_decrypts() {
        const AES128_ONLY: &str =
            "[libdefaults]\n    permitted_enctypes = aes128-cts-hmac-sha1-96\n";
        let host = krb5_kdc::testrealm::documented_host();
        let e = kpropd_with_profile(
            Some(AES128_ONLY),
            |_, t| {
                assert_ne!(t.enc_part.etype, 17, "the ticket's enctype must be another");
                let kvno = t.enc_part.kvno.unwrap_or(0);
                keytab(vec![kt_entry(&host, kvno, 1, wrong_key(t))], false)
            },
            &host,
        )
        .unwrap();
        assert_eq!(e.error_code, err::GENERIC);
        assert_eq!(e_text(&e), b"Encryption type not permitted\0");
        let e = kpropd_with_profile(
            Some(AES128_ONLY),
            |keys, _| keytab(host_entries(keys), true),
            &host,
        )
        .unwrap();
        assert_eq!(e.error_code, err::BAD_INTEGRITY, "the scan skips the entry");
    }

    #[test]
    fn kpropd_answers_a_default_keytab_that_does_not_resolve_as_mit() {
        let host = krb5_kdc::testrealm::documented_host();
        for ignore in [false, true] {
            let e = kpropd_with_keytab(
                |_, _| KpropdKeys {
                    error: Some(KpropdKeytabError::Resolve("Unknown Key table type".into())),
                    ..keytab(Vec::new(), ignore)
                },
                &host,
            )
            .unwrap();
            assert_eq!(
                e.error_code,
                err::GENERIC,
                "ignore_acceptor_hostname {ignore}"
            );
            assert_eq!(e_text(&e), b"Unknown Key table type\0");
        }
    }

    #[test]
    fn kpropd_ap_rep_echoes_no_subkey_and_takes_a_fresh_thirty_bit_seq() {
        use std::net::TcpListener;
        use std::thread;

        use krb5_asn1::decode;
        use krb5_crypto::{KeyUsage, decrypt_enc_data};
        use krb5_kdc::testrealm::{TEST_REALM, documented_host};
        use krb5_types::{ApRep, EncApRepPart, ku};

        let (host_keys, admin, tgs) = kprop_ticket();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            krb5_config::isolate_test_krb5();
            #[cfg(feature = "test-hooks")]
            krb5_protocol::set_test_seq_random(Some(0xc123_4567));
            let allowed = [format!("admin@{TEST_REALM}")];
            let (mut stream, _) = listener.accept().unwrap();
            kpropd_recvauth(
                &mut stream,
                &host_keys,
                Some(&documented_host()),
                Some(TEST_REALM),
                Some(allowed.as_slice()),
                &ReplayCache::new(),
                &AcceptorConfig::default(),
            )
        });
        let mut client = kprop_sends_ap_req(addr, &tgs, &admin);
        assert!(read_message(&mut client).unwrap().is_empty(), "accepted");
        let rep: ApRep = decode(&read_message(&mut client).unwrap()).unwrap();
        let usage = KeyUsage::new(ku::AP_REP_ENC_PART).unwrap();
        let plain = decrypt_enc_data(
            &tgs.session_key,
            usage,
            rep.enc_part.etype,
            rep.enc_part.cipher.as_ref(),
        )
        .unwrap();
        let part: EncApRepPart = decode(&plain).unwrap();
        assert_eq!(
            part.subkey, None,
            "kprop sends no subkey, so none is echoed"
        );
        let seq = part.seq_number.unwrap();
        #[cfg(feature = "test-hooks")]
        assert_eq!(
            seq, 0x0123_4567,
            "krb5_generate_seq_number: 30 bits of the random octets"
        );
        assert!(
            seq != 0 && seq < 1 << 30 && seq != 4242,
            "fresh 30-bit seq, got {seq}"
        );
        let auth = join.join().expect("thread").unwrap();
        assert_eq!(
            auth.local_seq, seq,
            "the size SAFE carries the AP-REP's seq"
        );
    }

    #[test]
    fn kpropd_refuses_an_enctype_it_does_not_permit() {
        use std::net::TcpListener;
        use std::thread;

        use krb5_asn1::decode;
        use krb5_kdc::testrealm::{TEST_REALM, documented_host};

        let (host_keys, admin, tgs) = kprop_ticket();
        assert_eq!(
            tgs.session_key.etype(),
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196
        );
        let profile = krb5_config::Krb5Conf::parse(
            "[libdefaults]\n    permitted_enctypes = aes128-cts-hmac-sha1-96\n",
        )
        .unwrap();
        let conf = AcceptorConfig::from_krb5_conf(&profile);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            krb5_config::isolate_test_krb5();
            let (mut stream, _) = listener.accept().unwrap();
            kpropd_recvauth(
                &mut stream,
                &host_keys,
                Some(&documented_host()),
                Some(TEST_REALM),
                None,
                &ReplayCache::new(),
                &conf,
            )
        });
        let mut client = kprop_sends_ap_req(addr, &tgs, &admin);
        let e: KrbError = decode(&read_message(&mut client).unwrap()).expect("KRB-ERROR");
        assert_eq!(e.error_code, err::GENERIC);
        assert_eq!(
            e.e_text.as_ref().map(krb5_types::KerberosString::as_bytes),
            Some(b"Encryption type not permitted\0".as_slice())
        );
        assert!(join.join().expect("thread").is_err());
    }

    #[test]
    fn kpropd_names_its_host_principal_in_a_refusal() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        use krb5_asn1::decode;
        use krb5_kdc::testrealm::TEST_REALM;

        let (host_keys, _, _) = kprop_ticket();
        let own = kpropd_server_name(&krb5_config::Krb5Conf::new()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            krb5_config::isolate_test_krb5();
            let (mut stream, _) = listener.accept().unwrap();
            kpropd_recvauth(
                &mut stream,
                &host_keys,
                Some(&own),
                Some(TEST_REALM),
                None,
                &ReplayCache::new(),
                &AcceptorConfig::default(),
            )
        });
        let mut client = TcpStream::connect(addr).unwrap();
        write_message(&mut client, SENDAUTH_VERSION).unwrap();
        write_message(&mut client, KPROP_PROT_VERSION).unwrap();
        let mut ack = [0u8; 1];
        client.read_exact(&mut ack).unwrap();
        write_message(&mut client, &[0xff, 0x00, 0x01]).unwrap();
        let e: KrbError = decode(&read_message(&mut client).unwrap()).expect("KRB-ERROR");
        assert!(join.join().expect("thread").is_err());
        let parts: Vec<_> = e
            .sname
            .name_string
            .iter()
            .map(krb5_types::KerberosString::as_bytes)
            .collect();
        assert_eq!(
            parts.len(),
            2,
            "sn2princ_realm's host/<this host>, not ????"
        );
        assert_eq!(parts[0], b"host");
        assert_ne!(parts[1], b"", "a host name");
        assert_eq!(e.sname.name_type, PrincipalName::NT_SRV_HST);
        assert_eq!(e.realm.as_bytes(), TEST_REALM.as_bytes());
    }

    fn kpropd_answer_to(size_seq: u32, block_seq: u32, short_by: u64) -> KrbError {
        use std::net::TcpListener;
        use std::thread;

        use krb5_asn1::decode;
        use krb5_kdc::testrealm::{TEST_REALM, documented_host};

        let (host_keys, admin, tgs) = kprop_ticket();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            krb5_config::isolate_test_krb5();
            let allowed = [format!("admin@{TEST_REALM}")];
            let (mut stream, _) = listener.accept().unwrap();
            let mut auth = kpropd_recvauth(
                &mut stream,
                &host_keys,
                Some(&documented_host()),
                Some(TEST_REALM),
                Some(allowed.as_slice()),
                &ReplayCache::new(),
                &AcceptorConfig::default(),
            )
            .unwrap();
            kpropd_recv_dump(&mut stream, &mut auth)
        });
        let mut client = kprop_sends_ap_req(addr, &tgs, &admin);
        assert!(read_message(&mut client).unwrap().is_empty(), "accepted");
        let _ap_rep = read_message(&mut client).unwrap();
        let dump = b"kdb5_util load_dump version 7\n";
        let size = encode_database_size(dump.len() as u64 - short_by);
        let safe =
            build_mit_safe(&tgs.session_key, &size, size_seq, &local_host_address(None)).unwrap();
        write_message(&mut client, &safe).unwrap();
        if size_seq == 4242 {
            let mut state = CipherState::initial();
            let block =
                build_krb_priv_chained(&tgs.session_key, dump, Some(block_seq), false, &mut state)
                    .unwrap();
            write_message(&mut client, &encode(&block).unwrap()).unwrap();
        }
        let e: KrbError = decode(&read_message(&mut client).unwrap()).expect("KRB-ERROR");
        // MIT goes on past a dump longer than its size.
        assert_eq!(join.join().expect("thread").is_err(), short_by == 0);
        assert_eq!(e.cname, Some(admin), "send_error names the client");
        e
    }

    #[test]
    fn kpropd_refuses_kprops_messages_out_of_sequence() {
        let size = kpropd_answer_to(4243, 0, 0);
        assert_eq!(size.error_code, err::BADORDER);
        assert_eq!(
            size.e_text
                .as_ref()
                .map(krb5_types::KerberosString::as_bytes),
            Some(b"while decoding database size\0".as_slice())
        );
        let block = kpropd_answer_to(4242, 4244, 0);
        assert_eq!(block.error_code, err::BADORDER);
        assert_eq!(
            block
                .e_text
                .as_ref()
                .map(krb5_types::KerberosString::as_bytes),
            Some(b"while decoding database block starting at offset 0\0".as_slice())
        );
    }

    #[test]
    fn kpropd_reports_a_dump_longer_than_its_size() {
        let e = kpropd_answer_to(4242, 4243, 5);
        assert_eq!(e.error_code, err::GENERIC);
        assert_eq!(
            e.e_text.as_ref().map(krb5_types::KerberosString::as_bytes),
            Some(b"Received 30 bytes, expected 25 bytes for database file\0".as_slice())
        );
    }

    #[test]
    fn kprop_refuses_an_ack_out_of_sequence() {
        use std::net::TcpListener;
        use std::thread;

        use krb5_kdc::testrealm::{TEST_REALM, documented_host};

        let (host_keys, admin, tgs) = kprop_ticket();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let dump = b"kdb5_util load_dump version 7\n".to_vec();
        let join = thread::spawn(move || {
            krb5_config::isolate_test_krb5();
            let allowed = [format!("admin@{TEST_REALM}")];
            let (mut stream, _) = listener.accept().unwrap();
            let mut auth = kpropd_recvauth(
                &mut stream,
                &host_keys,
                Some(&documented_host()),
                Some(TEST_REALM),
                Some(allowed.as_slice()),
                &ReplayCache::new(),
                &AcceptorConfig::default(),
            )
            .unwrap();
            let got = kpropd_recv_dump(&mut stream, &mut auth).unwrap();
            auth.next_local_seq();
            kpropd_send_ack(&mut stream, &mut auth, got.len() as u64).unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let creds = KpropCreds {
            ticket: tgs.rep.0.ticket.clone(),
            session: tgs.session_key.clone(),
            client: admin.clone(),
            crealm: krb5_types::ascii(TEST_REALM),
            time_offset: 0,
            client_aware: false,
            client_aware_invalid: false,
        };
        let mut auth = kprop_sendauth(&mut client, &creds, local_host_address(None)).unwrap();
        let e = kprop_send_dump(&mut client, &mut auth, &dump).unwrap_err();
        assert!(
            e.to_string()
                .contains("Message out of order while decoding final size packet from server"),
            "{e}"
        );
        join.join().expect("thread");
    }

    /// a twelve-byte size that fits in four, a non-zero lead, or any other length is refused.
    #[test]
    fn a_dump_size_is_four_bytes_or_twelve_as_mits() {
        assert_eq!(encode_database_size(0), [0u8; 12]);
        assert_eq!(encode_database_size(1), [0, 0, 0, 1]);
        assert_eq!(
            encode_database_size(u64::from(u32::MAX)),
            [0xff, 0xff, 0xff, 0xff]
        );
        let big = encode_database_size(1 << 32);
        assert_eq!(big, [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
        for n in [0, 1, 0x1692, u64::from(u32::MAX), 1 << 32, u64::MAX] {
            assert_eq!(decode_database_size(&encode_database_size(n)).unwrap(), n);
        }
        let mut small_in_twelve = [0u8; 12];
        small_in_twelve[11] = 5;
        assert!(decode_database_size(&small_in_twelve).is_err());
        let mut lead = [0u8; 12];
        lead[0] = 1;
        assert!(decode_database_size(&lead).is_err());
        assert!(decode_database_size(&[0u8; 8]).is_err());
        assert!(decode_database_size(&[]).is_err());
    }

    fn size_safe_from_kprop(
        dump: &'static [u8],
        sender: HostAddress,
    ) -> (krb5_types::KrbSafe, u32, Result<(), KpropError>) {
        use std::net::TcpListener;
        use std::thread;

        use krb5_kdc::testrealm::{TEST_REALM, documented_host};

        let (host_keys, admin, tgs) = kprop_ticket();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            krb5_config::isolate_test_krb5();
            let allowed = [format!("admin@{TEST_REALM}")];
            let (mut stream, _) = listener.accept().unwrap();
            let auth = kpropd_recvauth(
                &mut stream,
                &host_keys,
                Some(&documented_host()),
                Some(TEST_REALM),
                Some(allowed.as_slice()),
                &ReplayCache::new(),
                &AcceptorConfig::default(),
            )
            .unwrap();
            let safe: krb5_types::KrbSafe = decode(&read_message(&mut stream).unwrap()).unwrap();
            (safe, auth.remote.expected())
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let creds = KpropCreds {
            ticket: tgs.rep.0.ticket.clone(),
            session: tgs.session_key.clone(),
            client: admin,
            crealm: krb5_types::ascii(TEST_REALM),
            time_offset: 0,
            client_aware: false,
            client_aware_invalid: false,
        };
        let mut auth = kprop_sendauth(&mut client, &creds, sender).unwrap();
        let sent = kprop_send_dump(&mut client, &mut auth, dump);
        let (safe, expected) = join.join().expect("kpropd thread");
        (safe, expected, sent)
    }

    // MIT: `xmit_database` (kprop/kprop.c:421-439)
    /// The size goes from kprop's own address (its auth context's local one), with no receiver,
    /// with the authenticator's random 30-bit sequence number. Empty dump: size is 12 zero bytes.
    #[test]
    fn kprop_sends_its_size_from_its_own_address_with_the_authenticators_seq() {
        let sender = HostAddress {
            addr_type: 2,
            address: vec![192, 0, 2, 7].into(),
        };
        let (safe, expected, sent) = size_safe_from_kprop(b"", sender.clone());
        assert_eq!(safe.safe_body.s_address, sender);
        assert_eq!(safe.safe_body.r_address, None);
        assert_eq!(safe.safe_body.timestamp, None);
        let seq = safe.safe_body.seq_number.expect("a sequence number");
        assert_eq!(seq, expected, "the authenticator's");
        assert!(seq > 0 && seq < 1 << 30, "{seq}");
        assert_eq!(safe.safe_body.user_data.as_ref(), [0u8; 12]);
        assert!(sent.is_err(), "no acknowledgement came");
        let (other, _, _) = size_safe_from_kprop(b"x", local_host_address(None));
        assert_ne!(
            other.safe_body.seq_number,
            Some(seq),
            "a fresh one each time"
        );
        assert_eq!(other.safe_body.user_data.as_ref(), [0, 0, 0, 1]);
    }

    fn kprop_creds(time_offset: i64) -> (Vec<ProtocolKey>, KpropCreds) {
        use krb5_kdc::testrealm::TEST_REALM;

        let (host_keys, admin, tgs) = kprop_ticket();
        let creds = KpropCreds {
            ticket: tgs.rep.0.ticket.clone(),
            session: tgs.session_key.clone(),
            client: admin,
            crealm: krb5_types::ascii(TEST_REALM),
            time_offset,
            client_aware: false,
            client_aware_invalid: false,
        };
        (host_keys, creds)
    }

    // MIT: `verify_as_reply` (lib/krb5/krb/get_in_tkt.c:260-264)
    /// The AS reply sets the context's clock to the KDC's, so the authenticator carries its time.
    /// A host an hour off the KDC and kpropd is refused only when kprop dates it by its own clock.
    #[test]
    fn kprop_dates_its_authenticator_by_the_kdcs_clock() {
        use std::net::TcpListener;
        use std::thread;

        use krb5_kdc::testrealm::{TEST_REALM, documented_host};

        for (offset, accepted) in [(0, true), (3600, false), (-3600, false)] {
            let (host_keys, creds) = kprop_creds(offset);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let join = thread::spawn(move || {
                krb5_config::isolate_test_krb5();
                let allowed = [format!("admin@{TEST_REALM}")];
                let (mut stream, _) = listener.accept().unwrap();
                kpropd_recvauth(
                    &mut stream,
                    &host_keys,
                    Some(&documented_host()),
                    Some(TEST_REALM),
                    Some(allowed.as_slice()),
                    &ReplayCache::new(),
                    &AcceptorConfig::default(),
                )
                .is_ok()
            });
            let mut client = TcpStream::connect(addr).unwrap();
            let sent = kprop_sendauth(&mut client, &creds, local_host_address(None));
            assert_eq!(join.join().expect("kpropd thread"), accepted, "{offset}");
            match sent {
                Ok(_) => assert!(accepted, "{offset}"),
                Err(e) => {
                    assert!(!accepted, "{offset}: {e}");
                    assert_eq!(
                        e.lines("kprop"),
                        [
                            "kprop: Server rejected authentication (during sendauth exchange) while authenticating to server",
                            "kprop: Clock skew too great signalled from server",
                            "Error text from server: Clock skew too great",
                        ],
                        "{offset}"
                    );
                }
            }
        }
    }

    // MIT: `krb5_read_message` (lib/krb5/os/read_msg.c:52-54)
    /// A reply's length is allocated as stated; past 8 MiB this kprop refuses it as a failed
    /// allocation (docs/mit-deviations.md).
    #[test]
    fn kprop_refuses_a_reply_past_eight_mib() {
        use std::net::TcpListener;
        use std::thread;

        let (_, creds) = kprop_creds(0);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // The two version strings, sendauth's answer, the AP-REQ, then a refusal whose length is 8 MiB and one byte.
            for _ in 0..2 {
                read_message(&mut stream).unwrap();
            }
            stream.write_all(&[0]).unwrap();
            read_message(&mut stream).unwrap();
            stream
                .write_all(&(8 * 1024 * 1024 + 1u32).to_be_bytes())
                .unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let Err(e) = kprop_sendauth(&mut client, &creds, local_host_address(None)) else {
            panic!("a reply past 8 MiB was read");
        };
        assert_eq!(
            e.lines("kprop"),
            ["kprop: Cannot allocate memory while authenticating to server"]
        );
        join.join().expect("fake kpropd");
    }
}
