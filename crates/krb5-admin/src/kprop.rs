//! MIT-wire kprop/kpropd on TCP 754 wrapping a version-7 dump.
//!
//! Framing (MIT 1.22.2 `kprop.c` / `kpropd.c`):
//! `sendauth` (`KRB5_SENDAUTH_V1.0` then `kprop5_01`) with
//! `AP_OPTS_MUTUAL_REQUIRED`; KRB-SAFE 4-byte BE dump size; `initivector`;
//! KRB-PRIV 32768-byte dump chunks; KRB-SAFE size ack. Payload is MIT
//! `kdb5_util` dump text, not KDB3.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;

use krb5_asn1::{decode, encode};
use krb5_crypto::{CipherState, EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_kdc::{Acl, PrincipalStore, dump_store, dump_store_iprop, load_dump, save_store};
use krb5_protocol::{
    ApVerifyParams, ReplayCache, build_ap_rep, build_ap_req_mutual_seq, build_krb_priv_chained,
    build_krb_safe_ex, unwrap_krb_priv_chained, verify_ap_rep, verify_ap_req_ex,
    verify_krb_safe_checksum,
};
use krb5_types::{
    EncTicketPart, EncryptedData, EncryptionKey, KerberosTime, KrbError, Microseconds,
    PrincipalName, Ticket, TicketFlags, TransitedEncoding, err, ku,
};

use crate::Error;

/// MIT `KPROP_PROT_VERSION`.
const KPROP_PROT_VERSION: &[u8] = b"kprop5_01\0";
/// MIT `KRB5_SENDAUTH_V1.0`.
const SENDAUTH_VERSION: &[u8] = b"KRB5_SENDAUTH_V1.0\0";
/// MIT `KPROP_BUFSIZ`.
const KPROP_BUFSIZ: usize = 32_768;

/// Dump text from a store (version 7). Used as the kprop body.
///
/// # Errors
///
/// Dump crypto failures.
pub fn kprop_dump_bytes(store: &PrincipalStore, master_password: &[u8]) -> Result<Vec<u8>, Error> {
    dump_store(store, master_password)
        .map(String::into_bytes)
        .map_err(|e| Error::Inner(e.to_string()))
}

/// MIT `kdb5_util dump -i1` body so `kpropd -A` `load -i` sets replica last_sno.
///
/// # Errors
///
/// Dump crypto failures.
pub fn kprop_dump_iprop(store: &PrincipalStore, master_password: &[u8]) -> Result<Vec<u8>, Error> {
    dump_store_iprop(store, master_password)
        .map(String::into_bytes)
        .map_err(|e| Error::Inner(e.to_string()))
}

/// Load a kprop body as dump version 6/7. Rejects KDB3 magic and truncated
/// headers.
///
/// # Errors
///
/// Not a dump, parse, or crypto failures.
pub fn kprop_load_bytes(bytes: &[u8], master_password: &[u8]) -> Result<PrincipalStore, Error> {
    if bytes.starts_with(b"KDB1") || bytes.starts_with(b"KDB2") || bytes.starts_with(b"KDB3") {
        return Err(Error::Inner(
            "kprop body is a private KDB blob, not a MIT dump".into(),
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|e| Error::Inner(e.to_string()))?;
    if !text.starts_with("kdb5_util load_dump version ")
        && !text.starts_with("ipropx ")
        && !text.starts_with("iprop ")
    {
        return Err(Error::Inner("kprop body missing dump header".into()));
    }
    load_dump(text, master_password).map_err(|e| Error::Inner(e.to_string()))
}

fn write_message(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len()).unwrap_or(0);
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()
}

fn read_message(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
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

fn encode_database_size(size: u64) -> Vec<u8> {
    if let Ok(n) = u32::try_from(size) {
        n.to_be_bytes().to_vec()
    } else {
        let mut b = vec![0u8; 12];
        b[0..4].copy_from_slice(&0u32.to_be_bytes());
        b[4..12].copy_from_slice(&size.to_be_bytes());
        b
    }
}

fn decode_database_size(buf: &[u8]) -> Result<u64, Error> {
    match buf.len() {
        4 => Ok(u64::from(u32::from_be_bytes(
            buf.try_into().map_err(|_| Error::Inner("size".into()))?,
        ))),
        12 => {
            if buf[..4] != [0, 0, 0, 0] {
                return Err(Error::Inner("non-compact 64-bit dump size".into()));
            }
            Ok(u64::from_be_bytes(
                buf[4..12]
                    .try_into()
                    .map_err(|_| Error::Inner("size64".into()))?,
            ))
        }
        _ => Err(Error::Inner("dump size length".into())),
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

/// MIT `create_krbsafe`: checksum the full KRB-SAFE encoding with a
/// zero-type/zero-length checksum, then replace the checksum.
fn mit_safe_dummy_der(msg: &krb5_types::KrbSafe) -> Result<Vec<u8>, Error> {
    let mut dummy = msg.clone();
    dummy.cksum = krb5_types::Checksum {
        cksumtype: 0,
        checksum: Vec::new().into(),
    };
    encode(&dummy).map_err(|e| Error::Inner(e.to_string()))
}

fn verify_safe_user_data(
    session: &ProtocolKey,
    raw: &[u8],
) -> Result<(Vec<u8>, Option<u32>), Error> {
    let msg: krb5_types::KrbSafe = decode(raw).map_err(|e| Error::Inner(e.to_string()))?;
    verify_krb_safe_checksum(session, &msg).map_err(|e| Error::Inner(e.to_string()))?;
    Ok((msg.safe_body.user_data.to_vec(), msg.safe_body.seq_number))
}

fn build_mit_safe(session: &ProtocolKey, user_data: &[u8], seq: u32) -> Result<Vec<u8>, Error> {
    let safe = build_krb_safe_ex(session, user_data, Some(seq), false)
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

/// Established kprop session (session key + sequence).
pub struct KpropAuth {
    session: ProtocolKey,
    local_seq: u32,
    remote_seq: Option<u32>,
    replay: ReplayCache,
}

impl KpropAuth {
    fn check_remote_seq(&mut self, got: Option<u32>) -> Result<(), Error> {
        let s = got.ok_or_else(|| Error::Inner("kprop missing seq".into()))?;
        if let Some(prev) = self.remote_seq
            && s != prev.wrapping_add(1)
        {
            return Err(Error::Inner(format!(
                "kprop seq {s} want {}",
                prev.wrapping_add(1)
            )));
        }
        self.remote_seq = Some(s);
        Ok(())
    }

    fn next_local_seq(&mut self) -> u32 {
        let s = self.local_seq;
        self.local_seq = self.local_seq.wrapping_add(1);
        s
    }
}

/// Replica: `recvauth` then dump bytes (caller loads).
///
/// # Errors
///
/// I/O, sendauth, or dump framing.
pub fn kpropd_recvauth(
    stream: &mut TcpStream,
    host_keys: &[ProtocolKey],
    expected_server: Option<&PrincipalName>,
    expected_realm: Option<&str>,
    allowed_clients: Option<&[String]>,
    replay: ReplayCache,
) -> Result<KpropAuth, Error> {
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
    let params = ApVerifyParams {
        keys: host_keys,
        kvno: None,
        expected_server,
        expected_realm,
        skew: 300,
        addresses: None,
        now: None,
    };
    let ok = match verify_ap_req_ex(&ap_raw, &params, &replay, None) {
        Ok(v) => v,
        Err(e) => {
            let der = kprop_rd_req_error(&ap_raw, &e, expected_realm, expected_server);
            let _ = write_message(stream, &der);
            return Err(Error::Inner(e.to_string()));
        }
    };
    let crealm = String::from_utf8_lossy(ok.authenticator.crealm.as_bytes());
    let client = ok.authenticator.cname.unparse_with_realm(&crealm);
    if !kpropd_client_allowed(&client, allowed_clients) {
        let _ = write_message(stream, &[]);
        return Err(Error::AclDenied);
    }
    write_message(stream, &[]).map_err(|e| Error::Inner(e.to_string()))?;
    let session = session_from_ticket(&ok)?;
    let mut local_seq = 1u32;
    if ok.mutual_required {
        let mut buf = [0u8; 4];
        let _ = getrandom::getrandom(&mut buf);
        local_seq = u32::from_be_bytes(buf);
        if local_seq == 0 {
            local_seq = 1;
        }
        let ap_rep = build_ap_rep(&session, &ok.authenticator, None, Some(local_seq))
            .map_err(|e| Error::Inner(e.to_string()))?;
        let der = encode(&ap_rep).map_err(|e| Error::Inner(e.to_string()))?;
        write_message(stream, &der).map_err(|e| Error::Inner(e.to_string()))?;
        // MIT `rd_rep` stores this seq as remote_seq; the size-ack SAFE
        // must use the same value (then increment).
    }
    Ok(KpropAuth {
        session,
        local_seq,
        remote_seq: None,
        replay,
    })
}

fn kpropd_client_allowed(client: &str, allowed: Option<&[String]>) -> bool {
    allowed.is_some_and(|patterns| patterns.iter().any(|p| Acl::name_matches(p, client)))
}

/// MIT `krb5int_is_app_tag(dat, 14)` (`k5-int.h:1334-1336`).
fn is_ap_req(raw: &[u8]) -> bool {
    raw.first().is_some_and(|b| b & !0x20 == 0x4e)
}

fn recvauth_error_fields(raw: &[u8], e: &krb5_protocol::Error) -> (i32, String) {
    if !is_ap_req(raw) {
        return (err::MSG_TYPE, "Invalid message type".into());
    }
    match e {
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
    match code {
        err::BAD_INTEGRITY => "Decrypt integrity check failed".into(),
        err::NOKEY => "Service key not available".into(),
        err::TKT_EXPIRED => "Ticket expired".into(),
        err::TKT_NYV => "Ticket not yet valid".into(),
        err::REPEAT => "Request is a replay".into(),
        err::NOT_US => "The ticket isn't for us".into(),
        err::BADMATCH => "Ticket/authenticator don't match".into(),
        err::BADADDR => "Incorrect net address".into(),
        err::SKEW => "Clock skew too great".into(),
        err::BADVERSION => "Protocol version mismatch".into(),
        err::MSG_TYPE => "Invalid message type".into(),
        err::MODIFIED => "Message stream modified".into(),
        err::BADORDER => "Message out of order".into(),
        err::ILL_CR_TKT => "Illegal cross-realm ticket".into(),
        err::BADKEYVER => "Key version is not available".into(),
        err::MUT_FAIL => "Mutual authentication failed".into(),
        err::BADDIRECTION => "Incorrect message direction".into(),
        err::METHOD => "Alternative authentication method required".into(),
        err::BADSEQ => "Incorrect sequence number in message".into(),
        err::INAPP_CKSUM => "Inappropriate type of checksum in message".into(),
        err::GENERIC => "Generic error (see e-text)".into(),
        _ => format!("KRB5 error code {code}"),
    }
}

/// AP-REQ whose ticket `endtime` is 400s in the past (beyond the 300s skew).
///
/// # Errors
///
/// Crypto or DER failures.
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
    let mut kb = vec![0u8; host_key.etype().key_len()];
    getrandom::getrandom(&mut kb).map_err(|e| Error::Inner(e.to_string()))?;
    let session =
        ProtocolKey::from_bytes(host_key.etype(), &kb).map_err(|e| Error::Inner(e.to_string()))?;
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

/// MIT `recvauth.c:150-188`: AP-REQ failure is a length-prefixed KRB-ERROR.
fn kprop_rd_req_error(
    raw: &[u8],
    e: &krb5_protocol::Error,
    realm: Option<&str>,
    server: Option<&PrincipalName>,
) -> Vec<u8> {
    let (code, text) = recvauth_error_fields(raw, e);
    let realm_s = realm.unwrap_or("????");
    let realm_ks = match krb5_types::try_ascii(realm_s) {
        Ok(r) => r,
        Err(_) => match krb5_types::try_ascii("INVALID") {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        },
    };
    let sname = server
        .cloned()
        .unwrap_or_else(|| PrincipalName::new(PrincipalName::NT_UNKNOWN, ["????"]));
    let pdu = KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: code,
        crealm: None,
        cname: None,
        realm: realm_ks,
        sname,
        e_text: e_text_with_nul(&text),
        e_data: None,
    };
    encode(&pdu).unwrap_or_default()
}

/// Receive dump bytes after [`kpropd_recvauth`].
///
/// # Errors
///
/// SAFE/PRIV unwrap or I/O.
pub fn kpropd_recv_dump(stream: &mut TcpStream, auth: &mut KpropAuth) -> Result<Vec<u8>, Error> {
    let size_raw = read_message(stream).map_err(|e| Error::Inner(e.to_string()))?;
    let (size_plain, size_seq) = verify_safe_user_data(&auth.session, &size_raw)?;
    auth.check_remote_seq(size_seq)?;
    let want = decode_database_size(&size_plain)?;
    let mut state = CipherState::initial();
    let mut dump = Vec::with_capacity(usize::try_from(want).unwrap_or(0));
    while (dump.len() as u64) < want {
        let chunk_raw = read_message(stream).map_err(|e| Error::Inner(e.to_string()))?;
        let chunk = unwrap_krb_priv_chained(
            &auth.session,
            &chunk_raw,
            &auth.replay,
            true,
            false,
            &mut state,
        )
        .map_err(|e| Error::Inner(format!("priv chunk: {e}")))?;
        dump.extend_from_slice(&chunk);
        if let Some(prev) = auth.remote_seq {
            auth.remote_seq = Some(prev.wrapping_add(1));
        }
    }
    if dump.len() as u64 != want {
        return Err(Error::Inner(format!(
            "kprop dump {} bytes, expected {want}",
            dump.len()
        )));
    }
    Ok(dump)
}

/// Send the SAFE size-ack MIT `kprop` waits for.
///
/// # Errors
///
/// SAFE encode or I/O.
pub fn kpropd_send_ack(
    stream: &mut TcpStream,
    auth: &mut KpropAuth,
    size: u64,
) -> Result<(), Error> {
    let seq = auth.next_local_seq();
    let body = encode_database_size(size);
    let der = build_mit_safe(&auth.session, &body, seq)?;
    write_message(stream, &der).map_err(|e| Error::Inner(e.to_string()))?;
    Ok(())
}

/// Full replica handler: recvauth, dump v7 body, `load_dump`, persist, ack.
///
/// # Errors
///
/// Auth, dump, persist, or I/O.
#[allow(clippy::too_many_arguments)]
pub fn kpropd_handle_conn(
    stream: &mut TcpStream,
    host_keys: &[ProtocolKey],
    expected_server: Option<&PrincipalName>,
    expected_realm: Option<&str>,
    master_password: &[u8],
    db: &Path,
    stash: &Path,
    allowed_clients: Option<&[String]>,
    replay: ReplayCache,
) -> Result<PrincipalStore, Error> {
    let mut auth = kpropd_recvauth(
        stream,
        host_keys,
        expected_server,
        expected_realm,
        allowed_clients,
        replay,
    )?;
    let dump = kpropd_recv_dump(stream, &mut auth)?;
    let store = kprop_load_bytes(&dump, master_password)?;
    save_store(&store, db, stash).map_err(|e| Error::Inner(e.to_string()))?;
    kpropd_send_ack(stream, &mut auth, dump.len() as u64)?;
    tracing::info!(
        event = krb5_log::events::ADMIN,
        component = "krb5-admin",
        outcome = "ok",
        detail = "kpropd dump v7",
        nbytes = dump.len(),
    );
    Ok(store)
}

/// One in-process iprop poll (serial-delta or full-resync signal).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpropPoll {
    /// Applied `n` ulog entries.
    Applied(usize),
    /// No new serials.
    Nil,
    /// Replica should take a full dump (`kpropd_handle_conn`).
    FullResync(u32),
}

/// Pull `master` ulog into `slave`. `last_sno == 0` is full resync (MIT).
pub fn iprop_poll_once(master: &PrincipalStore, slave: &mut PrincipalStore) -> IpropPoll {
    let last = slave.serial();
    let (st, _, entries) = master.iprop_get(last);
    if st == krb5_kdc::IPROP_FULL_RESYNC {
        return IpropPoll::FullResync(master.serial());
    }
    if st == krb5_kdc::IPROP_NIL || entries.is_empty() {
        return IpropPoll::Nil;
    }
    let n = entries.len();
    slave.apply_updates(&entries);
    IpropPoll::Applied(n)
}

/// Primary: `sendauth` then dump bytes.
///
/// # Errors
///
/// I/O or sendauth.
pub fn kprop_sendauth(
    stream: &mut TcpStream,
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &krb5_types::Realm,
    cname: &PrincipalName,
    seq: u32,
) -> Result<KpropAuth, Error> {
    write_message(stream, SENDAUTH_VERSION).map_err(|e| Error::Inner(e.to_string()))?;
    write_message(stream, KPROP_PROT_VERSION).map_err(|e| Error::Inner(e.to_string()))?;
    let mut resp = [0u8; 1];
    stream
        .read_exact(&mut resp)
        .map_err(|e| Error::Inner(e.to_string()))?;
    if resp[0] != 0 {
        return Err(Error::Inner(format!("sendauth rejected {}", resp[0])));
    }
    let ap = build_ap_req_mutual_seq(ticket, session, crealm, cname, seq)
        .map_err(|e| Error::Inner(e.to_string()))?;
    let ap_der = encode(&ap).map_err(|e| Error::Inner(e.to_string()))?;
    write_message(stream, &ap_der).map_err(|e| Error::Inner(e.to_string()))?;
    let err_msg = read_message(stream).map_err(|e| Error::Inner(e.to_string()))?;
    if !err_msg.is_empty() {
        return Err(Error::Inner("sendauth KRB-ERROR".into()));
    }
    let replay = ReplayCache::new();
    let ap_rep_raw = read_message(stream).map_err(|e| Error::Inner(e.to_string()))?;
    let usage = krb5_crypto::KeyUsage::new(krb5_types::ku::AP_REQ_AUTHENTICATOR)
        .map_err(|e| Error::Inner(e.to_string()))?;
    let auth_plain = krb5_crypto::decrypt(session, usage, ap.authenticator.cipher.as_ref())
        .map_err(|e| Error::Inner(e.to_string()))?;
    let authenticator: krb5_types::Authenticator =
        decode(&auth_plain).map_err(|e| Error::Inner(e.to_string()))?;
    verify_ap_rep(&ap_rep_raw, session, &authenticator).map_err(|e| Error::Inner(e.to_string()))?;
    // MIT kpropd expects the dump-size SAFE to use the authenticator
    // sequence, not authenticator+1 (`Message out of order`).
    Ok(KpropAuth {
        session: session.clone(),
        local_seq: seq,
        remote_seq: None,
        replay,
    })
}

/// Send dump bytes after [`kprop_sendauth`].
///
/// # Errors
///
/// SAFE/PRIV or I/O.
pub fn kprop_send_dump(
    stream: &mut TcpStream,
    auth: &mut KpropAuth,
    dump: &[u8],
) -> Result<(), Error> {
    let size = encode_database_size(dump.len() as u64);
    let seq = auth.next_local_seq();
    let der = build_mit_safe(&auth.session, &size, seq)?;
    write_message(stream, &der).map_err(|e| Error::Inner(e.to_string()))?;
    let mut state = CipherState::initial();
    for chunk in dump.chunks(KPROP_BUFSIZ) {
        let seq = auth.next_local_seq();
        let priv_msg = build_krb_priv_chained(&auth.session, chunk, Some(seq), false, &mut state)
            .map_err(|e| Error::Inner(e.to_string()))?;
        let der = encode(&priv_msg).map_err(|e| Error::Inner(e.to_string()))?;
        write_message(stream, &der).map_err(|e| Error::Inner(e.to_string()))?;
    }
    let ack = read_message(stream).map_err(|e| Error::Inner(e.to_string()))?;
    let (plain, _) = verify_safe_user_data(&auth.session, &ack)?;
    let got = decode_database_size(&plain)?;
    if got != dump.len() as u64 {
        return Err(Error::Inner(format!(
            "kprop ack size {got} want {}",
            dump.len()
        )));
    }
    Ok(())
}

/// Primary helper: dump v7 + sendauth + PRIV chunks.
///
/// # Errors
///
/// Dump, auth, or I/O.
#[allow(clippy::too_many_arguments)]
pub fn kprop_send_store(
    stream: &mut TcpStream,
    store: &PrincipalStore,
    master_password: &[u8],
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &krb5_types::Realm,
    cname: &PrincipalName,
) -> Result<(), Error> {
    kprop_send_store_ex(
        stream,
        store,
        master_password,
        ticket,
        session,
        crealm,
        cname,
        false,
    )
}

/// [`kprop_send_store`] with an ipropx dump header (`kpropd -A` `load -i`).
///
/// # Errors
///
/// Dump, auth, or I/O.
#[allow(clippy::too_many_arguments)]
pub fn kprop_send_store_iprop(
    stream: &mut TcpStream,
    store: &PrincipalStore,
    master_password: &[u8],
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &krb5_types::Realm,
    cname: &PrincipalName,
) -> Result<(), Error> {
    kprop_send_store_ex(
        stream,
        store,
        master_password,
        ticket,
        session,
        crealm,
        cname,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn kprop_send_store_ex(
    stream: &mut TcpStream,
    store: &PrincipalStore,
    master_password: &[u8],
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &krb5_types::Realm,
    cname: &PrincipalName,
    iprop: bool,
) -> Result<(), Error> {
    let dump = if iprop {
        kprop_dump_iprop(store, master_password)?
    } else {
        kprop_dump_bytes(store, master_password)?
    };
    let mut auth = kprop_sendauth(stream, ticket, session, crealm, cname, 1)?;
    kprop_send_dump(stream, &mut auth, &dump)
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_kdc::{bootstrap_documented, documented_admin_id};
    use krb5_types::PrincipalName;

    #[test]
    fn iprop_poll_applies_delta_or_signals_resync() {
        let (mut master, acl) = bootstrap_documented().unwrap();
        let (mut slave, _) = bootstrap_documented().unwrap();
        assert_eq!(
            iprop_poll_once(&master, &mut slave),
            IpropPoll::Nil,
            "matching serials are NIL"
        );
        let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pulled"]);
        master
            .create_password(&acl, &documented_admin_id(), &extra, b"pulled-secret")
            .unwrap();
        match iprop_poll_once(&master, &mut slave) {
            IpropPoll::Applied(n) => assert!(n >= 1),
            other => panic!("expected Applied, got {other:?}"),
        }
        assert!(slave.get_name(&extra).is_some());
        let mut empty = krb5_kdc::PrincipalStore::new(krb5_kdc::TEST_REALM);
        assert!(matches!(
            iprop_poll_once(&master, &mut empty),
            IpropPoll::FullResync(_)
        ));
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

    #[test]
    fn kpropd_expired_ticket_is_32_ticket_expired() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_asn1::decode;
        use krb5_kdc::{TEST_REALM, bootstrap_documented, documented_host};
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
            let (mut stream, _) = listener.accept().unwrap();
            kpropd_recvauth(
                &mut stream,
                &host_keys,
                Some(&host_for_server),
                Some(TEST_REALM),
                None,
                ReplayCache::new(),
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
    fn asn1_com_err_maps_mit_table() {
        assert_eq!(
            asn1_com_err("missing field"),
            "ASN.1 structure is missing a required field"
        );
        assert_eq!(
            asn1_com_err("Need more data to continue: Size(1)"),
            "ASN.1 encoding ended unexpectedly"
        );
        assert_eq!(asn1_com_err("other"), "ASN.1 parse error");
    }

    #[test]
    fn kpropd_ap_req_fail_is_krb_error() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_asn1::decode;
        use krb5_kdc::{TEST_REALM, bootstrap_documented, documented_host};
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
            let (mut stream, _) = listener.accept().unwrap();
            kpropd_recvauth(
                &mut stream,
                &host_keys,
                Some(&host_for_server),
                Some(TEST_REALM),
                None,
                ReplayCache::new(),
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

    #[test]
    fn kpropd_ap_req_asn1_fail_is_generic_60() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_asn1::decode;
        use krb5_kdc::{TEST_REALM, bootstrap_documented, documented_host};
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
            let (mut stream, _) = listener.accept().unwrap();
            kpropd_recvauth(
                &mut stream,
                &host_keys,
                Some(&host_for_server),
                Some(TEST_REALM),
                None,
                ReplayCache::new(),
            )
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = TcpStream::connect(addr).unwrap();
        write_message(&mut client, SENDAUTH_VERSION).unwrap();
        write_message(&mut client, KPROP_PROT_VERSION).unwrap();
        let mut ack = [0u8; 1];
        client.read_exact(&mut ack).unwrap();
        assert_eq!(ack[0], 0);
        write_message(&mut client, &[0x6e, 0x00]).unwrap();
        let err_msg = read_message(&mut client).unwrap();
        assert_eq!(err_msg.first().copied(), Some(0x7e), "recvauth KRB-ERROR");
        let e: KrbError = decode(&err_msg).expect("KRB-ERROR");
        assert_eq!(e.error_code, err::GENERIC);
        assert_eq!(
            e.e_text.as_ref().map(krb5_types::KerberosString::as_bytes),
            Some(b"ASN.1 encoding ended unexpectedly\0".as_slice())
        );
        assert!(
            join.join().expect("thread").is_err(),
            "recvauth must fail after APPLICATION-14 ASN.1 fail"
        );
    }
}
