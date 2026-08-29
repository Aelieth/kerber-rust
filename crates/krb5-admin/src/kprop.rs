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
use krb5_crypto::{CipherState, EncryptionType, ProtocolKey};
use krb5_kdc::{Acl, PrincipalStore, dump_store, dump_store_iprop, load_dump, save_store};
use krb5_protocol::{
    ApVerifyParams, ReplayCache, build_ap_rep, build_ap_req_mutual_seq, build_krb_priv_chained,
    build_krb_safe_ex, unwrap_krb_priv_chained, verify_ap_rep, verify_ap_req_ex,
};
use krb5_types::{PrincipalName, Ticket};

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

/// Inner bytes of an EXPLICIT context tag `n` inside a SEQUENCE (or APPLICATION).
fn der_explicit_context(seq: &[u8], n: u8) -> Result<&[u8], Error> {
    let mut inner = der_unwrap_constructed(seq)?;
    // APPLICATION wrapping an extra UNIVERSAL SEQUENCE.
    if inner.first() == Some(&0x30) {
        inner = der_unwrap_constructed(inner)?;
    }
    let mut i = 0;
    while i < inner.len() {
        let (hdr, tag, constructed, len) = der_head(&inner[i..])?;
        let start = i + hdr;
        let end = start
            .checked_add(len)
            .ok_or_else(|| Error::Inner("der".into()))?;
        if end > inner.len() {
            return Err(Error::Inner("der truncated".into()));
        }
        let ctx = 0x80 | if constructed { 0x20 } else { 0 } | n;
        if tag == ctx {
            return if constructed {
                der_unwrap_constructed(&inner[start..end])
            } else {
                Ok(&inner[start..end])
            };
        }
        i = end;
    }
    Err(Error::Inner(format!("der missing context {n}")))
}

fn der_unwrap_constructed(data: &[u8]) -> Result<&[u8], Error> {
    let (hdr, _tag, constructed, len) = der_head(data)?;
    if !constructed {
        return Err(Error::Inner("der not constructed".into()));
    }
    let end = hdr
        .checked_add(len)
        .ok_or_else(|| Error::Inner("der".into()))?;
    data.get(hdr..end)
        .ok_or_else(|| Error::Inner("der body".into()))
}

fn der_head(data: &[u8]) -> Result<(usize, u8, bool, usize), Error> {
    if data.is_empty() {
        return Err(Error::Inner("der empty".into()));
    }
    let tag = data[0];
    let constructed = tag & 0x20 != 0;
    if data.len() < 2 {
        return Err(Error::Inner("der short".into()));
    }
    let l0 = data[1];
    if l0 < 0x80 {
        return Ok((2, tag, constructed, usize::from(l0)));
    }
    let n = usize::from(l0 & 0x7f);
    if n == 0 || n > 4 || data.len() < 2 + n {
        return Err(Error::Inner("der length".into()));
    }
    let mut len = 0usize;
    for b in &data[2..2 + n] {
        len = (len << 8) | usize::from(*b);
    }
    Ok((2 + n, tag, constructed, len))
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
    let usage = krb5_crypto::KeyUsage::new(krb5_types::ku::KRB_SAFE_CKSUM)
        .map_err(|e| Error::Inner(e.to_string()))?;
    let dummy = mit_safe_dummy_der(&msg)?;
    let ck = msg.cksum.checksum.as_ref();
    let body = encode(&msg.safe_body).map_err(|e| Error::Inner(e.to_string()))?;
    let orig = der_explicit_context(raw, 2).ok();
    let ok = krb5_crypto::verify_checksum(session, usage, &dummy, ck).is_ok()
        || krb5_crypto::verify_checksum(session, usage, &body, ck).is_ok()
        || orig.is_some_and(|o| krb5_crypto::verify_checksum(session, usage, o, ck).is_ok());
    if !ok {
        return Err(Error::Inner("safe checksum: integrity check failed".into()));
    }
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
    let replay = ReplayCache::new();
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
            let _ = write_message(stream, &[]);
            return Err(Error::Inner(e.to_string()));
        }
    };
    let crealm = String::from_utf8_lossy(ok.authenticator.crealm.as_bytes());
    let client = format!("{}@{crealm}", ok.authenticator.cname.components_joined());
    if !kpropd_client_allowed(&client, allowed_clients, expected_realm) {
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

fn kpropd_client_allowed(client: &str, allowed: Option<&[String]>, realm: Option<&str>) -> bool {
    match allowed {
        Some([]) => false,
        Some(patterns) => patterns.iter().any(|p| Acl::name_matches(p, client)),
        None => {
            let r = realm.unwrap_or("");
            Acl::name_matches(&format!("host/*@{r}"), client)
                || Acl::name_matches(&format!("kiprop/*@{r}"), client)
        }
    }
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
) -> Result<PrincipalStore, Error> {
    let mut auth = kpropd_recvauth(
        stream,
        host_keys,
        expected_server,
        expected_realm,
        allowed_clients,
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
}
