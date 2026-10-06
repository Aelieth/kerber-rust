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
use krb5_crypto::{CipherState, EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_kdc::{
    LoadLog, PrincipalStore, Ulog, UlogLast, dump_store, dump_store_iprop,
    dump_store_iprop_with_key, dump_store_with_key, load_dump, load_dump_with_stash,
    save_store_fresh,
};
use krb5_protocol::{
    AUTH_CONTEXT_DO_SEQUENCE, AcceptorAuthContext, ApVerifyParams, KeytabEntry, RemoteSeq,
    ReplayCache, build_ap_req_mutual_seq, build_krb_priv_chained, build_krb_safe_ex,
    local_host_address, permitted_enctypes_kdc, us_timeofday, verify_ap_rep, verify_ap_req_ex,
    verify_krb_safe_checksum,
};
use krb5_types::{
    ApReq, EncTicketPart, EncryptedData, EncryptionKey, KerberosTime, KrbError, NameError,
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
/// [`Error::Inner`] when string-to-key of `master_password` fails or a key cannot be wrapped
/// under the derived master key.
pub fn kprop_dump_bytes(store: &PrincipalStore, master_password: &[u8]) -> Result<Vec<u8>, Error> {
    dump_store(store, master_password)
        .map(String::into_bytes)
        .map_err(|e| Error::Inner(e.to_string()))
}

/// MIT `kdb5_util dump -i1` body so `kpropd -A` `load -i` sets replica last_sno: `last` is the
/// update log's last entry, read before `store` was ([`iprop_snapshot`]).
///
/// # Errors
///
/// [`Error::Inner`] when string-to-key of `master_password` fails or a key cannot be wrapped
/// under the derived master key.
pub fn kprop_dump_iprop(
    store: &PrincipalStore,
    master_password: &[u8],
    last: UlogLast,
) -> Result<Vec<u8>, Error> {
    dump_store_iprop(store, master_password, last)
        .map(String::into_bytes)
        .map_err(|e| Error::Inner(e.to_string()))
}

/// What `kprop -i` sends, read in MIT's order: the update log's last serial and time, then the
/// database. The dump then holds at least what its header says, and a change made after the read
/// reaches the replica as an update, never past it.
/// MIT `dump_db` (`kadmin/dbutil/dump.c:1318-1333`): the update log's last serial and time are read before the database is iterated.
///
/// # Errors
///
/// [`Error::Inner`] when the update log cannot be mapped or read, or the database does not load.
pub fn iprop_snapshot(
    db: &Path,
    stash: &Path,
    params: &krb5_config::IpropParams,
) -> Result<(PrincipalStore, UlogLast), Error> {
    let log = Ulog::map(&params.logfile, params.ulogsize)
        .map_err(|_| Error::Inner("Could not map log".into()))?;
    let last = log
        .get_last()
        .map_err(|e| Error::Inner(format!("{e} while reading update log header")))?;
    let store =
        krb5_kdc::load_store(db, stash).map_err(|e| Error::Inner(format!("load store: {e}")))?;
    Ok((store, last))
}

/// Load a kprop body as dump version 6/7. Rejects KDB3 magic and truncated
/// headers.
///
/// # Errors
///
/// [`Error::Inner`] when `bytes` is a KDB1/KDB2/KDB3 blob, is not UTF-8, lacks a dump or iprop
/// header, does not parse as a dump, or holds keys that do not decrypt under the master key
/// string-to-key derives from `master_password`.
pub fn kprop_load_bytes(bytes: &[u8], master_password: &[u8]) -> Result<PrincipalStore, Error> {
    load_dump(kprop_body_text(bytes)?, master_password).map_err(|e| Error::Inner(e.to_string()))
}

/// Load a kprop body with the master key in the stash at `stash`: the replica's, as MIT's
/// kpropd hands the body to `kdb5_util load` beside the replica's own stash.
/// MIT `load_database` (`kprop/kpropd.c:1541-1609`): the received dump is loaded by running `kdb5_util load`, no master password given.
///
/// # Errors
///
/// [`Error::Inner`] when `bytes` is a KDB1/KDB2/KDB3 blob, is not UTF-8 or lacks a dump or
/// iprop header, the stash cannot be read, or no key it holds loads the dump.
pub fn kprop_load_with_stash(bytes: &[u8], stash: &Path) -> Result<PrincipalStore, Error> {
    kprop_load_stash_bytes(bytes, &read_stash_file(stash)?)
}

/// The stash file's bytes, in a wiped buffer sized from the file; a stash that cannot be read is
/// named.
fn read_stash_file(stash: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    krb5_protocol::read_secret_file(stash)
        .map_err(|e| Error::Inner(format!("stash {}: {e}", stash.display())))
}

/// [`kprop_load_with_stash`] with the stash file already read.
fn kprop_load_stash_bytes(bytes: &[u8], stash: &[u8]) -> Result<PrincipalStore, Error> {
    let text = kprop_body_text(bytes)?;
    load_dump_with_stash(text, stash).map_err(|e| Error::Inner(e.to_string()))
}

/// Whether `dump` is an iprop dump (`iprop` / `ipropx` header, MIT `kdb5_util dump -i`), which
/// a replica loads keeping its own lockout attributes.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1497-1501`): an iprop load merges the non-replicated attributes the database already has.
#[must_use]
pub fn is_iprop_dump(dump: &[u8]) -> bool {
    dump.starts_with(b"ipropx ") || dump.starts_with(b"iprop ")
}

/// The kprop body as dump text: MIT dump or iprop text, never a private KDB blob.
fn kprop_body_text(bytes: &[u8]) -> Result<&str, Error> {
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
    Ok(text)
}

/// MIT `krb5_write_message` (`lib/krb5/os/write_msg.c:73-76`): one message, its length and
/// body in one write (`k5_write_messages`).
fn write_message(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    krb5_protocol::write_messages(stream, &[data])
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
    let msg = verify_krb_safe_checksum(session, raw, None, None)
        .map_err(|e| Error::Inner(e.to_string()))?;
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
    /// The sequence number the peer's next message must carry: for kprop, kpropd's AP-REP one.
    remote: RemoteSeq,
    /// kpropd's `recvauth` auth context, which reads kprop's size KRB-SAFE and dump KRB-PRIVs.
    acceptor: Option<AcceptorAuthContext>,
    /// The names kpropd's KRB-ERRORs carry: its own principal and realm, and the client's.
    names: Option<KpropdNames>,
}

/// The principals in kpropd's KRB-ERROR (MIT `send_error`'s `server` and `client`).
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

    /// MIT `send_error` (`kprop/kpropd.c:1476-1510`): a KRB-ERROR naming kpropd and the client, stamped now; an error code past the protocol's 127 is `KRB_ERR_GENERIC` with the error's message before `text`, any other carries `text` alone.
    fn send_error(&self, stream: &mut TcpStream, e: &krb5_protocol::Error, text: &str) {
        let Some(names) = &self.names else {
            return;
        };
        let (code, text) = match e {
            krb5_protocol::Error::KrbError { code, .. } if *code <= 127 => (*code, text.to_owned()),
            // MIT `krb5_k_decrypt`: a ciphertext that does not decrypt is `KRB5KRB_AP_ERR_BAD_INTEGRITY`.
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

/// Replica: `recvauth` then dump bytes (caller loads).
///
/// `acl_lines` are the raw `kpropd.acl` lines (`None` = no readable file);
/// after `recvauth` completes they are checked with
/// `kpropd_authorized_principal`, exactly as MIT does.
/// MIT `doit` (`kpropd.c:528-546`): `authorized_principal` is checked after authentication
/// (the AP-REP has already been sent; a rejected peer sees the connection close).
///
/// # Errors
///
/// [`Error::Inner`] when a read or write on `stream` fails or a message exceeds 8 MiB, the
/// peer's sendauth or `kprop5_01` version is wrong, the AP-REQ does not verify (a KRB-ERROR is
/// sent back first), or the session key or AP-REP cannot be built;
/// [`Error::KpropUnauthorized`] when `acl_lines` does not authorize the client.
pub fn kpropd_recvauth(
    stream: &mut TcpStream,
    host_keys: &[ProtocolKey],
    expected_server: Option<&PrincipalName>,
    expected_realm: Option<&str>,
    acl_lines: Option<&[String]>,
    replay: &ReplayCache,
) -> Result<KpropAuth, Error> {
    let keys = RecvauthKeys {
        keys: host_keys,
        keytab: None,
    };
    recvauth_with(
        stream,
        &keys,
        expected_server,
        expected_realm,
        acl_lines,
        replay,
    )
}

/// What recvauth decrypts kprop's ticket with: kpropd's keytab when there is one, else `keys`.
struct RecvauthKeys<'a> {
    keys: &'a [ProtocolKey],
    keytab: Option<&'a KpropdKeys>,
}

/// [`kpropd_recvauth`] with kpropd's keytab, whose key for the ticket is chosen as MIT's
/// `krb5_rd_req` chooses it ([`kpropd_ticket_key`]).
fn recvauth_with(
    stream: &mut TcpStream,
    keys: &RecvauthKeys<'_>,
    expected_server: Option<&PrincipalName>,
    expected_realm: Option<&str>,
    acl_lines: Option<&[String]>,
    replay: &ReplayCache,
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
    // The ticket's key comes from kpropd's keytab as MIT's chooses it; once chosen, it alone
    // decrypts the ticket, whatever server the ticket names.
    let chosen: [ProtocolKey; 1];
    let (verify_keys, verify_server, verify_realm) = match keys.keytab {
        Some(kt) => match kpropd_ticket_key(&ap_raw, kt, expected_server, expected_realm) {
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
        kvno: None,
        expected_server: verify_server,
        expected_realm: verify_realm,
        skew: 300,
        addresses: None,
        now: None,
    };
    // MIT `recvauth_common` (`recvauth.c:139-205`): an AP-REQ `krb5_rd_req` refuses, an enctype the server does not permit among them, is answered with a KRB-ERROR, and a mutual one with `krb5_mk_rep`.
    // MIT `parse_args` (`kprop/kpropd.c:1056-1058`): kpropd's context reads the KDC profile, so kdc.conf's `permitted_enctypes` comes first.
    let checked = verify_ap_req_ex(&ap_raw, &params, replay, None).and_then(|ok| {
        let ac = AcceptorAuthContext::from_ap_req(&ok, &permitted_enctypes_kdc()?)?;
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
    // MIT `kerberos_authenticate` (`kpropd.c:1221-1229`): the auth context does sequence numbers only.
    ac.set_flags(AUTH_CONTEXT_DO_SEQUENCE);
    // MIT `doit` (`kpropd.c:495-526`): the address `kerberos_authenticate` takes as its own is `from`, the peer's, from `getpeername`.
    // MIT `kerberos_authenticate` (`kpropd.c:1201-1247`): that address is set as the local one and none as the remote one, so a NAT may change the client's.
    ac.set_addrs(
        Some(local_host_address(stream.peer_addr().ok().map(|a| a.ip()))),
        None,
    );
    write_message(stream, &[]).map_err(|e| Error::Inner(e.to_string()))?;
    let session = session_from_ticket(&ok)?;
    // MIT kprop's authenticator carries no subkey, so the AP-REP echoes none: it carries the
    // fresh 30-bit seq-number only. Without mutual authentication there is no AP-REP and the
    // seq-number is the peer's (`rd_req`), as MIT's.
    if ok.mutual_required {
        let ap_rep = ac.mk_rep().map_err(|e| Error::Inner(e.to_string()))?;
        let der = encode(&ap_rep).map_err(|e| Error::Inner(e.to_string()))?;
        write_message(stream, &der).map_err(|e| Error::Inner(e.to_string()))?;
    }
    // The AP-REP's seq is the one kprop's `rd_rep` stores; the size-ack SAFE carries it.
    let local_seq = ac.local_seq();
    // MIT `doit` (`kpropd.c:526-546`): `authorized_principal` runs after
    // `kerberos_authenticate` (recvauth complete, AP-REP sent) and a rejected
    // peer gets `exit(1)` — no KRB-ERROR, the socket just closes, so MIT
    // kprop reports `Broken pipe while sending database block starting at 0`.
    let crealm = String::from_utf8_lossy(ok.authenticator.crealm.as_bytes());
    let client = ok.authenticator.cname.unparse_with_realm(&crealm);
    if !kpropd_authorized_principal(acl_lines, &client, ok.ticket_etype) {
        return Err(Error::KpropUnauthorized(client));
    }
    Ok(KpropAuth {
        session,
        local_seq,
        remote: RemoteSeq::new(ac.remote_seq()),
        acceptor: Some(ac),
        names: Some(KpropdNames {
            server: expected_server.cloned().unwrap_or_else(kpropd_error_server),
            realm: expected_realm.unwrap_or("????").to_owned(),
            client: ok.authenticator.cname.clone(),
            crealm: ok.authenticator.crealm.clone(),
        }),
    })
}

/// MIT `authorized_principal` (`kpropd.c:1298-1348`): a `kpropd.acl` line authorizes the
/// client when it starts with the unparsed name followed by whitespace or the end, and any
/// enctype after the name matches the ticket's.
///
/// `acl_lines` are the file's lines with only the trailing `\n` removed
/// (`fgets` + `buf[end] = '\0'`); `None` is an unopenable file. `name` is
/// the unparsed client (`krb5_unparse_name`); `auth_etype` is the ticket's
/// `enc_part.enctype`. A line matches when it starts with `name`
/// (`strncmp(name, buf, strlen(name))`) and the next byte is NUL or
/// `isspace`; after skipping whitespace an empty remainder authorizes, and a
/// non-empty remainder authorizes only if `krb5_string_to_enctype` accepts
/// it (a name or alias, `strcasecmp`, never a number) and it equals
/// `auth_etype` — otherwise the line is skipped. No wildcards, no leading
/// whitespace, no comments: `#` lines simply never match a name.
#[must_use]
pub fn kpropd_authorized_principal(
    acl_lines: Option<&[String]>,
    name: &str,
    auth_etype: i32,
) -> bool {
    // C-locale `isspace`: `' '`, `\t`, `\n`, `\v`, `\f`, `\r`.
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

/// `krb5_string_to_enctype` as used by the kpropd ACL.
/// MIT `krb5_string_to_enctype` (`enctype_util.c:89-114`): the whole remainder must be an
/// enctype name or alias, compared with `strcasecmp`; a number, trailing whitespace or `\r`
/// is `EINVAL`.
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

/// MIT `krb5int_is_app_tag` (`k5-int.h:1334-1336`): the first byte, with the constructed bit
/// `0x20` cleared, must be `tag | 0x40`; an AP-REQ is `krb5int_is_app_tag(dat, 14)`.
fn is_ap_req(raw: &[u8]) -> bool {
    raw.first().is_some_and(|b| b & !0x20 == 0x4e)
}

fn recvauth_error_fields(raw: &[u8], e: &krb5_protocol::Error) -> (i32, String) {
    if !is_ap_req(raw) {
        return (err::MSG_TYPE, "Invalid message type".into());
    }
    match e {
        // MIT `recvauth_common` (`recvauth.c:165-168`): the e-text is the error table's text, not the message `negotiate_etype` set.
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
/// [`Error::Inner`] when `realm` is not ASCII, the CSPRNG fails, or the ticket or AP-REQ
/// cannot be encoded or encrypted.
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

/// The principal kpropd answers as, its realm aside: `host/` and this host's name
/// ([`kpropd_server_name_for`] of `gethostname`'s).
///
/// # Errors
///
/// As [`kpropd_server_name_for`].
pub fn kpropd_server_name() -> Result<PrincipalName, NameError> {
    kpropd_server_name_for(&krb5_config::this_host())
}

/// `host/` and `host`, as MIT's kpropd makes its own name with the profile its context reads
/// (kdc.conf, then krb5.conf). Under `dns_canonicalize_hostname = fallback` (Fedora's) the name
/// is kept as it is, and kpropd's keytab entry is looked up under the name expanded when the
/// ticket comes ([`KpropdKeys::lookup`]); otherwise it is the expanded name. The name is expanded
/// without DNS ([`krb5_config::expand_hostname`]): a name without a dot gains
/// `qualify_shortname`, else the resolver's first search domain, and it is lowercased and loses a
/// trailing dot. MIT's `true`, its built-in default, and the second step of `fallback`
/// canonicalize the name through DNS, which this port does not: a name DNS would change is not
/// followed.
/// MIT `sn2princ_realm` (`kprop/kprop_util.c:33-55`): `krb5_sname_to_principal` for the local host and the `host` service, put in kpropd's realm.
/// MIT `krb5_sname_to_principal` (`lib/krb5/os/sn2princ.c:365-376`): with `fallback` the name is kept until it is used, else canonicalized now, through DNS only with `true`.
///
/// # Errors
///
/// [`NameError::NotGeneralString`] for a name that is not ASCII, which this port's principal
/// names cannot hold (MIT's can): kpropd then stops, as MIT's does when it cannot make the name.
pub fn kpropd_server_name_for(host: &str) -> Result<PrincipalName, NameError> {
    let conf = krb5_config::load_krb5_conf_paths(crate::kadmin_cli::krb5_conf_paths_with_kdc())
        .unwrap_or_default();
    let host = if conf.dns_canonicalize_hostname == krb5_config::CanonHost::Fallback {
        host.to_owned()
    } else {
        krb5_config::expand_hostname(host, &conf)
    };
    PrincipalName::try_new(PrincipalName::NT_SRV_HST, ["host", host.as_str()])
}

/// The name kpropd's keytab entry is looked up under, for its principal `server`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum KpropdLookup {
    /// kpropd's principal itself.
    #[default]
    Server,
    /// Under `dns_canonicalize_hostname = fallback`, the principal with its hostname expanded.
    Name(PrincipalName),
    /// An expanded name this port cannot hold (not ASCII): no entry has it.
    Unnamed,
}

/// The name kpropd's keytab is searched under for its principal `server`: under `fallback` a
/// host-based name's host expanded by `expand` (without DNS), else `server` itself.
/// MIT `k5_canonprinc` (`lib/krb5/os/sn2princ.c:281-307`): only a two-part host-based name with a hostname is canonicalized, and only under `fallback`, first without DNS.
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

/// kpropd's own name for a KRB-ERROR that has no server given: [`kpropd_server_name`], else, for
/// a name this port cannot hold, `????` as MIT's recvauth names a server it was not given.
fn kpropd_error_server() -> PrincipalName {
    kpropd_server_name().unwrap_or_else(|_| PrincipalName::new(PrincipalName::NT_UNKNOWN, ["????"]))
}

/// MIT `recvauth_common` (`recvauth.c:150-188`): AP-REQ failure is a length-prefixed KRB-ERROR.
/// MIT `recvauth_common` (`recvauth.c:154-157`): it is stamped with `krb5_us_timeofday` and names the server kpropd gave recvauth, its own host principal when no other is set.
fn kprop_rd_req_error(
    raw: &[u8],
    e: &krb5_protocol::Error,
    realm: Option<&str>,
    server: Option<&PrincipalName>,
) -> Vec<u8> {
    let (code, text) = recvauth_error_fields(raw, e);
    kprop_krb_error(code, &text, realm, server)
}

/// recvauth's KRB-ERROR with `code` and `text`, for kpropd's `server` in `realm`.
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

/// The key MIT's `krb5_rd_req` decrypts kprop's ticket with, from kpropd's keytab `kt`, for
/// `server` in `realm`; else recvauth's KRB-ERROR and its text. An AP-REQ that does not decode
/// is answered first, as MIT decodes it before it opens the keytab.
///
/// For kpropd's own principal the keytab gives one entry, as MIT's file keytab gives it
/// ([`kt_get_entry`]), and that key alone decrypts the ticket, whatever server the ticket names:
/// no entry for the ticket's enctype is "Service key not available", a ticket of another kvno
/// or one the key cannot decrypt is "The ticket isn't for us" unless it names kpropd itself
/// ("Key version is not available", "Decrypt integrity check failed"), and a keytab that cannot
/// be read sends its own error. With `ignore_acceptor_hostname` set, or no server, every entry
/// that matches the server with any hostname ([`sname_match`](krb5_protocol::sname_match)) and
/// has the ticket's enctype is tried in keytab order, whatever its kvno, and the first that
/// decrypts the ticket serves; MIT's "similar" enctypes are one enctype each here.
/// MIT `krb5_rd_req` (`lib/krb5/krb/rd_req.c:56-84`): the message is checked and decoded before the keytab is opened.
/// MIT `decrypt_ticket` (`lib/krb5/krb/rd_req_dec.c:454-456`): a server whose hostname is ignored is matched against every entry, uncanonicalized.
/// MIT `decrypt_try_server` (`lib/krb5/krb/rd_req_dec.c:373-377`): any other server is explicit and takes `try_one_princ`.
/// MIT `try_one_princ` (`lib/krb5/krb/rd_req_dec.c:335-346`): the entry for the principal, kvno and enctype is fetched, then its key decrypts the ticket.
/// MIT `keytab_fetch_error` (`lib/krb5/krb/rd_req_dec.c:126-148`): no entry is `NOKEY`, no kvno `BADKEYVER` for the ticket's own server else `NOT_US`, and an unreadable keytab its own code.
/// MIT `integrity_error` (`lib/krb5/krb/rd_req_dec.c:173-174`): a key that cannot decrypt is `BAD_INTEGRITY` for the ticket's own server, else `NOT_US`.
fn kpropd_ticket_key(
    raw: &[u8],
    kt: &KpropdKeys,
    server: Option<&PrincipalName>,
    realm: Option<&str>,
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
    // MIT `krb5_is_permitted_enctype` (`lib/krb5/krb/init_ctx.c:603-605`): a permitted list that cannot be had permits nothing.
    let permitted = permitted_enctypes_kdc().unwrap_or_default();
    let ticket = &ap.ticket;
    let realm_b = realm.unwrap_or_default().as_bytes();
    let (tkt_kvno, tkt_etype) = (ticket.enc_part.kvno.unwrap_or(0), ticket.enc_part.etype);
    let is_tkt_server = |name: &PrincipalName, name_realm: &[u8]| {
        name.name_string == ticket.sname.name_string && name_realm == ticket.realm.as_bytes()
    };
    let explicit = server.filter(|s| {
        // MIT `is_matching` (`lib/krb5/krb/rd_req_dec.c:283-285`): a host-based server matches many entries when its realm or hostname is empty, or hostnames are ignored.
        !(s.name_type == PrincipalName::NT_SRV_HST
            && s.name_string.len() == 2
            && (realm_b.is_empty()
                || s.name_string[1].as_bytes().is_empty()
                || kt.ignore_acceptor_hostname))
    });
    if let Some(KpropdKeytabError::Read(text)) = &kt.error {
        // MIT `decrypt_try_server` (`lib/krb5/krb/rd_req_dec.c:390-394`): a keytab that cannot be iterated is `NOKEY`.
        if explicit.is_none() {
            return Err(refuse(err::NOKEY));
        }
        return Err(generic(text));
    }
    if let Some(name) = explicit {
        // MIT `decrypt_ticket` (`lib/krb5/krb/rd_req_dec.c:460-466`): the server's canonical name is what the keytab is searched under.
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
        return match decrypt_ticket_part(&entry.key, ticket, &permitted) {
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
    // MIT `decrypt_try_server` (`lib/krb5/krb/rd_req_dec.c:395-432`): every entry that matches the server is a candidate; one of the ticket's enctype that decrypts it serves.
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
        if similar && decrypt_ticket_part(&e.key, ticket, &permitted).is_ok() {
            return Ok(e.key.clone());
        }
    }
    // MIT `iteration_error` (`lib/krb5/krb/rd_req_dec.c:222-270`): no matching entry is `NOKEY`, the ticket's server unmatched or absent `NOT_US`, its kvno or enctype absent `BADKEYVER`, else `BAD_INTEGRITY`.
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

/// Why a key does not decrypt a ticket ([`decrypt_ticket_part`]).
enum TicketPart {
    /// `KRB5KRB_AP_ERR_BAD_INTEGRITY`: the key is not the ticket's.
    Integrity,
    /// `KRB5_BAD_MSIZE`: the ciphertext is shorter than the enctype's header and trailer.
    Size,
    /// Any other failure, a part that does not decode among them.
    Other(krb5_protocol::Error),
}

/// Whether `key` decrypts `ticket`'s encrypted part to an `EncTicketPart`: first the ticket's
/// enctype must be one this port implements and one `permitted` holds.
/// MIT `try_one_entry` (`lib/krb5/krb/rd_req_dec.c:297-299`): the key serves when `krb5_decrypt_tkt_part` decrypts and decodes the ticket with it.
/// MIT `krb5_decrypt_tkt_part` (`lib/krb5/krb/decrypt_tk.c:46-50`): an enctype not implemented, then one not permitted, fails before any decryption.
/// MIT `krb5_k_decrypt` (`lib/crypto/krb/decrypt.c:48-52`): a ciphertext shorter than the header and trailer is `KRB5_BAD_MSIZE` before any key is tried.
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

/// What MIT's `krb5_kt_get_entry` finds in a file keytab for a principal, kvno and enctype.
enum KtGet<'a> {
    /// The entry it gives.
    Found(&'a KeytabEntry),
    /// `KRB5_KT_KVNONOTFOUND`: entries for the principal and enctype, none of the kvno.
    KvnoNotFound,
    /// `KRB5_KT_NOTFOUND`: no entry for the principal and enctype.
    NotFound,
}

/// The entry MIT's file keytab gives for `name`@`realm` (name type aside), `kvno` and
/// `enctype`, in keytab order: the first of that kvno; else the first whose kvno is `kvno`'s
/// low eight bits (a kvno an old keytab or kadmin cut to 8 bits); with `kvno` 0, which ignores
/// it, the most recent ([`more_recent`]), an entry of kvno 0 being weighed that way too.
/// MIT `krb5_ktfile_get_entry` (`lib/krb5/keytab/kt_file.c:333-391`): the principal and enctype filter the entries; a kvno that matches ends the scan, a low-8-bit match is kept if first, kvno 0 keeps the most recent, and only another kvno makes `KRB5_KT_KVNONOTFOUND`.
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

/// Whether `k1` is more recent than `k2`: the higher kvno, unless a kvno under 128 was written
/// no earlier than one over 240, which is then taken to have wrapped past it.
/// MIT `more_recent` (`lib/krb5/keytab/kt_file.c:267-275`): the wraparound guesses first, then the higher kvno.
fn more_recent(k1: &KeytabEntry, k2: &KeytabEntry) -> bool {
    if k2.timestamp <= k1.timestamp && k1.kvno < 128 && k2.kvno > 240 {
        return true;
    }
    if k1.timestamp <= k2.timestamp && k1.kvno > 240 && k2.kvno < 128 {
        return false;
    }
    k1.kvno > k2.kvno
}

/// Receive dump bytes after [`kpropd_recvauth`].
/// MIT `recv_database` (`kprop/kpropd.c:1356-1473`): the size comes in a KRB-SAFE and the dump in KRB-PRIV blocks chained from the initial cipher state, each read by `krb5_rd_safe` / `krb5_rd_priv` on recvauth's context, so each must carry kprop's next sequence number (the authenticator's, then one more per message); a message that fails is answered with a KRB-ERROR naming what was being read, and a KRB-ERROR from kprop ends the transfer without one.
///
/// # Errors
///
/// [`Error::Inner`] when a read on `stream` fails or a message exceeds 8 MiB, kprop sends a
/// KRB-ERROR, the size KRB-SAFE or a block's KRB-PRIV is refused (out of order, modified, or
/// not decrypting), the size is malformed, or the blocks overrun it.
pub fn kpropd_recv_dump(stream: &mut TcpStream, auth: &mut KpropAuth) -> Result<Vec<u8>, Error> {
    let size_raw = read_message(stream).map_err(|e| Error::Inner(e.to_string()))?;
    if size_raw.first() == Some(&0x7e) {
        return Err(Error::Inner("kprop sent a KRB-ERROR".into()));
    }
    let size_plain = match auth.acceptor().and_then(|ac| ac.rd_safe(&size_raw)) {
        Ok(p) => p,
        Err(e) => {
            auth.send_error(stream, &e, "while decoding database size");
            return Err(Error::Inner(format!("{e} while decoding database size")));
        }
    };
    let want = match decode_database_size(&size_plain) {
        Ok(n) => n,
        Err(e) => {
            let generic = krb5_protocol::Error::KrbError {
                code: err::GENERIC,
                text: None,
            };
            auth.send_error(stream, &generic, "malformed database size message");
            return Err(e);
        }
    };
    auth.acceptor()
        .map_err(|e| Error::Inner(e.to_string()))?
        .init_ivector();
    let mut dump = Vec::with_capacity(usize::try_from(want).unwrap_or(0));
    while (dump.len() as u64) < want {
        let chunk_raw = read_message(stream).map_err(|e| Error::Inner(e.to_string()))?;
        if chunk_raw.first() == Some(&0x7e) {
            return Err(Error::Inner("kprop sent a KRB-ERROR".into()));
        }
        let chunk = match auth.acceptor().and_then(|ac| ac.rd_priv(&chunk_raw)) {
            Ok(c) => c,
            Err(e) => {
                let text = format!(
                    "while decoding database block starting at offset {}",
                    dump.len()
                );
                auth.send_error(stream, &e, &text);
                return Err(Error::Inner(format!("{e} {text}")));
            }
        };
        dump.extend_from_slice(&chunk);
    }
    // MIT `recv_database` (`kpropd.c:1450-1458`): a dump longer than its size is reported with the same KRB-ERROR and then loaded anyway; this kpropd loads nothing it did not expect.
    if dump.len() as u64 != want {
        let generic = krb5_protocol::Error::KrbError {
            code: err::GENERIC,
            text: None,
        };
        let text = format!(
            "Received {} bytes, expected {want} bytes for database file",
            dump.len()
        );
        auth.send_error(stream, &generic, &text);
        return Err(Error::Inner(text));
    }
    Ok(dump)
}

/// Send the SAFE size-ack MIT `kprop` waits for.
///
/// # Errors
///
/// [`Error::Inner`] when the size KRB-SAFE cannot be built or checksummed, or the write on
/// `stream` fails.
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

/// kprop's keytab file: the keytab `keytab` names (`-s`), else the default keytab (`KRB5_KTNAME`,
/// else krb5.conf's `default_keytab_name`, else `FILE:/etc/krb5.keytab`); `None` for a `MEMORY:`
/// keytab, which a new process holds empty.
/// MIT `get_tickets` (`kprop/kprop.c:195-208`): `-s` is resolved, else a NULL keytab makes `krb5_get_init_creds_keytab` read the default one through kprop's context, whose profile is krb5.conf alone.
///
/// # Errors
///
/// `krb5_kt_resolve`'s text for a name of a type it does not know ("Unknown Key table type"), or
/// "Invalid argument" for a default name that is not UTF-8 or whose parameters do not expand.
pub fn kprop_keytab_file(keytab: Option<&str>) -> Result<Option<std::path::PathBuf>, &'static str> {
    crate::kadmin_cli::keytab_file_in(keytab, krb5_config::krb5_conf_paths())
}

/// kpropd's keytab for one connection, from which kprop's ticket's key is chosen as MIT's
/// `krb5_rd_req` chooses it.
#[derive(Debug, Default)]
pub struct KpropdKeys {
    /// The keytab's entries, in file order.
    pub entries: Vec<KeytabEntry>,
    /// Why the keytab gives no entries when MIT's would fail with its own error; `None` when it
    /// was read, or does not exist or may not be read (no entries).
    pub error: Option<KpropdKeytabError>,
    /// `[libdefaults] ignore_acceptor_hostname` of kpropd's profile: any `host` entry of the
    /// realm then serves, whatever its hostname.
    pub ignore_acceptor_hostname: bool,
    /// The name kpropd's own entry is looked up under.
    pub lookup: KpropdLookup,
}

/// A keytab error recvauth answers with MIT's text in a generic KRB-ERROR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KpropdKeytabError {
    /// The default keytab's name does not resolve ("Unknown Key table type"): `krb5_rd_req` fails
    /// before it looks at the server.
    /// MIT `krb5_rd_req` (`lib/krb5/krb/rd_req.c:80-84`): with no keytab given, `krb5_kt_default`'s error ends it.
    Resolve(String),
    /// The keytab cannot be read (no keytab of version 1 or 2, a read error): sent for kpropd's
    /// own principal; a scan of every entry finds none, "Service key not available".
    Read(String),
}

/// kpropd's keytab for one connection: the keytab `keytab` names (`-s`), else the default keytab
/// (`KRB5_KTNAME`, else the KDC profile's `default_keytab_name`, else `FILE:/etc/krb5.keytab`),
/// read with [`read_secret_file`](krb5_protocol::read_secret_file), the KDC profile's
/// `ignore_acceptor_hostname`, and the name `server`'s entry is looked up under
/// ([`KpropdKeys::lookup`]), expanded now as MIT expands it for each ticket. A keytab that does
/// not exist or may not be read, or a `MEMORY:` one, has no entries; one that is no keytab gives
/// MIT's error for it, and a default name that does not resolve MIT's error for that. A keytab
/// damaged after its version has no entries either: MIT stops at the damaged entry
/// (`KRB5_KT_END`), so an entry before it would still serve there.
/// MIT `kerberos_authenticate` (`kprop/kpropd.c:1249-1263`): each connection resolves `-s` with `krb5_kt_resolve` (a failure ends the connection), else `krb5_recvauth` reads the default keytab.
/// MIT `keytab_fetch_error` (`lib/krb5/krb/rd_req_dec.c:118-136`): a keytab that does not exist or may not be read, and no entry for an explicit server, are `KRB5KRB_AP_ERR_NOKEY`; any other keytab error stays itself.
/// MIT `krb5_ktfileint_open` (`lib/krb5/keytab/kt_file.c:785-804`): a file shorter than its version, or of a version other than 0x0501 and 0x0502, is `KRB5_KEYTAB_BADVNO`.
///
/// # Errors
///
/// `krb5_kt_resolve`'s text for a `-s` name of a type it does not know ("Unknown Key table
/// type"): the connection then ends.
pub fn kpropd_keytab_keys(
    keytab: Option<&str>,
    server: Option<&PrincipalName>,
) -> Result<KpropdKeys, &'static str> {
    let conf = krb5_config::load_krb5_conf_paths(crate::kadmin_cli::krb5_conf_paths_with_kdc())
        .unwrap_or_default();
    let fallback = conf.dns_canonicalize_hostname == krb5_config::CanonHost::Fallback;
    let lookup = server.map_or(KpropdLookup::Server, |s| {
        kpropd_lookup_name(s, fallback, |h| krb5_config::expand_hostname(h, &conf))
    });
    let empty = KpropdKeys {
        ignore_acceptor_hostname: conf.ignore_acceptor_hostname,
        lookup,
        ..KpropdKeys::default()
    };
    let path = match crate::kadmin_cli::keytab_file(keytab) {
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

/// kpropd's parsed configuration.
///
/// The realm, database path, stash, and ACL the daemon was started with.
/// MIT `realm` (`kpropd.c:131-131`): the realm kpropd serves, from `-r` or the default realm.
/// MIT `kerb_database` (`kpropd.c:136-136`): the database path, set by `-F`.
/// MIT `acl_file_name` (`kpropd.c:137-137`): the ACL file, `KPROPD_ACL_FILE` unless `-a`
/// names another.
#[derive(Clone, Copy)]
pub struct KpropdConfig<'a> {
    /// Host keys that accept the kprop `sendauth` when there is no `keytab`.
    pub host_keys: &'a [ProtocolKey],
    /// kpropd's keytab ([`kpropd_keytab_keys`]): when set, the ticket's key comes from it as
    /// MIT's `krb5_rd_req` chooses it, and `host_keys` is not used.
    pub keytab: Option<&'a KpropdKeys>,
    /// kpropd's own principal ([`kpropd_server_name`]), which its KRB-ERRORs name: with a
    /// `keytab`, its entry there takes kprop's ticket; else the ticket must name it
    /// (`ApVerifyParams.expected_server`).
    pub expected_server: Option<&'a PrincipalName>,
    /// kpropd's realm, `expected_server`'s.
    pub expected_realm: Option<&'a str>,
    /// The master password that opens the dump (the gates' `KRB5_MASTER_PASSWORD`); `None`,
    /// the replica's stash opens it ([`kprop_load_with_stash`]).
    pub master_password: Option<&'a [u8]>,
    /// Replica database path.
    pub db: &'a Path,
    /// Replica stash path.
    pub stash: &'a Path,
    /// Client principals allowed to propagate.
    pub allowed_clients: Option<&'a [String]>,
    /// The replica realm's iprop parameters when `iprop_enable` is set: the dump must then be an
    /// iprop one, and the update log takes its serial and time.
    pub iprop: Option<&'a krb5_config::IpropParams>,
}

/// The serial and time an iprop dump's header carries; `None` for a dump without one.
#[must_use]
pub fn iprop_dump_last(dump: &[u8]) -> Option<UlogLast> {
    let line = dump.split(|&b| b == b'\n').next()?;
    krb5_kdc::parse_iprop_header(std::str::from_utf8(line).ok()?)
        .ok()
        .map(|(_, last)| last)
}

/// Make `store` the replica's database as a full load does, and, for an iprop replica, keep its
/// update log as `kdb5_util load -i` keeps it: started over before the new database is live and
/// again after, then set to the dump's serial and time. A plain load keeps every principal's
/// lockout attributes from the dump; an iprop load keeps the replica's own.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1551-1559`): the log starts over before the promotion, so a kill just after it leaves no stale state.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1570-1586`): after the promotion the log starts over again and takes the iprop dump's serial and time.
///
/// # Errors
///
/// [`Error::Inner`] when the update log cannot be opened, reset or written, or the store cannot
/// be saved.
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

/// Full replica handler: recvauth, dump v7 body, `load_dump`, persist, ack. The database is
/// written as a full load leaves it, a new 0600 file owned by kpropd ([`load_replica`]).
/// Without `cfg.master_password` the replica's stash is read once the peer is authenticated and
/// before the dump is received, so a missing one is named before any transfer. A replica with
/// iprop enabled (`cfg.iprop`) loads only an iprop dump, keeps its own lockout attributes and
/// sets its update log to the dump's serial and time; any other loads only a plain dump, whose
/// lockout attributes replace its own.
/// MIT `load_database` (`kprop/kpropd.c:1541-1609`): an iprop replica loads with `-i`, any other with a plain `kdb5_util load`.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1447-1475`): `load -i` refuses a dump without an iprop header, and a plain load one with it.
///
/// # Errors
///
/// [`Error::KpropUnauthorized`] when `cfg.allowed_clients` does not authorize the client;
/// [`Error::Inner`] when [`kpropd_recvauth`], [`kpropd_recv_dump`], or [`kpropd_send_ack`]
/// fails, the dump does not load under `cfg.master_password` (or the stash's key when that is
/// `None`), or the store cannot be saved to
/// `cfg.db` / `cfg.stash`.
pub fn kpropd_handle_conn(
    stream: &mut TcpStream,
    cfg: &KpropdConfig<'_>,
    replay: &ReplayCache,
) -> Result<PrincipalStore, Error> {
    let KpropdConfig {
        host_keys,
        keytab,
        expected_server,
        expected_realm,
        master_password,
        db,
        stash,
        allowed_clients,
        iprop,
    } = *cfg;
    let keys = RecvauthKeys {
        keys: host_keys,
        keytab,
    };
    let mut auth = recvauth_with(
        stream,
        &keys,
        expected_server,
        expected_realm,
        allowed_clients,
        replay,
    )?;
    let stash_bytes = match master_password {
        Some(_) => None,
        None => Some(read_stash_file(stash)?),
    };
    let dump = kpropd_recv_dump(stream, &mut auth)?;
    let iprop_last = match (iprop, iprop_dump_last(&dump)) {
        (Some(params), Some(last)) => Some((params, last)),
        (None, None) if !is_iprop_dump(&dump) => None,
        _ => return Err(Error::Inner("dump header bad".into())),
    };
    let store = match (master_password, &stash_bytes) {
        (Some(pw), _) => kprop_load_bytes(&dump, pw)?,
        (None, Some(stash_bytes)) => kprop_load_stash_bytes(&dump, stash_bytes)?,
        (None, None) => return Err(Error::Inner("no master key".into())),
    };
    load_replica(&store, db, stash, iprop_last)?;
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

/// One poll of `master`'s update log by `slave`, in process: `slave`'s update log's last entry
/// (none mapped is serial 0) is what it asks from, and each update it gets is applied and kept
/// in its log, as kpropd's loop does with `IPROP_GET_UPDATES`.
/// MIT `ulog_replay` (`lib/kdb/kdb_log.c:474-476`): an update that does not apply leaves the replica to resynchronize in full.
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

/// Primary: `sendauth` then dump bytes.
///
/// # Errors
///
/// [`Error::Inner`] when a read or write on `stream` fails or a message exceeds 8 MiB, the
/// replica rejects the sendauth version, the AP-REQ cannot be built, the replica answers with
/// a KRB-ERROR, or the AP-REP does not verify under `session`.
pub fn kprop_sendauth(
    stream: &mut TcpStream,
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &krb5_types::Realm,
    cname: &PrincipalName,
    seq: u32,
) -> Result<KpropAuth, Error> {
    // MIT `krb5_sendauth` (`lib/krb5/krb/sendauth.c:63-67`): the two version strings go out in
    // one write.
    krb5_protocol::write_messages(stream, &[SENDAUTH_VERSION, KPROP_PROT_VERSION])
        .map_err(|e| Error::Inner(e.to_string()))?;
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
    let ap_rep_raw = read_message(stream).map_err(|e| Error::Inner(e.to_string()))?;
    let usage = krb5_crypto::KeyUsage::new(krb5_types::ku::AP_REQ_AUTHENTICATOR)
        .map_err(|e| Error::Inner(e.to_string()))?;
    let auth_plain = krb5_crypto::decrypt(session, usage, ap.authenticator.cipher.as_ref())
        .map_err(|e| Error::Inner(e.to_string()))?;
    let authenticator: krb5_types::Authenticator =
        decode(&auth_plain).map_err(|e| Error::Inner(e.to_string()))?;
    let rep = verify_ap_rep(&ap_rep_raw, session, &authenticator)
        .map_err(|e| Error::Inner(e.to_string()))?;
    // MIT kpropd expects the dump-size SAFE to use the authenticator
    // sequence, not authenticator+1 (`Message out of order`).
    // MIT `krb5_rd_rep` (`lib/krb5/krb/rd_rep.c:130-130`): kpropd's next message must carry the AP-REP's sequence number.
    Ok(KpropAuth {
        session: session.clone(),
        local_seq: seq,
        remote: RemoteSeq::new(rep.seq_number.unwrap_or(0)),
        acceptor: None,
        names: None,
    })
}

/// Send dump bytes after [`kprop_sendauth`].
///
/// # Errors
///
/// [`Error::Inner`] when a read or write on `stream` fails or a message exceeds 8 MiB, the size
/// KRB-SAFE or a KRB-PRIV chunk cannot be built, the ack KRB-SAFE does not verify or carries a
/// malformed size, or the acked size is not `dump.len()`.
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
    let (plain, ack_seq) = verify_safe_user_data(&auth.session, &ack)?;
    // MIT `xmit_database` (`kprop/kprop.c:524-529`): `krb5_rd_safe` with `DO_SEQUENCE` takes the acknowledgement only with kpropd's next sequence number, the AP-REP's.
    if !auth.remote.check(ack_seq.unwrap_or(0)) {
        return Err(Error::Inner(
            "Message out of order while decoding final size packet from server".into(),
        ));
    }
    auth.remote.advance();
    let got = decode_database_size(&plain)?;
    if got != dump.len() as u64 {
        return Err(Error::Inner(format!(
            "kprop ack size {got} want {}",
            dump.len()
        )));
    }
    Ok(())
}

/// Primary helper: dump v7 + sendauth + PRIV chunks. The dump's keys are wrapped under
/// `master`, the key the primary's stash holds.
///
/// # Errors
///
/// [`Error::Inner`] when a key cannot be wrapped under `master`, or when [`kprop_sendauth`] or
/// [`kprop_send_dump`] fails.
pub fn kprop_send_store(
    stream: &mut TcpStream,
    store: &PrincipalStore,
    master: &ProtocolKey,
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &krb5_types::Realm,
    cname: &PrincipalName,
) -> Result<(), Error> {
    kprop_send_store_ex(stream, store, master, ticket, session, crealm, cname, None)
}

/// [`kprop_send_store`] with an ipropx dump header (`kpropd -A` `load -i`) carrying `last`, the
/// update log's last entry read before `store` ([`iprop_snapshot`]).
///
/// # Errors
///
/// [`Error::Inner`] when a key cannot be wrapped under `master`, or when [`kprop_sendauth`] or
/// [`kprop_send_dump`] fails.
#[expect(clippy::too_many_arguments, reason = "krb5_creds args, no value type")]
pub fn kprop_send_store_iprop(
    stream: &mut TcpStream,
    store: &PrincipalStore,
    master: &ProtocolKey,
    last: UlogLast,
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &krb5_types::Realm,
    cname: &PrincipalName,
) -> Result<(), Error> {
    kprop_send_store_ex(
        stream,
        store,
        master,
        ticket,
        session,
        crealm,
        cname,
        Some(last),
    )
}

#[expect(clippy::too_many_arguments, reason = "krb5_creds args, no value type")]
fn kprop_send_store_ex(
    stream: &mut TcpStream,
    store: &PrincipalStore,
    master: &ProtocolKey,
    ticket: Ticket,
    session: &ProtocolKey,
    crealm: &krb5_types::Realm,
    cname: &PrincipalName,
    iprop: Option<UlogLast>,
) -> Result<(), Error> {
    let dump = match iprop {
        Some(last) => dump_store_iprop_with_key(store, master, last),
        None => dump_store_with_key(store, master),
    }
    .map(String::into_bytes)
    .map_err(|e| Error::Inner(e.to_string()))?;
    let mut auth = kprop_sendauth(stream, ticket, session, crealm, cname, 1)?;
    kprop_send_dump(stream, &mut auth, &dump)
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_kdc::testrealm::{bootstrap_documented, documented_admin_id};

    use krb5_types::PrincipalName;

    /// MIT `dump_db` reads the update log's last serial before the database: a change committed
    /// after `kprop -i` read the database is not in the dump, and the header is the serial from
    /// before it, so the replica asks for that change as an update instead of skipping it.
    #[test]
    fn an_iprop_dump_header_is_the_serial_read_before_the_database() {
        let dir = krb5_testkit::scratch_dir("kprop-iprop-snapshot");
        let (db, stash) = (dir.join("principal"), dir.join("stash"));
        let log = dir.join("principal.ulog");
        let (store, acl) = bootstrap_documented().unwrap();
        krb5_kdc::save_store(&store, &db, &stash).unwrap();
        let mut primary = krb5_kdc::load_store(&db, &stash).unwrap();
        primary
            .map_ulog(&log, 100, krb5_kdc::IpropRole::Primary)
            .unwrap();
        let actor = documented_admin_id();
        let host = |h: &str| PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", h]);
        primary
            .change(|s| s.create_host(&acl, &actor, &host("before.kerber.test")))
            .unwrap()
            .unwrap();
        let params = krb5_config::IpropParams {
            enabled: true,
            port: Some(2121),
            logfile: log.clone(),
            ulogsize: 100,
        };
        let (snapshot, last) = iprop_snapshot(&db, &stash, &params).unwrap();
        // Committed between kprop's read of the database and its dump.
        primary
            .change(|s| s.create_host(&acl, &actor, &host("after.kerber.test")))
            .unwrap()
            .unwrap();
        assert_eq!(primary.ulog_last().unwrap().sno, last.sno + 1);
        let mkey = snapshot.iprop_master_key().unwrap();
        let dump = dump_store_iprop_with_key(&snapshot, &mkey, last).unwrap();
        assert_eq!(
            dump.lines().next().unwrap(),
            format!(
                "ipropx 1 {} {} {}",
                last.sno, last.time.seconds, last.time.useconds
            )
        );
        assert!(dump.contains("host/before.kerber.test@KERBER.TEST"));
        assert!(!dump.contains("host/after.kerber.test@KERBER.TEST"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "test-hooks")]
    #[test]
    fn iprop_poll_applies_delta_or_signals_resync() {
        use krb5_kdc::IpropRole;
        use krb5_kdc::testrealm::map_memory_ulog;
        let (mut master, acl) = bootstrap_documented().unwrap();
        let (mut slave, _) = bootstrap_documented().unwrap();
        map_memory_ulog(&mut master, 100, IpropRole::Primary).unwrap();
        map_memory_ulog(&mut slave, 100, IpropRole::Replica).unwrap();
        assert!(
            matches!(
                iprop_poll_once(&master, &mut slave),
                IpropPoll::FullResync(_)
            ),
            "a replica's own new log is not the primary's: a full resync"
        );
        // Where a full resync leaves the replica: the primary's last entry.
        slave
            .ulog()
            .unwrap()
            .set_last(master.ulog_last().unwrap())
            .unwrap();
        assert_eq!(
            iprop_poll_once(&master, &mut slave),
            IpropPoll::Nil,
            "matching serials are NIL"
        );
        let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pulled"]);
        master
            .create_password(&acl, &documented_admin_id(), &extra, b"pulled-secret")
            .unwrap();
        assert_eq!(iprop_poll_once(&master, &mut slave), IpropPoll::Applied(1));
        assert!(slave.get_name(&extra).is_some());
        assert_eq!(slave.ulog_last(), master.ulog_last());
        let mut empty = krb5_kdc::PrincipalStore::new(krb5_kdc::testrealm::TEST_REALM);
        assert!(matches!(
            iprop_poll_once(&master, &mut empty),
            IpropPoll::FullResync(_)
        ));
    }

    /// A keytab at `path` with one entry for each of `principals` in `R.TEST`, their keys `[n; 32]`.
    fn write_keytab(path: &std::path::Path, principals: &[(&str, u32)]) {
        let mut kt = krb5_protocol::Keytab::single(
            krb5_types::ascii("R.TEST"),
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", principals[0].0]),
            principals[0].1,
            ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[1u8; 32]).unwrap(),
        );
        for (n, (host, kvno)) in principals.iter().enumerate().skip(1) {
            let mut more = krb5_protocol::Keytab::single(
                krb5_types::ascii("R.TEST"),
                PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", host]),
                *kvno,
                ProtocolKey::from_bytes(
                    EncryptionType::Aes256CtsHmacSha196,
                    &[u8::try_from(n + 1).unwrap(); 32],
                )
                .unwrap(),
            );
            kt.entries.append(&mut more.entries);
        }
        kt.write_file(path).unwrap();
    }

    /// MIT `kerberos_authenticate` (`kprop/kpropd.c:1249-1263`): `-s` names the keytab as `krb5_kt_resolve` reads a name, and each connection reads it whole; a missing keytab has no entries, one that is no keytab is `KRB5_KEYTAB_BADVNO`, and a type MIT does not know ends the connection.
    #[test]
    fn kpropd_keytab_gives_its_entries_or_mits_error() {
        let dir = krb5_testkit::scratch_dir("kpropd-keytab");
        let path = dir.join("host.keytab");
        write_keytab(
            &path,
            &[("alias.r.test", 2), ("kdc2.r.test", 3), ("kdc2.r.test", 4)],
        );
        let p = path.display().to_string();
        for name in [p.clone(), format!("FILE:{p}"), format!("WRFILE:{p}")] {
            let k = kpropd_keytab_keys(Some(&name), None).unwrap();
            let kvnos: Vec<_> = k.entries.iter().map(|e| e.kvno).collect();
            assert_eq!(kvnos, [2, 3, 4], "{name}");
            assert_eq!(k.entries[1].key.as_bytes(), [2u8; 32], "{name}");
            assert_eq!(k.error, None, "{name}");
        }
        let missing = dir.join("absent.keytab").display().to_string();
        let k = kpropd_keytab_keys(Some(&missing), None).unwrap();
        assert!(k.entries.is_empty() && k.error.is_none());
        for (file, bytes) in [
            ("junk.keytab", b"not a keytab".as_slice()),
            ("short.keytab", b"\x05".as_slice()),
        ] {
            std::fs::write(dir.join(file), bytes).unwrap();
            let junk = dir.join(file).display().to_string();
            let k = kpropd_keytab_keys(Some(&junk), None).unwrap();
            assert!(k.entries.is_empty());
            assert_eq!(
                k.error,
                Some(KpropdKeytabError::Read(
                    "Unsupported key table format version number".into()
                )),
                "{file}"
            );
        }
        let k = kpropd_keytab_keys(Some("MEMORY:kpropd"), None).unwrap();
        assert!(k.entries.is_empty() && k.error.is_none());
        assert_eq!(
            kpropd_keytab_keys(Some("KDB:"), None).unwrap_err(),
            "Unknown Key table type"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `name` in the documented realm as a keytab entry.
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

    /// MIT `krb5_ktfile_get_entry` (`lib/krb5/keytab/kt_file.c:333-391`): a matching kvno wins, else the first entry of its low eight bits; kvno 0 takes the most recent; another kvno is `KRB5_KT_KVNONOTFOUND` and another enctype no entry.
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

    /// The keytab `kpropd_keytab_keys(None, ..)` reads, printed by a child of the next test.
    #[test]
    fn kpropd_default_keytab_child() {
        if std::env::var_os("KERBER_KPROPD_KT_CHILD").is_some() {
            let file = crate::kadmin_cli::keytab_file(None).ok().flatten();
            let keys = kpropd_keytab_keys(None, None).unwrap();
            let kvnos: Vec<_> = keys.entries.iter().map(|e| e.kvno).collect();
            let file = file.map(|f| f.display().to_string()).unwrap_or_default();
            println!("keytab=[{file}] kvnos={kvnos:?} error={:?}", keys.error);
        }
    }

    /// MIT `kt_default_name` (`lib/krb5/os/ktdefname.c:35-57`): without `-s` kpropd reads `KRB5_KTNAME`, else the KDC profile's `default_keytab_name`, else `/etc/krb5.keytab`.
    /// MIT `krb5_rd_req` (`lib/krb5/krb/rd_req.c:80-84`): a default name of a type `krb5_kt_resolve` does not know is `krb5_rd_req`'s error, not the connection's end.
    #[test]
    fn kpropd_default_keytab_is_ktname_then_the_kdc_profile_then_etc() {
        let dir = krb5_testkit::scratch_dir("kpropd-default-kt");
        let (env_kt, prof_kt) = (dir.join("env.keytab"), dir.join("prof.keytab"));
        write_keytab(&env_kt, &[("kdc2.r.test", 5)]);
        write_keytab(&prof_kt, &[("kdc2.r.test", 6)]);
        let (kdc_conf, plain_kdc, krb5_conf) = (
            dir.join("kdc.conf"),
            dir.join("plain-kdc.conf"),
            dir.join("krb5.conf"),
        );
        std::fs::write(
            &kdc_conf,
            format!(
                "[libdefaults]\n    default_keytab_name = FILE:{}\n",
                prof_kt.display()
            ),
        )
        .unwrap();
        std::fs::write(&plain_kdc, "[kdcdefaults]\n").unwrap();
        std::fs::write(&krb5_conf, "[libdefaults]\n    default_realm = R.TEST\n").unwrap();
        let run = |ktname: Option<String>, profile: &std::path::Path| {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "kprop::tests::kpropd_default_keytab_child",
                "--exact",
                "--nocapture",
            ])
            .env("KERBER_KPROPD_KT_CHILD", "1")
            .env("KRB5_KDC_PROFILE", profile)
            .env("KRB5_CONFIG", &krb5_conf)
            .env_remove("KRB5_KTNAME")
            .env_remove("KRB5_KDC_CONF");
            if let Some(kt) = ktname {
                cmd.env("KRB5_KTNAME", kt);
            }
            String::from_utf8_lossy(&cmd.output().unwrap().stdout).into_owned()
        };
        let out = run(Some(format!("FILE:{}", env_kt.display())), &kdc_conf);
        assert!(
            out.contains(&format!("keytab=[{}] kvnos=[5]", env_kt.display())),
            "{out}"
        );
        let out = run(None, &kdc_conf);
        assert!(
            out.contains(&format!("keytab=[{}] kvnos=[6]", prof_kt.display())),
            "{out}"
        );
        let out = run(None, &plain_kdc);
        assert!(out.contains("keytab=[/etc/krb5.keytab]"), "{out}");
        let out = run(Some("BOGUS:/x".into()), &plain_kdc);
        assert!(
            out.contains(r#"error=Some(Resolve("Unknown Key table type"))"#),
            "{out}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// kpropd's own name for the hostname `kdc2` (and `KDC2`), printed by a child of the next test.
    #[test]
    fn kpropd_server_name_child() {
        if std::env::var_os("KERBER_KPROPD_NAME_CHILD").is_some() {
            for host in ["kdc2", "KDC2"] {
                match kpropd_server_name_for(host) {
                    Ok(name) => println!("{host}=[{}]", name.components_joined()),
                    Err(e) => println!("{host}=error {e}"),
                }
            }
        }
    }

    /// MIT `qualify_shortname` (`lib/krb5/os/sn2princ.c:66-80`): kpropd's context reads kdc.conf before krb5.conf, so kdc.conf's `qualify_shortname` qualifies a hostname without a dot, then krb5.conf's, then `LOCALDOMAIN`'s; under `fallback` the name stays as given, and a name this port cannot hold is an error.
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

    /// The documented host's keys and a TGS ticket to it for `admin`, as MIT kprop holds one.
    fn kprop_ticket() -> (Vec<ProtocolKey>, PrincipalName, krb5_kdc::IssuedTgs) {
        let (host_keys, admin, tgs) = kprop_ticket_kvnos();
        (host_keys.into_iter().map(|(k, _)| k).collect(), admin, tgs)
    }

    /// [`kprop_ticket`] with each host key's kvno.
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

    /// MIT kprop's `sendauth` up to its mutual AP-REQ (no subkey, seq-number 4242).
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

    /// kpropd's recvauth of kprop's AP-REQ for the documented host, as `server`, with the keytab
    /// `keytab` makes from the host's keys (each with its kvno) and the ticket: `None` when it
    /// takes the AP-REQ, else the KRB-ERROR it answers.
    fn kpropd_with_keytab(
        keytab: impl FnOnce(&[(ProtocolKey, u32)], &Ticket) -> KpropdKeys,
        server: &PrincipalName,
    ) -> Option<KrbError> {
        kpropd_with_profile(None, keytab, server)
    }

    /// [`kpropd_with_keytab`] with `kdc_conf` as kpropd's KDC profile.
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
            let dir = krb5_testkit::scratch_dir("kpropd-profile");
            if let Some(text) = kdc_conf {
                let path = dir.join("kdc.conf");
                std::fs::write(&path, text).unwrap();
                krb5_config::set_test_kdc_profile(Some(path));
            }
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
                None,
                &ReplayCache::new(),
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

    /// The documented host's keys as keytab entries.
    fn host_entries(keys: &[(ProtocolKey, u32)]) -> Vec<KeytabEntry> {
        let host = krb5_kdc::testrealm::documented_host();
        keys.iter()
            .map(|(k, kvno)| kt_entry(&host, *kvno, 1, k.clone()))
            .collect()
    }

    /// A key of the ticket's enctype that is not the ticket's key.
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

    /// MIT `try_one_princ` (`lib/krb5/krb/rd_req_dec.c:335-346`): kpropd's own entry for the ticket's kvno and enctype is the one key tried, whatever server the ticket names; without one the answer is `NOKEY`, with another kvno `NOT_US`, and a key that cannot decrypt the ticket `NOT_US`, each naming kpropd itself.
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

    /// MIT `k5_canonprinc` (`lib/krb5/os/sn2princ.c:281-307`): under `fallback` a host-based name's hostname is expanded when it is used; otherwise, or for another name, it is used as it is.
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

    /// MIT `keytab_fetch_error` (`lib/krb5/krb/rd_req_dec.c:126-148`): for a ticket that names kpropd itself, another kvno is `BADKEYVER` and a key that cannot decrypt it `BAD_INTEGRITY`; its own entries take it.
    #[test]
    fn kpropd_answers_a_ticket_for_itself_as_mit() {
        let host = krb5_kdc::testrealm::documented_host();
        assert_eq!(
            kpropd_with_keytab(|keys, _| keytab(host_entries(keys), false), &host),
            None
        );
        let e = kpropd_with_keytab(
            |keys, _| {
                let mut entries = host_entries(keys);
                for e in &mut entries {
                    e.kvno += 1;
                }
                keytab(entries, false)
            },
            &host,
        )
        .unwrap();
        assert_eq!(e.error_code, err::BADKEYVER);
        assert_eq!(e_text(&e), b"Key version is not available\0");
        let e = kpropd_with_keytab(
            |_, t| {
                let kvno = t.enc_part.kvno.unwrap_or(0);
                keytab(vec![kt_entry(&host, kvno, 1, wrong_key(t))], false)
            },
            &host,
        )
        .unwrap();
        assert_eq!(e.error_code, err::BAD_INTEGRITY);
        assert_eq!(e_text(&e), b"Decrypt integrity check failed\0");
    }

    /// MIT `decrypt_try_server` (`lib/krb5/krb/rd_req_dec.c:395-432`): with `ignore_acceptor_hostname` any `host` entry of the realm whose key decrypts the ticket serves, whatever its hostname; with none of the ticket's server the answer is `NOT_US`, with no `host` entry `NOKEY`.
    #[test]
    fn kpropd_with_ignore_acceptor_hostname_takes_any_host_key() {
        let own = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "kdc9.kerber.test"]);
        assert_eq!(
            kpropd_with_keytab(|keys, _| keytab(host_entries(keys), true), &own),
            None
        );
        let e = kpropd_with_keytab(
            |_, t| {
                let kvno = t.enc_part.kvno.unwrap_or(0);
                keytab(vec![kt_entry(&own, kvno, 1, wrong_key(t))], true)
            },
            &own,
        )
        .unwrap();
        assert_eq!(e.error_code, err::NOT_US);
        let kiprop = PrincipalName::new(PrincipalName::NT_SRV_HST, ["kiprop", "kdc9.kerber.test"]);
        let e = kpropd_with_keytab(
            |_, t| {
                let kvno = t.enc_part.kvno.unwrap_or(0);
                keytab(vec![kt_entry(&kiprop, kvno, 1, wrong_key(t))], true)
            },
            &own,
        )
        .unwrap();
        assert_eq!(e.error_code, err::NOKEY);
        let e = kpropd_with_keytab(
            |_, _| KpropdKeys {
                error: Some(KpropdKeytabError::Read(
                    "Unsupported key table format version number".into(),
                )),
                ..keytab(Vec::new(), true)
            },
            &own,
        )
        .unwrap();
        assert_eq!(e.error_code, err::NOKEY, "a keytab that cannot be iterated");
    }

    /// MIT `recvauth_common` (`lib/krb5/krb/recvauth.c:150-168`): a keytab that is no keytab (`KRB5_KEYTAB_BADVNO`) is sent as a generic error with MIT's message.
    #[test]
    fn kpropd_answers_a_keytab_that_is_no_keytab_as_mit() {
        let e = kpropd_with_keytab(
            |_, _| KpropdKeys {
                error: Some(KpropdKeytabError::Read(
                    "Unsupported key table format version number".into(),
                )),
                ..keytab(Vec::new(), false)
            },
            &krb5_kdc::testrealm::documented_host(),
        )
        .unwrap();
        assert_eq!(e.error_code, err::GENERIC);
        assert_eq!(e_text(&e), b"Unsupported key table format version number\0");
    }

    /// MIT `krb5_decrypt_tkt_part` (`lib/krb5/krb/decrypt_tk.c:46-50`): a ticket enctype the profile does not permit fails before the key is tried, so kpropd's own entry answers "Encryption type not permitted" whatever its key, and a scan of every entry skips the one that would decrypt it.
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

    /// MIT `krb5_rd_req` (`lib/krb5/krb/rd_req.c:80-84`): a default keytab name that does not resolve is the AP-REQ's answer as a generic error with MIT's text, whatever the server.
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

    /// MIT `krb5_k_decrypt` (`lib/crypto/krb/decrypt.c:48-52`): a ticket shorter than its enctype's header and trailer is `KRB5_BAD_MSIZE`, sent as a generic error.
    #[test]
    fn a_ticket_too_short_to_decrypt_is_mits_bad_msize() {
        let host = krb5_kdc::testrealm::documented_host();
        let (keys, _, tgs) = kprop_ticket_kvnos();
        let mut ticket = tgs.rep.0.ticket.clone();
        ticket.enc_part.cipher = vec![0u8; 8].into();
        let kt = keytab(host_entries(&keys), false);
        let ap = krb5_types::ApReq {
            pvno: 5,
            msg_type: 14,
            ap_options: krb5_types::ApOptions::none(),
            ticket,
            authenticator: tgs.rep.0.ticket.enc_part.clone(),
        };
        let raw = encode(&ap).unwrap();
        let realm = Some(krb5_kdc::testrealm::TEST_REALM);
        let Err((der, text)) = kpropd_ticket_key(&raw, &kt, Some(&host), realm) else {
            panic!("a short ticket must be refused");
        };
        assert_eq!(text, "Message size is incompatible with encryption type");
        let e: KrbError = decode(&der).unwrap();
        assert_eq!(e.error_code, err::GENERIC);
    }

    #[test]
    fn kpropd_ap_rep_echoes_no_subkey_and_takes_a_fresh_thirty_bit_seq() {
        use std::net::TcpListener;
        use std::thread;

        use krb5_asn1::decode;
        use krb5_crypto::{KeyUsage, decrypt};
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
            )
        });
        let mut client = kprop_sends_ap_req(addr, &tgs, &admin);
        assert!(read_message(&mut client).unwrap().is_empty(), "accepted");
        let rep: ApRep = decode(&read_message(&mut client).unwrap()).unwrap();
        let usage = KeyUsage::new(ku::AP_REP_ENC_PART).unwrap();
        let plain = decrypt(&tgs.session_key, usage, rep.enc_part.cipher.as_ref()).unwrap();
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
        let dir = krb5_testkit::scratch_dir("p15a-kpropd-permitted");
        let conf = dir.join("krb5.conf");
        std::fs::write(
            &conf,
            "[libdefaults]\n    permitted_enctypes = aes128-cts-hmac-sha1-96\n",
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            krb5_config::isolate_test_krb5();
            krb5_config::set_test_krb5_paths(Some(vec![conf]));
            let (mut stream, _) = listener.accept().unwrap();
            kpropd_recvauth(
                &mut stream,
                &host_keys,
                Some(&documented_host()),
                Some(TEST_REALM),
                None,
                &ReplayCache::new(),
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
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kpropd_names_its_host_principal_in_a_refusal() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        use krb5_asn1::decode;
        use krb5_kdc::testrealm::TEST_REALM;

        let (host_keys, _, _) = kprop_ticket();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            krb5_config::isolate_test_krb5();
            let (mut stream, _) = listener.accept().unwrap();
            kpropd_recvauth(
                &mut stream,
                &host_keys,
                None,
                Some(TEST_REALM),
                None,
                &ReplayCache::new(),
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

    /// kpropd's answer when kprop's size KRB-SAFE (`size_seq`) or first block KRB-PRIV
    /// (`block_seq`) carries the wrong seq-number, after an authenticator carrying 4242, or when
    /// the size announces `short_by` bytes fewer than the 30-byte block.
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
            )
            .unwrap();
            kpropd_recv_dump(&mut stream, &mut auth)
        });
        let mut client = kprop_sends_ap_req(addr, &tgs, &admin);
        assert!(read_message(&mut client).unwrap().is_empty(), "accepted");
        let _ap_rep = read_message(&mut client).unwrap();
        let dump = b"kdb5_util load_dump version 7\n";
        let size = encode_database_size(dump.len() as u64 - short_by);
        let safe = build_mit_safe(&tgs.session_key, &size, size_seq).unwrap();
        write_message(&mut client, &safe).unwrap();
        if size_seq == 4242 {
            let mut state = CipherState::initial();
            let block =
                build_krb_priv_chained(&tgs.session_key, dump, Some(block_seq), false, &mut state)
                    .unwrap();
            write_message(&mut client, &encode(&block).unwrap()).unwrap();
        }
        let e: KrbError = decode(&read_message(&mut client).unwrap()).expect("KRB-ERROR");
        assert!(join.join().expect("thread").is_err());
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

    /// MIT `recv_database` (`kpropd.c:1450-1458`): a dump longer than its size is answered with this KRB-ERROR and then loaded; this kpropd loads nothing (docs/security.md).
    #[test]
    fn kpropd_refuses_a_dump_longer_than_its_size() {
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
            )
            .unwrap();
            let got = kpropd_recv_dump(&mut stream, &mut auth).unwrap();
            // The ack one seq-number past the AP-REP's, as no kpropd sends it.
            auth.next_local_seq();
            kpropd_send_ack(&mut stream, &mut auth, got.len() as u64).unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let realm = krb5_types::ascii(TEST_REALM);
        let mut auth = kprop_sendauth(
            &mut client,
            tgs.rep.0.ticket.clone(),
            &tgs.session_key,
            &realm,
            &admin,
            4242,
        )
        .unwrap();
        let e = kprop_send_dump(&mut client, &mut auth, &dump).unwrap_err();
        assert!(
            e.to_string()
                .contains("Message out of order while decoding final size packet from server"),
            "{e}"
        );
        join.join().expect("thread");
    }
}
