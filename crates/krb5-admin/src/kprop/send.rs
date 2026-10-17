//! kprop, MIT `kprop/kprop.c`: send a replica the dump file `kdb5_util dump` wrote.
//!
//! kprop never opens the KDC database. It gets a ticket for the replica's `host` service from a
//! KDC with its keytab, checks the dump against its `.dump_ok` mark and locks it, sends it after
//! `sendauth` in KRB-PRIV blocks, and on the replica's acknowledgement writes
//! `<dump>.<replica>.last_prop`.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use krb5_asn1::{decode, encode};
use krb5_config::Krb5Conf;
use krb5_crypto::{CipherState, ProtocolKey};
use krb5_kdc::HeldFileLock;
use krb5_protocol::trace::{self, ERROR_TABLE_BASE_KRB5, error_message, kdc_code};
use krb5_protocol::{
    AsRequest, AsTicketOpts, KdcAddr, Keytab, RemoteSeq, build_ap_req_from_authenticator,
    build_krb_priv_chained_from, generate_seq_number, local_host_address, us_timeofday,
    verify_ap_rep, verify_krb_safe_checksum,
};
use krb5_types::{
    ApOptions, Authenticator, HostAddress, KerberosTime, KrbError, Microseconds, PrincipalName,
    Realm, Ticket, err,
};

use super::{
    KPROP_BUFSIZ, KPROP_PROT_VERSION, KpropAuth, SENDAUTH_VERSION, asn1_com_err, build_mit_safe,
    decode_database_size, e_text_with_nul, encode_database_size,
};

/// MIT `KPROP_SERVICE`: the port kprop connects to when `-P` names none, a services name.
pub const KPROP_SERVICE: &str = "krb5_prop";

/// What `get_tickets` failing says after the error (MIT keeps the newline, so a blank line
/// follows).
const GETTING_CREDS: &str = "while getting initial credentials\n";
/// What a `krb5_sendauth` failure says after the error.
const AUTHENTICATING: &str = "while authenticating to server";

/// `ERROR_TABLE_BASE_krb5` plus `n`, a code of MIT's `krb5` error table.
const fn krb5_code(n: i64) -> i64 {
    ERROR_TABLE_BASE_KRB5 + n
}

/// MIT `KRB5_PARSE_MALFORMED`'s text.
const PARSE_MALFORMED_TEXT: &str = "Malformed representation of principal";
/// MIT `KRB5_REALM_UNKNOWN`.
const REALM_UNKNOWN: i64 = krb5_code(154);
/// MIT `KRB5_MUTUAL_FAILED`.
const MUTUAL_FAILED: i64 = krb5_code(158);
/// MIT `KRB5_KT_NOTFOUND`.
const KT_NOTFOUND: i64 = krb5_code(181);
/// MIT `KRB5_SENDAUTH_BADAUTHVERS`.
const SENDAUTH_BADAUTHVERS: i64 = krb5_code(204);
/// MIT `KRB5_SENDAUTH_BADAPPLVERS`.
const SENDAUTH_BADAPPLVERS: i64 = krb5_code(205);
/// MIT `KRB5_SENDAUTH_BADRESPONSE`.
const SENDAUTH_BADRESPONSE: i64 = krb5_code(206);
/// MIT `KRB5_SENDAUTH_REJECTED`.
const SENDAUTH_REJECTED: i64 = krb5_code(207);

/// Why kprop stopped, as MIT's prints it: a `com_err` line, then the lines it prints for a
/// KRB-ERROR the replica's kpropd answered with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KpropError {
    /// The `com_err` line: the error's text (none for a code of 0) and what kprop was doing.
    /// `None` when kprop prints only the KRB-ERROR's lines.
    pub com_err: Option<(Option<String>, String)>,
    /// The KRB-ERROR kpropd answered with.
    pub remote: Option<RemoteError>,
}

/// A KRB-ERROR the replica's kpropd sent kprop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteError {
    /// Its error code.
    pub code: i32,
    /// Its e-text, up to its first NUL, when it carries one.
    pub text: Option<String>,
}

impl RemoteError {
    fn from_krb_error(e: &KrbError) -> Self {
        let text = e.e_text.as_ref().map(|t| {
            let bytes = t.as_bytes();
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        });
        Self {
            code: e.error_code,
            text,
        }
    }
}

impl KpropError {
    /// A failure with `code`'s text (`None` for 0) and `context`.
    fn new(code: Option<String>, context: impl Into<String>) -> Self {
        Self {
            com_err: Some((code, context.into())),
            remote: None,
        }
    }

    /// A failure with MIT's `krb5` table text for `code`.
    fn code(code: i64, context: impl Into<String>) -> Self {
        Self::new(Some(error_message(code)), context)
    }

    /// A failure with the system's text for `e`; an end of stream is `ECONNABORTED`, as
    /// `krb5_net_read` reports a short read.
    fn os(e: &io::Error, context: impl Into<String>) -> Self {
        Self::new(Some(os_text(e)), context)
    }

    /// The lines kprop prints on standard error, each `com_err` line led by `progname`.
    /// MIT `kerberos_authenticate` (`kprop/kprop.c:305-324`): a KRB-ERROR with the generic code is `Generic remote error: TEXT`; any other code goes to `com_err` as "signalled from server", with `Error text from server: TEXT` after it.
    #[must_use]
    pub fn lines(&self, progname: &str) -> Vec<String> {
        let mut lines = Vec::new();
        match &self.com_err {
            Some((Some(code), context)) => lines.push(format!("{progname}: {code} {context}")),
            Some((None, context)) => lines.push(format!("{progname}: {context}")),
            None => {}
        }
        if let Some(r) = &self.remote {
            if r.code == err::GENERIC {
                if let Some(t) = &r.text {
                    lines.push(format!("Generic remote error: {t}"));
                }
            } else if r.code != 0 {
                lines.push(format!(
                    "{progname}: {} signalled from server",
                    error_message(kdc_code(r.code))
                ));
                if let Some(t) = &r.text {
                    lines.push(format!("Error text from server: {t}"));
                }
            }
        }
        lines
    }
}

impl fmt::Display for KpropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines = self.lines("kprop");
        let text: Vec<&str> = lines
            .iter()
            .map(|l| l.strip_prefix("kprop: ").unwrap_or(l).trim_end())
            .collect();
        f.write_str(&text.join("; "))
    }
}

impl std::error::Error for KpropError {}

/// The system's text for `e`, as `strerror` prints it; an end of stream is `ECONNABORTED`'s.
/// MIT `krb5_read_message` (`lib/krb5/os/read_msg.c:40-58`): a read that ends early is `ECONNABORTED`.
fn os_text(e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        return krb5_log::klog::os_error_text(&io::Error::from(nix::errno::Errno::ECONNABORTED));
    }
    krb5_log::klog::os_error_text(e)
}

/// kprop's ticket for the replica: MIT `get_tickets`'s `creds`.
#[derive(Clone, Debug)]
pub struct KpropCreds {
    /// The ticket for `host/<replica>` in kprop's realm.
    pub ticket: Ticket,
    /// Its session key.
    pub session: ProtocolKey,
    /// The ticket's client, kprop's own `host/<this host>`.
    pub client: PrincipalName,
    /// The client's realm.
    pub crealm: Realm,
    /// Seconds to add to this host's clock to read the KDC's: the AS reply's authtime less the
    /// time of the request when `kdc_timesync` is on (MIT's default), else 0. kprop's own
    /// timestamps (its authenticator, its KRB-ERROR) carry it.
    pub time_offset: i64,
}

/// The time now by the context's clock: this host's, moved by `offset` seconds.
/// MIT `krb5_us_timeofday` (`lib/krb5/os/ustime.c:66-82`): with a valid time offset the seconds gain it, the microseconds are this host's.
fn timeofday_with_offset(offset: i64) -> (KerberosTime, Microseconds) {
    let (now, usec) = us_timeofday();
    let secs = i64::from(now.unix_seconds()).saturating_add(offset);
    let secs = u32::try_from(secs.max(0)).unwrap_or(u32::MAX);
    (KerberosTime::from_unix_seconds(secs), usec)
}

/// The ticket options of a request made with no options of the caller's.
/// MIT `krb5_init_creds_init` (`lib/krb5/krb/get_in_tkt.c:896-1005`): forwardable, proxiable and the two lifetimes come from `[libdefaults]` (the realm's own first), as does `noaddresses`, whose false sends the host's addresses.
fn init_creds_ticket_opts(conf: &Krb5Conf, realm: &str) -> Result<AsTicketOpts, KpropError> {
    let addresses = if conf.noaddresses_for(realm) == Some(false) {
        let found = krb5_protocol::os_localaddr()
            .map_err(|e| KpropError::new(Some(init_creds_text(&e)), GETTING_CREDS))?;
        Some(found)
    } else {
        None
    };
    Ok(AsTicketOpts {
        lifetime: conf.ticket_lifetime_for(realm),
        rlife: conf.renew_lifetime_for(realm),
        forwardable: conf.forwardable_for(realm),
        proxiable: conf.proxiable_for(realm),
        addresses,
        anonymous: false,
        starttime: None,
        pac_request: None,
        allowed_preauth_type: None,
        pa_config_in: None,
    })
}

/// kprop's ticket for `replica_host`: one AS exchange with the KDCs of `realm` that krb5.conf
/// names (the send walks that list), as `host/<this host>` with that principal's key from the
/// keytab `keytab` names (`-s`), else the default keytab, asking for `host/<replica>` itself. Both
/// names are made as MIT makes them without DNS ([`krb5_config::local_host_name`],
/// [`krb5_config::expand_hostname`]); the request's options are `krb5_init_creds_init`'s defaults from krb5.conf.
/// MIT `get_tickets` (`kprop/kprop.c:164-214`): the client is `sn2princ_realm` of no host (this one), the service of the replica, both in kprop's realm; a `-s` name that does not resolve is "while resolving keytab", and `krb5_get_init_creds_keytab` with the service unparsed without its realm as `in_tkt_service` does the rest.
/// MIT `sn2princ_realm` (`kprop/kprop_util.c:32-57`): a host-based `host` principal, its realm then set to kprop's.
///
/// # Errors
///
/// [`KpropError`] as MIT's kprop reports each step: a name that cannot be made, a keytab that
/// does not resolve, cannot be read, is no keytab or holds no key for the client, a realm with
/// no KDC, and the AS exchange's failure, each with its `krb5` table text.
pub fn kprop_get_tickets(
    conf: &Krb5Conf,
    realm: &str,
    replica_host: &str,
    keytab: Option<&str>,
) -> Result<KpropCreds, KpropError> {
    krb5_types::try_ascii(realm)
        .map_err(|_| KpropError::new(None, "while setting client principal name"))?;
    let me = krb5_config::local_host_name(conf);
    let client = PrincipalName::try_new(PrincipalName::NT_SRV_HST, ["host", me.as_str()])
        .map_err(|_| KpropError::new(None, "while setting client principal name"))?;
    let replica = krb5_config::expand_hostname(replica_host, conf);
    let server = PrincipalName::try_new(PrincipalName::NT_SRV_HST, ["host", replica.as_str()])
        .map_err(|_| KpropError::new(None, "while setting server principal name"))?;
    let service = server.unparse_no_realm();
    // MIT `krb5_get_init_creds_keytab` (`lib/krb5/krb/gic_keytab.c:287-292`): a NULL keytab is the default one, resolved there.
    let path = crate::kprop::kprop_keytab_file(keytab).map_err(|text| {
        let during = if keytab.is_some() {
            "while resolving keytab"
        } else {
            GETTING_CREDS
        };
        KpropError::new(Some(text.to_owned()), during)
    })?;
    // MIT `krb5_init_creds_init` (`lib/krb5/krb/get_in_tkt.c:850-1054`): the request is traced with its client.
    // MIT `krb5_init_creds_set_service` (`lib/krb5/krb/get_in_tkt.c:1055-1071`): then with its service.
    trace::init_creds(trace::Princ::new(&client, realm.as_bytes()));
    let ticket = init_creds_ticket_opts(conf, realm)?;
    trace::init_creds_service(&service);
    // MIT `build_in_tkt_name` (`lib/krb5/krb/get_in_tkt.c:484-495`): the service is parsed back from its unparsed name, so its type is `krb5_parse_name`'s (NT-PRINCIPAL for `host/<replica>`), in the client's realm.
    let in_tkt_service = krb5_types::principal_from_unparsed(&service, realm)
        .map_err(|_| KpropError::new(Some(PARSE_MALFORMED_TEXT.to_owned()), GETTING_CREDS))?
        .0;
    // MIT `krb5_init_creds_set_keytab` (`lib/krb5/krb/gic_keytab.c:209-213`): a keytab that cannot be read is traced and is no error yet: the request is made, and a key asked of the keytab fails with that error, as the preauth module's or as the reply's.
    let (keys, kt_etypes, unreadable) = match path.as_deref().map(krb5_protocol::read_keytab_file) {
        Some(Err(failure)) => {
            trace::init_creds_keytab_lookup_failed(failure.code, Some(&failure.text));
            (Vec::new(), Vec::new(), Some(failure))
        }
        Some(Ok(bytes)) => {
            // MIT `krb5_init_creds_set_keytab` (`lib/krb5/krb/gic_keytab.c:216-224`): no key for the client is `KRB5_KT_NOTFOUND`, whose table text kprop's `com_err` prints.
            let Some((keys, kt_etypes)) = Keytab::parse(&bytes)
                .ok()
                .and_then(|kt| krb5_protocol::keytab_init_creds_keys(&kt, &client, realm))
            else {
                return Err(KpropError::code(KT_NOTFOUND, GETTING_CREDS));
            };
            trace::init_creds_keytab_lookup(
                trace::Princ::new(&client, realm.as_bytes()),
                &kt_etypes,
            );
            (keys, kt_etypes, None)
        }
        None => return Err(KpropError::code(KT_NOTFOUND, GETTING_CREDS)),
    };
    // MIT `k5_locate_server` (`lib/krb5/os/locate_kdc.c:853-878`): a realm with no KDC is `KRB5_REALM_UNKNOWN`; the located list is handed to the send, which walks it.
    let found = krb5_config::discover_kdc(realm);
    let Some(first) = found.first() else {
        krb5_config::clear_handed();
        return Err(KpropError::code(REALM_UNKNOWN, GETTING_CREDS));
    };
    let kdc = KdcAddr {
        host: first.host.clone(),
        port: first.port,
    };
    krb5_config::hand_kdcs(realm, found);
    let mut etypes = krb5_protocol::conf_etypes(false);
    krb5_protocol::sort_etypes_keytab_first(&mut etypes, &kt_etypes);
    let req = AsRequest {
        cname: client.clone(),
        realm,
        password: b"",
        kdc: &kdc,
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: conf.canonicalize_for(realm),
        sname: Some(&in_tkt_service),
        etypes: Some(&etypes),
        ticket,
    };
    let name = path.map_or_else(String::new, |p| format!("FILE:{}", p.display()));
    let request_time = i64::from(us_timeofday().0.unix_seconds());
    let out = trace::with_gak_keytab(
        || name,
        || match &unreadable {
            Some(failure) => krb5_protocol::as_exchange_with_unreadable_keytab(&req, failure),
            None => krb5_protocol::as_exchange_with_keys(&req, &keys),
        },
    )
    .map_err(|e| KpropError::new(Some(init_creds_text(&e)), GETTING_CREDS))?;
    // MIT `verify_as_reply` (`lib/krb5/krb/get_in_tkt.c:260-264`): with `kdc_timesync` the context's clock takes the offset of the reply's authtime from the request's time, `time(NULL)` when it was sent.
    let time_offset = if conf.kdc_timesync {
        i64::from(out.enc_part.authtime.unix_seconds()) - request_time
    } else {
        0
    };
    Ok(KpropCreds {
        ticket: out.ticket,
        session: out.session_key,
        client: out.cname,
        crealm: out.crealm,
        time_offset,
    })
}

/// The `krb5` table text of an AS exchange's failure, what kprop's `com_err` prints for it.
/// MIT `default_com_err_proc` (`com_err.c:47-96`): the table text, not the message the library set.
/// A keytab lookup and an ASN.1 failure keep their own table texts; every other AS failure is
/// [`krb5_client::errmsg::Krb5Error::from_as`]'s code.
fn init_creds_text(e: &krb5_protocol::Error) -> String {
    use krb5_protocol::Error as E;
    match e {
        // MIT `get_as_key_keytab` (`lib/krb5/krb/gic_keytab.c:68-71`): the keytab lookup's code is the exchange's.
        E::Keytab { code, .. } => error_message(*code),
        E::Asn1(m) => asn1_com_err(m),
        _ => krb5_client::errmsg::Krb5Error::from_as(e, "", "").table_text(),
    }
}

/// The dump file kprop sends, open and locked shared, with its size when it was checked.
#[derive(Debug)]
pub struct KpropDump {
    file: File,
    lock: Option<HeldFileLock>,
    size: u64,
    name: String,
}

impl KpropDump {
    /// Open the dump `data_fn` as kprop sends it: locked shared without waiting, and not newer
    /// than its `<data_fn>.dump_ok` mark, which `kdb5_util dump` writes once the dump is whole.
    /// MIT `open_database` (`kprop/kprop.c:337-386`): open read-only, lock shared without blocking ("database locked" when held), `fstat` it, `stat` the `.dump_ok` file, and refuse a dump whose modification second is later than the mark's.
    ///
    /// # Errors
    ///
    /// [`KpropError`] with MIT's text when the dump does not open, is locked, cannot be
    /// examined, has no `.dump_ok` mark or is newer than it.
    pub fn open(data_fn: &str) -> Result<Self, KpropError> {
        let file = File::open(data_fn)
            .map_err(|e| KpropError::os(&e, format!("while trying to open {data_fn}")))?;
        let lock = match krb5_kdc::lock_file_shared_nowait(&file) {
            Ok(lock) => lock,
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(nix::libc::EAGAIN | nix::libc::EACCES)
                ) =>
            {
                return Err(KpropError::new(None, "database locked"));
            }
            Err(e) => {
                return Err(KpropError::os(
                    &e,
                    format!("while trying to lock '{data_fn}'"),
                ));
            }
        };
        let meta = file
            .metadata()
            .map_err(|e| KpropError::os(&e, format!("while trying to stat {data_fn}")))?;
        let ok_fn = format!("{data_fn}.dump_ok");
        let ok_meta = std::fs::metadata(&ok_fn)
            .map_err(|e| KpropError::os(&e, format!("while trying to stat {ok_fn}")))?;
        if meta.mtime() > ok_meta.mtime() {
            return Err(KpropError::new(
                None,
                format!("'{data_fn}' more recent than '{ok_fn}'."),
            ));
        }
        Ok(Self {
            file,
            lock: Some(lock),
            size: meta.size(),
            name: data_fn.to_owned(),
        })
    }

    /// The dump's size when it was opened (MIT's `st_size`).
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The open dump, read from where the last read stopped.
    pub const fn file(&mut self) -> &mut File {
        &mut self.file
    }

    /// Let the dump's lock go and close it.
    /// MIT `close_database` (`kprop/kprop.c:388-398`): an unlock that fails is reported, and the dump is closed either way.
    ///
    /// # Errors
    ///
    /// [`KpropError`] "while unlocking database" when the unlock fails.
    pub fn close(mut self) -> Result<(), KpropError> {
        match self.lock.take().map(|l| l.unlock(&self.file)) {
            Some(Err(e)) => Err(KpropError::os(
                &e,
                format!("while unlocking database '{}'", self.name),
            )),
            _ => Ok(()),
        }
    }
}

/// The port `service` names, as `getaddrinfo` reads a service for a stream socket: a decimal
/// number (glibc's `strtoul`, so leading blanks and a sign are taken, and the port is its low 16
/// bits), else a `tcp` entry of `/etc/services` by name or alias; `None` when there is none.
/// MIT `open_connection` (`kprop/kprop.c:227-235`): the port goes to `getaddrinfo` as a service name, `krb5_prop` when `-P` names none.
fn service_port(service: &str) -> Option<u16> {
    if service.is_empty() {
        return Some(0);
    }
    if let Some(n) = c_strtoul(service) {
        // glibc keeps the number in an `int`, its low 32 bits: a negative one is looked up as a
        // name, any other is the port's low 16 bits.
        let low = u32::try_from(n & 0xffff_ffff).unwrap_or_default();
        if i32::try_from(low).is_ok() {
            return u16::try_from(low & 0xffff).ok();
        }
    }
    let services = std::fs::read_to_string("/etc/services").ok()?;
    services_port(&services, service, "tcp")
}

/// The value of `s` when all of it is a decimal number to C's `strtoul`: leading blanks, an
/// optional sign, then digits; a negative number wraps, and one too large is `ULONG_MAX`.
fn c_strtoul(s: &str) -> Option<u64> {
    let t = s.trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = digits.parse::<u64>().unwrap_or(u64::MAX);
    Some(if neg { n.wrapping_neg() } else { n })
}

/// The port of `name` for `proto` in a services file's text: the first entry whose name or an
/// alias is `name`, `#` starting a comment.
/// glibc's files backend reads `name port/proto aliases…`, the port as `strtoul` reads it.
fn services_port(services: &str, name: &str, proto: &str) -> Option<u16> {
    for line in services.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut fields = line.split_ascii_whitespace();
        let (Some(sname), Some(port_proto)) = (fields.next(), fields.next()) else {
            continue;
        };
        let Some((port, p)) = port_proto.split_once('/') else {
            continue;
        };
        if p != proto || !(sname == name || fields.any(|a| a == name)) {
            continue;
        }
        if let Ok(port) = port.parse::<u32>() {
            return Some((port & 0xffff) as u16);
        }
    }
    None
}

/// Whether the host has an IPv4 address and an IPv6 address other than the loopback ones, as
/// glibc's `AI_ADDRCONFIG` counts them; when the addresses cannot be listed, both.
#[must_use]
pub fn configured_families() -> (bool, bool) {
    let Ok(addrs) = nix::ifaddrs::getifaddrs() else {
        return (true, true);
    };
    let (mut v4, mut v6) = (false, false);
    for a in addrs.filter_map(|i| i.address) {
        if let Some(sin) = a.as_sockaddr_in() {
            v4 |= sin.ip() != std::net::Ipv4Addr::LOCALHOST;
        } else if let Some(sin6) = a.as_sockaddr_in6() {
            v6 |= sin6.ip() != std::net::Ipv6Addr::LOCALHOST;
        }
    }
    (v4, v6)
}

/// glibc's `gai_strerror` text out of the standard library's lookup error.
fn gai_text(e: &io::Error) -> String {
    let text = krb5_log::klog::os_error_text(e);
    text.strip_prefix("failed to lookup address information: ")
        .map_or_else(|| text.clone(), str::to_owned)
}

/// The addresses `host` and `port` name, as `getaddrinfo` with `AI_ADDRCONFIG` gives them for a
/// stream socket: of the families the host has an address of, both when it has neither.
fn lookup(host: &str, port: &str) -> Result<Vec<SocketAddr>, String> {
    let Some(port) = service_port(port) else {
        // glibc's `EAI_SERVICE`.
        return Err("Servname not supported for ai_socktype".to_owned());
    };
    let found: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| gai_text(&e))?
        .collect();
    let (v4, v6) = configured_families();
    if v4 == v6 {
        return Ok(found);
    }
    let kept: Vec<SocketAddr> = found
        .into_iter()
        .filter(|a| if v4 { a.is_ipv4() } else { a.is_ipv6() })
        .collect();
    if kept.is_empty() {
        // glibc's `EAI_NONAME`.
        return Err("Name or service not known".to_owned());
    }
    Ok(kept)
}

/// A connection to `host` on `port` (a number or a services name) and kprop's own address on it,
/// the sender address of every KRB-SAFE and KRB-PRIV it sends.
/// MIT `open_connection` (`kprop/kprop.c:216-279`): each address `getaddrinfo` gives is tried in turn and the last `connect` error kept (`EINVAL` with none); the local address then comes from `getsockname`.
/// MIT `k5_sockaddr_to_address` (`lib/krb5/os/addr.c:43-75`): an IPv4-mapped IPv6 address is IPv4.
///
/// # Errors
///
/// [`KpropError`] `<host>: <gai_strerror>` when the lookup fails, "while connecting to server"
/// with the last connection error, and "while getting local socket address".
pub fn kprop_open_connection(
    host: &str,
    port: &str,
) -> Result<(TcpStream, HostAddress), KpropError> {
    let addrs = lookup(host, port).map_err(|e| KpropError::new(None, format!("{host}: {e}")))?;
    let mut last = io::Error::from(nix::errno::Errno::EINVAL);
    let mut stream = None;
    for a in addrs {
        match TcpStream::connect(a) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = e,
        }
    }
    let Some(stream) = stream else {
        return Err(KpropError::os(&last, "while connecting to server"));
    };
    let local = stream
        .local_addr()
        .map_err(|e| KpropError::os(&e, "while getting local socket address"))?;
    let ip: IpAddr = local.ip();
    Ok((stream, local_host_address(Some(ip))))
}

/// Read exactly `buf.len()` bytes, as `krb5_net_read` does; an early end is `UnexpectedEof`.
fn net_read(stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<()> {
    stream.read_exact(buf)
}

/// One message of the peer's: its length, then that many bytes.
/// MIT `krb5_read_message` (`lib/krb5/os/read_msg.c:30-62`): a length and the message, a short read `ECONNABORTED`.
fn read_message(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    net_read(stream, &mut hdr)?;
    let n = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(usize::MAX);
    // MIT mallocs what the length says; kprop's replies are small, so a length past 8 MiB is
    // refused as the allocation failing.
    if n > 8 * 1024 * 1024 {
        return Err(io::Error::from(nix::errno::Errno::ENOMEM));
    }
    let mut buf = vec![0u8; n];
    net_read(stream, &mut buf)?;
    Ok(buf)
}

/// MIT `krb5int_is_app_tag` (`include/k5-int.h:1334-1336`): the first byte, constructed bit cleared, is `tag | 0x40`.
fn is_app_tag(raw: &[u8], tag: u8) -> bool {
    raw.first().is_some_and(|b| b & !0x20 == tag | 0x40)
}

/// The authenticated context `krb5_sendauth` leaves kprop: kprop's sequence number, the one the
/// replica's AP-REP gave for its acknowledgement, and `sender_addr` as the local address.
/// MIT `kerberos_authenticate` (`kprop/kprop.c:281-327`): the auth context does sequence numbers, holds kprop's own address as its local one and no remote one, and `krb5_sendauth` runs with mutual authentication; a failure is "while authenticating to server", and a KRB-ERROR the replica answered with is printed after it.
/// MIT `krb5_sendauth` (`lib/krb5/krb/sendauth.c:36-206`): both version strings in one write, kpropd's one-byte answer (1 a bad sendauth version, 2 a bad application version, other than 0 a bad response, none `ECONNABORTED`), the AP-REQ, then an empty message (a non-empty one is the KRB-ERROR of a refusal, `KRB5_SENDAUTH_REJECTED`) and the AP-REP.
/// MIT `krb5_mk_req_extended` (`lib/krb5/krb/mk_req_ext.c:136-143`): a context doing sequence numbers takes a random one for the authenticator, and the authenticator is traced.
/// MIT `krb5_rd_rep` (`lib/krb5/krb/rd_rep.c:68-135`): the AP-REP must be one, must decrypt under the session key and echo the authenticator's time, else `KRB5_MUTUAL_FAILED`; its subkey becomes both of the context's subkeys, and its sequence number the one kpropd's next message carries.
///
/// # Errors
///
/// [`KpropError`] "while authenticating to server" with the failure's text, and the
/// replica's KRB-ERROR when it refused the AP-REQ.
pub fn kprop_sendauth(
    stream: &mut TcpStream,
    creds: &KpropCreds,
    sender_addr: HostAddress,
) -> Result<KpropAuth, KpropError> {
    let io_fail = |e: &io::Error| KpropError::os(e, AUTHENTICATING);
    krb5_protocol::write_messages(stream, &[SENDAUTH_VERSION, KPROP_PROT_VERSION])
        .map_err(|e| io_fail(&e))?;
    let mut result = [0u8; 1];
    net_read(stream, &mut result).map_err(|e| io_fail(&e))?;
    match result[0] {
        0 => {}
        1 => return Err(KpropError::code(SENDAUTH_BADAUTHVERS, AUTHENTICATING)),
        2 => return Err(KpropError::code(SENDAUTH_BADAPPLVERS, AUTHENTICATING)),
        _ => return Err(KpropError::code(SENDAUTH_BADRESPONSE, AUTHENTICATING)),
    }
    let seq =
        generate_seq_number().map_err(|e| KpropError::new(Some(e.to_string()), AUTHENTICATING))?;
    trace::mk_req(
        trace::Princ::new(&creds.client, creds.crealm.as_bytes()),
        trace::Princ::new(&creds.ticket.sname, creds.ticket.realm.as_bytes()),
        i32::from_ne_bytes(seq.to_ne_bytes()),
        None,
        (&creds.session).into(),
    );
    // MIT `generate_authenticator` (`lib/krb5/krb/mk_req_ext.c:269-327`): the client, the sequence number, no checksum, subkey or authorization data here, and the time to the microsecond.
    let (ctime, cusec) = timeofday_with_offset(creds.time_offset);
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: creds.crealm.clone(),
        cname: creds.client.clone(),
        cksum: None,
        cusec,
        ctime,
        subkey: None,
        seq_number: Some(seq),
        authorization_data: None,
    };
    let ap = build_ap_req_from_authenticator(
        creds.ticket.clone(),
        &creds.session,
        ApOptions::mutual_required(),
        &authenticator,
    )
    .map_err(|e| KpropError::new(Some(e.to_string()), AUTHENTICATING))?;
    let ap_der = encode(&ap).map_err(|e| KpropError::new(Some(e.to_string()), AUTHENTICATING))?;
    super::write_message(stream, &ap_der).map_err(|e| io_fail(&e))?;
    let refusal = read_message(stream).map_err(|e| io_fail(&e))?;
    if !refusal.is_empty() {
        // MIT `krb5_rd_error`: a KRB-ERROR that does not decode is that error, nothing after.
        let e: KrbError = decode(&refusal)
            .map_err(|e| KpropError::new(Some(asn1_com_err(&e.to_string())), AUTHENTICATING))?;
        return Err(KpropError {
            com_err: Some((
                Some(error_message(SENDAUTH_REJECTED)),
                AUTHENTICATING.into(),
            )),
            remote: Some(RemoteError::from_krb_error(&e)),
        });
    }
    let ap_rep = read_message(stream).map_err(|e| io_fail(&e))?;
    if !is_app_tag(&ap_rep, 15) {
        return Err(KpropError::code(kdc_code(err::MSG_TYPE), AUTHENTICATING));
    }
    let rep = verify_ap_rep(&ap_rep, &creds.session, &authenticator).map_err(|e| {
        let text = match e {
            krb5_protocol::Error::ReplyMismatch(_) => error_message(MUTUAL_FAILED),
            krb5_protocol::Error::Crypto(_) => error_message(kdc_code(err::BAD_INTEGRITY)),
            krb5_protocol::Error::Asn1(m) => asn1_com_err(&m),
            other => other.to_string(),
        };
        KpropError::new(Some(text), AUTHENTICATING)
    })?;
    let session = match &rep.subkey {
        Some(sk) => super::protocol_key_from_enc(sk)
            .map_err(|e| KpropError::new(Some(e.to_string()), AUTHENTICATING))?,
        None => creds.session.clone(),
    };
    Ok(KpropAuth {
        session,
        local_seq: seq,
        remote: RemoteSeq::new(rep.seq_number.unwrap_or(0)),
        local_addr: sender_addr,
        acceptor: None,
        names: None,
        sender: Some(SenderNames {
            server: creds.ticket.sname.clone(),
            realm: creds.ticket.realm.clone(),
            client: creds.client.clone(),
            crealm: creds.crealm.clone(),
            time_offset: creds.time_offset,
        }),
    })
}

/// The names kprop's own KRB-ERROR carries: its ticket's server, and kprop itself.
#[derive(Clone, Debug)]
pub(super) struct SenderNames {
    server: PrincipalName,
    realm: Realm,
    client: PrincipalName,
    crealm: Realm,
    /// The context's clock offset ([`KpropCreds::time_offset`]).
    time_offset: i64,
}

/// Tell the replica why kprop stops, best effort.
/// MIT `send_error` (`kprop/kprop.c:546-571`): a KRB-ERROR stamped now as the client's time, naming the ticket's server and kprop, its code past the protocol's 127 made generic, and the text with its NUL.
fn send_error(stream: &mut TcpStream, auth: &KpropAuth, text: &str, code: i64) {
    let Some(names) = &auth.sender else {
        return;
    };
    let error_code = i32::try_from(code - ERROR_TABLE_BASE_KRB5)
        .ok()
        .filter(|c| (0..=127).contains(c))
        .unwrap_or(err::GENERIC);
    let (ctime, cusec) = timeofday_with_offset(names.time_offset);
    let pdu = KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: Some(ctime),
        cusec: (cusec.get() != 0).then_some(cusec),
        stime: KerberosTime::from_unix_seconds(0),
        susec: Microseconds::from_subsec_micros(0),
        error_code,
        crealm: Some(names.crealm.clone()),
        cname: Some(names.client.clone()),
        realm: names.realm.clone(),
        sname: names.server.clone(),
        e_text: e_text_with_nul(text),
        e_data: None,
    };
    if let Ok(der) = encode(&pdu) {
        let _ = super::write_message(stream, &der);
    }
}

/// Send `database`, `database_size` bytes, after [`kprop_sendauth`], and wait for the replica's
/// acknowledgement of its size; with `debug`, each block's running total goes to standard
/// output.
/// MIT `xmit_database` (`kprop/kprop.c:409-544`): the size in a KRB-SAFE, then from the initial cipher state the file in KRB-PRIV blocks of up to `KPROP_BUFSIZ` bytes as `read` returns them, each counted ("N bytes sent." under `-d`); a total other than the size is "Premature EOF found for database file!" and a KRB-ERROR to the replica; then the replica's KRB-ERROR is printed, or its KRB-SAFE read in sequence and its size compared.
///
/// # Errors
///
/// [`KpropError`] with MIT's text for each step that fails: a message that cannot be made or
/// sent, a short dump, no answer, the replica's KRB-ERROR, an acknowledgement that does not
/// verify or is out of order, a malformed or different size.
pub fn kprop_xmit_database(
    stream: &mut TcpStream,
    auth: &mut KpropAuth,
    database: &mut dyn Read,
    database_size: u64,
    debug: bool,
) -> Result<(), KpropError> {
    let size = encode_database_size(database_size);
    let seq = auth.next_local_seq();
    let safe = match build_mit_safe(&auth.session, &size, seq, &auth.local_addr) {
        Ok(der) => der,
        Err(e) => {
            send_error(stream, auth, "while encoding database size", krb5_code(60));
            return Err(KpropError::new(
                Some(e.to_string()),
                "while encoding database size",
            ));
        }
    };
    super::write_message(stream, &safe)
        .map_err(|e| KpropError::os(&e, "while sending database size"))?;
    let mut state = CipherState::initial();
    let mut buf = vec![0u8; KPROP_BUFSIZ];
    let mut sent_size: u64 = 0;
    loop {
        // A read that fails ends the file as its end does; the size check below then refuses it.
        let n = match database.read(&mut buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let seq = auth.next_local_seq();
        let block = build_krb_priv_chained_from(
            &auth.session,
            &buf[..n],
            Some(seq),
            false,
            &auth.local_addr,
            &mut state,
        )
        .map_err(|e| e.to_string())
        .and_then(|m| encode(&m).map_err(|e| e.to_string()));
        let block = match block {
            Ok(der) => der,
            Err(e) => {
                let text = format!("while encoding database block starting at {sent_size}");
                send_error(stream, auth, &text, krb5_code(60));
                return Err(KpropError::new(Some(e), text));
            }
        };
        super::write_message(stream, &block).map_err(|e| {
            KpropError::os(
                &e,
                format!("while sending database block starting at {sent_size}"),
            )
        })?;
        sent_size += n as u64;
        if debug {
            println!("{sent_size} bytes sent.");
        }
    }
    zeroize::Zeroize::zeroize(&mut buf);
    if sent_size != database_size {
        let text = "Premature EOF found for database file!";
        send_error(stream, auth, text, krb5_code(60));
        return Err(KpropError::new(None, text));
    }
    let answer = read_message(stream)
        .map_err(|e| KpropError::os(&e, "while reading response from server"))?;
    if is_app_tag(&answer, 30) {
        let e: KrbError = decode(&answer).map_err(|e| {
            KpropError::new(
                Some(asn1_com_err(&e.to_string())),
                "while decoding error response from server",
            )
        })?;
        return Err(KpropError {
            com_err: None,
            remote: Some(RemoteError::from_krb_error(&e)),
        });
    }
    // MIT `krb5_rd_safe` (`lib/krb5/krb/rd_safe.c:127-178`): checked against kprop's local address (the message's receiver, when it names one) and no remote one, then in sequence.
    let decoding = "while decoding final size packet from server";
    let safe = verify_krb_safe_checksum(&auth.session, &answer, None, Some(&auth.local_addr))
        .map_err(|e| KpropError::new(Some(protocol_text(&e)), decoding))?;
    if !auth.remote.check(safe.safe_body.seq_number.unwrap_or(0)) {
        return Err(KpropError::code(kdc_code(err::BADORDER), decoding));
    }
    auth.remote.advance();
    let got = decode_database_size(safe.safe_body.user_data.as_ref()).map_err(|_| {
        KpropError::code(
            kdc_code(err::GENERIC),
            "malformed sent database size message",
        )
    })?;
    if got != database_size {
        return Err(KpropError::new(
            None,
            format!("Kpropd sent database size {got}, expecting {database_size}"),
        ));
    }
    Ok(())
}

/// The `krb5` table text of a protocol failure reading a message.
fn protocol_text(e: &krb5_protocol::Error) -> String {
    match e {
        krb5_protocol::Error::KrbError { code, .. } => error_message(kdc_code(*code)),
        krb5_protocol::Error::Asn1(m) => asn1_com_err(m),
        krb5_protocol::Error::Crypto(_) => error_message(kdc_code(err::BAD_INTEGRITY)),
        other => other.to_string(),
    }
}

/// Mark that `file_name` reached `hostname`: `<file_name>.<hostname>.last_prop`, one NUL byte,
/// mode 0600. A mark that cannot be made is reported and kprop goes on.
/// MIT `update_last_prop_file` (`kprop/kprop.c:573-596`): the name as the replica was given, created or emptied, a single NUL written.
///
/// # Errors
///
/// [`KpropError`] "while creating 'last_prop' file" when the mark cannot be created.
pub fn kprop_update_last_prop_file(hostname: &str, file_name: &str) -> Result<(), KpropError> {
    let path = format!("{file_name}.{hostname}.last_prop");
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut f = krb5_protocol::create_labeled(std::path::Path::new(&path), || opts.open(&path))
        .map_err(|e| KpropError::os(&e, format!("while creating 'last_prop' file, '{path}'")))?;
    let _ = f.write_all(&[0]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_is_a_number_or_a_tcp_entry_by_name_or_alias() {
        let services = "\
# comment\n\
kerberos        88/tcp          kerberos5 krb5  # Kerberos v5\n\
krb5_prop       754/udp\n\
krb5_prop       754/tcp         tell            # Kerberos slave propagation\n";
        assert_eq!(services_port(services, "krb5_prop", "tcp"), Some(754));
        assert_eq!(services_port(services, "tell", "tcp"), Some(754));
        assert_eq!(services_port(services, "krb5", "tcp"), Some(88));
        assert_eq!(services_port(services, "comment", "tcp"), None);
        assert_eq!(services_port(services, "nope", "tcp"), None);
        assert_eq!(c_strtoul("754"), Some(754));
        assert_eq!(c_strtoul(" +754"), Some(754));
        assert_eq!(c_strtoul("754x"), None);
        assert_eq!(c_strtoul(""), None);
        assert_eq!(service_port("1754"), Some(1754));
        assert_eq!(service_port("70000"), Some(4464), "70000's low 16 bits");
        assert_eq!(service_port(""), Some(0));
    }

    /// MIT `krb5_init_creds_init` (`lib/krb5/krb/get_in_tkt.c:896-1005`): a request made with no options of the caller's takes `forwardable`, `proxiable` and the two lifetimes from the client realm's own relations in `[libdefaults]`, then from its top level, and `noaddresses = false` alone sends the host's addresses.
    #[test]
    fn a_request_takes_its_ticket_options_from_krb5_conf_the_realm_first() {
        let conf = Krb5Conf::parse(
            "[libdefaults]\n    forwardable = true\n    ticket_lifetime = 2h\n    renew_lifetime = 1d\n    \
             A.TEST = {\n        forwardable = false\n        proxiable = true\n        ticket_lifetime = 30m\n    }\n",
        )
        .unwrap();
        let a = init_creds_ticket_opts(&conf, "A.TEST").unwrap();
        assert!(!a.forwardable && a.proxiable, "the realm's own relations");
        assert_eq!((a.lifetime, a.rlife), (Some(1800), Some(86400)));
        assert!(a.addresses.is_none());
        let b = init_creds_ticket_opts(&conf, "B.TEST").unwrap();
        assert!(b.forwardable && !b.proxiable, "[libdefaults]'s");
        assert_eq!((b.lifetime, b.rlife), (Some(7200), Some(86400)));
        let sent = Krb5Conf::parse("[libdefaults]\n    noaddresses = false\n").unwrap();
        assert!(
            init_creds_ticket_opts(&sent, "A.TEST")
                .unwrap()
                .addresses
                .is_some()
        );
        let unset = Krb5Conf::parse("[libdefaults]\n    default_realm = A.TEST\n").unwrap();
        let none = init_creds_ticket_opts(&unset, "A.TEST").unwrap();
        assert!(none.addresses.is_none() && !none.forwardable && none.lifetime.is_none());
    }

    /// MIT `default_com_err_proc` (`com_err.c:47-96`): an AS exchange's failure is printed as the `krb5` table's text of its code, never as the extended message the library sets in its place.
    /// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:716-723`): a preauthentication that failed is `KRB5_PREAUTH_FAILED`, "Generic preauthentication failure".
    #[test]
    fn an_as_failure_prints_the_table_text_of_its_code() {
        use krb5_protocol::Error as E;

        let io = E::Io {
            message: "no route".into(),
            kind: io::ErrorKind::TimedOut,
            retryable: true,
        };
        for (e, text) in [
            (
                E::KrbError {
                    code: err::S_PRINCIPAL_UNKNOWN,
                    text: Some("host/x@R not found".into()),
                },
                "Server not found in Kerberos database",
            ),
            (E::ReplyIntegrity, "Decrypt integrity check failed"),
            (io, "Cannot contact any KDC for requested realm"),
            (E::KdcReplySkew, "Clock skew too great in KDC reply"),
            (
                E::ReplyMismatch("Ticket modified in KDC reply".into()),
                "KDC reply did not match expectations",
            ),
            (E::NonceMismatch, "KDC reply did not match expectations"),
            (
                E::PreauthFailed(Box::new(E::Message("Cannot read password".into()))),
                "Generic preauthentication failure",
            ),
            (E::EnctsDisabled, "Generic preauthentication failure"),
        ] {
            assert_eq!(init_creds_text(&e), text, "{e:?}");
        }
    }

    #[test]
    fn a_failure_prints_as_mits_com_err() {
        let e = KpropError::new(None, "database locked");
        assert_eq!(e.lines("kprop"), ["kprop: database locked"]);
        let e = KpropError::code(KT_NOTFOUND, GETTING_CREDS);
        assert_eq!(
            e.lines("kprop"),
            ["kprop: Key table entry not found while getting initial credentials\n"]
        );
        let e = KpropError {
            com_err: Some((
                Some(error_message(SENDAUTH_REJECTED)),
                AUTHENTICATING.into(),
            )),
            remote: Some(RemoteError {
                code: err::NOT_US,
                text: Some("Wrong principal in request".into()),
            }),
        };
        assert_eq!(
            e.lines("kprop"),
            [
                "kprop: Server rejected authentication (during sendauth exchange) while authenticating to server",
                "kprop: The ticket isn't for us signalled from server",
                "Error text from server: Wrong principal in request",
            ]
        );
        let e = KpropError {
            com_err: None,
            remote: Some(RemoteError {
                code: err::GENERIC,
                text: Some("Received 30 bytes".into()),
            }),
        };
        assert_eq!(
            e.lines("kprop"),
            ["Generic remote error: Received 30 bytes"]
        );
    }
}
