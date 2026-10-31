//! Sends the dump file. It never opens the KDC database.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use krb5_asn1::{decode, encode};
use krb5_config::{ClientContext, Krb5Conf};
use krb5_crypto::{CipherState, ProtocolKey};
use krb5_kdc::HeldFileLock;
use krb5_protocol::trace::{self, ERROR_TABLE_BASE_KRB5, error_message, kdc_code};
use krb5_protocol::{
    ApAuthenticator, AsRequest, AsTicketOpts, KdcAddr, Keytab, RemoteSeq,
    build_ap_req_from_authenticator, build_krb_priv_chained_from, generate_ap_authenticator,
    generate_seq_number, local_host_address, us_timeofday, verify_ap_rep, verify_krb_safe_checksum,
};
use krb5_types::{
    ApOptions, HostAddress, KerberosTime, KrbError, Microseconds, PrincipalName, Realm, Ticket, err,
};

use super::{
    KPROP_BUFSIZ, KPROP_PROT_VERSION, KpropAuth, SENDAUTH_VERSION, asn1_com_err, build_mit_safe,
    decode_database_size, e_text_with_nul, encode_database_size,
};

pub const KPROP_SERVICE: &str = "krb5_prop";

const GETTING_CREDS: &str = "while getting initial credentials\n";
const AUTHENTICATING: &str = "while authenticating to server";

const fn krb5_code(n: i64) -> i64 {
    ERROR_TABLE_BASE_KRB5 + n
}

const PARSE_MALFORMED_TEXT: &str = "Malformed representation of principal";
const REALM_UNKNOWN: i64 = krb5_code(154);
const MUTUAL_FAILED: i64 = krb5_code(158);
const KT_NOTFOUND: i64 = krb5_code(181);
const SENDAUTH_BADAUTHVERS: i64 = krb5_code(204);
const SENDAUTH_BADAPPLVERS: i64 = krb5_code(205);
const SENDAUTH_BADRESPONSE: i64 = krb5_code(206);
const SENDAUTH_REJECTED: i64 = krb5_code(207);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KpropError {
    pub com_err: Option<(Option<String>, String)>,
    pub remote: Option<RemoteError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteError {
    pub code: i32,
    pub text: Option<String>,
}

impl RemoteError {
    pub(super) fn from_krb_error(e: &KrbError) -> Self {
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
    fn new(code: Option<String>, context: impl Into<String>) -> Self {
        Self {
            com_err: Some((code, context.into())),
            remote: None,
        }
    }

    fn code(code: i64, context: impl Into<String>) -> Self {
        Self::new(Some(error_message(code)), context)
    }

    fn os(e: &io::Error, context: impl Into<String>) -> Self {
        Self::new(Some(os_text(e)), context)
    }

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

pub(super) fn os_text(e: &io::Error) -> String {
    // sendauth's missing answer byte is `ECONNABORTED`.
    if e.kind() == io::ErrorKind::UnexpectedEof {
        return krb5_log::klog::os_error_text(&io::Error::from(nix::errno::Errno::ECONNABORTED));
    }
    krb5_log::klog::os_error_text(e)
}

#[derive(Clone, Debug)]
pub struct KpropCreds {
    pub ticket: Ticket,
    pub session: ProtocolKey,
    pub client: PrincipalName,
    pub crealm: Realm,
    /// AS authtime minus the request time when `kdc_timesync` is on, else 0.
    pub time_offset: i64,
    pub client_aware: bool,
    pub client_aware_invalid: bool,
}

// MIT: `krb5_us_timeofday` (lib/krb5/os/ustime.c:66-82)
fn timeofday_with_offset(offset: i64) -> (KerberosTime, Microseconds) {
    let (now, usec) = us_timeofday();
    let secs = i64::from(now.unix_seconds()).saturating_add(offset);
    let secs = u32::try_from(secs.max(0)).unwrap_or(u32::MAX);
    (KerberosTime::from_unix_seconds(secs), usec)
}

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
        restart: None,
    })
}

// MIT: `get_tickets` (kprop/kprop.c:164-214)
pub fn kprop_get_tickets(
    ctx: &ClientContext,
    realm: &str,
    replica_host: &str,
    keytab: Option<&str>,
) -> Result<KpropCreds, KpropError> {
    krb5_types::try_ascii(realm)
        .map_err(|_| KpropError::new(None, "while setting client principal name"))?;
    let conf = &ctx.profile;
    let me = krb5_config::local_host_name(conf);
    let client = PrincipalName::try_new(PrincipalName::NT_SRV_HST, ["host", me.as_str()])
        .map_err(|_| KpropError::new(None, "while setting client principal name"))?;
    let replica = krb5_config::expand_hostname(replica_host, conf);
    let server = PrincipalName::try_new(PrincipalName::NT_SRV_HST, ["host", replica.as_str()])
        .map_err(|_| KpropError::new(None, "while setting server principal name"))?;
    init_creds_keytab(
        ctx,
        realm,
        &client,
        &server.unparse_no_realm(),
        keytab,
        false,
    )
}

// MIT: `gic_iter` (lib/kadm5/clnt/client_init.c:439-517)
/// `unforwardable` also clears proxiable, as a kadm5 client asks.
pub(crate) fn init_creds_keytab(
    ctx: &ClientContext,
    realm: &str,
    client: &PrincipalName,
    service: &str,
    keytab: Option<&str>,
    unforwardable: bool,
) -> Result<KpropCreds, KpropError> {
    // MIT: `krb5_get_init_creds_keytab` (lib/krb5/krb/gic_keytab.c:287-292)
    let conf = &ctx.profile;
    let path = crate::kadmin_cli::keytab_file_of(keytab, ctx).map_err(|text| {
        let during = if keytab.is_some() {
            "while resolving keytab"
        } else {
            GETTING_CREDS
        };
        KpropError::new(Some(text.to_owned()), during)
    })?;
    // MIT: `krb5_init_creds_set_service` (lib/krb5/krb/get_in_tkt.c:1055-1071)
    trace::init_creds(trace::Princ::new(client, realm.as_bytes()));
    let mut ticket = init_creds_ticket_opts(conf, realm)?;
    if unforwardable {
        ticket.forwardable = false;
        ticket.proxiable = false;
    }
    trace::init_creds_service(service);
    // MIT: `build_in_tkt_name` (lib/krb5/krb/get_in_tkt.c:484-495)
    let in_tkt_service = krb5_types::principal_from_unparsed(service, realm)
        .map_err(|_| KpropError::new(Some(PARSE_MALFORMED_TEXT.to_owned()), GETTING_CREDS))?
        .0;
    // MIT: `krb5_init_creds_set_keytab` (lib/krb5/krb/gic_keytab.c:209-213)
    // An unreadable keytab is traced and is not an error until a key is asked.
    let (keys, kt_etypes, unreadable) = match path.as_deref().map(krb5_protocol::read_keytab_file) {
        Some(Err(failure)) => {
            trace::init_creds_keytab_lookup_failed(failure.code, Some(&failure.text));
            (Vec::new(), Vec::new(), Some(failure))
        }
        Some(Ok(bytes)) => {
            let Some((keys, kt_etypes)) = Keytab::parse(&bytes)
                .ok()
                .and_then(|kt| krb5_protocol::keytab_init_creds_keys(&kt, client, realm))
            else {
                return Err(KpropError::code(KT_NOTFOUND, GETTING_CREDS));
            };
            trace::init_creds_keytab_lookup(
                trace::Princ::new(client, realm.as_bytes()),
                &kt_etypes,
            );
            (keys, kt_etypes, None)
        }
        None => return Err(KpropError::code(KT_NOTFOUND, GETTING_CREDS)),
    };
    let found = match conf.kdcs_for_traced(realm, &mut krb5_protocol::trace::dns_srv) {
        Ok(list) => list,
        Err(krb5_config::Error::InvalidArgument) => {
            return Err(KpropError::code(
                i64::from(nix::errno::Errno::EINVAL as i32),
                GETTING_CREDS,
            ));
        }
        Err(_) => Vec::new(),
    };
    let Some(first) = found.first() else {
        krb5_config::clear_handed();
        return Err(KpropError::code(REALM_UNKNOWN, GETTING_CREDS));
    };
    let kdc = KdcAddr {
        host: first.host.clone(),
        port: first.port,
    };
    krb5_config::hand_kdcs(realm, found);
    let mut etypes = krb5_protocol::conf_etypes(conf, false);
    krb5_protocol::sort_etypes_keytab_first(&mut etypes, &kt_etypes);
    let pkinit = krb5_client::profile_pkinit(conf, realm)
        .map_err(|e| KpropError::new(Some(e.to_string()), GETTING_CREDS))?;
    let req = AsRequest {
        cname: client.clone(),
        realm,
        password: b"",
        kdc: &kdc,
        profile: conf,
        want_spake: false,
        fast_armor: None,
        pkinit: Some(pkinit.arg()),
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
        client_aware: conf.client_aware_channel_bindings,
        client_aware_invalid: conf.client_aware_channel_bindings_invalid,
    })
}

fn init_creds_text(e: &krb5_protocol::Error) -> String {
    use krb5_protocol::Error as E;
    match e {
        // MIT: `get_as_key_keytab` (lib/krb5/krb/gic_keytab.c:68-71)
        E::Keytab { code, .. } => error_message(*code),
        E::Asn1(m) => asn1_com_err(m),
        _ => krb5_client::errmsg::Krb5Error::from_as(e, "", "").table_text(),
    }
}

#[derive(Debug)]
pub struct KpropDump {
    file: File,
    lock: Option<HeldFileLock>,
    size: u64,
    name: String,
}

impl KpropDump {
    // MIT: `open_database` (kprop/kprop.c:337-386)
    /// `kdb5_util dump` writes `.dump_ok` only once the dump is whole, so a newer dump is refused.
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

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn file(&mut self) -> &mut File {
        &mut self.file
    }

    // MIT: `close_database` (kprop/kprop.c:388-398)
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

// MIT: `open_connection` (kprop/kprop.c:227-235)
#[must_use]
pub fn service_port(service: &str) -> Option<u16> {
    if service.is_empty() {
        return Some(0);
    }
    if let Some(n) = c_strtoul(service) {
        let low = u32::try_from(n & 0xffff_ffff).unwrap_or_default();
        if i32::try_from(low).is_ok() {
            return u16::try_from(low & 0xffff).ok();
        }
    }
    let services = std::fs::read_to_string("/etc/services").ok()?;
    services_port(&services, service, "tcp")
}

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

fn gai_text(e: &io::Error) -> String {
    let text = krb5_log::klog::os_error_text(e);
    text.strip_prefix("failed to lookup address information: ")
        .map_or_else(|| text.clone(), str::to_owned)
}

fn lookup(host: &str, port: &str) -> Result<Vec<SocketAddr>, String> {
    let Some(port) = service_port(port) else {
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
        return Err("Name or service not known".to_owned());
    }
    Ok(kept)
}

/// MIT uses the OS default. mit-deviations.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

// MIT: `k5_sockaddr_to_address` (lib/krb5/os/addr.c:43-75)
pub fn kprop_open_connection(
    host: &str,
    port: &str,
) -> Result<(TcpStream, HostAddress), KpropError> {
    let addrs = lookup(host, port).map_err(|e| KpropError::new(None, format!("{host}: {e}")))?;
    let mut last = io::Error::from(nix::errno::Errno::EINVAL);
    let mut stream = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
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

fn net_read(stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<()> {
    stream.read_exact(buf)
}

fn read_message(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    net_read(stream, &mut hdr)?;
    let n = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(usize::MAX);
    // Too big is `ENOMEM`, as the allocation failing.
    if n > 8 * 1024 * 1024 {
        return Err(io::Error::from(nix::errno::Errno::ENOMEM));
    }
    let mut buf = vec![0u8; n];
    net_read(stream, &mut buf)?;
    Ok(buf)
}

pub(crate) fn is_app_tag(raw: &[u8], tag: u8) -> bool {
    raw.first().is_some_and(|b| b & !0x20 == tag | 0x40)
}

// MIT: `krb5_sendauth` (lib/krb5/krb/sendauth.c:36-206)
// MIT: `krb5_mk_req_extended` (lib/krb5/krb/mk_req_ext.c:136-143)
// MIT: `krb5_rd_rep` (lib/krb5/krb/rd_rep.c:68-135)
/// Versions, one answer byte, the AP-REQ, empty or the refusal's KRB-ERROR, then the AP-REP.
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
    let stub = creds.client_aware_invalid.then(|| krb5_config::Krb5Conf {
        client_aware_channel_bindings_invalid: true,
        ..krb5_config::Krb5Conf::default()
    });
    let authenticator = generate_ap_authenticator(ApAuthenticator {
        crealm: &creds.crealm,
        cname: &creds.client,
        cksum: None,
        subkey: None,
        sequence: Some(seq),
        time_offset: creds.time_offset,
        cbt: creds.client_aware,
        desired_etypes: &[],
        ticket_etype: creds.session.etype().to_iana(),
        profile: stub.as_ref(),
    })
    .map_err(|e| KpropError::new(Some(e.to_string()), AUTHENTICATING))?;
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
    // 15 is an AP-REP.
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

#[derive(Clone, Debug)]
pub(super) struct SenderNames {
    server: PrincipalName,
    realm: Realm,
    client: PrincipalName,
    crealm: Realm,
    time_offset: i64,
}

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
        // A failed read ends the file; the size check then refuses it.
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
    // MIT: `krb5_rd_safe` (lib/krb5/krb/rd_safe.c:127-178)
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

fn protocol_text(e: &krb5_protocol::Error) -> String {
    match e {
        krb5_protocol::Error::KrbError { code, .. } => error_message(kdc_code(*code)),
        krb5_protocol::Error::Asn1(m) => asn1_com_err(m),
        krb5_protocol::Error::Crypto(_) => error_message(kdc_code(err::BAD_INTEGRITY)),
        other => other.to_string(),
    }
}

// MIT: `update_last_prop_file` (kprop/kprop.c:573-596)
/// The caller reports a failure and still exits 0.
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
