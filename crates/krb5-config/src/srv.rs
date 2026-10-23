// MIT: `dns_locate_server_srv` (lib/krb5/os/locate_kdc.c:756-797)
// `_kerberos._udp` then
// MIT: `krb5int_make_srv_query_realm` (lib/krb5/os/dnssrv.c:258-347)
// the query name ends in
// MIT: `krb5int_dns_init` (lib/krb5/os/dnsglue.c:120-194)
// `res_ninit` then `res_nsearch`.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use super::{Endpoint, Error};

const DNS_SRV: u16 = 33;
const DNS_IN: u16 = 1;
const MAX_NS: usize = 3;
const MAX_SEARCH: usize = 6;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_ATTEMPTS: u32 = 2;
const DEFAULT_NDOTS: usize = 1;

#[derive(Clone, Debug)]
struct Resolv {
    servers: Vec<SocketAddr>,
    timeout: Duration,
    attempts: u32,
    ndots: usize,
    search: Vec<String>,
}

impl Resolv {
    fn defaults() -> Self {
        Self {
            servers: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)],
            timeout: DEFAULT_TIMEOUT,
            attempts: DEFAULT_ATTEMPTS,
            ndots: DEFAULT_NDOTS,
            search: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsSrv {
    Send(String),
    Answer {
        priority: u16,
        weight: u16,
        port: u16,
        host: String,
    },
    NotFound,
}

pub fn lookup_srv_kdc(realm: &str) -> Result<Vec<Endpoint>, Error> {
    lookup_srv_kdc_traced(realm, &mut |_| {})
}

pub(crate) fn lookup_srv_kdc_traced(
    realm: &str,
    trace: &mut dyn FnMut(DnsSrv),
) -> Result<Vec<Endpoint>, Error> {
    locate_kdc_srv(realm, &load_resolv(), trace)
}

fn locate_kdc_srv(
    realm: &str,
    resolv: &Resolv,
    trace: &mut dyn FnMut(DnsSrv),
) -> Result<Vec<Endpoint>, Error> {
    locate_named_srv(realm, "_kerberos", resolv, trace)
}

pub(crate) fn lookup_srv_kpasswd(realm: &str) -> Result<Vec<Endpoint>, Error> {
    locate_named_srv(realm, "_kpasswd", &load_resolv(), &mut |_| {})
}

pub(crate) fn lookup_srv_kerberos_adm(realm: &str) -> Result<Vec<Endpoint>, Error> {
    let mut trace = |_| {};
    let tcp = query_service(realm, "_kerberos-adm", "_tcp", &load_resolv(), &mut trace);
    match tcp {
        Find::Hit(list) if !list.is_empty() => Ok(list),
        _ => {
            // MIT: `dns_locate_server_srv` (lib/krb5/os/locate_kdc.c:795)
            trace(DnsSrv::NotFound);
            Err(Error::Dns("no SRV".into()))
        }
    }
}

fn locate_named_srv(
    realm: &str,
    service: &str,
    resolv: &Resolv,
    trace: &mut dyn FnMut(DnsSrv),
) -> Result<Vec<Endpoint>, Error> {
    let udp = query_service(realm, service, "_udp", resolv, trace);
    let tcp = query_service(realm, service, "_tcp", resolv, trace);
    let mut out = Vec::new();
    if let Find::Hit(list) = udp {
        out.extend(list);
    }
    if let Find::Hit(list) = tcp {
        out.extend(list);
    }
    if out.is_empty() {
        // MIT: `dns_locate_server_srv` (lib/krb5/os/locate_kdc.c:795)
        trace(DnsSrv::NotFound);
        Err(Error::Dns("no SRV".into()))
    } else {
        Ok(out)
    }
}

enum Find {
    Hit(Vec<Endpoint>),
    None,
}

fn query_service(
    realm: &str,
    service: &str,
    proto: &str,
    resolv: &Resolv,
    trace: &mut dyn FnMut(DnsSrv),
) -> Find {
    // MIT: `make_lookup_name` (lib/krb5/os/dnssrv.c:50-78)
    // the name ends in `.` so the
    let name = format!("{service}.{proto}.{realm}.");
    // MIT: `krb5int_make_srv_query_realm` (lib/krb5/os/dnssrv.c:286)
    trace(DnsSrv::Send(name.clone()));
    let transport = if proto == "_tcp" {
        super::KdcTransport::Tcp
    } else {
        super::KdcTransport::Udp
    };
    match search(&name, DNS_SRV, resolv) {
        Ok(msg) => srv_targets(&msg, transport, trace),
        Err(_) => Find::None,
    }
}

fn load_resolv() -> Resolv {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let localdomain = std::env::var("LOCALDOMAIN").ok();
    let res_options = std::env::var("RES_OPTIONS").ok();
    parse_resolv(&text, localdomain.as_deref(), res_options.as_deref())
}

fn parse_resolv(text: &str, localdomain: Option<&str>, res_options: Option<&str>) -> Resolv {
    let mut resolv = Resolv {
        servers: Vec::new(),
        timeout: DEFAULT_TIMEOUT,
        attempts: DEFAULT_ATTEMPTS,
        ndots: DEFAULT_NDOTS,
        search: Vec::new(),
    };
    for line in text.lines() {
        let bare = match line.split_once('#') {
            Some((head, _)) => head,
            None => line,
        };
        let mut tok = bare.split_whitespace();
        let Some(key) = tok.next() else {
            continue;
        };
        match key {
            "nameserver" => {
                if resolv.servers.len() >= MAX_NS {
                    continue;
                }
                if let Some(ip) = tok.next().and_then(|s| s.parse::<IpAddr>().ok()) {
                    resolv.servers.push(SocketAddr::new(ip, 53));
                }
            }
            "search" => {
                resolv.search = tok.take(MAX_SEARCH).map(str::to_owned).collect();
            }
            "domain" => {
                resolv.search = tok.next().map(|s| vec![s.to_owned()]).unwrap_or_default();
            }
            "options" => apply_options(&mut resolv, &tok.collect::<Vec<_>>().join(" ")),
            _ => {}
        }
    }
    if let Some(dom) = localdomain {
        resolv.search = dom
            .split_whitespace()
            .take(MAX_SEARCH)
            .map(str::to_owned)
            .collect();
    }
    if let Some(opts) = res_options {
        apply_options(&mut resolv, opts);
    }
    if resolv.servers.is_empty() {
        resolv.servers = Resolv::defaults().servers;
    }
    resolv
}

fn apply_options(resolv: &mut Resolv, text: &str) {
    for tok in text.split_whitespace() {
        if let Some(v) = tok.strip_prefix("timeout:")
            && let Ok(n) = v.parse::<u64>()
            && n > 0
        {
            resolv.timeout = Duration::from_secs(n);
        } else if let Some(v) = tok.strip_prefix("attempts:")
            && let Ok(n) = v.parse::<u32>()
            && n > 0
        {
            resolv.attempts = n;
        } else if let Some(v) = tok.strip_prefix("ndots:")
            && let Ok(n) = v.parse::<usize>()
        {
            resolv.ndots = n;
        }
    }
}

fn search(name: &str, qtype: u16, resolv: &Resolv) -> Result<Vec<u8>, Error> {
    let trailing = name.ends_with('.');
    let bare = name.trim_end_matches('.');
    let dots = bare.bytes().filter(|b| *b == b'.').count();
    if trailing || dots >= resolv.ndots {
        let found = query(bare, qtype, resolv);
        if trailing || matches!(found, Ok(ref msg) if rcode(msg) == 0) {
            return found;
        }
    }
    if !trailing {
        for dom in &resolv.search {
            let joined = if dom.is_empty() {
                bare.to_owned()
            } else {
                format!("{bare}.{}", dom.trim_start_matches('.'))
            };
            if let Ok(msg) = query(&joined, qtype, resolv) {
                let rc = rcode(&msg);
                if rc == 0 || rc == 3 {
                    return Ok(msg);
                }
            }
        }
        if dots < resolv.ndots {
            return query(bare, qtype, resolv);
        }
    }
    Err(Error::Dns("search failed".into()))
}

fn rcode(msg: &[u8]) -> u8 {
    msg.get(3).map_or(0xff, |b| b & 0x0f)
}

fn query(name: &str, qtype: u16, resolv: &Resolv) -> Result<Vec<u8>, Error> {
    let id = random_id()?;
    let qname = encode_qname(name)?;
    let mut msg = Vec::with_capacity(12 + qname.len() + 4);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    msg.extend_from_slice(&qname);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&DNS_IN.to_be_bytes());
    let mut last = Error::Dns("no resolver".into());
    for server in &resolv.servers {
        match send_server(*server, &msg, id, name, qtype, resolv) {
            Ok(buf) => {
                let rc = rcode(&buf);
                if rc == 2 || rc == 4 || rc == 5 {
                    last = Error::Dns(format!("rcode {rc}"));
                    continue;
                }
                return Ok(buf);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn random_id() -> Result<u16, Error> {
    let mut buf = [0u8; 2];
    getrandom::getrandom(&mut buf).map_err(|e| Error::Dns(e.to_string()))?;
    Ok(u16::from_be_bytes(buf))
}

fn send_server(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    name: &str,
    qtype: u16,
    resolv: &Resolv,
) -> Result<Vec<u8>, Error> {
    let mut last = Error::Dns("timeout".into());
    for _ in 0..resolv.attempts {
        match udp_attempt(server, query, id, name, qtype, resolv.timeout) {
            Ok(buf) => return Ok(buf),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn udp_attempt(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    name: &str,
    qtype: u16,
    timeout: Duration,
) -> Result<Vec<u8>, Error> {
    let bind = wildcard(server);
    let sock = UdpSocket::bind(bind).map_err(|e| Error::Dns(e.to_string()))?;
    sock.send_to(query, server)
        .map_err(|e| Error::Dns(e.to_string()))?;
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::Dns("timeout".into()));
        }
        sock.set_read_timeout(Some(left))
            .map_err(|e| Error::Dns(e.to_string()))?;
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if src != server {
                    continue;
                }
                if !accepts(&buf[..n], id, name, qtype) {
                    continue;
                }
                if buf[2] & 0x02 != 0 {
                    return tcp_query(server, query, id, name, qtype, timeout);
                }
                return Ok(buf[..n].to_vec());
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Err(Error::Dns("timeout".into()));
            }
            Err(e) => return Err(Error::Dns(e.to_string())),
        }
    }
}

fn wildcard(server: SocketAddr) -> SocketAddr {
    match server {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
    }
}

fn tcp_query(
    server: SocketAddr,
    query: &[u8],
    id: u16,
    name: &str,
    qtype: u16,
    timeout: Duration,
) -> Result<Vec<u8>, Error> {
    let mut stream =
        TcpStream::connect_timeout(&server, timeout).map_err(|e| Error::Dns(e.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| Error::Dns(e.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| Error::Dns(e.to_string()))?;
    let len = u16::try_from(query.len()).map_err(|_| Error::Dns("query too long".into()))?;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|e| Error::Dns(e.to_string()))?;
    stream
        .write_all(query)
        .map_err(|e| Error::Dns(e.to_string()))?;
    let mut lenbuf = [0u8; 2];
    stream
        .read_exact(&mut lenbuf)
        .map_err(|e| Error::Dns(e.to_string()))?;
    let n = usize::from(u16::from_be_bytes(lenbuf));
    let mut body = vec![0u8; n];
    stream
        .read_exact(&mut body)
        .map_err(|e| Error::Dns(e.to_string()))?;
    if !accepts(&body, id, name, qtype) {
        return Err(Error::Dns("tcp answer mismatch".into()));
    }
    Ok(body)
}

fn accepts(msg: &[u8], id: u16, name: &str, qtype: u16) -> bool {
    if msg.len() < 12 || msg[2] & 0x80 == 0 {
        return false;
    }
    if u16::from_be_bytes([msg[0], msg[1]]) != id {
        return false;
    }
    let qd = usize::from(u16::from_be_bytes([msg[4], msg[5]]));
    if qd == 0 {
        return false;
    }
    let mut i = 12;
    let Some(qname) = decode_name(msg, i) else {
        return false;
    };
    i = match skip_name(msg, i) {
        Ok(n) => n,
        Err(()) => return false,
    };
    if i + 4 > msg.len() {
        return false;
    }
    let typ = u16::from_be_bytes([msg[i], msg[i + 1]]);
    let class = u16::from_be_bytes([msg[i + 2], msg[i + 3]]);
    eq_name(&qname, name) && typ == qtype && class == DNS_IN
}

fn eq_name(got: &str, want: &str) -> bool {
    got.trim_end_matches('.')
        .eq_ignore_ascii_case(want.trim_end_matches('.'))
}

fn trace_host(host: &str) -> String {
    let host = mit_host(host);
    if host.ends_with('.') {
        host
    } else {
        format!("{host}.")
    }
}

fn mit_host(host: &str) -> String {
    // MIT: `locate_srv_dns_1` (lib/krb5/os/locate_kdc.c:379-382)
    // a sole empty host is no service.
    if host.is_empty() || host == "." || host == ".." {
        "..".to_string()
    } else {
        host.to_string()
    }
}

fn srv_targets(msg: &[u8], transport: super::KdcTransport, trace: &mut dyn FnMut(DnsSrv)) -> Find {
    let mut recs = parse_srv(msg);
    if recs.is_empty() {
        return Find::None;
    }
    for rec in &recs {
        // MIT: `krb5int_make_srv_query_realm` (lib/krb5/os/dnssrv.c:337)
        trace(DnsSrv::Answer {
            priority: rec.1,
            weight: rec.2,
            port: rec.3,
            host: trace_host(&rec.0),
        });
    }
    for rec in &mut recs {
        rec.0 = mit_host(&rec.0);
    }
    // MIT place_srv_entry; see docs/parity/b1-client.md
    let mut order: Vec<usize> = (0..recs.len()).collect();
    order.sort_by(|&a, &b| recs[a].1.cmp(&recs[b].1).then(a.cmp(&b)));
    Find::Hit(
        order
            .into_iter()
            .map(|i| Endpoint {
                host: recs[i].0.clone(),
                port: recs[i].3,
                transport,
            })
            .collect(),
    )
}

fn parse_srv(msg: &[u8]) -> Vec<(String, u16, u16, u16)> {
    if msg.len() < 12 {
        return Vec::new();
    }
    let qd = usize::from(u16::from_be_bytes([msg[4], msg[5]]));
    let an = usize::from(u16::from_be_bytes([msg[6], msg[7]]));
    let mut i = 12;
    for _ in 0..qd {
        i = match skip_name(msg, i) {
            Ok(n) => n,
            Err(()) => return Vec::new(),
        };
        i = i.saturating_add(4);
    }
    let mut out = Vec::new();
    for _ in 0..an {
        i = match skip_name(msg, i) {
            Ok(n) => n,
            Err(()) => break,
        };
        if i + 10 > msg.len() {
            break;
        }
        let typ = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let class = u16::from_be_bytes([msg[i + 2], msg[i + 3]]);
        let rdlen = usize::from(u16::from_be_bytes([msg[i + 8], msg[i + 9]]));
        i += 10;
        if i + rdlen > msg.len() {
            break;
        }
        if typ == DNS_SRV && class == DNS_IN && rdlen >= 6 {
            let prio = u16::from_be_bytes([msg[i], msg[i + 1]]);
            let weight = u16::from_be_bytes([msg[i + 2], msg[i + 3]]);
            let port = u16::from_be_bytes([msg[i + 4], msg[i + 5]]);
            let host = decode_name(msg, i + 6).unwrap_or_default();
            out.push((host, prio, weight, port));
        }
        i += rdlen;
    }
    out
}

fn encode_qname(name: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let bare = name.trim_end_matches('.');
    if bare.is_empty() {
        out.push(0);
        return Ok(out);
    }
    for label in bare.split('.') {
        let b = label.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return Err(Error::Dns("bad label".into()));
        }
        let n = u8::try_from(b.len()).map_err(|_| Error::Dns("bad label".into()))?;
        out.push(n);
        out.extend_from_slice(b);
    }
    out.push(0);
    Ok(out)
}

fn skip_name(msg: &[u8], mut i: usize) -> Result<usize, ()> {
    let mut hops = 0;
    loop {
        if i >= msg.len() || hops > 16 {
            return Err(());
        }
        let len = msg[i];
        if len == 0 {
            return Ok(i + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Ok(i + 2);
        }
        i = i.saturating_add(1).saturating_add(usize::from(len));
        hops += 1;
    }
}

fn decode_name(msg: &[u8], mut i: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut hops = 0;
    loop {
        if hops > 16 || i >= msg.len() {
            return None;
        }
        let len = msg[i];
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            if i + 1 >= msg.len() {
                return None;
            }
            i = usize::from(u16::from_be_bytes([len & 0x3f, msg[i + 1]]));
            hops += 1;
            continue;
        }
        i += 1;
        let end = i + usize::from(len);
        if end > msg.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&msg[i..end]).into_owned());
        i = end;
    }
    Some(labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    fn resolv_at(addr: SocketAddr) -> Resolv {
        Resolv {
            servers: vec![addr],
            timeout: Duration::from_secs(2),
            attempts: 1,
            ndots: 1,
            search: Vec::new(),
        }
    }

    fn bind_udp() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    fn header(id: u16, flags: u16, qd: u16, an: u16) -> [u8; 12] {
        let mut h = [0u8; 12];
        h[0..2].copy_from_slice(&id.to_be_bytes());
        h[2..4].copy_from_slice(&flags.to_be_bytes());
        h[4..6].copy_from_slice(&qd.to_be_bytes());
        h[6..8].copy_from_slice(&an.to_be_bytes());
        h
    }

    fn answer(
        id: u16,
        qname: &[u8],
        flags: u16,
        rdata_host: &str,
        port: u16,
        prio: u16,
        weight: u16,
    ) -> Vec<u8> {
        let mut msg = header(id, flags, 1, 1).to_vec();
        msg.extend_from_slice(qname);
        msg.extend_from_slice(&DNS_SRV.to_be_bytes());
        msg.extend_from_slice(&DNS_IN.to_be_bytes());
        msg.extend_from_slice(qname);
        msg.extend_from_slice(&DNS_SRV.to_be_bytes());
        msg.extend_from_slice(&DNS_IN.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        let host = encode_qname(rdata_host).unwrap();
        let rdlen = 6 + host.len();
        msg.extend_from_slice(&u16::try_from(rdlen).unwrap().to_be_bytes());
        msg.extend_from_slice(&prio.to_be_bytes());
        msg.extend_from_slice(&weight.to_be_bytes());
        msg.extend_from_slice(&port.to_be_bytes());
        msg.extend_from_slice(&host);
        msg
    }

    type Script = Arc<dyn Fn(&UdpSocket, SocketAddr, &[u8]) + Send + Sync>;

    fn serve_script(script: Script) -> SocketAddr {
        let sock = bind_udp();
        let addr = sock.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));
            if let Ok((n, src)) = sock.recv_from(&mut buf) {
                script(&sock, src, &buf[..n]);
            }
        });
        addr
    }

    #[test]
    fn wrong_id_wrong_question_and_wrong_source_are_ignored() {
        let good_host = "kdc.example";
        let addr = serve_script(Arc::new(move |sock, src, q| {
            let id = u16::from_be_bytes([q[0], q[1]]);
            let qname = &q[12..q.len() - 4];
            let bad_id = answer(id ^ 0xffff, qname, 0x8180, "bad-id.example", 88, 0, 0);
            let _ = sock.send_to(&bad_id, src);
            let mut other = qname.to_vec();
            if let Some(b) = other.get_mut(1) {
                *b = b.wrapping_add(1);
            }
            let bad_q = answer(id, &other, 0x8180, "bad-q.example", 88, 0, 0);
            let _ = sock.send_to(&bad_q, src);
            let spoof = answer(id, qname, 0x8180, "spoof.example", 88, 0, 0);
            let other_sock = bind_udp();
            let _ = other_sock.send_to(&spoof, src);
            let good = answer(id, qname, 0x8180, good_host, 88, 0, 0);
            let _ = sock.send_to(&good, src);
        }));
        let found = locate_kdc_srv("EXAMPLE", &resolv_at(addr), &mut |_| {}).unwrap();
        assert_eq!(found[0].host, good_host);
        assert_eq!(found[0].port, 88);
    }
}
