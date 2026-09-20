//! DNS SRV (`os/dnssrv.c` `krb5int_make_srv_query_realm`;
//! `os/dnsglue.c` `krb5int_dns_init` / `krb5int_dns_nextans`;
//! `os/locate_kdc.c` `dns_locate_server_srv`): `_kerberos._udp` and
//! `_kerberos-adm._tcp`.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use super::{Endpoint, Error};

/// RFC 2782 lookup of `_kerberos._udp.{realm}`.
///
/// # Errors
///
/// Returns [`Error::Dns`] when no records are found or the query fails.
pub fn lookup_srv_kdc(realm: &str) -> Result<Vec<Endpoint>, Error> {
    lookup_srv(&format!("_kerberos._udp.{realm}"), 88)
}

/// RFC 2782 lookup of `_kerberos-adm._tcp.{realm}`.
///
/// # Errors
///
/// Returns [`Error::Dns`] when lookup fails.
pub fn lookup_srv_admin(realm: &str) -> Result<Vec<Endpoint>, Error> {
    lookup_srv(&format!("_kerberos-adm._tcp.{realm}"), 749)
}

fn lookup_srv(name: &str, default_port: u16) -> Result<Vec<Endpoint>, Error> {
    let qname = encode_qname(name);
    let mut msg = Vec::with_capacity(12 + qname.len() + 4);
    msg.extend_from_slice(&[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    msg.extend_from_slice(&qname);
    msg.extend_from_slice(&33u16.to_be_bytes()); // SRV
    msg.extend_from_slice(&1u16.to_be_bytes()); // IN
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| Error::Dns(e.to_string()))?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| Error::Dns(e.to_string()))?;
    let resolvers = ["127.0.0.53:53", "127.0.0.1:53", "1.1.1.1:53", "8.8.8.8:53"];
    let mut last = Error::Dns("no resolver".into());
    for r in resolvers {
        let Ok(addr) = r.parse::<SocketAddr>() else {
            continue;
        };
        if sock.send_to(&msg, addr).is_err() {
            continue;
        }
        let mut buf = [0u8; 2048];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => match parse_srv_answers(&buf[..n], default_port) {
                Ok(list) if !list.is_empty() => return Ok(list),
                Ok(_) => last = Error::Dns("empty SRV".into()),
                Err(e) => last = e,
            },
            Err(e) => last = Error::Dns(e.to_string()),
        }
    }
    Err(last)
}

fn encode_qname(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        let n = u8::try_from(b.len()).unwrap_or(63);
        out.push(n.min(63));
        out.extend_from_slice(&b[..usize::from(n.min(63))]);
    }
    out.push(0);
    out
}

fn parse_srv_answers(msg: &[u8], default_port: u16) -> Result<Vec<Endpoint>, Error> {
    if msg.len() < 12 {
        return Err(Error::Dns("short dns".into()));
    }
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    // skip question
    let mut i = 12;
    i = skip_name(msg, i)?;
    i = i
        .checked_add(4)
        .ok_or_else(|| Error::Dns("overflow".into()))?;
    let mut out = Vec::new();
    for _ in 0..ancount {
        i = skip_name(msg, i)?;
        if i + 10 > msg.len() {
            break;
        }
        let typ = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        i += 10;
        if typ == 33 && i + rdlen <= msg.len() && rdlen >= 6 {
            let port = u16::from_be_bytes([msg[i + 4], msg[i + 5]]);
            let host = decode_name(msg, i + 6).unwrap_or_default();
            if !host.is_empty() {
                out.push(Endpoint {
                    host: host.trim_end_matches('.').to_owned(),
                    port: if port == 0 { default_port } else { port },
                });
            }
        }
        i += rdlen;
    }
    Ok(out)
}

fn skip_name(msg: &[u8], mut i: usize) -> Result<usize, Error> {
    loop {
        if i >= msg.len() {
            return Err(Error::Dns("bad name".into()));
        }
        let len = msg[i];
        if len == 0 {
            return Ok(i + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Ok(i + 2);
        }
        i += 1 + usize::from(len);
    }
}

fn decode_name(msg: &[u8], mut i: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut hops = 0;
    loop {
        if hops > 10 || i >= msg.len() {
            break;
        }
        let len = msg[i];
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            if i + 1 >= msg.len() {
                break;
            }
            i = (u16::from_be_bytes([len & 0x3f, msg[i + 1]])) as usize;
            hops += 1;
            continue;
        }
        i += 1;
        let end = i + usize::from(len);
        if end > msg.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&msg[i..end]).into_owned());
        i = end;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}
