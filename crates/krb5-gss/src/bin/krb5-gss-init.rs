//! GSS initiator for out-of-process MIT `gss-server` interop (RFC 4121).
//!
//! Speaks the MIT `gss-sample` TCP framing: 4-byte length prefix then token.
//! Usage: `krb5-gss-init --ccache PATH --host HOST --ip IP --port PORT [--deleg]`

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use krb5_asn1::{decode, encode};
use krb5_gss::{ChannelBindings, DelegCred, GssContext, IovBuf, IovType, KRB5_OID};
use krb5_protocol::{AsOutcome, FileCcache, KdcAddr, build_ap_req_with_cksum, tgs_forward};
use krb5_types::{ApOptions, EncKdcRepPart, EncryptionKey, KerberosTime, Ticket, TicketFlags};

fn main() {
    let mut ccache = None::<String>;
    let mut host = None::<String>;
    let mut ip = "127.0.0.1".to_owned();
    let mut port = 4444u16;
    let mut deleg = false;
    let mut mutate = None::<String>;
    let mut bind_data = None::<String>;
    let mut no_checksum = false;
    let mut accept_only = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--ccache" => ccache = args.next(),
            "--host" => host = args.next(),
            "--ip" => {
                if let Some(v) = args.next() {
                    ip = v;
                }
            }
            "--port" => {
                if let Some(v) = args.next() {
                    port = v.parse().unwrap_or(4444);
                }
            }
            "--deleg" => deleg = true,
            "--mutate" => mutate = args.next(),
            "--channel-bindings" => bind_data = args.next(),
            "--no-checksum" => no_checksum = true,
            "--accept-only" => accept_only = true,
            _ => {}
        }
    }
    let (Some(cc_path), Some(host_name)) = (ccache, host) else {
        eprintln!(
            "usage: krb5-gss-init --ccache PATH --host HOST [--ip IP] [--port PORT] [--deleg] [--mutate direction|filler|ec] [--channel-bindings DATA] [--no-checksum] [--accept-only]"
        );
        std::process::exit(2);
    };
    let cc = FileCcache::parse(&std::fs::read(&cc_path).unwrap_or_default()).unwrap_or_else(|e| {
        eprintln!("ccache: {e}");
        std::process::exit(1);
    });
    let tgt = cc
        .creds
        .iter()
        .find(|c| !c.is_config() && c.server.1.components_joined().starts_with("krbtgt/"));
    let svc = cc.creds.iter().find(|c| {
        !c.is_config()
            && c.server
                .1
                .components_joined()
                .starts_with(&format!("host/{host_name}"))
    });
    let (Some(tgt), Some(svc)) = (tgt, svc) else {
        eprintln!("ccache missing TGT or host/{host_name} ticket");
        std::process::exit(1);
    };
    let ticket: Ticket = decode(&svc.ticket).unwrap_or_else(|e| {
        eprintln!("host ticket: {e}");
        std::process::exit(1);
    });
    let svc_key = svc.session_key().unwrap_or_else(|e| {
        eprintln!("host session key: {e}");
        std::process::exit(1);
    });
    let deleg_cred = if deleg {
        let session = tgt.session_key().unwrap_or_else(|e| {
            eprintln!("tgt session key: {e}");
            std::process::exit(1);
        });
        let tkt: Ticket = decode(&tgt.ticket).unwrap_or_else(|e| {
            eprintln!("tgt: {e}");
            std::process::exit(1);
        });
        let as_out = AsOutcome {
            ticket: tkt,
            enc_part: EncKdcRepPart {
                key: EncryptionKey {
                    keytype: session.etype().to_iana(),
                    keyvalue: session.as_bytes().to_vec().into(),
                },
                last_req: Vec::new(),
                nonce: 0,
                key_expiration: None,
                flags: TicketFlags::from_u32(tgt.ticket_flags),
                authtime: KerberosTime::from_unix_seconds(tgt.authtime),
                starttime: Some(KerberosTime::from_unix_seconds(tgt.starttime)),
                endtime: KerberosTime::from_unix_seconds(tgt.endtime),
                renew_till: (tgt.renew_till > 0)
                    .then(|| KerberosTime::from_unix_seconds(tgt.renew_till)),
                srealm: tgt.server.0.clone(),
                sname: tgt.server.1.clone(),
                caddr: None,
                encrypted_pa_data: None,
            },
            client_key: session.clone(),
            session_key: session,
            cname: tgt.client.1.clone(),
            crealm: tgt.client.0.clone(),
            fast_avail: false,
            used_fast: false,
            pa_type: None,
        };
        let kdc = std::env::var("KRB5_KDC")
            .ok()
            .filter(|s| !s.is_empty())
            .map_or_else(
                || KdcAddr::new("127.0.0.1"),
                |h| {
                    if let Some((host, port)) = h.rsplit_once(':')
                        && let Ok(p) = port.parse()
                    {
                        KdcAddr {
                            host: host.to_owned(),
                            port: p,
                        }
                    } else {
                        KdcAddr::new(h)
                    }
                },
            );
        let fwd = tgs_forward(&kdc, &as_out).unwrap_or_else(|e| {
            eprintln!("tgs_forward: {e}");
            std::process::exit(1);
        });
        Some(DelegCred {
            ticket: fwd.ticket,
            session: fwd.session_key,
            crealm: as_out.crealm,
            cname: as_out.cname,
            flags: fwd.enc_part.flags,
            authtime: Some(fwd.enc_part.authtime),
            starttime: fwd.enc_part.starttime,
            endtime: Some(fwd.enc_part.endtime),
            renew_till: fwd.enc_part.renew_till,
        })
    } else {
        None
    };
    let cb = bind_data.as_ref().map(|s| ChannelBindings {
        application_data: s.as_bytes().to_vec(),
        ..ChannelBindings::default()
    });
    let addr = format!("{ip}:{port}");
    let mut stream = TcpStream::connect(&addr).unwrap_or_else(|e| {
        eprintln!("connect {addr}: {e}");
        std::process::exit(1);
    });
    if no_checksum {
        let ap = build_ap_req_with_cksum(
            ticket,
            &svc_key,
            &svc.client.0,
            &svc.client.1,
            ApOptions::mutual_required(),
            None,
            None,
        )
        .unwrap_or_else(|e| {
            eprintln!("build_ap_req: {e}");
            std::process::exit(1);
        });
        let inner = encode(&ap).unwrap_or_else(|e| {
            eprintln!("encode AP-REQ: {e}");
            std::process::exit(1);
        });
        let token = wrap_app(&inner);
        eprintln!("gss-init AP-REQ bytes={}", token.len());
        write_token(&mut stream, &token).unwrap_or_else(|e| {
            eprintln!("write AP-REQ: {e}");
            std::process::exit(1);
        });
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        if read_token(&mut stream).is_ok() {
            println!("gss-init ap-rep=yes");
            std::process::exit(1);
        }
        println!("gss-init ap-rep=none");
        return;
    }
    let (mut ctx, token) = GssContext::init_sec_context(
        ticket,
        &svc_key,
        &svc.client.0,
        &svc.client.1,
        true,
        cb.as_ref(),
        deleg_cred.as_ref(),
    )
    .unwrap_or_else(|e| {
        eprintln!("init_sec_context: {e}");
        std::process::exit(1);
    });
    eprintln!("gss-init AP-REQ bytes={}", token.len());
    write_token(&mut stream, &token).unwrap_or_else(|e| {
        eprintln!("write AP-REQ: {e}");
        std::process::exit(1);
    });
    let ap_rep = read_token(&mut stream).unwrap_or_else(|e| {
        eprintln!("read AP-REP: {e}");
        std::process::exit(1);
    });
    println!("gss-init ap-rep=yes");
    ctx.process_ap_rep(&ap_rep, &svc_key).unwrap_or_else(|e| {
        eprintln!("process_ap_rep: {e}");
        std::process::exit(1);
    });
    if accept_only {
        return;
    }
    let mut wrapped = wrap_iov_token(&mut ctx, b"hello-from-rust-gss").unwrap_or_else(|e| {
        eprintln!("wrap: {e}");
        std::process::exit(1);
    });
    if let Some(kind) = mutate.as_deref() {
        if wrapped.len() < 16 {
            eprintln!("mutate: token too short");
            std::process::exit(1);
        }
        match kind {
            "direction" => wrapped[2] ^= 0x01,
            "filler" => wrapped[3] = 0x00,
            "ec" => {
                let ec = u16::from_be_bytes([wrapped[4], wrapped[5]]).wrapping_add(1);
                wrapped[4..6].copy_from_slice(&ec.to_be_bytes());
            }
            other => {
                eprintln!("unknown mutate {other}");
                std::process::exit(2);
            }
        }
        eprintln!("gss-init mutate={kind}");
    }
    write_token(&mut stream, &wrapped).unwrap_or_else(|e| {
        eprintln!("write wrap: {e}");
        std::process::exit(1);
    });
    println!("gss-init wrap sent hello-from-rust-gss");
}

fn wrap_app(inner: &[u8]) -> Vec<u8> {
    let mut body = der_tlv(0x06, KRB5_OID);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(inner);
    der_tlv(0x60, &body)
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(u8::try_from(body.len()).unwrap_or(u8::MAX));
    } else if body.len() < 256 {
        out.push(0x81);
        out.push(u8::try_from(body.len()).unwrap_or(u8::MAX));
    } else {
        out.push(0x82);
        out.extend_from_slice(&(u16::try_from(body.len()).unwrap_or(u16::MAX)).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

fn wrap_iov_token(ctx: &mut GssContext, msg: &[u8]) -> Result<Vec<u8>, krb5_gss::Error> {
    let mut header = Vec::new();
    let mut data = msg.to_vec();
    let mut padding = Vec::new();
    let mut trailer = Vec::new();
    ctx.wrap_iov(
        true,
        &mut [
            IovBuf {
                kind: IovType::Header,
                data: &mut header,
            },
            IovBuf {
                kind: IovType::Data,
                data: &mut data,
            },
            IovBuf {
                kind: IovType::Padding,
                data: &mut padding,
            },
            IovBuf {
                kind: IovType::Trailer,
                data: &mut trailer,
            },
        ],
    )?;
    let mut tok = header;
    tok.extend_from_slice(&data);
    tok.extend_from_slice(&padding);
    tok.extend_from_slice(&trailer);
    Ok(tok)
}

fn read_token(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr)?;
    let n = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(usize::MAX);
    if n == 0 || n > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad token length {n}"),
        ));
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_token(s: &mut TcpStream, tok: &[u8]) -> std::io::Result<()> {
    let n = u32::try_from(tok.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "token too large"))?;
    s.write_all(&n.to_be_bytes())?;
    s.write_all(tok)?;
    s.flush()
}
