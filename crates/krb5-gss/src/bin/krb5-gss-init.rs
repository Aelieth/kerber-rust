//! GSS initiator for out-of-process MIT `gss-server` interop (RFC 4121).
//!
//! Speaks the MIT `gss-sample` TCP framing: 4-byte length prefix then token.
//! Usage: `krb5-gss-init --ccache PATH --host HOST --ip IP --port PORT [--deleg]`

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::TcpStream;

use krb5_asn1::decode;
use krb5_gss::{DelegCred, GssContext, IovBuf, IovType};
use krb5_protocol::FileCcache;
use krb5_types::Ticket;

fn main() {
    let mut ccache = None::<String>;
    let mut host = None::<String>;
    let mut ip = "127.0.0.1".to_owned();
    let mut port = 4444u16;
    let mut deleg = false;
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
            _ => {}
        }
    }
    let (Some(cc_path), Some(host_name)) = (ccache, host) else {
        eprintln!(
            "usage: krb5-gss-init --ccache PATH --host HOST [--ip IP] [--port PORT] [--deleg]"
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
        let tkt: Ticket = decode(&tgt.ticket).unwrap_or_else(|e| {
            eprintln!("tgt: {e}");
            std::process::exit(1);
        });
        Some(DelegCred {
            ticket: tkt,
            session: tgt.session_key().unwrap_or_else(|e| {
                eprintln!("tgt session key: {e}");
                std::process::exit(1);
            }),
            crealm: tgt.client.0.clone(),
            cname: tgt.client.1.clone(),
        })
    } else {
        None
    };
    let (mut ctx, token) = GssContext::init_sec_context(
        ticket,
        &svc_key,
        &svc.client.0,
        &svc.client.1,
        true,
        None,
        deleg_cred.as_ref(),
    )
    .unwrap_or_else(|e| {
        eprintln!("init_sec_context: {e}");
        std::process::exit(1);
    });
    let addr = format!("{ip}:{port}");
    let mut stream = TcpStream::connect(&addr).unwrap_or_else(|e| {
        eprintln!("connect {addr}: {e}");
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
    ctx.process_ap_rep(&ap_rep, &svc_key).unwrap_or_else(|e| {
        eprintln!("process_ap_rep: {e}");
        std::process::exit(1);
    });
    let wrapped = wrap_iov_token(&mut ctx, b"hello-from-rust-gss").unwrap_or_else(|e| {
        eprintln!("wrap: {e}");
        std::process::exit(1);
    });
    write_token(&mut stream, &wrapped).unwrap_or_else(|e| {
        eprintln!("write wrap: {e}");
        std::process::exit(1);
    });
    println!("gss-init wrap sent hello-from-rust-gss");
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
