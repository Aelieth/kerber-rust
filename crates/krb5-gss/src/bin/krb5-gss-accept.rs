//! GSS acceptor for out-of-process MIT `gss-client` interop (RFC 4121).
//!
//! Speaks the MIT `gss-sample` TCP framing: 4-byte length prefix then token.
//! Usage: `krb5-gss-accept --keytab PATH [--listen HOST:PORT]`

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::TcpListener;

use krb5_gss::{GssContext, IovBuf, IovType};
use krb5_protocol::Keytab;

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "krb5_gss=info".into()),
        )
        .try_init();

    let mut keytab = None::<String>;
    let mut listen = "127.0.0.1:4444".to_owned();
    let mut assoc = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--keytab" => keytab = args.next(),
            "--listen" => {
                if let Some(v) = args.next() {
                    listen = v;
                }
            }
            "--assoc" => {
                if let Some(v) = args.next() {
                    assoc = v.into_bytes();
                }
            }
            _ => {}
        }
    }
    let Some(kt_path) = keytab else {
        eprintln!("usage: krb5-gss-accept --keytab PATH [--listen HOST:PORT]");
        std::process::exit(2);
    };
    let bytes = std::fs::read(&kt_path).unwrap_or_else(|e| {
        eprintln!("keytab: {e}");
        std::process::exit(1);
    });
    let kt = Keytab::parse(&bytes).unwrap_or_else(|e| {
        eprintln!("keytab parse: {e}");
        std::process::exit(1);
    });
    let Some(ent) = kt.entries.first() else {
        eprintln!("empty keytab");
        std::process::exit(1);
    };
    let service_keys: Vec<_> = kt.entries.iter().map(|e| e.key.clone()).collect();
    eprintln!(
        "gss-accept keytab entries={} principal={}",
        service_keys.len(),
        ent.name.components_joined()
    );

    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("bind {listen}: {e}");
        std::process::exit(1);
    });
    println!("gss-accept listening {listen}");
    let (mut stream, _) = listener.accept().unwrap_or_else(|e| {
        eprintln!("accept: {e}");
        std::process::exit(1);
    });
    let tok = read_token(&mut stream).unwrap_or_else(|e| {
        eprintln!("read AP-REQ: {e}");
        std::process::exit(1);
    });
    let realm = std::str::from_utf8(ent.realm.as_bytes()).unwrap_or("");
    let (mut ctx, ap_rep) = if krb5_gss::is_spnego(&tok) {
        let (ctx, resp) =
            krb5_gss::spnego_accept(&tok, &service_keys, None, Some(&ent.name), Some(realm))
                .unwrap_or_else(|e| {
                    eprintln!("spnego_accept: {e}");
                    std::process::exit(1);
                });
        println!("gss-accept spnego mic ok");
        (ctx, Some(resp))
    } else {
        let inner = krb5_gss::spnego_inner(&tok).map_or_else(|_| tok.clone(), Vec::from);
        GssContext::accept_sec_context(&inner, &service_keys, None, Some(&ent.name), Some(realm))
            .unwrap_or_else(|e| {
                eprintln!("accept_sec_context: {e}");
                std::process::exit(1);
            })
    };
    if let Some(c) = ctx.client.as_deref() {
        println!("gss-accept client={c}");
    }
    if let Some(d) = ctx.delegated() {
        println!("gss-accept delegated={d}");
    }
    {
        let q = ctx.inquire_context();
        println!(
            "gss-accept inquire flags={} lifetime={}",
            q.flags, q.lifetime
        );
    }
    let exported = ctx.export_sec_context().unwrap_or_else(|e| {
        eprintln!("export: {e}");
        std::process::exit(1);
    });
    ctx = GssContext::import_sec_context(&exported).unwrap_or_else(|e| {
        eprintln!("import: {e}");
        std::process::exit(1);
    });
    println!("gss-accept import ok");
    if let Some(rep) = ap_rep {
        write_token(&mut stream, &rep).unwrap_or_else(|e| {
            eprintln!("write AP-REP: {e}");
            std::process::exit(1);
        });
    }
    let mut nwrap = 0u32;
    loop {
        let wrap = match read_token(&mut stream) {
            Ok(w) => w,
            Err(_) if nwrap > 0 => break,
            Err(e) => {
                eprintln!("read wrap: {e}");
                std::process::exit(1);
            }
        };
        let n = wrap.len().min(16);
        eprintln!("wrap token len={} hdr={:02x?}", wrap.len(), &wrap[..n]);
        if wrap.first() == Some(&0xa1) {
            ctx.verify_spnego_mic(&wrap).unwrap_or_else(|e| {
                eprintln!("spnego peer mic: {e}");
                std::process::exit(1);
            });
            println!("gss-accept spnego peer mic ok");
            nwrap = nwrap.saturating_add(1);
            continue;
        }
        let plain = unwrap_iov_token(&mut ctx, &wrap, &assoc).unwrap_or_else(|e| {
            eprintln!("unwrap: {e}");
            std::process::exit(1);
        });
        println!("gss-accept unwrap ok bytes={}", plain.len());
        println!("gss-accept plaintext={}", String::from_utf8_lossy(&plain));
        nwrap = nwrap.saturating_add(1);
    }
}

fn unwrap_iov_token(
    ctx: &mut GssContext,
    wrap: &[u8],
    assoc: &[u8],
) -> Result<Vec<u8>, krb5_gss::Error> {
    if wrap.first() != Some(&0x05) {
        return ctx.unwrap(wrap);
    }
    let sealed = wrap.get(2).copied().unwrap_or(0) & 0x02 != 0;
    if !sealed {
        return ctx.unwrap(wrap);
    }
    let (header_len, _, trailer_len) = ctx.wrap_iov_length(true)?;
    if wrap.len() < header_len + trailer_len {
        return ctx.unwrap(wrap);
    }
    let mut header = wrap[..header_len].to_vec();
    let mut trailer = wrap[wrap.len() - trailer_len..].to_vec();
    let mut data = wrap[header_len..wrap.len() - trailer_len].to_vec();
    let mut padding = Vec::new();
    let mut sign = assoc.to_vec();
    let mut iov = vec![
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
    ];
    if !assoc.is_empty() {
        iov.insert(
            1,
            IovBuf {
                kind: IovType::SignOnly,
                data: &mut sign,
            },
        );
    }
    ctx.unwrap_iov(&mut iov)?;
    Ok(data)
}

fn read_token(s: &mut std::net::TcpStream) -> std::io::Result<Vec<u8>> {
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

fn write_token(s: &mut std::net::TcpStream, tok: &[u8]) -> std::io::Result<()> {
    let n = u32::try_from(tok.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "token too large"))?;
    s.write_all(&n.to_be_bytes())?;
    s.write_all(tok)?;
    s.flush()
}
