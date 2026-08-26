//! Concurrent AS+TGS load driver against a live KDC.
//!
//! Usage: loadgen \<kdc-host\> \<user@REALM\> [service]
//!
//! Password is `KRB5_PASSWORD`. Concurrency is `KERBER_LOAD_WORKERS` (default 8)
//! times `KERBER_LOAD_ITERS` (default 8), or loop until `KERBER_LOAD_SECONDS`.

use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use krb5_client::kinit;
use krb5_protocol::KdcAddr;

fn parse_u32(name: &str, default: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let mut args = env::args().skip(1);
    let host = args.next().unwrap_or_else(|| {
        eprintln!("usage: loadgen <kdc-host> <user@REALM> [service]");
        std::process::exit(2);
    });
    let principal = args.next().unwrap_or_else(|| {
        eprintln!("missing user@REALM");
        std::process::exit(2);
    });
    let service = args.next();
    let password = env::var("KRB5_PASSWORD").unwrap_or_else(|_| {
        eprintln!("KRB5_PASSWORD is required");
        std::process::exit(2);
    });
    let workers = parse_u32("KERBER_LOAD_WORKERS", 8).max(1);
    let iters = parse_u32("KERBER_LOAD_ITERS", 8).max(1);
    let seconds = env::var("KERBER_LOAD_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());

    let addr = if let Some((h, p)) = host.rsplit_once(':') {
        if let Ok(port) = p.parse() {
            KdcAddr {
                host: h.to_owned(),
                port,
            }
        } else {
            KdcAddr::new(host)
        }
    } else {
        KdcAddr::new(host)
    };

    let ok = AtomicU64::new(0);
    let err = AtomicU64::new(0);
    let start = Instant::now();
    let deadline = seconds.map(|s| start + Duration::from_secs(s));

    thread::scope(|scope| {
        for w in 0..workers {
            let addr = addr.clone();
            let principal = principal.clone();
            let password = password.clone();
            let service = service.clone();
            let ok = &ok;
            let err = &err;
            scope.spawn(move || {
                let mut i = 0u32;
                loop {
                    if let Some(d) = deadline {
                        if Instant::now() >= d {
                            break;
                        }
                    } else if i >= iters {
                        break;
                    }
                    i = i.saturating_add(1);
                    let cc = std::env::temp_dir().join(format!(
                        "kerber-load-{}-{}-{}.ccache",
                        std::process::id(),
                        w,
                        i
                    ));
                    let mut pw = password.clone().into_bytes();
                    match kinit(&addr, &principal, &mut pw, &cc, service.as_deref()) {
                        Ok(_) => {
                            ok.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            err.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    let _ = std::fs::remove_file(&cc);
                }
            });
        }
    });

    let elapsed = start.elapsed();
    let ok_n = ok.load(Ordering::Relaxed);
    let err_n = err.load(Ordering::Relaxed);
    let elapsed_s = elapsed.as_secs_f64();
    #[allow(clippy::cast_precision_loss)]
    let throughput = if elapsed_s > 0.0 {
        ok_n as f64 / elapsed_s
    } else {
        0.0
    };
    println!("ok={ok_n} err={err_n} elapsed_s={elapsed_s:.3} throughput={throughput:.3}");
    println!(
        "{{\"event\":\"loadgen\",\"ok\":{ok_n},\"err\":{err_n},\"elapsed_s\":{elapsed_s:.3},\"throughput\":{throughput:.3}}}"
    );
    if err_n > 0 {
        std::process::exit(1);
    }
}
