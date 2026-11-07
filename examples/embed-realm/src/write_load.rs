//! `--write-load N,MS`: N threads each changing `writeload/<i>`'s password through
//! `change_password_shared`, one write every MS ms, so a cell can time `kinit` under writes.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use krb5_kdc::{AdminEnt, Error, SharedDump};

pub struct WriteLoad {
    writers: usize,
    period: Duration,
}

pub fn parse(text: &str) -> Option<WriteLoad> {
    let (n, ms) = text.split_once(',')?;
    let writers = n.parse().ok().filter(|n| (1..=64).contains(n))?;
    let period = Duration::from_millis(ms.parse().ok()?);
    Some(WriteLoad { writers, period })
}

pub struct Running {
    started: Instant,
    writers: Vec<JoinHandle<(u64, u64)>>,
}

pub fn start(
    store: &SharedDump,
    realm: &str,
    load: &WriteLoad,
    stop: &Arc<AtomicBool>,
) -> Result<Running, String> {
    let actor = format!("admin/admin@{realm}");
    let mut writers = Vec::with_capacity(load.writers);
    for i in 0..load.writers {
        let unparsed = format!("writeload/{i}");
        let (name, _) = krb5_types::principal_from_unparsed(&unparsed, realm)
            .map_err(|e| format!("{e} while parsing {unparsed}"))?;
        let ent = AdminEnt::default();
        match krb5_kdc::create_password_shared(store, &name, realm, b"wl-0", &[], &ent, &actor) {
            Ok(()) | Err(Error::AlreadyExists) => {}
            Err(e) => return Err(format!("{e} while creating {unparsed}")),
        }
        let (store, realm, actor) = (Arc::clone(store), realm.to_owned(), actor.clone());
        let (stop, period) = (Arc::clone(stop), load.period);
        writers.push(thread::spawn(move || {
            let (mut ok, mut failed) = (0u64, 0u64);
            let mut next = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                let password = format!("wl-{i}-{}", ok + failed + 1);
                let changed = krb5_kdc::change_password_shared(
                    &store,
                    &name,
                    &realm,
                    password.as_bytes(),
                    0,
                    &actor,
                    &[],
                    |_| Ok(()),
                );
                match changed {
                    Ok(()) => ok += 1,
                    Err(e) => {
                        failed += 1;
                        if failed == 1 {
                            eprintln!("write-load: {unparsed}: {e}");
                        }
                    }
                }
                next += period;
                let now = Instant::now();
                if next > now {
                    thread::sleep(next - now);
                } else {
                    next = now;
                }
            }
            (ok, failed)
        }));
    }
    Ok(Running {
        started: Instant::now(),
        writers,
    })
}

impl Running {
    /// One line for the cell: writes and elapsed milliseconds, from which it takes the rate.
    pub fn finish(self, progname: &str) {
        let n = self.writers.len();
        let (mut ok, mut failed) = (0u64, 0u64);
        for writer in self.writers {
            let (o, f) = writer.join().unwrap_or((0, 1));
            ok += o;
            failed += f;
        }
        let ms = self.started.elapsed().as_millis();
        eprintln!("{progname}: write-load writers={n} writes={ok} failed={failed} ms={ms}");
    }
}
