//! The krb5-kadmind daemon on MIT's one net-server loop: one thread for kpasswd and kadm5 however
//! many clients hold a connection, one cap of 45 over kpasswd's streams and the RPC connections
//! with MIT's eviction lines, SIGHUP reopening the log while it serves on, and SIGTERM ending
//! the loop with MIT's lines.
//! MIT `main` (`kadmin/server/ovsec_kadmd.c:542-555`): `verto_run` serves until a signal ends the loop, then "finished, exiting" and the loop freed.

#![cfg(target_os = "linux")]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use krb5_testkit::scratch_dir;

/// A port free for UDP and TCP on 127.0.0.1.
fn free_port() -> u16 {
    loop {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = t.local_addr().unwrap().port();
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// The documented realm saved to a database that `krb5-kadmind -nofork` serves, kadm5 on
/// 127.0.0.1:`rpc` and kpasswd on 127.0.0.1:`kpasswd`, logging to `log` with debug lines.
struct Daemon {
    dir: PathBuf,
    child: Child,
    log: PathBuf,
    rpc: u16,
    kpasswd: u16,
}

impl Daemon {
    fn command(dir: &Path) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_krb5-kadmind"));
        cmd.current_dir(dir)
            .env("KRB5_CONFIG", dir.join("krb5.conf"))
            .env("KRB5_KDC_PROFILE", dir.join("kdc.conf"))
            .stdin(Stdio::null());
        for v in [
            "KRB5_KDC_DB",
            "KRB5_KDC_STASH",
            "KRB5_KDC_BIND",
            "KRB5_KPASSWD_BIND",
            "KRB5_MASTER_ETYPE",
            "KRB5_MASTER_PASSWORD",
            "KRB5_ACL_FILE",
            "KRB5_KDC_CONF",
            "KRB5_KDC_DB_LIBRARY",
        ] {
            cmd.env_remove(v);
        }
        cmd
    }

    fn start(name: &str) -> Self {
        let dir = scratch_dir(name);
        let (rpc, kpasswd) = (free_port(), free_port());
        let log = dir.join("kadmind.log");
        let (store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
        krb5_kdc::save_store(&store, &dir.join("principal"), &dir.join("stash")).unwrap();
        std::fs::write(dir.join("kadm5.acl"), "admin@KERBER.TEST *\n").unwrap();
        std::fs::write(
            dir.join("krb5.conf"),
            "[libdefaults]\n    default_realm = KERBER.TEST\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("kdc.conf"),
            format!(
                "[realms]\n    KERBER.TEST = {{\n        database_name = {db}\n        key_stash_file = {stash}\n        \
                 acl_file = {acl}\n        kadmind_listen = 127.0.0.1:{rpc}\n        kpasswd_listen = 127.0.0.1:{kpasswd}\n    }}\n\
                 [logging]\n    admin_server = FILE:{log}\n    debug = true\n",
                db = dir.join("principal").display(),
                stash = dir.join("stash").display(),
                acl = dir.join("kadm5.acl").display(),
                log = log.display(),
            ),
        )
        .unwrap();
        let mut child = Self::command(&dir)
            .arg("-nofork")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // MIT `main` (`kadmin/server/ovsec_kadmd.c:538-540`): "<prog>: starting..." on standard error once it serves.
        let mut err = BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        while !line.ends_with("starting...\n") {
            line.clear();
            assert_ne!(err.read_line(&mut line).unwrap(), 0, "kadmind exited");
        }
        Self {
            dir,
            child,
            log,
            rpc,
            kpasswd,
        }
    }

    fn text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn threads(&self) -> String {
        std::fs::read_to_string(format!("/proc/{}/status", self.child.id()))
            .unwrap()
            .lines()
            .find(|l| l.starts_with("Threads:"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned()
    }

    fn signal(&self, name: &str) {
        let ok = Command::new("kill")
            .args([&format!("-{name}"), &self.child.id().to_string()])
            .status()
            .unwrap()
            .success();
        assert!(ok, "kill -{name}");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An AUTH_NONE kadm5 call on `c`: answered AUTH_TOOWEAK.
fn too_weak(c: &mut TcpStream, xid: u32) -> bool {
    let call: Vec<u8> = [xid, 0, 2, 2112, 2, 99, 0, 0, 0, 0]
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect();
    let mut rec = (u32::try_from(call.len()).unwrap() | 0x8000_0000)
        .to_be_bytes()
        .to_vec();
    rec.extend_from_slice(&call);
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(&rec).unwrap();
    let mut reply = [0u8; 24];
    c.read_exact(&mut reply).is_ok()
        && reply[4..] == [xid, 1, 1, 1, 5].map(u32::to_be_bytes).concat()
}

/// Whether the server closed `c`.
fn evicted(c: &TcpStream) -> bool {
    c.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    matches!((&*c).read(&mut [0u8; 1]), Ok(0))
}

/// Fifty clients, kadm5 and kpasswd by turns, hold a connection, and a fifty-first kadm5 client
/// calls: one thread serves them all, the cap of 45 covers both kinds, and each eviction's line
/// names the kind of the client it closed. The caller is answered again after SIGHUP, which
/// reopens the log; SIGTERM ends the loop with MIT's lines: the request to exit, "finished,
/// exiting", then "closing down fd" for each of the 45 connections left and for each socket, the
/// sockets last and newest first.
#[test]
fn kadmind_serves_every_client_from_one_thread() {
    let mut d = Daemon::start("kadmind-loop-daemon");
    let conns: Vec<(bool, TcpStream)> = (0..50)
        .map(|i| {
            let rpc = i % 2 == 0;
            let port = if rpc { d.rpc } else { d.kpasswd };
            (rpc, TcpStream::connect(("127.0.0.1", port)).unwrap())
        })
        .collect();
    // Answered once the loop has taken every connection queued before this one.
    let mut caller = TcpStream::connect(("127.0.0.1", d.rpc)).unwrap();
    assert!(too_weak(&mut caller, 1), "the caller is answered");
    let gone: Vec<bool> = conns
        .iter()
        .filter(|(_, c)| evicted(c))
        .map(|(rpc, _)| *rpc)
        .collect();
    let text = d.text();
    assert_eq!(gone.len(), 6, "six past the cap of 45: {text}");
    assert_eq!(text.matches("(info): too many connections\n").count(), 6);
    let lines = |kind: &str| {
        text.matches(&format!("(info): dropping {kind} fd "))
            .count()
    };
    let rpc_gone = gone.iter().filter(|rpc| **rpc).count();
    assert_eq!(
        (lines("RPC"), lines("TCP")),
        (rpc_gone, 6 - rpc_gone),
        "{text}"
    );
    assert_eq!(d.threads(), "1", "one thread");
    d.signal("HUP");
    // The second call is served in a later turn of the loop than the signal's.
    assert!(
        too_weak(&mut caller, 2) && too_weak(&mut caller, 3),
        "answering after SIGHUP"
    );
    assert!(d.text().contains("(debug): Got signal to reset\n"));
    assert_eq!(d.threads(), "1");
    d.signal("TERM");
    let status = d.child.wait().unwrap();
    assert!(status.success(), "{status:?}");
    let text = d.text();
    let exit = text
        .find("(debug): Got signal to request exit\n")
        .expect(&text);
    let finished = text.find("(info): finished, exiting\n").expect(&text);
    assert!(exit < finished, "{text}");
    let closing: Vec<i32> = text[finished..]
        .lines()
        .filter_map(|l| l.split("(info): closing down fd ").nth(1))
        .map(|fd| fd.parse().unwrap())
        .collect();
    assert_eq!(closing.len(), 45 + 3, "each connection and socket: {text}");
    let sockets = &closing[45..];
    assert!(sockets.windows(2).all(|w| w[0] > w[1]), "{sockets:?}");
    assert!(
        closing[..45].iter().all(|fd| fd > &sockets[0]),
        "{closing:?}"
    );
    drop(conns);
}
