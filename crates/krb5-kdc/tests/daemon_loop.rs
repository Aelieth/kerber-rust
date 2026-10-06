//! The krb5-kdc daemon on MIT's one net-server loop: one thread however many clients hold a
//! connection, SIGHUP reopens the log and keeps serving, and SIGTERM ends the loop with MIT's
//! lines.
//! MIT `main` (`kdc/main.c:1030-1032`): `verto_run` serves until a signal ends the loop, then "shutting down".

#![cfg(target_os = "linux")]

use std::io::{BufRead as _, BufReader, Read as _};
use std::net::{TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use krb5_asn1::{decode, encode};
use krb5_testkit::scratch_dir;
use krb5_types::{KrbError, PrincipalName, err};

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

/// A KL.TEST realm made by `krb5-kdb create`, served by `krb5-kdc -n` on 127.0.0.1:`port`,
/// logging to `log` with debug lines.
struct Daemon {
    dir: PathBuf,
    child: Child,
    log: PathBuf,
    port: u16,
}

impl Daemon {
    fn command(dir: &Path, program: &str) -> Command {
        let mut cmd = Command::new(program);
        cmd.current_dir(dir)
            .env("KRB5_CONFIG", dir.join("krb5.conf"))
            .env("KRB5_KDC_PROFILE", dir.join("kdc.conf"))
            .stdin(Stdio::null());
        for v in [
            "KRB5_KDC_DB",
            "KRB5_KDC_STASH",
            "KRB5_KDC_BIND",
            "KRB5_MASTER_ETYPE",
            "KRB5_MASTER_PASSWORD",
            "KRB5_TEST_USER_PASSWORD",
            "KRB5_TEST_ADMIN_PASSWORD",
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
        let port = free_port();
        let log = dir.join("kdc.log");
        std::fs::write(
            dir.join("krb5.conf"),
            "[libdefaults]\n    default_realm = KL.TEST\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("kdc.conf"),
            format!(
                "[realms]\n    KL.TEST = {{\n        database_name = {db}\n        key_stash_file = {stash}\n        \
                 master_key_type = aes256-cts-hmac-sha1-96\n        supported_enctypes = aes256-cts-hmac-sha1-96:normal\n        \
                 kdc_listen = 127.0.0.1:{port}\n        kdc_tcp_listen = 127.0.0.1:{port}\n    }}\n\
                 [logging]\n    kdc = FILE:{log}\n    debug = true\n",
                db = dir.join("principal").display(),
                stash = dir.join("stash").display(),
                log = log.display(),
            ),
        )
        .unwrap();
        let out = Self::command(&dir, env!("CARGO_BIN_EXE_krb5-kdb"))
            .args(["-P", "kl-master", "create", "-s"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut child = Self::command(&dir, env!("CARGO_BIN_EXE_krb5-kdc"))
            .arg("-n")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // MIT `main` (`kdc/main.c:1027-1028`): "<prog>: starting..." on standard error once it serves.
        let mut err = BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        while !line.ends_with("starting...\n") {
            line.clear();
            assert_ne!(err.read_line(&mut line).unwrap(), 0, "the KDC exited");
        }
        Self {
            dir,
            child,
            log,
            port,
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

    /// One AS-REQ over UDP; the KDC answers CLIENT_NOT_FOUND.
    fn answers(&self, nonce: u32) -> bool {
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosuch"]);
        let req = encode(&krb5_protocol::as_req(cname, "KL.TEST", nonce, None).unwrap()).unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        sock.send_to(&req, ("127.0.0.1", self.port)).unwrap();
        let mut buf = [0u8; 4096];
        let Ok(n) = sock.recv(&mut buf) else {
            return false;
        };
        decode::<KrbError>(&buf[..n]).is_ok_and(|e| e.error_code == err::C_PRINCIPAL_UNKNOWN)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Fifty clients holding a TCP connection are served from one thread, past the cap of 45 by
/// evicting connections that started in the same second as the newcomers; SIGHUP reopens the
/// log and the KDC answers on; SIGTERM ends the loop with MIT's lines and a zero status.
#[test]
fn the_daemon_serves_every_client_from_one_thread() {
    let mut d = Daemon::start("kdc-loop-daemon");
    let conns: Vec<TcpStream> = (0..50)
        .map(|_| TcpStream::connect(("127.0.0.1", d.port)).unwrap())
        .collect();
    assert!(d.answers(1), "answered with 50 connections held");
    let evicted = conns
        .iter()
        .filter(|c| {
            c.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut b = [0u8; 1];
            matches!((&**c).read(&mut b), Ok(0))
        })
        .count();
    assert_eq!(evicted, 5, "five past the cap of 45");
    assert_eq!(
        d.text().matches("(info): too many connections\n").count(),
        5
    );
    assert_eq!(d.threads(), "1", "one thread");
    d.signal("HUP");
    // The second request is served in a later turn of the loop than the signal's.
    assert!(d.answers(2) && d.answers(3), "still answering after SIGHUP");
    assert!(d.text().contains("(debug): Got signal to reset\n"));
    assert_eq!(d.threads(), "1");
    d.signal("TERM");
    let status = d.child.wait().unwrap();
    assert!(status.success(), "{status:?}");
    let text = d.text();
    let exit = text
        .find("(debug): Got signal to request exit\n")
        .expect(&text);
    let down = text.find("(info): shutting down\n").expect(&text);
    assert!(exit < down, "{text}");
    drop(conns);
}
