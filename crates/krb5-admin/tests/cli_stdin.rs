//! Process-level stdin exit codes for `ktutil` / `kadmin.local`.

use krb5_testkit::scratch_dir;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn pipe_stdin(bin: &str, input: &[u8]) -> std::process::Output {
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input)
        .expect("write");
    child.wait_with_output().expect("wait")
}

/// MIT `main` (`ktutil.c:60-62`): the command loop exits 0 whatever it ran (settled live).
#[test]
fn ktutil_nope_then_q_exits_0() {
    let bin = env!("CARGO_BIN_EXE_krb5-ktutil");
    let out = pipe_stdin(bin, b"nope\nq\n");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "ktutil: Unknown request \"nope\".  Type \"?\" for a request list.\n"
    );
    let out = pipe_stdin(bin, b"q\n");
    assert_eq!(out.status.code(), Some(0));
    let out = pipe_stdin(bin, b"q\nnope\n");
    assert_eq!(out.status.code(), Some(0));
    let out = pipe_stdin(bin, b"\xff\nq\n");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = pipe_stdin(bin, b"\xff\nnope\nq\n");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Live MIT 1.22.2: a line that is no request, bytes as read, then the next line runs.
    assert_eq!(
        out.stderr,
        b"ktutil: Unknown request \"\xff\".  Type \"?\" for a request list.\n\
          ktutil: Unknown request \"nope\".  Type \"?\" for a request list.\n"
    );
}

fn dir_stdin(bin: &str, envs: &[(&str, std::path::PathBuf)]) -> std::process::Output {
    let scratch = scratch_dir("ktutil-dir");
    let file = File::open(&scratch).expect("open directory");
    let mut cmd = Command::new("timeout");
    cmd.args(["--kill-after=1s", "2", bin])
        .stdin(Stdio::from(file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("timeout spawn");
    let _ = std::fs::remove_dir_all(&scratch);
    out
}

#[test]
fn ktutil_directory_stdin_terminates() {
    let bin = env!("CARGO_BIN_EXE_krb5-ktutil");
    let out = dir_stdin(bin, &[]);
    assert_ne!(
        out.status.code(),
        Some(124),
        "directory stdin spun: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Live MIT 1.22.2: ktutil with a directory as stdin ends its loop and exits 0.
    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stderr.len() < 64 * 1024,
        "stderr {} bytes",
        out.stderr.len()
    );
}

/// A scratch realm for `kadmin.local`: the documented test realm saved where the env names it,
/// a krb5.conf naming its realm, no KDC profile and no ccache.
struct Realm {
    dir: std::path::PathBuf,
}

impl Realm {
    fn new(tag: &str) -> Self {
        let dir = scratch_dir(tag);
        let _ = std::fs::create_dir_all(&dir);
        let (store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
        krb5_kdc::save_store(&store, &dir.join("principal"), &dir.join("stash")).unwrap();
        std::fs::write(
            dir.join("krb5.conf"),
            "[libdefaults]\n default_realm = KERBER.TEST\n",
        )
        .unwrap();
        Self { dir }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_krb5-kadmin-local"));
        cmd.env("KRB5_KDC_DB", self.dir.join("principal"))
            .env("KRB5_KDC_STASH", self.dir.join("stash"))
            .env("KRB5_CONFIG", self.dir.join("krb5.conf"))
            .env("KRB5_KDC_PROFILE", self.dir.join("no-kdc.conf"))
            .env(
                "KRB5CCNAME",
                format!("FILE:{}", self.dir.join("no-cc").display()),
            )
            .env("USER", "tester");
        cmd
    }

    fn run(&self, args: &[&str], input: &[u8]) -> std::process::Output {
        let mut child = self
            .cmd()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input)
            .expect("write");
        child.wait_with_output().expect("wait")
    }
}

impl Drop for Realm {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// MIT `main` (`ss_wrapper.c`), settled live: a failed `-q` query exits 0, an unknown `-q` or
/// command-line command 1, a command-line command (script mode) that reports an error 1, and the
/// prompt loop 0 whatever it read.
#[test]
fn kadmin_local_exit_status_is_mit_s() {
    let realm = Realm::new("kadmin-exit");
    let out = realm.run(&["-q", "getprinc nosuch"], b"");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        text(&out.stdout),
        "Authenticating as principal tester/admin@KERBER.TEST with password.\n"
    );
    assert_eq!(
        text(&out.stderr),
        "get_principal: Principal does not exist while retrieving \"nosuch@KERBER.TEST\".\n"
    );
    let out = realm.run(&["-q", "nope"], b"");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stderr), "kadmin.local: Command not found nope\n");
    let out = realm.run(&["getprinc", "nosuch"], b"");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stdout), "", "script mode prints no banner");
    let out = realm.run(&["addprinc", "-randkey", "sm1"], b"");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        (text(&out.stdout), text(&out.stderr)),
        (String::new(), String::new())
    );
    let out = realm.run(&["nope"], b"");
    assert_eq!(out.status.code(), Some(1));
    let out = realm.run(&["-Z"], b"");
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with("kadmin.local: invalid option -- 'Z'\nUsage: "));
    let out = realm.run(&[], b"nope\nq\n");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        text(&out.stdout),
        "Authenticating as principal tester/admin@KERBER.TEST with password.\nkadmin.local:  \
         kadmin.local:  "
    );
    assert_eq!(
        text(&out.stderr),
        "kadmin.local: Unknown request \"nope\".  Type \"?\" for a request list.\n"
    );
    let out = realm.run(&[], b"q\nnope\n");
    assert_eq!(
        (out.status.code(), text(&out.stderr)),
        (Some(0), String::new())
    );
    let out = realm.run(&[], b"\xff\nlistprincs us*\n");
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("user@KERBER.TEST\n"));
}

/// The KLLDAP manager's lines: `addprinc -randkey` then `ktadd -k`, stdout as MIT prints it.
#[test]
fn kadmin_local_klldap_bootstrap_lines() {
    let realm = Realm::new("kadmin-klldap");
    let out = realm.run(&["-q", "addprinc -randkey admin/admin@KERBER.TEST"], b"");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        text(&out.stdout),
        "Authenticating as principal tester/admin@KERBER.TEST with password.\nPrincipal \
         \"admin/admin@KERBER.TEST\" created.\n"
    );
    let kt = realm.dir.join("kadm5.keytab");
    let q = format!("ktadd -k {} admin/admin@KERBER.TEST", kt.display());
    let out = realm.run(&["-q", &q], b"");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let lines: Vec<String> = text(&out.stdout).lines().map(str::to_owned).collect();
    assert!(lines.len() > 1, "{lines:?}");
    assert!(
        lines[1].starts_with("Entry for principal admin/admin@KERBER.TEST with kvno 2, ")
            && lines[1].ends_with(&format!("added to keytab WRFILE:{}.", kt.display())),
        "{lines:?}"
    );
    let out = realm.run(&["-q", "getprinc admin/admin@KERBER.TEST"], b"");
    let first_vno = text(&out.stdout)
        .lines()
        .find(|l| l.contains("vno"))
        .map(str::to_owned);
    assert!(
        first_vno
            .as_deref()
            .is_some_and(|l| l.starts_with("Key: vno 2, ")),
        "{first_vno:?}"
    );
}

/// `-p` is printed as given and stamps the change with its realm added, as MIT's `kadm5_init`
/// parses the client name.
#[test]
fn kadmin_local_explicit_principal_takes_the_realm() {
    let realm = Realm::new("kadmin-explicit-p");
    let out = realm.run(&["-p", "admin/admin", "-q", "addprinc -randkey pq1"], b"");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).starts_with("Authenticating as principal admin/admin with password.\n"),
        "{}",
        text(&out.stdout)
    );
    let modified = |realm: &Realm| {
        let out = realm.run(&["-q", "getprinc pq1"], b"");
        text(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("Last modified: "))
            .and_then(|l| l.rsplit_once(" ("))
            .map(|(_, by)| by.trim_end_matches(')').to_owned())
    };
    assert_eq!(modified(&realm).as_deref(), Some("admin/admin@KERBER.TEST"));
    let out = realm.run(
        &[
            "-p",
            "joe/admin@OTHER.TEST",
            "-q",
            "modprinc -maxlife 1h pq1",
        ],
        b"",
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(modified(&realm).as_deref(), Some("joe/admin@OTHER.TEST"));
}

/// Reads `from` until `marker` has been seen in all it read (or the stream ends).
fn read_through(from: &mut impl Read, seen: &mut Vec<u8>, marker: &[u8]) {
    let mut buf = [0u8; 256];
    let mut start = seen.len();
    while !seen[start.saturating_sub(marker.len())..]
        .windows(marker.len())
        .any(|w| w == marker)
    {
        start = seen.len();
        let Ok(n) = from.read(&mut buf) else {
            return;
        };
        if n == 0 {
            return;
        }
        seen.extend_from_slice(&buf[..n]);
    }
}

fn sigint(child: &std::process::Child) {
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGINT).unwrap();
}

/// MIT `ss_listen`: Ctrl-C at the prompt prints a newline and prompts again; the session goes
/// on and ends with 0.
#[test]
fn kadmin_local_sigint_at_the_prompt_prompts_again() {
    let realm = Realm::new("kadmin-sigint");
    let mut child = realm
        .cmd()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut seen = Vec::new();
    read_through(&mut stdout, &mut seen, b"kadmin.local:  ");
    sigint(&child);
    read_through(&mut stdout, &mut seen, b"\nkadmin.local:  ");
    stdin.write_all(b"listprincs us*\nq\n").unwrap();
    drop(stdin);
    stdout.read_to_end(&mut seen).unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));
    assert_eq!(
        text(&seen),
        "Authenticating as principal tester/admin@KERBER.TEST with password.\nkadmin.local:  \n\
         kadmin.local:  user@KERBER.TEST\nkadmin.local:  "
    );
}

/// MIT `krb5_prompter_posix`: Ctrl-C at a password prompt is `Password read interrupted`, and
/// `-q` still exits 0.
#[test]
fn kadmin_local_sigint_at_a_password_prompt_is_password_read_interrupted() {
    let realm = Realm::new("kadmin-sigint-pw");
    let mut child = realm
        .cmd()
        .args(["-q", "addprinc pz1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut seen = Vec::new();
    read_through(
        &mut stdout,
        &mut seen,
        b"Enter password for principal \"pz1@KERBER.TEST\": ",
    );
    sigint(&child);
    stdout.read_to_end(&mut seen).unwrap();
    drop(stdin);
    let mut err = Vec::new();
    child.stderr.take().unwrap().read_to_end(&mut err).unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(0));
    assert!(
        text(&seen).ends_with("\"pz1@KERBER.TEST\": \n"),
        "{}",
        text(&seen)
    );
    assert!(
        text(&err).ends_with(
            "add_principal: Password read interrupted while reading password for \
             \"pz1@KERBER.TEST\".\n"
        ),
        "{}",
        text(&err)
    );
}

/// MIT's prompt loop reads a directory stdin as the end of input (`fgets` fails): no spin, exit 0.
#[test]
fn kadmin_local_directory_stdin_terminates() {
    let realm = Realm::new("kadmin-dirin");
    let bin = env!("CARGO_BIN_EXE_krb5-kadmin-local");
    let out = dir_stdin(
        bin,
        &[
            ("KRB5_KDC_DB", realm.dir.join("principal")),
            ("KRB5_KDC_STASH", realm.dir.join("stash")),
            ("KRB5_CONFIG", realm.dir.join("krb5.conf")),
            ("KRB5_KDC_PROFILE", realm.dir.join("no-kdc.conf")),
        ],
    );
    assert_ne!(
        out.status.code(),
        Some(124),
        "directory stdin spun: stderr={}",
        text(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(0), "stderr={}", text(&out.stderr));
    assert!(
        out.stderr.len() < 64 * 1024,
        "stderr {} bytes",
        out.stderr.len()
    );
}
