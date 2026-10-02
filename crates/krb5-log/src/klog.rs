//! MIT's daemon log (`lib/kadm5/logger.c`): the text lines `krb5kdc` and `kadmind` write to
//! the `[logging]` destinations of their profile (files, standard error, the console, a device,
//! syslog), in MIT's shape `Mmm dd hh:mm:ss host prog[pid](Severity): message`.
//!
//! [`init`] opens the destinations as MIT `krb5_klog_init` does, [`syslog`] writes one line to
//! each, [`reopen`] reopens the files after a SIGHUP (logrotate's `systemctl reload`), and
//! [`close`] closes them. Before [`init`], and after [`close`], nothing is written, so a library
//! caller or a test that never sets the log up writes nothing.
//!
//! # Examples
//!
//! ```
//! use krb5_log::klog::{Severity, format_line};
//! let line = format_line("Oct 01 21:59:14", "kdc.example.com", "krb5kdc", 2012, Severity::Info, "commencing operation");
//! assert_eq!(line, "Oct 01 21:59:14 kdc.example.com krb5kdc[2012](info): commencing operation");
//! ```

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// A syslog severity: the level of one log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// `LOG_EMERG`.
    Emerg,
    /// `LOG_ALERT`.
    Alert,
    /// `LOG_CRIT`.
    Crit,
    /// `LOG_ERR`.
    Err,
    /// `LOG_WARNING`.
    Warning,
    /// `LOG_NOTICE`.
    Notice,
    /// `LOG_INFO`.
    Info,
    /// `LOG_DEBUG`.
    Debug,
}

impl Severity {
    /// The word in a line's parentheses.
    /// MIT `severity2string` (`lib/kadm5/logger.c:584-618`): `EMERGENCY` … `Error`, `Warning`,
    /// `Notice`, `info`, `debug`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Emerg => "EMERGENCY",
            Self::Alert => "ALERT",
            Self::Crit => "CRITICAL",
            Self::Err => "Error",
            Self::Warning => "Warning",
            Self::Notice => "Notice",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Emerg => 0,
            Self::Alert => 1,
            Self::Crit => 2,
            Self::Err => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }
}

/// `LOG_AUTH`, the facility of a `SYSLOG` destination that names none.
const LOG_AUTH: u8 = 4 << 3;

/// MIT `krb5_klog_init` (`lib/kadm5/logger.c:349-422`): the facility names, any case.
fn facility(name: &str) -> Option<u8> {
    const NAMES: [(&str, u8); 19] = [
        ("AUTH", 4),
        ("AUTHPRIV", 10),
        ("KERN", 0),
        ("USER", 1),
        ("MAIL", 2),
        ("DAEMON", 3),
        ("FTP", 11),
        ("LPR", 6),
        ("NEWS", 7),
        ("UUCP", 8),
        ("CRON", 9),
        ("LOCAL0", 16),
        ("LOCAL1", 17),
        ("LOCAL2", 18),
        ("LOCAL3", 19),
        ("LOCAL4", 20),
        ("LOCAL5", 21),
        ("LOCAL6", 22),
        ("LOCAL7", 23),
    ];
    NAMES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, f)| f << 3)
}

/// The longest line, terminator excluded.
/// MIT `KRB5_KLOG_MAX_ERRMSG_SIZE` (`lib/kadm5/logger.c:41-41`): the line buffer is 2048 bytes.
const MAX_LINE: usize = 2047;

/// One log line: `date host whoami[pid](severity): message`, cut to MIT's buffer.
/// MIT `klog_vsyslog` (`lib/kadm5/logger.c:655-679`): the verbose header, then the message.
#[must_use]
pub fn format_line(
    date: &str,
    host: &str,
    whoami: &str,
    pid: u32,
    severity: Severity,
    msg: &str,
) -> String {
    line_parts(date, host, whoami, pid, severity, msg).0
}

/// [`format_line`] and the length of its header: the message part is what syslog gets.
fn line_parts(
    date: &str,
    host: &str,
    whoami: &str,
    pid: u32,
    severity: Severity,
    msg: &str,
) -> (String, usize) {
    let mut line = format!("{date} {host} {whoami}[{pid}]({}): ", severity.label());
    let head = line.len();
    line.push_str(cut(msg, MAX_LINE.saturating_sub(head)));
    (line, head)
}

/// `s` cut to at most `max` bytes, on a character boundary.
fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The text of an OS error as `strerror` gives it, without Rust's ` (os error N)`.
#[must_use]
pub fn os_error_text(e: &io::Error) -> String {
    let text = e.to_string();
    match e.raw_os_error() {
        Some(code) => text
            .strip_suffix(&format!(" (os error {code})"))
            .map_or_else(|| text.clone(), str::to_owned),
        None => text,
    }
}

/// One `[logging]` destination.
enum Dest {
    /// `FILE:` / `FILE=`; `None` after a reopen that failed.
    File { path: String, file: Option<File> },
    /// `STDERR`.
    Stderr,
    /// `CONSOLE` or `DEVICE=`, lines ending CR LF.
    Device { name: String, file: File },
    /// `SYSLOG`.
    Syslog,
}

/// The process's syslog connection, as `openlog(whoami, LOG_NDELAY | LOG_PID, facility)`.
struct Syslog {
    path: PathBuf,
    tag: String,
    facility: u8,
    sock: Option<UnixDatagram>,
}

impl Syslog {
    fn connect(path: &Path) -> Option<UnixDatagram> {
        let sock = UnixDatagram::unbound().ok()?;
        sock.connect(path).ok()?;
        Some(sock)
    }

    /// glibc `syslog`: `<pri>Mmm dd hh:mm:ss tag[pid]: message`, one datagram, reconnecting
    /// once when the log socket went away.
    fn send(&mut self, stamp: &str, severity: Severity, msg: &str) {
        let datagram = format!(
            "<{}>{stamp} {}[{}]: {msg}",
            self.facility | severity.code(),
            self.tag,
            std::process::id()
        );
        if let Some(sock) = &self.sock
            && sock.send(datagram.as_bytes()).is_ok()
        {
            return;
        }
        self.sock = Self::connect(&self.path);
        if let Some(sock) = &self.sock {
            let _ = sock.send(datagram.as_bytes());
        }
    }
}

/// An open log: what [`init`] sets up.
struct Logger {
    whoami: String,
    host: String,
    debug: bool,
    dests: Vec<Dest>,
    syslog: Option<Syslog>,
}

/// Why a destination did not open.
enum Refused {
    /// The spec is not one MIT reads; warned as a syntax error.
    Syntax,
    /// A file that would not open; already reported.
    Reported,
}

impl Logger {
    /// MIT `krb5_klog_init` (`lib/kadm5/logger.c:232-522`): open every spec, warn on `err` for
    /// the ones that do not open, and log to syslog when none does.
    fn open(
        whoami: &str,
        specs: &[String],
        debug: bool,
        syslog_path: &Path,
        err: &mut dyn Write,
    ) -> Self {
        let mut dests = Vec::new();
        let mut facility_used = None;
        for spec in specs {
            // MIT `krb5_klog_init` (`lib/kadm5/logger.c:296-303`): leading and trailing white
            // space is not part of the spec.
            let cp = spec.trim_matches(|c: char| c.is_ascii_whitespace());
            match open_spec(cp, err) {
                Ok((dest, facility)) => {
                    if let Some(f) = facility {
                        facility_used = Some(f);
                    }
                    dests.push(dest);
                }
                Err(Refused::Reported) => {}
                Err(Refused::Syntax) => {
                    // MIT `krb5_klog_init` (`lib/kadm5/logger.c:470-478`): an unparsed spec is
                    // warned about twice and skipped.
                    let _ = writeln!(err, "{whoami}: cannot parse <{cp}>");
                    let _ = writeln!(err, "{whoami}: warning - logging entry syntax error");
                }
            }
        }
        // MIT `krb5_klog_init` (`lib/kadm5/logger.c:490-503`): with no destination that opened,
        // the log goes to syslog, facility AUTH.
        if dests.is_empty() {
            dests.push(Dest::Syslog);
            facility_used = Some(LOG_AUTH);
        }
        // MIT `krb5_klog_init` (`lib/kadm5/logger.c:513-516`): one `openlog` with the last
        // SYSLOG destination's facility, connected at once.
        let syslog = facility_used.map(|facility| Syslog {
            path: syslog_path.to_path_buf(),
            tag: whoami.to_owned(),
            facility,
            sock: Syslog::connect(syslog_path),
        });
        Self {
            whoami: whoami.to_owned(),
            host: hostname(),
            debug,
            dests,
            syslog,
        }
    }

    /// MIT `klog_vsyslog` (`lib/kadm5/logger.c:633-742`): the line to every destination, a debug
    /// line only to syslog unless `debug` is set, a write error reported on standard error.
    fn write(&mut self, severity: Severity, msg: &str) {
        let now = chrono::Local::now();
        let (line, head) = line_parts(
            &now.format("%b %d %H:%M:%S").to_string(),
            &self.host,
            &self.whoami,
            std::process::id(),
            severity,
            msg,
        );
        let body = line.get(head..).unwrap_or_default();
        let stamp = now.format("%b %e %T").to_string();
        for dest in &mut self.dests {
            if severity == Severity::Debug && !self.debug && !matches!(dest, Dest::Syslog) {
                continue;
            }
            match dest {
                Dest::File { path, file } => {
                    let ok = file
                        .as_mut()
                        .is_some_and(|f| writeln!(f, "{line}").and_then(|()| f.flush()).is_ok());
                    if !ok {
                        eprintln!("{}: error writing to {path}", self.whoami);
                    }
                }
                Dest::Stderr => {
                    let mut e = io::stderr().lock();
                    if writeln!(e, "{line}").and_then(|()| e.flush()).is_err() {
                        eprintln!("{}: error writing to standard error", self.whoami);
                    }
                }
                Dest::Device { name, file } => {
                    if write!(file, "{line}\r\n")
                        .and_then(|()| file.flush())
                        .is_err()
                    {
                        eprintln!("{}: error writing to {name} device", self.whoami);
                    }
                }
                Dest::Syslog => {
                    if let Some(s) = self.syslog.as_mut() {
                        s.send(&stamp, severity, body);
                    }
                }
            }
        }
    }

    /// MIT `krb5_klog_reopen` (`lib/kadm5/logger.c:764-791`): every file is closed and opened
    /// again for appending, so a rotated log starts a new file.
    fn reopen(&mut self) {
        for dest in &mut self.dests {
            if let Dest::File { path, file } = dest {
                *file = None;
                match OpenOptions::new()
                    .read(true)
                    .append(true)
                    .create(true)
                    .open(&*path)
                {
                    Ok(f) => *file = Some(f),
                    Err(e) => eprintln!("Couldn't open log file {path}: {}", os_error_text(&e)),
                }
            }
        }
    }
}

/// Open one trimmed spec; the facility is `Some` for a `SYSLOG` destination.
fn open_spec(cp: &str, err: &mut dyn Write) -> Result<(Dest, Option<u8>), Refused> {
    if let Some(rest) = strip_prefix_ci(cp, "FILE") {
        // MIT `krb5_klog_init` (`lib/kadm5/logger.c:304-327`): `FILE:` appends and `FILE=`
        // writes from the start without truncating, both creating the file 0640.
        let append = match rest.as_bytes().first() {
            Some(b':') => true,
            Some(b'=') => false,
            _ => return Err(Refused::Syntax),
        };
        let path = &rest[1..];
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).append(append).mode(0o640);
        return match opts.open(path) {
            Ok(file) => Ok((
                Dest::File {
                    path: path.to_owned(),
                    file: Some(file),
                },
                None,
            )),
            Err(e) => {
                let _ = writeln!(err, "Couldn't open log file {path}: {}", os_error_text(&e));
                Err(Refused::Reported)
            }
        };
    }
    if let Some(rest) = strip_prefix_ci(cp, "SYSLOG") {
        // MIT `krb5_klog_init` (`lib/kadm5/logger.c:328-428`): `SYSLOG[:severity[:facility]]`;
        // the severity is ignored and an unknown facility leaves AUTH.
        let fac = rest
            .strip_prefix(':')
            .and_then(|r| r.split_once(':'))
            .and_then(|(_, f)| facility(f))
            .unwrap_or(LOG_AUTH);
        return Ok((Dest::Syslog, Some(fac)));
    }
    if cp.eq_ignore_ascii_case("STDERR") {
        return Ok((Dest::Stderr, None));
    }
    if cp.eq_ignore_ascii_case("CONSOLE") {
        // MIT `krb5_klog_init` (`lib/kadm5/logger.c:441-452`): `/dev/console`, opened "a+".
        return OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("/dev/console")
            .map(|file| {
                (
                    Dest::Device {
                        name: "console".into(),
                        file,
                    },
                    None,
                )
            })
            .map_err(|_| Refused::Syntax);
    }
    if let Some(path) = strip_prefix_ci(cp, "DEVICE").and_then(|r| r.strip_prefix('=')) {
        // MIT `krb5_klog_init` (`lib/kadm5/logger.c:453-469`): `DEVICE=path`, opened "w"; one
        // that does not open is a syntax error.
        return OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map(|file| {
                (
                    Dest::Device {
                        name: path.to_owned(),
                        file,
                    },
                    None,
                )
            })
            .map_err(|_| Refused::Syntax);
    }
    Err(Refused::Syntax)
}

/// `s` without its first `prefix.len()` bytes when they are `prefix` in any case.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// The host name for the line header; empty when it cannot be read, as MIT leaves it.
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim_end_matches('\n').to_owned())
        .unwrap_or_default()
}

static LOG: Mutex<Option<Logger>> = Mutex::new(None);

fn with_log(f: impl FnOnce(&mut Logger)) {
    let mut g = LOG.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(l) = g.as_mut() {
        f(l);
    }
}

/// Open `specs` (the `[logging]` values of the program, see `krb5_config::LogSpecs`) for
/// program `whoami`, warning on standard error about each one that does not open, as MIT
/// `krb5_klog_init` does. With none open the log goes to syslog, facility AUTH.
pub fn init(whoami: &str, specs: &[String], debug: bool) {
    let logger = Logger::open(
        whoami,
        specs,
        debug,
        Path::new("/dev/log"),
        &mut io::stderr(),
    );
    *LOG.lock().unwrap_or_else(PoisonError::into_inner) = Some(logger);
}

/// Write `msg` at `severity` to every destination; nothing before [`init`].
/// MIT `krb5_klog_syslog` (`lib/kadm5/logger.c:745-754`): one formatted line per call.
pub fn syslog(severity: Severity, msg: &str) {
    with_log(|l| l.write(severity, msg));
}

/// MIT `klog_com_err_proc` (`lib/kadm5/logger.c:182-208`): an error's text, ` - `, then the
/// message at error severity; with no error, the message alone at info.
pub fn com_err(error: Option<&str>, msg: &str) {
    match error {
        Some(e) => syslog(Severity::Err, &format!("{e} - {msg}")),
        None => syslog(Severity::Info, msg),
    }
}

/// Reopen the file destinations (SIGHUP).
pub fn reopen() {
    with_log(Logger::reopen);
}

/// Close every destination; later lines are dropped.
/// MIT `krb5_klog_close` (`lib/kadm5/logger.c:535-578`): the files and the syslog connection are
/// closed.
pub fn close() {
    *LOG.lock().unwrap_or_else(PoisonError::into_inner) = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            Self(krb5_testkit::scratch_dir(&format!("krb5-log-klog-{tag}")))
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn open(specs: &[&str], sock: &Path) -> (Logger, String) {
        let specs: Vec<String> = specs.iter().map(|s| (*s).to_owned()).collect();
        let mut err = Vec::new();
        let l = Logger::open("krb5kdc", &specs, false, sock, &mut err);
        (l, String::from_utf8(err).unwrap())
    }

    #[test]
    fn line_shape_is_mits_and_long_messages_are_cut() {
        let line = format_line("Oct 01 21:59:14", "h", "kadmind", 7, Severity::Notice, "m");
        assert_eq!(line, "Oct 01 21:59:14 h kadmind[7](Notice): m");
        let long = "é".repeat(2000);
        let line = format_line("Oct 01 21:59:14", "h", "kadmind", 7, Severity::Err, &long);
        assert!(line.len() <= MAX_LINE && line.len() > MAX_LINE - 2);
        assert!(line.contains("(Error): é"));
    }

    #[test]
    fn file_colon_appends_and_creates_0640() {
        let s = Scratch::new("append");
        let p = s.path("kdc.log");
        std::fs::write(&p, "old line\n").unwrap();
        let (mut l, err) = open(&[&format!("FILE:{}", p.display())], &s.path("nosock"));
        assert_eq!(err, "");
        l.write(Severity::Info, "commencing operation");
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with("old line\n"));
        assert!(text.ends_with("](info): commencing operation\n"), "{text}");
        let fresh = s.path("fresh.log");
        let (mut l, _) = open(&[&format!(" file:{} ", fresh.display())], &s.path("nosock"));
        l.write(Severity::Info, "x");
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & !0o640, 0, "{mode:o}");
    }

    #[test]
    fn file_equals_overwrites_from_the_start_without_truncating() {
        let s = Scratch::new("eq");
        let p = s.path("kdc.log");
        std::fs::write(&p, "X".repeat(4000)).unwrap();
        let (mut l, _) = open(&[&format!("FILE={}", p.display())], &s.path("nosock"));
        l.write(Severity::Info, "first");
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.len(), 4000);
        assert!(text.contains("(info): first\nXXX"));
    }

    #[test]
    fn bad_specs_warn_like_mit_and_fall_back_to_syslog() {
        let s = Scratch::new("bad");
        let sock = krb5_testkit::socket_path(&s.0, "log.sock");
        let sock_path = sock.path();
        let rx = UnixDatagram::bind(sock_path).unwrap();
        let (mut l, err) = open(
            &[
                "FILE:/nonexistent-dir-for-test/x.log",
                "FILE/s/nocolon.log",
                "BOGUS",
                "DEVICE:/s/devcolon.log",
            ],
            sock_path,
        );
        assert_eq!(
            err,
            "Couldn't open log file /nonexistent-dir-for-test/x.log: No such file or directory\n\
             krb5kdc: cannot parse <FILE/s/nocolon.log>\n\
             krb5kdc: warning - logging entry syntax error\n\
             krb5kdc: cannot parse <BOGUS>\n\
             krb5kdc: warning - logging entry syntax error\n\
             krb5kdc: cannot parse <DEVICE:/s/devcolon.log>\n\
             krb5kdc: warning - logging entry syntax error\n"
        );
        l.write(Severity::Info, "commencing operation");
        let mut buf = [0u8; 512];
        let n = rx.recv(&mut buf).unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(got.starts_with("<38>"), "{got}");
        assert!(
            got.ends_with(&format!(
                " krb5kdc[{}]: commencing operation",
                std::process::id()
            )),
            "{got}"
        );
    }

    #[test]
    fn syslog_facility_is_the_last_syslog_specs_and_debug_reaches_syslog_only() {
        let s = Scratch::new("fac");
        let sock = krb5_testkit::socket_path(&s.0, "log.sock");
        let sock_path = sock.path();
        let rx = UnixDatagram::bind(sock_path).unwrap();
        let file = s.path("f.log");
        let (mut l, err) = open(
            &[
                "SYSLOG:INFO:DAEMON",
                &format!("FILE:{}", file.display()),
                "syslog:notice:authpriv",
            ],
            sock_path,
        );
        assert_eq!(err, "");
        l.write(Severity::Debug, "Got signal to request exit");
        let mut buf = [0u8; 512];
        for _ in 0..2 {
            let n = rx.recv(&mut buf).unwrap();
            assert!(std::str::from_utf8(&buf[..n]).unwrap().starts_with("<87>"));
        }
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "");
        let (mut l, _) = open(&["SYSLOG:INFO:NOSUCH"], sock_path);
        l.write(Severity::Err, "e");
        let n = rx.recv(&mut buf).unwrap();
        assert!(std::str::from_utf8(&buf[..n]).unwrap().starts_with("<35>"));
    }

    #[test]
    fn device_lines_end_crlf_and_reopen_follows_a_rotated_file() {
        let s = Scratch::new("dev");
        let dev = s.path("dev");
        let file = s.path("hup.log");
        let (mut l, err) = open(
            &[
                &format!("DEVICE={}", dev.display()),
                &format!("FILE:{}", file.display()),
            ],
            &s.path("nosock"),
        );
        assert_eq!(err, "");
        l.write(Severity::Info, "before");
        assert!(
            std::fs::read_to_string(&dev)
                .unwrap()
                .ends_with("before\r\n")
        );
        std::fs::rename(&file, s.path("hup.log.1")).unwrap();
        l.reopen();
        l.write(Severity::Info, "after");
        assert!(
            std::fs::read_to_string(s.path("hup.log.1"))
                .unwrap()
                .ends_with("before\n")
        );
        assert!(std::fs::read_to_string(&file).unwrap().ends_with("after\n"));
    }

    #[test]
    fn os_error_text_is_strerror() {
        let e = io::Error::from_raw_os_error(13);
        assert_eq!(os_error_text(&e), "Permission denied");
        assert_eq!(os_error_text(&io::Error::other("x")), "x");
    }
}
