//! Daemon text log for `[logging]`, in MIT's `Mmm dd hh:mm:ss host prog[pid](Severity): message` shape.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use nix::fcntl::OFlag;

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
    // MIT severity2string; see docs/parity/a3-preauth.md
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

/// Facility names, any case.
// MIT krb5_klog_init; see docs/parity/a3-preauth.md
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
// MIT KRB5_KLOG_MAX_ERRMSG_SIZE; see docs/parity/a3-preauth.md
const MAX_LINE: usize = 2047;

/// One log line: `date host whoami[pid](severity): message`, cut to the buffer.
// MIT klog_vsyslog; see docs/parity/a3-preauth.md
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
    /// Open every spec, warn for the ones that do not open, and use syslog when none does.
    // MIT krb5_klog_init; see docs/parity/a3-preauth.md
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
            // Leading and trailing white space is not part of the spec.
            // MIT krb5_klog_init; see docs/parity/a3-preauth.md
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
                    // An unparsed spec is warned about twice and skipped.
                    // MIT krb5_klog_init; see docs/parity/a3-preauth.md
                    let _ = writeln!(err, "{whoami}: cannot parse <{cp}>");
                    let _ = writeln!(err, "{whoami}: warning - logging entry syntax error");
                }
            }
        }
        // With no destination that opened, the log goes to syslog, facility AUTH.
        // MIT krb5_klog_init; see docs/parity/a3-preauth.md
        if dests.is_empty() {
            dests.push(Dest::Syslog);
            facility_used = Some(LOG_AUTH);
        }
        // One `openlog` with the last SYSLOG destination's facility, connected at once.
        // MIT krb5_klog_init; see docs/parity/a3-preauth.md
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

    /// The line to every destination; a debug line only to syslog unless `debug` is set.
    // MIT klog_vsyslog; see docs/parity/a3-preauth.md
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
                        .is_some_and(|f| write_line(f, &line, "\n").is_ok());
                    if !ok {
                        eprintln!("{}: error writing to {path}", self.whoami);
                    }
                }
                Dest::Stderr => {
                    if write_line(&mut io::stderr().lock(), &line, "\n").is_err() {
                        eprintln!("{}: error writing to standard error", self.whoami);
                    }
                }
                Dest::Device { name, file } => {
                    if write_line(file, &line, "\r\n").is_err() {
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

    /// Every file is closed and opened again for appending.
    // MIT krb5_klog_reopen; see docs/parity/a3-preauth.md
    fn reopen(&mut self) {
        for dest in &mut self.dests {
            if let Dest::File { path, file } = dest {
                *file = None;
                match open_log_file(
                    path,
                    OpenOptions::new().read(true).append(true).create(true),
                ) {
                    Ok(f) => *file = Some(f),
                    Err(e) => eprintln!("Couldn't open log file {path}: {}", os_error_text(&e)),
                }
            }
        }
    }
}

/// Refuse a symlink or a non-regular file, so a planted link is not written through.
fn open_log_file(path: &str, opts: &mut OpenOptions) -> io::Result<File> {
    let file = opts
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

/// One `write(2)` of the line and its terminator, so two daemons do not mix a line.
// MIT klog_vsyslog; see docs/parity/a3-preauth.md
fn write_line(w: &mut impl Write, line: &str, end: &str) -> io::Result<()> {
    let mut buf = Vec::with_capacity(line.len() + end.len());
    buf.extend_from_slice(line.as_bytes());
    buf.extend_from_slice(end.as_bytes());
    w.write_all(&buf)?;
    w.flush()
}

/// Open one trimmed spec; the facility is `Some` for a `SYSLOG` destination.
fn open_spec(cp: &str, err: &mut dyn Write) -> Result<(Dest, Option<u8>), Refused> {
    if let Some(rest) = strip_prefix_ci(cp, "FILE") {
        // `FILE:` appends and `FILE=` writes from the start without truncating, both mode 0640.
        // MIT krb5_klog_init; see docs/parity/a3-preauth.md
        let append = match rest.as_bytes().first() {
            Some(b':') => true,
            Some(b'=') => false,
            _ => return Err(Refused::Syntax),
        };
        let path = &rest[1..];
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).append(append).mode(0o640);
        return match open_log_file(path, &mut opts) {
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
        // `SYSLOG[:severity[:facility]]`; the severity is ignored and an unknown facility leaves AUTH.
        // MIT krb5_klog_init; see docs/parity/a3-preauth.md
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
        // `/dev/console`, opened for append.
        // MIT krb5_klog_init; see docs/parity/a3-preauth.md
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
        // `DEVICE=path`, opened for write; one that does not open is a syntax error.
        // MIT krb5_klog_init; see docs/parity/a3-preauth.md
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

/// Open `specs` for `whoami`, and warn on standard error for each that does not open.
// MIT krb5_klog_init; see docs/parity/a3-preauth.md
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
// MIT krb5_klog_syslog; see docs/parity/a3-preauth.md
pub fn syslog(severity: Severity, msg: &str) {
    with_log(|l| l.write(severity, msg));
}

/// An error's text, ` - `, then the message at error severity; with no error, the message at info.
// MIT klog_com_err_proc; see docs/parity/a3-preauth.md
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
// MIT krb5_klog_close; see docs/parity/a3-preauth.md
pub fn close() {
    *LOG.lock().unwrap_or_else(PoisonError::into_inner) = None;
}

/// `[logging] json`, a relation MIT does not read.
#[derive(Clone, Debug)]
pub enum JsonLog {
    /// `STDOUT`.
    Stdout,
    /// `STDERR`.
    Stderr,
    /// `FILE:<path>`, opened once and appended to as a `FILE:` destination is.
    File(Arc<File>),
}

impl JsonLog {
    /// `STDOUT`, `STDERR`, or `FILE:<path>`; anything else, or a file that does not open, leaves it off.
    #[must_use]
    pub fn open(whoami: &str, spec: &str) -> Option<Self> {
        Self::open_reporting(whoami, spec, &mut io::stderr())
    }

    fn open_reporting(whoami: &str, spec: &str, err: &mut dyn Write) -> Option<Self> {
        let cp = spec.trim_matches(|c: char| c.is_ascii_whitespace());
        if cp.eq_ignore_ascii_case("STDOUT") {
            return Some(Self::Stdout);
        }
        if cp.eq_ignore_ascii_case("STDERR") {
            return Some(Self::Stderr);
        }
        if let Some(path) = strip_prefix_ci(cp, "FILE:") {
            let mut opts = OpenOptions::new();
            opts.append(true).create(true).mode(0o640);
            return match open_log_file(path, &mut opts) {
                Ok(file) => Some(Self::File(Arc::new(file))),
                Err(e) => {
                    let _ = writeln!(err, "Couldn't open log file {path}: {}", os_error_text(&e));
                    None
                }
            };
        }
        let _ = writeln!(err, "{whoami}: cannot parse <{cp}>");
        let _ = writeln!(err, "{whoami}: warning - logging entry syntax error");
        None
    }

    /// Whether the stream goes to a file, which a detached daemon still has.
    #[must_use]
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }

    /// One writer per event, for a `tracing` subscriber's `with_writer`.
    pub fn make_writer(self) -> impl Fn() -> Box<dyn Write> + Send + Sync + 'static {
        move || -> Box<dyn Write> {
            match &self {
                Self::Stdout => Box::new(io::stdout()),
                Self::Stderr => Box::new(io::stderr()),
                Self::File(file) => Box::new(SharedFile(Arc::clone(file))),
            }
        }
    }
}

/// A [`JsonLog::File`] writer: every event writes through the one open file.
struct SharedFile(Arc<File>);

impl Write for SharedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A target with known bytes and an old modification time, and a symlink to it at `link`,
    /// as a non-root owner of the log directory may plant one.
    fn plant_link(s: &Scratch, link: &Path) -> (PathBuf, std::time::SystemTime) {
        let victim = s.path("victim");
        std::fs::write(&victim, b"not a log\n").unwrap();
        let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        File::options()
            .write(true)
            .open(&victim)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(old)
                    .set_accessed(old),
            )
            .unwrap();
        let _ = std::fs::remove_file(link);
        std::os::unix::fs::symlink(&victim, link).unwrap();
        (victim, old)
    }

    fn assert_untouched(link: &Path, victim: &Path, old: std::time::SystemTime) {
        assert!(
            std::fs::symlink_metadata(link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(victim).unwrap(), b"not a log\n");
        assert_eq!(std::fs::metadata(victim).unwrap().modified().unwrap(), old);
    }

    /// A planted symlink is not opened, and the target is left as it was.
    #[test]
    fn a_log_file_is_never_opened_through_a_symlink() {
        let s = Scratch::new("link");
        let link = s.path("kdc.log");
        for spec in ["FILE:", "FILE="] {
            let (victim, old) = plant_link(&s, &link);
            let (mut l, err) = open(&[&format!("{spec}{}", link.display())], &s.path("nosock"));
            assert_eq!(
                err,
                format!(
                    "Couldn't open log file {}: Too many levels of symbolic links\n",
                    link.display()
                ),
                "{spec}"
            );
            l.write(Severity::Info, "commencing operation");
            assert_untouched(&link, &victim, old);
        }
    }

    /// A log file swapped for a symlink before a reopen (logrotate's) is not reopened through it.
    #[test]
    fn a_reopen_never_follows_a_symlink() {
        let s = Scratch::new("relink");
        let path = s.path("kdc.log");
        let (mut l, err) = open(&[&format!("FILE:{}", path.display())], &s.path("nosock"));
        assert_eq!(err, "");
        let (victim, old) = plant_link(&s, &path);
        l.reopen();
        assert!(
            matches!(l.dests.first(), Some(Dest::File { file: None, .. })),
            "the destination is not reopened"
        );
        l.write(Severity::Info, "after the reopen");
        assert_untouched(&path, &victim, old);
    }
}
