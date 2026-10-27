use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use nix::fcntl::OFlag;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Emerg,
    Alert,
    Crit,
    Err,
    Warning,
    Notice,
    Info,
    Debug,
}

impl Severity {
    // MIT: `severity2string` (lib/kadm5/logger.c:584-618)
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

const LOG_AUTH: u8 = 4 << 3;

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

/// Terminator excluded.
// MIT: `KRB5_KLOG_MAX_ERRMSG_SIZE` (lib/kadm5/logger.c:41-41)
const MAX_LINE: usize = 2047;

// MIT: `klog_vsyslog` (lib/kadm5/logger.c:633-742)
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

enum Dest {
    File { path: String, file: Option<File> },
    Stderr,
    Device { name: String, file: File },
    Syslog,
}

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

struct Logger {
    whoami: String,
    host: String,
    debug: bool,
    dests: Vec<Dest>,
    syslog: Option<Syslog>,
}

enum Refused {
    Syntax,
    Reported,
}

impl Logger {
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
                    let _ = writeln!(err, "{whoami}: cannot parse <{cp}>");
                    let _ = writeln!(err, "{whoami}: warning - logging entry syntax error");
                }
            }
        }
        if dests.is_empty() {
            dests.push(Dest::Syslog);
            facility_used = Some(LOG_AUTH);
        }
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

    // MIT: `krb5_klog_reopen` (lib/kadm5/logger.c:764-791)
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

/// Symlinks and non-files are refused.
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

fn write_line(w: &mut impl Write, line: &str, end: &str) -> io::Result<()> {
    let mut buf = Vec::with_capacity(line.len() + end.len());
    buf.extend_from_slice(line.as_bytes());
    buf.extend_from_slice(end.as_bytes());
    w.write_all(&buf)?;
    w.flush()
}

fn open_spec(cp: &str, err: &mut dyn Write) -> Result<(Dest, Option<u8>), Refused> {
    if let Some(rest) = strip_prefix_ci(cp, "FILE") {
        // `FILE:` appends. `FILE=` does not truncate. Mode 0640.
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
        // `SYSLOG` ignores severity; bad facility: AUTH.
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

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

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

// MIT: `krb5_klog_init` (lib/kadm5/logger.c:232-522)
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

pub trait LogSink: Send + Sync {
    fn line(&self, severity: Severity, msg: &str);
}

static SINK: Mutex<Option<Arc<dyn LogSink>>> = Mutex::new(None);

thread_local! {
    static THREAD_SINK: RefCell<Option<Arc<dyn LogSink>>> = const { RefCell::new(None) };
}

pub fn set_sink(sink: Option<Arc<dyn LogSink>>) {
    *SINK.lock().unwrap_or_else(PoisonError::into_inner) = sink;
}

pub struct ThreadSinkGuard {
    prev: Option<Arc<dyn LogSink>>,
}

impl Drop for ThreadSinkGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        THREAD_SINK.with(|slot| *slot.borrow_mut() = prev);
    }
}

pub fn push_thread_sink(sink: Arc<dyn LogSink>) -> ThreadSinkGuard {
    THREAD_SINK.with(|slot| ThreadSinkGuard {
        prev: slot.replace(Some(sink)),
    })
}

fn chosen_sink() -> Option<Arc<dyn LogSink>> {
    let local = THREAD_SINK.with(|slot| slot.borrow().clone());
    if local.is_some() {
        return local;
    }
    SINK.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

fn trace_unsent(severity: Severity, msg: &str) {
    match severity {
        Severity::Emerg | Severity::Alert | Severity::Crit | Severity::Err => {
            tracing::error!(target: "krb5_klog", "{msg}");
        }
        Severity::Warning => tracing::warn!(target: "krb5_klog", "{msg}"),
        Severity::Debug => tracing::debug!(target: "krb5_klog", "{msg}"),
        Severity::Notice | Severity::Info => tracing::info!(target: "krb5_klog", "{msg}"),
    }
}

// MIT: `krb5_klog_syslog` (lib/kadm5/logger.c:745-754)
pub fn syslog(severity: Severity, msg: &str) {
    if !write_open(severity, msg) {
        trace_unsent(severity, msg);
    }
}

pub fn syslog_open(severity: Severity, msg: &str) {
    write_open(severity, msg);
}

// MIT: `klog_com_err_proc` (lib/kadm5/logger.c:182-208)
pub fn com_err(error: Option<&str>, msg: &str) {
    match error {
        Some(e) => syslog(Severity::Err, &format!("{e} - {msg}")),
        None => syslog(Severity::Info, msg),
    }
}

pub fn reopen() {
    with_log(Logger::reopen);
}

// MIT: `krb5_klog_close` (lib/kadm5/logger.c:535-578)
pub fn close() {
    *LOG.lock().unwrap_or_else(PoisonError::into_inner) = None;
}

fn write_open(severity: Severity, msg: &str) -> bool {
    if let Some(sink) = chosen_sink() {
        sink.line(severity, msg);
        return true;
    }
    let mut held = LOG.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(logger) = held.as_mut() {
        logger.write(severity, msg);
        return true;
    }
    false
}

#[derive(Clone, Debug)]
pub enum JsonLog {
    Stdout,
    Stderr,
    File(Arc<File>),
}

impl JsonLog {
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

    #[must_use]
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }

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
