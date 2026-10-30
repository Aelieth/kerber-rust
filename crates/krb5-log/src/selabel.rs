//! A created file's SELinux context is set at create, never after.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

const DEFAULT_POLICY_TYPE: &str = "targeted";

#[derive(Clone, Debug)]
pub(crate) struct Roots {
    selinuxfs: PathBuf,
    config: PathBuf,
    policy_root: PathBuf,
    attr: PathBuf,
    xattr: &'static str,
}

impl Roots {
    fn system() -> Self {
        Self {
            selinuxfs: PathBuf::from("/sys/fs/selinux"),
            config: PathBuf::from("/etc/selinux/config"),
            policy_root: PathBuf::from("/etc/selinux"),
            attr: PathBuf::from("/proc/thread-self/attr"),
            xattr: "security.selinux",
        }
    }
}

#[derive(Debug)]
pub(crate) struct SeLinux {
    roots: Roots,
    enforcing: bool,
}

/// A context that cannot be set fails when enforcing; permissive skips it.
/// An unreadable enforce mode counts as enforcing.
pub fn create_labeled<T>(path: &Path, create: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    match SeLinux::system() {
        Some(se) => se.create_labeled(path, create),
        None => create(),
    }
}

pub fn create_temp(
    path: &Path,
    keep: bool,
    create: impl FnOnce() -> io::Result<(File, PathBuf)>,
) -> io::Result<(File, PathBuf)> {
    match SeLinux::system() {
        Some(se) => se.create_temp(path, keep, create),
        None => create(),
    }
}

fn with_user(context: &str, user: &str) -> String {
    match context.split_once(':') {
        Some((_, rest)) => format!("{user}:{rest}"),
        None => context.to_owned(),
    }
}

impl SeLinux {
    pub(crate) fn system() -> Option<Self> {
        Self::detect(Roots::system())
    }

    fn detect(roots: Roots) -> Option<Self> {
        let mounted = nix::sys::statfs::statfs(&roots.selinuxfs)
            .is_ok_and(|fs| fs.filesystem_type() == nix::sys::statfs::SELINUX_MAGIC)
            && nix::sys::statvfs::statvfs(&roots.selinuxfs)
                .is_ok_and(|vfs| !vfs.flags().contains(nix::sys::statvfs::FsFlags::ST_RDONLY));
        let configured = nix::unistd::access(&roots.config, nix::unistd::AccessFlags::F_OK).is_ok();
        if !mounted || !configured {
            return None;
        }
        let enforcing =
            fs::read_to_string(roots.selinuxfs.join("enforce")).map_or(true, |t| t.trim() != "0");
        Some(Self { roots, enforcing })
    }

    fn create_labeled<T>(
        &self,
        path: &Path,
        create: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        if fs::symlink_metadata(path).is_ok() {
            return create();
        }
        let Some(context) = self.policy_context(path) else {
            return create();
        };
        let _clear = self.set_fscreate(&context, path)?;
        create()
    }

    fn create_temp(
        &self,
        path: &Path,
        replace: bool,
        create: impl FnOnce() -> io::Result<(File, PathBuf)>,
    ) -> io::Result<(File, PathBuf)> {
        let context = replace
            .then(|| self.regular_file_label(path))
            .flatten()
            .or_else(|| self.policy_context(path));
        let Some(context) = context else {
            return create();
        };
        let _clear = self.set_fscreate(&context, path)?;
        create()
    }

    fn set_fscreate(&self, context: &str, path: &Path) -> io::Result<Option<FsCreate>> {
        match FsCreate::set(&self.roots.attr, context) {
            Ok(set) => Ok(set),
            Err(e) if self.enforcing => Err(io::Error::new(
                e.kind(),
                format!(
                    "cannot create '{}' with SELinux context '{context}' (enforcing): {e}",
                    path.display()
                ),
            )),
            Err(e) => {
                tracing::warn!(
                    event = crate::events::PROTOCOL_SECRET_FILE,
                    correlation_id = crate::current_correlation_id(),
                    component = "krb5-protocol",
                    outcome = "ok",
                    path = %path.display(),
                    detail = "SELinux context not set",
                    error = %e,
                );
                Ok(None)
            }
        }
    }

    fn policy_context(&self, path: &Path) -> Option<String> {
        let context = FileContexts::load(&self.policy_context_dir())
            .ok()?
            .lookup(&absolute(path))?;
        Some(match self.own_user() {
            Some(user) => with_user(&context, &user),
            None => context,
        })
    }

    fn own_user(&self) -> Option<String> {
        let current = fs::read(self.roots.attr.join("current")).ok()?;
        let current = std::str::from_utf8(attr_value(&current)).ok()?;
        let user = current.split(':').next()?;
        (!user.is_empty()).then(|| user.to_owned())
    }

    fn policy_context_dir(&self) -> PathBuf {
        let config = fs::read_to_string(&self.roots.config).unwrap_or_default();
        let kind = config
            .lines()
            .filter_map(|l| l.trim().strip_prefix("SELINUXTYPE="))
            .map(str::trim)
            .find(|v| !v.is_empty())
            .unwrap_or(DEFAULT_POLICY_TYPE)
            .to_owned();
        self.roots
            .policy_root
            .join(kind)
            .join("contexts")
            .join("files")
    }

    fn regular_file_label(&self, path: &Path) -> Option<String> {
        if !fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file()) {
            return None;
        }
        let mut buf = [0u8; 4096];
        let n = rustix::fs::lgetxattr(path, self.roots.xattr, &mut buf[..]).ok()?;
        let context = std::str::from_utf8(attr_value(&buf[..n])).ok()?;
        (!context.is_empty()).then(|| context.to_owned())
    }
}

fn attr_value(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|&b| b != 0 && b != b'\n')
        .map_or(0, |i| i + 1);
    &bytes[..end]
}

fn absolute(path: &Path) -> String {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    };
    let resolved = match (joined.parent(), joined.file_name()) {
        (Some(dir), Some(name)) => fs::canonicalize(dir).map_or(joined.clone(), |d| d.join(name)),
        _ => joined,
    };
    resolved.to_string_lossy().into_owned()
}

struct FsCreate(File);

impl FsCreate {
    fn set(attr: &Path, context: &str) -> io::Result<Option<Self>> {
        let path = attr.join("fscreate");
        if fs::read(&path).is_ok_and(|now| attr_value(&now) == context.as_bytes()) {
            return Ok(None);
        }
        let file = OpenOptions::new().write(true).open(&path)?;
        let mut bytes = context.as_bytes().to_vec();
        bytes.push(0);
        write_attr(&file, &bytes)?;
        Ok(Some(Self(file)))
    }
}

impl Drop for FsCreate {
    fn drop(&mut self) {
        let _ = write_attr(&self.0, &[]);
    }
}

fn write_attr(file: &File, bytes: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    tests::ATTR_WRITES.with(|w| w.borrow_mut().push(bytes.to_vec()));
    nix::unistd::write(file, bytes)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpecType {
    Any,
    Regular,
    Other,
}

#[derive(Debug)]
struct Spec {
    regex: String,
    kind: SpecType,
    context: String,
    meta: bool,
}

#[derive(Debug, Default)]
struct FileContexts {
    specs: Vec<Spec>,
    subs: Vec<(String, String)>,
    dist_subs: Vec<(String, String)>,
}

impl FileContexts {
    /// `file_contexts` must exist; the other policy files are optional.
    fn load(dir: &Path) -> io::Result<Self> {
        let mut fc = Self::default();
        fc.add_specs(&fs::read_to_string(dir.join("file_contexts"))?);
        for extra in ["file_contexts.homedirs", "file_contexts.local"] {
            if let Ok(text) = fs::read_to_string(dir.join(extra)) {
                fc.add_specs(&text);
            }
        }
        fc.subs = read_subs(&dir.join("file_contexts.subs"));
        fc.dist_subs = read_subs(&dir.join("file_contexts.subs_dist"));
        Ok(fc)
    }

    fn add_specs(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (regex, kind, context) = match fields.as_slice() {
                [regex, context] => (*regex, SpecType::Any, *context),
                [regex, kind, context] => (
                    *regex,
                    if *kind == "--" {
                        SpecType::Regular
                    } else {
                        SpecType::Other
                    },
                    *context,
                ),
                _ => continue,
            };
            self.specs.push(Spec {
                regex: regex.to_owned(),
                kind,
                context: context.to_owned(),
                meta: has_meta(regex),
            });
        }
    }

    /// Rust regex, not PCRE2: anchored, no DOTALL, a bad spec skipped.
    fn lookup(&self, path: &str) -> Option<String> {
        let key = self.substitute(&normalize(path));
        let candidates = self
            .specs
            .iter()
            .filter(|s| !s.meta)
            .rev()
            .chain(self.specs.iter().filter(|s| s.meta).rev());
        for spec in candidates {
            if spec.kind == SpecType::Other || !may_match(&spec.regex, &key) {
                continue;
            }
            let Ok(re) = regex_automata::meta::Regex::new(&format!("^(?:{})$", spec.regex)) else {
                continue;
            };
            if re.is_match(key.as_bytes()) {
                return (spec.context != "<<none>>").then(|| spec.context.clone());
            }
        }
        None
    }

    fn substitute(&self, key: &str) -> String {
        match sub_one(&self.subs, key) {
            Some(s) => sub_one(&self.dist_subs, &s).unwrap_or(s),
            None => sub_one(&self.dist_subs, key).unwrap_or_else(|| key.to_owned()),
        }
    }
}

fn read_subs(path: &Path) -> Vec<(String, String)> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let mut f = l.split_whitespace();
            Some((f.next()?.to_owned(), f.next()?.to_owned()))
        })
        .collect()
}

fn sub_one(subs: &[(String, String)], key: &str) -> Option<String> {
    subs.iter().find_map(|(src, dst)| {
        let rest = key.strip_prefix(src.as_str())?;
        (rest.is_empty() || rest.starts_with('/')).then(|| format!("{dst}{rest}"))
    })
}

fn normalize(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if c == '/' && out.ends_with('/') {
            continue;
        }
        out.push(c);
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

fn has_meta(regex: &str) -> bool {
    let mut chars = regex.chars();
    while let Some(c) = chars.next() {
        match c {
            '.' | '^' | '$' | '?' | '*' | '+' | '|' | '[' | '(' | '{' => return true,
            '\\' => {
                chars.next();
            }
            _ => {}
        }
    }
    false
}

fn may_match(regex: &str, path: &str) -> bool {
    let mut depth = 0usize;
    let mut chars = regex.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            '|' if depth == 0 => return true,
            _ => {}
        }
    }
    let mut prefix = String::new();
    let mut chars = regex.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(e) if e.is_ascii_punctuation() => prefix.push(e),
                _ => break,
            },
            '?' | '*' | '{' => {
                prefix.pop();
                break;
            }
            '.' | '^' | '$' | '+' | '|' | '[' | '(' | ')' | ']' | '}' => break,
            other => prefix.push(other),
        }
    }
    path.starts_with(&prefix)
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "a test sets up its own profile and environment"
)]
pub(crate) mod tests {

    use std::cell::RefCell;

    thread_local! {
        pub(crate) static ATTR_WRITES: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }
}
