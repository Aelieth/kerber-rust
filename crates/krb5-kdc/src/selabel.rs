//! The SELinux context of a file the database tools create, set at its creation as Fedora's krb5
//! sets it: the context the loaded policy's `file_contexts` gives the path (what `matchpathcon`
//! prints) becomes the creating thread's fscreate context, the file is created, and the fscreate
//! context is cleared again on every return. A file already there is opened as it is. SELinux is
//! on as libselinux's `is_selinux_enabled` says: selinuxfs mounted at `/sys/fs/selinux` and an
//! `/etc/selinux/config`; without SELinux nothing happens, and with it an `enforce` that cannot be
//! read counts as enforcing.
//!
//! The lookup is libselinux's: the path goes through `file_contexts.subs` and
//! `file_contexts.subs_dist`; of the specifications in `file_contexts`, `file_contexts.homedirs`
//! and `file_contexts.local`, in that order, those without regular-expression characters are
//! tried first, and among each kind the last one whose expression matches the whole path and whose
//! file type allows a regular file wins; `<<none>>` means no context.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

/// Where selinuxfs is mounted when SELinux is on.
const SELINUXMNT: &str = "/sys/fs/selinux";
/// The selinuxfs file that says whether SELinux is enforcing.
const ENFORCE: &str = "/sys/fs/selinux/enforce";
/// The creating thread's fscreate context.
const FSCREATE: &str = "/proc/thread-self/attr/fscreate";
/// The SELinux configuration naming the loaded policy type.
const SELINUX_CONFIG: &str = "/etc/selinux/config";
/// libselinux's policy type when the configuration names none.
const DEFAULT_POLICY_TYPE: &str = "targeted";

/// Create the file at `path` with `create`, labeled with the context the policy gives `path`; a
/// file already there is left to `create` as it is.
///
/// # Errors
///
/// The error of `create`; when SELinux is enforcing, the error of setting the fscreate context
/// (the file is then not created).
pub(crate) fn create_labeled<T>(
    path: &Path,
    create: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let Some(enforcing) = selinux_enforcing() else {
        return create();
    };
    if fs::symlink_metadata(path).is_ok() {
        return create();
    }
    let Some(context) = FileContexts::load(&policy_context_dir())
        .ok()
        .and_then(|fc| fc.lookup(&absolute(path)))
    else {
        return create();
    };
    let _clear = match FsCreate::set(&context) {
        Ok(set) => Some(set),
        Err(e) if enforcing => return Err(e),
        Err(_) => None,
    };
    create()
}

/// Whether SELinux is enforcing, `None` when it is off: libselinux's `is_selinux_enabled`
/// (selinuxfs mounted read-write at [`SELINUXMNT`], a read-only one being how a container is
/// shown the host's, and its configuration file there, which a confined domain such as
/// `kpropd_t` may not read), then its `enforce`, where only `0` is permissive.
fn selinux_enforcing() -> Option<bool> {
    let mounted = nix::sys::statfs::statfs(SELINUXMNT)
        .is_ok_and(|fs| fs.filesystem_type() == nix::sys::statfs::SELINUX_MAGIC)
        && nix::sys::statvfs::statvfs(SELINUXMNT)
            .is_ok_and(|vfs| !vfs.flags().contains(nix::sys::statvfs::FsFlags::ST_RDONLY));
    let configured = nix::unistd::access(SELINUX_CONFIG, nix::unistd::AccessFlags::F_OK).is_ok();
    if !mounted || !configured {
        return None;
    }
    Some(fs::read_to_string(ENFORCE).map_or(true, |text| text.trim() != "0"))
}

/// `path` made absolute against the current directory, with its directory's symlinks resolved
/// when it exists, as the file's real location is what the policy labels.
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

/// `/etc/selinux/<SELINUXTYPE>/contexts/files`.
fn policy_context_dir() -> PathBuf {
    let config = fs::read_to_string(SELINUX_CONFIG).unwrap_or_default();
    let kind = config
        .lines()
        .filter_map(|l| l.trim().strip_prefix("SELINUXTYPE="))
        .map(str::trim)
        .find(|v| !v.is_empty())
        .unwrap_or(DEFAULT_POLICY_TYPE)
        .to_owned();
    Path::new("/etc/selinux")
        .join(kind)
        .join("contexts")
        .join("files")
}

/// The thread's fscreate context while this lives; cleared when it is dropped.
struct FsCreate(fs::File);

impl FsCreate {
    fn set(context: &str) -> io::Result<Self> {
        let mut f = OpenOptions::new().write(true).open(FSCREATE)?;
        let mut bytes = context.as_bytes().to_vec();
        bytes.push(0);
        f.write_all(&bytes)?;
        Ok(Self(f))
    }
}

impl Drop for FsCreate {
    fn drop(&mut self) {
        let _ = nix::unistd::write(&self.0, &[]);
    }
}

/// The file type a specification is limited to: `--` a regular file, and the others.
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

/// The specifications and substitutions of one policy's file contexts.
#[derive(Debug, Default)]
pub(crate) struct FileContexts {
    specs: Vec<Spec>,
    subs: Vec<(String, String)>,
    dist_subs: Vec<(String, String)>,
}

impl FileContexts {
    /// Read `file_contexts` (which must exist), `file_contexts.homedirs`, `file_contexts.local`
    /// and the two substitution files from `dir`.
    ///
    /// # Errors
    ///
    /// The OS error when `file_contexts` cannot be read.
    pub(crate) fn load(dir: &Path) -> io::Result<Self> {
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

    /// The context for a regular file at the absolute `path`, `None` for `<<none>>` or no match.
    pub(crate) fn lookup(&self, path: &str) -> Option<String> {
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

/// The first substitution whose source is `key` or a leading directory of it.
fn sub_one(subs: &[(String, String)], key: &str) -> Option<String> {
    subs.iter().find_map(|(src, dst)| {
        let rest = key.strip_prefix(src.as_str())?;
        (rest.is_empty() || rest.starts_with('/')).then(|| format!("{dst}{rest}"))
    })
}

/// Duplicate slashes collapsed and a trailing one dropped.
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

/// Whether a specification has regular-expression characters; an escaped character is literal.
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

/// Whether `path` starts with the literal text a specification's expression starts with, so that
/// only the few specifications that may match are compiled.
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
mod tests {
    use super::*;

    /// The `/var/kerberos/krb5kdc` lines of Fedora 43's targeted `file_contexts`, in their order,
    /// among a few others of the same shape.
    const FC: &str = "\
/.*\tsystem_u:object_r:default_t:s0
/var(/.*)?\tsystem_u:object_r:var_t:s0
/var/tmp(/.*)?\tsystem_u:object_r:tmp_t:s0
/var/kerberos/krb5kdc(/.*)?\tsystem_u:object_r:krb5kdc_conf_t:s0
/var/kerberos/krb5kdc/principal.*\tsystem_u:object_r:krb5kdc_principal_t:s0
/var/kerberos/krb5kdc/principal.*\\.ok\tsystem_u:object_r:krb5kdc_lock_t:s0
/var/kerberos/krb5kdc/from_master.*\tsystem_u:object_r:krb5kdc_lock_t:s0
/var/kerberos/krb5kdc/kadm5\\.keytab\t--\tsystem_u:object_r:krb5_keytab_t:s0
/var/kerberos/krb5kdc/nolabel\t<<none>>
/var/kerberos/krb5kdc/adir\t-d\tsystem_u:object_r:krb5kdc_conf_t:s0
";

    fn fc() -> FileContexts {
        let mut fc = FileContexts::default();
        fc.add_specs(FC);
        fc.dist_subs = vec![("/var/run".into(), "/run".into())];
        fc
    }

    #[test]
    fn the_lock_files_take_mits_lock_and_principal_types() {
        let fc = fc();
        let at = |p: &str| fc.lookup(p);
        let kdc = "/var/kerberos/krb5kdc";
        assert_eq!(
            at(&format!("{kdc}/principal.ok")).as_deref(),
            Some("system_u:object_r:krb5kdc_lock_t:s0")
        );
        assert_eq!(
            at(&format!("{kdc}/principal~.ok")).as_deref(),
            Some("system_u:object_r:krb5kdc_lock_t:s0")
        );
        assert_eq!(
            at(&format!("{kdc}/principal.kadm5.lock")).as_deref(),
            Some("system_u:object_r:krb5kdc_principal_t:s0")
        );
        assert_eq!(
            at(&format!("{kdc}//principal.kadm5.lock/")).as_deref(),
            Some("system_u:object_r:krb5kdc_principal_t:s0")
        );
        assert_eq!(
            at(&format!("{kdc}/kadm5.keytab")).as_deref(),
            Some("system_u:object_r:krb5_keytab_t:s0")
        );
        assert_eq!(at(&format!("{kdc}/nolabel")), None);
        assert_eq!(
            at(&format!("{kdc}/adir")).as_deref(),
            Some("system_u:object_r:krb5kdc_conf_t:s0")
        );
        assert_eq!(
            at("/var/tmp/x/principal.ok").as_deref(),
            Some("system_u:object_r:tmp_t:s0")
        );
        assert_eq!(
            at("/srv/kdc/principal.ok").as_deref(),
            Some("system_u:object_r:default_t:s0")
        );
    }

    #[test]
    fn substitutions_apply_to_a_leading_directory_only() {
        let fc = fc();
        assert_eq!(fc.substitute("/var/run/x"), "/run/x");
        assert_eq!(fc.substitute("/var/run"), "/run");
        assert_eq!(fc.substitute("/var/runner"), "/var/runner");
    }

    #[test]
    fn the_prefix_filter_never_drops_a_match() {
        for (re, path) in [
            ("/var/kerberos/krb5kdc(/.*)?", "/var/kerberos/krb5kdc"),
            (
                "/var/kerberos/krb5kdc/principal.*\\.ok",
                "/var/kerberos/krb5kdc/principal.ok",
            ),
            ("/foos?", "/foo"),
            ("/a|/b", "/b"),
            ("/x\\.y", "/x.y"),
        ] {
            assert!(may_match(re, path), "{re} {path}");
        }
        assert!(!may_match("/var/kerberos/krb5kdc(/.*)?", "/srv/x"));
    }

    /// Run with `KERBER_FILE_CONTEXTS_DIR` (a copy of a policy's `contexts/files`) and
    /// `KERBER_MATCHPATHCON_TABLE` (`matchpathcon` output: path, a tab, context) to compare this
    /// lookup with libselinux's for every path in the table; skipped otherwise.
    #[test]
    fn agrees_with_matchpathcon_when_given_its_table() {
        let (Some(dir), Some(table)) = (
            std::env::var_os("KERBER_FILE_CONTEXTS_DIR"),
            std::env::var_os("KERBER_MATCHPATHCON_TABLE"),
        ) else {
            return;
        };
        let fc = FileContexts::load(Path::new(&dir)).unwrap();
        let text = fs::read_to_string(table).unwrap();
        let mut rows = 0;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let (path, want) = line.split_once('\t').unwrap();
            let got = fc.lookup(path).unwrap_or_else(|| "<<none>>".to_owned());
            println!("{path}\tmatchpathcon {want}\tours {got}");
            assert_eq!(got, want.trim(), "{path}");
            rows += 1;
        }
        assert!(rows > 0);
    }
}
