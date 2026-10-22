//! The SELinux context of each file the Kerberos tools create, set as the file is created and never changed afterwards, the way Fedora's krb5 labels its files (its SELinux patch, `push_fscreatecon`): the context becomes the creating thread's fscreate context, the file is created, and the fscreate context is cleared again on every return.

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

/// Create the file at `path` with `create`, labeled with the context the policy gives a new file at `path`; a file already there is left to `create` as it is.
/// A context that cannot be set fails the create when SELinux is enforcing (an `enforce` that cannot be read counts as enforcing) and is skipped with a warning when it is permissive.
pub fn create_labeled<T>(path: &Path, create: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    match SeLinux::system() {
        Some(se) => se.create_labeled(path, create),
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
    /// SELinux on this system, `None` when it is off.
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

    /// Create the temp file that will be renamed onto `path` with `create`: with the replaced regular file's context when `replace` and `path` is one, else with the context the policy gives a new file at `path`.
    pub(crate) fn create_temp(
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
                    event = krb5_log::events::PROTOCOL_SECRET_FILE,
                    correlation_id = krb5_log::current_correlation_id(),
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

    /// The context of the regular file at `path`, not following a symlink.
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

/// `path` made absolute against the current directory, with its directory's symlinks resolved when it exists, as the file's real location is what the policy labels.
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

/// The thread's fscreate context while this lives, cleared when it is dropped with an empty write, as libselinux's `setfscreatecon(NULL)` clears it.
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

/// One write to a thread attribute, which the kernel takes whole or refuses.
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
    /// Read `file_contexts` (which must exist), `file_contexts.homedirs`, `file_contexts.local` and the two substitution files from `dir`.
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

    /// The context for a regular file at the absolute `path`, `None` for `<<none>>` or no match.
    /// Expressions are Rust regex, not PCRE2: anchored `^(?:…)$`, `.` excludes newline (no `DOTALL`), Unicode `\d\w\s`, and an uncompilable spec is skipped.
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
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::fs::PermissionsExt as _;

    thread_local! {
        /// Every write to the fscreate attribute, in order: a context ends in a NUL, a clear is empty.
        pub(crate) static ATTR_WRITES: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    const TEST_XATTR: &str = "user.kerber.test.selinux";

    const PRINCIPAL: &str = "system_u:object_r:krb5kdc_principal_t:s0";
    const LOCK: &str = "system_u:object_r:krb5kdc_lock_t:s0";
    const CONF: &str = "system_u:object_r:krb5kdc_conf_t:s0";
    const PRINCIPAL_U: &str = "unconfined_u:object_r:krb5kdc_principal_t:s0";
    const LOCK_U: &str = "unconfined_u:object_r:krb5kdc_lock_t:s0";

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

    /// A stand-in SELinux in a scratch directory: the thread's fscreate and current attributes (an unconfined user), and a policy whose `file_contexts` labels the files named in `specs` in its `data` directory. The write record starts empty.
    pub(crate) struct Fake {
        pub(crate) se: SeLinux,
        dir: PathBuf,
    }

    impl Fake {
        pub(crate) fn new(name: &str, enforcing: bool, specs: &[(&str, &str)]) -> Self {
            ATTR_WRITES.with(|w| w.borrow_mut().clear());
            let dir = krb5_testkit::scratch_dir(name);
            let attr = dir.join("attr");
            let files = dir.join("policy/targeted/contexts/files");
            let data = dir.join("data");
            for d in [&attr, &files, &data] {
                fs::create_dir_all(d).unwrap();
            }
            fs::write(attr.join("fscreate"), b"").unwrap();
            fs::write(
                attr.join("current"),
                b"unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023\0",
            )
            .unwrap();
            let real = fs::canonicalize(&data).unwrap();
            let mut fc = String::new();
            for (file, context) in specs {
                fc.push_str(&escape(&real.join(file).to_string_lossy()));
                fc.push('\t');
                fc.push_str(context);
                fc.push('\n');
            }
            fs::write(files.join("file_contexts"), fc).unwrap();
            fs::write(
                dir.join("config"),
                b"SELINUX=enforcing\nSELINUXTYPE=targeted\n",
            )
            .unwrap();
            Self {
                se: SeLinux {
                    roots: Roots {
                        selinuxfs: dir.join("selinuxfs"),
                        config: dir.join("config"),
                        policy_root: dir.join("policy"),
                        attr,
                        xattr: TEST_XATTR,
                    },
                    enforcing,
                },
                dir,
            }
        }

        /// The path of `name` in the labeled directory.
        pub(crate) fn path(&self, name: &str) -> PathBuf {
            self.dir.join("data").join(name)
        }

        /// What the fscreate stand-in holds: what was written to it.
        pub(crate) fn fscreate(&self) -> String {
            String::from_utf8(fs::read(self.fscreate_path()).unwrap()).unwrap()
        }

        fn fscreate_path(&self) -> PathBuf {
            self.se.roots.attr.join("fscreate")
        }

        fn hold(&self, context: &str) {
            fs::write(self.fscreate_path(), format!("{context}\0")).unwrap();
            fs::set_permissions(self.fscreate_path(), fs::Permissions::from_mode(0o400)).unwrap();
        }

        /// The fscreate attribute refuses every write.
        fn refuse(&self) {
            fs::remove_file(self.fscreate_path()).unwrap();
        }

        /// Give `path` the stand-in context `context`; false when the filesystem keeps no user extended attributes.
        pub(crate) fn label(path: &Path, context: &str) -> bool {
            let done = rustix::fs::setxattr(
                path,
                TEST_XATTR,
                context.as_bytes(),
                rustix::fs::XattrFlags::empty(),
            )
            .is_ok();
            if !done {
                eprintln!("skipped: no user extended attributes on this filesystem");
            }
            done
        }

        fn files(&self) -> usize {
            fs::read_dir(self.dir.join("data")).unwrap().count()
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = fs::set_permissions(self.fscreate_path(), fs::Permissions::from_mode(0o600));
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn escape(path: &str) -> String {
        let mut out = String::new();
        for c in path.chars() {
            if "\\.^$?*+|[](){}".contains(c) {
                out.push('\\');
            }
            out.push(c);
        }
        out
    }

    fn writes() -> Vec<Vec<u8>> {
        ATTR_WRITES.with(|w| w.borrow().clone())
    }

    fn set_then_cleared(context: &str) -> Vec<Vec<u8>> {
        vec![format!("{context}\0").into_bytes(), Vec::new()]
    }

    /// `create_temp` as the secret-file writes call it.
    fn temp(fake: &Fake, path: &Path, replace: bool) -> io::Result<(File, PathBuf)> {
        fake.se
            .create_temp(path, replace, || crate::secret_file::new_temp(path))
    }

    #[test]
    fn the_writers_user_replaces_the_policys() {
        assert_eq!(with_user(PRINCIPAL, "unconfined_u"), PRINCIPAL_U);
        assert_eq!(
            with_user("system_u:object_r:t:s0-s0:c0.c1023", "staff_u"),
            "staff_u:object_r:t:s0-s0:c0.c1023"
        );
        assert_eq!(with_user("garbage", "staff_u"), "garbage");
    }

    #[test]
    fn an_attribute_value_loses_its_trailing_nul_and_newline() {
        assert_eq!(attr_value(b"u:r:t:s0\0"), b"u:r:t:s0");
        assert_eq!(attr_value(b"u:r:t:s0\n\0"), b"u:r:t:s0");
        assert_eq!(attr_value(b"u:r:t:s0"), b"u:r:t:s0");
        assert_eq!(attr_value(b"\0"), b"");
        assert_eq!(attr_value(b""), b"");
    }

    #[test]
    fn a_first_create_takes_the_policys_context_whatever_the_kernel_gives() {
        let fake = Fake::new("selabel-first", true, &[("principal.ok", LOCK)]);
        let path = fake.path("principal.ok");
        fake.se
            .create_labeled(&path, || fs::write(&path, b""))
            .unwrap();
        assert_eq!(fake.fscreate(), format!("{LOCK_U}\0"));
        assert_eq!(fake.files(), 1, "nothing but the file");
    }

    #[test]
    fn the_context_is_set_for_the_create_and_cleared_with_an_empty_write() {
        let fake = Fake::new("selabel-set-clear", true, &[("principal.ok", LOCK)]);
        let path = fake.path("principal.ok");
        fake.se
            .create_labeled(&path, || {
                assert_eq!(writes(), vec![format!("{LOCK_U}\0").into_bytes()]);
                fs::write(&path, b"")
            })
            .unwrap();
        assert_eq!(writes(), set_then_cleared(LOCK_U));
    }

    #[test]
    fn the_fscreate_context_is_cleared_when_the_create_fails() {
        let fake = Fake::new("selabel-clear", true, &[("db", PRINCIPAL)]);
        let path = fake.path("db");
        let err = fake
            .se
            .create_labeled(&path, || -> io::Result<()> {
                Err(io::Error::other("boom"))
            })
            .unwrap_err();
        assert_eq!(err.to_string(), "boom");
        assert_eq!(writes(), set_then_cleared(PRINCIPAL_U));
    }

    #[test]
    fn fscreate_is_not_written_when_it_holds_the_context_already() {
        let fake = Fake::new("selabel-same", true, &[("db", PRINCIPAL)]);
        let path = fake.path("db");
        fake.hold(PRINCIPAL_U);
        fake.se
            .create_labeled(&path, || fs::write(&path, b"db"))
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"db");
        if !Fake::label(&path, PRINCIPAL_U) {
            return;
        }
        let (_, tmp) = temp(&fake, &path, true).unwrap();
        assert!(tmp.exists());
        assert_eq!(fake.fscreate(), format!("{PRINCIPAL_U}\0"));
    }

    #[test]
    fn a_refused_fscreate_write_fails_the_create_only_when_enforcing() {
        for enforcing in [true, false] {
            let fake = Fake::new("selabel-refused", enforcing, &[("principal", PRINCIPAL)]);
            fake.refuse();
            let path = fake.path("principal");
            let out = temp(&fake, &path, false);
            if enforcing {
                let err = out.unwrap_err();
                assert!(err.to_string().contains("(enforcing)"), "{err}");
                assert_eq!(fake.files(), 0, "no temp file is made");
            } else {
                assert!(out.unwrap().1.exists());
            }
        }
    }

    #[test]
    fn a_context_that_cannot_be_set_fails_the_create_only_when_enforcing() {
        for enforcing in [true, false] {
            let fake = Fake::new("selabel-unset", enforcing, &[("db", PRINCIPAL)]);
            fake.refuse();
            let path = fake.path("db");
            let mut created = false;
            let out = fake.se.create_labeled(&path, || {
                created = true;
                Ok(())
            });
            if enforcing {
                let err = out.unwrap_err();
                assert!(err.to_string().contains("(enforcing)"), "{err}");
                assert!(!created);
            } else {
                out.unwrap();
                assert!(created);
            }
        }
    }

    #[test]
    fn a_replace_keeps_the_replaced_files_context() {
        let fake = Fake::new("selabel-replace", true, &[("principal", PRINCIPAL)]);
        let path = fake.path("principal");
        fs::write(&path, b"old").unwrap();
        if !Fake::label(&path, CONF) {
            return;
        }
        let (_, tmp) = temp(&fake, &path, true).unwrap();
        assert_eq!(fake.fscreate(), format!("{CONF}\0"));
        assert!(tmp.exists());
        assert_eq!(fake.files(), 2, "the database and one temp file");
    }

    #[test]
    fn a_fresh_write_over_a_file_takes_the_policys_context() {
        let fake = Fake::new("selabel-fresh", true, &[("principal", PRINCIPAL)]);
        let path = fake.path("principal");
        fs::write(&path, b"old").unwrap();
        if !Fake::label(&path, CONF) {
            return;
        }
        let (_, tmp) = temp(&fake, &path, false).unwrap();
        assert_eq!(fake.fscreate(), format!("{PRINCIPAL_U}\0"));
        assert!(tmp.exists());
        assert_eq!(fake.files(), 2, "the database and one temp file");
    }

    #[test]
    fn a_replace_whose_context_cannot_be_set_fails_only_when_enforcing() {
        for enforcing in [true, false] {
            let fake = Fake::new("selabel-replace-unset", enforcing, &[]);
            let path = fake.path("principal");
            fs::write(&path, b"old").unwrap();
            if !Fake::label(&path, PRINCIPAL) {
                return;
            }
            fake.refuse();
            let out = temp(&fake, &path, true);
            if enforcing {
                let err = out.unwrap_err();
                assert!(err.to_string().contains("(enforcing)"), "{err}");
                assert_eq!(fake.files(), 1, "no temp file is left");
            } else {
                assert!(out.unwrap().1.exists());
            }
        }
    }

    #[test]
    fn a_file_already_there_is_left_as_it_is() {
        let fake = Fake::new("selabel-there", true, &[("db", PRINCIPAL)]);
        let path = fake.path("db");
        fs::write(&path, b"old").unwrap();
        fake.se.create_labeled(&path, || Ok(())).unwrap();
        assert_eq!(fake.fscreate(), "");
        assert_eq!(writes().len(), 0, "nothing written to fscreate");
    }

    #[test]
    fn without_selinuxfs_selinux_is_off() {
        let fake = Fake::new("selabel-off", true, &[]);
        assert!(SeLinux::detect(fake.se.roots.clone()).is_none());
    }

    #[test]
    fn the_lock_files_take_mits_lock_and_principal_types() {
        let fc = fc();
        let at = |p: &str| fc.lookup(p);
        let kdc = "/var/kerberos/krb5kdc";
        assert_eq!(at(&format!("{kdc}/principal.ok")).as_deref(), Some(LOCK));
        assert_eq!(at(&format!("{kdc}/principal~.ok")).as_deref(), Some(LOCK));
        assert_eq!(
            at(&format!("{kdc}/principal.kadm5.lock")).as_deref(),
            Some(PRINCIPAL)
        );
        assert_eq!(
            at(&format!("{kdc}//principal.kadm5.lock/")).as_deref(),
            Some(PRINCIPAL)
        );
        assert_eq!(
            at(&format!("{kdc}/kadm5.keytab")).as_deref(),
            Some("system_u:object_r:krb5_keytab_t:s0")
        );
        assert_eq!(at(&format!("{kdc}/nolabel")), None);
        assert_eq!(at(&format!("{kdc}/adir")).as_deref(), Some(CONF));
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
        let skipped: Vec<&str> = fc
            .specs
            .iter()
            .filter(|s| regex_automata::meta::Regex::new(&format!("^(?:{})$", s.regex)).is_err())
            .map(|s| s.regex.as_str())
            .collect();
        println!(
            "specifications this syntax cannot compile: {} of {}",
            skipped.len(),
            fc.specs.len()
        );
        for regex in skipped {
            println!("\t{regex}");
        }
    }
}
