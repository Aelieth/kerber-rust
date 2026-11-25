//! The lab harness (`test-hooks`): the realm on a scripted host store, with a stub admission
//! module. `KERBER_TEST_HOST_DIR` names its directory: `stash`, `lockout` and `admin.keytab`,
//! the `events.log` it appends, and the `locked` and `ctl` files it reads. Not a shipped program.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock, Weak};
use std::thread;
use std::time::Duration;

use krb5_config::{KdcPaths, ProfileSet};
use krb5_embed_realm_example::totp::{SEEDS_ENV, TotpVerifier};
use krb5_kdc::admission::{AsNotice, AsQuestion, HostAdmission, KdcRefusal, TgsQuestion};
use krb5_kdc::host::{
    Caller, Denial, HostChange, HostPaths, HostPrepared, KerberosStore, KerberosStoreError,
    LoadedRealm, MemoryRealm, Operation, TargetPeek, WriteIntent,
};
use krb5_kdc::{AdminSpec, OtpVerdict, OtpVerifier, OtpVerifyRequest, PrincipalStore, SharedDump};
use krb5_types::PrincipalName;

// MIT: `KADM5_AUTH_ADD` (kadm_err.et:9-11)
const AUTH_ADD: u32 = 43_787_522;
const AUTH_MODIFY: u32 = 43_787_523;
const AUTH_DELETE: u32 = 43_787_524;
// MIT: `KADM5_PASS_Q_TOOSHORT` (kadm_err.et:29-29)
const PASS_Q_TOOSHORT: u32 = 43_787_542;
// MIT: `KADM5_AUTH_CHANGEPW` (kadm_err.et:52-52)
const AUTH_CHANGEPW: u32 = 43_787_565;
// MIT: `KADM5_AUTH_SETKEY` (kadm_err.et:57-57)
const AUTH_SETKEY: u32 = 43_787_570;
// MIT: `KADM5_PROTECT_PRINCIPAL` (kadm_err.et:37-37)
const PROTECT_PRINCIPAL: u32 = 43_787_550;
// MIT: `KADM5_BAD_KEYSALTS` (kadm_err.et:65-65)
const BAD_KEYSALTS: u32 = 43_787_578;
const FAIL_AUTH_COUNT: u32 = 0x0001_0000;
const TL_DATA: u32 = 0x0004_0000;
/// The directory's own password rule, checked before a change is carried out.
const MIN_PASSWORD: usize = 8;

struct Events(Mutex<File>);

impl Events {
    fn line(&self, text: &str) {
        let mut f = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(f, "{text}");
    }
}

struct Otp {
    inner: TotpVerifier,
    events: Arc<Events>,
}

impl OtpVerifier for Otp {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn verify(&self, req: &OtpVerifyRequest) -> OtpVerdict {
        let verdict = self.inner.verify(req);
        self.events.line(&format!(
            "otp {} armor={} {verdict:?}",
            req.principal.id(),
            req.armor_client.unparse_with_realm_lossy(&req.armor_realm)
        ));
        verdict
    }
}

/// A directory's answers for the principals it owns; every other row is carried out as MIT would.
struct TestHost {
    inner: MemoryRealm,
    events: Arc<Events>,
    store: OnceLock<Weak<RwLock<PrincipalStore>>>,
    directory: Mutex<BTreeSet<String>>,
    tokens: AtomicU64,
}

fn caller(c: &Caller) -> String {
    match c {
        Caller::Kadmind { client, .. } => format!("kadmind:{client}"),
        Caller::Kpasswd { client, .. } => format!("kpasswd:{client}"),
        Caller::Local { principal } => format!("local:{principal}"),
        Caller::Embedder => "embedder".to_owned(),
    }
}

fn digest(password: &[u8]) -> String {
    use sha2::Digest as _;
    let d = sha2::Sha256::digest(password);
    d.iter().take(8).fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl TestHost {
    fn ours(&self, change: &HostChange) -> bool {
        let dir = self
            .directory
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        change
            .rows
            .iter()
            .any(|r| r.host_owned || dir.contains(&r.id.to_lowercase()))
            || change
                .intent
                .requested
                .iter()
                .any(|n| dir.contains(&n.to_lowercase()))
    }

    fn verdict(&self, change: &HostChange) -> Result<(), KerberosStoreError> {
        let i = &change.intent;
        if i.operation == Operation::Embedded {
            return Err(KerberosStoreError::Refused(
                "an own change at commit_change".into(),
            ));
        }
        if i.operation == Operation::Bootstrap || !self.ours(change) {
            return Ok(());
        }
        let deny = |code: u32, text: &str| {
            Err(KerberosStoreError::Denied(Denial {
                kadm5_code: code,
                text: format!("directory: {text}"),
            }))
        };
        match i.operation {
            Operation::ChangePassword => match &i.password {
                Some(_) if !i.keysalts.is_empty() => {
                    deny(BAD_KEYSALTS, "no key/salt list for a directory user")
                }
                Some(p) if String::from_utf8_lossy(p).chars().count() < MIN_PASSWORD => {
                    deny(PASS_Q_TOOSHORT, "password shorter than 8")
                }
                Some(_) => Ok(()),
                None => deny(AUTH_CHANGEPW, "no random key for a directory user"),
            },
            Operation::Modify
                if i.client_mask.is_some_and(|m| {
                    m & FAIL_AUTH_COUNT != 0 && m & !(FAIL_AUTH_COUNT | TL_DATA) == 0
                }) =>
            {
                Ok(())
            }
            Operation::Randkey => deny(AUTH_CHANGEPW, "no random key for a directory user"),
            Operation::SetKey => deny(AUTH_SETKEY, "no foreign key for a directory user"),
            Operation::Create | Operation::CreateAlias => {
                deny(AUTH_ADD, "the name is the directory's")
            }
            Operation::Delete => deny(AUTH_DELETE, "delete the user in the directory"),
            Operation::Rename => deny(PROTECT_PRINCIPAL, "rename the user in the directory"),
            _ => deny(AUTH_MODIFY, "the directory owns this principal"),
        }
    }

    fn rows(change: &HostChange) -> String {
        change
            .rows
            .iter()
            .map(|r| {
                format!(
                    "{}:{:#x}:{}",
                    r.id,
                    r.mask,
                    if r.host_owned { "owned" } else { "-" }
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    fn own(&self, change: HostChange) -> Result<(), KerberosStoreError> {
        self.events.line(&format!(
            "own op={:?} rows={}",
            change.intent.operation,
            Self::rows(&change)
        ));
        self.inner.commit_change(change)
    }

    fn race_policy(&self, name: &str) {
        let out = self
            .store
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| "no store".to_owned())
            .and_then(|shared| {
                let mut g = shared.try_write().map_err(|_| "store locked".to_owned())?;
                let mut p = g.policies().get(name).cloned().ok_or("no such policy")?;
                p.pw_max_life += 86_400;
                g.change_committing(|c| self.own(c), |s| s.put_policy(p))
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())
            });
        self.events.line(&format!(
            "race policy {name} {}",
            out.map_or_else(|e| format!("err:{e}"), |()| "ok".to_owned())
        ));
    }
}

impl KerberosStore for TestHost {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
        self.inner.load()
    }

    fn commit_change(&self, change: HostChange) -> Result<(), KerberosStoreError> {
        let verdict = self.verdict(&change);
        let token = change
            .prepared
            .as_ref()
            .and_then(|p| p.downcast_ref::<String>())
            .cloned();
        self.events.line(&format!(
            "commit op={:?} caller={} mask={} rows={} password={} prepared={} verdict={}",
            change.intent.operation,
            caller(&change.intent.caller),
            change
                .intent
                .client_mask
                .map_or("-".into(), |m| format!("{m:#x}")),
            Self::rows(&change),
            change
                .intent
                .password
                .as_deref()
                .map_or("-".into(), |p| digest(p)),
            token.as_deref().unwrap_or("-"),
            match &verdict {
                Ok(()) => "ok".to_owned(),
                Err(KerberosStoreError::Denied(d)) => format!("denied:{}", d.kadm5_code),
                Err(e) => format!("refused:{e}"),
            }
        ));
        verdict?;
        self.inner.commit_change(change)
    }

    fn prepare(
        &self,
        intent: &WriteIntent,
        target: Option<&TargetPeek>,
    ) -> Result<Option<HostPrepared>, KerberosStoreError> {
        let unlocked = self
            .store
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|s| s.try_write().is_ok());
        let token = format!("tok-{}", self.tokens.fetch_add(1, Ordering::Relaxed) + 1);
        self.events.line(&format!(
            "prepare op={:?} caller={} target={} owned={} password={} lock_free={} token={token}",
            intent.operation,
            caller(&intent.caller),
            target.map_or("-", |t| t.id.as_str()),
            target.is_some_and(|t| t.host_owned),
            intent.password.as_deref().map_or("-".into(), |p| digest(p)),
            unlocked,
        ));
        if intent.operation == Operation::Create
            && let Ok(name) = std::env::var("KERBER_TEST_HOST_RACE_POLICY")
        {
            self.race_policy(&name);
        }
        Ok(Some(Box::new(token)))
    }
}

/// Refuses, with 18, the principals named in `locked` (one per line; a tab, then an e-text).
struct Gate {
    dir: PathBuf,
    events: Arc<Events>,
}

impl Gate {
    fn locked(&self, id: &str) -> Option<KdcRefusal> {
        let text = std::fs::read_to_string(self.dir.join("locked")).ok()?;
        text.lines().find_map(|l| {
            let (name, e_text) = l.split_once('\t').map_or((l, None), |(n, t)| (n, Some(t)));
            name.trim().eq_ignore_ascii_case(id).then(|| KdcRefusal {
                code: 18,
                e_text: e_text.map(str::to_owned),
            })
        })
    }

    fn answer(&self, what: &str, id: &str, extra: &str) -> Result<(), KdcRefusal> {
        let refusal = self.locked(id);
        self.events.line(&format!(
            "{what} client={id} {extra} verdict={}",
            refusal
                .as_ref()
                .map_or("ok".into(), |r| format!("refused:{}", r.code))
        ));
        refusal.map_or(Ok(()), Err)
    }
}

impl HostAdmission for Gate {
    fn check_as(&self, q: &AsQuestion<'_>) -> Result<(), KdcRefusal> {
        let extra = format!(
            "requested={} peer={:?} s4u2self={}",
            q.requested.components_joined_lossy(),
            q.peer,
            q.s4u2self
        );
        self.answer("check_as", &q.client.id(), &extra)
    }

    fn as_notice(&self, n: AsNotice) {
        self.events.line(&format!(
            "notice client={} requested={} peer={:?} code={} reason={:?} mechanism={}",
            n.client,
            n.requested,
            n.peer,
            n.code,
            n.reason,
            n.mechanism.map_or("-".into(), |m| format!("{m:?}"))
        ));
    }

    fn check_tgs(&self, q: &TgsQuestion<'_>) -> Result<(), KdcRefusal> {
        let id = q.client.principal().map_or_else(
            || format!("{}(none)", q.subject.components_joined_lossy()),
            krb5_kdc::Principal::id,
        );
        let extra = format!(
            "subject={} kind={:?} server={}",
            q.subject.components_joined_lossy(),
            q.kind,
            q.server.id()
        );
        self.answer("check_tgs", &id, &extra)
    }
}

pub(crate) struct Harness {
    host: Arc<TestHost>,
    dir: PathBuf,
    realm: String,
}

/// `None` when `KERBER_TEST_HOST_DIR` is unset: the example opens its own database.
pub(crate) fn open(
    paths: &KdcPaths,
    profile: &ProfileSet,
) -> Option<Result<(PrincipalStore, Harness), String>> {
    let dir = PathBuf::from(std::env::var_os("KERBER_TEST_HOST_DIR")?);
    Some(open_in(&dir, paths, profile))
}

fn open_in(
    dir: &Path,
    paths: &KdcPaths,
    profile: &ProfileSet,
) -> Result<(PrincipalStore, Harness), String> {
    let realm = paths.realm.clone().ok_or("no default realm")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let host_paths = HostPaths {
        stash: dir.join("stash"),
        lockout: dir.join("lockout"),
    };
    // The host is in memory: every start is a fresh realm.
    let _ = std::fs::remove_file(&host_paths.stash);
    let _ = std::fs::remove_file(&host_paths.lockout);
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("events.log"))
        .map_err(|e| e.to_string())?;
    let events = Arc::new(Events(Mutex::new(log)));
    let host = Arc::new(TestHost {
        inner: MemoryRealm::default(),
        events: Arc::clone(&events),
        store: OnceLock::new(),
        directory: Mutex::new(BTreeSet::new()),
        tokens: AtomicU64::new(0),
    });
    let admin = Some(AdminSpec::new(PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        ["admin", "admin"],
    )));
    let (mut store, boot) = krb5_kdc::open_or_create_host(
        paths,
        profile,
        admin,
        Arc::clone(&host) as Arc<dyn KerberosStore>,
        &host_paths,
    )
    .map_err(|e| e.to_string())?;
    if let Some(keytab) = &boot.admin_keytab {
        keytab
            .write_file(dir.join("admin.keytab"))
            .map_err(|e| e.to_string())?;
    }
    if std::env::var_os(SEEDS_ENV).is_some() {
        store
            .policy
            .plugins
            .register_otp_verifier(Arc::new(Otp {
                inner: TotpVerifier::from_env(),
                events: Arc::clone(&events),
            }))
            .map_err(|e| e.to_string())?;
    }
    if std::env::var_os("KERBER_TEST_HOST_NO_MODULE").is_none() {
        store.policy.plugins.set_host_admission(Arc::new(Gate {
            dir: dir.to_owned(),
            events,
        }));
    }
    Ok((
        store,
        Harness {
            host,
            dir: dir.to_owned(),
            realm,
        },
    ))
}

impl Harness {
    /// Gives the host the store, for its lock check, and starts reading `ctl`.
    pub(crate) fn attach(self, shared: &SharedDump) {
        let _ = self.host.store.set(Arc::downgrade(shared));
        let shared = Arc::clone(shared);
        thread::spawn(move || {
            loop {
                let ctl = self.dir.join("ctl");
                if let Ok(text) = std::fs::read_to_string(&ctl) {
                    let _ = std::fs::remove_file(&ctl);
                    for line in text.lines().filter(|l| !l.trim().is_empty()) {
                        let out = self.command(&shared, line.trim());
                        self.host.events.line(&format!(
                            "ctl {line} {}",
                            out.map_or_else(|e| format!("err:{e}"), |()| "ok".to_owned())
                        ));
                    }
                }
                thread::sleep(Duration::from_millis(200));
            }
        });
    }

    /// `mark NAME`, `unmark NAME`, `delete NAME` or `delegate SERVICE TARGET`, as the host's own change.
    fn command(&self, shared: &SharedDump, line: &str) -> Result<(), String> {
        let usage = "usage: mark|unmark|delete NAME, delegate SERVICE TARGET";
        let (verb, rest) = line.split_once(' ').ok_or(usage)?;
        let (who, target) = match verb {
            "delegate" => {
                let (who, target) = rest.trim().split_once(' ').ok_or(usage)?;
                (who, Some(target.trim()))
            }
            _ => (rest.trim(), None),
        };
        let (parts, realm) = krb5_types::parse_name(who, &self.realm).map_err(|e| e.to_string())?;
        if target.is_some() && realm != self.realm {
            return Err("service is in another realm".to_owned());
        }
        let actor = format!("admin/admin@{}", self.realm);
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, parts);
        let id = name.unparse_with_realm_lossy(&realm).to_lowercase();
        let host = Arc::clone(&self.host);
        let mut g = shared.write().unwrap_or_else(PoisonError::into_inner);
        let done = g
            .change_committing(
                |c| host.own(c),
                |s| match (verb, target) {
                    ("mark", None) => s.set_host_owned_in(&name, &realm, true),
                    ("unmark", None) => s.set_host_owned_in(&name, &realm, false),
                    ("delete", None) => s.remove_in(&name, &realm),
                    ("delegate", Some(to)) => s.record_s4u_to(&name, to, &actor),
                    _ => Err(krb5_kdc::Error::InvalidArgument(format!(
                        "no command {verb}"
                    ))),
                },
            )
            .map_err(|e| e.to_string())?;
        done.map_err(|e| e.to_string())?;
        let mut dir = self
            .host
            .directory
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match verb {
            "mark" => {
                dir.insert(id);
            }
            "unmark" | "delete" => {
                dir.remove(&id);
            }
            _ => {}
        }
        Ok(())
    }
}
