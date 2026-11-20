//! kadm5 hooks.

use std::sync::{Arc, Mutex};

use krb5_crypto::EncryptionType;
use krb5_types::PrincipalName;
use zeroize::Zeroizing;

use super::PrincipalStore;
use crate::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookStage {
    Precommit = 0,
    Postcommit = 1,
}

// MIT: `kadm5_hook_vftable_1` (include/krb5/kadm5_hook_plugin.h)
pub trait Kadm5Hook: Send + Sync {
    fn name(&self) -> &'static str;

    // MIT: `k5_kadm5_hook_chpass` (kadm5_hook.c:142-151)
    // MIT: `kadm5_randkey_principal_3` (svr_principal.c:1485-1495)
    fn chpass(
        &self,
        _stage: HookStage,
        _princ: &PrincipalName,
        _realm: &str,
        _keepold: u32,
        _password: Option<&[u8]>,
        _etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        Ok(())
    }

    // MIT: `k5_kadm5_hook_create` (kadm5_hook.c:154-162)
    fn create(
        &self,
        _stage: HookStage,
        _princ: &PrincipalName,
        _realm: &str,
        _mask: u32,
        _password: Option<&[u8]>,
        _etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        Ok(())
    }

    // MIT: `k5_kadm5_hook_modify` (kadm5_hook.c:165-170)
    fn modify(
        &self,
        _stage: HookStage,
        _princ: &PrincipalName,
        _realm: &str,
        _mask: u32,
    ) -> Result<(), Error> {
        Ok(())
    }

    // MIT: `k5_kadm5_hook_rename` (kadm5_hook.c:173-178)
    fn rename(
        &self,
        _stage: HookStage,
        _old: &PrincipalName,
        _old_realm: &str,
        _new: &PrincipalName,
        _new_realm: &str,
    ) -> Result<(), Error> {
        Ok(())
    }

    // MIT: `k5_kadm5_hook_remove` (kadm5_hook.c:181-186)
    fn remove(&self, _stage: HookStage, _princ: &PrincipalName, _realm: &str) -> Result<(), Error> {
        Ok(())
    }

    // MIT: `k5_kadm5_hook_alias` (kadm5_hook.c:189-194)
    fn alias(
        &self,
        _stage: HookStage,
        _alias: &PrincipalName,
        _alias_realm: &str,
        _target: &PrincipalName,
        _target_realm: &str,
    ) -> Result<(), Error> {
        Ok(())
    }
}

static EXTRA: Mutex<Vec<Arc<dyn Kadm5Hook>>> = Mutex::new(Vec::new());

thread_local! {
    static THREAD: std::cell::RefCell<Option<Vec<Arc<dyn Kadm5Hook>>>> =
        const { std::cell::RefCell::new(None) };
}

/// No dlopen here.
pub fn register_kadm5_hook(module: Arc<dyn Kadm5Hook>) {
    EXTRA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(module);
}

pub fn set_thread_kadm5_hook(modules: Vec<Arc<dyn Kadm5Hook>>) {
    THREAD.with(|slot| *slot.borrow_mut() = Some(modules));
}

pub fn clear_thread_kadm5_hook() {
    THREAD.with(|slot| *slot.borrow_mut() = None);
}

/// A thread list hides the process list.
fn candidates() -> Vec<Arc<dyn Kadm5Hook>> {
    if let Some(modules) = THREAD.with(|slot| slot.borrow().clone()) {
        return modules;
    }
    EXTRA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// disable runs before enable_only.
fn selected(store: &PrincipalStore) -> Vec<Arc<dyn Kadm5Hook>> {
    let modules = candidates();
    let names: Vec<&str> = modules.iter().map(|module| module.name()).collect();
    let kept = krb5_config::filter_plugin_modules(&store.policy.kadm5_hook, &names);
    let mut left = modules;
    let mut out = Vec::new();
    for want in kept {
        if let Some(index) = left.iter().position(|module| module.name() == want) {
            out.push(left.remove(index));
        }
    }
    out
}

// MIT: `ITERATE` (kadm5_hook.c)
/// Precommit fails before the write.
/// Postcommit logs and continues.
fn walk(
    store: &PrincipalStore,
    stage: HookStage,
    operation: &'static str,
    mut call: impl FnMut(&dyn Kadm5Hook) -> Result<(), Error>,
) -> Result<(), Error> {
    for module in selected(store) {
        if let Err(err) = call(module.as_ref()) {
            if stage == HookStage::Precommit {
                return Err(err);
            }
            krb5_log::klog::syslog(
                krb5_log::klog::Severity::Err,
                &format!(
                    "kadm5_hook {} failed postcommit {operation}: {err}",
                    module.name()
                ),
            );
        }
    }
    Ok(())
}

pub(super) fn hook_chpass(
    store: &PrincipalStore,
    stage: HookStage,
    princ: &PrincipalName,
    realm: &str,
    keepold: u32,
    password: Option<&[u8]>,
    etypes: &[EncryptionType],
) -> Result<(), Error> {
    walk(store, stage, "chpass", |module| {
        module.chpass(stage, princ, realm, keepold, password, etypes)
    })
}

pub(super) fn hook_create(
    store: &PrincipalStore,
    stage: HookStage,
    princ: &PrincipalName,
    realm: &str,
    mask: u32,
    password: Option<&[u8]>,
    etypes: &[EncryptionType],
) -> Result<(), Error> {
    walk(store, stage, "create", |module| {
        module.create(stage, princ, realm, mask, password, etypes)
    })
}

pub(super) fn hook_modify(
    store: &PrincipalStore,
    stage: HookStage,
    princ: &PrincipalName,
    realm: &str,
    mask: u32,
) -> Result<(), Error> {
    walk(store, stage, "modify", |module| {
        module.modify(stage, princ, realm, mask)
    })
}

pub(super) fn hook_rename(
    store: &PrincipalStore,
    stage: HookStage,
    old: &PrincipalName,
    old_realm: &str,
    new: &PrincipalName,
    new_realm: &str,
) -> Result<(), Error> {
    walk(store, stage, "rename", |module| {
        module.rename(stage, old, old_realm, new, new_realm)
    })
}

pub(super) fn hook_remove(
    store: &PrincipalStore,
    stage: HookStage,
    princ: &PrincipalName,
    realm: &str,
) -> Result<(), Error> {
    walk(store, stage, "remove", |module| {
        module.remove(stage, princ, realm)
    })
}

pub(super) fn hook_alias(
    store: &PrincipalStore,
    stage: HookStage,
    alias_name: &PrincipalName,
    alias_realm: &str,
    target: &PrincipalName,
    target_realm: &str,
) -> Result<(), Error> {
    walk(store, stage, "alias", |module| {
        module.alias(stage, alias_name, alias_realm, target, target_realm)
    })
}

#[derive(Clone)]
pub(crate) enum Post {
    Chpass {
        princ: PrincipalName,
        realm: String,
        keepold: u32,
        password: Option<Zeroizing<Vec<u8>>>,
        etypes: Vec<EncryptionType>,
    },
    Create {
        princ: PrincipalName,
        realm: String,
        mask: u32,
        password: Option<Zeroizing<Vec<u8>>>,
        etypes: Vec<EncryptionType>,
    },
    Modify {
        princ: PrincipalName,
        realm: String,
        mask: u32,
    },
    Rename {
        old: PrincipalName,
        old_realm: String,
        new: PrincipalName,
        new_realm: String,
    },
    Remove {
        princ: PrincipalName,
        realm: String,
    },
    Alias {
        alias: PrincipalName,
        alias_realm: String,
        target: PrincipalName,
        target_realm: String,
    },
    ZeroFailCount {
        principal: Box<super::Principal>,
        stamp: u32,
    },
    MoveLockout {
        old_id: String,
        principal: Box<super::Principal>,
        kept: crate::lockout::Lockout,
    },
}

impl Post {
    pub(crate) fn always(&self) -> bool {
        matches!(self, Self::Create { .. })
    }

    pub(crate) fn run(&self, store: &PrincipalStore) {
        let stage = HookStage::Postcommit;
        let _ = match self {
            Self::Chpass {
                princ,
                realm,
                keepold,
                password,
                etypes,
            } => hook_chpass(
                store,
                stage,
                princ,
                realm,
                *keepold,
                password.as_deref().map(Vec::as_slice),
                etypes,
            ),
            Self::Create {
                princ,
                realm,
                mask,
                password,
                etypes,
            } => hook_create(
                store,
                stage,
                princ,
                realm,
                *mask,
                password.as_deref().map(Vec::as_slice),
                etypes,
            ),
            Self::Modify { princ, realm, mask } => hook_modify(store, stage, princ, realm, *mask),
            Self::Rename {
                old,
                old_realm,
                new,
                new_realm,
            } => hook_rename(store, stage, old, old_realm, new, new_realm),
            Self::Remove { princ, realm } => hook_remove(store, stage, princ, realm),
            Self::Alias {
                alias,
                alias_realm,
                target,
                target_realm,
            } => hook_alias(store, stage, alias, alias_realm, target, target_realm),
            Self::ZeroFailCount { principal, stamp } => {
                store.zero_fail_count_now(principal, *stamp);
                Ok(())
            }
            Self::MoveLockout {
                old_id,
                principal,
                kept,
            } => {
                store.move_lockout_now(old_id, principal, *kept);
                Ok(())
            }
        };
    }
}

impl std::fmt::Debug for Post {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Chpass { .. } => "chpass",
            Self::Create { .. } => "create",
            Self::Modify { .. } => "modify",
            Self::Rename { .. } => "rename",
            Self::Remove { .. } => "remove",
            Self::Alias { .. } => "alias",
            Self::ZeroFailCount { .. } => "zero fail count",
            Self::MoveLockout { .. } => "move lockout",
        })
    }
}

#[cfg(test)]
mod tests {

    use std::sync::{Arc, Mutex};

    use super::*;

    use crate::testrealm::TEST_USER;

    struct Rec {
        name: &'static str,
        fail_pre: bool,
        fail_post: bool,
        hits: Mutex<Vec<String>>,
        named: Mutex<Vec<String>>,
    }

    impl Rec {
        fn new(name: &'static str, fail_pre: bool, fail_post: bool) -> Arc<Self> {
            Arc::new(Self {
                name,
                fail_pre,
                fail_post,
                hits: Mutex::new(Vec::new()),
                named: Mutex::new(Vec::new()),
            })
        }

        fn name_call(&self, op: &str, stage: HookStage, princ: &PrincipalName, realm: &str) {
            let which = match stage {
                HookStage::Precommit => "pre",
                HookStage::Postcommit => "post",
            };
            self.named
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(format!(
                    "{op}:{which}:{}",
                    princ.unparse_with_realm_lossy(realm)
                ));
        }

        fn named(&self) -> Vec<String> {
            self.named
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn note(&self, op: &str, stage: HookStage, extra: &str) -> Result<(), Error> {
            let which = match stage {
                HookStage::Precommit => "pre",
                HookStage::Postcommit => "post",
            };
            let item = if extra.is_empty() {
                format!("{op}:{which}")
            } else {
                format!("{op}:{which}:{extra}")
            };
            self.hits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(item);
            if self.fail_pre && stage == HookStage::Precommit {
                return Err(Error::InvalidArgument("hook refused".into()));
            }
            if self.fail_post && stage == HookStage::Postcommit {
                return Err(Error::InvalidArgument("hook post".into()));
            }
            Ok(())
        }

        fn seen(&self) -> Vec<String> {
            self.hits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl Kadm5Hook for Rec {
        fn name(&self) -> &'static str {
            self.name
        }

        fn chpass(
            &self,
            stage: HookStage,
            princ: &PrincipalName,
            realm: &str,
            _keepold: u32,
            password: Option<&[u8]>,
            _etypes: &[EncryptionType],
        ) -> Result<(), Error> {
            self.name_call("chpass", stage, princ, realm);
            let extra = if password.is_none() { "none" } else { "pw" };
            self.note("chpass", stage, extra)
        }

        fn create(
            &self,
            stage: HookStage,
            princ: &PrincipalName,
            realm: &str,
            _mask: u32,
            _password: Option<&[u8]>,
            _etypes: &[EncryptionType],
        ) -> Result<(), Error> {
            self.name_call("create", stage, princ, realm);
            self.note("create", stage, "")
        }

        fn modify(
            &self,
            stage: HookStage,
            princ: &PrincipalName,
            realm: &str,
            mask: u32,
        ) -> Result<(), Error> {
            self.name_call(&format!("modify:{mask:#x}"), stage, princ, realm);
            self.note("modify", stage, "")
        }

        fn rename(
            &self,
            stage: HookStage,
            _old: &PrincipalName,
            _old_realm: &str,
            _new: &PrincipalName,
            _new_realm: &str,
        ) -> Result<(), Error> {
            self.note("rename", stage, "")
        }

        fn remove(
            &self,
            stage: HookStage,
            _princ: &PrincipalName,
            _realm: &str,
        ) -> Result<(), Error> {
            self.note("remove", stage, "")
        }

        fn alias(
            &self,
            stage: HookStage,
            _alias: &PrincipalName,
            _alias_realm: &str,
            _target: &PrincipalName,
            _target_realm: &str,
        ) -> Result<(), Error> {
            self.note("alias", stage, "")
        }
    }

    struct ClearThread;

    impl Drop for ClearThread {
        fn drop(&mut self) {
            clear_thread_kadm5_hook();
        }
    }

    fn user() -> PrincipalName {
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
    }

    fn install(module: &Arc<Rec>) -> ClearThread {
        set_thread_kadm5_hook(vec![Arc::clone(module) as Arc<dyn Kadm5Hook>]);
        ClearThread
    }

    fn kvno(store: &PrincipalStore, name: &PrincipalName) -> u32 {
        let id = crate::kdb::lookup_principal_id(name, store.realm()).expect("utf-8 name");
        store
            .get(&id)
            .expect("principal")
            .keys
            .iter()
            .map(|key| key.kvno)
            .max()
            .expect("key")
    }

    #[test]
    fn a_precommit_error_on_chpass_writes_nothing() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let module = Rec::new("bad", true, false);
        let _guard = install(&module);
        let before = kvno(&store, &user());
        let err = store
            .set_password(&user(), b"another-password")
            .expect_err("refused");
        assert!(matches!(err, Error::InvalidArgument(text) if text == "hook refused"));
        assert_eq!(kvno(&store, &user()), before);
        assert_eq!(module.seen(), ["chpass:pre:pw"]);
    }

    #[test]
    fn a_postcommit_error_does_not_fail_chpass() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let module = Rec::new("bad", false, true);
        let _guard = install(&module);
        let before = kvno(&store, &user());
        store
            .set_password(&user(), b"another-password")
            .expect("postcommit is logged");
        assert!(kvno(&store, &user()) > before);
        assert_eq!(module.seen(), ["chpass:pre:pw", "chpass:post:pw"]);
    }

    #[test]
    fn enable_only_of_an_unknown_hook_keeps_nothing() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        store.policy.kadm5_hook = krb5_config::Krb5Conf::parse(
            "[plugins]\n    kadm5_hook = {\n        enable_only = nosuch\n    }\n",
        )
        .expect("stanza")
        .plugin_relations("kadm5_hook");
        let module = Rec::new("bad", true, false);
        let _guard = install(&module);
        store
            .set_password(&user(), b"another-password")
            .expect("no module is loaded");
        assert_eq!(module.seen(), Vec::<String>::new());
    }

    #[test]
    fn a_kept_module_sees_precommit_then_postcommit() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let module = Rec::new("yes", false, false);
        let _guard = install(&module);
        store
            .set_password(&user(), b"another-password")
            .expect("chpass");
        store.chrand(&user()).expect("randkey");
        assert_eq!(
            module.seen(),
            [
                "chpass:pre:pw",
                "chpass:post:pw",
                "chpass:pre:none",
                "chpass:post:none",
            ]
        );
    }

    fn name_at(princ: &str) -> String {
        format!("{princ}@{}", crate::testrealm::TEST_REALM)
    }

    #[test]
    fn history_creation_fires_mits_create_then_randkey_hooks() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        store
            .put_policy(crate::store::NamedPolicy {
                history: 2,
                ..crate::store::NamedPolicy::new("hist")
            })
            .expect("policy");
        store
            .set_principal_policy(&user(), Some("hist".into()))
            .expect("bind");
        assert!(store.history_key().is_none());
        let module = Rec::new("yes", false, false);
        let _guard = install(&module);
        store
            .set_password(&user(), b"another-password")
            .expect("chpass");
        let (hist, me) = (name_at("kadmin/history"), name_at(TEST_USER));
        assert_eq!(
            module.named(),
            [
                format!("create:pre:{hist}"),
                format!("create:post:{hist}"),
                format!("chpass:pre:{hist}"),
                format!("chpass:post:{hist}"),
                format!("chpass:pre:{me}"),
                format!("chpass:post:{me}"),
            ]
        );
    }

    #[test]
    fn modify_hook_gets_the_clients_mask() {
        use crate::store::{ModifyPrincipal, TlData, kadm5_mask};
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let module = Rec::new("yes", false, false);
        let _guard = install(&module);
        let realm = crate::testrealm::TEST_REALM;
        let unlock = TlData {
            ty: crate::kdb_dump::TL_LAST_ADMIN_UNLOCK,
            contents: 7u32.to_le_bytes().to_vec(),
        };
        for m in [
            ModifyPrincipal {
                mask: kadm5_mask::KVNO,
                kvno: Some(9),
                ..ModifyPrincipal::default()
            },
            ModifyPrincipal {
                mask: kadm5_mask::TL_DATA,
                tl_data: vec![unlock.clone()],
                ..ModifyPrincipal::default()
            },
            ModifyPrincipal {
                mask: kadm5_mask::FAIL_AUTH_COUNT | kadm5_mask::TL_DATA,
                tl_data: vec![unlock.clone()],
                zero_fail_count: true,
                ..ModifyPrincipal::default()
            },
        ] {
            store
                .modify_principal_in(&user(), realm, m, "admin/admin")
                .expect("modify");
        }
        let me = name_at(TEST_USER);
        assert_eq!(
            module.named(),
            [
                format!("modify:0x100:pre:{me}"),
                format!("modify:0x100:post:{me}"),
                format!("modify:0x40000:pre:{me}"),
                format!("modify:0x40000:post:{me}"),
                format!("modify:0x50000:pre:{me}"),
                format!("modify:0x50000:post:{me}"),
            ]
        );
        assert_eq!(kvno(&store, &user()), 9);
    }

    #[test]
    fn hooks_name_the_principal_as_requested_even_an_alias() {
        use crate::store::{AdminFields, ModifyPrincipal, kadm5_mask};
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let realm = crate::testrealm::TEST_REALM;
        let alias = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nick"]);
        store
            .create_alias_in(&alias, realm, &user(), realm, "admin/admin")
            .expect("alias");
        let module = Rec::new("yes", false, false);
        let _guard = install(&module);
        store
            .set_password_keepold_n_in(&alias, realm, b"another-password", 0, "admin/admin")
            .expect("chpass");
        store
            .chrand_etypes_keepold_in(&alias, realm, &[], 0, "admin/admin")
            .expect("randkey");
        store
            .modify_principal_in(
                &alias,
                realm,
                ModifyPrincipal {
                    mask: kadm5_mask::MAX_LIFE,
                    fields: AdminFields {
                        max_life: Some(3600),
                        ..AdminFields::default()
                    },
                    ..ModifyPrincipal::default()
                },
                "admin/admin",
            )
            .expect("modify");
        let me = name_at("nick");
        assert_eq!(
            module.named(),
            [
                format!("chpass:pre:{me}"),
                format!("chpass:post:{me}"),
                format!("chpass:pre:{me}"),
                format!("chpass:post:{me}"),
                format!("modify:0x20:pre:{me}"),
                format!("modify:0x20:post:{me}"),
            ]
        );
    }

    #[test]
    fn a_modify_that_fails_after_its_edits_fires_no_hook() {
        use crate::store::{ModifyPrincipal, kadm5_mask};
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let module = Rec::new("yes", false, false);
        let _guard = install(&module);
        let out = store.modify_principal_in(
            &user(),
            crate::testrealm::TEST_REALM,
            ModifyPrincipal {
                mask: kadm5_mask::KVNO,
                kvno: Some(70_000),
                ..ModifyPrincipal::default()
            },
            "admin/admin",
        );
        assert!(out.is_err());
        assert_eq!(module.named(), Vec::<String>::new());
    }

    #[test]
    fn a_precommit_veto_leaves_the_row_as_it_was() {
        use crate::store::{AdminFields, ModifyPrincipal, kadm5_mask};
        let (mut store, _) = crate::testrealm::bootstrap_documented().expect("realm");
        let realm = crate::testrealm::TEST_REALM;
        let id = format!("{TEST_USER}@{realm}");
        let was = store.get(&id).cloned().expect("user");
        let module = Rec::new("no", true, false);
        let _guard = install(&module);
        let vetoed = store.modify_principal_in(
            &user(),
            realm,
            ModifyPrincipal {
                mask: kadm5_mask::MAX_LIFE | kadm5_mask::KVNO,
                fields: AdminFields {
                    max_life: Some(60),
                    ..AdminFields::default()
                },
                kvno: Some(9),
                ..ModifyPrincipal::default()
            },
            "admin/admin",
        );
        assert!(vetoed.is_err());
        assert!(
            store
                .chrand_etypes_keepold_in(&user(), realm, &[], 0, "admin/admin")
                .is_err()
        );
        let now = store.get(&id).expect("user");
        assert_eq!(
            (now.max_life, now.top_kvno(), &now.tl_data),
            (was.max_life, was.top_kvno(), &was.tl_data)
        );
    }

    struct Ordered(Arc<Mutex<Vec<String>>>, crate::host::MemoryRealm);

    impl Ordered {
        fn push(&self, what: String) {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(what);
        }
    }

    impl crate::host::KerberosStore for Ordered {
        fn load(&self) -> Result<crate::host::LoadedRealm, crate::host::KerberosStoreError> {
            self.1.load()
        }
        fn commit_change(
            &self,
            change: crate::host::HostChange,
        ) -> Result<(), crate::host::KerberosStoreError> {
            self.push("host:commit".to_owned());
            self.1.commit(change.batch)
        }
    }

    impl Kadm5Hook for Ordered {
        fn name(&self) -> &'static str {
            "ordered"
        }
        fn create(
            &self,
            stage: HookStage,
            princ: &PrincipalName,
            realm: &str,
            _mask: u32,
            _password: Option<&[u8]>,
            _etypes: &[EncryptionType],
        ) -> Result<(), Error> {
            if stage == HookStage::Postcommit {
                self.push(format!("post:{}", princ.unparse_with_realm_lossy(realm)));
            }
            Ok(())
        }
    }

    #[test]
    fn host_bootstrap_runs_create_postcommit_after_the_host_commit() {
        let realm = "M4.TEST";
        let dir = krb5_testkit::scratch_dir("kadm5-hook-m4");
        let log = Arc::new(Mutex::new(Vec::new()));
        let host = Arc::new(Ordered(
            Arc::clone(&log),
            crate::host::MemoryRealm::default(),
        ));
        set_thread_kadm5_hook(vec![Arc::clone(&host) as Arc<dyn Kadm5Hook>]);
        let _clear = ClearThread;
        let paths = krb5_config::KdcPaths {
            profile: dir.join("kdc.conf"),
            conf: None,
            realm: Some(realm.to_owned()),
            database_name: dir.join("principal"),
            key_stash_file: dir.join("stash"),
            acl_file: None,
            master_key_type: None,
        };
        let profile =
            krb5_config::ProfileSet::from_structs(realm, krb5_config::Krb5Conf::new(), None);
        let host_paths = crate::host::HostPaths {
            stash: dir.join("host.stash"),
            lockout: dir.join("host.lockout"),
        };
        crate::open_or_create_host(&paths, &profile, None, host, &host_paths).expect("realm");
        let seen = log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            seen,
            [
                "host:commit".to_owned(),
                format!("post:kadmin/admin@{realm}"),
                format!("post:kadmin/changepw@{realm}"),
            ]
        );
    }
}
