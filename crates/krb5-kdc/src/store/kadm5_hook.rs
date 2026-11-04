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
    }

    impl Rec {
        fn new(name: &'static str, fail_pre: bool, fail_post: bool) -> Arc<Self> {
            Arc::new(Self {
                name,
                fail_pre,
                fail_post,
                hits: Mutex::new(Vec::new()),
            })
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
            _princ: &PrincipalName,
            _realm: &str,
            _keepold: u32,
            password: Option<&[u8]>,
            _etypes: &[EncryptionType],
        ) -> Result<(), Error> {
            let extra = if password.is_none() { "none" } else { "pw" };
            self.note("chpass", stage, extra)
        }

        fn create(
            &self,
            stage: HookStage,
            _princ: &PrincipalName,
            _realm: &str,
            _mask: u32,
            _password: Option<&[u8]>,
            _etypes: &[EncryptionType],
        ) -> Result<(), Error> {
            self.note("create", stage, "")
        }

        fn modify(
            &self,
            stage: HookStage,
            _princ: &PrincipalName,
            _realm: &str,
            _mask: u32,
        ) -> Result<(), Error> {
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
        let id = crate::kdb::lookup_principal_id(name, store.realm());
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
}
