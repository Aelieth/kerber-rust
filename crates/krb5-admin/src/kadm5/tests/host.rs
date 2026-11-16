//! kadmind against a host store: every write reaches the host with its intent.

use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

use krb5_kdc::host::{
    Caller, Denial, HostChange, HostPrepared, KerberosStore, KerberosStoreError, LoadedRealm,
    MemoryRealm, Operation, TargetPeek, WriteIntent,
};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER};
use krb5_kdc::{PrincipalStore, SharedDump};

use super::*;

/// What one commit said: the operation, the caller, the client's mask, a password or not, the
/// rows' ids, and the names requested.
type Seen = (
    Operation,
    Caller,
    Option<u32>,
    bool,
    Vec<String>,
    Vec<String>,
);

/// What one prepare saw: the operation, a password or not, the lock free, the client's mask.
type Prepared = (Operation, bool, bool, Option<u32>);

#[derive(Default)]
struct TestHost {
    inner: MemoryRealm,
    seen: Mutex<Vec<Seen>>,
    deny: Mutex<Option<u32>>,
    prepared: Mutex<Vec<Prepared>>,
    store: OnceLock<Weak<std::sync::RwLock<PrincipalStore>>>,
}

impl TestHost {
    fn seen(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl KerberosStore for TestHost {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
        self.inner.load()
    }

    fn commit_change(&self, change: HostChange) -> Result<(), KerberosStoreError> {
        let i = &change.intent;
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((
                i.operation,
                i.caller.clone(),
                i.client_mask,
                i.password.is_some(),
                change.rows.iter().map(|r| r.id.clone()).collect(),
                i.requested.clone(),
            ));
        if let Some(code) = *self.deny.lock().unwrap_or_else(PoisonError::into_inner) {
            return Err(KerberosStoreError::Denied(Denial {
                kadm5_code: code,
                text: "not here".to_owned(),
            }));
        }
        self.inner.commit(change.batch)
    }

    fn prepare(
        &self,
        intent: &WriteIntent,
        _target: Option<&TargetPeek>,
    ) -> Result<Option<HostPrepared>, KerberosStoreError> {
        let unlocked = self
            .store
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|s| s.try_write().is_ok());
        self.prepared
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((
                intent.operation,
                intent.password.is_some(),
                unlocked,
                intent.client_mask,
            ));
        Ok(None)
    }
}

fn hosted() -> (SharedDump, Arc<TestHost>, krb5_kdc::Acl, String) {
    let (mut built, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let profile =
        krb5_config::ProfileSet::from_structs(TEST_REALM, krb5_config::Krb5Conf::default(), None);
    let spec = krb5_kdc::RealmSpec {
        realm: TEST_REALM,
        profile: &profile,
        mkvno: 1,
        admin: None,
    };
    krb5_kdc::bootstrap_realm_into(
        &mut built,
        krb5_kdc::MasterKey::Random { etype: None },
        &spec,
    )
    .unwrap();
    let host = Arc::new(TestHost::default());
    host.inner.commit(built.host_full_batch().unwrap()).unwrap();
    let seal = built.host_seal_key().unwrap();
    let mut store = PrincipalStore::open_host(
        Arc::clone(&host) as Arc<dyn KerberosStore>,
        TEST_REALM,
        seal,
    )
    .unwrap();
    store.policy = built.policy.clone();
    let shared = krb5_kdc::shared_dump(store);
    host.store.set(Arc::downgrade(&shared)).unwrap();
    (
        shared,
        host,
        acl,
        krb5_kdc::testrealm::documented_admin_id(),
    )
}

#[test]
fn every_kadmind_write_reaches_the_host_with_its_intent() {
    let (store, host, acl, actor) = hosted();
    let calls: [(u32, Vec<u8>, Operation); 7] = [
        (
            CHPASS_PRINCIPAL,
            chpass_args(TEST_USER, "another-password"),
            Operation::ChangePassword,
        ),
        (MODIFY_PRINCIPAL, modify_rec(TEST_USER), Operation::Modify),
        (
            PURGEKEYS,
            purgekeys_args(TEST_USER, 1),
            Operation::PurgeKeys,
        ),
        (
            SETKEY_PRINCIPAL,
            setkey16_args(TEST_USER, 17, &[7; 16]),
            Operation::SetKey,
        ),
        (
            SETKEY_PRINCIPAL3,
            setkey3_args(TEST_USER, 17, &[8; 16]),
            Operation::SetKey,
        ),
        (
            SETKEY_PRINCIPAL4,
            setkey4_args(TEST_USER, false, 9, 17, &[9; 16], 0, &[]),
            Operation::SetKey,
        ),
        (
            CREATE_PRINCIPAL,
            create_rec("fresh", "fresh-password"),
            Operation::Create,
        ),
    ];
    for (proc, args, op) in calls {
        let out = dispatch_kadm5(&store, &acl, &actor, proc, &args).unwrap();
        assert_eq!(ret_code(&out), 0, "{op:?} proc {proc}");
        let seen = host.seen();
        assert_eq!(seen.len(), 1, "{op:?} committed {} times", seen.len());
        let (got, caller, mask, password, rows, _) = &seen[0];
        assert_eq!(got, &op);
        let target = if op == Operation::Create {
            format!("fresh@{TEST_REALM}")
        } else {
            format!("{TEST_USER}@{TEST_REALM}")
        };
        assert!(rows.contains(&target), "{op:?} proc {proc}: {rows:?}");
        assert!(
            matches!(caller, Caller::Kadmind { client, .. } if *client == actor),
            "{op:?}: {caller:?}"
        );
        assert_eq!(
            *password,
            matches!(op, Operation::ChangePassword | Operation::Create),
            "{op:?}"
        );
        if op == Operation::Modify {
            assert_eq!(*mask, Some(KADM5_ATTRIBUTES));
        }
    }
    let prepared = std::mem::take(&mut *host.prepared.lock().unwrap());
    assert_eq!(prepared.len(), 7);
    assert!(
        prepared.iter().all(|(_, _, unlocked, _)| *unlocked),
        "prepare ran under the store's lock: {prepared:?}"
    );
    assert!(
        prepared
            .iter()
            .any(|(op, pw, _, _)| *op == Operation::ChangePassword && *pw)
    );
}

#[test]
fn a_host_denial_reaches_the_client_as_its_code() {
    let (store, host, acl, actor) = hosted();
    let id = format!("{TEST_USER}@{TEST_REALM}");
    let before = store.read().unwrap().get(&id).cloned().unwrap();
    for (proc, args, code) in [
        (
            CHPASS_PRINCIPAL,
            chpass_args(TEST_USER, "another-password"),
            KADM5_AUTH_CHANGEPW,
        ),
        (
            SETKEY_PRINCIPAL,
            setkey16_args(TEST_USER, 17, &[7; 16]),
            KADM5_AUTH_SETKEY,
        ),
        (
            SETKEY_PRINCIPAL4,
            setkey4_args(TEST_USER, false, 3, 17, &[7; 16], 0, &[]),
            KADM5_AUTH_SETKEY,
        ),
    ] {
        *host.deny.lock().unwrap() = Some(code);
        let out = dispatch_kadm5(&store, &acl, &actor, proc, &args).unwrap();
        assert_eq!(ret_code(&out), code, "proc {proc}");
    }
    let after = store.read().unwrap().get(&id).cloned().unwrap();
    assert_eq!(after.top_kvno(), before.top_kvno());
}

#[test]
fn kpasswd_takes_mits_result_code_for_a_denial() {
    assert_eq!(crate::kadm5::kpasswd_result(KADM5_AUTH_CHANGEPW), 5);
    assert_eq!(crate::kadm5::kpasswd_result(KADM5_AUTH_INITIAL), 7);
    assert_eq!(crate::kadm5::kpasswd_result(KADM5_PASS_Q_TOOSHORT), 4);
    assert_eq!(crate::kadm5::kpasswd_result(KADM5_AUTH_MODIFY), 2);
}

fn set_string_args(name: &str) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    w.nullstring(Some("key"));
    w.nullstring(Some("value"));
    w.b
}

#[test]
fn an_unauthorized_write_never_reaches_prepare() {
    let (store, host, _, _) = hosted();
    let limited = krb5_kdc::Acl::parse("limited@KERBER.TEST i\n").unwrap();
    let actor = "limited@KERBER.TEST";
    for (proc, args, want) in [
        (MODIFY_PRINCIPAL, modify_rec(TEST_USER), KADM5_AUTH_MODIFY),
        (
            CHRAND_PRINCIPAL,
            encode_named(TEST_USER),
            KADM5_AUTH_CHANGEPW,
        ),
        (PURGEKEYS, purgekeys_args(TEST_USER, 1), KADM5_AUTH_MODIFY),
        (
            SETKEY_PRINCIPAL,
            setkey16_args(TEST_USER, 17, &[7; 16]),
            KADM5_AUTH_SETKEY,
        ),
        (SET_STRING, set_string_args(TEST_USER), KADM5_AUTH_MODIFY),
    ] {
        let out = dispatch_kadm5(&store, &limited, actor, proc, &args).unwrap();
        assert_eq!(ret_code(&out), want, "proc {proc}");
    }
    assert_eq!(host.prepared.lock().unwrap().len(), 0);
    assert_eq!(host.seen(), Vec::<Seen>::new());
}

#[test]
fn modifys_prepare_sees_the_acl_restricted_mask() {
    let (store, host, _, actor) = hosted();
    let acl = krb5_kdc::Acl::parse(&format!("{actor} m * -maxlife 3600\n")).unwrap();
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        MODIFY_PRINCIPAL,
        &modify_rec(TEST_USER),
    );
    assert_eq!(ret_code(&out.unwrap()), 0);
    let prepared = std::mem::take(&mut *host.prepared.lock().unwrap());
    assert_eq!(prepared.len(), 1);
    assert_eq!(prepared[0].3, Some(KADM5_ATTRIBUTES | KADM5_MAX_LIFE));
}

#[test]
fn a_marked_principals_keys_are_not_read_out() {
    let (store, host, _, actor) = hosted();
    let acl = krb5_kdc::Acl::parse(&format!("{actor} *e\n")).unwrap();
    let extract = || {
        let out = dispatch_kadm5(
            &store,
            &acl,
            &actor,
            EXTRACT_KEYS,
            &extract_args(TEST_USER, 0),
        );
        ret_code(&out.unwrap())
    };
    assert_eq!(extract(), 0);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let committer = Arc::clone(&host);
    store
        .write()
        .unwrap()
        .change_committing(
            |c| committer.commit_change(c),
            |s| s.set_host_owned_in(&user, TEST_REALM, true),
        )
        .unwrap()
        .unwrap();
    assert_eq!(extract(), KADM5_AUTH_EXTRACT);
}

#[test]
fn create_alias_declares_the_alias_and_its_target() {
    let (store, host, acl, actor) = hosted();
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("nick@KERBER.TEST"));
    w.nullstring(Some("user@KERBER.TEST"));
    let out = dispatch_kadm5(&store, &acl, &actor, CREATE_ALIAS, &w.b).unwrap();
    assert_eq!(ret_code(&out), 0);
    let seen = host.seen();
    assert_eq!(seen.len(), 1);
    let (op, _, _, _, rows, requested) = &seen[0];
    assert_eq!(*op, Operation::CreateAlias);
    assert_eq!(requested, &["nick@KERBER.TEST", "user@KERBER.TEST"]);
    assert!(rows.contains(&"nick@KERBER.TEST".to_owned()), "{rows:?}");
}

#[test]
fn get_never_returns_the_host_mark() {
    let (store, host, acl, actor) = hosted();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let committer = Arc::clone(&host);
    store
        .write()
        .unwrap()
        .change_committing(
            |c| committer.commit_change(c),
            |s| s.set_host_owned_in(&user, TEST_REALM, true),
        )
        .unwrap()
        .unwrap();
    let id = format!("{TEST_USER}@{TEST_REALM}");
    assert!(store.read().unwrap().get(&id).unwrap().host_owned());
    let types = get_tl_types(&store, &acl, &actor, &id);
    assert!(!types.contains(&0x004B), "{types:x?}");
}
