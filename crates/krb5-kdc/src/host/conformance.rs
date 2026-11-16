//! Rows a host runs against its own store; names hold a `/`, so none binds a user.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use krb5_config::{Krb5Conf, ProfileSet};
use krb5_types::PrincipalName;

use super::{
    Caller, HostChange, KerberosStore, KerberosStoreError, LoadedRealm, Operation, PrincipalRow,
    RealmBatch, SealKey, WriteIntent, open_policy,
};
use crate::create::{MasterKey, RealmSpec, bootstrap_realm_into};
use crate::error::Error;
use crate::store::{NamedPolicy, PrincipalStore};

const REALM: &str = "CONFORMANCE.TEST";
const ACTOR: &str = "conformance/admin@CONFORMANCE.TEST";

#[derive(Debug)]
pub struct Row {
    pub name: &'static str,
    pub outcome: Result<(), String>,
}

type NewStore<'a> = &'a dyn Fn() -> Arc<dyn KerberosStore>;
type Check = fn(NewStore<'_>) -> Result<(), String>;

pub fn run(new_store: NewStore<'_>) -> Vec<Row> {
    let rows: [(&'static str, Check); 16] = [
        ("a realm round-trips", round_trip),
        (
            "a refused, failed or not-ready commit restores memory",
            restores,
        ),
        (
            "a commit that landed but failed is reloaded",
            unknown_outcome,
        ),
        ("delete and rename reach the host", delete_and_rename),
        ("policies reach the host", policies),
        ("a broken seal is refused", broken_seals),
        ("change_committing commits once", commits_once),
        ("a mutator outside a change is refused", outside_change),
        (
            "a panic in the commit or the change restores memory",
            panics_restore,
        ),
        (
            "kadmin/history commits with the change that made it",
            history_in_the_change,
        ),
        (
            "a refused change leaves no kadmin/history",
            history_rolls_back,
        ),
        (
            "a commit carries each touched row with its mask",
            rows_and_masks,
        ),
        (
            "a declared intent reaches the host; a change of nothing does not",
            declared_intent,
        ),
        (
            "a denied commit restores memory without a reload",
            denied_restores,
        ),
        (
            "the host mark is set only in a change and survives a reload",
            host_mark,
        ),
        ("no lockout field is in a row's mask", no_lockout_bits),
    ];
    rows.into_iter()
        .map(|(name, row)| Row {
            name,
            outcome: row(new_store),
        })
        .collect()
}

fn fail(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn ensure(ok: bool, what: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(what.to_owned()) }
}

fn name(n: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, n.split('/'))
}

fn fresh(host: Arc<dyn KerberosStore>) -> Result<(PrincipalStore, SealKey), String> {
    let mut built = PrincipalStore::try_new(REALM).map_err(fail)?;
    let profile = ProfileSet::from_structs(REALM, Krb5Conf::default(), None);
    let spec = RealmSpec {
        realm: REALM,
        profile: &profile,
        mkvno: 1,
        admin: None,
    };
    bootstrap_realm_into(&mut built, MasterKey::Random { etype: None }, &spec).map_err(fail)?;
    let seal = built.host_seal_key().ok_or("no master key")?;
    host.commit_change(built.host_full_change().map_err(fail)?)
        .map_err(fail)?;
    let store = PrincipalStore::open_host(host, REALM, seal.clone()).map_err(fail)?;
    Ok((store, seal))
}

fn add(store: &mut PrincipalStore, n: &str) -> Result<(), Error> {
    store.change(|s| s.insert_new_randkey(&name(n), REALM, &[], ACTOR))?
}

fn host_has(host: &dyn KerberosStore, row: &str) -> Result<bool, String> {
    Ok(host
        .load()
        .map_err(fail)?
        .principals
        .iter()
        .any(|p| p.name == row))
}

#[derive(Clone, Copy)]
enum Fault {
    Refuse,
    Fail,
    NotReady,
    CommitThenFail,
    Panic,
    Deny,
}

/// What a commit said: the operation, then each row's id, mask and mark.
type Seen = (Operation, Caller, Vec<(String, u32, bool)>);

struct Faulty {
    inner: Arc<dyn KerberosStore>,
    next: Mutex<Option<Fault>>,
    commits: Mutex<Vec<Vec<String>>>,
    seen: Mutex<Vec<Seen>>,
}

impl Faulty {
    fn arm(&self, fault: Fault) {
        *self.next.lock().unwrap_or_else(PoisonError::into_inner) = Some(fault);
    }
}

impl KerberosStore for Faulty {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
        self.inner.load()
    }

    fn commit_change(&self, change: HostChange) -> Result<(), KerberosStoreError> {
        let fault = self
            .next
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.commits
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(
                change
                    .batch
                    .upsert_principals
                    .iter()
                    .map(|p| p.name.clone())
                    .collect(),
            );
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((
                change.intent.operation,
                change.intent.caller.clone(),
                change
                    .rows
                    .iter()
                    .map(|r| (r.id.clone(), r.mask, r.host_owned))
                    .collect(),
            ));
        match fault {
            None => self.inner.commit_change(change),
            Some(Fault::Deny) => Err(KerberosStoreError::Denied(super::Denial {
                kadm5_code: DENIED_CODE,
                text: "conformance".to_owned(),
            })),
            Some(Fault::Refuse) => Err(KerberosStoreError::Refused("conformance".to_owned())),
            Some(Fault::Fail) => Err(KerberosStoreError::Failed("conformance".to_owned())),
            Some(Fault::NotReady) => Err(KerberosStoreError::NotReady("conformance".to_owned())),
            Some(Fault::CommitThenFail) => {
                self.inner.commit_change(change)?;
                Err(KerberosStoreError::Failed("conformance".to_owned()))
            }
            #[expect(clippy::panic, reason = "the row arms the store's panic guard")]
            Some(Fault::Panic) => panic!("conformance: the host's commit panics"),
        }
    }
}

const DENIED_CODE: u32 = 43_787_522;

impl Faulty {
    fn seen(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn commits(&self) -> Vec<Vec<String>> {
        std::mem::take(&mut *self.commits.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

fn faulty(new_store: NewStore<'_>) -> Arc<Faulty> {
    Arc::new(Faulty {
        inner: new_store(),
        next: Mutex::new(None),
        commits: Mutex::new(Vec::new()),
        seen: Mutex::new(Vec::new()),
    })
}

fn round_trip(new_store: NewStore<'_>) -> Result<(), String> {
    let host = new_store();
    let (mut store, seal) = fresh(Arc::clone(&host))?;
    add(&mut store, "conformance/one").map_err(fail)?;
    let again = PrincipalStore::open_host(host, REALM, seal).map_err(fail)?;
    ensure(
        again.ids() == store.ids(),
        "the reopened realm has other principals",
    )?;
    for id in store.ids() {
        let (a, b) = (store.get(&id), again.get(&id));
        let same = a.zip(b).is_some_and(|(a, b)| {
            a.keys.len() == b.keys.len()
                && a.keys
                    .iter()
                    .zip(&b.keys)
                    .all(|(x, y)| x.kvno == y.kvno && x.key.as_bytes() == y.key.as_bytes())
        });
        ensure(same, &format!("{id} reopened with other keys"))?;
    }
    Ok(())
}

fn restores(new_store: NewStore<'_>) -> Result<(), String> {
    for fault in [Fault::Refuse, Fault::Fail, Fault::NotReady] {
        let host = faulty(new_store);
        let (mut store, _) = fresh(host.clone())?;
        host.arm(fault);
        ensure(
            add(&mut store, "conformance/one").is_err(),
            "a failed commit was acknowledged",
        )?;
        ensure(
            store.get("conformance/one@CONFORMANCE.TEST").is_none(),
            "memory kept the change",
        )?;
        ensure(
            !host_has(host.as_ref(), "conformance/one")?,
            "the host kept the change",
        )?;
        add(&mut store, "conformance/two").map_err(fail)?;
        ensure(
            host_has(host.as_ref(), "conformance/two")?,
            "the next commit was lost",
        )?;
    }
    Ok(())
}

fn unknown_outcome(new_store: NewStore<'_>) -> Result<(), String> {
    let host = faulty(new_store);
    let (mut store, _) = fresh(host.clone())?;
    host.arm(Fault::CommitThenFail);
    ensure(
        add(&mut store, "conformance/one").is_err(),
        "a failed commit was acknowledged",
    )?;
    ensure(
        store.get("conformance/one@CONFORMANCE.TEST").is_some(),
        "memory was not reloaded from the host",
    )
}

fn delete_and_rename(new_store: NewStore<'_>) -> Result<(), String> {
    let host = new_store();
    let (mut store, _) = fresh(Arc::clone(&host))?;
    add(&mut store, "conformance/one").map_err(fail)?;
    add(&mut store, "conformance/two").map_err(fail)?;
    store
        .change(|s| s.remove_in(&name("conformance/one"), REALM))
        .map_err(fail)?
        .map_err(fail)?;
    ensure(
        !host_has(host.as_ref(), "conformance/one")?,
        "a delete did not reach the host",
    )?;
    store
        .change(|s| {
            s.rename_unchecked(
                &name("conformance/two"),
                REALM,
                &name("conformance/three"),
                REALM,
                ACTOR,
            )
        })
        .map_err(fail)?
        .map_err(fail)?;
    ensure(
        host_has(host.as_ref(), "conformance/three")?
            && !host_has(host.as_ref(), "conformance/two")?,
        "a rename did not reach the host",
    )
}

fn policies(new_store: NewStore<'_>) -> Result<(), String> {
    let host = new_store();
    let (mut store, seal) = fresh(Arc::clone(&host))?;
    let mut pol = NamedPolicy::new("conformance");
    pol.history = 3;
    store.put_policy(pol.clone()).map_err(fail)?;
    pol.history = 5;
    store.put_policy(pol.clone()).map_err(fail)?;
    let loaded = host.load().map_err(fail)?;
    let held = loaded
        .policies
        .iter()
        .find(|p| p.name == "conformance")
        .ok_or("no policy row")?;
    ensure(
        open_policy(held, REALM, &seal).map_err(fail)? == pol,
        "a modify did not reach the host",
    )?;
    store.delete_policy("conformance").map_err(fail)?;
    ensure(
        host.load().map_err(fail)?.policies.is_empty(),
        "a delete did not reach the host",
    )
}

fn broken_seals(new_store: NewStore<'_>) -> Result<(), String> {
    let good = new_store();
    let (mut store, seal) = fresh(Arc::clone(&good))?;
    add(&mut store, "conformance/one").map_err(fail)?;
    add(&mut store, "conformance/two").map_err(fail)?;
    let loaded = good.load().map_err(fail)?;
    let record = |n: &str| {
        loaded
            .principals
            .iter()
            .find(|p| p.name == n)
            .map(|p| p.record.clone())
            .ok_or("no row")
    };
    let (one, two) = (record("conformance/one")?, record("conformance/two")?);
    let mut flipped = one.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    let mut other_mac = one.clone();
    other_mac[9..13].copy_from_slice(&15i32.to_be_bytes());
    for (what, bad) in [
        ("a flipped byte", flipped),
        ("a swapped record", two),
        ("a header naming another checksum", other_mac),
    ] {
        let host = new_store();
        let mut batch = RealmBatch {
            realm: loaded.realm.clone(),
            ..RealmBatch::default()
        };
        for p in &loaded.principals {
            let record = if p.name == "conformance/one" {
                bad.clone()
            } else {
                p.record.clone()
            };
            batch.upsert_principals.push(plain_row(&p.name, record));
        }
        host.commit_change(HostChange {
            intent: WriteIntent::new(Operation::Bootstrap, Caller::Embedder),
            rows: Vec::new(),
            prepared: None,
            batch,
        })
        .map_err(fail)?;
        let opened = PrincipalStore::open_host(host, REALM, seal.clone());
        ensure(
            matches!(opened, Err(Error::Record(_))),
            &format!("{what} was accepted"),
        )?;
    }
    Ok(())
}

fn plain_row(name: &str, record: Vec<u8>) -> PrincipalRow {
    PrincipalRow {
        name: name.to_owned(),
        record,
        has_keys: true,
        disabled: false,
        kvno: 1,
        expiration: None,
        password_expiration: None,
        policy: None,
        modified_date: 0,
        attributes: 0,
        alias_target: None,
    }
}

fn commits_once(new_store: NewStore<'_>) -> Result<(), String> {
    let host = new_store();
    let (mut store, _) = fresh(host)?;
    let calls = AtomicUsize::new(0);
    let count = |c: HostChange| {
        calls.fetch_add(1, Ordering::SeqCst);
        ensure(
            c.batch.is_empty() && c.rows.is_empty() && c.intent.operation == Operation::Embedded,
            "a change of nothing sent rows",
        )
        .map_err(KerberosStoreError::Failed)
    };
    store
        .change_committing(count, |_| Ok::<(), Error>(()))
        .map_err(fail)?
        .map_err(fail)?;
    ensure(
        calls.load(Ordering::SeqCst) == 1,
        "commit was not called once",
    )?;
    let never = |_: HostChange| -> Result<(), KerberosStoreError> {
        Err(KerberosStoreError::Failed(
            "called after a failed change".to_owned(),
        ))
    };
    let out = store.change_committing(never, |_| Err::<(), Error>(Error::NotFound));
    ensure(
        matches!(out, Ok(Err(Error::NotFound))),
        "commit ran after a failed change",
    )
}

fn outside_change(new_store: NewStore<'_>) -> Result<(), String> {
    let (mut store, _) = fresh(new_store())?;
    let out = store.insert_new_randkey(&name("conformance/one"), REALM, &[], ACTOR);
    ensure(out.is_err(), "a write outside a change was taken")?;
    ensure(
        store.get("conformance/one@CONFORMANCE.TEST").is_none(),
        "memory kept it",
    )
}

#[expect(clippy::panic, reason = "the row arms the store's panic guard")]
fn panics_restore(new_store: NewStore<'_>) -> Result<(), String> {
    let host = faulty(new_store);
    let (mut store, _) = fresh(host.clone())?;
    host.arm(Fault::Panic);
    ensure(
        matches!(
            add(&mut store, "conformance/one"),
            Err(Error::Host(KerberosStoreError::Failed(_)))
        ),
        "a panic in the commit was not a failed commit",
    )?;
    ensure(
        store.get("conformance/one@CONFORMANCE.TEST").is_none(),
        "memory kept a change whose commit panicked",
    )?;
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.change(|s| -> Result<(), Error> {
            s.insert_new_randkey(&name("conformance/two"), REALM, &[], ACTOR)?;
            panic!("conformance: the change panics")
        })
    }));
    ensure(panicked.is_err(), "the change's panic was swallowed")?;
    ensure(
        store.get("conformance/two@CONFORMANCE.TEST").is_none(),
        "memory kept a change that panicked",
    )?;
    add(&mut store, "conformance/three").map_err(fail)?;
    ensure(
        host_has(host.as_ref(), "conformance/three")?
            && !host_has(host.as_ref(), "conformance/two")?,
        "the host is not what memory says",
    )
}

fn with_history_policy(store: &mut PrincipalStore, who: &str) -> Result<(), String> {
    let mut pol = NamedPolicy::new("conformance");
    pol.history = 2;
    store.put_policy(pol).map_err(fail)?;
    add(store, who).map_err(fail)?;
    store
        .change(|s| {
            s.set_principal_policy_in(&name(who), REALM, Some("conformance".to_owned()), ACTOR)
        })
        .map_err(fail)?
        .map_err(fail)
}

fn set_password(store: &mut PrincipalStore, who: &str) -> Result<(), Error> {
    store.change(|s| s.set_password_keepold_n_in(&name(who), REALM, b"conformance-pw", 0, ACTOR))?
}

fn history_in_the_change(new_store: NewStore<'_>) -> Result<(), String> {
    let host = faulty(new_store);
    let (mut store, _) = fresh(host.clone())?;
    with_history_policy(&mut store, "conformance/one")?;
    host.commits();
    set_password(&mut store, "conformance/one").map_err(fail)?;
    let commits = host.commits();
    ensure(
        commits.len() == 1,
        "the password change took more than one commit",
    )?;
    ensure(
        commits[0].iter().any(|n| n == "kadmin/history")
            && commits[0].iter().any(|n| n == "conformance/one"),
        "kadmin/history and the password were not in one commit",
    )
}

fn history_rolls_back(new_store: NewStore<'_>) -> Result<(), String> {
    let host = faulty(new_store);
    let (mut store, _) = fresh(host.clone())?;
    with_history_policy(&mut store, "conformance/one")?;
    host.arm(Fault::Refuse);
    ensure(
        set_password(&mut store, "conformance/one").is_err(),
        "a refused change was acknowledged",
    )?;
    ensure(
        store.get("kadmin/history@CONFORMANCE.TEST").is_none()
            && !host_has(host.as_ref(), "kadmin/history")?,
        "a refused change left kadmin/history",
    )
}

fn the_row(seen: &[Seen], id: &str) -> Option<(u32, bool)> {
    let (_, _, rows) = seen.last()?;
    rows.iter()
        .find(|(rid, _, _)| rid == id)
        .map(|(_, mask, owned)| (*mask, *owned))
}

fn rows_and_masks(new_store: NewStore<'_>) -> Result<(), String> {
    use crate::store::kadm5_mask as m;
    let host = faulty(new_store);
    let (mut store, _) = fresh(host.clone())?;
    host.seen();
    add(&mut store, "conformance/one").map_err(fail)?;
    let one = "conformance/one@CONFORMANCE.TEST";
    let seen = host.seen();
    ensure(
        seen.last().is_some_and(|s| s.0 == Operation::Unspecified),
        "an undeclared change did not say Unspecified",
    )?;
    ensure(
        the_row(&seen, one).is_some_and(|(mask, _)| mask == m::PRINCIPAL),
        "a create's row is not PRINCIPAL",
    )?;
    store
        .change(|s| {
            s.apply_admin_fields_in(
                &name("conformance/one"),
                REALM,
                crate::store::AdminFields {
                    max_life: Some(4321),
                    ..crate::store::AdminFields::default()
                },
                ACTOR,
            )
        })
        .map_err(fail)?
        .map_err(fail)?;
    let mask = the_row(&host.seen(), one).ok_or("no row for a modify")?.0;
    ensure(
        mask & m::MAX_LIFE != 0 && mask & !(m::MAX_LIFE | m::MOD_TIME | m::MOD_NAME) == 0,
        &format!("a max-life modify showed mask {mask:#x}"),
    )?;
    store
        .change(|s| s.remove_in(&name("conformance/one"), REALM))
        .map_err(fail)?
        .map_err(fail)?;
    ensure(
        the_row(&host.seen(), one).is_some_and(|(mask, _)| mask == m::PRINCIPAL),
        "a delete's row is not PRINCIPAL",
    )
}

fn declared_intent(new_store: NewStore<'_>) -> Result<(), String> {
    let host = faulty(new_store);
    let (mut store, _) = fresh(host.clone())?;
    host.seen();
    let caller = Caller::Local {
        principal: ACTOR.to_owned(),
    };
    store
        .change_as(
            WriteIntent::new(Operation::Create, caller.clone()),
            None,
            |s| s.insert_new_randkey(&name("conformance/one"), REALM, &[], ACTOR),
        )
        .map_err(fail)?
        .map_err(fail)?;
    ensure(
        host.seen()
            .last()
            .is_some_and(|s| s.0 == Operation::Create && s.1 == caller),
        "the declared operation and caller did not reach the host",
    )?;
    store
        .change_as(WriteIntent::new(Operation::Modify, caller), None, |_| {
            Ok::<(), Error>(())
        })
        .map_err(fail)?
        .map_err(fail)?;
    ensure(
        host.seen().is_empty(),
        "a change that touched nothing reached the host",
    )
}

fn denied_restores(new_store: NewStore<'_>) -> Result<(), String> {
    let host = faulty(new_store);
    let (mut store, _) = fresh(host.clone())?;
    host.arm(Fault::Deny);
    let out = add(&mut store, "conformance/one");
    ensure(
        matches!(
            out,
            Err(Error::Host(KerberosStoreError::Denied(super::Denial { kadm5_code, .. })))
                if kadm5_code == DENIED_CODE
        ),
        "a denial did not come back with its code",
    )?;
    ensure(
        store.get("conformance/one@CONFORMANCE.TEST").is_none(),
        "memory kept a denied change",
    )?;
    add(&mut store, "conformance/two").map_err(fail)?;
    ensure(
        host_has(host.as_ref(), "conformance/two")?,
        "the next commit was lost",
    )
}

fn host_mark(new_store: NewStore<'_>) -> Result<(), String> {
    let host = faulty(new_store);
    let (mut store, seal) = fresh(host.clone())?;
    let who = name("conformance/one");
    ensure(
        store.set_host_owned_in(&who, REALM, true).is_err(),
        "the mark was set outside a change",
    )?;
    let committer = Arc::clone(&host);
    store
        .change_committing(
            |c| committer.commit_change(c),
            |s| {
                s.insert_new_randkey(&who, REALM, &[], ACTOR)?;
                s.set_host_owned_in(&who, REALM, true)
            },
        )
        .map_err(fail)?
        .map_err(fail)?;
    let seen = host.seen();
    ensure(
        seen.last().is_some_and(|s| s.0 == Operation::Embedded)
            && the_row(&seen, "conformance/one@CONFORMANCE.TEST").is_some_and(|(_, o)| o),
        "the host's change did not show the mark",
    )?;
    let again = PrincipalStore::open_host(host, REALM, seal).map_err(fail)?;
    ensure(
        again
            .get("conformance/one@CONFORMANCE.TEST")
            .is_some_and(crate::store::Principal::host_owned),
        "the mark did not survive a reload",
    )
}

fn no_lockout_bits(new_store: NewStore<'_>) -> Result<(), String> {
    use crate::store::kadm5_mask as m;
    let host = faulty(new_store);
    let (mut store, _) = fresh(host.clone())?;
    add(&mut store, "conformance/one").map_err(fail)?;
    host.seen();
    store
        .change(|s| s.clear_fail_auth_count_in(&name("conformance/one"), REALM, ACTOR))
        .map_err(fail)?
        .map_err(fail)?;
    let mask = the_row(&host.seen(), "conformance/one@CONFORMANCE.TEST")
        .ok_or("an unlock sent no row")?
        .0;
    ensure(
        mask & (m::FAIL_AUTH_COUNT | m::LAST_SUCCESS | m::LAST_FAILED) == 0,
        &format!("an unlock's row mask {mask:#x} has a lockout bit"),
    )
}
