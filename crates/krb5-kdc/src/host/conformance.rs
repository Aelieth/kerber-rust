//! Rows a host runs against its own store; names hold a `/`, so none binds a user.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use krb5_config::{Krb5Conf, ProfileSet};
use krb5_types::PrincipalName;

use super::{
    KerberosStore, KerberosStoreError, LoadedRealm, PrincipalRow, RealmBatch, SealKey, open_policy,
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
    let rows: [(&'static str, Check); 8] = [
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
    host.commit(built.host_full_batch().map_err(fail)?)
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
}

struct Faulty {
    inner: Arc<dyn KerberosStore>,
    next: Mutex<Option<Fault>>,
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

    fn commit(&self, batch: RealmBatch) -> Result<(), KerberosStoreError> {
        let fault = self
            .next
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        match fault {
            None => self.inner.commit(batch),
            Some(Fault::Refuse) => Err(KerberosStoreError::Refused("conformance".to_owned())),
            Some(Fault::Fail) => Err(KerberosStoreError::Failed("conformance".to_owned())),
            Some(Fault::NotReady) => Err(KerberosStoreError::NotReady("conformance".to_owned())),
            Some(Fault::CommitThenFail) => {
                self.inner.commit(batch)?;
                Err(KerberosStoreError::Failed("conformance".to_owned()))
            }
        }
    }
}

fn faulty(new_store: NewStore<'_>) -> Arc<Faulty> {
    Arc::new(Faulty {
        inner: new_store(),
        next: Mutex::new(None),
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
        host.commit(batch).map_err(fail)?;
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
    let count = |b: RealmBatch| {
        calls.fetch_add(1, Ordering::SeqCst);
        ensure(b.is_empty(), "a change of nothing sent rows").map_err(KerberosStoreError::Failed)
    };
    store
        .change_committing(count, |_| Ok::<(), Error>(()))
        .map_err(fail)?
        .map_err(fail)?;
    ensure(
        calls.load(Ordering::SeqCst) == 1,
        "commit was not called once",
    )?;
    let never = |_: RealmBatch| -> Result<(), KerberosStoreError> {
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
