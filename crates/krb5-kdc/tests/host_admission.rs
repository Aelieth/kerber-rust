//! The host's verdicts and notices for the principals it owns.

#[path = "common/mod.rs"]
mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use krb5_asn1::{decode, encode};
use krb5_kdc::admission::{
    AsNotice, AsQuestion, AsReason, HostAdmission, KdcRefusal, Mechanism, TgsKind, TgsQuestion,
};
use krb5_kdc::host::{KerberosStore, MemoryRealm};
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented,
};
use krb5_kdc::{Error, KdcPolicy, PolicyAdjustment, Principal, PrincipalRead, PrincipalStore};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_testkit::{TgsReqBuilder, password_key, user};
use krb5_types::{KdcOptions, KrbError, PrincipalName, err, flag_bit};

#[derive(Default)]
struct Host {
    refuse_as: AtomicBool,
    refuse_text: Mutex<Option<String>>,
    refuse_tgs: AtomicBool,
    notices: Mutex<Vec<AsNotice>>,
    tgs: Mutex<Vec<(TgsKind, bool)>>,
    read_failed: AtomicBool,
    subjects: Mutex<Vec<(TgsKind, String, Option<String>)>>,
    deny_subject: Mutex<Option<String>>,
}

impl HostAdmission for Host {
    fn check_as(&self, _q: &AsQuestion<'_>) -> Result<(), KdcRefusal> {
        if self.refuse_as.load(Ordering::SeqCst) {
            return Err(KdcRefusal {
                code: err::CLIENT_REVOKED,
                e_text: self.refuse_text.lock().unwrap().clone(),
            });
        }
        Ok(())
    }

    fn as_notice(&self, n: AsNotice) {
        self.notices.lock().unwrap().push(n);
    }

    fn check_tgs(&self, q: &TgsQuestion<'_>) -> Result<(), KdcRefusal> {
        if matches!(q.client, krb5_kdc::admission::TgsClient::ReadFailed) {
            self.read_failed.store(true, Ordering::SeqCst);
        }
        let found = q.client.principal().is_some();
        self.tgs.lock().unwrap().push((q.kind, found));
        let client = q.client.principal().map(Principal::id);
        let subject = q.subject.components_joined_lossy();
        let denied = self.deny_subject.lock().unwrap().as_ref() == Some(&subject);
        self.subjects
            .lock()
            .unwrap()
            .push((q.kind, subject, client));
        if denied || self.refuse_tgs.load(Ordering::SeqCst) {
            return Err(KdcRefusal {
                code: err::CLIENT_REVOKED,
                e_text: None,
            });
        }
        Ok(())
    }
}

impl Host {
    fn notices(&self) -> Vec<(AsReason, Option<Mechanism>, i32)> {
        std::mem::take(&mut *self.notices.lock().unwrap())
            .into_iter()
            .map(|n| (n.reason, n.mechanism, n.code))
            .collect()
    }
}

/// The documented realm on a host store, its user marked as the host's.
fn marked(module: Option<Arc<Host>>) -> PrincipalStore {
    marked_with(module, |_| Ok(()))
}

fn marked_with(
    module: Option<Arc<Host>>,
    edit: impl FnOnce(&mut PrincipalStore) -> Result<(), Error>,
) -> PrincipalStore {
    let (mut built, _) = bootstrap_documented().unwrap();
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
    let host = Arc::new(MemoryRealm::default());
    host.commit(built.host_full_batch().unwrap()).unwrap();
    let seal = built.host_seal_key().unwrap();
    let mut store = PrincipalStore::open_host(
        Arc::clone(&host) as Arc<dyn KerberosStore>,
        TEST_REALM,
        seal,
    )
    .unwrap();
    store.policy = built.policy.clone();
    store
        .change_committing(
            |c| host.commit_change(c),
            |s| {
                s.set_host_owned_in(&user(), TEST_REALM, true)?;
                edit(s)
            },
        )
        .unwrap()
        .unwrap();
    if let Some(m) = module {
        store.policy.plugins.set_host_admission(m);
    }
    store
}

fn as_error(store: &PrincipalStore, nonce: u32, password: Option<&[u8]>) -> Option<KrbError> {
    let padata = password.map(|pw| vec![pa_enc_timestamp(&password_key(TEST_USER, pw)).unwrap()]);
    let raw = encode(&as_req(user(), TEST_REALM, nonce, padata).unwrap()).unwrap();
    let reply = krb5_kdc::handle_request(store, &raw).unwrap();
    decode::<KrbError>(&reply).ok()
}

fn as_code(store: &PrincipalStore, nonce: u32, password: Option<&[u8]>) -> i32 {
    as_error(store, nonce, password).map_or(0, |e| e.error_code)
}

#[test]
fn the_as_verdict_comes_before_preauth_and_reveals_nothing() {
    let module = Arc::new(Host::default());
    let store = marked(Some(Arc::clone(&module)));
    module.refuse_as.store(true, Ordering::SeqCst);
    assert_eq!(as_code(&store, 1, None), err::CLIENT_REVOKED);
    assert_eq!(
        as_code(&store, 2, Some(TEST_USER_PASSWORD)),
        err::CLIENT_REVOKED
    );
    assert_eq!(as_code(&store, 3, Some(b"wrong")), err::CLIENT_REVOKED);
    assert!(
        module
            .notices()
            .iter()
            .all(|(reason, _, _)| *reason == AsReason::HostRefused)
    );
    let e_text = |pw: &[u8]| as_error(&store, 4, Some(pw)).and_then(|e| e.e_text);
    assert_eq!(e_text(TEST_USER_PASSWORD), None);
    assert_eq!(e_text(b"wrong"), None);
    *module.refuse_text.lock().unwrap() = Some("outside your hours".to_owned());
    let text = |pw: &[u8]| e_text(pw).map(|t| String::from_utf8_lossy(t.as_bytes()).into_owned());
    assert_eq!(
        text(TEST_USER_PASSWORD).as_deref(),
        Some("outside your hours")
    );
    assert_eq!(text(b"wrong").as_deref(), Some("outside your hours"));
}

struct Deny;

impl KdcPolicy for Deny {
    fn check_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Err(Error::Protocol {
            code: err::POLICY,
            text: None,
            e_data: None,
            detail: None,
        })
    }
    fn check_tgs(
        &self,
        _store: &dyn PrincipalRead,
        _sname: &PrincipalName,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Ok(PolicyAdjustment::default())
    }
}

#[test]
fn notices_tell_a_right_a_wrong_and_a_refused_password_apart() {
    let module = Arc::new(Host::default());
    let mut store = marked(Some(Arc::clone(&module)));
    let id = format!("{TEST_USER}@{TEST_REALM}");
    assert_eq!(as_code(&store, 1, None), err::PREAUTH_REQUIRED);
    assert_eq!(as_code(&store, 2, Some(TEST_USER_PASSWORD)), 0);
    assert_eq!(as_code(&store, 3, Some(b"wrong")), err::PREAUTH_FAILED);
    store.policy.plugins.set_policy(Arc::new(Deny));
    assert_eq!(as_code(&store, 4, Some(TEST_USER_PASSWORD)), err::POLICY);
    let ts = Some(Mechanism::EncTimestamp);
    assert_eq!(
        module.notices(),
        [
            (AsReason::Issued, ts, 0),
            (AsReason::PreauthFailed, ts, err::PREAUTH_FAILED),
            (AsReason::PolicyRefused, ts, err::POLICY),
        ]
    );
    assert_eq!(store.fetch(&id).unwrap().unwrap().fail_auth_count, 0);
}

#[test]
fn a_marked_principal_with_no_module_is_refused() {
    let store = marked(None);
    assert_eq!(
        as_code(&store, 1, Some(TEST_USER_PASSWORD)),
        err::CLIENT_REVOKED
    );
}

fn tgs_code(store: &dyn PrincipalRead, issued: &krb5_kdc::IssuedAs, sname: PrincipalName) -> i32 {
    let options = if sname == PrincipalName::krbtgt(TEST_REALM) {
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true)
    } else {
        KdcOptions::forwardable()
    };
    let req = TgsReqBuilder::new(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &user(),
        sname,
        TEST_REALM,
        7,
    )
    .options(options)
    .build()
    .unwrap();
    krb5_kdc::issue_tgs(store, &req).map_or_else(
        |e| match e {
            Error::Protocol { code, .. } => code,
            _ => -1,
        },
        |_| 0,
    )
}

fn unreadable(store: &PrincipalStore) -> common::Faulty<'_> {
    common::Faulty {
        inner: store,
        fail_id: String::new(),
        fail_client: true,
        fault: || Error::InvalidArgument("backend: disk read failed".into()),
    }
}

#[test]
fn a_tgs_client_read_failure_reaches_the_host_and_goes_on_without_one() {
    let service = krb5_kdc::testrealm::documented_host();
    let module = Arc::new(Host::default());
    let store = marked(Some(Arc::clone(&module)));
    let issued = krb5_testkit::issue_tgt_renewable(&store, TEST_USER, 9, true);
    assert_eq!(tgs_code(&unreadable(&store), &issued, service.clone()), 0);
    assert!(module.read_failed.load(Ordering::SeqCst));
    let (store, _) = bootstrap_documented().unwrap();
    let issued = krb5_testkit::issue_tgt_renewable(&store, TEST_USER, 9, true);
    assert_eq!(tgs_code(&unreadable(&store), &issued, service), 0);
}

#[test]
fn a_client_the_host_locks_gets_no_renewal_and_no_service_ticket() {
    let module = Arc::new(Host::default());
    let store = marked(Some(Arc::clone(&module)));
    let issued = krb5_testkit::issue_tgt_renewable(&store, TEST_USER, 9, true);
    let service = krb5_kdc::testrealm::documented_host();
    assert_eq!(tgs_code(&store, &issued, service.clone()), 0);
    module.refuse_tgs.store(true, Ordering::SeqCst);
    assert_eq!(
        tgs_code(&store, &issued, PrincipalName::krbtgt(TEST_REALM)),
        err::CLIENT_REVOKED
    );
    assert_eq!(tgs_code(&store, &issued, service), err::CLIENT_REVOKED);
    let kinds = module.tgs.lock().unwrap().clone();
    assert_eq!(
        kinds,
        [
            (TgsKind::Normal, true),
            (TgsKind::Renew, true),
            (TgsKind::Normal, true),
        ]
    );
}

#[test]
fn with_its_module_gone_a_marked_client_gets_no_service_ticket() {
    let service = krb5_kdc::testrealm::documented_host();
    let target = service.clone();
    let mut store = marked_with(None, |s| {
        let fields = krb5_kdc::AdminFields {
            attributes: Some(krb5_kdc::KDB_NO_AUTH_DATA_REQUIRED),
            ..Default::default()
        };
        let m = krb5_kdc::ModifyPrincipal {
            mask: 0x10,
            fields,
            kvno: None,
            tl_data: Vec::new(),
            zero_fail_count: false,
        };
        s.modify_principal_in(&target, TEST_REALM, m, "test")
    });
    let bare = store.policy.plugins.clone();
    store
        .policy
        .plugins
        .set_host_admission(Arc::new(Host::default()));
    let issued = krb5_testkit::issue_tgt_renewable(&store, TEST_USER, 9, true);
    store.policy.plugins = bare;
    assert_eq!(tgs_code(&store, &issued, service), err::CLIENT_REVOKED);
}

#[test]
fn an_s4u2self_check_names_the_user_not_the_service() {
    let module = Arc::new(Host::default());
    let store = marked(Some(Arc::clone(&module)));
    let tgt = krb5_testkit::host_tgt(&store, 7301);
    let pa = krb5_protocol::pa_for_user(&tgt.session_key, user(), TEST_REALM).unwrap();
    krb5_kdc::issue_tgs(&store, &krb5_testkit::s4u_self(&tgt, vec![pa], 7302)).unwrap();
    assert_eq!(
        *module.subjects.lock().unwrap(),
        [(
            TgsKind::S4u2Self,
            TEST_USER.to_owned(),
            Some(format!("{TEST_USER}@{TEST_REALM}"))
        )]
    );
}

#[test]
fn the_host_decides_an_s4u2self_on_the_user_not_the_service() {
    let module = Arc::new(Host::default());
    *module.deny_subject.lock().unwrap() = Some(TEST_USER.to_owned());
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let store = marked_with(Some(Arc::clone(&module)), |s| {
        s.set_host_owned_in(&admin, TEST_REALM, true)
    });
    let tgt = krb5_testkit::host_tgt(&store, 7321);
    let pa = krb5_protocol::pa_for_user(&tgt.session_key, user(), TEST_REALM).unwrap();
    let out = krb5_kdc::issue_tgs(&store, &krb5_testkit::s4u_self(&tgt, vec![pa], 7322));
    let code = krb5_testkit::expect_status(out.expect_err("issued")).0;
    assert_eq!(code, err::CLIENT_REVOKED);
    let allowed = krb5_testkit::s4u_admin(&tgt, 7323, KdcOptions::forwardable());
    krb5_kdc::issue_tgs(&store, &allowed).unwrap();
    let asked: Vec<_> = module
        .subjects
        .lock()
        .unwrap()
        .iter()
        .map(|(k, s, _)| (*k, s.clone()))
        .collect();
    assert_eq!(
        asked,
        [
            (TgsKind::S4u2Self, TEST_USER.to_owned()),
            (TgsKind::S4u2Self, TEST_ADMIN.to_owned())
        ]
    );
}
