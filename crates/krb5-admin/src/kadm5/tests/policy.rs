//! kadm5 policy tests (private-bound; regrouped in place).

use super::*;

#[test]
fn policy_min_max_life_round_trip_and_min_life() {
    let (store, acl, actor) = setup();
    let mut pol = krb5_kdc::NamedPolicy::new("life");
    pol.pw_min_life = 3600;
    pol.pw_max_life = 86400;
    let mask = KADM5_POLICY | KADM5_PW_MIN_LIFE | KADM5_PW_MAX_LIFE;
    let created = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_POLICY,
        &encode_cpol(API_V2, &pol, mask),
    )
    .unwrap();
    assert_eq!(ret_code(&created), 0);
    let mut gq = XdrW::default();
    gq.u32(API_V2);
    gq.nullstring(Some("life"));
    let got = dispatch_kadm5(&store, &acl, &actor, GET_POLICY, &gq.b).unwrap();
    assert_eq!(ret_code(&got), 0);
    let mut r = XdrR::new(&got);
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.nullstring().unwrap().as_deref(), Some("life"));
    assert_eq!(r.u32().unwrap(), 3600);
    assert_eq!(r.u32().unwrap(), 86400);
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    {
        let mut g = store.write().unwrap();
        g.set_principal_policy(&user, Some("life".into())).unwrap();
        assert!(g.get_name(&user).unwrap().pw_expire > 0);
        g.set_last_pwd_unix(&user, 1);
    }
    let once = dispatch_kadm5(
        &store,
        &acl,
        "user@KERBER.TEST",
        CHPASS_PRINCIPAL,
        &chpass_args("user@KERBER.TEST", "user-rotated"),
    )
    .unwrap();
    assert_eq!(ret_code(&once), 0);
    let twice = dispatch_kadm5(
        &store,
        &acl,
        "user@KERBER.TEST",
        CHPASS_PRINCIPAL,
        &chpass_args("user@KERBER.TEST", "user-rotated2"),
    )
    .unwrap();
    assert_eq!(ret_code(&twice), KADM5_PASS_TOOSOON);
    let admin = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CHPASS_PRINCIPAL,
        &chpass_args("user@KERBER.TEST", "admin-rotated"),
    )
    .unwrap();
    assert_eq!(ret_code(&admin), 0);
}

#[test]
fn min_life_requires_pwchange_bypasses() {
    let (store, acl, _actor) = setup();
    let mut pol = krb5_kdc::NamedPolicy::new("soon");
    pol.pw_min_life = 3600;
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    {
        let mut g = store.write().unwrap();
        g.put_policy(pol);
        g.set_principal_policy(&user, Some("soon".into())).unwrap();
        g.set_password(&user, b"need-change").unwrap();
        g.apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(krb5_kdc::KDB_REQUIRES_PWCHANGE),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let out = dispatch_kadm5(
        &store,
        &acl,
        "user@KERBER.TEST",
        CHPASS_PRINCIPAL,
        &chpass_args("user@KERBER.TEST", "changed-now"),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0);
}

#[test]
fn create_policy_min_life_without_max_is_ok() {
    let (store, acl, actor) = setup();
    let mut pol = krb5_kdc::NamedPolicy::new("minonly");
    pol.pw_min_life = 3600;
    pol.pw_max_life = 1;
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_POLICY,
        &encode_cpol(API_V2, &pol, KADM5_POLICY | KADM5_PW_MIN_LIFE),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0);
}

#[test]
fn create_policy_dup_checked_before_name() {
    let (store, acl, actor) = setup();
    let pol = krb5_kdc::NamedPolicy::new("bad\u{1}name");
    store.write().unwrap().put_policy(pol.clone());
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_POLICY,
        &encode_cpol(API_V2, &pol, KADM5_POLICY),
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_DUP);
}

#[test]
fn create_policy_unspecified_floors_and_zero_history_is_bad() {
    let (store, acl, actor) = setup();
    let empty = krb5_kdc::NamedPolicy::new("floors");
    let created = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_POLICY,
        &encode_cpol(API_V2, &empty, KADM5_POLICY),
    )
    .unwrap();
    assert_eq!(ret_code(&created), 0);
    let g = store.read().unwrap();
    let p = g.policies().get("floors").unwrap();
    assert_eq!(p.min_length, 1);
    assert_eq!(p.min_classes, 1);
    assert_eq!(p.history, 1);
    drop(g);
    let zhist = krb5_kdc::NamedPolicy {
        name: "zhist".into(),
        min_length: 1,
        min_classes: 1,
        history: 0,
        max_fail: 0,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
        pw_min_life: 0,
        pw_max_life: 0,
        allowed_keysalts: None,
    };
    let bad = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_POLICY,
        &encode_cpol(API_V2, &zhist, KADM5_POLICY | KADM5_PW_HISTORY_NUM),
    )
    .unwrap();
    assert_eq!(ret_code(&bad), KADM5_BAD_HISTORY);
}

#[test]
fn modify_policy_below_floor_is_bad_length() {
    let code = modify_policy_floor_code(KADM5_PW_MIN_LENGTH, |p| p.min_length = 0);
    assert_eq!(code, KADM5_BAD_LENGTH);
}

#[test]
fn modify_policy_below_floor_is_bad_class() {
    let code = modify_policy_floor_code(KADM5_PW_MIN_CLASSES, |p| p.min_classes = 0);
    assert_eq!(code, KADM5_BAD_CLASS);
}

#[test]
fn modify_policy_below_floor_is_bad_history() {
    let code = modify_policy_floor_code(KADM5_PW_HISTORY_NUM, |p| p.history = 0);
    assert_eq!(code, KADM5_BAD_HISTORY);
}

#[test]
fn modify_policy_min_life_over_merged_max_is_bad_min_pass_life() {
    let (store, acl, actor) = setup();
    let mut pol = krb5_kdc::NamedPolicy::new("life");
    pol.pw_max_life = 86_400;
    assert_eq!(
        ret_code(
            &dispatch_kadm5(
                &store,
                &acl,
                &actor,
                CREATE_POLICY,
                &encode_cpol(API_V2, &pol, KADM5_POLICY | KADM5_PW_MAX_LIFE),
            )
            .unwrap()
        ),
        0
    );
    pol.pw_min_life = 172_800;
    let bad = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        MODIFY_POLICY,
        &encode_cpol(API_V2, &pol, KADM5_PW_MIN_LIFE),
    )
    .unwrap();
    assert_eq!(ret_code(&bad), KADM5_BAD_MIN_PASS_LIFE);
}

#[test]
fn create_policy_dup_before_floors() {
    let (store, acl, actor) = setup();
    let pol = krb5_kdc::NamedPolicy::new("dup");
    assert_eq!(
        ret_code(
            &dispatch_kadm5(
                &store,
                &acl,
                &actor,
                CREATE_POLICY,
                &encode_cpol(API_V2, &pol, KADM5_POLICY),
            )
            .unwrap()
        ),
        0
    );
    let mut z = pol.clone();
    z.history = 0;
    let dup = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_POLICY,
        &encode_cpol(API_V2, &z, KADM5_POLICY | KADM5_PW_HISTORY_NUM),
    )
    .unwrap();
    assert_eq!(ret_code(&dup), KADM5_DUP);
}

#[test]
fn kadm5_policy_verbs_and_pwqual() {
    let (store, acl, actor) = setup();
    let pol = krb5_kdc::NamedPolicy {
        name: "strict".into(),
        min_length: 8,
        min_classes: 2,
        history: 0,
        max_fail: 2,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
        pw_min_life: 0,
        pw_max_life: 0,
        allowed_keysalts: None,
    };
    let mask = KADM5_POLICY | KADM5_PW_MIN_LENGTH | KADM5_PW_MIN_CLASSES | KADM5_PW_MAX_FAILURE;
    let created = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_POLICY,
        &encode_cpol(API_V4, &pol, mask),
    )
    .unwrap();
    assert_eq!(ret_code(&created), 0);

    let dup = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_POLICY,
        &encode_cpol(API_V4, &pol, mask),
    )
    .unwrap();
    assert_eq!(ret_code(&dup), KADM5_DUP);

    let mut gq = XdrW::default();
    gq.u32(API_V4);
    gq.nullstring(Some("strict"));
    let got = dispatch_kadm5(&store, &acl, &actor, GET_POLICY, &gq.b).unwrap();
    assert_eq!(ret_code(&got), 0);
    let mut r = XdrR::new(&got);
    assert_eq!(r.u32().unwrap(), API_V4);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.nullstring().unwrap().as_deref(), Some("strict"));
    r.u32().unwrap();
    r.u32().unwrap();
    assert_eq!(r.u32().unwrap(), 8);
    assert_eq!(r.u32().unwrap(), 2);
    r.u32().unwrap();
    r.u32().unwrap();
    assert_eq!(r.u32().unwrap(), 2);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.u32().unwrap(), 0);

    let mut list_args = XdrW::default();
    list_args.u32(API_V4);
    list_args.u32(0);
    let listed = dispatch_kadm5(&store, &acl, &actor, GET_POLS, &list_args.b).unwrap();
    assert_eq!(ret_code(&listed), 0);
    let mut lr = XdrR::new(&listed);
    let _ = lr.u32().unwrap();
    let _ = lr.u32().unwrap();
    let n = lr.u32().unwrap();
    assert_eq!(lr.u32().unwrap(), n);
    let mut names = Vec::new();
    for _ in 0..n {
        names.push(lr.nullstring().unwrap().unwrap());
    }
    assert!(names.iter().any(|s| s == "strict"));

    let mut shorter = pol.clone();
    shorter.min_length = 10;
    let mod_mask = KADM5_PW_MIN_LENGTH;
    let modified = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        MODIFY_POLICY,
        &encode_cpol(API_V4, &shorter, mod_mask),
    )
    .unwrap();
    assert_eq!(ret_code(&modified), 0);
    {
        let g = store.read().unwrap();
        let p = g.policies().get("strict").unwrap();
        assert_eq!(p.min_length, 10);
        assert_eq!(p.max_fail, 2, "modpol must not zero unmasked fields");
    }
    let mut timed = pol.clone();
    timed.pw_failcnt_interval = 30;
    timed.pw_lockout_duration = 60;
    let tmask = KADM5_PW_FAILURE_COUNT_INTERVAL | KADM5_PW_LOCKOUT_DURATION;
    let tmod = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        MODIFY_POLICY,
        &encode_cpol(API_V4, &timed, tmask),
    )
    .unwrap();
    assert_eq!(ret_code(&tmod), 0);
    {
        let g = store.read().unwrap();
        let p = g.policies().get("strict").unwrap();
        assert_eq!(p.pw_failcnt_interval, 30);
        assert_eq!(p.pw_lockout_duration, 60);
        assert_eq!(p.min_length, 10);
    }

    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    {
        let mut g = store.write().unwrap();
        g.set_principal_policy(&user, Some("strict".into()))
            .unwrap();
    }
    let mut chpw = XdrW::default();
    chpw.u32(API_V2);
    chpw.nullstring(Some("user@KERBER.TEST"));
    chpw.nullstring(Some("short"));
    let rejected = dispatch_kadm5(&store, &acl, &actor, CHPASS_PRINCIPAL, &chpw.b).unwrap();
    assert_eq!(ret_code(&rejected), KADM5_PASS_Q_TOOSHORT);

    let mut del = XdrW::default();
    del.u32(API_V4);
    del.nullstring(Some("strict"));
    let deleted = dispatch_kadm5(&store, &acl, &actor, DELETE_POLICY, &del.b).unwrap();
    assert_eq!(ret_code(&deleted), 0);
    let missing = dispatch_kadm5(&store, &acl, &actor, GET_POLICY, &gq.b).unwrap();
    assert_eq!(ret_code(&missing), KADM5_UNK_POLICY);
}
