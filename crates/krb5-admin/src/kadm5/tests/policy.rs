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
        g.set_last_pwd_unix(&user, 1).unwrap();
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
