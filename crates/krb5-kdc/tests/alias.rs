//! Principal aliases like MIT 1.22.2: `kadm5_create_alias` (`svr_principal.c:2051-2087`),
//! `krb5_dbe_make_alias_entry` / `krb5_dbe_read_alias` (`kdb5.c:2826-2895`),
//! `krb5_db_get_principal` resolution (`kdb5.c:800-840`), the AS cname decision
//! (`do_as_req.c:681-687`) and the TGS requested sname (`do_tgs_req.c:1029`).
//! Texts and the dump line were settled live in
//! `working/logs/audit-polish-0902/w1k/m3a-settle-mit-alias.log`.

use krb5_asn1::decode;
use krb5_kdc::{
    Error, KDB_DISALLOW_ALL_TIX, KDB_REQUIRES_PRE_AUTH, MAX_ALIAS_DEPTH, PrincipalStore,
    TEST_REALM, TEST_USER, TL_ALIAS_TARGET, bootstrap_documented, decrypt_ticket_part,
    documented_host, dump_store, issue_as, issue_tgs, load_dump,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};
use krb5_types::{EtypeInfo2, PrincipalName, flag_bit, pa};

const MASTER_PASSWORD: &[u8] = b"masterpassword";

fn name(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn id(s: &str) -> String {
    format!("{s}@{TEST_REALM}")
}

fn store_with_alias(alias: &str, target: &str) -> PrincipalStore {
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .create_alias_in(&name(alias), TEST_REALM, &name(target), TEST_REALM)
        .unwrap();
    store
}

#[test]
fn alias_stub_shape_matches_make_alias_entry_and_lookups_resolve() {
    let store = store_with_alias("a1", TEST_USER);
    let stub = store.get_raw(&id("a1")).unwrap();
    assert!(stub.keys.is_empty());
    assert_eq!(stub.attributes, KDB_DISALLOW_ALL_TIX);
    assert_eq!(stub.rid, 0);
    assert_eq!(stub.alias_target().as_deref(), Some("user@KERBER.TEST"));
    let types: Vec<i32> = stub.tl_data.iter().map(|t| t.ty).collect();
    assert_eq!(types, vec![3, 2, TL_ALIAS_TARGET]);
    assert_eq!(stub.tl_data[0].contents.len(), 24);
    assert_eq!(&stub.tl_data[0].contents[..4], &[0x12, 0x34, 0x5c, 0x01]);
    assert_eq!(stub.tl_data[2].contents, b"user@KERBER.TEST\0");
    let resolved = store.get(&id("a1")).unwrap();
    assert_eq!(resolved.id(), id(TEST_USER));
    assert_eq!(store.get_name(&name("a1")).unwrap().id(), id(TEST_USER));
    assert!(store.ids().contains(&id("a1")));
}

#[test]
fn alias_chain_of_ten_resolves_eleven_and_self_do_not() {
    let mut store = store_with_alias("a1", TEST_USER);
    for i in 2..=MAX_ALIAS_DEPTH + 1 {
        store
            .create_alias_in(
                &name(&format!("a{i}")),
                TEST_REALM,
                &name(&format!("a{}", i - 1)),
                TEST_REALM,
            )
            .unwrap();
    }
    assert_eq!(
        store.get(&id("a10")).map(krb5_kdc::Principal::id),
        Some(id(TEST_USER))
    );
    assert!(store.get(&id("a11")).is_none());
    store
        .create_alias_in(
            &name("selfalias"),
            TEST_REALM,
            &name("selfalias"),
            TEST_REALM,
        )
        .unwrap();
    assert!(store.get(&id("selfalias")).is_none());
    assert!(store.get_raw(&id("selfalias")).is_some());
}

#[test]
fn dup_realm_and_rename_refusals_carry_mit_texts() {
    let mut store = store_with_alias("a1", TEST_USER);
    assert!(matches!(
        store.create_alias_in(&name("a1"), TEST_REALM, &name(TEST_USER), TEST_REALM),
        Err(Error::AlreadyExists)
    ));
    assert!(matches!(
        store.insert_new_password(&name("a1"), TEST_REALM, b"pw", &[]),
        Err(Error::AlreadyExists)
    ));
    let realm = store.create_alias_in(&name("x"), TEST_REALM, &name("y"), "OTHER.REALM");
    assert!(matches!(realm, Err(Error::AliasRealm)));
    assert_eq!(
        realm.unwrap_err().to_string(),
        "Alias target must be within the same realm"
    );
    let ren = store.rename_unchecked(&name("a1"), TEST_REALM, &name("b1"), TEST_REALM);
    assert!(matches!(ren, Err(Error::AliasUnsupported)));
    assert_eq!(
        ren.unwrap_err().to_string(),
        "Operation unsupported on alias principal name"
    );
}

#[test]
fn dangling_alias_is_overwritable_by_create_and_rename() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .create_alias_in(&name("xa1"), TEST_REALM, &name("nosuch"), TEST_REALM)
        .unwrap();
    store
        .create_alias_in(&name("xa3"), TEST_REALM, &name("nosuch"), TEST_REALM)
        .unwrap();
    assert!(store.get(&id("xa1")).is_none());
    store
        .insert_new_password(&name("xa1"), TEST_REALM, b"pw", &[])
        .unwrap();
    let xa1 = store.get(&id("xa1")).unwrap();
    assert_eq!(xa1.id(), id("xa1"));
    assert!(xa1.alias_target().is_none());
    store
        .rename_unchecked(&name("xa1"), TEST_REALM, &name("xa3"), TEST_REALM)
        .unwrap();
    assert_eq!(store.get(&id("xa3")).unwrap().id(), id("xa3"));
}

#[test]
fn modify_cpw_and_lockout_through_alias_act_on_target_and_delete_removes_stub_only() {
    let mut store = store_with_alias("a1", TEST_USER);
    let before = store.get_name(&name(TEST_USER)).unwrap().attributes;
    store
        .apply_admin_fields_in(
            &name("a1"),
            TEST_REALM,
            Some(before | KDB_REQUIRES_PRE_AUTH),
            None,
            None,
            None,
            None,
            false,
        )
        .unwrap();
    let user = store.get_name(&name(TEST_USER)).unwrap();
    assert_ne!(user.attributes & KDB_REQUIRES_PRE_AUTH, 0);
    let kvno = user.keys.iter().map(|k| k.kvno).max().unwrap();
    store
        .set_password_keepold_n_in(&name("a1"), TEST_REALM, b"newpw", 0)
        .unwrap();
    let user = store.get_name(&name(TEST_USER)).unwrap();
    assert_eq!(user.keys.iter().map(|k| k.kvno).max().unwrap(), kvno + 1);
    store.record_as_outcome(&name("a1"), false);
    store.record_as_outcome(&name("a1"), false);
    assert_eq!(
        store.fail_auth_of(store.get_name(&name(TEST_USER)).unwrap()),
        2
    );
    store.remove_in(&name("a1"), TEST_REALM).unwrap();
    assert!(store.get_raw(&id("a1")).is_none());
    assert!(store.get_name(&name(TEST_USER)).is_some());
}

#[test]
fn as_via_alias_keeps_requested_cname_unless_canonicalize() {
    let store = store_with_alias("a1", TEST_USER);
    let user_key = store
        .get_name(&name(TEST_USER))
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let plain = as_req(
        name("a1"),
        TEST_REALM,
        11,
        Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
    )
    .unwrap();
    let out = issue_as(&store, &plain).unwrap();
    assert_eq!(out.rep.0.cname, name("a1"));
    let krbtgt = store.krbtgt().unwrap().first_current_key().unwrap();
    let part = decrypt_ticket_part(&krbtgt.key, &out.rep.0.ticket).unwrap();
    assert_eq!(part.cname, name("a1"));

    let mut canon = as_req(
        name("a1"),
        TEST_REALM,
        12,
        Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
    )
    .unwrap();
    canon.0.req_body.kdc_options = canon
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::CANONICALIZE, true);
    let out = issue_as(&store, &canon).unwrap();
    assert_eq!(out.rep.0.cname, name(TEST_USER));
    let part = decrypt_ticket_part(&krbtgt.key, &out.rep.0.ticket).unwrap();
    assert_eq!(part.cname, name(TEST_USER));

    let missing = as_req(name("a11"), TEST_REALM, 13, None).unwrap();
    let err = issue_as(&store, &missing).unwrap_err();
    assert!(matches!(err, Error::Protocol { code: 6, .. }), "{err}");
}

#[test]
fn tgs_via_alias_keeps_requested_sname_and_uses_target_key() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    store
        .create_alias_in(&name("svcalias"), TEST_REALM, &host, TEST_REALM)
        .unwrap();
    store
        .create_alias_in(
            &name("tgtalias"),
            TEST_REALM,
            &PrincipalName::krbtgt(TEST_REALM),
            TEST_REALM,
        )
        .unwrap();
    let user_key = store
        .get_name(&name(TEST_USER))
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        name(TEST_USER),
        TEST_REALM,
        21,
        Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
    )
    .unwrap();
    let tgt = issue_as(&store, &req).unwrap();
    for (alias, key) in [
        (
            "svcalias",
            store
                .get_name(&host)
                .unwrap()
                .first_current_key()
                .unwrap()
                .key
                .clone(),
        ),
        (
            "tgtalias",
            store
                .krbtgt()
                .unwrap()
                .first_current_key()
                .unwrap()
                .key
                .clone(),
        ),
    ] {
        let req = tgs_req(
            tgt.rep.0.ticket.clone(),
            &tgt.session_key,
            TEST_REALM,
            &name(TEST_USER),
            name(alias),
            TEST_REALM,
            22,
        )
        .unwrap();
        let out = issue_tgs(&store, &req).unwrap();
        assert_eq!(out.rep.0.ticket.sname, name(alias));
        decrypt_ticket_part(&key, &out.rep.0.ticket).unwrap();
    }
    let req = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &name(TEST_USER),
        name("selfalias"),
        TEST_REALM,
        23,
    )
    .unwrap();
    store
        .create_alias_in(
            &name("selfalias"),
            TEST_REALM,
            &name("selfalias"),
            TEST_REALM,
        )
        .unwrap();
    let err = issue_tgs(&store, &req).unwrap_err();
    assert!(matches!(err, Error::Protocol { code: 7, .. }), "{err}");
}

#[test]
fn as_rep_via_alias_carries_the_target_salt_in_etype_info2() {
    // A no-preauth client kinit'ing an alias must receive the target's salt,
    // else string-to-key uses the alias name and fails (kdc_preauth.c add_etype_info).
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .apply_admin_fields_in(
            &name(TEST_USER),
            TEST_REALM,
            Some(store.get_name(&name(TEST_USER)).unwrap().attributes & !KDB_REQUIRES_PRE_AUTH),
            None,
            None,
            None,
            None,
            false,
        )
        .unwrap();
    store
        .create_alias_in(&name("a1"), TEST_REALM, &name(TEST_USER), TEST_REALM)
        .unwrap();
    let req = as_req(name("a1"), TEST_REALM, 31, None).unwrap();
    let out = issue_as(&store, &req).unwrap();
    let padata = out.rep.0.padata.expect("AS-REP padata");
    let info = padata
        .iter()
        .find(|p| p.padata_type == pa::ETYPE_INFO2)
        .expect("ETYPE-INFO2 on the AS-REP");
    let entries: EtypeInfo2 = decode(info.padata_value.as_ref()).unwrap();
    let salt = entries[0].salt.as_ref().expect("salt").as_bytes();
    assert_eq!(salt, b"KERBER.TESTuser");
    // The one entry describes the reply key (add_etype_info uses the selected key).
    assert_eq!(entries[0].etype, out.rep.0.enc_part.etype);
    assert!(entries[0].s2kparams.is_none());
}

#[test]
fn dump_line_matches_mit_and_round_trips() {
    let store = store_with_alias("a1", TEST_USER);
    let text = dump_store(&store, MASTER_PASSWORD).unwrap();
    let line = text
        .lines()
        .find(|l| l.contains("\ta1@KERBER.TEST\t"))
        .unwrap();
    let mut fields = line.split('\t');
    let head: Vec<&str> = fields.by_ref().take(15).collect();
    assert_eq!(
        head,
        [
            "princ",
            "38",
            "14",
            "3",
            "0",
            "0",
            "a1@KERBER.TEST",
            "64",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0"
        ]
    );
    assert_eq!(fields.next(), Some("3"));
    assert_eq!(fields.next(), Some("24"));
    assert_eq!(
        fields.next(),
        Some("12345c010000000000000000000000000000000000000000")
    );
    assert_eq!(fields.next(), Some("2"));
    fields.next();
    fields.next();
    assert_eq!(fields.next(), Some("12"));
    assert_eq!(fields.next(), Some("17"));
    assert_eq!(fields.next(), Some("75736572404b45524245522e5445535400"));
    assert_eq!(fields.next(), Some("-1;"));
    let reloaded = load_dump(&text, MASTER_PASSWORD).unwrap();
    assert_eq!(reloaded.get(&id("a1")).unwrap().id(), id(TEST_USER));
    assert_eq!(
        reloaded
            .get_raw(&id("a1"))
            .unwrap()
            .alias_target()
            .as_deref(),
        Some("user@KERBER.TEST")
    );
}
