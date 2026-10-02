//! What this primary's update log records and sends for each change, as MIT's
//! `ulog_conv_2logentry` does (the attribute lists settled live with `kproplog -v` against an MIT
//! 1.22.2 primary), and a replica fed by it.

use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented, documented_admin_id};
use krb5_kdc::{
    AT_ATTRFLAGS, AT_EXP, AT_KEYDATA, AT_MAX_LIFE, AT_MOD_PRINC, AT_MOD_TIME, AT_PRINC, AT_PW_EXP,
    AT_PW_LAST_CHANGE, AT_TL_DATA, Acl, AdminFields, KDB_DISALLOW_ALL_TIX, KDB_REQUIRES_PRE_AUTH,
    KdbeVal, NamedPolicy, Principal, PrincipalStore, PrincipalWrite, TL_LAST_PWD_CHANGE,
    TL_MOD_PRINC, TL_STRING_ATTRS, ULOG_ADD_ATTRS, UlogEntry, attr_bit, conv_2logentry, load_store,
    save_store, tl_mod_princ_name,
};
use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

fn bits(attrs: &[u32]) -> u32 {
    attrs.iter().fold(0, |m, a| m | attr_bit(*a))
}

fn last_for(store: &PrincipalStore, id: &str) -> UlogEntry {
    store
        .ulog()
        .into_iter()
        .rev()
        .find(|e| e.name == id)
        .unwrap()
}

/// The list without `AT_TL_DATA`, which a change in the same second by the same caller may leave
/// out: the modifier record is then the same bytes, as on MIT.
fn listed_besides_tl(store: &PrincipalStore, id: &str) -> u32 {
    last_for(store, id).attrs & !attr_bit(AT_TL_DATA)
}

fn kinds(vals: &[KdbeVal]) -> Vec<u32> {
    vals.iter().map(KdbeVal::attr).collect()
}

#[test]
fn each_change_records_mits_attribute_list() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["p11list"]);
    let id = format!("p11list@{TEST_REALM}");
    store
        .create_password(&acl, &actor, &name, b"p11-Secret1")
        .unwrap();
    assert_eq!(last_for(&store, &id).attrs, ULOG_ADD_ATTRS);
    store.set_string(&name, "note", Some("n1")).unwrap();
    assert_eq!(last_for(&store, &id).attrs, bits(&[AT_PRINC, AT_TL_DATA]));
    store.chrand(&name).unwrap();
    assert_eq!(
        last_for(&store, &id).attrs,
        bits(&[AT_PRINC, AT_KEYDATA, AT_TL_DATA])
    );
    let fields = |f: AdminFields| f;
    store
        .apply_admin_fields(
            &name,
            fields(AdminFields {
                max_life: Some(4 * 3600),
                ..AdminFields::default()
            }),
        )
        .unwrap();
    assert_eq!(
        listed_besides_tl(&store, &id),
        bits(&[AT_MAX_LIFE, AT_PRINC])
    );
    store
        .apply_admin_fields(
            &name,
            AdminFields {
                attributes: Some(KDB_REQUIRES_PRE_AUTH | KDB_DISALLOW_ALL_TIX),
                ..AdminFields::default()
            },
        )
        .unwrap();
    assert_eq!(
        listed_besides_tl(&store, &id),
        bits(&[AT_ATTRFLAGS, AT_PRINC])
    );
    store
        .apply_admin_fields(
            &name,
            AdminFields {
                expiration: Some(1_924_992_000),
                ..AdminFields::default()
            },
        )
        .unwrap();
    assert_eq!(listed_besides_tl(&store, &id), bits(&[AT_EXP, AT_PRINC]));
    store.delete(&acl, &actor, &name).unwrap();
    let gone = last_for(&store, &id);
    assert!(gone.deleted);
    assert_eq!(gone.attrs, 0);
    assert!(gone.kdbe_vals().is_empty());
}

#[test]
fn an_update_sends_the_listed_attributes_in_mits_shapes() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["p11shape"]);
    let id = format!("p11shape@{TEST_REALM}");
    store
        .create_password(&acl, &documented_admin_id(), &name, b"p11-Secret1")
        .unwrap();
    store.set_string(&name, "note", Some("n1")).unwrap();
    let entry = last_for(&store, &id);
    let vals = entry.kdbe_vals();
    // kproplog -v of an MIT setstr: Principal, Password last changed, Modifying principal,
    // Modification time, TL data.
    assert_eq!(
        kinds(&vals),
        [
            AT_PRINC,
            AT_PW_LAST_CHANGE,
            AT_MOD_PRINC,
            AT_MOD_TIME,
            AT_TL_DATA
        ]
    );
    let record = store.get_name(&name).unwrap();
    let modifier = vals.iter().find_map(|v| match v {
        KdbeVal::ModPrinc(n, r) => Some(krb5_kdc::lookup_principal_id(n, r)),
        _ => None,
    });
    assert_eq!(modifier, tl_mod_princ_name(&record.tl_data));
    let tl = vals
        .iter()
        .find_map(|v| match v {
            KdbeVal::TlData(tl) => Some(tl.clone()),
            _ => None,
        })
        .unwrap();
    assert!(tl.iter().any(|t| t.ty == TL_STRING_ATTRS));
    assert!(!tl.iter().any(|t| t.ty == TL_LAST_PWD_CHANGE
        || t.ty == TL_MOD_PRINC
        || (0x4B00..=0x4BFF).contains(&t.ty)));
    // No list sends a lockout attribute, nor one past AT_LEN of its own.
    let every = conv_2logentry(record, u32::MAX);
    assert_eq!(
        kinds(&every),
        [
            AT_ATTRFLAGS,
            1,
            2,
            AT_EXP,
            AT_PW_EXP,
            AT_PRINC,
            AT_KEYDATA,
            AT_PW_LAST_CHANGE,
            AT_MOD_PRINC,
            AT_MOD_TIME,
            AT_TL_DATA,
            11
        ]
    );
}

#[test]
fn an_expiration_past_2038_is_sent() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["p11y2038"]);
    store
        .create_password(&acl, &documented_admin_id(), &name, b"p11-Secret1")
        .unwrap();
    let mut p = store.get_name(&name).unwrap().clone();
    p.expiration = 2_208_988_800;
    p.pw_expire = 2_208_988_800;
    let vals = conv_2logentry(&p, bits(&[AT_EXP, AT_PW_EXP]));
    assert!(matches!(
        vals[..],
        [KdbeVal::Exp(2_208_988_800), KdbeVal::PwExp(2_208_988_800)]
    ));
}

#[test]
fn the_attribute_list_survives_a_primary_restart() {
    let dir = scratch_dir("krb5-p11-ulog-attrs");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut store, acl) = bootstrap_documented().unwrap();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["p11keep"]);
    let id = format!("p11keep@{TEST_REALM}");
    store
        .create_password(&acl, &documented_admin_id(), &name, b"p11-Secret1")
        .unwrap();
    store.persist_paths = Some((db.clone(), stash.clone()));
    save_store(&store, &db, &stash).unwrap();
    store
        .change(|s| s.set_string(&name, "note", Some("n1")))
        .unwrap()
        .unwrap();
    let loaded = load_store(&db, &stash).unwrap();
    assert_eq!(last_for(&loaded, &id).attrs, bits(&[AT_PRINC, AT_TL_DATA]));
}

#[test]
fn an_update_log_entry_from_before_the_list_sends_every_attribute() {
    let dir = scratch_dir("krb5-p11-ulog-v1");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut store, acl) = bootstrap_documented().unwrap();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["p11old"]);
    store
        .create_password(&acl, &documented_admin_id(), &name, b"p11-Secret1")
        .unwrap();
    store
        .apply_admin_fields(
            &name,
            AdminFields {
                attributes: Some(KDB_REQUIRES_PRE_AUTH | KDB_DISALLOW_ALL_TIX),
                ..AdminFields::default()
            },
        )
        .unwrap();
    save_store(&store, &db, &stash).unwrap();
    let mut ulog = db.clone().into_os_string();
    ulog.push(".ulog");
    std::fs::write(
        &ulog,
        format!(
            "ulog 1\n7\t1790000000\t0\tp11old@{TEST_REALM}\n8\t1790000001\t1\tgone@{TEST_REALM}\n"
        ),
    )
    .unwrap();
    let loaded = load_store(&db, &stash).unwrap();
    let entries = loaded.ulog();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].attrs, ULOG_ADD_ATTRS);
    assert_eq!(entries[1].attrs, 0);
    let vals = entries[0].kdbe_vals();
    assert!(vals.iter().any(|v| matches!(
        v,
        KdbeVal::AttrFlags(a) if *a & KDB_DISALLOW_ALL_TIX != 0
    )));
}

#[test]
fn a_modify_kvno_put_is_logged() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["p11kvno"]);
    let id = format!("p11kvno@{TEST_REALM}");
    store
        .create_password(&acl, &documented_admin_id(), &name, b"p11-Secret1")
        .unwrap();
    let mut p = store.get_name(&name).unwrap().clone();
    for k in &mut p.keys {
        k.kvno = 7;
    }
    PrincipalWrite::put_principal(&mut store, p).unwrap();
    assert_eq!(
        listed_besides_tl(&store, &id),
        bits(&[AT_PRINC, AT_KEYDATA])
    );
}

#[test]
fn a_restricted_create_logs_the_restriction() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("res@KERBER.TEST a *@KERBER.TEST -maxlife 1h\n").unwrap();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["p11res"]);
    let id = format!("p11res@{TEST_REALM}");
    store
        .create_password(&acl, "res@KERBER.TEST", &name, b"p11-Secret1")
        .unwrap();
    let entry = last_for(&store, &id);
    assert_ne!(entry.attrs & attr_bit(AT_MAX_LIFE), 0);
    assert_eq!(entry.princ.unwrap().max_life, 3600);
}

/// Pull everything `primary` logged after `sno` into `replica`; the primary's serial after.
fn pull(primary: &PrincipalStore, replica: &mut PrincipalStore, sno: u32) -> u32 {
    let (_, last, entries) = primary.iprop_get(sno);
    let updates: Vec<_> = entries.iter().map(UlogEntry::to_update).collect();
    replica.apply_updates(&updates).unwrap();
    last
}

fn assert_same(primary: &Principal, replica: &Principal) {
    assert_eq!(replica.attributes, primary.attributes);
    assert_eq!(replica.locked, primary.locked);
    assert_eq!(replica.requires_preauth, primary.requires_preauth);
    assert_eq!(replica.max_life, primary.max_life);
    assert_eq!(replica.max_renewable_life, primary.max_renewable_life);
    assert_eq!(replica.expiration, primary.expiration);
    assert_eq!(replica.pw_expire, primary.pw_expire);
    assert_eq!(replica.string_attrs, primary.string_attrs);
    assert_eq!(replica.pw_policy, primary.pw_policy);
    assert_eq!(
        replica
            .keys
            .iter()
            .map(|k| (k.kvno, k.etype, k.key.as_bytes().to_vec()))
            .collect::<Vec<_>>(),
        primary
            .keys
            .iter()
            .map(|k| (k.kvno, k.etype, k.key.as_bytes().to_vec()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        tl_mod_princ_name(&replica.tl_data),
        tl_mod_princ_name(&primary.tl_data)
    );
}

#[test]
fn a_replica_fed_by_this_primary_matches_it_after_each_change() {
    let (mut primary, acl) = bootstrap_documented().unwrap();
    let (mut replica, _) = bootstrap_documented().unwrap();
    primary.put_policy(NamedPolicy::new("p11pol"));
    let actor = documented_admin_id();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["p11mirror"]);
    let mut sno = primary.serial();
    let same = |p: &PrincipalStore, r: &PrincipalStore| {
        assert_same(p.get_name(&name).unwrap(), r.get_name(&name).unwrap());
    };
    primary
        .create_password(&acl, &actor, &name, b"p11-Secret1")
        .unwrap();
    primary
        .apply_admin_fields(
            &name,
            AdminFields {
                attributes: Some(KDB_REQUIRES_PRE_AUTH | KDB_DISALLOW_ALL_TIX),
                max_life: Some(5 * 3600),
                expiration: Some(1_924_992_000),
                pw_expire: Some(1_906_502_400),
                policy: Some("p11pol".into()),
                clear_policy: false,
                max_renewable_life: Some(3 * 86_400),
            },
        )
        .unwrap();
    primary.set_string(&name, "start", Some("s0")).unwrap();
    sno = pull(&primary, &mut replica, sno);
    same(&primary, &replica);
    primary.set_string(&name, "note", Some("n1")).unwrap();
    sno = pull(&primary, &mut replica, sno);
    same(&primary, &replica);
    primary.chrand(&name).unwrap();
    sno = pull(&primary, &mut replica, sno);
    same(&primary, &replica);
    primary
        .apply_admin_fields(
            &name,
            AdminFields {
                max_life: Some(4 * 3600),
                ..AdminFields::default()
            },
        )
        .unwrap();
    sno = pull(&primary, &mut replica, sno);
    same(&primary, &replica);
    primary
        .apply_admin_fields(
            &name,
            AdminFields {
                attributes: Some(KDB_REQUIRES_PRE_AUTH),
                ..AdminFields::default()
            },
        )
        .unwrap();
    sno = pull(&primary, &mut replica, sno);
    same(&primary, &replica);
    assert!(!replica.get_name(&name).unwrap().locked);
    // The last string deleted: MIT keeps an empty record, which clears it on the replica.
    primary.set_string(&name, "note", None).unwrap();
    primary.set_string(&name, "start", None).unwrap();
    sno = pull(&primary, &mut replica, sno);
    same(&primary, &replica);
    assert_eq!(
        replica.get_name(&name).unwrap().string_attrs,
        Vec::<(String, String)>::new()
    );
    primary.delete(&acl, &actor, &name).unwrap();
    pull(&primary, &mut replica, sno);
    assert!(replica.get_name(&name).is_none());
}
