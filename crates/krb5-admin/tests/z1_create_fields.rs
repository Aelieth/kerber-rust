//! W1-Z Z1.1: `kadm5_create_principal_3` applies the `kadm5_principal_ent_rec`
//! fields under the request mask (`svr_principal.c:376-420`) and the ACL
//! restrictions are imposed on the *request* before the create/modify runs
//! (`kadmin/server/auth.c:205-272` `impose_restrictions`, called from
//! `server_stubs.c:478,519,630` `stub_auth_restrict`). Compiles at `b50d6bf`
//! (parent-red): every assertion here is on the stored entry through the RPC
//! path, which the parent accepted while silently dropping the fields.

mod common;

use common::{
    API_V2, GSS_INTEGRITY, SUCCESS, data_call, init_client, push_nullstring, push_u32, ret_code,
};
use krb5_kdc::{
    Acl, KDB_DISALLOW_ALL_TIX, KDB_REQUIRES_PRE_AUTH, NamedPolicy, TEST_ADMIN, TEST_REALM,
    bootstrap_documented, documented_kadmin, shared_dump,
};
use krb5_types::PrincipalName;

const CREATE_PRINCIPAL: u32 = 1;
const MODIFY_PRINCIPAL: u32 = 3;
const KADM5_PRINCIPAL: u32 = 0x0000_0001;
const KADM5_PRINC_EXPIRE_TIME: u32 = 0x0000_0002;
const KADM5_PW_EXPIRATION: u32 = 0x0000_0004;
const KADM5_ATTRIBUTES: u32 = 0x0000_0010;
const KADM5_MAX_LIFE: u32 = 0x0000_0020;
const KADM5_KVNO: u32 = 0x0000_0100;
const KADM5_POLICY: u32 = 0x0000_0800;
const KADM5_MAX_RLIFE: u32 = 0x0000_2000;
/// `kadm_err.et` 22.
const KADM5_PASS_Q_TOOSHORT: u32 = 43_787_542;

/// The `kadm5_principal_ent_rec` scalars a create/modify request carries.
#[derive(Clone, Copy, Default)]
struct Ent {
    expire: u32,
    pw_expire: u32,
    max_life: u32,
    max_rlife: u32,
    attributes: u32,
    kvno: u32,
}

/// `xdr_cprinc_arg` / `xdr_mprinc_arg` body: api_version, the record, mask
/// (and for create the password). Field order is
/// `kadm_rpc_xdr.c:xdr_kadm5_principal_ent_rec_v1`.
fn ent_args(
    name: &str,
    ent: Ent,
    policy: Option<&str>,
    mask: u32,
    password: Option<&str>,
) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, name);
    push_u32(&mut w, ent.expire);
    push_u32(&mut w, 0); // last_pwd_change
    push_u32(&mut w, ent.pw_expire);
    push_u32(&mut w, ent.max_life);
    push_u32(&mut w, 1); // mod_name NULL
    push_u32(&mut w, 0); // mod_date
    push_u32(&mut w, ent.attributes);
    push_u32(&mut w, ent.kvno);
    push_u32(&mut w, 0); // mkvno
    match policy {
        Some(p) => push_nullstring(&mut w, p),
        None => push_u32(&mut w, 0),
    }
    push_u32(&mut w, 0); // aux_attributes
    push_u32(&mut w, ent.max_rlife);
    push_u32(&mut w, 0); // last_success
    push_u32(&mut w, 0); // last_failed
    push_u32(&mut w, 0); // fail_auth_count
    push_u32(&mut w, 0); // n_key_data
    push_u32(&mut w, 0); // n_tl_data
    push_u32(&mut w, 1); // tl_data NULL
    push_u32(&mut w, 0); // key_data array: 0 entries
    push_u32(&mut w, mask);
    if let Some(pw) = password {
        push_nullstring(&mut w, pw);
    }
    w
}

fn n(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn now() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

struct Rig {
    store: krb5_kdc::SharedDump,
    acl: Acl,
    client: common::Client,
}

/// A kadmind with `acl_text` and an authenticated `admin@KERBER.TEST` client.
fn rig(acl_text: &str, setup: impl FnOnce(&mut krb5_kdc::PrincipalStore)) -> Rig {
    let (mut store, _) = bootstrap_documented().unwrap();
    setup(&mut store);
    let acl = Acl::parse(acl_text).unwrap();
    let store = shared_dump(store);
    let client = init_client(
        &store,
        &acl,
        &n(TEST_ADMIN),
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    Rig { store, acl, client }
}

fn create(r: &mut Rig, args: &[u8]) -> u32 {
    let (stat, body) = data_call(&mut r.client, &r.store, &r.acl, CREATE_PRINCIPAL, args);
    assert_eq!(stat, SUCCESS);
    ret_code(&body)
}

fn modify(r: &mut Rig, args: &[u8]) -> u32 {
    let (stat, body) = data_call(&mut r.client, &r.store, &r.acl, MODIFY_PRINCIPAL, args);
    assert_eq!(stat, SUCCESS);
    ret_code(&body)
}

fn stored(r: &Rig, name: &str) -> krb5_kdc::Principal {
    let g = r
        .store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    g.get_name(&n(name))
        .unwrap_or_else(|| panic!("{name} not created"))
        .clone()
}

/// `svr_principal.c:381-401`: every masked field lands on the entry;
/// `:461-464`: `KADM5_KVNO` keys the password at that kvno. Live MIT
/// `addprinc -pw x -maxlife 1h -maxrenewlife 0 -expire 2030-01-01 -pwexpire
/// 2031-01-01 -kvno 7 +disallow_all_tix +requires_preauth z1u` shows all six
/// in `getprinc`.
#[test]
fn z1_kadm5_create_applies_every_masked_field() {
    let mut r = rig("admin@KERBER.TEST *\n", |_| {});
    let ent = Ent {
        expire: 1_893_456_000,    // 2030-01-01
        pw_expire: 1_924_992_000, // 2031-01-01
        max_life: 3600,
        max_rlife: 0,
        attributes: KDB_DISALLOW_ALL_TIX | KDB_REQUIRES_PRE_AUTH,
        kvno: 7,
    };
    let mask = KADM5_PRINCIPAL
        | KADM5_PRINC_EXPIRE_TIME
        | KADM5_PW_EXPIRATION
        | KADM5_ATTRIBUTES
        | KADM5_MAX_LIFE
        | KADM5_MAX_RLIFE
        | KADM5_KVNO;
    let args = ent_args(&format!("z1u@{TEST_REALM}"), ent, None, mask, Some("x"));
    assert_eq!(create(&mut r, &args), 0);
    let p = stored(&r, "z1u");
    assert_eq!(p.attributes, KDB_DISALLOW_ALL_TIX | KDB_REQUIRES_PRE_AUTH);
    assert!(p.locked, "DISALLOW_ALL_TIX mirrors into `locked`");
    assert_eq!(p.max_life, 3600);
    assert_eq!(
        p.max_renewable_life, 0,
        "an in-mask 0 is stored, not defaulted"
    );
    assert_eq!(p.expiration, 1_893_456_000);
    assert_eq!(p.pw_expire, 1_924_992_000);
    assert!(!p.keys.is_empty());
    assert!(
        p.keys.iter().all(|k| k.kvno == 7),
        "KADM5_KVNO keys at 7: {:?}",
        p.keys.iter().map(|k| k.kvno).collect::<Vec<_>>()
    );
}

/// `svr_principal.c:381-401` `else` arms: without the mask bit the field is
/// `handle->params.*` — `max_life`/`max_rlife` from kdc.conf, expiration 0,
/// `pw_expiration` 0 unless the policy has `pw_max_life` (`:397-400`), and
/// `attributes` = `params.flags` (the realm default flags).
#[test]
fn z1_kadm5_create_without_mask_bits_takes_realm_defaults() {
    let mut r = rig("admin@KERBER.TEST *\n", |s| {
        let mut pol = NamedPolicy::new("z1pw");
        pol.pw_max_life = 30 * 86400;
        s.put_policy(pol);
    });
    let (realm_max_life, realm_max_rlife) = {
        let g = r.store.read().unwrap();
        (g.policy().max_life, g.policy().max_renewable_life)
    };
    assert!(realm_max_life > 0, "fixture realm max_life");
    let args = ent_args(
        &format!("z1d@{TEST_REALM}"),
        Ent::default(),
        None,
        KADM5_PRINCIPAL,
        Some("z1d-secret"),
    );
    assert_eq!(create(&mut r, &args), 0);
    let p = stored(&r, "z1d");
    assert_eq!(p.max_life, realm_max_life, "params.max_life");
    assert_eq!(p.max_renewable_life, realm_max_rlife, "params.max_rlife");
    assert_eq!(p.expiration, 0, "params.expiration");
    assert_eq!(p.pw_expire, 0, "no policy: pw_expiration 0");
    assert_eq!(
        p.attributes & KDB_REQUIRES_PRE_AUTH,
        KDB_REQUIRES_PRE_AUTH,
        "params.flags (the realm default flags)"
    );
    // `:397-400`: a policy with pw_max_life sets pw_expiration = now + it.
    let t0 = now();
    let args = ent_args(
        &format!("z1p@{TEST_REALM}"),
        Ent::default(),
        Some("z1pw"),
        KADM5_PRINCIPAL | KADM5_POLICY,
        Some("z1p-secret"),
    );
    assert_eq!(create(&mut r, &args), 0);
    let p = stored(&r, "z1p");
    assert_eq!(p.pw_policy.as_deref(), Some("z1pw"));
    assert!(
        (t0 + 30 * 86400..=now() + 30 * 86400).contains(&p.pw_expire),
        "pw_expiration = now + pw_max_life, got {}",
        p.pw_expire
    );
}

/// `auth.c:218-231` + `svr_principal.c:364-373`: a `-policy P` restriction
/// puts P into the request mask *before* the create, so P's floors reject
/// the password and nothing is created. Live MIT: `Password is too short
/// while creating "..."`.
#[test]
fn z1_acl_policy_restriction_is_enforced_on_create() {
    let mut r = rig(
        "admin@KERBER.TEST * *@KERBER.TEST -policy shortpol\n",
        |s| {
            let mut pol = NamedPolicy::new("shortpol");
            pol.min_length = 8;
            s.put_policy(pol);
        },
    );
    let args = ent_args(
        &format!("z1short@{TEST_REALM}"),
        Ent::default(),
        None,
        KADM5_PRINCIPAL,
        Some("abc"),
    );
    assert_eq!(create(&mut r, &args), KADM5_PASS_Q_TOOSHORT);
    let g = r.store.read().unwrap();
    assert!(
        g.get_name(&n("z1short")).is_none(),
        "rejected create wrote an entry"
    );
    drop(g);
    let args = ent_args(
        &format!("z1long@{TEST_REALM}"),
        Ent::default(),
        None,
        KADM5_PRINCIPAL,
        Some("longenough"),
    );
    assert_eq!(create(&mut r, &args), 0);
    assert_eq!(
        stored(&r, "z1long").pw_policy.as_deref(),
        Some("shortpol"),
        "the restriction's policy is bound"
    );
}

/// `auth.c:265-270`: with `KADM5_MAX_RLIFE` in the mask the value is only
/// lowered to the cap — an explicit 0 stays 0 (MIT `getprinc` shows
/// `0 days 00:00:00`); a value above the cap is lowered.
#[test]
fn z1_acl_maxrenewlife_keeps_an_in_mask_zero_and_lowers_above_cap() {
    let mut r = rig(
        "admin@KERBER.TEST * *@KERBER.TEST -maxrenewlife 1d\n",
        |_| {},
    );
    let args = ent_args(
        &format!("z1r0@{TEST_REALM}"),
        Ent {
            max_rlife: 0,
            ..Ent::default()
        },
        None,
        KADM5_PRINCIPAL | KADM5_MAX_RLIFE,
        Some("z1r0-secret"),
    );
    assert_eq!(create(&mut r, &args), 0);
    assert_eq!(stored(&r, "z1r0").max_renewable_life, 0);
    let args = ent_args(
        &format!("z1r30@{TEST_REALM}"),
        Ent {
            max_rlife: 30 * 86400,
            ..Ent::default()
        },
        None,
        KADM5_PRINCIPAL | KADM5_MAX_RLIFE,
        Some("z1r30-secret"),
    );
    assert_eq!(create(&mut r, &args), 0);
    assert_eq!(stored(&r, "z1r30").max_renewable_life, 86400);
}

/// `auth.c:259-263`: a modify request *without* `KADM5_MAX_LIFE` takes the
/// cap outright (`!(*mask & KADM5_MAX_LIFE)`), even when the stored value
/// is already below it — MIT rewrites `ent->max_life` and sets the bit.
#[test]
fn z1_acl_maxlife_absent_from_modify_mask_takes_the_cap() {
    let mut r = rig("admin@KERBER.TEST * *@KERBER.TEST -maxlife 1h\n", |_| {});
    let args = ent_args(
        &format!("z1m@{TEST_REALM}"),
        Ent {
            max_life: 1800,
            ..Ent::default()
        },
        None,
        KADM5_PRINCIPAL | KADM5_MAX_LIFE,
        Some("z1m-secret"),
    );
    assert_eq!(create(&mut r, &args), 0);
    assert_eq!(stored(&r, "z1m").max_life, 1800, "below the cap stays");
    let args = ent_args(
        &format!("z1m@{TEST_REALM}"),
        Ent {
            attributes: KDB_REQUIRES_PRE_AUTH,
            ..Ent::default()
        },
        None,
        KADM5_ATTRIBUTES,
        None,
    );
    assert_eq!(modify(&mut r, &args), 0);
    assert_eq!(
        stored(&r, "z1m").max_life,
        3600,
        "absent from the mask: the cap is imposed"
    );
}

/// `auth.c:214-217`: `ent->attributes |= require_attrs` on the request's
/// own attributes, so a masked `DISALLOW_ALL_TIX` survives a
/// `+requires_preauth` restriction.
#[test]
fn z1_acl_attribute_restriction_composes_with_the_request_attributes() {
    let mut r = rig(
        "admin@KERBER.TEST * *@KERBER.TEST +requires_preauth\n",
        |_| {},
    );
    let args = ent_args(
        &format!("z1a@{TEST_REALM}"),
        Ent {
            attributes: KDB_DISALLOW_ALL_TIX,
            ..Ent::default()
        },
        None,
        KADM5_PRINCIPAL | KADM5_ATTRIBUTES,
        Some("z1a-secret"),
    );
    assert_eq!(create(&mut r, &args), 0);
    assert_eq!(
        stored(&r, "z1a").attributes,
        KDB_DISALLOW_ALL_TIX | KDB_REQUIRES_PRE_AUTH
    );
}

/// `auth.c:236-241`: `-expire` caps a masked `princ_expire_time` at
/// `now + delta` only when it is later; an earlier request value is kept.
#[test]
fn z1_acl_expire_keeps_a_masked_value_below_the_cap() {
    let mut r = rig("admin@KERBER.TEST * *@KERBER.TEST -expire 1d\n", |_| {});
    let soon = now() + 3600;
    let args = ent_args(
        &format!("z1e@{TEST_REALM}"),
        Ent {
            expire: soon,
            ..Ent::default()
        },
        None,
        KADM5_PRINCIPAL | KADM5_PRINC_EXPIRE_TIME,
        Some("z1e-secret"),
    );
    assert_eq!(create(&mut r, &args), 0);
    assert_eq!(stored(&r, "z1e").expiration, soon);
    let far = now() + 30 * 86400;
    let t0 = now();
    let args = ent_args(
        &format!("z1f@{TEST_REALM}"),
        Ent {
            expire: far,
            ..Ent::default()
        },
        None,
        KADM5_PRINCIPAL | KADM5_PRINC_EXPIRE_TIME,
        Some("z1f-secret"),
    );
    assert_eq!(create(&mut r, &args), 0);
    let e = stored(&r, "z1f").expiration;
    assert!(
        (t0 + 86400..=now() + 86400).contains(&e),
        "capped at now + 1d, got {e}"
    );
}
