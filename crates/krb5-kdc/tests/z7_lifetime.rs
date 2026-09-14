//! Z7.1: lifetime defaults whole. Compiles at `818d4d6` (parent-red):
//! omitted `max_renewable_life` still fed the create field (0) into the
//! KDC issue cap, `synthesize_km` hard-coded 10 h / 7 d, and `as_ex`
//! `till` fell back to 10 h. Do not name `realm_max_renewable_life` here.

use krb5_kdc::{
    PrincipalStore, TEST_REALM, TEST_USER, bootstrap_documented, decrypt_ticket_part, dump_store,
    parse_dump,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_types::{PrincipalName, flag_bit};

const ACTOR: &str = "kadmin/admin@KERBER.TEST";

fn name(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

/// Live: kdc.conf with `max_life = 1h` and no `max_renewable_life`,
/// principals at 7 d, `kinit -r 5d` → renew-till = start + 5 d.
/// Create default 0 rides along (already 0 at the parent).
#[test]
fn z7_realm_cap_omitted_rlife_allows_five_day_renew() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let conf = krb5_config::KdcConf::parse(&format!(
        "[realms]\n    {TEST_REALM} = {{\n        max_life = 1h\n    }}\n"
    ))
    .unwrap();
    assert_eq!(conf.max_renewable_life, 0, "alt_prof.c create default");
    store.apply_kdc_conf(&conf).unwrap();
    store
        .insert_new_password(&name("z71c"), TEST_REALM, b"x", &[], ACTOR)
        .unwrap();
    assert_eq!(
        store.get_name(&name("z71c")).unwrap().max_renewable_life,
        0,
        "omitted kdc.conf max_renewable_life is params.max_rlife = 0"
    );

    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = PrincipalName::krbtgt(TEST_REALM);
    store
        .apply_admin_fields(
            &user,
            None,
            None,
            None,
            None,
            None,
            false,
            Some(7 * 24 * 3600),
        )
        .unwrap();
    store
        .apply_admin_fields(
            &tgt,
            None,
            None,
            None,
            None,
            None,
            false,
            Some(7 * 24 * 3600),
        )
        .unwrap();

    let key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let mut req = as_req(
        user,
        TEST_REALM,
        7101,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    req.0.req_body.rtime = Some(
        req.0
            .req_body
            .till
            .add_seconds(i64::from(5 * 24 * 3600) - 10 * 3600)
            .expect("rtime 5d from now"),
    );
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    let tgt_key = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let part = decrypt_ticket_part(&tgt_key, &issued.rep.0.ticket).unwrap();
    let start = part
        .starttime
        .as_ref()
        .unwrap_or(&part.authtime)
        .unix_seconds();
    let renew = part
        .renew_till
        .as_ref()
        .expect("RENEWABLE ticket")
        .unix_seconds();
    let delta = i64::from(renew) - i64::from(start);
    assert!(
        (i64::from(5 * 24 * 3600) - 5..=i64::from(5 * 24 * 3600) + 5).contains(&delta),
        "kdc/main.c realm_maxrlife 7 d allows a 5 d renew; got {delta}"
    );
}

/// `kdb5_create.c:394-395` copies `params.max_life` / `params.max_rlife`.
#[test]
fn z7_synthesize_km_uses_params_lifetimes() {
    let store = PrincipalStore::new(TEST_REALM);
    let text = dump_store(&store, b"masterpassword").expect("dump");
    let dump = parse_dump(&text).expect("parse");
    let km = dump.princ("K/M@KERBER.TEST").expect("K/M");
    assert_eq!(km.max_life, 24 * 3600, "params.max_life default 24 h");
    assert_eq!(km.max_renewable_life, 0, "params.max_rlife default 0");
}

/// `get_in_tkt.c:947` omitted `till` is 24 h. Source pin so the inject
/// compiles at the parent (no public till getter there) and still fails.
#[test]
fn z7_client_till_default_is_one_day() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../krb5-protocol/src/as_ex.rs"
    ));
    assert!(
        src.contains("unwrap_or(24 * 3600)") || src.contains("unwrap_or(24 * 60 * 60)"),
        "get_in_tkt.c:947 omitted lifetime is 24 h"
    );
    assert!(
        !src.contains("unwrap_or(10 * 3600)"),
        "as_ex till fallback must not be 10 h"
    );
}
