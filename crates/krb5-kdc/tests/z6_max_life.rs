//! Z6.6: unset `kdc.conf` `max_life` is `params.max_life` = 24 h
//! (`alt_prof.c:574-575` `GET_DELTAT_PARAM(…, 24 * 60 * 60)`). Compiles
//! at the parent: create already takes `Policy::max_life` / `KdcConf::max_life`;
//! the parent defaults both to 10 h.

use krb5_kdc::{TEST_REALM, bootstrap_documented};
use krb5_types::PrincipalName;

const ACTOR: &str = "kadmin/admin@KERBER.TEST";

fn name(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

/// Live: kdc.conf with no `max_life`, `addprinc -pw x z66` →
/// `Maximum ticket life: 1 day 00:00:00` on both kadminds.
#[test]
fn z6_params_max_life_default_is_one_day() {
    let (mut store, _) = bootstrap_documented().unwrap();
    assert_eq!(
        store.policy().max_life,
        24 * 3600,
        "Policy default is alt_prof.c 24 h, not 10 h"
    );
    store
        .insert_new_password(&name("z66"), TEST_REALM, b"x", &[], ACTOR)
        .unwrap();
    assert_eq!(store.get_name(&name("z66")).unwrap().max_life, 24 * 3600);

    let conf =
        krb5_config::KdcConf::parse(&format!("[realms]\n    {TEST_REALM} = {{\n    }}\n")).unwrap();
    assert_eq!(
        conf.max_life,
        24 * 3600,
        "omitted kdc.conf max_life is 24 h"
    );
    store.apply_kdc_conf(&conf).unwrap();
    store
        .insert_new_password(&name("z66b"), TEST_REALM, b"x", &[], ACTOR)
        .unwrap();
    assert_eq!(store.get_name(&name("z66b")).unwrap().max_life, 24 * 3600);
}
