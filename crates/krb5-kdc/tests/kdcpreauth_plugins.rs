//! `[plugins] kdcpreauth` selects built-in and embedder modules by MIT's names.
//!
//! MIT `get_plugin_vtables` (`kdc/kdc_preauth.c:117-163`): disable and enable_only run inside k5_plugin_load_all, so a module that is not loaded neither advertises nor verifies.

use std::sync::Arc;

use krb5_asn1::decode;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};
use krb5_kdc::{
    Error, KdcPreauth, PreauthAction, PreauthRock, PrincipalStore, clear_thread_preauth,
    set_thread_preauth,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_testkit::password_key;
use krb5_types::{MethodData, PaData, PrincipalName, pa};

const WIDGET: i32 = 211;

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        clear_thread_preauth();
    }
}

struct Widget;

impl KdcPreauth for Widget {
    fn name(&self) -> &'static str {
        "widget"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[WIDGET]
    }
    fn advertise(
        &self,
        _store: &dyn krb5_kdc::PrincipalRead,
        _client: &krb5_kdc::Principal,
        _armor: bool,
        _requested: &[i32],
    ) -> Vec<PaData> {
        vec![PaData {
            padata_type: WIDGET,
            padata_value: Vec::<u8>::new().into(),
        }]
    }
    fn process_as(&self, _rock: &PreauthRock<'_>) -> Result<Option<PreauthAction>, Error> {
        Ok(None)
    }
}

fn realm(stanza: &str) -> PrincipalStore {
    let (mut store, _) = bootstrap_documented().unwrap();
    let conf = krb5_config::KdcConf::parse(stanza).unwrap();
    store.apply_kdc_conf(&conf).unwrap();
    store
}

fn hint_types(store: &PrincipalStore, nonce: u32) -> Vec<i32> {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, nonce, None).unwrap();
    let err = krb5_kdc::issue_as(store, &req).unwrap_err();
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PreauthRequired, got {err:?}");
    };
    let method: MethodData = decode(&e_data).unwrap();
    method.iter().map(|p| p.padata_type).collect()
}

#[test]
fn disable_encrypted_timestamp_drops_type_2_and_refuses_it() {
    let plain = realm("");
    let offered = hint_types(&plain, 71_001);
    assert!(
        offered.contains(&pa::ENC_TIMESTAMP),
        "an empty profile still offers 2: {offered:?}"
    );
    let store = realm(
        "[plugins]\n    kdcpreauth = {\n        disable = encrypted_timestamp\n        disable = nosuch\n    }\n",
    );
    let types = hint_types(&store, 71_002);
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP),
        "disable drops type 2: {types:?}"
    );
    assert!(
        types.contains(&pa::SPAKE) && types.contains(&pa::FX_FAST),
        "SPAKE and FX-FAST stay: {types:?}"
    );
    let key = password_key(TEST_USER, TEST_USER_PASSWORD);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(
        cname,
        TEST_REALM,
        71_003,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let Error::PreauthRequired { e_data } = err else {
        panic!("a disabled encrypted_timestamp is not verified, got {err:?}");
    };
    let method: MethodData = decode(&e_data).unwrap();
    let again: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert!(
        !again.contains(&pa::ENC_TIMESTAMP),
        "the refusal offer also omits type 2: {again:?}"
    );
}

#[test]
fn enable_only_keeps_named_modules_in_that_order() {
    let store = realm(
        "[plugins]\n    kdcpreauth = {\n        enable_only = encrypted_timestamp\n        enable_only = spake\n    }\n",
    );
    let types = hint_types(&store, 71_010);
    let ts = types.iter().position(|t| *t == pa::ENC_TIMESTAMP);
    let spake = types.iter().position(|t| *t == pa::SPAKE);
    assert_eq!(
        (ts, spake),
        (
            Some(types.iter().position(|t| *t == pa::FX_FAST).unwrap() + 2),
            Some(types.iter().position(|t| *t == pa::FX_FAST).unwrap() + 3)
        ),
        "enable_only order is encrypted_timestamp then spake, after 136 and etype info: {types:?}"
    );
    assert!(
        !types.contains(&pa::PK_AS_REQ),
        "pkinit is not in enable_only: {types:?}"
    );
}

#[test]
fn an_unknown_enable_only_name_keeps_no_module() {
    let store = realm("[plugins]\n    kdcpreauth = {\n        enable_only = otp\n    }\n");
    let types = hint_types(&store, 71_020);
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP) && !types.contains(&pa::SPAKE),
        "otp is not a loaded module, so enable_only keeps none of them: {types:?}"
    );
    assert!(
        types.contains(&pa::FX_FAST),
        "FX-FAST is not a kdcpreauth module: {types:?}"
    );
    let kept = realm("[plugins]\n    kdcpreauth = {\n        disable = otp\n    }\n");
    let types = hint_types(&kept, 71_021);
    assert!(
        types.contains(&pa::ENC_TIMESTAMP) && types.contains(&pa::SPAKE),
        "disable of an absent name drops nothing: {types:?}"
    );
}

#[test]
fn an_embedder_module_is_selected_and_dropped_by_name() {
    let _guard = Guard;
    set_thread_preauth(vec![Arc::new(Widget)]);
    let selected = realm("[plugins]\n    kdcpreauth = {\n        enable_only = widget\n    }\n");
    let types = hint_types(&selected, 71_030);
    assert!(
        types.contains(&WIDGET),
        "enable_only selects the embedder module: {types:?}"
    );
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP) && !types.contains(&pa::SPAKE),
        "enable_only drops the modules it does not name: {types:?}"
    );
    let dropped = realm("[plugins]\n    kdcpreauth = {\n        disable = widget\n    }\n");
    let types = hint_types(&dropped, 71_031);
    assert!(
        !types.contains(&WIDGET),
        "disable drops the embedder module: {types:?}"
    );
    assert!(
        types.contains(&pa::ENC_TIMESTAMP),
        "the built-ins stay when only widget is disabled: {types:?}"
    );
}

#[test]
fn krb5_conf_disable_follows_the_kdc_conf_disable() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let kdc = krb5_config::KdcConf::parse(
        "[plugins]\n    kdcpreauth = {\n        disable = spake\n    }\n",
    )
    .unwrap();
    let krb5 = krb5_config::Krb5Conf::parse(
        "[plugins]\n    kdcpreauth = {\n        disable = encrypted_timestamp\n    }\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    store.apply_kdcpreauth_plugins(Some(&kdc), Some(&krb5));
    let types = hint_types(&store, 71_040);
    assert!(
        !types.contains(&pa::SPAKE) && !types.contains(&pa::ENC_TIMESTAMP),
        "kdc.conf and krb5.conf disables both apply: {types:?}"
    );
    assert!(types.contains(&pa::FX_FAST), "FX-FAST stays: {types:?}");
}

#[test]
fn disable_encrypted_challenge_ignores_type_138_outside_fast() {
    let store =
        realm("[plugins]\n    kdcpreauth = {\n        disable = encrypted_challenge\n    }\n");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(
        cname,
        TEST_REALM,
        71_050,
        Some(vec![PaData {
            padata_type: pa::ENCRYPTED_CHALLENGE,
            padata_value: b"outside-fast".to_vec().into(),
        }]),
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let Error::PreauthRequired { e_data } = err else {
        panic!("a disabled encrypted_challenge is ignored, got {err:?}");
    };
    let method: MethodData = decode(&e_data).unwrap();
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert!(
        types.contains(&pa::ENC_TIMESTAMP) && types.contains(&pa::FX_FAST),
        "the other modules stay offered: {types:?}"
    );
}
