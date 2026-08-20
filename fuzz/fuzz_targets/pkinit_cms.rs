#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krb5_types::pkinit::parse_pa_pk_as_req_cms(data);
    let _ = krb5_types::pkinit::parse_authpack(data);
    let _ = krb5_types::pkinit::parse_dh_spki(data);
    let _ = krb5_types::pkinit::cms_unwrap(data);
});
