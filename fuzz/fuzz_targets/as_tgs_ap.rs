#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krb5_asn1::decode::<krb5_types::AsReq>(data);
    let _ = krb5_asn1::decode::<krb5_types::TgsReq>(data);
    let _ = krb5_asn1::decode::<krb5_types::ApReq>(data);
    let _ = krb5_asn1::decode::<krb5_types::ApRep>(data);
});
