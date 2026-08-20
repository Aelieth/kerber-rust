#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krb5_asn1::decode::<krb5_types::AsReq>(data);
    let _ = krb5_asn1::decode::<krb5_types::TgsReq>(data);
    let _ = krb5_asn1::decode::<krb5_types::AsRep>(data);
    let _ = krb5_asn1::decode::<krb5_types::TgsRep>(data);
    let _ = krb5_asn1::decode::<krb5_types::KrbError>(data);
    let _ = krb5_asn1::decode::<krb5_types::Ticket>(data);
});
