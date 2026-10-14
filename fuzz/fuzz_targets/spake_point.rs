#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for group in krb5_crypto::SpakeGroup::ALL {
        let _ = krb5_crypto::spake_decode_point(group, data);
        let _ = krb5_crypto::spake_result(group, &[1u8; 32], &[2u8; 32], data, true);
    }
});
