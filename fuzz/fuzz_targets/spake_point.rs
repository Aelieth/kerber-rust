#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krb5_crypto::spake_decode_point(data);
    let _ = krb5_crypto::spake_result_wbytes(&[1u8; 32], &[2u8; 32], data, true);
});
