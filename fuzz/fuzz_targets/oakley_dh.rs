#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krb5_crypto::dh_group_for_prime(data);
    let _ = krb5_crypto::dh_shared(&krb5_crypto::OAKLEY_2048, data.get(..32).unwrap_or(data), data);
});
