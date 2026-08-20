#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krb5_types::pac::Pac::parse(data);
    let _ = krb5_types::pac::parse_logon_info(data);
});
