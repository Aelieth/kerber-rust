#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krb5_protocol::Keytab::parse(data);
    if let Ok(cc) = krb5_protocol::FileCcache::parse(data) {
        let _ = cc.to_bytes();
    }
});
