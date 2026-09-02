#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krb5_gss::spnego_inner(data);
    let _ = krb5_gss::GssContext::accept_sec_context(
        data,
        &[],
        None,
        None,
        None,
        &krb5_protocol::ReplayCache::new(),
    );
});
