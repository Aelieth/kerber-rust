#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fuzz_target!(|data: &[u8]| {
    static RCACHE: OnceLock<krb5_protocol::ReplayCache> = OnceLock::new();
    static CONF: OnceLock<krb5_protocol::AcceptorConfig> = OnceLock::new();
    let rcache = RCACHE.get_or_init(krb5_protocol::ReplayCache::new);
    let conf = CONF.get_or_init(krb5_protocol::AcceptorConfig::default);
    let _ = krb5_gss::spnego_inner(data);
    let _ = krb5_gss::GssContext::accept_sec_context(data, &[], None, None, None, rcache, conf);
});
