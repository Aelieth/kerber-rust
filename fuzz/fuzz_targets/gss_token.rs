#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fuzz_target!(|data: &[u8]| {
    static RCACHE: OnceLock<krb5_protocol::ReplayCache> = OnceLock::new();
    static CONF: OnceLock<krb5_protocol::AcceptorConfig> = OnceLock::new();
    static KEY: OnceLock<krb5_crypto::ProtocolKey> = OnceLock::new();
    let rcache = RCACHE.get_or_init(krb5_protocol::ReplayCache::new);
    let conf = CONF.get_or_init(krb5_protocol::AcceptorConfig::default);
    let key = KEY.get_or_init(|| {
        let et = krb5_crypto::EncryptionType::Aes256CtsHmacSha196;
        krb5_crypto::ProtocolKey::from_bytes(et, &[0x5a; 32]).unwrap()
    });
    let keys = std::slice::from_ref(key);
    let _ = krb5_gss::spnego_inner(data);
    let _ = krb5_gss::GssContext::accept_sec_context(data, keys, None, None, None, rcache, conf);
    let _ = krb5_gss::spnego_accept(data, keys, None, None, None, rcache, conf);
});
