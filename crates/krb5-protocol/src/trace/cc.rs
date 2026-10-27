use krb5_types::PrincipalName;

use super::{
    Princ, cc_destroy, cc_get_config, cc_init, cc_move, cc_new_unique, cc_retrieve, cc_set_config,
    cc_store, enabled,
};
use crate::ccache::{CcacheCred, FileCcache};

// MIT: `krb5int_random_string` (lib/krb5/krb/random_str.c:37-68)
#[must_use]
pub(crate) fn random_string(len: usize) -> String {
    const CHARS: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut bytes = vec![0u8; len];
    if getrandom::getrandom(&mut bytes).is_err() {
        return "0".repeat(len);
    }
    bytes
        .iter()
        .map(|b| char::from(CHARS[usize::from(*b) % CHARS.len()]))
        .collect()
}

// MIT: `write_out_ccache` (lib/krb5/krb/get_in_tkt.c:1616-1663)
pub fn write_out_ccache(dest: &str, cc: &FileCcache) {
    if !enabled() {
        return;
    }
    let mcc = format!("MEMORY:{}", random_string(7));
    cc_new_unique("MEMORY");
    cc_init(&mcc, Princ::new(&cc.primary.1, cc.primary.0.as_bytes()));
    store_creds(&mcc, &cc.creds);
    cc_move(&mcc, dest);
    cc_destroy(&mcc);
}

// MIT: `krb5_cc_store_cred` (lib/krb5/ccache/ccfns.c:80-85)
// MIT: `krb5_cc_set_config` (lib/krb5/ccache/ccfns.c:236-261)
/// Configuration is traced, then again as the stored credential.
pub fn store_creds(cache: &str, creds: &[CcacheCred]) {
    if !enabled() {
        return;
    }
    for c in creds {
        if let Some((key, princ)) = config_key(c) {
            cc_set_config(cache, princ.as_deref(), &key, &c.ticket);
        }
        cc_store(
            cache,
            Princ::new(&c.client.1, c.client.0.as_bytes()),
            Princ::new(&c.server.1, c.server.0.as_bytes()),
        );
    }
}

fn config_key(c: &CcacheCred) -> Option<(String, Option<String>)> {
    if !c.is_config() {
        return None;
    }
    let comps = &c.server.1.name_string;
    let text = |i: usize| {
        comps
            .get(i)
            .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
    };
    Some((text(1)?, text(2)))
}

// MIT: `krb5_cc_get_config` (lib/krb5/ccache/ccfns.c:264-292)
pub fn get_config(
    cache: &str,
    client: Princ<'_>,
    princ: Option<&str>,
    key: &str,
    found: Option<&[u8]>,
    not_found: &str,
) {
    if !enabled() {
        return;
    }
    let mut comps = vec!["krb5_ccache_conf_data", key];
    if let Some(p) = princ {
        comps.push(p);
    }
    let server = PrincipalName::new(PrincipalName::NT_UNKNOWN, comps);
    let server = Princ::new(&server, b"X-CACHECONF:");
    match found {
        Some(data) => {
            cc_retrieve(cache, Some(client), server, 0, None);
            cc_get_config(cache, princ, key, data);
        }
        None => cc_retrieve(
            cache,
            Some(client),
            server,
            super::KRB5_CC_NOTFOUND,
            Some(not_found),
        ),
    }
}
