//! KDB keytab. `GSS_C_NO_NAME`: ticket's server. Named: that principal's key only.

use std::io;

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_gss::{ChannelBindings, GssContext};
use krb5_kdc::principals::{kadmin_admin, kadmin_changepw};
use krb5_kdc::{PrincipalStore, SharedDump as SharedStore, ktkdb_get_entry};
use krb5_log::klog::Severity;
use krb5_protocol::{
    AcceptorConfig, ApVerifyOk, ApVerifyParams, KeytabLookup, ReplayCache, verify_ap_req_ex,
};
use krb5_types::PrincipalName;

// MIT: `krb5_db2_get_principal` (plugins/kdb/db2/kdb_db2.c:769-773)
/// The keytab lookup takes the shared lock and fails if it cannot.
fn kdb_keytab_entry(
    store: &SharedStore,
    name: &PrincipalName,
    realm: &str,
    kvno: u32,
    etype: i32,
    permitted: &[EncryptionType],
) -> Result<ProtocolKey, KeytabLookup> {
    let (g, read) = krb5_kdc::read_fresh(store);
    if let Err(e) = read {
        crate::kadmind::admin_syslog(Severity::Err, &format!("{e} while reloading database"));
        return Err(KeytabLookup::Other(krb5_protocol::Error::Io {
            message: e.to_string(),
            kind: io::ErrorKind::Other,
            retryable: false,
        }));
    }
    ktkdb_get_entry(g.get_in_realm(name, realm), name, realm, kvno, etype, |e| {
        permitted.contains(&e)
    })
    .map(|entry| entry.key.clone())
    .map_err(KeytabLookup::from)
}

// MIT: `kg_accept_krb5` (lib/gssapi/krb5/accept_sec_context.c:829-831)
pub(super) fn accept_from_kdb(
    store: &SharedStore,
    realm: &str,
    acceptor: Option<&PrincipalName>,
    token: &[u8],
    bindings: Option<&ChannelBindings>,
    rcache: &ReplayCache,
    conf: &AcceptorConfig,
) -> Result<(GssContext, Option<Vec<u8>>), krb5_gss::Error> {
    let permitted = conf.permitted()?;
    let get_entry = kdb_get_entry(store, permitted);
    GssContext::accept_sec_context_kdb(token, acceptor, realm, &get_entry, bindings, rcache, conf)
}

fn kdb_get_entry<'a>(
    store: &'a SharedStore,
    permitted: &'a [EncryptionType],
) -> impl Fn(&PrincipalName, &str, u32, i32) -> Result<ProtocolKey, KeytabLookup> + 'a {
    move |name, server_realm, kvno, etype| {
        kdb_keytab_entry(store, name, server_realm, kvno, etype, permitted)
    }
}

/// No GSS layer.
pub fn kdb_rd_req(
    store: &SharedStore,
    realm: &str,
    acceptor: Option<&PrincipalName>,
    conf: &AcceptorConfig,
    ap_req: &[u8],
    rcache: &ReplayCache,
) -> Result<ApVerifyOk, krb5_protocol::Error> {
    let permitted = conf.permitted()?;
    let get_entry = kdb_get_entry(store, permitted);
    let params = ApVerifyParams {
        keys: &[],
        key_kvnos: None,
        key_principals: None,
        kvno: None,
        permitted,
        expected_server: acceptor,
        expected_realm: Some(realm),
        get_entry: Some(&get_entry),
        skew: i64::from(conf.clockskew),
        ignore_acceptor_hostname: conf.ignore_acceptor_hostname,
        capaths: &conf.capaths,
        remote_addr: None,
        now: None,
    };
    verify_ap_req_ex(ap_req, &params, rcache, None)
}

// MIT: `gssrpc__svcauth_gssapi` (lib/rpc/svc_auth_gssapi.c:391-436)
pub(super) fn accept_auth_gssapi(
    store: &SharedStore,
    realm: &str,
    token: &[u8],
    bindings: Option<&ChannelBindings>,
    rcache: &ReplayCache,
    conf: &AcceptorConfig,
) -> Result<(GssContext, Option<Vec<u8>>), krb5_gss::Error> {
    let mut result = Err(krb5_gss::Error::Truncated);
    for name in [kadmin_admin(), kadmin_changepw()] {
        result = accept_from_kdb(store, realm, Some(&name), token, bindings, rcache, conf);
        if !matches!(result, Err(krb5_gss::Error::NotUs(_))) {
            break;
        }
    }
    result
}

// MIT: `check_keytab` (lib/gssapi/krb5/acquire_cred.c:126-138)
#[must_use]
pub fn acceptor_names_served(store: &PrincipalStore, conf: &AcceptorConfig) -> bool {
    let Ok(permitted) = conf.permitted() else {
        return false;
    };
    let realm = store.realm();
    [kadmin_admin(), kadmin_changepw()].iter().all(|name| {
        ktkdb_get_entry(store.get_in_realm(name, realm), name, realm, 0, 0, |e| {
            permitted.contains(&e)
        })
        .is_ok()
    })
}
