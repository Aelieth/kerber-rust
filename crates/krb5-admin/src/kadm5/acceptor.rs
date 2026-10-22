//! kadmind's acceptor keytab: the KDB, as MIT's GSS acceptor reads it. `setup_kdb_keytab` points the GSS mechanism at the `KDB:` keytab, so a context is accepted with the key `krb5_ktkdb_get_entry` gives the ticket's server (RPCSEC_GSS, accepted with `GSS_C_NO_NAME`), or the key of each name `svcauth_gssapi_set_names` was given (AUTH_GSSAPI): never with a key the database holds for another principal, enctype or key version.

use std::io;

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_gss::{ChannelBindings, GssContext};
use krb5_kdc::principals::{kadmin_admin, kadmin_changepw};
use krb5_kdc::{PrincipalStore, SharedDump as SharedStore, ktkdb_get_entry};
use krb5_log::klog::{self, Severity};
use krb5_protocol::{
    AcceptorConfig, ApVerifyOk, ApVerifyParams, KeytabLookup, ReplayCache, verify_ap_req_ex,
};
use krb5_types::PrincipalName;

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
        klog::syslog(Severity::Err, &format!("{e} while reloading database"));
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

/// A context accepted from `token` with the key the KDB keytab gives: for `acceptor`, or, with no name (`GSS_C_NO_NAME`), for the server the ticket names; `conf` is kadmind's KDC context's.
/// MIT `kg_accept_krb5` (`lib/gssapi/krb5/accept_sec_context.c:829-831`): `krb5_rd_req_decoded` takes the credential's `acceptor_mprinc` (NULL for no name) and its keytab.
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

/// `krb5_rd_req` as kadmind's GSS acceptor makes it, without the GSS layer: the AP-REQ `ap_req` against the KDB keytab for `acceptor` in `realm`, or, with none (`GSS_C_NO_NAME`), for the server the ticket names, on the profile values `conf` (the KDB gives keys of the enctypes it permits).
/// refuses the AP-REQ with: the lookup's codes as `keytab_fetch_error` maps them, a key that does not decrypt the ticket, and the ticket and authenticator checks.
pub fn kdb_rd_req(
    store: &SharedStore,
    realm: &str,
    acceptor: Option<&PrincipalName>,
    conf: &AcceptorConfig,
    ap_req: &[u8],
    rcache: &ReplayCache,
) -> Result<ApVerifyOk, krb5_protocol::Error> {
    let get_entry = kdb_get_entry(store, conf.permitted()?);
    let params = ApVerifyParams {
        keys: &[],
        key_kvnos: None,
        key_principals: None,
        kvno: None,
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

/// AUTH_GSSAPI's accept: `kadmin/admin`, then `kadmin/changepw`, each with a credential of its own (the list `svcauth_gssapi_set_names` was given); the next name is tried only when the ticket is for no principal the keytab serves under this one (`KRB5KRB_AP_ERR_NOT_US`).
/// MIT `gssrpc__svcauth_gssapi` (`lib/rpc/svc_auth_gssapi.c:391-436`): the loop over the credentials stops at the first that completes or fails otherwise than with `GSS_S_FAILURE` and `KRB5KRB_AP_ERR_NOT_US`.
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

/// MIT `check_keytab` (`lib/gssapi/krb5/acquire_cred.c:126-138`): a credential for a name that is not host-based asks `krb5_kt_get_entry(kt, princ, 0, 0)` for it.
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
