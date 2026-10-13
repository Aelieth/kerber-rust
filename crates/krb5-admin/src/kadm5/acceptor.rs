//! kadmind's acceptor keytab: the KDB, as MIT's GSS acceptor reads it. `setup_kdb_keytab` points
//! the GSS mechanism at the `KDB:` keytab, so a context is accepted with the key
//! `krb5_ktkdb_get_entry` gives the ticket's server (RPCSEC_GSS, accepted with `GSS_C_NO_NAME`),
//! or the key of each name `svcauth_gssapi_set_names` was given (AUTH_GSSAPI): never with a key
//! the database holds for another principal, enctype or key version.

use std::io;
use std::sync::PoisonError;

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_gss::{ChannelBindings, GssContext};
use krb5_kdc::principals::{kadmin_admin, kadmin_changepw};
use krb5_kdc::{PrincipalStore, SharedDump as SharedStore, ktkdb_get_entry};
use krb5_log::klog::{self, Severity};
use krb5_protocol::{KeytabLookup, ReplayCache};
use krb5_types::PrincipalName;

/// The KDB keytab's lookup for one ticket, under the database's lock.
/// MIT `krb5_ktkdb_get_entry` (`lib/kdb/keytab.c:117-185`): the principal's first permitted key at the ticket's kvno, whatever the ticket's enctype, which must then be similar to it.
/// MIT `krb5_db2_get_principal` (`plugins/kdb/db2/kdb_db2.c:769-773`): the lookup takes the shared lock, reads the database again when it changed, and fails when it cannot.
fn kdb_keytab_entry(
    store: &SharedStore,
    name: &PrincipalName,
    realm: &str,
    kvno: u32,
    etype: i32,
    permitted: &[EncryptionType],
) -> Result<ProtocolKey, KeytabLookup> {
    let mut g = store.write().unwrap_or_else(PoisonError::into_inner);
    if let Err(e) = g.reload_if_stale() {
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

/// A context accepted from `token` with the key the KDB keytab gives: for `acceptor`, or, with no
/// name (`GSS_C_NO_NAME`), for the server the ticket names.
/// MIT `kg_accept_krb5` (`lib/gssapi/krb5/accept_sec_context.c:829-831`): `krb5_rd_req_decoded` takes the credential's `acceptor_mprinc` (NULL for no name) and its keytab.
pub(super) fn accept_from_kdb(
    store: &SharedStore,
    realm: &str,
    acceptor: Option<&PrincipalName>,
    token: &[u8],
    bindings: Option<&ChannelBindings>,
    rcache: &ReplayCache,
) -> Result<(GssContext, Option<Vec<u8>>), krb5_gss::Error> {
    let permitted = GssContext::acceptor_permitted_enctypes()?;
    let get_entry = |name: &PrincipalName, server_realm: &str, kvno: u32, etype: i32| {
        kdb_keytab_entry(store, name, server_realm, kvno, etype, &permitted)
    };
    GssContext::accept_sec_context_kdb(token, acceptor, realm, &get_entry, bindings, rcache)
}

/// AUTH_GSSAPI's accept: `kadmin/admin`, then `kadmin/changepw`, each with a credential of its own
/// (the list `svcauth_gssapi_set_names` was given); the next name is tried only when the ticket is
/// for no principal the keytab serves under this one (`KRB5KRB_AP_ERR_NOT_US`).
/// MIT `main` (`kadmin/server/ovsec_kadmd.c:460-476`): the names are `kadmin/admin` and `kadmin/changepw` in `params.realm`.
/// MIT `gssrpc__svcauth_gssapi` (`lib/rpc/svc_auth_gssapi.c:391-436`): the loop over the credentials stops at the first that completes or fails otherwise than with `GSS_S_FAILURE` and `KRB5KRB_AP_ERR_NOT_US`.
pub(super) fn accept_auth_gssapi(
    store: &SharedStore,
    realm: &str,
    token: &[u8],
    bindings: Option<&ChannelBindings>,
    rcache: &ReplayCache,
) -> Result<(GssContext, Option<Vec<u8>>), krb5_gss::Error> {
    let mut result = Err(krb5_gss::Error::Truncated);
    for name in [kadmin_admin(), kadmin_changepw()] {
        result = accept_from_kdb(store, realm, Some(&name), token, bindings, rcache);
        if !matches!(result, Err(krb5_gss::Error::NotUs(_))) {
            break;
        }
    }
    result
}

/// Whether the KDB keytab serves both names AUTH_GSSAPI accepts, as `svcauth_gssapi_set_names`
/// needs of it before kadmind starts.
/// MIT `check_keytab` (`lib/gssapi/krb5/acquire_cred.c:126-138`): a credential for a name that is not host-based asks `krb5_kt_get_entry(kt, princ, 0, 0)` for it.
/// MIT `main` (`kadmin/server/ovsec_kadmd.c:476-477`): kadmind fails to start, "Cannot set GSSAPI authentication names", when a credential cannot be acquired.
#[must_use]
pub fn acceptor_names_served(store: &PrincipalStore) -> bool {
    let Ok(permitted) = GssContext::acceptor_permitted_enctypes() else {
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
