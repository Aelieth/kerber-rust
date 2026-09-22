//! Pure-Rust Kerberos V5 KDC graded against MIT 1.22.2.
//!
//! AS/TGS issue (`issue`), preauth — PA-ENC-TIMESTAMP, encrypted challenge,
//! PKINIT with RFC 8070 freshness and RFC 8062 anonymity, SPAKE, FAST
//! (`preauth`), the kdcpreauth / kdcpolicy registries (`plugins`), PAC and
//! S4U2Self / S4U2Proxy (`ad`), the MIT ISSUE tuple + audit plugin (`audit`),
//! KDB traits and the in-memory store (`kdb`, `store`), `kdb5_util` dump v7
//! at rest (`kdb_dump`, `persist`), master-key stash (`mkey`), the lookaside
//! reply cache (`lookaside`), ACL-gated admin (`acl`), keytab export, the
//! documented test realm (`testrealm`), and MIT kadm5 names (`principals`).
//! Ticket issuance, ACL checks, and keytab export are pure functions so tests
//! do not need a bound socket. UDP/TCP 88 is a thin listener over
//! [`handle_request`]. There is no C FFI.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod acl;
mod ad;
mod audit;
mod error;
mod issue;
mod kdb;
mod kdb_dump;
mod listen;
mod lookaside;
mod mkey;
mod osa;
mod persist;
mod plugins;
mod preauth;
pub mod principals;
mod status;
mod store;
pub mod testrealm;

pub use acl::{Acl, AclEntry, AdminOp, Restrictions, kadmin_flagspec};
pub use ad::{
    PacTicket, decrypt_ticket_part, pac_from_ticket_part, should_have_ticket_signature, sign_pac,
    sign_reply_pac, ticket_checksum_der, verify_pac, verify_pac_signatures, wrap_win2k_pac,
};
pub use audit::{
    AUTHN_REQ_CL, AuditState, ENCR_REP, JsonAudit, KdcAudit, REQID_LEN, SRVC_PRINC,
    clear_thread_audit, current_audit, enctype_name, ktypes2str, make_tkt_id, new_req_id,
    rep_etypes2str, set_audit, set_thread_audit,
};
pub use error::Error;
pub use issue::{
    IssuedAs, IssuedTgs, handle_request, handle_request_from, issue_as, issue_tgs, kdc_error_bytes,
    tgs_header_is_crossrealm,
};
pub use kdb::{
    KdcEnv, MemoryStore, PrincipalRead, PrincipalWrite, Store, StoreLifecycle, lookup_principal_id,
    open_store,
};
pub use kdb_dump::{
    DumpError, DumpFile, DumpKeyData, DumpKeySlot, DumpPrincipal, KDB_DUMP_VERSION,
    TL_ALIAS_TARGET, TL_DB_ARGS, TL_KADM_DATA, TL_KERBER_HIST, TL_KERBER_SERIAL, TL_KERBER_SID,
    TL_LAST_ADMIN_UNLOCK, TL_LAST_PWD_CHANGE, TL_MOD_PRINC, TL_STRING_ATTRS, dump_store,
    dump_store_iprop, load_dump, load_dump_etype, load_dump_path, parse_dump, tl_mod_princ_name,
    write_dump_path_etype,
};
pub use listen::{
    BIND_CANDIDATES, ConnGuard, ConnRegistry, ListenLimits, MAX_DGRAM_REPLY, MAX_TCP_REQUEST,
    MAX_TCP_WORKERS, SharedDump, SharedStore, WHILE_DISPATCHING_TCP, WHILE_DISPATCHING_UDP,
    bind_preferred, drop_privileges, serve, serve_until, shared_dump, shared_store,
};
pub use mkey::{MASTER_NAME, default_master_etype, master_key_from_password};
pub use osa::{
    INITIAL_HIST_KVNO, KADM5_POLICY, OsaError, OsaKeyData, OsaPrincEnt,
    decrypt_entry as decrypt_history_entry, history_entry as encrypt_history_entry,
};
pub use persist::{PersistError, load_store, save_store, save_store_legacy_kdb3};
pub use plugins::{
    KdcAuthdata, KdcPolicy, KdcPreauth, PolicyAdjustment, PreauthAction, apply_policy_times,
    clear_thread_policy, current_policy, register_authdata, register_preauth, set_policy,
    set_thread_policy,
};
pub use store::{
    AdminEnt, IPROP_ERROR, IPROP_FULL_RESYNC, IPROP_NIL, IPROP_OK, IPROP_PERM_DENIED,
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_POSTDATED,
    KDB_DISALLOW_PROXIABLE, KDB_DISALLOW_RENEWABLE, KDB_DISALLOW_SVR, KDB_DISALLOW_TGT_BASED,
    KDB_LOCKDOWN_KEYS, KDB_NO_AUTH_DATA_REQUIRED, KDB_OK_AS_DELEGATE, KDB_OK_TO_AUTH_AS_DELEGATE,
    KDB_PWCHANGE_SERVICE, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PRE_AUTH, KDB_REQUIRES_PWCHANGE,
    KDB_V1_BASE_LENGTH, KadmData, KeyEntry, KeyLookup, MAX_ALIAS_DEPTH, NamedPolicy, PWQUAL_DICT,
    PWQUAL_EMPTY, PWQUAL_PRINC, Policy, Principal, PrincipalStore, RID_ADMINISTRATOR,
    RID_FIRST_USER, RID_KRBTGT, S2K_ITERS, TlData, UlogEntry, apply_keysalt_policy,
    db_args_put_error, kadm5_mask, parse_dict_words, parse_spake_preauth_groups, random_key,
    s2k_params, strip_db_args,
};

use krb5_types::PrincipalName;
use testrealm::{TEST_ADMIN, documented_kiprop};

/// `admin@<realm>` actor string used by kadmind when no `acl_file` is set.
#[must_use]
pub fn admin_id_for_realm(realm: &str) -> String {
    format!("{TEST_ADMIN}@{realm}")
}

/// `kdb5_util@<realm>` — `kadm5_init(context, progname, …)` when
/// `kdb5_util create` seeds `kadmin/admin` and `kadmin/changepw`
/// (`kadm5_create.c:100`).
#[must_use]
pub fn kdb5_util_id_for_realm(realm: &str) -> String {
    format!("kdb5_util@{realm}")
}

/// `host/testhost.<realm-as-dns>` as NT-SRV-HST.
#[must_use]
pub fn host_for_realm(realm: &str) -> PrincipalName {
    let inst = format!("testhost.{}", realm.to_ascii_lowercase());
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", inst.as_str()])
}

/// Default `acl_file` (`osconf.hin:106` `KDC_DIR "/kadm5.acl"`).
#[must_use]
pub fn default_acl_path(kdc_dir: &std::path::Path) -> std::path::PathBuf {
    kdc_dir.join("kadm5.acl")
}

/// Load `acl_file` (`auth_acl.c` `acl_init` / `load_acl_file`).
///
/// `None` or an empty path is self-only (`ovsec_kadmd.c:497` empty → NULL;
/// `acl_init` `:554-555` → `KRB5_PLUGIN_NO_HANDLE`). A missing path is MIT
/// `Cannot open … while initializing ACL file`.
///
/// # Errors
///
/// [`Error::AclParse`] when the file cannot be read or does not load.
pub fn acl_for_store(realm: &str, acl_file: Option<&std::path::Path>) -> Result<Acl, Error> {
    let Some(path) = acl_file else {
        return Ok(Acl::none());
    };
    if path.as_os_str().is_empty() {
        return Ok(Acl::none());
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            let why = if e.kind() == std::io::ErrorKind::NotFound {
                "No such file or directory".to_string()
            } else {
                e.to_string()
            };
            return Err(Error::AclParse(format!(
                "Cannot open {}: {why} while initializing ACL file, aborting",
                path.display()
            )));
        }
    };
    Acl::parse_located(&text, realm).map_err(|e| {
        let snippet: String = e.line.chars().take(10).collect();
        Error::AclParse(format!(
            "{}\n{}: syntax error at line {} <{snippet}...> while initializing ACL file, aborting",
            e.message,
            path.display(),
            e.lineno
        ))
    })
}

/// Bootstrap a named realm: krbtgt, user, admin, host, `kadmin/admin`, `kadmin/changepw`.
///
/// # Errors
///
/// Returns crypto failures from string-to-key or ACL-gated host create.
pub fn bootstrap_realm(
    realm: &str,
    user: &str,
    user_password: &[u8],
    admin: &str,
    admin_password: &[u8],
) -> Result<(PrincipalStore, Acl), Error> {
    bootstrap_realm_with_kdc_conf(realm, user, user_password, admin, admin_password, None)
}

/// [`bootstrap_realm`] honouring `kdc.conf` `supported_enctypes`.
///
/// # Errors
///
/// Returns crypto failures from string-to-key or ACL-gated host create.
pub fn bootstrap_realm_with_kdc_conf(
    realm: &str,
    user: &str,
    user_password: &[u8],
    admin: &str,
    admin_password: &[u8],
    kdc: Option<&krb5_config::KdcConf>,
) -> Result<(PrincipalStore, Acl), Error> {
    let mut store = PrincipalStore::bootstrap_with_kdc_conf(
        realm,
        user,
        user_password,
        admin,
        admin_password,
        kdc,
    )?;
    let actor = admin_id_for_realm(realm);
    let acl = Acl::allow_admin(&actor)?;
    store.create_host(&acl, &actor, &host_for_realm(realm))?;
    store.create_host(&acl, &actor, &principals::kadmin_admin())?;
    store.create_host(&acl, &actor, &principals::kadmin_changepw())?;
    store.create_host(&acl, &actor, &documented_kiprop())?;
    apply_kadm5_create_service_attrs(&mut store)?;
    Ok((store, acl))
}

/// MIT `kadm5_create.c:54` `ADMIN_LIFETIME`.
const KADM5_ADMIN_LIFETIME: u64 = 60 * 60 * 3;
/// MIT `kadm5_create.c:55` `CHANGEPW_LIFETIME`.
const KADM5_CHANGEPW_LIFETIME: u64 = 60 * 5;

/// MIT `kadm5_create` (`kadm5_create.c`) flags. `create_principal` does not set these.
///
/// # Errors
///
/// [`Error::NotFound`] when the kadmin principals are missing.
pub fn apply_kadm5_create_service_attrs(store: &mut PrincipalStore) -> Result<(), Error> {
    let realm = store.realm().to_owned();
    let actor = kdb5_util_id_for_realm(&realm);
    store.apply_admin_fields_in(
        &principals::kadmin_admin(),
        &realm,
        Some(store::KDB_DISALLOW_TGT_BASED | store::KDB_LOCKDOWN_KEYS),
        Some(KADM5_ADMIN_LIFETIME),
        None,
        None,
        None,
        false,
        None,
        &actor,
    )?;
    store.apply_admin_fields_in(
        &principals::kadmin_changepw(),
        &realm,
        Some(
            store::KDB_DISALLOW_TGT_BASED | store::KDB_PWCHANGE_SERVICE | store::KDB_LOCKDOWN_KEYS,
        ),
        Some(KADM5_CHANGEPW_LIFETIME),
        None,
        None,
        None,
        false,
        None,
        &actor,
    )?;
    Ok(())
}
