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
//!
//! The public surface is the names this root re-exports, plus `principals`
//! and `testrealm`. Every other module stays private.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod acl;
mod ad;
mod audit;
mod create;
mod daemon;
mod dblock;
mod der;
mod error;
mod issue;
mod kdb;
mod kdb_dump;
mod listen;
mod lockout;
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
mod ulog;

pub use acl::{Acl, AdminOp, Restrictions, kadmin_flagspec};
pub use ad::{
    PacTicket, decrypt_ticket_part, pac_from_ticket_part, should_have_ticket_signature, sign_pac,
    sign_reply_pac, ticket_checksum_der, verify_pac, verify_pac_signatures, wrap_win2k_pac,
};
pub use audit::{
    AUTHN_REQ_CL, AuditState, ENCR_REP, JsonAudit, KdcAudit, REQID_LEN, SRVC_PRINC,
    clear_thread_audit, current_audit, enctype_name, ktypes2str, make_tkt_id, new_req_id,
    rep_etypes2str, set_audit, set_thread_audit,
};
#[cfg(feature = "test-hooks")]
pub use create::seed_test_principals;
pub use create::{create_realm, kdc_conf_for_realm};
pub use daemon::{
    OpenFailure, Signals, database_path, detach, names_relative_database, open_database,
    write_pid_file,
};
pub use dblock::{
    DbAge, DbLock, DbLockError, DbLockHold, DbLockMode, FileLockGuard, SUFFIX_LOCK,
    SUFFIX_POLICY_LOCK, lock_file_exclusive, suffixed,
};
pub use error::Error;
pub(crate) use issue::kdc_error_bytes;
pub use issue::{
    IssuedAs, IssuedTgs, handle_request, handle_request_from, issue_as, issue_tgs,
    tgs_header_is_crossrealm,
};
pub use kdb::{
    KdcEnv, MemoryStore, PrincipalRead, PrincipalWrite, Store, StoreLifecycle, lookup_principal_id,
    open_store,
};
pub use kdb_dump::{
    DumpError, DumpFile, DumpKeyData, DumpKeySlot, DumpPrincipal, IpropHeaderError,
    KDB_DUMP_VERSION, TL_ALIAS_TARGET, TL_DB_ARGS, TL_KADM_DATA, TL_KERBER_HIST, TL_KERBER_SERIAL,
    TL_KERBER_SID, TL_LAST_ADMIN_UNLOCK, TL_LAST_PWD_CHANGE, TL_MOD_PRINC, TL_STRING_ATTRS,
    dump_store, dump_store_iprop, dump_store_iprop_with_key, dump_store_with_key, load_dump,
    load_dump_etype, load_dump_path, load_dump_with_key, parse_dump, parse_iprop_header,
    tl_mod_princ_name, update_store, write_dump_path_etype,
};
pub use listen::{
    BIND_CANDIDATES, ClosingFd, ConnGuard, ConnRegistry, Datagram, ListenLimits, MAX_DGRAM_REPLY,
    MAX_TCP_REQUEST, MAX_TCP_WORKERS, PktInfo, SharedDump, SharedStore, WHILE_DISPATCHING_TCP,
    WHILE_DISPATCHING_UDP, bind_preferred, bind_rpc_listeners, bind_tcp_listeners,
    bind_udp_listeners, drop_privileges, recv_from_to, send_udp_reply, serve, serve_all,
    serve_all_until, serve_until, shared_dump, shared_store, wait_for_connection,
};
pub use lockout::{
    Lockout, LockoutUpdate, SUFFIX_LOCKOUT, lockout_path, lockout_records, merge_lockout_file,
};
pub use mkey::{default_master_etype, master_etype, master_key_from_password, string_to_enctype};
pub use osa::{
    KADM5_POLICY, OsaError, OsaKeyData, OsaPrincEnt, decrypt_entry as decrypt_history_entry,
    history_entry as encrypt_history_entry,
};
pub use persist::{
    CreateError, DbUpdate, DbWrite, FullLoad, LoadError, LoadLog, PersistError, Unopenable,
    check_database, check_openable, create_store, load_dump_with_stash, load_store,
    load_store_full, load_store_with_master, load_text_full, read_db_and_lockout_locked,
    read_db_locked, read_stash, save_dump_text, save_store, save_store_fresh,
    save_store_legacy_kdb3, save_store_with_master, stash_keys, write_stash,
};
pub use plugins::{
    KdcAuthdata, KdcPolicy, KdcPreauth, PolicyAdjustment, PreauthAction, PreauthHint, PreauthRock,
    apply_policy_times, clear_thread_authdata, clear_thread_policy, clear_thread_preauth,
    current_policy, register_authdata, register_preauth, set_policy, set_thread_authdata,
    set_thread_policy, set_thread_preauth,
};
pub use store::{
    AT_ATTRFLAGS, AT_EXP, AT_FAIL_AUTH_COUNT, AT_KEYDATA, AT_LAST_FAILED, AT_LAST_SUCCESS, AT_LEN,
    AT_MAX_LIFE, AT_MAX_RENEW_LIFE, AT_MOD_PRINC, AT_MOD_TIME, AT_MOD_WHERE, AT_PRINC, AT_PW_EXP,
    AT_PW_HIST, AT_PW_HIST_KVNO, AT_PW_LAST_CHANGE, AT_PW_POLICY, AT_PW_POLICY_SWITCH, AT_TL_DATA,
    IncrLayout, IpropRole, IpropUpdate, KdbeVal, KeyWrap, LoggedWrite, PreparedLog, ULOG_ADD_ATTRS,
    UlogTime, XdrError, attr_bit, conv_2dbentry, conv_2logentry, decode_incr_update,
    decode_kdbe_bytes, encode_incr_update, encode_kdbe, walk_incr_update,
};
pub use store::{
    AdminEnt, AdminFields, IPROP_ERROR, IPROP_FULL_RESYNC, IPROP_NIL, IPROP_OK, IPROP_PERM_DENIED,
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_POSTDATED,
    KDB_DISALLOW_RENEWABLE, KDB_DISALLOW_SVR, KDB_DISALLOW_TGT_BASED, KDB_LOCKDOWN_KEYS,
    KDB_NO_AUTH_DATA_REQUIRED, KDB_OK_AS_DELEGATE, KDB_OK_TO_AUTH_AS_DELEGATE,
    KDB_PWCHANGE_SERVICE, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PRE_AUTH, KDB_REQUIRES_PWCHANGE,
    KDB_V1_BASE_LENGTH, KadmData, KeyEntry, KeyLookup, MAX_ALIAS_DEPTH, NamedPolicy, PWQUAL_DICT,
    PWQUAL_EMPTY, PWQUAL_PRINC, Policy, Principal, PrincipalStore, RID_FIRST_USER, RID_KRBTGT,
    S2K_ITERS, SpakeKdc, TlData, apply_keysalt_policy, kadm5_mask, random_key, s2k_params,
    strip_db_args,
};
#[cfg(any(test, feature = "test-hooks"))]
pub use ulog::UlogEntry;
pub use ulog::{
    KDB_STABLE, KDB_ULOG_HDR_MAGIC, KDB_ULOG_MAGIC, KDB_UNSTABLE, KDB_VERSION, MAXLOGLEN,
    ULOG_BLOCK, Ulog, UlogBatch, UlogError, UlogHeader, UlogLast, UlogUpdates,
};

use krb5_types::PrincipalName;
use testrealm::{TEST_ADMIN, documented_kiprop};

/// `admin@<realm>` actor string used by kadmind when no `acl_file` is set.
#[must_use]
pub(crate) fn admin_id_for_realm(realm: &str) -> String {
    format!("{TEST_ADMIN}@{realm}")
}

/// `kdb5_util@<realm>` — `kadm5_init(context, progname, …)` when
/// `kdb5_util create` seeds `kadmin/admin` and `kadmin/changepw`.
/// MIT `kadm5_create_magic_princs` (`kadm5_create.c:100-100`): `kadm5_init` is called
/// with `progname` as the client name, before the admin principals are added.
#[must_use]
pub(crate) fn kdb5_util_id_for_realm(realm: &str) -> String {
    format!("kdb5_util@{realm}")
}

/// `host/testhost.<realm-as-dns>` as NT-SRV-HST.
#[must_use]
pub(crate) fn host_for_realm(realm: &str) -> PrincipalName {
    let inst = format!("testhost.{}", realm.to_ascii_lowercase());
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", inst.as_str()])
}

/// Default `acl_file`.
/// MIT `DEFAULT_KADM5_ACL_FILE` (`osconf.hin:106-106`): `KDC_DIR "/kadm5.acl"`.
#[must_use]
pub fn default_acl_path(kdc_dir: &std::path::Path) -> std::path::PathBuf {
    kdc_dir.join("kadm5.acl")
}

/// Load `acl_file` (`auth_acl.c` `acl_init` / `load_acl_file`): the file's bytes, as MIT's
/// `fgets` reads them, whether or not they are UTF-8. A directory opens, and its first read fails,
/// which MIT's `get_line` takes for the end: an ACL with no line.
///
/// `None` or an empty path is self-only.
/// MIT `main` (`ovsec_kadmd.c:497-497`): an empty `acl_file` becomes NULL.
/// MIT `acl_init` (`auth_acl.c:554-555`): a NULL ACL file → `KRB5_PLUGIN_NO_HANDLE`.
/// MIT `load_acl_file` (`auth_acl.c:398-405`): a file that does not open is logged as
/// `<strerror> while opening ACL file <fname>`, and the context's message is `Cannot open`.
///
/// # Errors
///
/// [`Error::AclParse`] when the file does not open or a line does not load. Its lines but the
/// last are what MIT logs (`parse_entry`'s message, `load_acl_file`'s); the last is the line
/// MIT's `fail_to_start` prints and logs: `Cannot open FNAME: <strerror>`, or `FNAME: syntax
/// error at line N <…>`, then ` while initializing ACL file, aborting`.
pub fn acl_for_store(realm: &str, acl_file: Option<&std::path::Path>) -> Result<Acl, Error> {
    let Some(path) = acl_file else {
        return Ok(Acl::none());
    };
    if path.as_os_str().is_empty() {
        return Ok(Acl::none());
    }
    let fname = path.display().to_string();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::IsADirectory => Vec::new(),
        Err(e) => {
            let text = e.to_string();
            let why = text
                .rsplit_once(" (os error ")
                .map_or(text.as_str(), |(t, _)| t);
            return Err(Error::AclParse(format!(
                "{why} while opening ACL file {fname}\n\
                 Cannot open {fname}: {why} while initializing ACL file, aborting"
            )));
        }
    };
    Acl::parse_located(&bytes, realm, &fname).map_err(|e| {
        let located = e.located(&fname);
        let logged = e.message.map(|m| format!("{m}\n")).unwrap_or_default();
        Error::AclParse(format!(
            "{logged}{located}\n{located} while initializing ACL file, aborting"
        ))
    })
}

/// Bootstrap a named realm: krbtgt, user, admin, host, `kadmin/admin`, `kadmin/changepw`.
///
/// # Errors
///
/// [`Error::PasswordPolicy`] when `user_password` or `admin_password` is empty,
/// [`Error::AlreadyExists`] when `user` and `admin` are the same name, [`Error::AclParse`] when
/// `admin@<realm>` is not a principal name (a realm with `/` or `@`), and [`Error::Rng`] when the
/// CSPRNG fails while generating a random key.
pub(crate) fn bootstrap_realm(
    realm: &str,
    user: &str,
    user_password: &[u8],
    admin: &str,
    admin_password: &[u8],
) -> Result<(PrincipalStore, Acl), Error> {
    bootstrap_realm_with_kdc_conf(realm, user, user_password, admin, admin_password, None)
}

/// `bootstrap_realm` honouring `kdc.conf` `supported_enctypes`.
///
/// # Errors
///
/// [`Error::Crypto`] when `kdc` sets a `domain_sid` that is not valid SDDL,
/// [`Error::PasswordPolicy`] when `user_password` or `admin_password` is empty,
/// [`Error::AlreadyExists`] when `user` and `admin` are the same name, [`Error::AclParse`] when
/// `admin@<realm>` is not a principal name (a realm with `/` or `@`), and [`Error::Rng`] when the
/// CSPRNG fails while generating a random key.
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

/// MIT `ADMIN_LIFETIME` (`kadm5_create.c:54-54`): `60*60*3`, three hours.
const KADM5_ADMIN_LIFETIME: u64 = 60 * 60 * 3;
/// MIT `CHANGEPW_LIFETIME` (`kadm5_create.c:55-55`): `60*5`, five minutes.
const KADM5_CHANGEPW_LIFETIME: u64 = 60 * 5;

/// MIT `kadm5_create` (`kadm5_create.c`) flags. `create_principal` does not set these.
///
/// # Errors
///
/// [`Error::NotFound`] when `kadmin/admin` or `kadmin/changepw` is missing, and [`Error::Db`]
/// when the store's configured file cannot be written after an update.
pub fn apply_kadm5_create_service_attrs(store: &mut PrincipalStore) -> Result<(), Error> {
    let realm = store.realm().to_owned();
    let actor = kdb5_util_id_for_realm(&realm);
    store.apply_admin_fields_in(
        &principals::kadmin_admin(),
        &realm,
        AdminFields {
            attributes: Some(store::KDB_DISALLOW_TGT_BASED | store::KDB_LOCKDOWN_KEYS),
            max_life: Some(KADM5_ADMIN_LIFETIME),
            expiration: None,
            pw_expire: None,
            policy: None,
            clear_policy: false,
            max_renewable_life: None,
        },
        &actor,
    )?;
    store.apply_admin_fields_in(
        &principals::kadmin_changepw(),
        &realm,
        AdminFields {
            attributes: Some(
                store::KDB_DISALLOW_TGT_BASED
                    | store::KDB_PWCHANGE_SERVICE
                    | store::KDB_LOCKDOWN_KEYS,
            ),
            max_life: Some(KADM5_CHANGEPW_LIFETIME),
            expiration: None,
            pw_expire: None,
            policy: None,
            clear_policy: false,
            max_renewable_life: None,
        },
        &actor,
    )?;
    Ok(())
}
