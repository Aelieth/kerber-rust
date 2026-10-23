//! The KDC library.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod acl;
mod ad;
mod asn1_text;
mod audit;
mod create;
mod daemon;
mod dblock;
mod der;
mod error;
mod issue;
mod kadm5_params;
mod kdb;
mod kdb_dump;
mod listen;
mod lockout;
mod lookaside;
mod mkey;
pub mod net_server;
mod osa;
mod persist;
mod pkinit;
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
    audit_kdc_start, audit_kdc_stop, clear_thread_audit, clear_thread_audits, current_audit,
    enctype_name, ktypes2str, make_tkt_id, new_req_id, register_audit, rep_etypes2str, set_audit,
    set_thread_audit, set_thread_audits,
};
#[cfg(feature = "test-hooks")]
pub use create::seed_test_principals;
pub use create::{add_admin_principals, create_realm, create_realm_db, kdc_conf_for_realm};
pub use daemon::{
    OpenFailure, Signals, copy_persist_master, database_path, detach, json_log_filter,
    kadmind_mkey_from_kbd, manual_master_key, mkey_log_context, names_relative_database,
    open_database, open_database_with_key, open_database_with_password, write_pid_file,
};
pub use dblock::{
    DbAge, DbLock, DbLockError, DbLockHold, DbLockMode, FileLockGuard, HeldFileLock, SUFFIX_LOCK,
    SUFFIX_POLICY_LOCK, lock_file_exclusive, lock_file_shared_nowait, suffixed,
};
pub use error::Error;
pub use issue::{
    IssuedAs, IssuedTgs, handle_request, handle_request_from, issue_as, issue_tgs,
    tgs_header_is_crossrealm,
};
pub use kadm5_params::{kadm5_params_missing, realm_kadm5_params_missing};
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
#[cfg(feature = "test-hooks")]
pub use listen::drop_privileges;
pub use listen::{
    BIND_CANDIDATES, DEFAULT_TCP_LISTEN_BACKLOG, Datagram, ListenLimits, MAX_DGRAM_REPLY,
    MAX_TCP_REQUEST, MAX_TCP_WORKERS, PktInfo, SharedDump, SharedStore, WHILE_DISPATCHING_TCP,
    WHILE_DISPATCHING_UDP, bind_preferred, bind_rpc_listeners, bind_tcp_listeners,
    bind_tcp_listeners_with_backlog, bind_udp_listeners, read_fresh, recv_from_to, send_udp_reply,
    serve, serve_all, serve_all_until, serve_daemon, serve_until, shared_dump, shared_store,
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
pub use pkinit::PkinitKdc;
pub use plugins::{
    KdcAuthdata, KdcPolicy, KdcPreauth, OtpVerdict, OtpVerifier, OtpVerifyRequest,
    PolicyAdjustment, PreauthAction, PreauthHint, PreauthRock, apply_policy_times,
    clear_thread_authdata, clear_thread_kdcpolicies, clear_thread_otp_verifiers,
    clear_thread_policy, clear_thread_preauth, current_policy, register_authdata,
    register_kdcpolicy, register_kdcpolicy_test_if_selected, register_otp_verifier,
    register_preauth, set_policy, set_thread_authdata, set_thread_kdcpolicies,
    set_thread_otp_verifiers, set_thread_policy, set_thread_preauth,
};
pub use plugins::{otp_startup_lines, preauth_startup_lines};
pub use store::{
    AT_ATTRFLAGS, AT_EXP, AT_FAIL_AUTH_COUNT, AT_KEYDATA, AT_LAST_FAILED, AT_LAST_SUCCESS, AT_LEN,
    AT_MAX_LIFE, AT_MAX_RENEW_LIFE, AT_MOD_PRINC, AT_MOD_TIME, AT_MOD_WHERE, AT_PRINC, AT_PW_EXP,
    AT_PW_HIST, AT_PW_HIST_KVNO, AT_PW_LAST_CHANGE, AT_PW_POLICY, AT_PW_POLICY_SWITCH, AT_TL_DATA,
    IncrLayout, IpropRole, IpropUpdate, KdbeVal, KeyWrap, LoggedWrite, PreparedLog, ULOG_ADD_ATTRS,
    UlogTime, XdrError, attr_bit, conv_2dbentry, conv_2logentry, decode_incr_update,
    decode_kdbe_bytes, encode_incr_update, encode_kdbe, walk_incr_update,
};
pub use store::{
    AdminEnt, AdminFields, HookStage, IPROP_ERROR, IPROP_FULL_RESYNC, IPROP_NIL, IPROP_OK,
    IPROP_PERM_DENIED, KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_FORWARDABLE,
    KDB_DISALLOW_POSTDATED, KDB_DISALLOW_RENEWABLE, KDB_DISALLOW_SVR, KDB_DISALLOW_TGT_BASED,
    KDB_LOCKDOWN_KEYS, KDB_NO_AUTH_DATA_REQUIRED, KDB_OK_AS_DELEGATE, KDB_OK_TO_AUTH_AS_DELEGATE,
    KDB_PWCHANGE_SERVICE, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PRE_AUTH, KDB_REQUIRES_PWCHANGE,
    KDB_V1_BASE_LENGTH, Kadm5Hook, KadmData, KeyEntry, KeyLookup, KtkdbError, MAX_ALIAS_DEPTH,
    NamedPolicy, PWQUAL_DICT, PWQUAL_EMPTY, PWQUAL_PRINC, Policy, Principal, PrincipalStore,
    Pwqual, RID_FIRST_USER, RID_KRBTGT, S2K_ITERS, SpakeKdc, TlData, apply_keysalt_policy,
    clear_thread_kadm5_hook, clear_thread_pwqual, kadm5_mask, ktkdb_get_entry, random_key,
    register_kadm5_hook, register_pwqual, s2k_params, set_thread_kadm5_hook, set_thread_pwqual,
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

#[must_use]
pub(crate) fn admin_id_for_realm(realm: &str) -> String {
    format!("{TEST_ADMIN}@{realm}")
}

// MIT: `kadm5_create_magic_princs` (kadm5_create.c:100-100)
#[must_use]
pub(crate) fn kdb5_util_id_for_realm(realm: &str) -> String {
    format!("kdb5_util@{realm}")
}

#[must_use]
pub(crate) fn host_for_realm(realm: &str) -> PrincipalName {
    let inst = format!("testhost.{}", realm.to_ascii_lowercase());
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", inst.as_str()])
}

// MIT: `DEFAULT_KADM5_ACL_FILE` (osconf.hin:106-106)
#[must_use]
pub fn default_acl_path(kdc_dir: &std::path::Path) -> std::path::PathBuf {
    kdc_dir.join("kadm5.acl")
}

// MIT: `main` (ovsec_kadmd.c:497-497)
// MIT: `acl_init` (auth_acl.c:554-555)
// MIT: `load_acl_file` (auth_acl.c:398-405)
/// Empty path is self-only; a directory has no lines.
/// A missing ACL file errors and names it.
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

pub(crate) fn bootstrap_realm(
    realm: &str,
    user: &str,
    user_password: &[u8],
    admin: &str,
    admin_password: &[u8],
) -> Result<(PrincipalStore, Acl), Error> {
    bootstrap_realm_with_kdc_conf(realm, user, user_password, admin, admin_password, None)
}

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

// MIT: `ADMIN_LIFETIME` (kadm5_create.c:54-54)
const KADM5_ADMIN_LIFETIME: u64 = 60 * 60 * 3;
// MIT: `CHANGEPW_LIFETIME` (kadm5_create.c:55-55)
const KADM5_CHANGEPW_LIFETIME: u64 = 60 * 5;

// MIT: `kadm5_create` (kadm5_create.c)
/// kadmin/admin is three hours; kadmin/changepw is five minutes.
/// The attributes word is replaced, so other flags clear.
/// Expiry and policy fields stay unchanged.
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
