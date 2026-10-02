//! The words `kadmin.local` prints: MIT's usage blocks and the `com_err` text of each error the
//! store returns (`kadm_err.et`, `kdb5_err.et`, the db2 module's messages).

use krb5_kdc::Error;

/// MIT `usage` (`kadmin.c:101-115`): the startup usage block, written through `error`.
pub(crate) fn startup_usage(whoami: &str) -> String {
    format!(
        "Usage: {whoami} [-r realm] [-p principal] [-q query] [clnt|local args]\n              \
         [command args...]\n\tclnt args: [-s admin_server[:port]] [[-c ccache]|[-k [-t \
         keytab]]]|[-n] [-O | -N]\n\tlocal args: [-x db_args]* [-d dbname] [-e \"enc:salt \
         ...\"] [-m] [-w password] where,\n\t[-x db_args]* - any number of database specific \
         arguments.\n\t\t\tLook at each database documentation for supported arguments\n"
    )
}

const ATTRIBUTES: &str = "\tattributes are:\n\t\tallow_postdated allow_forwardable \
     allow_tgs_req allow_renewable\n\t\tallow_proxiable allow_dup_skey allow_tix \
     requires_preauth\n\t\trequires_hwauth needchange allow_svr password_changing_service\n\t\t\
     ok_as_delegate ok_to_auth_as_delegate no_auth_data_required\n\t\tlockdown_keys\n\nwhere,\n\t\
     [-x db_princ_args]* - any number of database specific arguments.\n\t\t\tLook at each \
     database documentation for supported arguments\n";

/// MIT `kadmin_addprinc_usage` (`kadmin.c:1182-1203`): its four `error` calls.
pub(crate) const ADDPRINC_USAGE: [&str; 4] = [
    "usage: add_principal [options] principal\n",
    "\toptions are:\n",
    "\t\t[-randkey|-nokey] [-x db_princ_args]* [-expire expdate] [-pwexpire pwexpdate] \
     [-maxlife maxtixlife]\n\t\t[-kvno kvno] [-policy policy] [-clearpolicy]\n\t\t[-pw \
     password] [-maxrenewlife maxrenewlife]\n\t\t[-e keysaltlist]\n\t\t[{+|-}attribute]\n",
    ATTRIBUTES,
];

/// MIT `kadmin_modprinc_usage` (`kadmin.c:1206-1226`): its four `error` calls.
pub(crate) const MODPRINC_USAGE: [&str; 4] = [
    "usage: modify_principal [options] principal\n",
    "\toptions are:\n",
    "\t\t[-x db_princ_args]* [-expire expdate] [-pwexpire pwexpdate] [-maxlife \
     maxtixlife]\n\t\t[-kvno kvno] [-policy policy] [-clearpolicy]\n\t\t[-maxrenewlife \
     maxrenewlife] [-unlock] [{+|-}attribute]\n",
    ATTRIBUTES,
];

/// MIT `cpw_usage` (`kadmin.c:827-833`): the `change_password` usage line.
pub(crate) const CPW_USAGE: &str =
    "usage: change_password [-randkey] [-keepold] [-e keysaltlist] [-pw password] principal\n";

/// MIT `kadmin_addmodpol_usage` (`kadmin.c:1699-1708`): its four `error` calls.
pub(crate) fn addmodpol_usage(func: &str) -> [String; 4] {
    [
        format!("usage; {func} [options] policy\n"),
        "\toptions are:\n".to_owned(),
        "\t\t[-maxlife time] [-minlife time] [-minlength length]\n\t\t[-minclasses number] \
         [-history number]\n\t\t[-maxfailure number] [-failurecountinterval time]\n\t\t\
         [-allowedkeysalts keysalts]\n"
            .to_owned(),
        "\t\t[-lockoutduration time]\n".to_owned(),
    ]
}

/// MIT `add_usage` (`kadmin/cli/keytab.c:53-57`): the `ktadd` usage line, on stderr.
pub(crate) const KTADD_USAGE: &str = "Usage: ktadd [-k[eytab] keytab] [-q] [-e keysaltlist] \
     [-norandkey] [principal | -glob princ-exp] [...]\n";

/// MIT `rem_usage` (`kadmin/cli/keytab.c:60-64`): the `ktremove` usage line, on stderr.
pub(crate) const KTREM_USAGE: &str =
    "Usage: ktremove [-k[eytab] keytab] [-q] principal [kvno|\"all\"|\"old\"]\n";

/// `KADM5_DUP`.
pub(crate) const DUP: &str = "Principal or policy already exists";
/// `KADM5_UNK_PRINC`.
pub(crate) const UNK_PRINC: &str = "Principal does not exist";
/// `KADM5_UNK_POLICY`.
pub(crate) const UNK_POLICY: &str = "Policy does not exist";
/// `KRB5_KDB_NOENTRY`.
pub(crate) const NOENTRY: &str = "No such entry in the database";
/// `KRB5_KDB_CANTLOCK_DB`.
pub(crate) const CANTLOCK: &str = "Insufficient access to lock database";
/// `KADM5_PROTECT_PRINCIPAL`.
pub(crate) const PROTECT_PRINCIPAL: &str = "Cannot change protected principal";
/// `KRB5_PARSE_MALFORMED`.
pub(crate) const MALFORMED: &str = "Malformed representation of principal";
/// `KRB5_KDB_BADMASTERKEY` as `krb5_def_fetch_mkey_list` words it, its newline included.
pub(crate) const BAD_MASTER_KEY: &str =
    "Unable to decrypt latest master key with the provided master key\n";

/// The text MIT's library gives for a store error on a principal operation.
/// MIT `ctx_lock` (`kdb_db2.c:426-478`): a writer that may not write the database cannot take
/// the lock, `KRB5_KDB_CANTLOCK_DB`.
pub(crate) fn princ_text(e: &Error) -> String {
    match e {
        Error::AlreadyExists => DUP.to_owned(),
        Error::NotFound => UNK_PRINC.to_owned(),
        Error::Db {
            kind: std::io::ErrorKind::PermissionDenied,
            ..
        } => CANTLOCK.to_owned(),
        other => common_text(other),
    }
}

/// The text for a store error on a policy operation: the policy database is opened as a file,
/// so a refused write is the system's own text.
pub(crate) fn policy_text(e: &Error) -> String {
    match e {
        Error::NotFound => UNK_POLICY.to_owned(),
        Error::AlreadyExists => DUP.to_owned(),
        other => common_text(other),
    }
}

fn common_text(e: &Error) -> String {
    match e {
        Error::PasswordPolicy(s) => password_text(s),
        Error::PassTooSoon { .. } => "Current password's minimum life has not expired".to_owned(),
        Error::BadKeysalts => "Invalid key/salt tuples".to_owned(),
        Error::AclDenied => "Insufficient authorization for operation".to_owned(),
        Error::Crypto(s) | Error::Asn1(s) => s.clone(),
        other => other.to_string(),
    }
}

/// MIT `passwd_check` (`server_misc.c:107-137`): the `kadm_err.et` text of a refused password,
/// or the quality module's own message.
fn password_text(s: &str) -> String {
    if s.contains("min_length") {
        "Password is too short".to_owned()
    } else if s.contains("min_classes") {
        "Password does not contain enough character classes".to_owned()
    } else if s.contains("history") {
        "Cannot reuse password".to_owned()
    } else {
        s.to_owned()
    }
}

/// The system's text for an I/O error (`strerror`), without Rust's `(os error N)`.
pub(crate) fn strerror(e: &std::io::Error) -> String {
    let text = e.to_string();
    match e.raw_os_error() {
        Some(code) => text
            .strip_suffix(&format!(" (os error {code})"))
            .map_or_else(|| text.clone(), str::to_owned),
        None => text,
    }
}
