//! MIT kadm5 service principal names.
//!
//! MIT `KADM5_ADMIN_SERVICE` (`lib/kadm5/admin.h:64-64`): `"kadmin/admin"`.
//! MIT `KADM5_CHANGEPW_SERVICE` (`lib/kadm5/admin.h:65-65`): `"kadmin/changepw"`.
//! MIT `KADM5_HIST_PRINCIPAL` (`lib/kadm5/admin.h:66-66`): `"kadmin/history"`.

use krb5_types::PrincipalName;

/// `kadmin/admin` as NT-SRV-INST (MIT kadmind acceptor).
#[must_use]
pub fn kadmin_admin() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "admin"])
}

/// `kadmin/changepw` as NT-SRV-INST (RFC 3244 kpasswd acceptor).
#[must_use]
pub fn kadmin_changepw() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"])
}

/// `kadmin/history` as NT-SRV-INST, the key-history principal MIT `create_hist` creates.
/// MIT `kdb_init_hist` (`lib/kadm5/srv/server_kdb.c:124-131`): the history principal is parsed
/// from `kadmin/history@REALM`, so MIT's copy is NT-PRINCIPAL.
#[must_use]
pub fn kadmin_history() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "history"])
}
