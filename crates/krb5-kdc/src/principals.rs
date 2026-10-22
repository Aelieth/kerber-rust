//! MIT kadm5 service principal names.
//!
// MIT: `KADM5_ADMIN_SERVICE` (lib/kadm5/admin.h:64-64)
//! `"kadmin/admin"`.
// MIT: `KADM5_CHANGEPW_SERVICE` (lib/kadm5/admin.h:65-65)
//! `"kadmin/changepw"`.
// MIT: `KADM5_HIST_PRINCIPAL` (lib/kadm5/admin.h:66-66)
//! `"kadmin/history"`.

use krb5_types::PrincipalName;

// MIT: `k5_infer_principal_type` (lib/krb5/krb/bld_princ.c:31-43)
/// `kadmin/admin` is NT-PRINCIPAL.
#[must_use]
pub fn kadmin_admin() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin", "admin"])
}

// MIT: `k5_infer_principal_type` (lib/krb5/krb/bld_princ.c:31-43)
/// `kadmin/changepw` is NT-PRINCIPAL.
#[must_use]
pub fn kadmin_changepw() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin", "changepw"])
}

// MIT: `k5_infer_principal_type` (lib/krb5/krb/bld_princ.c:31-43)
/// `kadmin/history` is NT-PRINCIPAL.
// MIT: `kdb_init_hist` (lib/kadm5/srv/server_kdb.c:124-131)
/// the history principal is parsed
/// from `kadmin/history@REALM`.
#[must_use]
pub fn kadmin_history() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin", "history"])
}
