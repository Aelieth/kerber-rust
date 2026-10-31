//! MIT kadm5 service principal names.

use krb5_types::PrincipalName;

// MIT: `KADM5_ADMIN_SERVICE` (lib/kadm5/admin.h:64-64)
// MIT: `k5_infer_principal_type` (lib/krb5/krb/bld_princ.c:31-43)
#[must_use]
pub fn kadmin_admin() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin", "admin"])
}

// MIT: `KADM5_CHANGEPW_SERVICE` (lib/kadm5/admin.h:65-65)
// MIT: `k5_infer_principal_type` (lib/krb5/krb/bld_princ.c:31-43)
#[must_use]
pub fn kadmin_changepw() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin", "changepw"])
}

// MIT: `KADM5_HIST_PRINCIPAL` (lib/kadm5/admin.h:66-66)
// MIT: `k5_infer_principal_type` (lib/krb5/krb/bld_princ.c:31-43)
// MIT: `kdb_init_hist` (lib/kadm5/srv/server_kdb.c:124-131)
#[must_use]
pub fn kadmin_history() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin", "history"])
}
