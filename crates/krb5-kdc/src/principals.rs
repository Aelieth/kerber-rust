//! MIT kadm5 service principal names.
//!
//! KADM5_ADMIN_SERVICE (`lib/kadm5/admin.h`),
//! `KADM5_CHANGEPW_SERVICE` (`lib/kadm5/admin.h`), and
//! `KADM5_HIST_PRINCIPAL` (`lib/kadm5/admin.h`).

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

/// MIT `create_hist` (`server_kdb.c:142-164`): `kadmin/history` as NT-SRV-INST ( key-history principal).
#[must_use]
pub fn kadmin_history() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "history"])
}
