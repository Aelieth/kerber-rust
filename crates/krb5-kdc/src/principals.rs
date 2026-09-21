//! MIT kadm5 service principal names.
//!
//! MIT `KADM5_ADMIN_SERVICE` (`admin.h:64`), `KADM5_CHANGEPW_SERVICE`
//! (`admin.h:65`), and `KADM5_HIST_PRINCIPAL` (`admin.h:66`).

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

/// `kadmin/history` as NT-SRV-INST (MIT `create_hist` key-history principal).
#[must_use]
pub fn kadmin_history() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "history"])
}
