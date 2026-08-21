//! Administration: kadmind, kadmin.local, kdb5_util, kpasswd, kprop.
//!
//! The kadmind path enforces the KDC ACL. There is no C FFI.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use krb5_kdc::{Acl, AdminOp, PrincipalStore};
use krb5_protocol::{verify_ap_req, Keytab, ReplayCache};
use krb5_types::PrincipalName;
use thiserror::Error;

/// Admin error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// ACL denied.
    #[error("acl denied")]
    AclDenied,
    /// Principal missing.
    #[error("not found")]
    NotFound,
    /// Wrapped KDC error.
    #[error("{0}")]
    Inner(String),
}

impl From<krb5_kdc::Error> for Error {
    fn from(e: krb5_kdc::Error) -> Self {
        match e {
            krb5_kdc::Error::AclDenied => Self::AclDenied,
            krb5_kdc::Error::NotFound => Self::NotFound,
            other => Self::Inner(other.to_string()),
        }
    }
}

/// Wire op codes for the kadmind-equivalent framing.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Create principal.
    Create = 1,
    /// Delete principal.
    Delete = 2,
    /// Export keytab (ktadd).
    Ktadd = 3,
    /// Change password (kpasswd / RFC 3244 style).
    Cpw = 4,
    /// Dump (kdb5_util / kprop).
    Dump = 5,
}

/// Authenticated admin session: AP-REQ must succeed and ACL is checked per op.
pub struct AdminSession<'a> {
    store: &'a mut PrincipalStore,
    acl: &'a Acl,
    actor: String,
}

impl<'a> AdminSession<'a> {
    /// Verify `ap_req` with `service_key` and bind `actor` from the authenticator.
    ///
    /// # Errors
    ///
    /// AP-REQ verify or missing cname.
    pub fn from_ap_req(
        store: &'a mut PrincipalStore,
        acl: &'a Acl,
        service_key: &krb5_crypto::ProtocolKey,
        ap_req: &[u8],
        replay: &ReplayCache,
    ) -> Result<Self, Error> {
        let ok =
            verify_ap_req(ap_req, service_key, replay).map_err(|e| Error::Inner(e.to_string()))?;
        let actor = format!(
            "{}@{}",
            ok.authenticator.cname.components_joined(),
            String::from_utf8_lossy(ok.authenticator.crealm.as_bytes())
        );
        Ok(Self { store, acl, actor })
    }

    /// Local (kadmin.local) session: actor is trusted as already authenticated.
    #[must_use]
    pub fn local(store: &'a mut PrincipalStore, acl: &'a Acl, actor: impl Into<String>) -> Self {
        Self {
            store,
            acl,
            actor: actor.into(),
        }
    }

    /// Create a password principal (ACL `add`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor is not permitted.
    pub fn create_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        self.store
            .create_password(self.acl, &self.actor, name, password)
            .map_err(Error::from)
    }

    /// Delete a principal (ACL `delete`).
    ///
    /// # Errors
    ///
    /// ACL or not found.
    pub fn delete(&mut self, name: &PrincipalName) -> Result<(), Error> {
        self.store
            .delete(self.acl, &self.actor, name)
            .map_err(Error::from)
    }

    /// Over-the-wire ktadd (ACL `inquire`).
    ///
    /// # Errors
    ///
    /// ACL or not found.
    pub fn ktadd(&self, name: &PrincipalName) -> Result<Keytab, Error> {
        self.store
            .export_keytab(self.acl, &self.actor, name)
            .map_err(Error::from)
    }

    /// Change password (kpasswd / RFC 3244).
    ///
    /// The actor may always change their own password. Changing another
    /// principal requires ACL `c` / `*`.
    ///
    /// # Errors
    ///
    /// ACL denied or principal missing.
    pub fn change_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        let target = format!("{}@{}", name.components_joined(), self.store.realm());
        if self.actor != target {
            self.acl
                .check(&self.actor, AdminOp::ChangePassword)
                .map_err(Error::from)?;
        }
        self.store.set_password(name, password).map_err(Error::from)
    }
}

/// RFC 3244 kpasswd request: AP-REQ + new password octets.
///
/// # Errors
///
/// AP-REQ verify or ACL.
pub fn kpasswd_set(
    store: &mut PrincipalStore,
    acl: &Acl,
    service_key: &krb5_crypto::ProtocolKey,
    ap_req: &[u8],
    replay: &ReplayCache,
    name: &PrincipalName,
    new_password: &[u8],
) -> Result<(), Error> {
    let mut sess = AdminSession::from_ap_req(store, acl, service_key, ap_req, replay)?;
    sess.change_password(name, new_password)
}

/// kprop-equivalent: serialize the store (dump) and load on a replica.
///
/// # Errors
///
/// Persist errors.
pub fn propagate(
    store: &PrincipalStore,
    db_path: &std::path::Path,
    stash_path: &std::path::Path,
) -> Result<(), krb5_kdc::PersistError> {
    krb5_kdc::save_store(store, db_path, stash_path)
}

/// Load a propagated dump.
///
/// # Errors
///
/// Persist errors.
pub fn receive_propagate(
    db_path: &std::path::Path,
    stash_path: &std::path::Path,
) -> Result<PrincipalStore, krb5_kdc::PersistError> {
    krb5_kdc::load_store(db_path, stash_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_kdc::{bootstrap_documented, documented_admin_id, documented_host};

    #[test]
    fn kadmind_enforces_acl() {
        let (mut store, acl) = bootstrap_documented().unwrap();
        let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
        let extra = PrincipalName::new(
            PrincipalName::NT_SRV_HST,
            ["host", "admin-extra.kerber.test"],
        );
        admin.create_password(&extra, b"secret-pass").unwrap();
        let kt = admin.ktadd(&extra).unwrap();
        assert_eq!(&kt.to_bytes()[..2], &[0x05, 0x02]);
    }

    #[test]
    fn kadmind_denies_user() {
        let (mut store, acl) = bootstrap_documented().unwrap();
        let mut user = AdminSession::local(&mut store, &acl, "user@KERBER.TEST");
        let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "nope.kerber.test"]);
        assert_eq!(
            user.create_password(&extra, b"x").unwrap_err(),
            Error::AclDenied
        );
        assert_eq!(
            user.ktadd(&documented_host()).unwrap_err(),
            Error::AclDenied
        );
    }

    #[test]
    fn kpasswd_self_service_and_admin_acl() {
        let (mut store, acl) = bootstrap_documented().unwrap();
        let user_name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let admin_name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
        {
            let mut user = AdminSession::local(&mut store, &acl, "user@KERBER.TEST");
            user.change_password(&user_name, b"new-user-pass").unwrap();
            assert_eq!(
                user.change_password(&admin_name, b"nope").unwrap_err(),
                Error::AclDenied
            );
        }
        let after = store.get_name(&user_name).unwrap();
        let old_max = after.keys.iter().map(|k| k.kvno).max().unwrap();
        assert!(old_max > 1, "self-service kpasswd must bump kvno");
        {
            let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
            admin
                .change_password(&user_name, b"admin-set-pass")
                .unwrap();
        }
        let after = store.get_name(&user_name).unwrap();
        let new_max = after.keys.iter().map(|k| k.kvno).max().unwrap();
        assert!(new_max > old_max);
    }

    #[test]
    fn kprop_replica_issues_with_same_krbtgt() {
        let dir = std::env::temp_dir().join(format!("kprop-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("principal");
        let stash = dir.join("stash");
        let (store, _) = bootstrap_documented().unwrap();
        let before = store
            .krbtgt()
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .as_bytes()
            .to_vec();
        propagate(&store, &db, &stash).unwrap();
        let replica = receive_propagate(&db, &stash).unwrap();
        let after = replica
            .krbtgt()
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .as_bytes()
            .to_vec();
        assert_eq!(before, after);
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let salt = cname.default_salt("KERBER.TEST");
        let key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"userpassword",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = krb5_kdc::as_req(
            cname,
            "KERBER.TEST",
            9,
            Some(vec![krb5_kdc::pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&replica, &req).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
