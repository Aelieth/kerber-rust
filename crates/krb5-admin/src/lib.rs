//! Administration: kadmind, kadmin.local, kdb5_util, kpasswd, kprop.
//!
//! The kadmind path enforces the KDC ACL. There is no C FFI.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod kadm5;
mod kprop;
mod listen;

use krb5_kdc::{Acl, AdminOp, NamedPolicy, PrincipalStore};
use krb5_protocol::{Keytab, ReplayCache, verify_ap_req};
use krb5_types::PrincipalName;
use thiserror::Error;

pub use kadm5::{IpropPull, iprop_pull, serve_kadm5_conn};
pub use kprop::{
    IpropPoll, KpropAuth, iprop_poll_once, kprop_dump_bytes, kprop_dump_iprop, kprop_load_bytes,
    kprop_send_dump, kprop_send_store, kprop_send_store_iprop, kprop_sendauth, kpropd_handle_conn,
    kpropd_recv_dump, kpropd_recvauth, kpropd_send_ack,
};
pub use listen::{
    KADMIND_PORT, KPASSWD_PORT, KPROP_PORT, dispatch_kadmind, encode_kadmind_req,
    encode_kpasswd_req, handle_kpasswd_rfc3244, kpasswd_udp_exchange_to, kprop_recv, kprop_send,
    parse_kpasswd_rep, serve_kadmind, serve_kpasswd_tcp, serve_kpasswd_udp,
};

/// Load a kadm5 ACL file. `None` is MIT `kadmin.local` full privs for `actor`.
///
/// The ACL is not a security boundary here: the actor is self-chosen via
/// `KRB5_KADMIN_PRINCIPAL`. A set-but-unreadable path is a hard error.
///
/// # Errors
///
/// `path` is set and cannot be read.
pub fn load_acl_file(actor: &str, path: Option<&std::path::Path>) -> Result<Acl, String> {
    match path {
        Some(p) => {
            let t = std::fs::read_to_string(p).map_err(|e| format!("ACL {}: {e}", p.display()))?;
            Ok(Acl::parse(&t))
        }
        None => Ok(Acl::allow_admin(actor)),
    }
}

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

    /// Rename (ACL add + delete).
    ///
    /// # Errors
    ///
    /// ACL, not found, or already exists.
    pub fn rename(&mut self, old: &PrincipalName, new: &PrincipalName) -> Result<(), Error> {
        self.store
            .rename(self.acl, &self.actor, old, new)
            .map_err(Error::from)
    }

    /// Over-the-wire ktadd (ACL `e` / extract).
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

    /// Realm of the bound store.
    #[must_use]
    pub fn realm(&self) -> &str {
        self.store.realm()
    }

    /// `listprincs`.
    #[must_use]
    pub fn list_ids(&self) -> Vec<String> {
        self.store.ids()
    }

    /// `getprinc` display id.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn get_principal_id(&self, name: &PrincipalName) -> Result<String, Error> {
        let p = self.store.get_name(name).ok_or(Error::NotFound)?;
        Ok(format!("{}@{}", p.name.components_joined(), p.realm))
    }

    /// `modprinc` attributes only.
    ///
    /// # Errors
    ///
    /// ACL or not found.
    pub fn modify_attributes(
        &mut self,
        name: &PrincipalName,
        attributes: Option<u32>,
    ) -> Result<(), Error> {
        self.acl
            .check(&self.actor, AdminOp::Modify)
            .map_err(Error::from)?;
        self.store
            .apply_admin_fields(name, attributes, None, None, None, None, false)
            .map_err(Error::from)
    }

    /// `addpol`.
    pub fn add_policy(&mut self, name: &str) {
        self.store.put_policy(NamedPolicy::new(name));
    }

    /// `getpol`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn get_policy(&self, name: &str) -> Result<String, Error> {
        self.store
            .policies()
            .get(name)
            .map(|p| p.name.clone())
            .ok_or(Error::NotFound)
    }

    /// `setstr`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn set_string_attr(
        &mut self,
        name: &PrincipalName,
        key: &str,
        val: &str,
    ) -> Result<(), Error> {
        self.store
            .set_string(name, key, Some(val))
            .map_err(Error::from)
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
    use krb5_protocol::ReplayCache;

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

    #[test]
    fn kadmind_wire_create_is_visible_after_reload() {
        use krb5_asn1::encode;
        use krb5_kdc::{
            TEST_REALM, documented_host, load_store, save_store, shared_dump as shared_store,
        };
        use krb5_protocol::{build_ap_req, pa_enc_timestamp, tgs_req};

        let dir = std::env::temp_dir().join(format!(
            "kadmind-wire-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("principal");
        let stash = dir.join("stash");
        let (store, acl) = bootstrap_documented().unwrap();
        save_store(&store, &db, &stash).unwrap();
        let store = load_store(&db, &stash).unwrap();
        assert!(store.persist_paths.is_some());

        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
        let admin_key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_req = krb5_kdc::as_req(
            admin.clone(),
            TEST_REALM,
            41,
            Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &admin,
            documented_host(),
            TEST_REALM,
            42,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let host_key = store
            .get_name(&documented_host())
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &admin,
        )
        .unwrap();
        let ap_der = encode(&ap).unwrap();

        let shared = shared_store(store);
        let replay = ReplayCache::new();
        let payload = b"wireuser@KERBER.TEST\0wire-secret";
        let body = encode_kadmind_req(Op::Create, &ap_der, payload);
        let reply = dispatch_kadmind(&shared, &acl, &host_key, &replay, &body).expect("create");
        assert_eq!(&reply[..4], &[0, 0, 0, 0]);

        let loaded = load_store(&db, &stash).unwrap();
        let created = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["wireuser"]);
        assert!(
            loaded.get_name(&created).is_some(),
            "kadmind create must persist to stash/db"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kpasswd_rfc3244_bumps_kvno() {
        use krb5_asn1::encode;
        use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
        use krb5_protocol::{build_ap_req, build_krb_priv, pa_enc_timestamp, tgs_req};
        use krb5_types::ChangePasswdData;

        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let kvno_before = store
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let as_req = krb5_kdc::as_req(
            user.clone(),
            TEST_REALM,
            43,
            Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
        let changepw = documented_changepw();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &user,
            changepw.clone(),
            TEST_REALM,
            44,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let ap_der = encode(&ap).unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"rfc3244-new".to_vec().into(),
            targname: Some(user.clone()),
            targrealm: Some(krb5_types::ascii(TEST_REALM)),
        };
        let cpw_der = encode(&cpw).unwrap();
        let priv_msg = build_krb_priv(&tgs_out.session_key, &cpw_der).unwrap();
        let priv_der = encode(&priv_msg).unwrap();
        let req = encode_kpasswd_req(&ap_der, &priv_der);
        let shared = shared_store(store);
        let replay = ReplayCache::new();
        let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &replay, &req).expect("kpasswd");
        assert!(
            rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
            "success reply must include AP-REP"
        );
        let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).expect("parse kpasswd rep");
        assert!(!ap_rep.is_empty() && !priv_rep.is_empty());
        assert!(parse_kpasswd_rep(&[0, 6, 0, 1, 0, 0]).is_err());
        let after = shared.read().unwrap();
        let kvno_after = after
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        assert!(kvno_after > kvno_before, "RFC 3244 must bump kvno");

        let salt = user.default_salt(TEST_REALM);
        let new_key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"rfc3244-new",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let as_new = krb5_kdc::as_req(
            user.clone(),
            TEST_REALM,
            45,
            Some(vec![pa_enc_timestamp(&new_key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&*after, &as_new).expect("AS with RFC 3244 new password");

        let as_old = krb5_kdc::as_req(
            user,
            TEST_REALM,
            46,
            Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
        )
        .unwrap();
        assert!(
            krb5_kdc::issue_as(&*after, &as_old).is_err(),
            "old password must fail after kpasswd"
        );
    }

    #[test]
    fn kpasswd_udp_listener_then_issue_as() {
        use std::net::UdpSocket;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;
        use std::time::Duration;

        use krb5_asn1::encode;
        use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
        use krb5_protocol::{build_ap_req, build_krb_priv, pa_enc_timestamp, tgs_req};
        use krb5_types::ChangePasswdData;

        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let changepw = documented_changepw();
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_out = krb5_kdc::issue_as(
            &store,
            &krb5_kdc::as_req(
                user.clone(),
                TEST_REALM,
                47,
                Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
            )
            .unwrap(),
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(
            &store,
            &tgs_req(
                as_out.rep.0.ticket.clone(),
                &as_out.session_key,
                TEST_REALM,
                &user,
                changepw,
                TEST_REALM,
                48,
            )
            .unwrap(),
        )
        .unwrap();
        let ap = build_ap_req(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"udp-new-pass".to_vec().into(),
            targname: Some(user.clone()),
            targrealm: Some(krb5_types::ascii(TEST_REALM)),
        };
        let priv_msg = build_krb_priv(&tgs_out.session_key, &encode(&cpw).unwrap()).unwrap();
        let req = encode_kpasswd_req(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shared = shared_store(store);
        let shared2 = shared.clone();
        let stop2 = Arc::clone(&stop);
        thread::spawn(move || {
            let _ = serve_kpasswd_udp(shared2, acl, cpw_key, sock, stop2);
        });
        thread::sleep(Duration::from_millis(30));
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Debug s2k in change_password can exceed 2s before the reply.
        client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        client.send_to(&req, addr).unwrap();
        let mut buf = [0u8; 4096];
        let n = client.recv(&mut buf).expect("kpasswd reply");
        assert!(n > 6, "RFC 3244 reply");
        stop.store(true, Ordering::Relaxed);
        let after = shared.read().unwrap();
        let salt = user.default_salt(TEST_REALM);
        let new_key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"udp-new-pass",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let as_new = krb5_kdc::as_req(
            user,
            TEST_REALM,
            49,
            Some(vec![pa_enc_timestamp(&new_key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&*after, &as_new).expect("AS after UDP kpasswd");
    }

    #[test]
    fn kpasswd_mit_style_subkey_seq0_then_issue_as() {
        use krb5_asn1::encode;
        use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
        use krb5_protocol::{
            build_ap_req_with_cksum, build_krb_priv_with_seq, pa_enc_timestamp, tgs_req,
        };
        use krb5_types::ApOptions;

        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let changepw = documented_changepw();
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_out = krb5_kdc::issue_as(
            &store,
            &krb5_kdc::as_req(
                user.clone(),
                TEST_REALM,
                50,
                Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
            )
            .unwrap(),
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(
            &store,
            &tgs_req(
                as_out.rep.0.ticket.clone(),
                &as_out.session_key,
                TEST_REALM,
                &user,
                changepw,
                TEST_REALM,
                51,
            )
            .unwrap(),
        )
        .unwrap();
        let sub = krb5_crypto::ProtocolKey::from_bytes(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            &[0x5au8; 32],
        )
        .unwrap();
        let sub_ek = krb5_types::EncryptionKey {
            keytype: sub.etype().to_iana(),
            keyvalue: sub.as_bytes().to_vec().into(),
        };
        let ap = build_ap_req_with_cksum(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
            ApOptions::none(),
            None,
            Some(sub_ek),
        )
        .unwrap();
        // MIT kpasswd: version 1, raw password, subkey, seq 0.
        let priv_msg = build_krb_priv_with_seq(&sub, b"kpasswd-one", Some(0)).unwrap();
        let req = encode_kpasswd_req(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let shared = shared_store(store);
        let replay = ReplayCache::new();
        let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &replay, &req)
            .expect("MIT-style kpasswd");
        assert!(
            rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
            "MIT kpasswd requires AP-REP on success"
        );
        let after = shared.read().unwrap();
        let salt = user.default_salt(TEST_REALM);
        let new_key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"kpasswd-one",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let as_new = krb5_kdc::as_req(
            user,
            TEST_REALM,
            52,
            Some(vec![pa_enc_timestamp(&new_key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&*after, &as_new).expect("AS after MIT-style kpasswd");
    }

    #[test]
    fn kprop_tcp_replica_issues_as_with_shared_stash() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_kdc::TEST_REALM;
        use krb5_kdc::TEST_USER;

        const MASTER: &[u8] = b"masterpassword";

        let (store, _) = bootstrap_documented().unwrap();
        let before = store
            .krbtgt()
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .as_bytes()
            .to_vec();

        let listener = TcpListener::bind("127.0.0.1:754")
            .or_else(|_| TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            kprop_recv(&mut stream, MASTER).expect("kprop_recv")
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = TcpStream::connect(addr).unwrap();
        kprop_send(&store, MASTER, &mut client).expect("kprop_send");
        let replica = join.join().expect("thread");
        let after = replica
            .krbtgt()
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .as_bytes()
            .to_vec();
        assert_eq!(
            before, after,
            "replica krbtgt must match the primary (shared stash)"
        );
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let salt = cname.default_salt(TEST_REALM);
        let key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"userpassword",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = krb5_kdc::as_req(
            cname,
            TEST_REALM,
            91,
            Some(vec![krb5_kdc::pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&replica, &req).expect("replica issue_as");
    }

    #[test]
    fn kprop_dump_payload_is_version_7_not_kdb3() {
        const MASTER: &[u8] = b"masterpassword";
        let (store, _) = bootstrap_documented().unwrap();
        let bytes = kprop_dump_bytes(&store, MASTER).unwrap();
        assert!(
            bytes.starts_with(b"kdb5_util load_dump version 7\n"),
            "kprop body must be dump version 7, got {}",
            String::from_utf8_lossy(&bytes[..bytes.len().min(40)])
        );
        assert!(!bytes.starts_with(b"KDB3"));
        let replica = kprop_load_bytes(&bytes, MASTER).unwrap();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
        let salt = cname.default_salt(krb5_kdc::TEST_REALM);
        let key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"userpassword",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = krb5_kdc::as_req(
            cname,
            krb5_kdc::TEST_REALM,
            92,
            Some(vec![krb5_kdc::pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&replica, &req).expect("dump-codec replica issue_as");
    }

    #[test]
    fn kprop_truncated_or_kdb3_body_fails() {
        const MASTER: &[u8] = b"masterpassword";
        assert!(kprop_load_bytes(b"KDB3notadump", MASTER).is_err());
        assert!(kprop_load_bytes(b"kdb5_util load_dump version 7\nprinc\t", MASTER).is_err());
        assert!(kprop_load_bytes(b"not a dump", MASTER).is_err());
    }

    #[test]
    fn kprop_mit_wire_sendauth_replica_issues_as() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_kdc::{TEST_REALM, TEST_USER, documented_host};
        use krb5_protocol::{pa_enc_timestamp, tgs_req};

        const MASTER: &[u8] = b"masterpassword";
        let (store, _) = bootstrap_documented().unwrap();
        let host = documented_host();
        let host_keys: Vec<_> = store
            .get_name(&host)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.key.clone())
            .collect();

        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
        let admin_key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_req = krb5_kdc::as_req(
            admin.clone(),
            TEST_REALM,
            71,
            Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &admin,
            host.clone(),
            TEST_REALM,
            72,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host_keys2 = host_keys.clone();
        let host_for_server = host.clone();
        let allowed = vec![format!("admin@{TEST_REALM}")];
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let dir = std::env::temp_dir().join(format!(
                "kprop-mit-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            let _ = std::fs::create_dir_all(&dir);
            let db = dir.join("replica");
            let stash = dir.join("stash");
            let store = kpropd_handle_conn(
                &mut stream,
                &host_keys2,
                Some(&host_for_server),
                Some(TEST_REALM),
                MASTER,
                &db,
                &stash,
                Some(allowed.as_slice()),
            )
            .expect("kpropd_handle_conn");
            let _ = std::fs::remove_dir_all(&dir);
            store
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = TcpStream::connect(addr).unwrap();
        kprop_send_store(
            &mut client,
            &store,
            MASTER,
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &admin,
        )
        .expect("kprop_send_store");
        let replica = join.join().expect("thread");
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let salt = cname.default_salt(TEST_REALM);
        let key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"userpassword",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = krb5_kdc::as_req(
            cname,
            TEST_REALM,
            93,
            Some(vec![krb5_kdc::pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&replica, &req).expect("MIT-wire replica issue_as");
    }

    #[test]
    fn kpropd_rejects_client_not_on_allowlist() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_kdc::{TEST_REALM, documented_host};
        use krb5_protocol::{pa_enc_timestamp, tgs_req};

        const MASTER: &[u8] = b"masterpassword";
        let (store, _) = bootstrap_documented().unwrap();
        let host = documented_host();
        let host_keys: Vec<_> = store
            .get_name(&host)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.key.clone())
            .collect();
        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
        let admin_key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_req = krb5_kdc::as_req(
            admin.clone(),
            TEST_REALM,
            81,
            Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &admin,
            host.clone(),
            TEST_REALM,
            82,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host_keys2 = host_keys.clone();
        let host_for_server = host.clone();
        let allowed = vec![format!("host/testhost.kerber.test@{TEST_REALM}")];
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let dir = std::env::temp_dir().join(format!(
                "kprop-deny-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            let _ = std::fs::create_dir_all(&dir);
            let db = dir.join("replica");
            let stash = dir.join("stash");
            let err = kpropd_handle_conn(
                &mut stream,
                &host_keys2,
                Some(&host_for_server),
                Some(TEST_REALM),
                MASTER,
                &db,
                &stash,
                Some(allowed.as_slice()),
            )
            .unwrap_err();
            let _ = std::fs::remove_dir_all(&dir);
            err
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = TcpStream::connect(addr).unwrap();
        let _ = kprop_send_store(
            &mut client,
            &store,
            MASTER,
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &admin,
        );
        let err = join.join().expect("thread");
        assert_eq!(err, Error::AclDenied);
    }

    #[test]
    fn kpropd_rejects_when_acl_unset() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_kdc::{TEST_REALM, documented_host};
        use krb5_protocol::{pa_enc_timestamp, tgs_req};

        const MASTER: &[u8] = b"masterpassword";
        let (store, _) = bootstrap_documented().unwrap();
        let host = documented_host();
        let host_keys: Vec<_> = store
            .get_name(&host)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.key.clone())
            .collect();
        let host_key = store
            .get_name(&host)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_req = krb5_kdc::as_req(
            host.clone(),
            TEST_REALM,
            83,
            Some(vec![pa_enc_timestamp(&host_key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &host,
            host.clone(),
            TEST_REALM,
            84,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host_keys2 = host_keys.clone();
        let host_for_server = host.clone();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let dir = std::env::temp_dir().join(format!(
                "kprop-unset-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            let _ = std::fs::create_dir_all(&dir);
            let db = dir.join("replica");
            let stash = dir.join("stash");
            let err = kpropd_handle_conn(
                &mut stream,
                &host_keys2,
                Some(&host_for_server),
                Some(TEST_REALM),
                MASTER,
                &db,
                &stash,
                None,
            )
            .unwrap_err();
            let _ = std::fs::remove_dir_all(&dir);
            err
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = TcpStream::connect(addr).unwrap();
        let _ = kprop_send_store(
            &mut client,
            &store,
            MASTER,
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &host,
        );
        let err = join.join().expect("thread");
        assert_eq!(err, Error::AclDenied);
    }

    #[test]
    fn load_acl_file_missing_is_error() {
        let path = std::env::temp_dir().join(format!("krb5-acl-missing-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(load_acl_file("admin@KERBER.TEST", Some(&path)).is_err());
        let acl = load_acl_file("admin@KERBER.TEST", None).unwrap();
        assert!(acl.check("admin@KERBER.TEST", AdminOp::Create).is_ok());
    }

    #[test]
    fn load_acl_file_parses_readable() {
        let path = std::env::temp_dir().join(format!("krb5-acl-ok-{}", std::process::id()));
        std::fs::write(&path, "admin@KERBER.TEST *\n").unwrap();
        let acl = load_acl_file("other@KERBER.TEST", Some(&path)).unwrap();
        assert!(acl.check("admin@KERBER.TEST", AdminOp::Create).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn kpasswd_udp_exchange_ignores_off_path() {
        use std::net::UdpSocket;
        use std::thread;
        use std::time::Duration;

        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest = server.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (n, src) = server.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"req");
            let spoof = UdpSocket::bind("127.0.0.1:0").unwrap();
            let _ = spoof.send_to(b"spoof", src);
            thread::sleep(Duration::from_millis(30));
            let _ = server.send_to(b"kdc-ok", src);
        });
        let got = kpasswd_udp_exchange_to(dest, b"req").expect("kdc reply");
        assert_eq!(got, b"kdc-ok");
    }
}
