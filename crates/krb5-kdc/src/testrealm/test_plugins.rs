//! In-tree stand-ins for MIT's test plugins.
//!
//! MIT `plugins/kdcpolicy/test`, `plugins/audit/test`,
//! `plugins/authdata/greet_server`, and `plugins/authdata/greet_client`.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use krb5_asn1::encode;
use krb5_crypto::{KeyUsage, ProtocolKey, checksum};
use krb5_types::cammac::AdKdcIssued;
use krb5_types::{
    AuthorizationData, AuthorizationDataValue, Checksum, PaData, PrincipalName, ku, pa,
};

use crate::audit::{AuditState, KdcAudit, start_stop_json};
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::plugins::{KdcAuthdata, KdcPolicy, KdcPreauth, PolicyAdjustment, PreauthAction};
use crate::preauth::proto;
use crate::status;
use crate::store::Principal;

/// Demo extra module: counts advertise/process so tests prove the registry.
#[derive(Debug)]
pub struct DemoPreauth {
    /// advertise() calls.
    pub ads: AtomicU64,
    /// process_as() calls.
    pub procs: AtomicU64,
}

impl DemoPreauth {
    /// Zero counters.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ads: AtomicU64::new(0),
            procs: AtomicU64::new(0),
        })
    }
}

impl KdcPreauth for DemoPreauth {
    fn name(&self) -> &'static str {
        "demo"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[]
    }
    fn advertise(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _armor: bool,
        _requested: &[i32],
    ) -> Vec<PaData> {
        self.ads.fetch_add(1, Ordering::SeqCst);
        Vec::new()
    }
    fn process_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _padata: Option<&[PaData]>,
        _ikey: &ProtocolKey,
        _etype: krb5_crypto::EncryptionType,
        _as_req_der: &[u8],
        _body_der: &[u8],
        _cname: &PrincipalName,
    ) -> Result<Option<PreauthAction>, Error> {
        self.procs.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
}

/// MIT greet_server AD type (`greet_auth.c:55`).
pub const GREET_AD_TYPE: i32 = -42;
/// MIT greet_server greeting (`greet_auth.c:38`).
pub const GREET_TEXT: &[u8] = b"Hello, KDC issued acceptor world!";

/// Test / deploy greet module. Production loads none unless `KERBER_KDC_GREET=1`.
pub struct GreetAuth;

fn make_authdata_kdc_issued(
    session: &ProtocolKey,
    issuer: &PrincipalName,
    realm: &str,
    elements: &[AuthorizationDataValue],
) -> Result<AuthorizationDataValue, Error> {
    let der = encode(&elements.to_vec())?;
    let usage = KeyUsage::new(ku::AD_KDCISSUED_CKSUM)?;
    let mac = checksum(session, usage, &der)?;
    let issued = AdKdcIssued {
        ad_checksum: Checksum {
            cksumtype: session.etype().checksum_type(),
            checksum: mac.into(),
        },
        i_realm: Some(krb5_types::try_ascii(realm).map_err(|e| Error::Crypto(e.to_string()))?),
        i_sname: Some(issuer.clone()),
        elements: elements.to_vec(),
    };
    Ok(AuthorizationDataValue {
        ad_type: pa::AD_KDC_ISSUED,
        ad_data: encode(&issued)?.into(),
    })
}

impl KdcAuthdata for GreetAuth {
    fn name(&self) -> &'static str {
        "greet"
    }
    fn handle(
        &self,
        is_tgs: bool,
        reply: &mut AuthorizationData,
        session: Option<&ProtocolKey>,
        issuer: Option<(&PrincipalName, &str)>,
    ) -> Result<(), Error> {
        if !is_tgs {
            return Ok(());
        }
        let Some(session) = session else {
            return Ok(());
        };
        let Some((tgs, realm)) = issuer else {
            return Ok(());
        };
        let elements = vec![AuthorizationDataValue {
            ad_type: GREET_AD_TYPE,
            ad_data: GREET_TEXT.to_vec().into(),
        }];
        let kdc_issued = make_authdata_kdc_issued(session, tgs, realm, &elements)?;
        let wrapped = encode(&vec![kdc_issued])?;
        let greet = AuthorizationDataValue {
            ad_type: pa::AD_IF_RELEVANT,
            ad_data: wrapped.into(),
        };
        let mut merged = vec![greet];
        merged.append(reply);
        *reply = merged;
        Ok(())
    }
}

/// MIT `plugins/kdcpolicy/test` (`t_kdcpolicy.py`).
pub struct TestPolicy;

fn first_comp(name: &PrincipalName) -> Option<String> {
    name.name_string
        .first()
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
}

fn output_from_indicator(indicators: &[String], divisor: i64) -> Result<PolicyAdjustment, Error> {
    let Some(ind) = indicators.first() else {
        return Ok(PolicyAdjustment::default());
    };
    let life = match ind.as_str() {
        "ONE_HOUR" => 3600 / divisor,
        "SEVEN_HOURS" => 7 * 3600 / divisor,
        _ => {
            return Err(proto(krb5_types::err::POLICY, status::LOCAL_POLICY));
        }
    };
    Ok(PolicyAdjustment {
        lifetime: life,
        renew_lifetime: life * 2,
    })
}

impl KdcPolicy for TestPolicy {
    fn check_as(
        &self,
        _store: &dyn PrincipalRead,
        client: &Principal,
        indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        if first_comp(&client.name).as_deref() == Some("fail") {
            return Err(proto(krb5_types::err::POLICY, status::LOCAL_POLICY));
        }
        output_from_indicator(indicators, 1)
    }
    fn check_tgs(
        &self,
        _store: &dyn PrincipalRead,
        sname: &PrincipalName,
        indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        if first_comp(sname).as_deref() == Some("fail") {
            return Err(proto(krb5_types::err::POLICY, status::LOCAL_POLICY));
        }
        output_from_indicator(indicators, 2)
    }
}

/// Test hook: deny every AS and TGS.
#[cfg(test)]
pub struct DenyPolicy;

#[cfg(test)]
impl KdcPolicy for DenyPolicy {
    fn check_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Err(Error::Protocol {
            code: krb5_types::err::POLICY,
            text: Some("kdcpolicy".into()),
            e_data: None,
            detail: None,
        })
    }
    fn check_tgs(
        &self,
        _store: &dyn PrincipalRead,
        _sname: &PrincipalName,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Err(Error::Protocol {
            code: krb5_types::err::POLICY,
            text: Some("kdcpolicy".into()),
            e_data: None,
            detail: None,
        })
    }
}

/// Demo policy: counts AS/TGS checks.
#[derive(Debug, Default)]
pub struct DemoPolicy {
    /// AS checks.
    pub(crate) as_checks: AtomicU64,
    /// TGS checks.
    pub(crate) tgs_checks: AtomicU64,
}

impl KdcPolicy for DemoPolicy {
    fn check_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        self.as_checks.fetch_add(1, Ordering::SeqCst);
        Ok(PolicyAdjustment::default())
    }
    fn check_tgs(
        &self,
        _store: &dyn PrincipalRead,
        _sname: &PrincipalName,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        self.tgs_checks.fetch_add(1, Ordering::SeqCst);
        Ok(PolicyAdjustment::default())
    }
}

/// MIT `plugins/audit/test` twin: append one JSON object per line.
pub struct TestAudit {
    file: Mutex<File>,
    path: PathBuf,
}

impl TestAudit {
    /// Open `path` for append (MIT `fopen("au.log", "a+")`).
    ///
    /// # Errors
    ///
    /// The file could not be created or opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            file: Mutex::new(file),
            path,
        })
    }

    /// Destination path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write_line(&self, line: &str) {
        let mut f = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = writeln!(f, "{line}");
        let _ = f.flush();
    }
}

impl KdcAudit for TestAudit {
    fn kdc_start(&self, success: bool) {
        self.write_line(&start_stop_json("KDC_START", success));
    }
    fn kdc_stop(&self, success: bool) {
        self.write_line(&start_stop_json("KDC_STOP", success));
    }
    fn as_req(&self, success: bool, state: &AuditState) {
        self.write_line(&state.to_json(success));
    }
    fn tgs_req(&self, success: bool, state: &AuditState) {
        self.write_line(&state.to_json(success));
    }
    fn s4u2self(&self, success: bool, state: &AuditState) {
        self.write_line(&state.to_json(success));
    }
    fn s4u2proxy(&self, success: bool, state: &AuditState) {
        self.write_line(&state.to_json(success));
    }
    fn u2u(&self, success: bool, state: &AuditState) {
        self.write_line(&state.to_json(success));
    }
}
