//! The `require_mfa` `KdcPolicy`: see the crate README. The refusal is 24, so it is no oracle.

use krb5_kdc::{Error, KdcPolicy, PolicyAdjustment, Principal, PrincipalRead};
use krb5_types::{EncTicketPart, KdcReqBody, PrincipalName};

pub struct RequireMfa {
    indicator: String,
}

impl RequireMfa {
    #[must_use]
    pub fn new(indicator: impl Into<String>) -> Self {
        Self {
            indicator: indicator.into(),
        }
    }

    #[must_use]
    pub fn from_env() -> Self {
        Self::new(
            std::env::var("KERBER_EXAMPLE_MFA_INDICATOR").unwrap_or_else(|_| "mfa".to_owned()),
        )
    }

    fn needs_mfa(client: &Principal) -> bool {
        client.string_attrs.iter().any(|(k, _)| k == "require_mfa")
    }

    fn satisfied(&self, indicators: &[String]) -> bool {
        indicators.contains(&self.indicator)
    }

    fn refuse() -> Error {
        Error::Protocol {
            code: krb5_types::err::PREAUTH_FAILED,
            text: None,
            e_data: None,
            detail: Some("require_mfa: the MFA auth indicator is missing".to_owned()),
        }
    }
}

impl KdcPolicy for RequireMfa {
    fn name(&self) -> &'static str {
        "require_mfa"
    }

    fn check_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Ok(PolicyAdjustment::default())
    }

    fn check_tgs(
        &self,
        _store: &dyn PrincipalRead,
        _sname: &PrincipalName,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Ok(PolicyAdjustment::default())
    }

    fn check_as_req(
        &self,
        _request: &KdcReqBody,
        _store: &dyn PrincipalRead,
        client: &Principal,
        _server: &Principal,
        indicators: &[String],
        _status: &mut Option<&'static str>,
    ) -> Result<PolicyAdjustment, Error> {
        if Self::needs_mfa(client) && !self.satisfied(indicators) {
            return Err(Self::refuse());
        }
        Ok(PolicyAdjustment::default())
    }

    fn check_tgs_req(
        &self,
        _request: &KdcReqBody,
        store: &dyn PrincipalRead,
        _server: &Principal,
        ticket: &EncTicketPart,
        indicators: &[String],
        _status: &mut Option<&'static str>,
    ) -> Result<PolicyAdjustment, Error> {
        let crealm = String::from_utf8_lossy(ticket.crealm.as_bytes());
        if crealm == store.realm()
            && let Ok(Some(client)) = store.fetch_name(&ticket.cname)
            && Self::needs_mfa(&client)
            && !self.satisfied(indicators)
        {
            return Err(Self::refuse());
        }
        Ok(PolicyAdjustment::default())
    }
}
