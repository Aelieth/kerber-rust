//! MIT `plugins/kdcpolicy/test` (`t_kdcpolicy.py`), built only in test and `test-hooks` builds.
//!
//! A release binary has no `test` module: it cannot name `testrealm`, a string banned in a ship
//! build. Registered only when `[plugins] kdcpolicy` `enable_only` lists `test`.

use krb5_types::{EncTicketPart, KdcReqBody, PrincipalName};

use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::plugins::{KdcPolicy, PolicyAdjustment};
use crate::preauth::proto;
use crate::status;
use crate::store::Principal;

/// MIT's kdcpolicy test module. The profile name is `test`.
pub struct TestModule;

fn first_comp(name: &PrincipalName) -> Option<String> {
    name.name_string
        .first()
        .map(|component| String::from_utf8_lossy(component.as_bytes()).into_owned())
}

fn output_from_indicator(indicators: &[String], divisor: i64) -> Result<PolicyAdjustment, Error> {
    let Some(indicator) = indicators.first() else {
        return Ok(PolicyAdjustment::default());
    };
    let life = match indicator.as_str() {
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

impl KdcPolicy for TestModule {
    fn name(&self) -> &'static str {
        "test"
    }

    fn check_as_req(
        &self,
        request: &KdcReqBody,
        store: &dyn PrincipalRead,
        client: &Principal,
        _server: &Principal,
        indicators: &[String],
        status_out: &mut Option<&'static str>,
    ) -> Result<PolicyAdjustment, Error> {
        if request.cname.as_ref().and_then(first_comp).as_deref() == Some("fail") {
            *status_out = Some(status::LOCAL_POLICY);
            return Err(proto(krb5_types::err::POLICY, status::LOCAL_POLICY));
        }
        self.check_as(store, client, indicators).inspect_err(|_| {
            *status_out = Some(status::LOCAL_POLICY);
        })
    }

    fn check_tgs_req(
        &self,
        request: &KdcReqBody,
        store: &dyn PrincipalRead,
        server: &Principal,
        _ticket: &EncTicketPart,
        indicators: &[String],
        status_out: &mut Option<&'static str>,
    ) -> Result<PolicyAdjustment, Error> {
        if request.sname.as_ref().and_then(first_comp).as_deref() == Some("fail") {
            *status_out = Some(status::LOCAL_POLICY);
            return Err(proto(krb5_types::err::POLICY, status::LOCAL_POLICY));
        }
        self.check_tgs(store, &server.name, indicators)
            .inspect_err(|_| {
                *status_out = Some(status::LOCAL_POLICY);
            })
    }

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
