//! MIT `plugins/kdcpolicy/test` (`t_kdcpolicy.py`), for the release KDC.
//!
//! The release binary cannot name `testrealm`: that string is banned in a
//! ship build. This module is the same checks, registered only when
//! `[plugins] kdcpolicy` `enable_only` lists `test`.

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testrealm::{
        TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    };

    fn user_store() -> (crate::PrincipalStore, Principal) {
        let store = crate::PrincipalStore::bootstrap(
            TEST_REALM,
            TEST_USER,
            TEST_USER_PASSWORD,
            TEST_ADMIN,
            TEST_ADMIN_PASSWORD,
        )
        .unwrap();
        let user = store
            .get_name(&PrincipalName::new(
                PrincipalName::NT_PRINCIPAL,
                [TEST_USER],
            ))
            .unwrap()
            .clone();
        (store, user)
    }

    fn assert_local_policy(err: Error) {
        match err {
            Error::Protocol { code, text, .. } => {
                assert_eq!(code, krb5_types::err::POLICY);
                assert_eq!(text.as_deref(), Some(status::LOCAL_POLICY));
            }
            other => panic!("expected LOCAL_POLICY, got {other:?}"),
        }
    }

    #[test]
    fn one_hour_caps_other_and_fail_deny_empty_does_not() {
        let (store, user) = user_store();
        let hour = TestModule
            .check_as(&store, &user, &["ONE_HOUR".to_owned()])
            .unwrap();
        assert_eq!(hour.lifetime, 3600);
        assert_eq!(hour.renew_lifetime, 7200);
        let tgs = TestModule
            .check_tgs(&store, &user.name, &["ONE_HOUR".to_owned()])
            .unwrap();
        assert_eq!(tgs.lifetime, 1800);
        assert_eq!(tgs.renew_lifetime, 3600);
        let empty = TestModule.check_as(&store, &user, &[]).unwrap();
        assert_eq!(empty.lifetime, 0);
        assert_local_policy(
            TestModule
                .check_as(&store, &user, &["OTHER".to_owned()])
                .unwrap_err(),
        );
        let mut fail = user;
        fail.name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["fail"]);
        assert_local_policy(TestModule.check_as(&store, &fail, &[]).unwrap_err());
        assert_local_policy(
            TestModule
                .check_tgs(&store, &fail.name, &["ONE_HOUR".to_owned()])
                .unwrap_err(),
        );
    }
}
