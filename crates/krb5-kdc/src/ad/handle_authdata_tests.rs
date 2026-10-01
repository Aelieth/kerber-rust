use super::*;

#[test]
fn if_relevant_decode_fail_is_not_issued() {
    let junk = AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: b"not-der".to_vec().into(),
    };
    assert!(!is_kdc_issued_authdatum(&junk));
}

#[test]
fn copy_tgt_strips_issued_keeps_other() {
    let keep = AuthorizationDataValue {
        ad_type: pa::AD_AND_OR,
        ad_data: b"keep".to_vec().into(),
    };
    let pac = AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: encode(&vec![AuthorizationDataValue {
            ad_type: pa::AD_WIN2K_PAC,
            ad_data: b"p".to_vec().into(),
        }])
        .unwrap()
        .into(),
    };
    let tgt = vec![pac, keep.clone()];
    let out = handle_authdata(true, false, None, None, None, Some(&tgt), None, None)
        .unwrap()
        .unwrap();
    assert!(out.iter().any(|e| e.ad_type == pa::AD_AND_OR));
    assert!(out.iter().all(|e| !is_kdc_issued_authdatum(e)));
}

#[test]
fn tgt_mandatory_is_handle_authdata() {
    let tgt = vec![AuthorizationDataValue {
        ad_type: pa::AD_MANDATORY_FOR_KDC,
        ad_data: Vec::<u8>::new().into(),
    }];
    let err = handle_authdata(true, false, None, None, None, Some(&tgt), None, None).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::POLICY);
            assert_eq!(text.as_deref(), Some(status::HANDLE_AUTHDATA));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn check_indicators_any_match_and_policy() {
    let mut server = crate::store::Principal::from_keys(
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["svc"]),
        "KERBER.TEST".into(),
        Vec::new(),
        Vec::new(),
        crate::store::PrincipalFields {
            requires_preauth: false,
            max_life: 0,
            locked: false,
            pw_expire: 0,
        },
    );
    assert!(check_indicators(&server, &[]).is_ok());
    server
        .string_attrs
        .push((REQUIRE_AUTH.into(), "pkinit spake".into()));
    assert!(check_indicators(&server, &["spake".into()]).is_ok());
    let err = check_indicators(&server, &["password".into()]).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::POLICY);
            assert_eq!(
                text.as_deref(),
                Some(status::HIGHER_AUTHENTICATION_REQUIRED)
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn cammac_round_trip_and_bad_mac_ignored() {
    let key = crate::store::random_key(EncryptionType::Aes256CtsHmacSha196).unwrap();
    let mut tgt = crate::store::Principal::from_keys(
        PrincipalName::krbtgt("KERBER.TEST"),
        "KERBER.TEST".into(),
        Vec::new(),
        Vec::new(),
        crate::store::PrincipalFields {
            requires_preauth: false,
            max_life: 0,
            locked: false,
            pw_expire: 0,
        },
    );
    tgt.keys.push(crate::store::KeyEntry::new(
        EncryptionType::Aes256CtsHmacSha196,
        key.clone(),
        1,
    ));
    let part = EncTicketPart {
        flags: krb5_types::TicketFlags::initial_preauth(),
        key: EncryptionKey {
            keytype: key.etype().to_iana(),
            keyvalue: key.as_bytes().to_vec().into(),
        },
        crealm: krb5_types::try_ascii("KERBER.TEST").unwrap(),
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        transited: krb5_types::TransitedEncoding {
            tr_type: 1,
            contents: Vec::<u8>::new().into(),
        },
        authtime: krb5_types::KerberosTime::now(),
        starttime: None,
        endtime: krb5_types::KerberosTime::now(),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let mut extra = AuthorizationData::new();
    add_auth_indicators(&mut extra, &["pkinit".into()], &key, &tgt, &key, &part).unwrap();
    let mut issued = part.clone();
    issued.authorization_data = Some(extra.clone());
    let got = get_auth_indicators(&crate::store::Policy::default(), &issued, &tgt, &key).unwrap();
    assert_eq!(got, vec!["pkinit".to_string()]);
    extra[0].ad_data = b"nope".to_vec().into();
    issued.authorization_data = Some(extra);
    let err =
        get_auth_indicators(&crate::store::Policy::default(), &issued, &tgt, &key).unwrap_err();
    match err {
        Error::Protocol { text, .. } => {
            assert_eq!(text.as_deref(), Some(status::GET_AUTH_INDICATORS));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn cammac_bad_kdcver_mac_is_skipped() {
    let key = crate::store::random_key(EncryptionType::Aes256CtsHmacSha196).unwrap();
    let mut tgt = crate::store::Principal::from_keys(
        PrincipalName::krbtgt("KERBER.TEST"),
        "KERBER.TEST".into(),
        Vec::new(),
        Vec::new(),
        crate::store::PrincipalFields {
            requires_preauth: false,
            max_life: 0,
            locked: false,
            pw_expire: 0,
        },
    );
    tgt.keys.push(crate::store::KeyEntry::new(
        EncryptionType::Aes256CtsHmacSha196,
        key.clone(),
        1,
    ));
    let part = EncTicketPart {
        flags: krb5_types::TicketFlags::initial_preauth(),
        key: EncryptionKey {
            keytype: key.etype().to_iana(),
            keyvalue: key.as_bytes().to_vec().into(),
        },
        crealm: krb5_types::try_ascii("KERBER.TEST").unwrap(),
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        transited: krb5_types::TransitedEncoding {
            tr_type: 1,
            contents: Vec::<u8>::new().into(),
        },
        authtime: krb5_types::KerberosTime::now(),
        starttime: None,
        endtime: krb5_types::KerberosTime::now(),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let mut extra = AuthorizationData::new();
    add_auth_indicators(&mut extra, &["pkinit".into()], &key, &tgt, &key, &part).unwrap();
    let inner: AuthorizationData = decode(extra[0].ad_data.as_ref()).unwrap();
    let mut cammac: Cammac = decode(inner[0].ad_data.as_ref()).unwrap();
    let ver = cammac.kdc_verifier.as_mut().unwrap();
    let mut bytes = ver.mac.checksum.as_ref().to_vec();
    bytes[0] ^= 0xff;
    ver.mac.checksum = bytes.into();
    let inner = vec![AuthorizationDataValue {
        ad_type: pa::AD_CAMMAC,
        ad_data: encode(&cammac).unwrap().into(),
    }];
    extra[0].ad_data = encode(&inner).unwrap().into();
    let mut issued = part.clone();
    issued.authorization_data = Some(extra);
    let got = get_auth_indicators(&crate::store::Policy::default(), &issued, &tgt, &key).unwrap();
    assert_eq!(got, [] as [String; 0]);
}

#[test]
fn module_error_is_logged_as_kdc_authdata_module_with_the_schema_fields() {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    struct Failing;
    impl crate::plugins::KdcAuthdata for Failing {
        fn name(&self) -> &'static str {
            "schema-probe"
        }
        fn handle(
            &self,
            _is_tgs: bool,
            _reply: &mut AuthorizationData,
            _session: Option<&ProtocolKey>,
            _issuer: Option<(&PrincipalName, &str)>,
        ) -> Result<(), Error> {
            Err(Error::Crypto("probe refused".into()))
        }
    }
    struct Mem(Arc<Mutex<Vec<u8>>>);
    impl Write for Mem {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| io::Error::other("poison"))?
                .extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn string_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        let pat = format!("\"{key}\":");
        let rest = line[line.find(&pat)? + pat.len()..].trim_start();
        let rest = rest.strip_prefix('"')?;
        Some(&rest[..rest.find('"')?])
    }

    crate::plugins::register_authdata(Arc::new(Failing));
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer = Arc::clone(&buf);
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_current_span(false)
        .with_writer(move || Mem(Arc::clone(&writer)))
        .finish();
    let out = tracing::subscriber::with_default(subscriber, || {
        handle_authdata(false, false, None, None, None, None, None, None)
    });
    assert!(out.is_ok(), "a module error is logged, not returned");
    let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    let line = text
        .lines()
        .find(|l| string_field(l, "event") == Some("kdc.authdata.module"))
        .unwrap_or_else(|| panic!("no kdc.authdata.module line in {text}"));
    for key in ["event", "correlation_id", "component", "outcome"] {
        assert!(string_field(line, key).is_some(), "{key} missing in {line}");
    }
    assert_eq!(string_field(line, "component"), Some("krb5-kdc"));
    assert_eq!(string_field(line, "outcome"), Some("error"));
    assert_eq!(string_field(line, "module"), Some("schema-probe"));
}
