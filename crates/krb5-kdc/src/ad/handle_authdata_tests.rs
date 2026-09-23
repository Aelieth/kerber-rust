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
    assert!(got.is_empty());
}
