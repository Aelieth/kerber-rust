use super::*;

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
