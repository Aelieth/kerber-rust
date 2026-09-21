use super::*;

#[test]
fn principal_compare_ignores_name_type_and_checks_realm() {
    let a = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let b = PrincipalName::new(PrincipalName::NT_UNKNOWN, ["user"]);
    let c = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    assert!(principal_compare(&a, "KERBER.TEST", &b, "KERBER.TEST"));
    assert!(!principal_compare(&a, "KERBER.TEST", &b, "OTHER.TEST"));
    assert!(!principal_compare(&a, "KERBER.TEST", &c, "KERBER.TEST"));
}

#[test]
fn ticket_flags_initial_preauth_is_rfc_bits_9_and_10() {
    let f = TicketFlags::initial_preauth();
    assert!(f.initial(), "bit 9 initial");
    assert!(f.pre_authent(), "bit 10 pre-authent");
    assert!(!f.renewable(), "must not set renewable (bit 8)");
    // MIT packed: bit 9 => 1<<22, bit 10 => 1<<21
    assert_eq!(f.to_u32(), 0x0060_0000);
    let round = TicketFlags::from_u32(0x0060_0000);
    assert!(round.initial() && round.pre_authent() && !round.renewable());
    assert_eq!(round.mit_letters(), "IA");
    let fwd = TicketFlags::none().with_bit(flag_bit::FORWARDABLE, true);
    assert_eq!(fwd.mit_letters(), "F");
    let ha = TicketFlags::none()
        .with_bit(flag_bit::HW_AUTHENT, true)
        .with_bit(flag_bit::PRE_AUTHENT, true);
    assert_eq!(ha.mit_letters(), "HA");
    let anon = TicketFlags::none().with_bit(flag_bit::ANONYMOUS, true);
    assert_eq!(anon.mit_letters(), "a");
}

#[test]
fn is_krbtgt_requires_two_components() {
    let two = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "KERBER.TEST"]);
    assert!(two.is_krbtgt());
    let three = PrincipalName::new(
        PrincipalName::NT_SRV_INST,
        ["krbtgt", "KERBER.TEST", "extra"],
    );
    assert!(!three.is_krbtgt());
}

#[test]
fn microseconds_rejects_out_of_range() {
    assert!(Microseconds::new(0).is_ok());
    assert!(Microseconds::new(999_999).is_ok());
    assert_eq!(
        Microseconds::new(1_000_000).unwrap_err(),
        TimeError::MicrosecondsOutOfRange(1_000_000)
    );
    assert_eq!(Microseconds::from_subsec_micros(1_000_042).get(), 42);
    assert!(Microseconds(1_000_001).validate().is_err());
}

#[test]
fn add_hours_does_not_panic_on_overflow() {
    let t = kerberos_time_from_utc_z("99991231235959Z").expect("max");
    assert_eq!(t.add_hours(i64::MAX).unwrap_err(), TimeError::Overflow);
    let now = KerberosTime::now();
    assert!(now.add_hours(10).is_ok());
}

#[test]
fn try_new_rejects_non_ascii_principal() {
    let err = PrincipalName::try_new(1, ["usér"]).unwrap_err();
    assert_eq!(err, NameError::NotGeneralString);
    let err = kerberos_string_from_bytes(&[0x80, 0x81]).unwrap_err();
    assert_eq!(err, NameError::NotUtf8);
}

#[test]
fn ap_options_mutual_required_is_bit_2() {
    let o = ApOptions::mutual_required();
    assert!(o.wants_mutual());
    assert!(!o.use_session_key());
    assert!(!ApOptions::none().wants_mutual());
}

#[test]
fn krbtgt_name_helpers() {
    let t = PrincipalName::krbtgt("KERBER.TEST");
    assert!(t.is_krbtgt());
    assert!(t.is_krbtgt_for("KERBER.TEST"));
    assert!(!t.is_krbtgt_for("OTHER.TEST"));
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x"]);
    assert!(!host.is_krbtgt());
    let flat = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["krbtgt/KERBER.TEST"]);
    assert_eq!(t.components_joined(), flat.components_joined());
    assert_ne!(t.name_string, flat.name_string);
}

fn te(contents: &[u8]) -> TransitedEncoding {
    TransitedEncoding {
        tr_type: 1,
        contents: OctetString::from(contents.to_vec()),
    }
}

fn hops(contents: &[u8]) -> Vec<String> {
    te(contents).realms_for("", "").expect("expand")
}

#[test]
fn transited_csv_round_trip() {
    let t = TransitedEncoding::empty()
        .append_realm("A.TEST", "", "")
        .unwrap()
        .append_realm("B.TEST", "", "")
        .unwrap();
    assert_eq!(
        t.realms_for("", "").unwrap(),
        vec!["A.TEST".to_string(), "B.TEST".to_string()]
    );
    assert_eq!(
        t.append_realm("A.TEST", "", "")
            .unwrap()
            .realms_for("", "")
            .unwrap()
            .len(),
        2
    );
    assert_eq!(t.tr_type, 1);
    assert_eq!(TransitedEncoding::empty().tr_type, 1);
}

#[test]
fn transited_x500_expand_mit_live_fixture() {
    // Live MIT 1.22.2 4-hop A.EX.COM→EX.COM→B.EX.COM→C.EX.COM issued
    // tr-type 1 contents "EX.COM,B." (captured s2-live-compress.log).
    assert_eq!(
        hops(b"EX.COM,B."),
        vec!["EX.COM".to_string(), "B.EX.COM".to_string()]
    );
}

#[test]
fn transited_x500_expand_rfc4120_example() {
    assert_eq!(
        hops(b"EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."),
        vec![
            "EDU".to_string(),
            "MIT.EDU".to_string(),
            "ATHENA.MIT.EDU".to_string(),
            "WASHINGTON.EDU".to_string(),
            "CS.WASHINGTON.EDU".to_string(),
        ]
    );
}

#[test]
fn transited_x500_overlong_is_err() {
    let spam = te(&vec![b','; 20_000]);
    assert_eq!(
        spam.realms_for("", "").unwrap_err(),
        TransitError::TooManyFields
    );

    let modest = te(format!("{}X.COM", "X.COM,".repeat(199)).as_bytes());
    let hops = modest.realms_for("", "").unwrap();
    assert_eq!(hops.len(), 200);
    assert_eq!(hops[0], "X.COM");

    let mut long_field = b"X.COM,".to_vec();
    long_field.extend(vec![b'A'; 513]);
    assert_eq!(
        te(&long_field).realms_for("", "").unwrap_err(),
        TransitError::FieldTooLong,
        "≤256 commas holding a >512-byte literal field must err"
    );
}

#[test]
fn transited_x500_escaped_marker_still_joins() {
    assert_eq!(
        hops(b"X.COM,C\\."),
        vec!["X.COM".to_string(), "C.X.COM".to_string()],
        "MIT maybe_join: escaped trailing . still suffix-joins"
    );
    assert_eq!(
        hops(b"X.COM,\\/Y"),
        vec!["X.COM".to_string(), "X.COM/Y".to_string()],
        "MIT maybe_join: escaped leading / still prefix-joins"
    );
    assert_eq!(
        hops(b"X.COM,/Y"),
        vec!["X.COM".to_string(), "X.COM/Y".to_string()],
        "unescaped leading / still prefix-joins"
    );
}

#[test]
fn transited_x500_bounds_nul_and_append() {
    assert_eq!(hops(&vec![b'A'; 511]), vec!["A".repeat(511)]);
    assert_eq!(
        te(&vec![b'A'; 512]).realms_for("", "").unwrap_err(),
        TransitError::FieldTooLong
    );
    assert_eq!(
        te(b",").realms_for("A.TEST", &"A".repeat(512)).unwrap_err(),
        TransitError::FieldTooLong
    );

    let mut joined_ok = b"X,".to_vec();
    joined_ok.extend(vec![b'B'; 510]);
    joined_ok.push(b'.');
    assert_eq!(
        hops(&joined_ok),
        vec!["X".to_string(), format!("{}.X", "B".repeat(510))]
    );

    let mut joined_err = b"XX,".to_vec();
    joined_err.extend(vec![b'B'; 510]);
    joined_err.push(b'.');
    assert_eq!(
        te(&joined_err).realms_for("", "").unwrap_err(),
        TransitError::FieldTooLong
    );

    assert_eq!(hops(b"EDU\0"), vec!["EDU".to_string()]);
    assert!(te(b"\0").realms_for("", "").unwrap().is_empty());

    let x500 = te(b"/COM,/HP").append_realm("X", "", "").unwrap();
    assert_eq!(x500.contents.as_ref(), b"/COM,/HP,X");
    assert_eq!(
        x500.realms_for("", "").unwrap(),
        vec!["/COM".to_string(), "/COM/HP".to_string(), "X".to_string()]
    );

    let spaced = te(b"/COM,/HP").append_realm("/EDU/W", "", "").unwrap();
    assert_eq!(spaced.contents.as_ref(), b"/COM,/HP, /EDU/W");
    assert_eq!(
        spaced.realms_for("", "").unwrap(),
        vec![
            "/COM".to_string(),
            "/COM/HP".to_string(),
            "/EDU/W".to_string()
        ]
    );
}

#[test]
fn transited_mit_transit_tests_vectors() {
    fn set(xs: &[&str]) -> std::collections::BTreeSet<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }
    fn got(crealm: &str, srealm: &str, transit: &[u8]) -> std::collections::BTreeSet<String> {
        te(transit)
            .realms_for(crealm, srealm)
            .expect("expand")
            .into_iter()
            .collect()
    }

    assert_eq!(
        got("ATHENA.MIT.EDU", "HACK.FOOBAR.COM", b",EDU,BLORT.COM,COM,"),
        set(&["MIT.EDU", "EDU", "BLORT.COM", "COM", "FOOBAR.COM"])
    );
    assert_eq!(got("ATHENA.MIT.EDU", "EDU", b","), set(&["MIT.EDU"]));
    assert_eq!(got("EDU", "ATHENA.MIT.EDU", b","), set(&["MIT.EDU"]));
    assert_eq!(
        got("x", "x", b"/COM,/HP,/APOLLO, /COM/DEC"),
        set(&["/COM", "/COM/HP", "/COM/HP/APOLLO", "/COM/DEC"])
    );
    assert_eq!(
        got("x", "x", b"EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."),
        set(&[
            "EDU",
            "MIT.EDU",
            "ATHENA.MIT.EDU",
            "WASHINGTON.EDU",
            "CS.WASHINGTON.EDU"
        ])
    );
    assert_eq!(
        te(b",EDU,/COM,")
            .realms_for("ATHENA.MIT.EDU", "/COM/HP/APOLLO")
            .unwrap_err(),
        TransitError::BadIntermediates
    );
    assert_eq!(
        got("ATHENA.MIT.EDU", "/COM/HP/APOLLO", b",EDU, /COM,"),
        set(&["EDU", "MIT.EDU", "/COM", "/COM/HP"])
    );
    let edu = got("ATHENA.MIT.EDU", "CS.CMU.EDU", b",EDU,");
    assert_eq!(edu, set(&["EDU", "MIT.EDU", "CMU.EDU"]));
    assert_ne!(edu, set(&["EDU"]), ",EDU, must not be hops {{EDU}} only");
    assert_eq!(
        got("XYZZY.ATHENA.MIT.EDU", "XYZZY.CS.CMU.EDU", b",EDU,"),
        set(&["EDU", "MIT.EDU", "ATHENA.MIT.EDU", "CMU.EDU", "CS.CMU.EDU"])
    );
}

#[test]
fn transited_hop_cap_is_too_many_fields() {
    // Space-clears last, emits "/", then 510 slashes with intermediates.
    // Nine cycles exceed MAX_TRANSIT_HOPS; comma count stays under 256.
    let mut cycle = b" /,,".to_vec();
    cycle.extend(std::iter::repeat_n(b'/', 510));
    cycle.push(b',');
    let buf = cycle.repeat(9);
    assert_eq!(
        te(&buf).realms_for("", "").unwrap_err(),
        TransitError::TooManyFields
    );
    assert_eq!(
        hops(b"EX.COM,B."),
        vec!["EX.COM".to_string(), "B.EX.COM".to_string()]
    );
}

#[test]
fn transited_add_path_bounds() {
    let r499 = "A".repeat(499);
    assert_eq!(
        TransitedEncoding::empty()
            .append_realm(&r499, "", "")
            .unwrap()
            .contents
            .as_ref()
            .len(),
        499
    );
    assert_eq!(
        TransitedEncoding::empty()
            .append_realm(&"A".repeat(500), "", "")
            .unwrap_err(),
        TransitError::FieldTooLong
    );
    assert!(te(&vec![b'A'; 511]).realms_for("", "").is_ok());
    assert_eq!(
        te(&vec![b'A'; 512]).realms_for("", "").unwrap_err(),
        TransitError::FieldTooLong
    );
    assert_eq!(
        te(&vec![b'A'; 500]).append_realm("X", "", "").unwrap_err(),
        TransitError::FieldTooLong
    );
    assert_eq!(
        te(&vec![b'A'; 497])
            .append_realm("X", "", "")
            .unwrap()
            .contents
            .as_ref()
            .len(),
        499
    );
    assert_eq!(
        te(&vec![b'A'; 498]).append_realm("X", "", "").unwrap_err(),
        TransitError::FieldTooLong
    );

    let mut joined_ok = b"X,".to_vec();
    joined_ok.extend(vec![b'B'; 496]);
    joined_ok.push(b'.');
    te(&joined_ok)
        .append_realm("X", "", "")
        .expect("joined 498 ok");

    let mut joined_err = b"X,".to_vec();
    joined_err.extend(vec![b'B'; 497]);
    joined_err.push(b'.');
    assert_eq!(
        te(&joined_err).append_realm("X", "", "").unwrap_err(),
        TransitError::FieldTooLong
    );

    let edu = te(b"EDU,").append_realm("X", "", "").unwrap();
    assert_eq!(edu.contents.as_ref(), b"EDU,X");

    let inner = te(b"A,,B").append_realm("X", "", "").unwrap();
    assert_eq!(inner.contents.as_ref(), b"A,,B,X");

    let five = std::iter::repeat_n("A".repeat(100), 5)
        .collect::<Vec<_>>()
        .join(",");
    assert!(five.len() >= 500);
    assert_eq!(
        te(five.as_bytes()).validate_add_path().unwrap_err(),
        TransitError::FieldTooLong
    );
    let named = format!("{},B.TEST", "A".repeat(494));
    assert!(named.len() >= 500);
    assert_eq!(
        te(named.as_bytes())
            .append_realm("B.TEST", "", "")
            .unwrap_err(),
        TransitError::FieldTooLong
    );
}

#[test]
fn pac_ndr_logon_info_round_trip() {
    let raw = pac::logon_info_buffer(
        "user",
        "KERBER.TEST",
        &pac::RpcSid::nt_domain(9, 8, 7),
        1000,
    );
    let (c, r) = pac::parse_logon_info(&raw).expect("NDR parse");
    assert_eq!(c, "user");
    assert_eq!(r, "KERBER.TEST");
}

#[test]
fn pkinit_cms_wrap_unwrap() {
    let inner = b"authpack-bytes";
    let ca = pkinit::PkinitCa::generate().expect("CA");
    let wrapped = pkinit::cms_wrap(inner, &ca).expect("wrap");
    assert_ne!(wrapped, inner);
    assert_eq!(pkinit::cms_unwrap(&wrapped), inner);
    assert_eq!(pkinit::cms_unwrap(inner), inner);
    assert_eq!(
        pkinit::cms_verify(&wrapped, &ca.ca_cert).expect("cert-backed ECDSA"),
        inner
    );
    let mut bad = wrapped.clone();
    if let Some(b) = bad.last_mut() {
        *b ^= 0x01;
    }
    assert!(pkinit::cms_verify(&bad, &ca.ca_cert).is_err());
    assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
    let id = ca.user_identity_pem("user@KERBER.TEST").expect("user pem");
    assert!(id.contains("BEGIN CERTIFICATE"));
    assert!(id.contains("BEGIN EC PRIVATE KEY"));
    let wrapped2 = ca.sign_cms(inner, "kdc").expect("ca cms");
    assert_eq!(
        pkinit::cms_verify(&wrapped2, &ca.ca_cert).expect("ca-backed"),
        inner
    );
    let other = pkinit::PkinitCa::generate().expect("other CA");
    assert!(
        pkinit::cms_verify(&wrapped, &other.ca_cert).is_err(),
        "forged / wrong-anchor CMS must not authenticate"
    );
    assert!(
        pkinit::cms_verify(inner, &ca.ca_cert).is_err(),
        "unwrapped plaintext is not a valid CMS"
    );
    let (cert, key) = pkinit::parse_identity_pem(&id).expect("parse identity");
    assert!(
        cert.windows(6)
            .any(|w| w == [0x2b, 0x06, 0x01, 0x05, 0x02, 0x02]),
        "client cert must carry id-pkinit-san 1.3.6.1.5.2.2"
    );
    let signed =
        pkinit::cms_sign_leaf(inner, &cert, &key, pkinit::ECONTENT_AUTHDATA).expect("leaf cms");
    assert_eq!(
        pkinit::cms_verify(&signed, &ca.ca_cert).expect("leaf verify"),
        inner
    );
    let kdc_pem = ca.kdc_identity_pem().expect("kdc pem");
    assert!(kdc_pem.contains("BEGIN CERTIFICATE"));
    assert!(kdc_pem.contains("BEGIN EC PRIVATE KEY"));
    let (kcert, kkey) = pkinit::parse_identity_pem(&kdc_pem).expect("kdc identity");
    let ksigned =
        pkinit::cms_sign_leaf(inner, &kcert, &kkey, pkinit::ECONTENT_DHKEY).expect("kdc cms");
    assert_eq!(
        pkinit::cms_verify(&ksigned, &ca.ca_cert).expect("kdc leaf verify"),
        inner
    );
    pkinit::require_kdc_pkinit_cert(&kcert, "KERBER.TEST").expect("KPKdc SAN");
    assert!(pkinit::require_kdc_pkinit_cert(&kcert, "OTHER.TEST").is_err());
    assert!(pkinit::require_kdc_pkinit_cert(&cert, "KERBER.TEST").is_err());
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    pkinit::require_client_pkinit_cert(&cert, &user, "KERBER.TEST").expect("client SAN");
    let other = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["other"]);
    assert!(pkinit::require_client_pkinit_cert(&cert, &other, "KERBER.TEST").is_err());

    let split = pkinit::cms_sign_leaf_oids(
        inner,
        &cert,
        &key,
        pkinit::ECONTENT_AUTHDATA,
        pkinit::ECONTENT_DHKEY,
    )
    .expect("split oids");
    assert_eq!(
        pkinit::cms_verify_full(&split, &ca.ca_cert).expect_err("content-type"),
        "cms content-type"
    );
    let body = b"kdc-req-body";
    let ck = pkinit::kdc_req_body_checksum(body);
    let pk_auth = pkinit::PkAuthenticator {
        cusec: Microseconds::ZERO,
        ctime: KerberosTime::now(),
        nonce: 1,
        pa_checksum: Some(ck.clone().into()),
        freshness_token: None,
    };
    let pack = pkinit::encode_client_authpack(&pk_auth, &pkinit::encode_ec_spki(&[0x04u8; 65]))
        .expect("authpack");
    pkinit::authpack_pa_checksum_ok(&pack, body).expect("paChecksum");
    assert!(pkinit::authpack_pa_checksum_ok(&pack, b"other-body").is_err());
    let mut ck_bad = ck;
    ck_bad[0] ^= 1;
    let pk_bad = pkinit::PkAuthenticator {
        cusec: Microseconds::ZERO,
        ctime: KerberosTime::now(),
        nonce: 1,
        pa_checksum: Some(ck_bad.into()),
        freshness_token: None,
    };
    let pack_bad = pkinit::encode_client_authpack(&pk_bad, &pkinit::encode_ec_spki(&[0x04u8; 65]))
        .expect("authpack bad");
    assert!(pkinit::authpack_pa_checksum_ok(&pack_bad, body).is_err());
}

#[test]
fn pkinit_cms_path_validation() {
    let ca = pkinit::PkinitCa::generate().expect("CA");
    let inner = b"path-validation";
    let wrapped = pkinit::cms_wrap(inner, &ca).expect("wrap");
    assert_eq!(
        pkinit::cms_verify(&wrapped, &ca.ca_cert).expect("in-window chain"),
        inner
    );

    let (expired, ekey) = ca
        .client_identity_window("user@KERBER.TEST", b"200101000000Z", b"210101000000Z")
        .expect("expired");
    let cms = pkinit::cms_sign_leaf(inner, &expired, &ekey, pkinit::ECONTENT_AUTHDATA)
        .expect("expired cms");
    assert_eq!(
        pkinit::cms_verify(&cms, &ca.ca_cert).expect_err("expired"),
        "cms expired"
    );

    let (ee, ek) = pkinit::PkinitCa::self_signed_end_entity().expect("ee");
    let cms = pkinit::cms_sign_leaf(inner, &ee, &ek, pkinit::ECONTENT_AUTHDATA).expect("ee cms");
    assert_eq!(
        pkinit::cms_verify(&cms, &ee).expect_err("non-CA anchor"),
        "cms ca"
    );

    let (wrong, wkey) = ca
        .client_identity_wrong_issuer("user@KERBER.TEST")
        .expect("wrong issuer");
    let cms =
        pkinit::cms_sign_leaf(inner, &wrong, &wkey, pkinit::ECONTENT_AUTHDATA).expect("wrong cms");
    assert_eq!(
        pkinit::cms_verify(&cms, &ca.ca_cert).expect_err("DN mismatch"),
        "cms chain"
    );

    let expired_ca =
        pkinit::PkinitCa::generate_window(b"200101000000Z", b"210101000000Z").expect("expired CA");
    let cms = expired_ca.sign_cms(inner, "user").expect("expired ca cms");
    assert_eq!(
        pkinit::cms_verify(&cms, &expired_ca.ca_cert).expect_err("expired CA"),
        "cms ca expired"
    );

    let noku = pkinit::PkinitCa::generate_no_key_cert_sign().expect("no ku");
    let cms = noku.sign_cms(inner, "user").expect("no ku cms");
    assert_eq!(
        pkinit::cms_verify(&cms, &noku.ca_cert).expect_err("no keyCertSign"),
        "cms ca ku"
    );
    let absent = pkinit::PkinitCa::generate_absent_key_usage().expect("absent ku");
    let cms = absent.sign_cms(inner, "user").expect("absent ku cms");
    assert_eq!(
        pkinit::cms_verify(&cms, &absent.ca_cert).expect("RFC 5280 absent KU"),
        inner
    );

    let kcert = {
        let (c, _, _) = ca.kdc_identity_for("KERBER.TEST").expect("kdc");
        c
    };
    assert!(pkinit::require_kdc_pkinit_cert(&kcert, "kerber.test").is_err());
}

#[test]
fn pa_pk_as_rep_is_choice_dhinfo() {
    let rep = pkinit::PaPkAsRep::DhInfo(pkinit::DhRepInfo {
        dh_signed_data: vec![1, 2, 3].into(),
        server_dh_nonce: None,
    });
    let der = rasn::der::encode(&rep).expect("CHOICE");
    assert_eq!(
        der.first().copied(),
        Some(0xa0),
        "PA-PK-AS-REP dhInfo is [0] EXPLICIT, not a SEQUENCE"
    );
    let back = rasn::der::decode::<pkinit::PaPkAsRep>(&der).expect("round-trip");
    match back {
        pkinit::PaPkAsRep::DhInfo(info) => assert_eq!(info.dh_signed_data.as_ref(), &[1, 2, 3]),
        pkinit::PaPkAsRep::EncKeyPack(_) => panic!("expected DhInfo"),
    }
}

#[test]
fn pa_pk_as_req_signed_auth_pack_is_implicit() {
    let req = pkinit::PaPkAsReq {
        signed_auth_pack: vec![9, 9, 9].into(),
        trusted_certifiers: None,
        kdc_pk_id: None,
    };
    let der = rasn::der::encode(&req).expect("req");
    assert_eq!(der.first().copied(), Some(0x30));
    let body = rasn::der::decode::<pkinit::PaPkAsReq>(&der).expect("round-trip");
    assert_eq!(body.signed_auth_pack.as_ref(), &[9, 9, 9]);
    let cms = pkinit::parse_pa_pk_as_req_cms(&der).expect("implicit 0x80");
    assert_eq!(cms, vec![9, 9, 9]);
    assert_eq!(
        der.get(2).copied(),
        Some(0x80),
        "signedAuthPack is [0] IMPLICIT OCTET STRING"
    );
}

#[test]
fn parse_authpack_accepts_spki_sequence() {
    let spki = pkinit::encode_ec_spki(&[0x04u8; 65]);
    // AuthPack SEQUENCE { [0] empty-ish, [1] EXPLICIT SPKI }
    // Minimal: SEQUENCE { [1] EXPLICIT SPKI } is enough for parse_authpack.
    let mut inner = vec![0xa1];
    let spki_len = u8::try_from(spki.len()).expect("spki");
    inner.push(spki_len);
    inner.extend_from_slice(&spki);
    let mut seq = vec![0x30, 0];
    seq.extend_from_slice(&inner);
    seq[1] = u8::try_from(inner.len()).expect("seq");
    let (nonce, got) = pkinit::parse_authpack(&seq).expect("parse");
    assert_eq!(nonce, 0);
    assert_eq!(got, spki);
}

#[test]
fn typed_data_uses_rfc6113_tags_not_padata() {
    // MIT encode_krb5_typed_data (asn1_k_encode.c:1547-1556): [0] Int32, [1] OCTET STRING.
    let td: crate::TypedDataList = vec![crate::TypedData {
        data_type: 13,
        data_value: b"pa-data".to_vec().into(),
    }];
    let der = rasn::der::encode(&td).expect("TYPED-DATA");
    assert_eq!(der[0], 0x30);
    let pa: crate::MethodData = vec![crate::PaData {
        padata_type: 13,
        padata_value: b"pa-data".to_vec().into(),
    }];
    let pa_der = rasn::der::encode(&pa).expect("METHOD-DATA");
    assert_ne!(
        der, pa_der,
        "TYPED-DATA tags [0]/[1] must not match PA-DATA [1]/[2]"
    );
    let first_ctx = der.iter().copied().find(|b| b & 0xc0 == 0x80);
    assert_eq!(
        first_ctx,
        Some(0xa0),
        "data-type is [0] EXPLICIT, not PA-DATA [1]"
    );
    let pa_ctx = pa_der.iter().copied().find(|b| b & 0xc0 == 0x80);
    assert_eq!(pa_ctx, Some(0xa1), "PA-DATA type is [1]");
    let back = rasn::der::decode::<crate::TypedDataList>(&der).expect("round-trip");
    assert_eq!(back[0].data_type, 13);
    assert_eq!(back[0].data_value.as_ref(), &b"pa-data"[..]);
    let as_pa: crate::MethodData = rasn::der::decode(&der).unwrap_or_default();
    assert!(
        as_pa.is_empty(),
        "TYPED-DATA must not decode as PA-DATA entries: {as_pa:?}"
    );
    let empty: crate::TypedDataList = vec![crate::TypedData {
        data_type: 109,
        data_value: Vec::<u8>::new().into(),
    }];
    let empty_der = rasn::der::encode(&empty).expect("empty data-value");
    assert!(
        empty_der
            .windows(2)
            .any(|w| w == [0xa1, 0x02] || w[0] == 0xa1),
        "DEFCNFIELD always encodes [1] data-value: {empty_der:02x?}"
    );
}

#[test]
fn parse_dh_spki_round_trips_p_and_y() {
    let p = vec![0xff, 0xff, 0xff, 0xfd];
    let y = vec![0x03];
    let spki = pkinit::encode_dh_spki(&p, &y);
    let (got_p, got_y) = pkinit::parse_dh_spki(&spki).expect("DH SPKI");
    assert_eq!(got_p, p);
    assert_eq!(got_y, y);
    assert!(pkinit::decode_ec_spki(&spki).is_none());
}
