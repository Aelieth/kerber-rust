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
    assert_eq!(te(b"\0").realms_for("", "").unwrap(), [] as [String; 0]);

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
    // MIT `typed_data_0` (`asn1_k_encode.c:1547-1547`): `data-type [0]` is an Int32.
    // MIT `typed_data_1` (`asn1_k_encode.c:1548-1548`): `data-value [1]` is an OCTET STRING.
    // MIT `typed_data_fields` (`asn1_k_encode.c:1549-1551`): `encode_krb5_typed_data` writes
    // those two fields in that order.
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

/// Key octets with a quote, a backslash, a newline and a NUL, so each rendering differs.
const SECRET: [u8; 16] = [
    0x13, 0x37, 0xc0, 0xde, 0x22, 0x5c, 0x0a, 0xa5, 0x9e, 0x41, 0x42, 0x43, 0x7f, 0x00, 0xfe, 0x5a,
];

/// Whether `debug` shows `secret` as hex, as a list of numbers, as an escaped byte string (an
/// `OctetString`'s derived `Debug`), or as text.
fn shows(debug: &str, secret: &[u8]) -> bool {
    use std::fmt::Write as _;
    let hex = secret.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    let numbers = format!("{secret:?}");
    let escaped = format!("{:?}", bytes::Bytes::copy_from_slice(secret));
    debug.to_lowercase().contains(&hex)
        || debug.contains(&numbers[1..numbers.len() - 1])
        || debug.contains(&escaped[2..escaped.len() - 1])
        || std::str::from_utf8(secret).is_ok_and(|text| debug.contains(text))
}

fn secret_key() -> EncryptionKey {
    EncryptionKey {
        keytype: 18,
        keyvalue: OctetString::from(SECRET.to_vec()),
    }
}

#[test]
fn an_encryption_keys_debug_shows_its_type_and_length_not_its_octets() {
    let debug = format!("{:?}", secret_key());
    assert!(!shows(&debug, &SECRET), "{debug}");
    assert_eq!(
        debug,
        "EncryptionKey { keytype: 18, keyvalue: <redacted, 16 octets> }"
    );
}

#[test]
fn a_key_holders_debug_shows_no_key_octets() {
    let info = KrbCredInfo {
        key: secret_key(),
        prealm: None,
        pname: None,
        flags: None,
        authtime: None,
        starttime: None,
        endtime: None,
        renew_till: None,
        srealm: None,
        sname: None,
        caddr: None,
    };
    for debug in [format!("{info:?}"), format!("{info:#?}")] {
        assert!(!shows(&debug, &SECRET), "{debug}");
        assert!(debug.contains("<redacted, 16 octets>"), "{debug}");
    }
}

#[test]
fn a_password_changes_debug_shows_no_password() {
    let password = b"correct horse battery staple";
    let data = ChangePasswdData {
        newpasswd: OctetString::from_static(password),
        targname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["u"]),
        targrealm: ascii("R"),
    };
    let debug = format!("{data:?}");
    assert!(!shows(&debug, password), "{debug}");
    assert!(
        debug.starts_with("ChangePasswdData { newpasswd: <redacted>, targname: PrincipalName {"),
        "{debug}"
    );
}

#[test]
fn a_pac_logon_infos_debug_shows_no_session_key() {
    let sid = pac::RpcSid::dummy_domain();
    let mut info = pac::KerbValidationInfo::for_client("user", "KERBER.TEST", &sid, 1104);
    info.session_key = SECRET;
    let debug = format!("{info:?}");
    assert!(!shows(&debug, &SECRET), "{debug}");
    assert!(debug.contains("session_key: <redacted>"), "{debug}");
}

#[test]
fn a_pkinit_cas_debug_shows_no_private_scalar() {
    let ca = pkinit::PkinitCa::generate().unwrap();
    let debug = format!("{ca:?}");
    assert!(
        !shows(&debug, &ca.ca_secret),
        "the CA scalar is in its Debug"
    );
    assert!(debug.contains("ca_secret: <redacted>"), "{debug}");
}

/// MIT `decode_seqno` (`asn1_k_encode.c:133-146`): a seq-number from `INT32_MIN` to `0xFFFFFFFF` decodes, a negative one as its 32 bits unsigned, and anything wider does not.
#[test]
fn seq_numbers_decode_as_mit_decode_seqno_reads_them() {
    fn negated(mut der: Vec<u8>, field: u8) -> Vec<u8> {
        let at = der
            .windows(5)
            .position(|w| w == [field, 0x03, 0x02, 0x01, 0x7f])
            .unwrap();
        der[at + 4] = 0x80;
        der
    }
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, u8::try_from(body.len()).unwrap()];
        out.extend_from_slice(body);
        out
    }
    let ap_rep_part = |seq: &[u8]| {
        let mut fields = tlv(0xa0, &tlv(0x18, b"20261005120000Z"));
        fields.extend(tlv(0xa1, &tlv(0x02, &[0x05])));
        fields.extend(tlv(0xa3, &tlv(0x02, seq)));
        tlv(0x7b, &tlv(0x30, &fields))
    };
    let seq_of =
        |seq: &[u8]| rasn::der::decode::<EncApRepPart>(&ap_rep_part(seq)).map(|p| p.seq_number);
    assert_eq!(seq_of(&[0x80]).unwrap(), Some(0xFFFF_FF80), "-128");
    assert_eq!(
        seq_of(&[0x80, 0, 0, 0]).unwrap(),
        Some(0x8000_0000),
        "INT32_MIN"
    );
    assert_eq!(
        seq_of(&[0, 0xff, 0xff, 0xff, 0xff]).unwrap(),
        Some(u32::MAX)
    );
    assert!(
        seq_of(&[0xff, 0x7f, 0xff, 0xff, 0xff]).is_err(),
        "INT32_MIN - 1"
    );
    assert!(seq_of(&[0x01, 0, 0, 0, 0]).is_err(), "2^32");

    // The authenticator, KRB-SAFE body and KRB-PRIV part read a negative one the same way.
    let addr = HostAddress {
        addr_type: 2,
        address: vec![127, 0, 0, 1].into(),
    };
    let now = KerberosTime::from_unix_seconds(1_790_000_000);
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: ascii("KERBER.TEST"),
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        cksum: None,
        cusec: Microseconds::from_subsec_micros(5),
        ctime: now.clone(),
        subkey: None,
        seq_number: Some(0x7f),
        authorization_data: None,
    };
    let der = negated(rasn::der::encode(&authenticator).unwrap(), 0xa7);
    let back = rasn::der::decode::<Authenticator>(&der).unwrap();
    assert_eq!(back.seq_number, Some(0xFFFF_FF80));
    let body = KrbSafeBody {
        user_data: b"s".to_vec().into(),
        timestamp: None,
        usec: None,
        seq_number: Some(0x7f),
        s_address: addr.clone(),
        r_address: None,
    };
    let der = negated(rasn::der::encode(&body).unwrap(), 0xa3);
    assert_eq!(
        rasn::der::decode::<KrbSafeBody>(&der).unwrap().seq_number,
        Some(0xFFFF_FF80)
    );
    let part = EncKrbPrivPart {
        user_data: b"p".to_vec().into(),
        timestamp: None,
        usec: None,
        seq_number: Some(0x7f),
        s_address: addr,
        r_address: None,
    };
    let der = negated(rasn::der::encode(&part).unwrap(), 0xa3);
    assert_eq!(
        rasn::der::decode::<EncKrbPrivPart>(&der)
            .unwrap()
            .seq_number,
        Some(0xFFFF_FF80)
    );
    // Encoding is unchanged: an unsigned INTEGER, as MIT's `encode_seqno` writes it.
    let back = rasn::der::encode(&back).unwrap();
    assert!(
        back.windows(7)
            .any(|w| w == [0xa7, 0x07, 0x02, 0x05, 0x00, 0xff, 0xff])
    );
}

#[test]
fn pa_spake_unknown_choice_decodes() {
    // MIT `decode_cntype` (`asn1_encode.c:1277-1293`): an element no PA-SPAKE alternative takes, by
    // its tag ([4]) or by its constructed bit (a primitive [1]), is an unknown choice; a [2] that
    // does not decode as a SPAKEResponse fails the message.
    for der in [&[0xa4, 0x02, 0x30, 0x00][..], &[0x81, 0x00][..]] {
        assert_eq!(
            rasn::der::decode::<spake::PaSpake>(der).unwrap(),
            spake::PaSpake::Unknown
        );
    }
    assert!(rasn::der::decode::<spake::PaSpake>(&[0xa2, 0x02, 0x31, 0x00]).is_err());
    assert!(rasn::der::encode(&spake::PaSpake::Unknown).is_err());
}

// RFC 6560 OTP types (`otp.rs`) checked against MIT 1.22.2's own encodings. The
// octets are lines 62 to 68 of MIT's `reference_encode.out`; each value is the one
// that MIT's `ktest.c` builds in its `ktest_make_*otp*` helpers.

/// MIT's reference output for `encode_krb5_otp_tokeninfo(optionals NULL)`.
const MIT_OTP_TOKENINFO_MINIMAL: &str = "30 07 80 05 00 00 00 00 00";
/// MIT's reference output for `encode_krb5_otp_tokeninfo`, all fields set.
const MIT_OTP_TOKENINFO_MAXIMAL: &str = "30 72 80 05 00 77 00 00 00 81 0B 45 78 61 6D 70 6C 65 63 6F 72 70 82 05 68 61 72 6B 21 83 01 0A 84 01 02 85 09 79 6F 75 72 74 6F 6B 65 6E 86 28 75 72 6E 3A 69 65 74 66 3A 70 61 72 61 6D 73 3A 78 6D 6C 3A 6E 73 3A 6B 65 79 70 72 6F 76 3A 70 73 6B 63 3A 68 6F 74 70 A7 16 30 0B 06 09 60 86 48 01 65 03 04 02 01 30 07 06 05 2B 0E 03 02 1A 88 02 03 E8";
/// MIT's reference output for `encode_krb5_pa_otp_challenge(optionals NULL)`.
const MIT_PA_OTP_CHALLENGE_MINIMAL: &str =
    "30 15 80 08 6D 69 6E 6E 6F 6E 63 65 A2 09 30 07 80 05 00 00 00 00 00";
/// MIT's reference output for `encode_krb5_pa_otp_challenge`, all fields set.
const MIT_PA_OTP_CHALLENGE_MAXIMAL: &str = "30 81 A5 80 08 6D 61 78 6E 6F 6E 63 65 81 0B 74 65 73 74 73 65 72 76 69 63 65 A2 7D 30 07 80 05 00 00 00 00 00 30 72 80 05 00 77 00 00 00 81 0B 45 78 61 6D 70 6C 65 63 6F 72 70 82 05 68 61 72 6B 21 83 01 0A 84 01 02 85 09 79 6F 75 72 74 6F 6B 65 6E 86 28 75 72 6E 3A 69 65 74 66 3A 70 61 72 61 6D 73 3A 78 6D 6C 3A 6E 73 3A 6B 65 79 70 72 6F 76 3A 70 73 6B 63 3A 68 6F 74 70 A7 16 30 0B 06 09 60 86 48 01 65 03 04 02 01 30 07 06 05 2B 0E 03 02 1A 88 02 03 E8 83 07 6B 65 79 73 61 6C 74 84 04 31 32 33 34";
/// MIT's reference output for `encode_krb5_pa_otp_req(optionals NULL)`.
const MIT_PA_OTP_REQ_MINIMAL: &str = "30 2C 80 05 00 00 00 00 00 A2 23 A0 03 02 01 00 A1 03 02 01 05 A2 17 04 15 6B 72 62 41 53 4E 2E 31 20 74 65 73 74 20 6D 65 73 73 61 67 65";
/// MIT's reference output for `encode_krb5_pa_otp_req`, all fields set.
const MIT_PA_OTP_REQ_MAXIMAL: &str = "30 81 B9 80 05 00 60 00 00 00 81 05 6E 6F 6E 63 65 A2 23 A0 03 02 01 00 A1 03 02 01 05 A2 17 04 15 6B 72 62 41 53 4E 2E 31 20 74 65 73 74 20 6D 65 73 73 61 67 65 A3 0B 06 09 60 86 48 01 65 03 04 02 01 84 02 03 E8 85 05 66 72 6F 67 73 86 0A 6D 79 66 69 72 73 74 70 69 6E 87 05 68 61 72 6B 21 88 0F 31 39 39 34 30 36 31 30 30 36 30 33 31 37 5A 89 03 33 34 36 8A 01 02 8B 09 79 6F 75 72 74 6F 6B 65 6E 8C 28 75 72 6E 3A 69 65 74 66 3A 70 61 72 61 6D 73 3A 78 6D 6C 3A 6E 73 3A 6B 65 79 70 72 6F 76 3A 70 73 6B 63 3A 68 6F 74 70 8D 0B 45 78 61 6D 70 6C 65 63 6F 72 70";
/// MIT's reference output for `encode_krb5_pa_otp_enc_req`.
const MIT_PA_OTP_ENC_REQ: &str = "30 0A 80 08 6B 72 62 35 64 61 74 61";

/// The OTP algorithm identifier URN that MIT's `ktest.c` uses.
const OTP_ALG_ID: &str = "urn:ietf:params:xml:ns:keyprov:pskc:hotp";

/// `value`'s DER octets as MIT's reference output prints them: upper-case hex, a space between octets.
fn mit_hex(der: &[u8]) -> String {
    der.iter()
        .map(|octet| format!("{octet:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The octets of MIT's reference output `hex`.
fn mit_octets(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .map(|octet| u8::from_str_radix(octet, 16).unwrap())
        .collect()
}

/// Asserts that `value` encodes to MIT's reference output `hex`, octet for octet, and that
/// decoding those octets gives `value` back.
fn assert_mit_encoding<T>(value: &T, hex: &str)
where
    T: rasn::Encode + rasn::Decode + PartialEq + std::fmt::Debug,
{
    let der = rasn::der::encode(value).unwrap();
    assert_eq!(mit_hex(&der), hex, "the encoder differs from MIT");
    let decoded: T = rasn::der::decode(&mit_octets(hex)).unwrap();
    assert_eq!(&decoded, value, "decoding MIT's octets gives another value");
}

/// The OTP flags as the `OTPFlags` bit string of a 32-bit word (bit 0 is the most significant).
fn otp_flags(bits: u32) -> KerberosFlags {
    KerberosFlags::from_slice(&bits.to_be_bytes())
}

/// The EncryptedData of MIT's `ktest_make_sample_enc_data`: etype 0, kvno 5.
fn sample_enc_data() -> EncryptedData {
    EncryptedData {
        etype: 0,
        kvno: Some(5),
        cipher: OctetString::from_static(b"krbASN.1 test message"),
    }
}

/// MIT `opt_der_data` (`lib/krb5/asn.1/asn1_k_encode.c:65-65`): an AlgorithmIdentifier's parameters are kept as DER, so a NULL survives a decode and an encode.
#[test]
fn algorithm_identifier_parameters_survive_a_round_trip() {
    // sha256, then a NULL parameter, then the same OID with no parameter.
    let with_null = [
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    ];
    let bare = [
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];
    for der in [&with_null[..], &bare[..]] {
        let alg = rasn::der::decode::<pkinit::CmsAlgorithmIdentifier>(der).unwrap();
        assert_eq!(rasn::der::encode(&alg).unwrap(), der);
    }
}

/// The SHA-256 AlgorithmIdentifier of MIT's `ktest_make_sha256_alg`, with no parameters.
fn sha256_alg() -> pkinit::CmsAlgorithmIdentifier {
    pkinit::CmsAlgorithmIdentifier {
        algorithm: rasn::types::ObjectIdentifier::new(vec![2, 16, 840, 1, 101, 3, 4, 2, 1])
            .unwrap(),
        parameters: None,
    }
}

/// The SHA-1 AlgorithmIdentifier of MIT's `ktest_make_sha1_alg`, with no parameters.
fn sha1_alg() -> pkinit::CmsAlgorithmIdentifier {
    pkinit::CmsAlgorithmIdentifier {
        algorithm: rasn::types::ObjectIdentifier::new(vec![1, 3, 14, 3, 2, 26]).unwrap(),
        parameters: None,
    }
}

/// MIT's `ktest_make_minimal_otp_tokeninfo`: every optional field absent.
fn minimal_token_info() -> otp::OtpTokenInfo {
    otp::OtpTokenInfo {
        flags: otp_flags(0),
        vendor: None,
        challenge: None,
        length: None,
        format: None,
        token_id: None,
        alg_id: None,
        supported_hash_alg: None,
        iteration_count: None,
    }
}

/// MIT's `ktest_make_maximal_otp_tokeninfo`: every field set.
fn maximal_token_info() -> otp::OtpTokenInfo {
    otp::OtpTokenInfo {
        flags: otp_flags(
            otp::OTP_FLAG_NEXTOTP
                | otp::OTP_FLAG_COMBINE
                | otp::OTP_FLAG_COLLECT_PIN
                | otp::OTP_FLAG_ENCRYPT_NONCE
                | otp::OTP_FLAG_SEPARATE_PIN
                | otp::OTP_FLAG_CHECK_DIGIT,
        ),
        vendor: Some("Examplecorp".into()),
        challenge: Some(OctetString::from_static(b"hark!")),
        length: Some(10),
        format: Some(otp::OTP_FORMAT_ALPHANUMERIC),
        token_id: Some(OctetString::from_static(b"yourtoken")),
        alg_id: Some(OTP_ALG_ID.into()),
        supported_hash_alg: Some(vec![sha256_alg(), sha1_alg()]),
        iteration_count: Some(1000),
    }
}

/// MIT's `ktest_make_maximal_pa_otp_req`: every field set.
fn maximal_request() -> otp::PaOtpRequest {
    otp::PaOtpRequest {
        flags: otp_flags(otp::OTP_FLAG_NEXTOTP | otp::OTP_FLAG_COMBINE),
        nonce: Some(OctetString::from_static(b"nonce")),
        enc_data: sample_enc_data(),
        hash_alg: Some(sha256_alg()),
        iteration_count: Some(1000),
        otp_value: Some(OctetString::from_static(b"frogs")),
        pin: Some("myfirstpin".into()),
        challenge: Some(OctetString::from_static(b"hark!")),
        time: Some(KerberosTime::from_unix_seconds(771_228_197)),
        counter: Some(OctetString::from_static(b"346")),
        format: Some(otp::OTP_FORMAT_ALPHANUMERIC),
        token_id: Some(OctetString::from_static(b"yourtoken")),
        alg_id: Some(OTP_ALG_ID.into()),
        vendor: Some("Examplecorp".into()),
    }
}

#[test]
fn otp_tokeninfo_minimal_is_mits_encoding() {
    assert_mit_encoding(&minimal_token_info(), MIT_OTP_TOKENINFO_MINIMAL);
}

#[test]
fn otp_tokeninfo_maximal_is_mits_encoding() {
    assert_mit_encoding(&maximal_token_info(), MIT_OTP_TOKENINFO_MAXIMAL);
}

#[test]
fn pa_otp_challenge_minimal_is_mits_encoding() {
    let challenge = otp::PaOtpChallenge {
        nonce: OctetString::from_static(b"minnonce"),
        service: None,
        token_info: vec![minimal_token_info()],
        salt: None,
        s2kparams: None,
    };
    assert_mit_encoding(&challenge, MIT_PA_OTP_CHALLENGE_MINIMAL);
}

#[test]
fn pa_otp_challenge_maximal_is_mits_encoding() {
    let challenge = otp::PaOtpChallenge {
        nonce: OctetString::from_static(b"maxnonce"),
        service: Some("testservice".into()),
        token_info: vec![minimal_token_info(), maximal_token_info()],
        salt: Some(ascii("keysalt")),
        s2kparams: Some(OctetString::from_static(b"1234")),
    };
    assert_mit_encoding(&challenge, MIT_PA_OTP_CHALLENGE_MAXIMAL);
}

#[test]
fn pa_otp_req_minimal_is_mits_encoding() {
    let request = otp::PaOtpRequest {
        flags: otp_flags(0),
        nonce: None,
        enc_data: sample_enc_data(),
        hash_alg: None,
        iteration_count: None,
        otp_value: None,
        pin: None,
        challenge: None,
        time: None,
        counter: None,
        format: None,
        token_id: None,
        alg_id: None,
        vendor: None,
    };
    assert_mit_encoding(&request, MIT_PA_OTP_REQ_MINIMAL);
}

#[test]
fn pa_otp_req_maximal_is_mits_encoding() {
    assert_mit_encoding(&maximal_request(), MIT_PA_OTP_REQ_MAXIMAL);
}

#[test]
fn pa_otp_enc_request_is_mits_encoding() {
    let enc = otp::PaOtpEncRequest {
        nonce: OctetString::from_static(b"krb5data"),
    };
    assert_mit_encoding(&enc, MIT_PA_OTP_ENC_REQ);
}

#[test]
fn a_pa_otp_requests_debug_shows_no_pin_or_otp_value() {
    let debug = format!("{:?}", maximal_request());
    assert!(!shows(&debug, b"myfirstpin"), "{debug}");
    assert!(!shows(&debug, b"frogs"), "{debug}");
    assert!(
        debug.contains("otp_value: Some(<redacted>), pin: Some(<redacted>)"),
        "{debug}"
    );
}
