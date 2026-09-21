use super::*;

#[test]
fn ultype_16_is_ticket_checksum_not_upn_dns() {
    assert_eq!(PAC_UPN_DNS_INFO, 12);
    assert_eq!(PAC_TICKET_CHECKSUM, 16);
    assert_eq!(PAC_FULL_CHECKSUM, 19);
    assert_ne!(PAC_UPN_DNS_INFO, PAC_TICKET_CHECKSUM);
}

fn u8_len(n: usize) -> u8 {
    u8::try_from(n).expect("test DER fits in a short length")
}

#[test]
fn zero_pac_ad_data_preserves_sibling_encoding() {
    let pac = vec![0x09, 0, 0, 0, 0, 0, 0, 0, 1, 2];
    // SEQUENCE { INTEGER 1 with non-minimal length, OCTET STRING pac }
    let mut der = vec![0x30, 0];
    der.extend_from_slice(&[0x02, 0x81, 0x01, 0x01]);
    der.push(0x04);
    der.push(u8_len(pac.len()));
    der.extend_from_slice(&pac);
    der[1] = u8_len(der.len() - 2);
    let out = zero_pac_ad_data(&der, &pac).expect("PAC in DER");
    assert_eq!(&out[2..6], &[0x02, 0x81, 0x01, 0x01]);
    assert_eq!(&out[6..], &[0x04, 0x01, 0x00]);
    assert!(zero_pac_ad_data(&der, b"nope").is_none());
}

#[test]
fn zero_pac_ad_data_walks_ad_if_relevant() {
    let pac = vec![0x09, 0, 0, 0, 0, 0, 0, 0, 3, 4];
    // AD-WIN2K-PAC inner SEQUENCE { INTEGER 128, OCTET STRING pac }
    let mut inner = vec![0x30, 0];
    inner.extend_from_slice(&[0x02, 0x02, 0x00, 0x80]);
    inner.push(0x04);
    inner.push(u8_len(pac.len()));
    inner.extend_from_slice(&pac);
    inner[1] = u8_len(inner.len() - 2);
    // AD-IF-RELEVANT SEQUENCE { INTEGER 1, OCTET STRING inner }
    let mut outer = vec![0x30, 0];
    outer.extend_from_slice(&[0x02, 0x01, 0x01]);
    outer.push(0x04);
    outer.push(u8_len(inner.len()));
    outer.extend_from_slice(&inner);
    outer[1] = u8_len(outer.len() - 2);
    // APPLICATION 3 wrapping SEQUENCE
    let mut app = vec![0x63, 0];
    app.extend_from_slice(&outer);
    app[1] = u8_len(app.len() - 2);
    let out = zero_pac_ad_data(&app, &pac).expect("nested PAC");
    assert_eq!(out[0], 0x63);
    assert!(
        out.windows(3).any(|w| w == [0x04, 0x01, 0x00]),
        "PAC octet string must be a single zero: {out:02x?}"
    );
    assert!(!out.windows(pac.len()).any(|w| w == pac.as_slice()));
}

#[test]
fn issued_logon_round_trip_is_byte_identical() {
    let sid = RpcSid::nt_domain(9, 8, 7);
    let raw = logon_info_buffer("user", "KERBER.TEST", &sid, 1000);
    let parsed = parse_kerb_validation_info(&raw).expect("NDR");
    assert_eq!(parsed.effective_name.value, "user");
    assert_eq!(parsed.logon_domain_name.value, "KERBER.TEST");
    assert_eq!(parsed.user_id, 1000);
    assert_eq!(parsed.primary_group_id, 513);
    assert_eq!(parsed.logon_domain_id.to_sddl(), "S-1-5-21-9-8-7");
    assert_ne!(
        parsed.logon_domain_id.to_sddl(),
        RpcSid::dummy_domain().to_sddl()
    );
    let again = parsed.to_ndr();
    assert_eq!(again, raw, "issued NDR must round-trip byte-for-byte");
}

#[test]
fn upn_dns_attributes_requester_round_trip() {
    let ident = PacIdentity {
        sam: "user".into(),
        realm: "KERBER.TEST".into(),
        domain_sid: RpcSid::nt_domain(9, 8, 7),
        rid: 1000,
    };
    let upn = upn_dns_buffer(&ident);
    let parsed = parse_upn_dns(&upn).expect("upn");
    assert_eq!(parsed.upn, "user@KERBER.TEST");
    assert_eq!(parsed.dns_domain, "kerber.test");
    assert_eq!(parsed.sam.as_deref(), Some("user"));
    assert_eq!(parsed.sid.unwrap().to_sddl(), ident.client_sid().to_sddl());
    let attr = attributes_info_buffer();
    assert_eq!(&attr[0..4], &2u32.to_le_bytes());
    assert_eq!(&attr[4..8], &PAC_ATTRIBUTE_WAS_REQUESTED.to_le_bytes());
    let req = requester_sid_buffer(&ident.client_sid());
    assert_eq!(
        RpcSid::from_ms_dtyp(&req).unwrap().to_sddl(),
        "S-1-5-21-9-8-7-1000"
    );
}

#[test]
fn sddl_round_trip_and_with_rid() {
    let s = RpcSid::from_sddl("S-1-5-21-891046300-1937985867-1481223175").unwrap();
    assert_eq!(s.to_sddl(), "S-1-5-21-891046300-1937985867-1481223175");
    assert_eq!(
        s.with_rid(1103).to_sddl(),
        "S-1-5-21-891046300-1937985867-1481223175-1103"
    );
    assert!(RpcSid::from_sddl("not-a-sid").is_none());
}

#[test]
fn ad_golden_kbruser_fields_and_reencode() {
    let raw = include_bytes!("../../../../tests/traces/pac-kbruser.ndr");
    let v = parse_kerb_validation_info(raw).expect("AD NDR");
    assert_eq!(v.effective_name.value, "kbruser");
    assert_eq!(v.logon_domain_name.value, "ADKERBER");
    assert_eq!(v.logon_server.value, "TEST-SERVER");
    assert_eq!(v.user_id, 1103);
    assert_eq!(v.primary_group_id, 513);
    assert!(
        v.groups.iter().any(|g| g.relative_id == 1104),
        "kbrgroup RID 1104: {:?}",
        v.groups
    );
    assert_eq!(
        v.logon_domain_id.to_sddl(),
        "S-1-5-21-1662395604-3502713894-542445324"
    );
    assert_eq!(v.extra_sids.len(), 1);
    assert_eq!(v.extra_sids[0].sid.to_sddl(), "S-1-18-1");
    let again = v.to_ndr();
    assert_eq!(
        again.as_slice(),
        raw.as_slice(),
        "re-encode must match captured AD NDR"
    );
}

#[test]
fn ad2019_s4u_di_short_parses() {
    let raw: &[u8] = &[
        0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x2a, 0x00, 0x2c, 0x00, 0x04, 0x00, 0x02, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15,
        0x00, 0x00, 0x00, 0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x32, 0x00, 0x2f, 0x00, 0x61, 0x00,
        0x64, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x2e,
        0x00, 0x61, 0x00, 0x64, 0x00, 0x2e, 0x00, 0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x3c, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x1e,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x73, 0x00, 0x76, 0x00,
        0x63, 0x00, 0x31, 0x00, 0x2f, 0x00, 0x61, 0x00, 0x64, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72,
        0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x64, 0x00, 0x2e, 0x00,
        0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x40, 0x00, 0x41, 0x00, 0x44, 0x00, 0x2e,
        0x00, 0x54, 0x00, 0x45, 0x00, 0x53, 0x00, 0x54, 0x00, 0x00, 0x00,
    ];
    let di = parse_delegation_info(raw).expect("MIT t_ndr.c s4u_di_short");
    assert_eq!(di.proxy_target, "svc2/adserver.ad.test");
    assert_eq!(di.transited_services, vec!["svc1/adserver.ad.test@AD.TEST"]);
}
