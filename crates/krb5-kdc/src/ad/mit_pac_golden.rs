//! MIT 1.22.2's PACs, byte for byte: [`mit_ticket_pac`] given what MIT's KDC had.
//!
//! Each vector is the decrypted EncTicketPart of a ticket MIT 1.22.2's db2 KDC issued in a
//! scratch realm, PACA.TEST, or in PACB.TEST, trusted from it. Every key is a throwaway password
//! under the default salt (AES256, 4096 iterations): `user` `userpassword`, `krbtgt/PACA.TEST`
//! `krbtgt-a-password`, `host/svc.paca.test` `svc-a-password`, `krbtgt/PACB.TEST@PACA.TEST`
//! `crosspassword`, `krbtgt/PACB.TEST` `krbtgt-b-password`, `host/svc.pacb.test` `svc-b-password`,
//! and for the cross-realm S4U2Self, `svc@PACA.TEST` `svc-password`.

use super::*;
use krb5_crypto::{EncryptionType, string_to_key};

fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn part(der_hex: &str) -> EncTicketPart {
    decode(&hex(der_hex)).unwrap()
}

fn key(password: &str, salt: &str) -> ProtocolKey {
    let et = EncryptionType::Aes256CtsHmacSha196;
    string_to_key(
        et,
        password.as_bytes(),
        salt.as_bytes(),
        Some(&crate::store::s2k_params(et)),
    )
    .unwrap()
}

/// `kinit -r 1d user`: the AS TGT.
const L1_AS_TGT: &str = "
    638201313082012da00703050040c10000a12b3029a003020112a1220420eb51a6d73162b241845f132af732764cd379
    67f88b7596d9fdfe4d8916e296eaa20b1b09504143412e54455354a311300fa003020101a10830061b0475736572a40b
    3009a003020101a1020400a511180f32303236313030353134303733385aa711180f3230323631303036303030373338
    5aa811180f32303236313030363134303733385aaa818e30818b308188a003020101a18180047e307c307aa004020200
    80a172047003000000000000000a00000012000000380000000000000006000000100000005000000000000000070000
    0010000000600000000000000000b1a8e0d254dd010800750073006500720000000000000010000000caf44f4610522e
    f618bb62ba10000000d27ec3183d8550798a47f193
";

/// `kvno host/svc.paca.test` with L1's TGT.
const L2_TGS_SVC: &str = "
    6382017630820172a00703050040890000a12b3029a003020112a12204203ecc3c1346ff96742e790ee78ae7f96ca074
    77344734dabbea9c0881156b2004a20b1b09504143412e54455354a311300fa003020101a10830061b0475736572a40b
    3009a003020101a1020400a511180f32303236313030353134303733385aa711180f3230323631303036303030373338
    5aa811180f32303236313030363134303733385aaa81d33081d03081cda003020101a181c50481c23081bf3081bca004
    02020080a181b30481b005000000000000000a0000001200000058000000000000001000000010000000700000000000
    000006000000100000008000000000000000070000001000000090000000000000001300000010000000a00000000000
    000000b1a8e0d254dd010800750073006500720000000000000010000000b87f2cf30367dca90925c20210000000bb77
    7c323f9d7cd2c28a20ab10000000054676e5a529f87eb7af6c9c100000009a46910fb927a1e14c4b92fc
";

/// `kinit -S host/svc.paca.test user`.
const L3_AS_SVC: &str = "
    6382017630820172a00703050040c10000a12b3029a003020112a1220420f712355a8934a7310428432106be536dc97e
    39b8ab838f4c3f6315a0530084d3a20b1b09504143412e54455354a311300fa003020101a10830061b0475736572a40b
    3009a003020101a1020400a511180f32303236313030353134303733395aa711180f3230323631303036303030373339
    5aa811180f32303236313030363134303733395aaa81d33081d03081cda003020101a181c50481c23081bf3081bca004
    02020080a181b30481b00500000000000000100000001000000058000000000000000a00000012000000680000000000
    000006000000100000008000000000000000070000001000000090000000000000001300000010000000a00000000000
    000010000000c989c4d318cc7f363cb35b80804741e1d254dd010800750073006500720000000000000010000000ad7a
    b326e576b2938877996e10000000ac6dd0f18d500b32b7e61ac4100000009f0e6dbaae87207a1a78d0c5
";

/// `kinit -R -S host/svc.paca.test` on L3's ticket.
const L5_RENEW_SVC: &str = "
    6382018930820185a00703050040c90000a12b3029a003020112a1220420825929d82eb746f55ff59aa519360ba25f77
    38010b3895e32b69f65cec7c2c16a20b1b09504143412e54455354a311300fa003020101a10830061b0475736572a40b
    3009a003020101a1020400a511180f32303236313030353134303733395aa611180f3230323631303035313430373431
    5aa711180f32303236313030363030303734315aa811180f32303236313030363134303733395aaa81d33081d03081cd
    a003020101a181c50481c23081bf3081bca00402020080a181b30481b005000000000000000a00000012000000580000
    000000000010000000100000007000000000000000060000001000000080000000000000000700000010000000900000
    00000000001300000010000000a000000000000000804741e1d254dd0108007500730065007200000000000000100000
    00acf2bd14a0bd7905566994de10000000546927e0472071c8f30deea1100000006dc6463edab7b990abb2bcda100000
    0022228adaeb42d64176306cf0
";

/// `kinit -k host/svc.paca.test`: S4U2Self's header TGT.
const L6H_SVC_TGT: &str = "
    6382015d30820159a00703050040c10000a12b3029a003020112a1220420a589d0d2ed5c10d2e9016c40805d70497a80
    7af5171080e9af22751b76747886a20b1b09504143412e54455354a320301ea003020101a11730151b04686f73741b0d
    7376632e706163612e74657374a40b3009a003020101a1020400a511180f32303236313030353134303734315aa71118
    0f32303236313030363030303734315aa811180f32303236313030363134303734315aaa81ab3081a83081a5a0030201
    01a1819d04819a308197308194a00402020080a1818b04818803000000000000000a0000002e00000038000000000000
    000600000010000000680000000000000007000000100000007800000000000000807472e2d254dd01240068006f0073
    0074002f007300760063002e0070006100630061002e0074006500730074000000100000005fa2ff55f0fe7189f5ff6a
    e2100000009e2f847e9ff5fe97ff92499b
";

/// `kvno -U user host/svc.paca.test` with L6h's TGT.
const L6_S4U2SELF: &str = "
    6382018930820185a00703050040890000a12b3029a003020112a122042064dc9c4c90629a2eb72b6a6f99f71b54d748
    1528d66ceb2b67fda49b7451e6dca20b1b09504143412e54455354a311300fa00302010aa10830061b0475736572a40b
    3009a003020101a1020400a511180f32303236313030353134303734315aa611180f3230323631303035313430373432
    5aa711180f32303236313030363030303734315aa811180f32303236313030363134303734315aaa81d33081d03081cd
    a003020101a181c50481c23081bf3081bca00402020080a181b30481b005000000000000001000000010000000580000
    00000000000a000000120000006800000000000000060000001000000080000000000000000700000010000000900000
    00000000001300000010000000a00000000000000010000000722ceec768929cf89115f946807472e2d254dd01080075
    00730065007200000000000000100000004896d2d7b592b044fba38fda10000000cfc911eb6f6e99beda61fadb100000
    00599e78e50fa2285dfbf80ab2
";

/// `kinit user`: the cross-realm leg's TGT.
const L7H_USER_TGT: &str = "
    638201313082012da00703050040c10000a12b3029a003020112a1220420d97f95e5ba82139ef8845c81b0cedfbbe327
    d51e10efe6024cee15da9c479497a20b1b09504143412e54455354a311300fa003020101a10830061b0475736572a40b
    3009a003020101a1020400a511180f32303236313030353134303734325aa711180f3230323631303036303030373432
    5aa811180f32303236313030363134303734325aaa818e30818b308188a003020101a18180047e307c307aa004020200
    80a172047003000000000000000a00000012000000380000000000000006000000100000005000000000000000070000
    00100000006000000000000000000b0be3d254dd010800750073006500720000000000000010000000c19a344e454aaf
    bfa009e03010000000b55afc41c102eed0ba460949
";

/// `krbtgt/PACB.TEST@PACA.TEST` from L7h's TGT.
const L7A_CROSS_TGT: &str = "
    638201313082012da00703050040890000a12b3029a003020112a1220420129cc052a8658485bcd204cc8d2e6383f599
    db6d2297687ffa0af1e9d2286995a20b1b09504143412e54455354a311300fa003020101a10830061b0475736572a40b
    3009a003020101a1020400a511180f32303236313030353134303734325aa711180f3230323631303036303030373432
    5aa811180f32303236313030363134303734325aaa818e30818b308188a003020101a18180047e307c307aa004020200
    80a172047003000000000000000a00000012000000380000000000000006000000100000005000000000000000070000
    00100000006000000000000000000b0be3d254dd010800750073006500720000000000000010000000d4d126fbaf41db
    59aa623082100000003da2f7b0afba4ae39e97c94e
";

/// PACB.TEST's `host/svc.pacb.test` from L7a's TGT.
const L7B_CROSS_SVC: &str = "
    6382017630820172a00703050040890000a12b3029a003020112a12204208583726d61ea94f7d7ae7901974fd314d5c1
    e5f0a809270da95e13c0a2dcf967a20b1b09504143412e54455354a311300fa003020101a10830061b0475736572a40b
    3009a003020101a1020400a511180f32303236313030353134303734325aa711180f3230323631303036303030373432
    5aa811180f32303236313030363134303734325aaa81d33081d03081cda003020101a181c50481c23081bf3081bca004
    02020080a181b30481b005000000000000000a0000001200000058000000000000001000000010000000700000000000
    000006000000100000008000000000000000070000001000000090000000000000001300000010000000a00000000000
    0000000b0be3d254dd010800750073006500720000000000000010000000b55511f80dd30f3c1e412acb100000007288
    764661cbec1931151a25100000000c619b7338592ab5f590a5d910000000bdd99a555a30827fe017800c
";

/// The final hop of a cross-realm S4U2Self, `kvno -I user@PACB.TEST svc@PACA.TEST` with svc's
/// TGT, PACB referring the request back by a db2 alias (a separate run of the same realms).
const XS4U_FINAL: &str = "
    6382017630820172a00703050040890000a12b3029a003020112a1220420759b4d6b91ef9db868ab49e57ca446d153c4
    2becd996350dbb622287f812cd90a20b1b09504143422e54455354a311300fa003020101a10830061b0475736572a40b
    3009a003020101a1020400a511180f32303236313030353135323634325aa711180f3230323631303036303132363432
    5aa811180f32303236313030363135323634325aaa81d33081d03081cda003020101a181c50481c23081bf3081bca004
    02020080a181b30481b00500000000000000100000001000000058000000000000000a00000012000000680000000000
    000006000000100000008000000000000000070000001000000090000000000000001300000010000000a00000000000
    0000100000007cd6e6521fded2a17b69d8c100a54decdd54dd010800750073006500720000000000000010000000c154
    3cd2f10834bf3f2096501000000008e8dbfc722f837df242e16810000000bd3397d9feb9e174e1bfe080
";

fn krbtgt_a() -> ProtocolKey {
    key("krbtgt-a-password", "PACA.TESTkrbtgtPACA.TEST")
}

fn svc_a() -> ProtocolKey {
    key("svc-a-password", "PACA.TESThostsvc.paca.test")
}

fn svc_a_name() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.paca.test"])
}

/// Our PAC for the ticket MIT issued as `mit`, from the same inputs MIT's `handle_pac` had.
fn ours(
    req: &HandlePac<'_>,
    mit: &EncTicketPart,
    sname: &PrincipalName,
    server: &ProtocolKey,
    kdc: &ProtocolKey,
) -> Vec<u8> {
    let der = ticket_checksum_der(mit).unwrap();
    let ticket = PacTicket {
        server,
        kdc,
        enc_tkt_der: &der,
        is_service_tkt: should_have_ticket_signature(sname),
    };
    mit_ticket_pac(req, &mit.cname, mit.authtime.unix_seconds(), &ticket).unwrap()
}

fn kinds(pac: &[u8]) -> Vec<u32> {
    Pac::parse(pac)
        .unwrap()
        .buffers
        .iter()
        .map(|b| b.kind)
        .collect()
}

#[test]
fn as_tgt_is_mits_pac() {
    let mit = part(L1_AS_TGT);
    let want = pac_from_ticket_part(&mit).unwrap();
    assert_eq!(kinds(&want), [10, 6, 7]);
    let got = ours(
        &HandlePac::default(),
        &mit,
        &PrincipalName::krbtgt("PACA.TEST"),
        &krbtgt_a(),
        &krbtgt_a(),
    );
    assert_eq!(got, want);
}

#[test]
fn tgt_renewal_gives_the_tgt_pac_back() {
    // MIT renews this TGT into a PAC identical to its own.
    let mit = part(L1_AS_TGT);
    let subject = pac_from_ticket_part(&mit).unwrap();
    let req = HandlePac {
        subject: Some(&subject),
        ..HandlePac::default()
    };
    let got = ours(
        &req,
        &mit,
        &PrincipalName::krbtgt("PACA.TEST"),
        &krbtgt_a(),
        &krbtgt_a(),
    );
    assert_eq!(got, subject);
}

#[test]
fn tgs_service_ticket_is_mits_pac() {
    let header = pac_from_ticket_part(&part(L1_AS_TGT)).unwrap();
    let mit = part(L2_TGS_SVC);
    let want = pac_from_ticket_part(&mit).unwrap();
    assert_eq!(kinds(&want), [10, 16, 6, 7, 19]);
    let req = HandlePac {
        subject: Some(&header),
        ..HandlePac::default()
    };
    assert_eq!(ours(&req, &mit, &svc_a_name(), &svc_a(), &krbtgt_a()), want);
}

#[test]
fn as_service_ticket_is_mits_pac() {
    let mit = part(L3_AS_SVC);
    let want = pac_from_ticket_part(&mit).unwrap();
    assert_eq!(kinds(&want), [16, 10, 6, 7, 19]);
    let got = ours(
        &HandlePac::default(),
        &mit,
        &svc_a_name(),
        &svc_a(),
        &krbtgt_a(),
    );
    assert_eq!(got, want);
}

#[test]
fn service_ticket_renewal_is_mits_pac() {
    let header = pac_from_ticket_part(&part(L3_AS_SVC)).unwrap();
    let mit = part(L5_RENEW_SVC);
    let want = pac_from_ticket_part(&mit).unwrap();
    assert_eq!(kinds(&want), [10, 16, 6, 7, 19]);
    let req = HandlePac {
        subject: Some(&header),
        ..HandlePac::default()
    };
    assert_eq!(ours(&req, &mit, &svc_a_name(), &svc_a(), &krbtgt_a()), want);
}

#[test]
fn s4u2self_is_mits_pac() {
    let header = pac_from_ticket_part(&part(L6H_SVC_TGT)).unwrap();
    let mit = part(L6_S4U2SELF);
    let want = pac_from_ticket_part(&mit).unwrap();
    assert_eq!(kinds(&want), [16, 10, 6, 7, 19]);
    let req = HandlePac {
        subject: Some(&header),
        s4u: true,
        ..HandlePac::default()
    };
    assert_eq!(ours(&req, &mit, &svc_a_name(), &svc_a(), &krbtgt_a()), want);
}

#[test]
fn cross_realm_tgt_is_mits_pac() {
    // The server checksum is under the inter-realm key, the KDC checksum under PACA's krbtgt.
    let header = pac_from_ticket_part(&part(L7H_USER_TGT)).unwrap();
    let mit = part(L7A_CROSS_TGT);
    let want = pac_from_ticket_part(&mit).unwrap();
    assert_eq!(kinds(&want), [10, 6, 7]);
    let req = HandlePac {
        subject: Some(&header),
        ..HandlePac::default()
    };
    let cross = key("crosspassword", "PACA.TESTkrbtgtPACB.TEST");
    let got = ours(
        &req,
        &mit,
        &PrincipalName::krbtgt("PACB.TEST"),
        &cross,
        &krbtgt_a(),
    );
    assert_eq!(got, want);
}

#[test]
fn foreign_service_ticket_is_mits_pac() {
    let header = pac_from_ticket_part(&part(L7A_CROSS_TGT)).unwrap();
    let mit = part(L7B_CROSS_SVC);
    let want = pac_from_ticket_part(&mit).unwrap();
    assert_eq!(kinds(&want), [10, 16, 6, 7, 19]);
    let req = HandlePac {
        subject: Some(&header),
        ..HandlePac::default()
    };
    let got = ours(
        &req,
        &mit,
        &PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.pacb.test"]),
        &key("svc-b-password", "PACB.TESThostsvc.pacb.test"),
        &key("krbtgt-b-password", "PACB.TESTkrbtgtPACB.TEST"),
    );
    assert_eq!(got, want);
}

#[test]
fn cross_realm_s4u2self_final_hop_is_mits_pac() {
    // The header is PACB's referral TGT back to PACA, which MIT's client does not store in its
    // ccache, so its bytes are not captured. MIT's S4U referral PAC names the user with the realm
    // and holds no DELEGATION_INFO, and the final hop names the user anew without the realm, so
    // nothing else of that PAC reaches the ticket.
    let mit = part(XS4U_FINAL);
    let want = pac_from_ticket_part(&mit).unwrap();
    assert_eq!(kinds(&want), [16, 10, 6, 7, 19]);
    let header = Pac::built(
        0,
        vec![PacBuffer::new(
            PAC_CLIENT_INFO,
            client_info_buffer(mit.authtime.unix_seconds(), "user@PACB.TEST"),
        )],
    )
    .to_bytes();
    let req = HandlePac {
        subject: Some(&header),
        s4u: true,
        ..HandlePac::default()
    };
    let got = ours(
        &req,
        &mit,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["svc"]),
        &key("svc-password", "PACA.TESTsvc"),
        &krbtgt_a(),
    );
    assert_eq!(got, want);
}
