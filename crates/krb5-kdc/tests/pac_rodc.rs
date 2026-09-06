//! RODCIdentifier trailer on the server checksum (MIT `pac.c:557-569`).

use krb5_crypto::{KeyUsage, ProtocolKey, checksum};
use krb5_kdc::{
    TEST_REALM, TEST_USER, bootstrap_documented, documented_host, sign_pac, ticket_checksum_der,
    verify_pac_signatures,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_types::PrincipalName;
use krb5_types::ku;
use krb5_types::pac::{PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, Pac, signature_buffer};

fn signed_as_pac() -> (Vec<u8>, ProtocolKey, ProtocolKey) {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user = store.get_name(&cname).unwrap().best_key().unwrap();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        802,
        Some(vec![pa_enc_timestamp(&user.key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let part = krb5_kdc::decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    let der = ticket_checksum_der(&part).unwrap();
    let ident = store.pac_identity(&cname, TEST_REALM);
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let signed = sign_pac(
        &cname,
        part.authtime.unix_seconds(),
        &host.key,
        &krbtgt.key,
        &der,
        &ident,
        None,
    )
    .unwrap();
    (signed, host.key.clone(), krbtgt.key.clone())
}

#[test]
fn accept_rodc_trailer_privsvr_covers_server_buffer_minus_type() {
    let (signed, server, kdc) = signed_as_pac();
    let stretched = {
        let mut parsed = Pac::parse(&signed).unwrap();
        for b in &mut parsed.buffers {
            if b.kind == PAC_SERVER_CHECKSUM {
                b.data.extend_from_slice(&[0x12, 0x34]);
            }
        }
        parsed.to_bytes()
    };
    let stretched_pac = Pac::parse(&stretched).unwrap();
    let copy = stretched_pac.bytes_for_checksum();
    let usage = KeyUsage::new(ku::KERB_NON_KERB_CKSUM_SALT).unwrap();
    let server_mac = checksum(&server, usage, &copy).unwrap();
    let mut out_bufs = stretched_pac.buffers.clone();
    for b in &mut out_bufs {
        if b.kind == PAC_SERVER_CHECKSUM {
            let mut d = signature_buffer(server.etype().checksum_type(), &server_mac);
            d.extend_from_slice(&[0x12, 0x34]);
            b.data = d;
        }
    }
    let privsvr_over = {
        let s = out_bufs
            .iter()
            .find(|b| b.kind == PAC_SERVER_CHECKSUM)
            .unwrap();
        checksum(&kdc, usage, &s.data[4..]).unwrap()
    };
    for b in &mut out_bufs {
        if b.kind == PAC_PRIVSVR_CHECKSUM {
            b.data = signature_buffer(kdc.etype().checksum_type(), &privsvr_over);
        }
    }
    let out = {
        let mut rebuilt = stretched_pac.clone();
        rebuilt.buffers = out_bufs;
        rebuilt.to_bytes()
    };
    verify_pac_signatures(&out, &server, Some(&kdc), None).expect("RODC trailer PAC verifies");
}
