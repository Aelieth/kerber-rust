//! In-repo consumer of `krb5-crypto` and `krb5-asn1`.
//!
//! This binary is not a Kerberos client. It exercises the public encrypt and
//! DER APIs with published vectors so CI can catch crate-boundary regressions.

use krb5_asn1::{decode, encode, PrincipalName};
use krb5_crypto::{decrypt, encrypt_with_confounder, EncryptionType, KeyUsage, ProtocolKey};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// RFC 8009 Appendix A, aes128-cts-hmac-sha256-128, empty plaintext, usage 2.
fn rfc8009_empty_plaintext() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let key = from_hex("3705d96080c17728a0e800eab6e0d23c");
    let conf = from_hex("7e5895eaf2672435bad817f545a37148");
    let ct = from_hex("ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718");
    (key, conf, Vec::new(), ct)
}

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter("krb5_crypto=info,krb5_asn1=info")
        .try_init();

    let (key_bytes, conf, plaintext, expected_ct) = rfc8009_empty_plaintext();
    let key =
        ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha256128, &key_bytes).expect("key");
    let usage = KeyUsage::new(2).expect("usage");
    let ct = encrypt_with_confounder(&key, usage, &conf, &plaintext).expect("encrypt");
    let pt = decrypt(&key, usage, &ct).expect("decrypt");

    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let der = encode(&name).expect("der encode");
    let name2: PrincipalName = decode(&der).expect("der decode");

    println!("encrypt_hex={}", hex(&ct));
    println!("expected_ct_hex={}", hex(&expected_ct));
    println!("decrypt_len={}", pt.len());
    println!("der_hex={}", hex(&der));
    println!("principal_round_trip={}", name == name2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_asn1::{decode, encode, EncryptedData, KdcRep, KdcReq, KrbError, Ticket};
    use krb5_crypto::encrypt;
    use krb5_types::{
        ascii, kerberos_time_from_utc_z, ApOptions, KdcOptions, KdcReqBody, OctetString,
        Ticket as Tkt,
    };

    fn install_tracing() {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_env_filter("krb5_crypto=info,krb5_asn1=info")
            .try_init();
    }

    #[test]
    fn consumer_encrypt_matches_rfc8009_and_decrypts() {
        install_tracing();
        let (key_bytes, conf, plaintext, expected_ct) = rfc8009_empty_plaintext();
        let key =
            ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha256128, &key_bytes).unwrap();
        let usage = KeyUsage::new(2).unwrap();
        let ct = encrypt_with_confounder(&key, usage, &conf, &plaintext).unwrap();
        assert_eq!(ct, expected_ct);
        assert_eq!(decrypt(&key, usage, &ct).unwrap(), plaintext);
    }

    #[test]
    fn consumer_encrypt_random_confounder_round_trips() {
        install_tracing();
        let key = ProtocolKey::from_bytes(
            EncryptionType::Aes128CtsHmacSha196,
            &from_hex("42263c6e89f4fc28b8df68ee09799f15"),
        )
        .unwrap();
        let usage = KeyUsage::new(7).unwrap();
        let pt = b"consumer-payload";
        let ct = encrypt(&key, usage, pt).unwrap();
        assert_eq!(decrypt(&key, usage, &ct).unwrap(), pt);
    }

    #[test]
    fn consumer_der_encode_decode_principal_and_ticket() {
        install_tracing();
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let der = encode(&name).unwrap();
        assert_eq!(der[0], 0x30, "PrincipalName is a SEQUENCE");
        let back: PrincipalName = decode(&der).unwrap();
        assert_eq!(name, back);

        let ticket = Tkt {
            tkt_vno: Tkt::VNO,
            realm: ascii("KERBER.TEST"),
            sname: PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "KERBER.TEST"]),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![1, 2, 3, 4]),
            },
        };
        let tder = encode(&ticket).unwrap();
        // APPLICATION 1 => 0x61
        assert_eq!(tder[0], 0x61);
        let ticket2: Ticket = decode(&tder).unwrap();
        assert_eq!(ticket, ticket2);
    }

    #[test]
    fn consumer_der_kdc_req_rep_ap_req_error() {
        install_tracing();
        let till = kerberos_time_from_utc_z("20260819120000Z").unwrap();
        let req = KdcReq {
            pvno: KdcReq::PVNO,
            msg_type: KdcReq::MSG_AS_REQ,
            padata: None,
            req_body: KdcReqBody {
                kdc_options: KdcOptions::none(),
                cname: Some(PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"])),
                realm: ascii("KERBER.TEST"),
                sname: None,
                from: None,
                till,
                rtime: None,
                nonce: 42,
                etype: vec![18],
                addresses: None,
                enc_authorization_data: None,
                additional_tickets: None,
            },
        };
        let bytes = encode(&req).unwrap();
        let req2: KdcReq = decode(&bytes).unwrap();
        assert_eq!(req, req2);

        let ticket = Tkt {
            tkt_vno: Tkt::VNO,
            realm: ascii("KERBER.TEST"),
            sname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["host"]),
            enc_part: EncryptedData {
                etype: 17,
                kvno: None,
                cipher: OctetString::from(vec![9, 9, 9]),
            },
        };
        let rep = KdcRep {
            pvno: KdcRep::PVNO,
            msg_type: KdcRep::MSG_AS_REP,
            padata: None,
            crealm: ascii("KERBER.TEST"),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            ticket: ticket.clone(),
            enc_part: EncryptedData {
                etype: 17,
                kvno: None,
                cipher: OctetString::from(vec![8, 8]),
            },
        };
        let r2: KdcRep = decode(&encode(&rep).unwrap()).unwrap();
        assert_eq!(rep, r2);

        let ap = krb5_asn1::ApReq {
            pvno: krb5_asn1::ApReq::PVNO,
            msg_type: krb5_asn1::ApReq::MSG_TYPE,
            ap_options: ApOptions::none(),
            ticket,
            authenticator: EncryptedData {
                etype: 17,
                kvno: None,
                cipher: OctetString::from(vec![7]),
            },
        };
        let a2: krb5_asn1::ApReq = decode(&encode(&ap).unwrap()).unwrap();
        assert_eq!(ap, a2);

        let err = KrbError {
            pvno: KrbError::PVNO,
            msg_type: KrbError::MSG_TYPE,
            ctime: None,
            cusec: None,
            stime: kerberos_time_from_utc_z("20260819120000Z").unwrap(),
            susec: krb5_types::Microseconds(1),
            error_code: 6,
            crealm: None,
            cname: None,
            realm: ascii("KERBER.TEST"),
            sname: PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "KERBER.TEST"]),
            e_text: None,
            e_data: None,
        };
        let e2: KrbError = decode(&encode(&err).unwrap()).unwrap();
        assert_eq!(err, e2);
    }
}
