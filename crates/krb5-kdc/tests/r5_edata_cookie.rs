//! AS e_data-bearing errors carry PA-FX-COOKIE; PKINIT 65 is TYPED-DATA
//! (`do_as_req.c:785-814`, `pkinit_srv.c:932`); FAST inner FX-ERROR has no
//! e_data (`fast_util.c:384-386`).

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_kdc::{
    Error, S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    pa_enc_timestamp,
};
use krb5_protocol::{armor_key, attach_fast, build_fast_armor, pa_pk_as_req_spki, unwrap_fast_rep};
use krb5_types::{KrbError, MethodData, PrincipalName, ascii, err, pa};

fn first_ctx_tag(der: &[u8]) -> Option<u8> {
    der.iter().copied().find(|b| b & 0xc0 == 0x80)
}

fn user_key() -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(TEST_REALM);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap()
}

fn pkinit_as_req(
    cname: PrincipalName,
    nonce: u32,
    make_pa: impl FnOnce(&[u8]) -> krb5_types::PaData,
) -> krb5_types::AsReq {
    let mut req = as_req(cname, TEST_REALM, nonce, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let cksum = krb5_types::pkinit::kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![make_pa(&cksum)]);
    req
}

fn issue_tgt(store: &krb5_kdc::PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&user_key()).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

#[test]
fn pkinit_unknown_dh_is_typed_edata_with_cookie() {
    let (mut store, _) = bootstrap_documented().unwrap();
    store.enable_pkinit_ca().expect("PKINIT CA");
    let ca = store.pkinit_ca().expect("CA").clone();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let p = vec![0xffu8; 64];
    let y = vec![0x02];
    let spki = krb5_types::pkinit::encode_dh_spki(&p, &y);
    let req = pkinit_as_req(cname, 901, |ck| {
        pa_pk_as_req_spki(&spki, &ca, Some(ck)).expect("PA-PK-AS-REQ")
    });
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).unwrap();
    let e: KrbError = decode(&bytes).unwrap();
    assert_eq!(e.error_code, err::DH_KEY_PARAMETERS_NOT_ACCEPTED);
    let ed = e.e_data.as_ref().expect("e_data");
    assert_eq!(
        first_ctx_tag(ed.as_ref()),
        Some(0xa0),
        "PKINIT 65 e_data is TYPED-DATA [0]/[1], not METHOD-DATA [1]/[2]"
    );
    let method = match decode::<MethodData>(ed.as_ref()) {
        Ok(m) if !m.is_empty() => m,
        _ => Vec::new(),
    };
    assert!(
        method.is_empty(),
        "TYPED-DATA must not decode as PA-DATA: {:?}",
        method.iter().map(|p| p.padata_type).collect::<Vec<_>>()
    );
    let types = edata_int_types(ed.as_ref());
    assert_eq!(types, vec![pa::TD_DH_PARAMETERS, pa::FX_COOKIE]);
}

fn edata_int_types(ed: &[u8]) -> Vec<i32> {
    fn read_len(buf: &[u8], i: usize) -> Option<(usize, usize)> {
        let n = *buf.get(i)? as usize;
        if n < 0x80 {
            return Some((n, i + 1));
        }
        let count = n & 0x7f;
        let mut val = 0usize;
        for j in 0..count {
            val = (val << 8) | *buf.get(i + 1 + j)? as usize;
        }
        Some((val, i + 1 + count))
    }
    fn tlv(buf: &[u8], i: usize) -> Option<(u8, &[u8], usize)> {
        let tag = *buf.get(i)?;
        let (ln, j) = read_len(buf, i + 1)?;
        let end = j.checked_add(ln)?;
        Some((tag, buf.get(j..end)?, end))
    }
    fn parse_int(val: &[u8]) -> i32 {
        let mut n: i32 = 0;
        for b in val {
            n = (n << 8) | i32::from(*b);
        }
        n
    }
    let Ok((_, seq, _)) = tlv(ed, 0).ok_or(()) else {
        return Vec::new();
    };
    let mut types = Vec::new();
    let mut i = 0;
    while i < seq.len() {
        let Some((_, pa, next)) = tlv(seq, i) else {
            break;
        };
        i = next;
        let mut j = 0;
        while j < pa.len() {
            let Some((ptag, pval, n)) = tlv(pa, j) else {
                break;
            };
            j = n;
            if ptag & 0xc0 != 0x80 {
                continue;
            }
            let inner = if ptag & 0x20 != 0 {
                tlv(pval, 0).map_or(pval, |(_, v, _)| v)
            } else {
                pval
            };
            let num = ptag & 0x1f;
            if num == 0 || num == 1 {
                types.push(parse_int(inner));
                break;
            }
        }
    }
    types
}

#[test]
fn fast_error_inner_fx_error_omits_edata() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let armor = issue_tgt(&store, 910);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x51u8; 32]).unwrap();
    let armor_ap = build_fast_armor(
        armor.rep.0.ticket.clone(),
        &armor.session_key,
        &ascii(TEST_REALM),
        &cname,
        Some(&sub),
    )
    .unwrap();
    let akey = armor_key(&armor.session_key, Some(&sub)).unwrap();
    let mut req = as_req(cname, TEST_REALM, 911, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, vec![]).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).expect_err("preauth required");
    let ed = match err {
        Error::PreauthRequired { e_data } => e_data,
        other => panic!("expected PreauthRequired, got {other:?}"),
    };
    let method: MethodData = decode(&ed).expect("outer METHOD-DATA");
    let fast = unwrap_fast_rep(&akey, &Some(method)).expect("FAST inner");
    let fx = fast
        .padata
        .iter()
        .find(|p| p.padata_type == pa::FX_ERROR)
        .expect("PA-FX-ERROR");
    let inner: KrbError = decode(fx.padata_value.as_ref()).expect("inner KRB-ERROR");
    assert!(
        inner.e_data.is_none(),
        "kdc_fast_handle_error zeroes inner FX-ERROR e_data"
    );
    assert!(
        fast.padata.iter().any(|p| p.padata_type == pa::FX_COOKIE),
        "cookie travels in FAST inner padata, not the inner error: {:?}",
        fast.padata
            .iter()
            .map(|p| p.padata_type)
            .collect::<Vec<_>>()
    );
}
