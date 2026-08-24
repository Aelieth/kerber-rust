//! Gated AD PAC tests: captured Windows Server 2022 `host/svc` ticket.
//!
//! The NDR golden `tests/traces/pac-kbruser.ndr` is committed (no keys).
//! `svc.keytab` / ccache stay gitignored; those paths skip cleanly.

use std::path::{Path, PathBuf};

use krb5_asn1::decode;
use krb5_crypto::{checksum, KeyUsage};
use krb5_kdc::{
    bootstrap_documented, decrypt_ticket_part, documented_host, pac_from_ticket_part, sign_pac,
    ticket_checksum_der, verify_pac, verify_pac_signatures, TEST_REALM, TEST_USER,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req, FileCcache, Keytab};
use krb5_types::ku;
use krb5_types::pac::{
    parse_kerb_validation_info, Pac, PAC_CLIENT_INFO, PAC_FULL_CHECKSUM, PAC_LOGON_INFO,
    PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, PAC_TICKET_CHECKSUM, PAC_UPN_DNS_INFO,
};
use krb5_types::{PrincipalName, Ticket};

fn traces_ad() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/traces/ad")
}

fn fixture_dir() -> Option<PathBuf> {
    let traces = traces_ad();
    if traces.join("svc.keytab").is_file() {
        return Some(traces);
    }
    if let Ok(home) = std::env::var("HOME") {
        let adlab = PathBuf::from(home).join("adlab");
        if adlab.join("svc.keytab").is_file() {
            return Some(adlab);
        }
    }
    None
}

fn load_service_key(dir: &Path) -> Option<krb5_crypto::ProtocolKey> {
    let bytes = std::fs::read(dir.join("svc.keytab")).ok()?;
    let kt = Keytab::parse(&bytes).ok()?;
    kt.entries.first().map(|e| e.key.clone())
}

fn load_service_ticket(dir: &Path) -> Option<Ticket> {
    let mut candidates = vec![dir.join("ad.ccache")];
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(PathBuf::from(home).join("adlab/ad.ccache"));
    }
    for path in candidates {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(cc) = FileCcache::parse(&bytes) else {
            continue;
        };
        for cred in &cc.creds {
            if cred.is_config() {
                continue;
            }
            if cred.server.1.components_joined().starts_with("host/") {
                if let Ok(t) = decode::<Ticket>(&cred.ticket) {
                    return Some(t);
                }
            }
        }
    }
    None
}

fn captured_service_pac() -> Option<(Vec<u8>, krb5_crypto::ProtocolKey, krb5_types::EncTicketPart)>
{
    let dir = fixture_dir()?;
    let key = load_service_key(&dir)?;
    let ticket = load_service_ticket(&dir)?;
    let part = decrypt_ticket_part(&key, &ticket).ok()?;
    let pac = pac_from_ticket_part(&part)?;
    Some((pac, key, part))
}

#[test]
fn golden_ndr_is_kbruser_and_byte_identical() {
    let raw = include_bytes!("../../../tests/traces/pac-kbruser.ndr");
    let v = parse_kerb_validation_info(raw).expect("AD NDR");
    assert_eq!(v.effective_name.value, "kbruser");
    assert_eq!(v.logon_domain_name.value, "ADKERBER");
    assert_eq!(v.user_id, 1103);
    assert_eq!(v.primary_group_id, 513);
    assert!(
        v.groups.iter().any(|g| g.relative_id == 1104),
        "kbrgroup RID 1104"
    );
    assert_eq!(
        v.logon_domain_id.to_sddl(),
        "S-1-5-21-1662395604-3502713894-542445324"
    );
    assert_eq!(v.to_ndr().as_slice(), raw.as_slice());
}

#[test]
fn captured_pac_server_checksum_usage_17() {
    let Some((pac_bytes, key, _)) = captured_service_pac() else {
        eprintln!("ad_pac: no svc.keytab/host ticket; skip checksum");
        return;
    };
    let pac = Pac::parse(&pac_bytes).expect("PACTYPE");
    let kinds: Vec<u32> = pac.buffers.iter().map(|b| b.kind).collect();
    assert!(
        kinds.contains(&PAC_LOGON_INFO)
            && kinds.contains(&PAC_SERVER_CHECKSUM)
            && kinds.contains(&PAC_PRIVSVR_CHECKSUM)
            && kinds.contains(&PAC_TICKET_CHECKSUM)
            && kinds.contains(&PAC_FULL_CHECKSUM),
        "AD PAC buffers {kinds:?} must include 1,6,7,16,19"
    );
    assert!(
        kinds.contains(&PAC_UPN_DNS_INFO),
        "UPN/DNS is ulType 12, not 16: {kinds:?}"
    );
    assert_eq!(PAC_UPN_DNS_INFO, 12);
    assert_eq!(PAC_TICKET_CHECKSUM, 16);
    let logon = pac.buffer(PAC_LOGON_INFO).expect("logon");
    let v = parse_kerb_validation_info(logon).expect("NDR");
    assert_eq!(v.effective_name.value, "kbruser");
    let usage = KeyUsage::new(ku::KERB_NON_KERB_CKSUM_SALT).expect("usage 17");
    let mac = checksum(&key, usage, &pac.bytes_for_checksum()).expect("server mac");
    krb5_types::pac::verify_server_checksum(&pac, &mac).expect("AD server checksum");
    verify_pac_signatures(&pac_bytes, &key, None, None).expect("server-only verify");
}

#[test]
fn issued_pac_self_verifies_all_four_signatures() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user = store.get_name(&cname).unwrap().best_key().unwrap();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        701,
        Some(vec![pa_enc_timestamp(&user.key).expect("pa")]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS");
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let tgt_part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).expect("TGT");
    let tgt_pac = pac_from_ticket_part(&tgt_part).expect("TGT PAC");
    let parsed = Pac::parse(&tgt_pac).expect("parse");
    let kinds: Vec<u32> = parsed.buffers.iter().map(|b| b.kind).collect();
    for need in [
        PAC_LOGON_INFO,
        PAC_CLIENT_INFO,
        PAC_SERVER_CHECKSUM,
        PAC_PRIVSVR_CHECKSUM,
        PAC_TICKET_CHECKSUM,
        PAC_FULL_CHECKSUM,
    ] {
        assert!(
            kinds.contains(&need),
            "issued PAC missing {need}: {kinds:?}"
        );
    }
    let der = ticket_checksum_der(&tgt_part).expect("zeroed PAC DER");
    verify_pac_signatures(&tgt_pac, &krbtgt.key, Some(&krbtgt.key), Some(&der))
        .expect("TGT all four");

    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        702,
    )
    .expect("TGS-REQ");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let svc = decrypt_ticket_part(&host.key, &tgs_out.rep.0.ticket).expect("svc");
    let pac = pac_from_ticket_part(&svc).expect("svc PAC");
    let der = ticket_checksum_der(&svc).expect("svc zeroed");
    verify_pac_signatures(&pac, &host.key, Some(&krbtgt.key), Some(&der)).expect("svc all four");
    verify_pac(&pac, &host.key, &krbtgt.key).expect("server+kdc");

    let signed = sign_pac(
        &cname,
        TEST_REALM,
        tgt_part.authtime.unix_seconds(),
        &host.key,
        &krbtgt.key,
        &der,
    )
    .expect("sign");
    // Re-sign uses the service-ticket checksum input, so ticket/full will
    // not match that EncTicketPart; server+kdc still must.
    verify_pac(&signed, &host.key, &krbtgt.key).expect("re-sign server+kdc");
}

#[test]
fn captured_ticket_checksum_structurally_present() {
    let Some((pac_bytes, key, part)) = captured_service_pac() else {
        eprintln!("ad_pac: no fixture; skip ticket-checksum structure");
        return;
    };
    let pac = Pac::parse(&pac_bytes).expect("parse");
    assert!(pac.ticket_checksum().is_some());
    assert!(pac.full_checksum().is_some());
    // krbtgt key is not held; only the server checksum is key-verifiable.
    let der = ticket_checksum_der(&part).expect("der");
    assert!(
        verify_pac_signatures(&pac_bytes, &key, None, Some(&der)).is_ok(),
        "server checksum still holds when ticket-checksum DER is supplied without krbtgt"
    );
}

#[test]
fn absent_keytab_is_not_a_hard_fail() {
    // The golden NDR test above always runs. This assertion documents that
    // checksum tests return rather than panic when fixtures are missing.
    if fixture_dir().is_none() {
        eprintln!("ad_pac: fixtures absent (ok)");
    }
}
