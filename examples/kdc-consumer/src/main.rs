//! In-repo consumer of `krb5-kdc` issue, keytab export, and AP-REQ verify.
//!
//! This binary does not bind a socket. It calls the shipped issue and verify
//! paths and prints the actual return values.

use krb5_asn1::{decode, encode};
use krb5_client::Keytab;
use krb5_crypto::{KeyUsage, decrypt};
use krb5_kdc::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented, documented_admin_id,
    documented_host, pa_enc_timestamp, pac_from_ticket_part, tgs_req,
};
use krb5_protocol::{ReplayCache, build_ap_req, verify_ap_req};
use krb5_types::{EncTicketPart, PrincipalName, ascii, ku};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let (store, acl) = bootstrap_documented()?;
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user = store.get_name(&cname).ok_or("missing user")?;
    let ckey = user.best_key().ok_or("missing user key")?;
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        99,
        Some(vec![pa_enc_timestamp(&ckey.key)?]),
    )?;
    let as_out = krb5_kdc::issue_as(&store, &req)?;
    let tkt_usage = KeyUsage::new(ku::TICKET)?;
    let tgt_key = store
        .krbtgt()
        .ok_or("krbtgt")?
        .best_key()
        .ok_or("tgt key")?;
    let tkt_plain = decrypt(
        &tgt_key.key,
        tkt_usage,
        as_out.rep.0.ticket.enc_part.cipher.as_ref(),
    )?;
    let tgt_part: EncTicketPart = decode(&tkt_plain)?;

    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        100,
    )?;
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs)?;
    let host = store.get_name(&documented_host()).ok_or("host")?;
    let host_key = host.best_key().ok_or("host key")?;
    let svc_plain = decrypt(
        &host_key.key,
        tkt_usage,
        tgs_out.rep.0.ticket.enc_part.cipher.as_ref(),
    )?;
    let svc_part: EncTicketPart = decode(&svc_plain)?;

    let kt = store.export_keytab(&acl, &documented_admin_id(), &documented_host())?;
    let kt_bytes = kt.to_bytes();
    let parsed = Keytab::parse(&kt_bytes)?;

    let ap = build_ap_req(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
    )?;
    let raw = encode(&ap)?;
    let replay = ReplayCache::new();
    verify_ap_req(&raw, &parsed.entries[0].key, &replay)?;

    println!("user={TEST_USER}@{TEST_REALM}");
    println!("password_len={}", TEST_USER_PASSWORD.len());
    println!("tgt_usage={}", tkt_usage.get());
    println!("tgt_client={}", tgt_part.cname.components_joined());
    println!("host_ticket_client={}", svc_part.cname.components_joined());
    println!("keytab_entries={}", parsed.entries.len());
    println!("keytab_v2={}", kt_bytes[0] == 0x05 && kt_bytes[1] == 0x02);
    println!("ap_ok=true");
    if let Some(pac) = pac_from_ticket_part(&svc_part) {
        let parsed = krb5_types::pac::Pac::parse(&pac)?;
        if let Some(logon) = parsed.buffer(krb5_types::pac::PAC_LOGON_INFO) {
            let (name, _) = krb5_types::pac::parse_logon_info(logon)?;
            println!("pac_effective_name={name}");
        }
    }
    let golden = include_bytes!("../../../tests/traces/pac-kbruser.ndr");
    let v = krb5_types::pac::parse_kerb_validation_info(golden)?;
    println!("golden_effective_name={}", v.effective_name.value);
    Ok(())
}

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter("krb5_kdc=info,krb5_protocol=info")
        .try_init();
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("kdc-consumer failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_kdc::TEST_HOST;

    fn install() {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_env_filter("krb5_kdc=info")
            .try_init();
    }

    #[test]
    fn consumer_tgt_host_keytab_apreq() {
        install();
        let (store, acl) = bootstrap_documented().unwrap();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user = store.get_name(&cname).unwrap();
        let ckey = user.best_key().expect("user key");
        let req = as_req(
            cname.clone(),
            TEST_REALM,
            3,
            Some(vec![pa_enc_timestamp(&ckey.key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
        let usage = KeyUsage::new(ku::TICKET).unwrap();
        assert_ne!(usage.get(), 0);
        let tgt_key = store.krbtgt().unwrap().best_key().unwrap();
        let tkt_plain = decrypt(
            &tgt_key.key,
            usage,
            as_out.rep.0.ticket.enc_part.cipher.as_ref(),
        )
        .unwrap();
        let tgt: EncTicketPart = decode(&tkt_plain).unwrap();
        assert_eq!(tgt.cname.components_joined(), TEST_USER);

        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &cname,
            documented_host(),
            TEST_REALM,
            4,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let host = store.get_name(&documented_host()).unwrap();
        let host_key = host.best_key().unwrap();
        let svc_plain = decrypt(
            &host_key.key,
            usage,
            tgs_out.rep.0.ticket.enc_part.cipher.as_ref(),
        )
        .unwrap();
        let svc: EncTicketPart = decode(&svc_plain).unwrap();
        assert_eq!(svc.cname.components_joined(), TEST_USER);

        let kt = store
            .export_keytab(&acl, &documented_admin_id(), &documented_host())
            .unwrap();
        let parsed = Keytab::parse(&kt.to_bytes()).unwrap();
        assert!(
            parsed.entries.len() >= 4,
            "host randkeys include RFC 8009 etypes"
        );
        assert!(
            parsed.entries[0]
                .name
                .components_joined()
                .contains(TEST_HOST)
        );

        let golden = include_bytes!("../../../tests/traces/pac-kbruser.ndr");
        let v = krb5_types::pac::parse_kerb_validation_info(golden).unwrap();
        assert_eq!(v.effective_name.value, "kbruser");

        let ap = build_ap_req(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &ascii(TEST_REALM),
            &cname,
        )
        .unwrap();
        let raw = encode(&ap).unwrap();
        let replay = ReplayCache::new();
        verify_ap_req(&raw, &parsed.entries[0].key, &replay).unwrap();
    }
}
