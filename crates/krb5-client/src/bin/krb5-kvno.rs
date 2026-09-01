//! Obtain a service ticket via TGS and print its kvno (MIT `kvno`).
//!
//! Usage: krb5-kvno [-c ccache] <kdc-host> <service>
//!
//! `-U`/`-P` (S4U) are not implemented.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use krb5_asn1::decode;
use krb5_client::cli::parse_kvno;
use krb5_client::{load_ccache, store_ccache_keep_default};
use krb5_config::resolve_ccspec;
use krb5_protocol::{AsOutcome, KdcAddr, parse_principal, tgs_exchange, tgt_cred};
use krb5_types::{EncKdcRepPart, EncryptionKey, KerberosTime, PrincipalName, Ticket, TicketFlags};

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|a| a == "-U" || a == "-P") {
        eprintln!("krb5-kvno: -U/-P (S4U) is not implemented");
        std::process::exit(2);
    }
    let args = parse_kvno(&raw).unwrap_or_else(|e| {
        eprintln!("kvno: {e}");
        std::process::exit(2);
    });
    let service = args.services.first().cloned().unwrap_or_else(|| {
        eprintln!("usage: krb5-kvno [-c ccache] [kdc-host] <service>");
        std::process::exit(2);
    });
    let spec = resolve_ccspec(args.ccache.as_deref()).unwrap_or_else(|e| {
        eprintln!("kvno: {e}");
        std::process::exit(2);
    });
    let host = if let Some(h) = args.kdc_host.clone() {
        h
    } else {
        let cc = load_ccache(&spec).unwrap_or_else(|e| {
            eprintln!("kvno: {e}");
            std::process::exit(1);
        });
        let realm = String::from_utf8_lossy(cc.primary.0.as_bytes()).into_owned();
        krb5_config::discover_kdc(&realm).map_or_else(
            || "127.0.0.1".into(),
            |ep| format!("{}:{}", ep.host, ep.port),
        )
    };
    if let Err(e) = run(&spec, &host, &service) {
        eprintln!("kvno: {e}");
        std::process::exit(1);
    }
}

fn run(spec: &krb5_config::CcSpec, host: &str, service: &str) -> Result<(), String> {
    let mut cc = load_ccache(spec).map_err(|e| e.to_string())?;
    let cred = cc
        .list()
        .into_iter()
        .find(|c| c.server.1.components_joined().starts_with("krbtgt/"))
        .ok_or_else(|| "ccache has no TGT".to_string())?
        .clone();
    let session = cred.session_key().map_err(|e| e.to_string())?;
    let ticket: Ticket = decode(&cred.ticket).map_err(|e| e.to_string())?;
    let tgt = AsOutcome {
        ticket,
        enc_part: EncKdcRepPart {
            key: EncryptionKey {
                keytype: session.etype().to_iana(),
                keyvalue: session.as_bytes().to_vec().into(),
            },
            last_req: Vec::new(),
            nonce: 0,
            key_expiration: None,
            flags: TicketFlags::from_u32(cred.ticket_flags),
            authtime: KerberosTime::from_unix_seconds(cred.authtime),
            starttime: Some(KerberosTime::from_unix_seconds(cred.starttime)),
            endtime: KerberosTime::from_unix_seconds(cred.endtime),
            renew_till: (cred.renew_till > 0)
                .then(|| KerberosTime::from_unix_seconds(cred.renew_till)),
            srealm: cred.server.0.clone(),
            sname: cred.server.1.clone(),
            caddr: None,
            encrypted_pa_data: None,
        },
        client_key: session.clone(),
        session_key: session,
        cname: cred.client.1.clone(),
        crealm: cred.client.0.clone(),
    };
    let crealm = String::from_utf8_lossy(tgt.crealm.as_bytes()).into_owned();
    let (sname, srealm) = if service.contains('@') {
        parse_principal(service)?
    } else {
        let parts: Vec<&str> = service.split('/').collect();
        (
            PrincipalName::try_new(PrincipalName::NT_PRINCIPAL, parts)
                .map_err(|e| e.to_string())?,
            crealm,
        )
    };
    let addr = if let Some((h, p)) = host.rsplit_once(':') {
        if let Ok(port) = p.parse() {
            KdcAddr {
                host: h.to_owned(),
                port,
            }
        } else {
            KdcAddr::new(host)
        }
    } else {
        KdcAddr::new(host)
    };
    let tgs = tgs_exchange(&addr, &tgt, sname, &srealm).map_err(|e| e.to_string())?;
    let kvno = tgs.ticket.enc_part.kvno.unwrap_or(0);
    println!("{service}: kvno = {kvno}");
    cc.creds.push(
        tgt_cred(
            &tgt.crealm,
            &tgt.cname,
            &tgs.ticket,
            &tgs.session_key,
            &tgs.enc_part,
        )
        .map_err(|e| e.to_string())?,
    );
    store_ccache_keep_default(spec, cc).map_err(|e| e.to_string())?;
    Ok(())
}
