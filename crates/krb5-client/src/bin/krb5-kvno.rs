//! Obtain a service ticket via TGS and print its kvno (MIT `kvno`).
//!
//! Usage: krb5-kvno [-c ccache] <kdc-host> <service>
//!
//! `-U`/`-P` (S4U) are not implemented.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use krb5_asn1::decode;
use krb5_config::{default_ccache_name, env_ccname};
use krb5_protocol::{AsOutcome, FileCcache, KdcAddr, parse_principal, tgs_exchange, tgt_cred};
use krb5_types::{EncKdcRepPart, EncryptionKey, KerberosTime, PrincipalName, Ticket, TicketFlags};

fn main() {
    let mut ccname = None::<PathBuf>;
    let mut positional = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a.as_str() == "-c" {
            ccname = args
                .next()
                .map(|s| PathBuf::from(s.strip_prefix("FILE:").unwrap_or(&s)));
        } else if a == "-U" || a == "-P" {
            eprintln!("krb5-kvno: -U/-P (S4U) is not implemented");
            std::process::exit(2);
        } else {
            positional.push(a);
        }
    }
    let mut pos = positional.into_iter();
    let host = pos.next().unwrap_or_else(|| {
        eprintln!("usage: krb5-kvno [-c ccache] <kdc-host> <service>");
        std::process::exit(2);
    });
    let service = pos.next().unwrap_or_else(|| {
        eprintln!("missing service");
        std::process::exit(2);
    });
    let path = ccname
        .or_else(env_ccname)
        .unwrap_or_else(default_ccache_name);
    if let Err(e) = run(&path, &host, &service) {
        eprintln!("kvno: {e}");
        std::process::exit(1);
    }
}

fn run(path: &std::path::Path, host: &str, service: &str) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut cc = FileCcache::parse(&bytes).map_err(|e| e.to_string())?;
    let cred = cc
        .list()
        .into_iter()
        .find(|c| c.server.1.components_joined().starts_with("krbtgt/"))
        .ok_or_else(|| "ccache has no TGT".to_string())?
        .clone();
    let ticket: Ticket = decode(&cred.ticket).map_err(|e| e.to_string())?;
    let tgt = AsOutcome {
        ticket,
        enc_part: EncKdcRepPart {
            key: EncryptionKey {
                keytype: cred.key.etype().to_iana(),
                keyvalue: cred.key.as_bytes().to_vec().into(),
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
        client_key: cred.key.clone(),
        session_key: cred.key.clone(),
        cname: cred.client.1.clone(),
        crealm: cred.client.0.clone(),
    };
    let crealm = String::from_utf8_lossy(tgt.crealm.as_bytes()).into_owned();
    let (sname, srealm) = if service.contains('@') {
        parse_principal(service)?
    } else {
        let parts: Vec<&str> = service.split('/').collect();
        (
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, parts),
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
    cc.write_file(path).map_err(|e| e.to_string())?;
    Ok(())
}
