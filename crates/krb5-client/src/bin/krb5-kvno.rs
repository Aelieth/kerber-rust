//! Obtain a service ticket via TGS and print its kvno (MIT `kvno`).
//!
//! Usage: krb5-kvno [-c ccache] [--disable-transited-check] [kdc-host] <service>
//!
//! `--disable-transited-check` is gate-only (MIT `kvno` cannot set bit 26).
//! `-U <user>` sends PA-FOR-USER (S4U2Self). MIT `kvno -U` also requires the
//! ccache principal to equal the service; this binary does not, so a user TGT
//! can present the Y0 mismatch cell. `-P` is not implemented.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use krb5_asn1::decode;
use krb5_client::cli::parse_kvno;
use krb5_client::{load_ccache, store_ccache_keep_default};
use krb5_config::resolve_ccspec;
use krb5_protocol::{AsOutcome, KdcAddr, parse_principal, tgs_exchange_ex, tgs_s4u, tgt_cred};
use krb5_types::{
    EncKdcRepPart, EncryptionKey, KerberosTime, PrincipalName, Ticket, TicketFlags, err,
};

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.iter().any(|a| a == "-P") {
        eprintln!("krb5-kvno: -P (S4U2Proxy) is not implemented");
        std::process::exit(2);
    }
    let args = parse_kvno(&raw).unwrap_or_else(|e| {
        eprintln!("kvno: {e}");
        std::process::exit(2);
    });
    let service = args.services.first().cloned().unwrap_or_else(|| {
        eprintln!("usage: krb5-kvno [-c ccache] [--disable-transited-check] [kdc-host] <service>");
        std::process::exit(2);
    });
    let spec = resolve_ccspec(args.ccache.as_deref()).unwrap_or_else(|e| {
        eprintln!("kvno: {e}");
        std::process::exit(2);
    });
    if let Err(e) = run(
        &spec,
        args.kdc_host.as_deref(),
        &service,
        args.disable_transited_check,
        args.for_user.as_deref(),
    ) {
        eprintln!("kvno: {e}");
        std::process::exit(1);
    }
}

fn kvno_err(e: krb5_protocol::Error) -> String {
    match e {
        krb5_protocol::Error::KrbError {
            code: err::POLICY, ..
        } => "KDC policy rejects request".into(),
        krb5_protocol::Error::KrbError {
            code: err::BADMATCH,
            text,
        } => text.unwrap_or_else(|| "Ticket/authenticator don't match".into()),
        other => other.to_string(),
    }
}

fn parse_addr(host: &str) -> KdcAddr {
    if let Some((h, p)) = host.rsplit_once(':')
        && let Ok(port) = p.parse()
    {
        return KdcAddr {
            host: h.to_owned(),
            port,
        };
    }
    KdcAddr::new(host)
}

fn addr_for_realm(realm: &str, explicit: Option<&str>) -> KdcAddr {
    if let Some(h) = explicit {
        return parse_addr(h);
    }
    krb5_config::discover_kdc(realm).map_or_else(
        || KdcAddr::new("127.0.0.1"),
        |ep| KdcAddr {
            host: ep.host,
            port: ep.port,
        },
    )
}

fn run(
    spec: &krb5_config::CcSpec,
    kdc_host: Option<&str>,
    service: &str,
    disable_transited_check: bool,
    for_user: Option<&str>,
) -> Result<(), String> {
    let mut cc = load_ccache(spec).map_err(|e| e.to_string())?;
    let (cred, sname, srealm, hop_realm) = {
        let creds = cc.list();
        let any_tgt = creds
            .iter()
            .copied()
            .find(|c| c.server.1.components_joined().starts_with("krbtgt/"))
            .ok_or_else(|| "ccache has no TGT".to_string())?;
        let crealm = String::from_utf8_lossy(any_tgt.client.0.as_bytes()).into_owned();
        let (sname, srealm) = if service.contains('@') {
            parse_principal(service)?
        } else {
            let parts: Vec<&str> = service.split('/').collect();
            let host_realm = parts.get(1).and_then(|h| {
                krb5_config::load_krb5_conf().and_then(|c| c.realm_for_host(h).map(str::to_owned))
            });
            (
                PrincipalName::try_new(PrincipalName::NT_PRINCIPAL, parts)
                    .map_err(|e| e.to_string())?,
                host_realm.unwrap_or(crealm.clone()),
            )
        };
        let cred = creds
            .iter()
            .copied()
            .find(|c| c.server.1.is_krbtgt_for(&srealm))
            .unwrap_or(any_tgt)
            .clone();
        let hop_realm = if cred.server.1.is_krbtgt_for(&srealm) {
            srealm.clone()
        } else {
            crealm
        };
        (cred, sname, srealm, hop_realm)
    };
    let addr = addr_for_realm(&hop_realm, kdc_host);
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
    let tgs = if let Some(who) = for_user {
        let (uname, urealm) = if who.contains('@') {
            parse_principal(who)?
        } else {
            (
                PrincipalName::try_new(PrincipalName::NT_PRINCIPAL, [who])
                    .map_err(|e| e.to_string())?,
                srealm.clone(),
            )
        };
        tgs_s4u(&addr, &tgt, sname, &srealm, uname, &urealm).map_err(kvno_err)?
    } else {
        tgs_exchange_ex(&addr, &tgt, sname, &srealm, disable_transited_check).map_err(kvno_err)?
    };
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
