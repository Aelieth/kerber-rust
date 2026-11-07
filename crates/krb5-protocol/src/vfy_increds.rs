use std::io;

use krb5_asn1::{decode, encode};
use krb5_crypto::ProtocolKey;
use krb5_types::{
    EncKdcRepPart, EncryptionKey, KerberosTime, PrincipalName, Realm, Ticket, TicketFlags,
};

use krb5_config::{CanonPrinc, Krb5Conf};

use crate::acceptor_conf::AcceptorConfig;
use crate::ap_req::{
    ApVerifyParams, build_ap_req_in, refused, stamped, validate_times, verify_ap_req_ex,
};
use crate::as_ex::AsOutcome;
use crate::ccmarshal::CcacheCred;
use crate::error::Error;
use crate::keytab::Keytab;
use crate::replay::ReplayCache;
use crate::tgs::tgs_exchange;
use crate::transport::KdcAddr;

// MIT: `nofail` (vfy_increds.c:38-51)
#[must_use]
pub fn verify_init_creds_nofail(opt_nofail: Option<bool>, conf_nofail: bool) -> bool {
    opt_nofail.unwrap_or(conf_nofail)
}

#[must_use]
pub fn keytab_has_server(keytab: &Keytab, realm: &Realm, name: &PrincipalName) -> bool {
    let realm_b = realm.as_bytes();
    keytab
        .entries
        .iter()
        .any(|e| e.realm.as_bytes() == realm_b && e.name.name_string == name.name_string)
}

// MIT: `get_host_princs_from_keytab` (vfy_increds.c:221-257)
#[must_use]
pub fn host_princs_from_keytab(keytab: &Keytab) -> Vec<(Realm, PrincipalName)> {
    let mut out = Vec::new();
    for e in &keytab.entries {
        if e.name.name_string.len() != 2 || e.name.name_string[0].as_bytes() != b"host" {
            continue;
        }
        if out.iter().any(|(r, n): &(Realm, PrincipalName)| {
            r.as_bytes() == e.realm.as_bytes() && n.name_string == e.name.name_string
        }) {
            continue;
        }
        out.push((e.realm.clone(), e.name.clone()));
    }
    out
}

// MIT: `krb5_verify_init_creds` (vfy_increds.c:259-321)
/// No ccache is written.
pub fn verify_init_creds(
    profile: &Krb5Conf,
    creds: &CcacheCred,
    server: Option<(&Realm, &PrincipalName)>,
    keytab: Option<&Keytab>,
    kdc: &KdcAddr,
    nofail: bool,
) -> Result<(), Error> {
    // MIT: `get_vfy_cred` (lib/krb5/krb/vfy_increds.c:151-151)
    let conf = AcceptorConfig::from_krb5_conf(profile);
    let mut last = Err(no_verify_keys());
    let mut have_keys = false;
    if let Some((realm, name)) = server {
        if let Some(kt) = keytab.filter(|kt| keytab_has_server(kt, realm, name)) {
            have_keys = true;
            last = get_vfy_cred(profile, creds, realm, name, kt, kdc, &conf);
        }
    } else if let Some(kt) = keytab {
        let hosts = host_princs_from_keytab(kt);
        if !hosts.is_empty() {
            have_keys = true;
            last = Err(no_verify_keys());
            for (realm, name) in &hosts {
                last = get_vfy_cred(profile, creds, realm, name, kt, kdc, &conf);
                if last.is_ok() {
                    break;
                }
            }
        }
    }
    if !have_keys && !nofail {
        return Ok(());
    }
    last
}

fn no_verify_keys() -> Error {
    Error::File(io::Error::new(
        io::ErrorKind::NotFound,
        "keytab has no verify keys",
    ))
}

fn princ_eq(a: &(Realm, PrincipalName), realm: &Realm, name: &PrincipalName) -> bool {
    a.0.as_bytes() == realm.as_bytes() && a.1.name_string == name.name_string
}

// MIT: `get_vfy_cred` (vfy_increds.c:90-94)
/// Other servers: TGS exchange first.
fn get_vfy_cred(
    profile: &Krb5Conf,
    creds: &CcacheCred,
    realm: &Realm,
    name: &PrincipalName,
    keytab: &Keytab,
    kdc: &KdcAddr,
    conf: &AcceptorConfig,
) -> Result<(), Error> {
    let session = creds.session_key()?;
    let ticket: Ticket = decode(&creds.ticket)?;
    let now = stamped(0).0;
    let (ticket, session, crealm, cname, times) = if princ_eq(&creds.server, realm, name) {
        (
            ticket,
            session,
            creds.client.0.clone(),
            creds.client.1.clone(),
            creds.times(),
        )
    } else {
        // MIT: `get_cached_local_tgt` (lib/krb5/krb/get_creds.c:833-837)
        if now.unix_seconds() > creds.endtime {
            return Err(refused(krb5_types::err::TKT_EXPIRED));
        }
        let tgt = cred_as_outcome(creds, &session, ticket);
        // MIT: `krb5_tkt_creds_step` (lib/krb5/krb/get_creds.c:1293-1305)
        let princ = (realm.clone(), name.clone());
        let mut last = refused(krb5_types::err::S_PRINCIPAL_UNKNOWN);
        let mut tgs = None;
        for (crealm, cname) in CanonPrinc::new(profile, &princ) {
            let realm_s = String::from_utf8_lossy(crealm.as_bytes()).into_owned();
            match tgs_exchange(profile, kdc, &tgt, cname, &realm_s) {
                Err(
                    e @ Error::KrbError {
                        code: krb5_types::err::S_PRINCIPAL_UNKNOWN,
                        ..
                    },
                ) => {
                    last = e;
                }
                got => {
                    tgs = Some(got?);
                    break;
                }
            }
        }
        let tgs = tgs.ok_or(last)?;
        let times = (&tgs.enc_part).into();
        (tgs.ticket, tgs.session_key, tgt.crealm, tgt.cname, times)
    };
    // MIT: `krb5_mk_req_extended` (lib/krb5/krb/mk_req_ext.c:115-117)
    validate_times(&times, &now, i64::from(profile.clockskew))?;
    let ap = build_ap_req_in(ticket, &session, &crealm, &cname, Some(profile))?;
    let raw = encode(&ap)?;
    // MIT: `decrypt_ticket` (lib/krb5/krb/rd_req_dec.c:454-470)
    let princ = (realm.clone(), name.clone());
    let wildcard = matches!(name.name_string.as_slice(), [_, host]
        if name.name_type == PrincipalName::NT_SRV_HST
            && (host.as_bytes().is_empty() || conf.ignore_acceptor_hostname));
    let mut iter = CanonPrinc::new(profile, &princ);
    iter.no_hostrealm = true;
    let names: Vec<_> = if wildcard {
        vec![princ.clone()]
    } else {
        iter.collect()
    };
    let mut last = refused(krb5_types::err::NOKEY);
    for (_, name) in &names {
        match rd_req_as(&raw, realm, name, keytab, conf) {
            Err(
                e @ Error::KrbError {
                    code: krb5_types::err::NOKEY,
                    ..
                },
            ) => last = e,
            got => return got,
        }
    }
    Err(last)
}

fn rd_req_as(
    raw: &[u8],
    realm: &Realm,
    name: &PrincipalName,
    keytab: &Keytab,
    conf: &AcceptorConfig,
) -> Result<(), Error> {
    let matched: Vec<_> = keytab
        .entries
        .iter()
        .filter(|e| {
            e.realm.as_bytes() == realm.as_bytes() && e.name.name_string == name.name_string
        })
        .collect();
    let keys: Vec<ProtocolKey> = matched.iter().map(|e| e.key.clone()).collect();
    let kvnos: Vec<u32> = matched.iter().map(|e| e.kvno).collect();
    let realm_s = String::from_utf8_lossy(realm.as_bytes()).into_owned();
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: Some(kvnos.as_slice()),
        key_principals: None,
        kvno: None,
        permitted: conf.permitted()?,
        expected_server: Some(name),
        expected_realm: Some(realm_s.as_str()),
        get_entry: None,
        skew: i64::from(conf.clockskew),
        ignore_acceptor_hostname: conf.ignore_acceptor_hostname,
        capaths: &conf.capaths,
        remote_addr: None,
        now: None,
    };
    verify_ap_req_ex(raw, &params, &ReplayCache::new(), None)?;
    Ok(())
}

fn cred_as_outcome(creds: &CcacheCred, session: &ProtocolKey, ticket: Ticket) -> AsOutcome {
    AsOutcome {
        ticket,
        enc_part: EncKdcRepPart {
            key: EncryptionKey {
                keytype: session.etype().to_iana(),
                keyvalue: session.as_bytes().to_vec().into(),
            },
            last_req: Vec::new(),
            nonce: 0,
            key_expiration: None,
            flags: TicketFlags::from_u32(creds.ticket_flags),
            authtime: KerberosTime::from_unix_seconds(creds.authtime),
            starttime: Some(KerberosTime::from_unix_seconds(creds.starttime)),
            endtime: KerberosTime::from_unix_seconds(creds.endtime),
            renew_till: (creds.renew_till > 0)
                .then(|| KerberosTime::from_unix_seconds(creds.renew_till)),
            srealm: creds.server.0.clone(),
            sname: creds.server.1.clone(),
            caddr: None,
            encrypted_pa_data: None,
        },
        client_key: session.clone(),
        session_key: session.clone(),
        cname: creds.client.1.clone(),
        crealm: creds.client.0.clone(),
        fast_avail: false,
        used_fast: false,
        pa_type: None,
        pa_config: None,
        time_offset: 0,
    }
}
