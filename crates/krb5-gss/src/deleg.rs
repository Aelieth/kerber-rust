//! Delegation (`init_sec_context.c` KRB-CRED trailer): `DelegCred`
//! and the 0x8003 checksum cred.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_protocol::{CcacheCred, CcacheKeyblock, FileCcache, ReplayCache, unwrap_krb_cred};
use krb5_types::{
    EncKrbCredPart, EncryptedData, EncryptionKey, KerberosTime, KrbCred, KrbCredInfo, Microseconds,
    PrincipalName, Realm, Ticket, TicketFlags, ku,
};

use super::oid::GSS_C_DELEG;
use super::{Error, GssContext};

/// Forwarded TGT (or other ticket) to embed in a GSS delegation checksum.
#[derive(Clone, Debug)]
pub struct DelegCred {
    /// Ticket to forward.
    pub ticket: Ticket,
    /// Session key of `ticket` (goes in `KrbCredInfo.key`).
    pub session: ProtocolKey,
    /// Client realm.
    pub crealm: Realm,
    /// Client name.
    pub cname: PrincipalName,
    /// Ticket flags copied into `KrbCredInfo`.
    pub flags: TicketFlags,
    /// `KrbCredInfo` authtime.
    pub authtime: Option<KerberosTime>,
    /// `KrbCredInfo` starttime.
    pub starttime: Option<KerberosTime>,
    /// `KrbCredInfo` endtime.
    pub endtime: Option<KerberosTime>,
    /// `KrbCredInfo` renew-till.
    pub renew_till: Option<KerberosTime>,
}

pub(super) fn krb_cred_for_deleg(
    ticket_session: &ProtocolKey,
    deleg: &DelegCred,
) -> Result<Vec<u8>, Error> {
    let realm = String::from_utf8_lossy(deleg.crealm.as_bytes());
    let info = KrbCredInfo {
        key: EncryptionKey {
            keytype: deleg.session.etype().to_iana(),
            keyvalue: deleg.session.as_bytes().to_vec().into(),
        },
        prealm: Some(deleg.crealm.clone()),
        pname: Some(deleg.cname.clone()),
        flags: Some(deleg.flags.clone()),
        authtime: deleg.authtime.clone(),
        starttime: deleg.starttime.clone(),
        endtime: deleg.endtime.clone(),
        renew_till: deleg.renew_till.clone(),
        srealm: Some(deleg.crealm.clone()),
        sname: Some(PrincipalName::krbtgt(realm.as_ref())),
        caddr: None,
    };
    let now = KerberosTime::now();
    let part = EncKrbCredPart {
        ticket_info: vec![info],
        nonce: None,
        timestamp: Some(now.clone()),
        usec: Some(Microseconds::from_subsec_micros(
            now.0.timestamp_subsec_micros(),
        )),
        s_address: None,
        r_address: None,
    };
    let der = encode(&part)?;
    let usage = KeyUsage::new(ku::KRB_CRED_ENC_PART)?;
    let cipher = encrypt(ticket_session, usage, &der)?;
    let cred = KrbCred {
        pvno: KrbCred::PVNO,
        msg_type: KrbCred::MSG_TYPE,
        tickets: vec![deleg.ticket.clone()],
        enc_part: EncryptedData {
            etype: ticket_session.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    Ok(encode(&cred)?)
}

pub(super) fn extract_delegated(
    cksum: &[u8],
    flags: u32,
    subkey: Option<&ProtocolKey>,
    ticket_session: &ProtocolKey,
    replay: &ReplayCache,
) -> Result<Option<String>, Error> {
    if flags & GSS_C_DELEG == 0 {
        return Ok(None);
    }
    if cksum.len() < 28 {
        return Err(Error::Truncated);
    }
    let dlgth = usize::from(u16::from_le_bytes(
        cksum[26..28].try_into().map_err(|_| Error::Truncated)?,
    ));
    if dlgth > cksum.len() - 28 {
        return Err(Error::Truncated);
    }
    let raw = &cksum[28..28 + dlgth];
    let mut part = None;
    if let Some(sk) = subkey {
        part = unwrap_krb_cred(sk, raw, replay).ok();
    }
    if part.is_none() {
        part = unwrap_krb_cred(ticket_session, raw, replay).ok();
    }
    let part = part.ok_or_else(|| Error::Inner("gss failure".into()))?;
    let info = part.1.ticket_info.first().ok_or(Error::Truncated)?;
    let realm = info.prealm.as_ref().map_or_else(String::new, |r| {
        String::from_utf8_lossy(r.as_bytes()).into_owned()
    });
    let name = info
        .pname
        .as_ref()
        .map_or_else(String::new, |n| n.unparse_with_realm(&realm));
    if let Ok(path) = std::env::var("GSS_DELEG_CCACHE")
        && !path.is_empty()
    {
        write_deleg_ccache(&path, &part.0, &part.1)?;
    }
    Ok(Some(name))
}

fn write_deleg_ccache(path: &str, cred: &KrbCred, part: &EncKrbCredPart) -> Result<(), Error> {
    let info = part.ticket_info.first().ok_or(Error::Truncated)?;
    let ticket = cred.tickets.first().ok_or(Error::Truncated)?;
    let prealm = info.prealm.clone().ok_or(Error::Truncated)?;
    let pname = info.pname.clone().ok_or(Error::Truncated)?;
    let etype = EncryptionType::from_iana(info.key.keytype).map_err(Error::from)?;
    let session =
        ProtocolKey::from_bytes(etype, info.key.keyvalue.as_ref()).map_err(Error::from)?;
    let srealm = info.srealm.clone().unwrap_or_else(|| prealm.clone());
    let sname = info
        .sname
        .clone()
        .unwrap_or_else(|| PrincipalName::krbtgt(&String::from_utf8_lossy(prealm.as_bytes())));
    let cc = FileCcache::new(
        (prealm.clone(), pname.clone()),
        vec![CcacheCred {
            client: (prealm, pname),
            server: (srealm, sname),
            key: CcacheKeyblock::from_protocol(&session),
            authtime: info.authtime.as_ref().map_or(0, KerberosTime::unix_seconds),
            starttime: info
                .starttime
                .as_ref()
                .or(info.authtime.as_ref())
                .map_or(0, KerberosTime::unix_seconds),
            endtime: info.endtime.as_ref().map_or(0, KerberosTime::unix_seconds),
            renew_till: info
                .renew_till
                .as_ref()
                .map_or(0, KerberosTime::unix_seconds),
            is_skey: 0,
            ticket_flags: info.flags.as_ref().map_or(0, TicketFlags::to_u32),
            addresses: Vec::new(),
            authdata: Vec::new(),
            ticket: encode(ticket).map_err(|e| Error::Inner(e.to_string()))?,
            second_ticket: Vec::new(),
        }],
    );
    cc.write_file(path).map_err(|e| Error::Inner(e.to_string()))
}

impl GssContext {
    /// Delegated initiator name if `GSS_C_DELEG_FLAG` carried a KRB-CRED.
    #[must_use]
    pub fn delegated(&self) -> Option<&str> {
        self.delegated.as_deref()
    }
}
