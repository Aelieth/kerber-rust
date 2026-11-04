use krb5_crypto::{EncryptionType, ProtocolKey};

use super::seqstate::SeqState;
use super::{Error, GssContext};

const EXPORT_MAGIC: &[u8; 4] = b"K5G1";

const EXPORT_VERSION: u8 = 2;

fn write_key(out: &mut Vec<u8>, key: &ProtocolKey) -> Result<(), Error> {
    out.extend_from_slice(&key.etype().to_iana().to_be_bytes());
    let n = u16::try_from(key.as_bytes().len()).map_err(|_| Error::Truncated)?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(key.as_bytes());
    Ok(())
}

fn read_key(token: &[u8], i: &mut usize) -> Result<ProtocolKey, Error> {
    let etype_n = i32::from_be_bytes(take_arr(token, i)?);
    let n = usize::from(u16::from_be_bytes(take_arr(token, i)?));
    let bytes = token.get(*i..*i + n).ok_or(Error::Truncated)?;
    *i += n;
    let et = EncryptionType::from_iana(etype_n).or_else(|_| EncryptionType::known(etype_n))?;
    Ok(ProtocolKey::from_bytes(et, bytes)?)
}

fn take_arr<const N: usize>(token: &[u8], i: &mut usize) -> Result<[u8; N], Error> {
    let s = token.get(*i..*i + N).ok_or(Error::Truncated)?;
    *i += N;
    s.try_into().map_err(|_| Error::Truncated)
}

fn write_opt_str(out: &mut Vec<u8>, s: Option<&str>) -> Result<(), Error> {
    let b = s.unwrap_or("").as_bytes();
    let n = u16::try_from(b.len()).map_err(|_| Error::Truncated)?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn read_opt_str(token: &[u8], i: &mut usize) -> Result<Option<String>, Error> {
    let n = usize::from(u16::from_be_bytes(take_arr(token, i)?));
    let b = token.get(*i..*i + n).ok_or(Error::Truncated)?;
    *i += n;
    if b.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8(b.to_vec()).map_err(|_| Error::Truncated)?,
    ))
}

impl GssContext {
    pub fn export_sec_context(&self) -> Result<Vec<u8>, Error> {
        let mut o = Vec::new();
        o.extend_from_slice(EXPORT_MAGIC);
        o.push(EXPORT_VERSION);
        o.push(u8::from(self.initiator));
        o.extend_from_slice(&self.gss_flags.to_le_bytes());
        o.extend_from_slice(&self.lifetime_end.to_le_bytes());
        o.extend_from_slice(&self.acceptor_skew.to_le_bytes());
        o.extend_from_slice(&self.send_seq.to_be_bytes());
        let r = &self.recv;
        o.push(u8::from(r.do_replay) | u8::from(r.do_sequence) << 1 | u8::from(r.wide) << 2);
        o.extend_from_slice(&r.base.to_be_bytes());
        o.extend_from_slice(&r.next.to_be_bytes());
        o.extend_from_slice(&r.recvmap.to_be_bytes());
        write_key(&mut o, &self.session)?;
        match &self.acceptor_subkey {
            Some(k) => {
                o.push(1);
                write_key(&mut o, k)?;
            }
            None => o.push(0),
        }
        write_opt_str(&mut o, self.client.as_deref())?;
        write_opt_str(&mut o, self.delegated.as_deref())?;
        let sp = self.spnego_mech_list.as_deref().unwrap_or(&[]);
        let n = u16::try_from(sp.len()).map_err(|_| Error::Truncated)?;
        o.extend_from_slice(&n.to_be_bytes());
        o.extend_from_slice(sp);
        Ok(o)
    }

    pub fn import_sec_context(token: &[u8]) -> Result<Self, Error> {
        let mut i = 0usize;
        if token.get(i..i + 4) != Some(EXPORT_MAGIC.as_slice()) {
            return Err(Error::Truncated);
        }
        i += 4;
        let ver = *token.get(i).ok_or(Error::Truncated)?;
        i += 1;
        if ver != EXPORT_VERSION {
            return Err(Error::Truncated);
        }
        let initiator = *token.get(i).ok_or(Error::Truncated)? != 0;
        i += 1;
        let gss_flags = u32::from_le_bytes(take_arr(token, &mut i)?);
        let lifetime_end = u32::from_le_bytes(take_arr(token, &mut i)?);
        let acceptor_skew = i32::from_le_bytes(take_arr(token, &mut i)?);
        let send_seq = u64::from_be_bytes(take_arr(token, &mut i)?);
        let checks = *token.get(i).ok_or(Error::Truncated)?;
        i += 1;
        if checks > 7 {
            return Err(Error::Truncated);
        }
        let recv = SeqState {
            do_replay: checks & 1 != 0,
            do_sequence: checks & 2 != 0,
            wide: checks & 4 != 0,
            base: u64::from_be_bytes(take_arr(token, &mut i)?),
            next: u64::from_be_bytes(take_arr(token, &mut i)?),
            recvmap: u64::from_be_bytes(take_arr(token, &mut i)?),
        };
        let session = read_key(token, &mut i)?;
        let has_sub = *token.get(i).ok_or(Error::Truncated)?;
        i += 1;
        let acceptor_subkey = if has_sub != 0 {
            Some(read_key(token, &mut i)?)
        } else {
            None
        };
        let client = read_opt_str(token, &mut i)?;
        let delegated = read_opt_str(token, &mut i)?;
        let nsp = usize::from(u16::from_be_bytes(take_arr(token, &mut i)?));
        let sp = token.get(i..i + nsp).ok_or(Error::Truncated)?;
        i += nsp;
        if i != token.len() {
            return Err(Error::Truncated);
        }
        Ok(Self {
            session,
            acceptor_subkey,
            send_seq,
            recv,
            initiator,
            client,
            delegated,
            spnego_mech_list: if sp.is_empty() {
                None
            } else {
                Some(sp.to_vec())
            },
            lifetime_end,
            acceptor_skew,
            gss_flags,
            ticket_initial: false,
            acceptor: None,
            ticket_realm: None,
            ap_rep_key: None,
            dce_style: false,
            ap_req_time: None,
        })
    }
}
