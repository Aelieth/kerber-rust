//! Exported context tokens (`export_sec_context.c`,
//! `import_sec_context.c`, `ser_sctx.c`): a Rust-private encoding,
//! not MIT's `ser_sctx` wire.

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_protocol::ReplayCache;

use super::{Error, GssContext};

const EXPORT_MAGIC: &[u8; 4] = b"K5G1";

const EXPORT_VERSION: u8 = 1;

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
    /// Serialize context state (private Rust↔Rust format, not MIT `kg_ctx_externalize`).
    ///
    /// # Errors
    ///
    /// Key length overflows `u16`.
    pub fn export_sec_context(&self) -> Result<Vec<u8>, Error> {
        let mut o = Vec::new();
        o.extend_from_slice(EXPORT_MAGIC);
        o.push(EXPORT_VERSION);
        o.push(u8::from(self.initiator));
        o.push(u8::from(self.rpcsec_init_window));
        o.extend_from_slice(&self.gss_flags.to_le_bytes());
        o.extend_from_slice(&self.lifetime_end.to_le_bytes());
        o.extend_from_slice(&self.send_seq.to_be_bytes());
        o.extend_from_slice(&self.recv_seq.to_be_bytes());
        o.push(u8::from(self.recv_seen));
        let mut win: Vec<u64> = self.recv_window.iter().copied().collect();
        win.sort_unstable();
        let nwin = u16::try_from(win.len()).map_err(|_| Error::Truncated)?;
        o.extend_from_slice(&nwin.to_be_bytes());
        for s in win {
            o.extend_from_slice(&s.to_be_bytes());
        }
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

    /// Inverse of [`Self::export_sec_context`].
    ///
    /// # Errors
    ///
    /// Truncated or unknown version.
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
        let rpcsec_init_window = *token.get(i).ok_or(Error::Truncated)? != 0;
        i += 1;
        let gss_flags = u32::from_le_bytes(take_arr(token, &mut i)?);
        let lifetime_end = u32::from_le_bytes(take_arr(token, &mut i)?);
        let send_seq = u64::from_be_bytes(take_arr(token, &mut i)?);
        let recv_seq = u64::from_be_bytes(take_arr(token, &mut i)?);
        let recv_seen = *token.get(i).ok_or(Error::Truncated)? != 0;
        i += 1;
        let nwin = usize::from(u16::from_be_bytes(take_arr(token, &mut i)?));
        if nwin > 64 {
            return Err(Error::Truncated);
        }
        let mut recv_window = std::collections::HashSet::new();
        for _ in 0..nwin {
            recv_window.insert(u64::from_be_bytes(take_arr(token, &mut i)?));
        }
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
            recv_seq,
            recv_seen,
            recv_window,
            initiator,
            rpcsec_init_window,
            replay: ReplayCache::new(),
            client,
            delegated,
            spnego_mech_list: if sp.is_empty() {
                None
            } else {
                Some(sp.to_vec())
            },
            lifetime_end,
            gss_flags,
            ticket_initial: false,
            acceptor: None,
            ticket_realm: None,
            ap_rep_key: None,
            dce_style: false,
        })
    }
}
