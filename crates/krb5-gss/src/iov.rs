//! IOV wrap (`k5sealiov.c`, `k5sealv3iov.c`, `k5unsealiov.c`,
//! `wrap_size_limit.c`): SIGN_ONLY buffers and DCE RRC.

use krb5_crypto::{checksum, decrypt_cts, encrypt_with_confounder, integrity_mac};

use super::wrap::{
    AES_CONFOUNDER, FLAG_SEALED, TOK_WRAP, check_direction, mac_eq, require_aes, seal_usage,
    verify_enc_header, wrap_header,
};
use super::{Error, GssContext};

/// GSS IOV buffer type (MIT `gssapi_ext.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IovType {
    /// Confidentiality payload (encrypted in place).
    Data,
    /// Token header (GSS 16 + AES confounder ciphertext).
    Header,
    /// E(header) + HMAC.
    Trailer,
    /// Empty for AES-CTS / RFC 8009.
    Padding,
    /// Integrity-only associated data (RPCSEC_GSS header).
    SignOnly,
}

/// One wrap_iov buffer. HEADER/TRAILER/PADDING are resized; DATA is in-place.
pub struct IovBuf<'a> {
    /// Buffer role.
    pub kind: IovType,
    /// Backing storage.
    pub data: &'a mut Vec<u8>,
}

fn iov_find<'a>(iov: &'a [IovBuf<'_>], kind: IovType) -> Result<&'a [u8], Error> {
    let mut found = None;
    for b in iov {
        if b.kind == kind {
            if found.is_some() {
                return Err(Error::Truncated);
            }
            found = Some(b.data.as_slice());
        }
    }
    found.ok_or(Error::Truncated)
}

fn iov_data_len(iov: &[IovBuf<'_>]) -> Result<usize, Error> {
    let n: usize = iov
        .iter()
        .filter(|b| b.kind == IovType::Data)
        .map(|b| b.data.len())
        .sum();
    if n == 0 && !iov.iter().any(|b| b.kind == IovType::Data) {
        return Err(Error::Truncated);
    }
    Ok(n)
}

fn iov_copy_data(iov: &[IovBuf<'_>], out: &mut Vec<u8>) -> Result<(), Error> {
    let mut any = false;
    for b in iov {
        if b.kind == IovType::Data {
            any = true;
            out.extend_from_slice(b.data);
        }
    }
    if any { Ok(()) } else { Err(Error::Truncated) }
}

fn iov_sign_body(iov: &[IovBuf<'_>], out: &mut Vec<u8>) {
    for b in iov {
        if matches!(b.kind, IovType::Data | IovType::SignOnly) {
            out.extend_from_slice(b.data);
        }
    }
}

fn write_iov_one(iov: &mut [IovBuf<'_>], kind: IovType, bytes: &[u8]) -> Result<(), Error> {
    let mut slot = None;
    for (i, b) in iov.iter().enumerate() {
        if b.kind == kind {
            if slot.is_some() {
                return Err(Error::Truncated);
            }
            slot = Some(i);
        }
    }
    let i = slot.ok_or(Error::Truncated)?;
    iov[i].data.clear();
    iov[i].data.extend_from_slice(bytes);
    Ok(())
}

fn write_iov_data(iov: &mut [IovBuf<'_>], plain: &[u8]) -> Result<(), Error> {
    let mut off = 0usize;
    for b in iov.iter_mut() {
        if b.kind == IovType::Data {
            let n = b.data.len();
            let chunk = plain.get(off..off + n).ok_or(Error::Truncated)?;
            b.data.copy_from_slice(chunk);
            off += n;
        }
    }
    if off == plain.len() {
        Ok(())
    } else {
        Err(Error::Truncated)
    }
}

fn join_wrap_token(iov: &[IovBuf<'_>]) -> Result<Vec<u8>, Error> {
    let mut tok = iov_find(iov, IovType::Header)?.to_vec();
    iov_copy_data(iov, &mut tok)?;
    if let Ok(p) = iov_find(iov, IovType::Padding) {
        tok.extend_from_slice(p);
    }
    tok.extend_from_slice(iov_find(iov, IovType::Trailer)?);
    Ok(tok)
}

fn split_wrap_token(
    iov: &mut [IovBuf<'_>],
    tok: &[u8],
    n: usize,
    trailer_len: usize,
) -> Result<(), Error> {
    let header_len = 16 + AES_CONFOUNDER;
    if tok.len() != header_len + n + trailer_len {
        return Err(Error::Truncated);
    }
    write_iov_one(iov, IovType::Header, &tok[..header_len])?;
    write_iov_data(iov, &tok[header_len..header_len + n])?;
    if let Some(p) = iov.iter_mut().find(|b| b.kind == IovType::Padding) {
        p.data.clear();
    }
    write_iov_one(iov, IovType::Trailer, &tok[header_len + n..])
}

fn iov_hmac_input(
    iov: &[IovBuf<'_>],
    rfc8009: bool,
    conf: &[u8],
    cipher: &[u8],
    tok_hdr: &[u8; 16],
    data_plain: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    if rfc8009 {
        let mut m = vec![0u8; 16];
        m.extend_from_slice(cipher.get(..AES_CONFOUNDER).ok_or(Error::Truncated)?);
        let mut off = AES_CONFOUNDER;
        for b in iov {
            match b.kind {
                IovType::Data => {
                    let n = b.data.len();
                    m.extend_from_slice(cipher.get(off..off + n).ok_or(Error::Truncated)?);
                    off += n;
                }
                IovType::SignOnly => m.extend_from_slice(b.data),
                _ => {}
            }
        }
        m.extend_from_slice(cipher.get(off..off + 16).ok_or(Error::Truncated)?);
        return Ok(m);
    }
    let mut m = conf.to_vec();
    let mut poff = 0usize;
    for b in iov {
        match b.kind {
            IovType::Data => {
                if let Some(p) = data_plain {
                    let n = b.data.len();
                    m.extend_from_slice(p.get(poff..poff + n).ok_or(Error::Truncated)?);
                    poff += n;
                } else {
                    m.extend_from_slice(b.data);
                }
            }
            IovType::SignOnly => m.extend_from_slice(b.data),
            _ => {}
        }
    }
    m.extend_from_slice(tok_hdr);
    Ok(m)
}

impl GssContext {
    /// CFX wrap_iov (AES / RFC 8009). `conf` encrypts DATA; `SIGN_ONLY` is MAC-only.
    ///
    /// Layout: HEADER (32) | DATA | PADDING (empty) | TRAILER (E(header)+HMAC), RRC=0.
    ///
    /// # Errors
    ///
    /// Non-AES etype, missing HEADER/DATA/TRAILER, or crypto failures.
    pub fn wrap_iov(&mut self, conf: bool, iov: &mut [IovBuf<'_>]) -> Result<(), Error> {
        if conf {
            self.wrap_iov_sealed(iov)
        } else {
            self.wrap_iov_integ(iov)
        }
    }

    /// Inverse of [`Self::wrap_iov`]. DATA is replaced with plaintext.
    ///
    /// # Errors
    ///
    /// Truncated buffers, integrity, sequence, or non-AES etype.
    pub fn unwrap_iov(&mut self, iov: &mut [IovBuf<'_>]) -> Result<(), Error> {
        let sealed = iov
            .iter()
            .find(|b| b.kind == IovType::Header)
            .and_then(|b| b.data.get(2).copied())
            .ok_or(Error::Truncated)?
            & FLAG_SEALED
            != 0;
        if sealed {
            self.unwrap_iov_sealed(iov)
        } else {
            self.unwrap_iov_integ(iov)
        }
    }

    /// HEADER / PADDING / TRAILER sizes for AES wrap_iov (`conf` = confidentiality).
    ///
    /// # Errors
    ///
    /// Non-AES etype.
    pub fn wrap_iov_length(&self, conf: bool) -> Result<(usize, usize, usize), Error> {
        let (key, _) = self.send_key();
        require_aes(key.etype())?;
        let h = key.etype().hmac_output_len();
        if conf {
            Ok((16 + AES_CONFOUNDER, 0, 16 + h))
        } else {
            Ok((16, 0, h))
        }
    }

    fn wrap_iov_sealed(&mut self, iov: &mut [IovBuf<'_>]) -> Result<(), Error> {
        let (key, extra) = self.send_key();
        let key = key.clone();
        require_aes(key.etype())?;
        let hmac_len = key.etype().hmac_output_len();
        let usage = seal_usage(self.initiator);
        let mut tok_hdr = wrap_header(self.initiator, true, self.send_seq);
        tok_hdr[2] |= extra;
        let has_ad = iov
            .iter()
            .any(|b| b.kind == IovType::SignOnly && !b.data.is_empty());
        if !has_ad {
            let n = iov_data_len(iov)?;
            let mut plain = Vec::with_capacity(n);
            iov_copy_data(iov, &mut plain)?;
            let tok = self.wrap(&plain)?;
            let trailer_len = 16 + hmac_len;
            if tok.len() != 16 + AES_CONFOUNDER + n + trailer_len {
                return Err(Error::Truncated);
            }
            return split_wrap_token(iov, &tok, n, trailer_len);
        }
        let n = iov_data_len(iov)?;
        let mut plain = Vec::with_capacity(n);
        iov_copy_data(iov, &mut plain)?;
        let mut conf = [0u8; AES_CONFOUNDER];
        getrandom::getrandom(&mut conf).map_err(|e| Error::Inner(e.to_string()))?;
        let mut to_enc = plain.clone();
        to_enc.extend_from_slice(&tok_hdr);
        let mut cipher = encrypt_with_confounder(&key, usage, &conf, &to_enc)?;
        let c_len = cipher.len().checked_sub(hmac_len).ok_or(Error::Truncated)?;
        let hmac_in = iov_hmac_input(
            iov,
            key.etype().is_rfc8009(),
            &conf,
            &cipher[..c_len],
            &tok_hdr,
            None,
        )?;
        let mac = integrity_mac(&key, usage, &hmac_in)?;
        if mac.len() != hmac_len {
            return Err(Error::Truncated);
        }
        cipher.truncate(c_len);
        cipher.extend_from_slice(&mac);
        self.send_seq = self.send_seq.wrapping_add(1);
        let trailer_len = 16 + hmac_len;
        let mut tok = tok_hdr.to_vec();
        tok.extend_from_slice(&cipher);
        split_wrap_token(iov, &tok, n, trailer_len)
    }

    fn wrap_iov_integ(&mut self, iov: &mut [IovBuf<'_>]) -> Result<(), Error> {
        let (key, extra) = self.send_key();
        let key = key.clone();
        require_aes(key.etype())?;
        let usage = seal_usage(self.initiator);
        let mut header = wrap_header(self.initiator, false, self.send_seq);
        header[2] |= extra;
        let mut to_ck = Vec::new();
        iov_sign_body(iov, &mut to_ck);
        to_ck.extend_from_slice(&header);
        let mac = checksum(&key, usage, &to_ck)?;
        let ec = u16::try_from(mac.len()).map_err(|_| Error::Truncated)?;
        header[4..6].copy_from_slice(&ec.to_be_bytes());
        self.send_seq = self.send_seq.wrapping_add(1);
        write_iov_one(iov, IovType::Header, &header)?;
        write_iov_one(iov, IovType::Trailer, &mac)?;
        if let Some(p) = iov.iter_mut().find(|b| b.kind == IovType::Padding) {
            p.data.clear();
        }
        Ok(())
    }

    fn unwrap_iov_sealed(&mut self, iov: &mut [IovBuf<'_>]) -> Result<(), Error> {
        let has_ad = iov
            .iter()
            .any(|b| b.kind == IovType::SignOnly && !b.data.is_empty());
        if !has_ad {
            let flags = {
                let hdr = iov_find(iov, IovType::Header)?;
                *hdr.get(2).ok_or(Error::Truncated)?
            };
            require_aes(self.recv_key(flags)?.etype())?;
            let tok = join_wrap_token(iov)?;
            let plain = self.unwrap(&tok)?;
            write_iov_data(iov, &plain)?;
            return Ok(());
        }
        let header = iov_find(iov, IovType::Header)?.to_vec();
        if header.len() != 16 + AES_CONFOUNDER {
            return Err(Error::Truncated);
        }
        let mut tok_hdr = [0u8; 16];
        tok_hdr.copy_from_slice(&header[..16]);
        if tok_hdr[..2] != TOK_WRAP || tok_hdr[2] & FLAG_SEALED == 0 || tok_hdr[3] != 0xFF {
            return Err(Error::Truncated);
        }
        check_direction(tok_hdr[2], self.initiator)?;
        let rrc = u16::from_be_bytes(tok_hdr[6..8].try_into().map_err(|_| Error::Truncated)?);
        if rrc != 0 {
            return Err(Error::Truncated);
        }
        let ec = usize::from(u16::from_be_bytes(
            tok_hdr[4..6].try_into().map_err(|_| Error::Truncated)?,
        ));
        let key = self.recv_key(tok_hdr[2])?.clone();
        require_aes(key.etype())?;
        let hmac_len = key.etype().hmac_output_len();
        let trailer = iov_find(iov, IovType::Trailer)?.to_vec();
        if trailer.len() != 16 + hmac_len {
            return Err(Error::Truncated);
        }
        let n = iov_data_len(iov)?;
        let mut c = Vec::with_capacity(AES_CONFOUNDER + n + 16);
        c.extend_from_slice(&header[16..]);
        iov_copy_data(iov, &mut c)?;
        c.extend_from_slice(&trailer[..16]);
        let mac = &trailer[16..];
        let usage = seal_usage(!self.initiator);
        let rfc8009 = key.etype().is_rfc8009();
        let (conf, plain) = if rfc8009 {
            let hmac_in = iov_hmac_input(iov, true, &[], &c, &tok_hdr, None)?;
            let expect = integrity_mac(&key, usage, &hmac_in)?;
            if !mac_eq(mac, &expect) {
                return Err(Error::Integrity);
            }
            decrypt_cts(&key, usage, &c)?
        } else {
            decrypt_cts(&key, usage, &c)?
        };
        if plain.len() < 16 {
            return Err(Error::Truncated);
        }
        let seq = u64::from_be_bytes(tok_hdr[8..16].try_into().map_err(|_| Error::Truncated)?);
        if !verify_enc_header(&plain, tok_hdr[2], ec, seq) {
            return Err(Error::Truncated);
        }
        let (msg, _) = plain.split_at(plain.len() - 16);
        if !rfc8009 {
            let hmac_in = iov_hmac_input(iov, false, &conf, &[], &tok_hdr, Some(msg))?;
            let expect = integrity_mac(&key, usage, &hmac_in)?;
            if !mac_eq(mac, &expect) {
                return Err(Error::Integrity);
            }
        }
        self.accept_seq(seq)?;
        write_iov_data(iov, msg)
    }

    fn unwrap_iov_integ(&mut self, iov: &mut [IovBuf<'_>]) -> Result<(), Error> {
        let flags = iov
            .iter()
            .find(|b| b.kind == IovType::Header)
            .and_then(|b| b.data.get(2).copied())
            .ok_or(Error::Truncated)?;
        require_aes(self.recv_key(flags)?.etype())?;
        let tok = join_wrap_token(iov)?;
        let plain = self.unwrap(&tok)?;
        write_iov_data(iov, &plain)
    }
}
