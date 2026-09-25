//! Per-message wrap (`k5seal.c`, `k5sealv3.c`, `unwrap.c`,
//! `util_crypt.c`): RFC 4121 CFX wrap/unwrap, RRC, and EC.

use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, checksum_output_size, decrypt, encrypt,
    verify_checksum_type,
};
use krb5_types::ku;

use super::context::FLAG_ACCEPTOR_SUBKEY;
use super::oid::message_token;
use super::{Error, GssContext};

pub(super) const TOK_WRAP: [u8; 2] = [0x05, 0x04];

pub(super) const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;

pub(super) const FLAG_SEALED: u8 = 0x02;

pub(super) const AES_CONFOUNDER: usize = 16;

pub(super) fn require_aes(et: EncryptionType) -> Result<(), Error> {
    if et.is_aes() {
        Ok(())
    } else {
        Err(Error::Inner("gss wrap_iov aes".into()))
    }
}

pub(super) fn mac_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(super) fn seal_usage(initiator: bool) -> KeyUsage {
    KeyUsage::from_rfc(if initiator {
        ku::GSS_INITIATOR_SEAL
    } else {
        ku::GSS_ACCEPTOR_SEAL
    })
}

pub(super) fn sign_usage(initiator: bool) -> KeyUsage {
    KeyUsage::from_rfc(if initiator {
        ku::GSS_INITIATOR_SIGN
    } else {
        ku::GSS_ACCEPTOR_SIGN
    })
}

fn rotate_rrc(cipher: &[u8], rrc: u16) -> Vec<u8> {
    if cipher.is_empty() {
        return cipher.to_vec();
    }
    let n = usize::from(rrc) % cipher.len();
    if n == 0 {
        return cipher.to_vec();
    }
    let split = cipher.len() - n;
    let mut out = Vec::with_capacity(cipher.len());
    out.extend_from_slice(&cipher[split..]);
    out.extend_from_slice(&cipher[..split]);
    out
}

fn apply_send_rrc(tok: &mut [u8], rrc: u16) -> Result<(), Error> {
    if tok.len() < 16 {
        return Err(Error::Truncated);
    }
    tok[6..8].copy_from_slice(&rrc.to_be_bytes());
    let clen = tok.len() - 16;
    if clen == 0 {
        return Ok(());
    }
    let n = usize::from(rrc) % clen;
    if n == 0 {
        return Ok(());
    }
    let cipher = tok[16..].to_vec();
    // Inverse of [`rotate_rrc`]: left-rotate by `rrc` so recv right-rotates back.
    let mut rotated = Vec::with_capacity(cipher.len());
    rotated.extend_from_slice(&cipher[n..]);
    rotated.extend_from_slice(&cipher[..n]);
    tok[16..].copy_from_slice(&rotated);
    Ok(())
}

pub(super) fn map_gss_cksum(e: &krb5_crypto::Error) -> Error {
    match e {
        krb5_crypto::Error::BadChecksumSize => Error::Truncated,
        _ => Error::Integrity,
    }
}

pub(super) fn rfc4121_ckhdr(toktype: [u8; 2], flags: u8, seq: u64, mic: bool) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = toktype[0];
    h[1] = toktype[1];
    h[2] = flags;
    h[3] = 0xFF;
    if mic {
        h[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    }
    h[8..16].copy_from_slice(&seq.to_be_bytes());
    h
}

pub(super) fn check_direction(flags: u8, initiator: bool) -> Result<(), Error> {
    let sender_is_acceptor = flags & FLAG_SENT_BY_ACCEPTOR != 0;
    if sender_is_acceptor == initiator {
        Ok(())
    } else {
        Err(Error::Integrity)
    }
}

pub(super) fn verify_enc_header(plain: &[u8], flags: u8, ec: usize, seq: u64) -> bool {
    if plain.len() < 16 + ec {
        return false;
    }
    let h = &plain[plain.len() - 16..];
    let hdr_ec = u16::from_be_bytes([h[4], h[5]]);
    let Ok(hdr_seq) = h[8..16].try_into().map(u64::from_be_bytes) else {
        return false;
    };
    h[0] == TOK_WRAP[0]
        && h[1] == TOK_WRAP[1]
        && h[2] == flags
        && h[3] == 0xFF
        && usize::from(hdr_ec) == ec
        && hdr_seq == seq
}

pub(super) fn wrap_header(initiator: bool, sealed: bool, seq: u64) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = TOK_WRAP[0];
    h[1] = TOK_WRAP[1];
    let mut flags = 0u8;
    if !initiator {
        flags |= FLAG_SENT_BY_ACCEPTOR;
    }
    if sealed {
        flags |= FLAG_SEALED;
    }
    h[2] = flags;
    h[3] = 0xff;
    h[4] = 0;
    h[5] = 0;
    h[6] = 0;
    h[7] = 0;
    h[8..16].copy_from_slice(&seq.to_be_bytes());
    h
}

/// Build a MIT-shaped wrap token (16-byte RFC 4121 header + `encrypt(plain||header)`).
///
/// Used by tests to prove unwrap accepts the layout MIT `libgssapi_krb5` emits.
///
/// # Errors
///
/// Crypto failures.
pub fn mit_shaped_wrap(
    session: &ProtocolKey,
    initiator: bool,
    seq: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    mit_shaped_wrap_flags(session, initiator, seq, plaintext, 0)
}

pub(super) fn mit_shaped_wrap_flags(
    session: &ProtocolKey,
    initiator: bool,
    seq: u64,
    plaintext: &[u8],
    extra_flags: u8,
) -> Result<Vec<u8>, Error> {
    let usage = seal_usage(initiator);
    let mut header = wrap_header(initiator, true, seq);
    header[2] |= extra_flags;
    let mut to_enc = plaintext.to_vec();
    to_enc.extend_from_slice(&header);
    let cipher = encrypt(session, usage, &to_enc)?;
    let mut tok = header.to_vec();
    tok.extend_from_slice(&cipher);
    Ok(tok)
}

impl GssContext {
    pub(super) fn recv_key(&self, flags: u8) -> Result<&ProtocolKey, Error> {
        if flags & FLAG_ACCEPTOR_SUBKEY != 0 {
            self.acceptor_subkey
                .as_ref()
                .ok_or_else(|| Error::Inner("gss acceptor subkey".into()))
        } else {
            Ok(&self.session)
        }
    }

    pub(super) fn send_key(&self) -> (&ProtocolKey, u8) {
        if let Some(k) = &self.acceptor_subkey {
            (k, FLAG_ACCEPTOR_SUBKEY)
        } else {
            (&self.session, 0)
        }
    }

    /// Per-message wrap (confidentiality). RFC 4121 §4.2.6 token.
    ///
    /// # Errors
    ///
    /// Crypto failures.
    pub fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        // MIT 1.22.2 libgssapi_krb5 wrap tokens use RRC=0 (observed in
        // gss-gate). wrap_with_rrc(16) remains for SSPI in-place decrypt.
        self.wrap_conf_inner(plaintext, 0, 0)
    }

    /// Unwrap a wrap token. Sequence numbers are checked.
    ///
    /// # Errors
    ///
    /// Integrity, truncated tokens, or sequence mismatch.
    pub fn unwrap(&mut self, token: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.unwrap_v3(token)?.0)
    }

    /// Like [`Self::unwrap`] but also returns whether the token was sealed
    /// (`conf_state`, MIT `unwrap.c:363-364`); the RPCSEC_GSS privacy service
    /// rejects an integrity-only body (`authgss_prot.c:238-240`).
    ///
    /// # Errors
    ///
    /// Integrity, truncated tokens, or sequence mismatch.
    pub fn unwrap_conf(&mut self, token: &[u8]) -> Result<(Vec<u8>, bool), Error> {
        self.unwrap_v3(token)
    }

    /// MIT `unwrap_v3` (`unwrap.c:295-304`): a bad token type, a bad filler, or the wrong direction is rejected before the payload is decrypted.
    /// The right-rotation is undone before the checksum or the seal is checked, so a rotated trailer is not left in the plaintext.
    fn unwrap_v3(&mut self, token: &[u8]) -> Result<(Vec<u8>, bool), Error> {
        let owned = message_token(token)?;
        let inner = owned.as_slice();
        if inner.len() < 16 || inner[..2] != TOK_WRAP {
            return Err(Error::Truncated);
        }
        let mut header = [0u8; 16];
        header.copy_from_slice(&inner[..16]);
        let flags = header[2];
        if header[3] != 0xFF {
            return Err(Error::Truncated);
        }
        check_direction(flags, self.initiator)?;
        let ec = usize::from(u16::from_be_bytes(
            header[4..6].try_into().map_err(|_| Error::Truncated)?,
        ));
        let rrc = u16::from_be_bytes(header[6..8].try_into().map_err(|_| Error::Truncated)?);
        let seq = u64::from_be_bytes(header[8..16].try_into().map_err(|_| Error::Truncated)?);
        let payload = rotate_rrc(&inner[16..], rrc);
        let usage = seal_usage(!self.initiator);
        let key = self.recv_key(flags)?;
        let conf = flags & FLAG_SEALED != 0;
        let msg = if flags & FLAG_SEALED == 0 {
            let ctype = key.etype().checksum_type();
            let cksumsize = checksum_output_size(ctype).ok_or(Error::Truncated)?;
            if cksumsize > payload.len() || ec != cksumsize {
                return Err(Error::Truncated);
            }
            let split = payload.len() - cksumsize;
            let data = &payload[..split];
            let mac = &payload[split..];
            let ckhdr = rfc4121_ckhdr(TOK_WRAP, flags, seq, false);
            let mut to_ck = data.to_vec();
            to_ck.extend_from_slice(&ckhdr);
            verify_checksum_type(key, usage, &to_ck, ctype, mac).map_err(|e| map_gss_cksum(&e))?;
            data.to_vec()
        } else {
            let plain = decrypt(key, usage, &payload).map_err(|e| {
                if matches!(e, krb5_crypto::Error::Integrity) {
                    Error::Integrity
                } else {
                    Error::from(e)
                }
            })?;
            if !verify_enc_header(&plain, flags, ec, seq) {
                return Err(Error::Truncated);
            }
            let n = plain.len() - ec - 16;
            plain[..n].to_vec()
        };
        self.accept_seq(seq)?;
        Ok((msg, conf))
    }

    /// Wrap with an explicit RRC (tests pin rotate direction).
    ///
    /// # Errors
    ///
    /// Crypto failures.
    pub fn wrap_with_rrc(&mut self, plaintext: &[u8], rrc: u16) -> Result<Vec<u8>, Error> {
        self.wrap_conf_inner(plaintext, 0, rrc)
    }

    /// Wrap without confidentiality (`gss_seal` conf=0). AUTH_GSSAPI
    /// `signed_isn` / sequence verifiers use this (MIT `auth_gssapi_seal_seq`).
    ///
    /// # Errors
    ///
    /// Crypto failures.
    pub fn wrap_integ(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let usage = seal_usage(self.initiator);
        let mut header = wrap_header(self.initiator, false, self.send_seq);
        let mut to_ck = plaintext.to_vec();
        to_ck.extend_from_slice(&header);
        let mac = checksum(&self.session, usage, &to_ck)?;
        let ec = u16::try_from(mac.len()).map_err(|_| Error::Truncated)?;
        header[4..6].copy_from_slice(&ec.to_be_bytes());
        self.send_seq = self.send_seq.wrapping_add(1);
        let mut tok = header.to_vec();
        tok.extend_from_slice(plaintext);
        tok.extend_from_slice(&mac);
        Ok(tok)
    }

    fn wrap_conf_inner(&mut self, plaintext: &[u8], ec: u16, rrc: u16) -> Result<Vec<u8>, Error> {
        let usage = seal_usage(self.initiator);
        let (key, extra) = self.send_key();
        let mut header = wrap_header(self.initiator, true, self.send_seq);
        header[2] |= extra;
        header[4..6].copy_from_slice(&ec.to_be_bytes());
        let mut to_enc = plaintext.to_vec();
        to_enc.extend(vec![0xFF; usize::from(ec)]);
        to_enc.extend_from_slice(&header);
        let cipher = encrypt(key, usage, &to_enc)?;
        self.send_seq = self.send_seq.wrapping_add(1);
        let mut tok = header.to_vec();
        tok.extend_from_slice(&cipher);
        apply_send_rrc(&mut tok, rrc)?;
        Ok(tok)
    }
}
