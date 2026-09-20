//! MIC tokens (`verify_mic.c`, `k5seal.c`).

use krb5_crypto::{checksum, verify_checksum_type};

use super::oid::message_token;
use super::wrap::{
    FLAG_SENT_BY_ACCEPTOR, check_direction, map_gss_cksum, rfc4121_ckhdr, sign_usage,
};
use super::{Error, GssContext};

const TOK_MIC: [u8; 2] = [0x04, 0x04];

fn mic_header(initiator: bool, seq: u64) -> [u8; 16] {
    let mut h = [0xff; 16];
    h[0] = TOK_MIC[0];
    h[1] = TOK_MIC[1];
    h[2] = if initiator { 0 } else { FLAG_SENT_BY_ACCEPTOR };
    h[8..16].copy_from_slice(&seq.to_be_bytes());
    h
}

impl GssContext {
    /// MIC (integrity only). RFC 4121 §4.2.6.1 token.
    ///
    /// # Errors
    ///
    /// Crypto failures.
    pub fn get_mic(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let usage = sign_usage(self.initiator);
        let header = mic_header(self.initiator, self.send_seq);
        let mut buf = data.to_vec();
        buf.extend_from_slice(&header);
        let mic = checksum(&self.session, usage, &buf)?;
        self.send_seq = self.send_seq.wrapping_add(1);
        let mut tok = header.to_vec();
        tok.extend_from_slice(&mic);
        Ok(tok)
    }

    /// Verify a MIC. Sequence numbers are checked.
    ///
    /// # Errors
    ///
    /// Integrity failure or sequence mismatch.
    pub fn verify_mic(&mut self, data: &[u8], token: &[u8]) -> Result<(), Error> {
        let owned = message_token(token)?;
        let inner = owned.as_slice();
        if inner.len() < 16 || inner[..2] != TOK_MIC {
            return Err(Error::Truncated);
        }
        let seq = u64::from_be_bytes(inner[8..16].try_into().map_err(|_| Error::Truncated)?);
        if inner[3] != 0xFF || inner[4..8] != [0xFF; 4] {
            return Err(Error::Truncated);
        }
        check_direction(inner[2], self.initiator)?;
        let usage = sign_usage(!self.initiator);
        let key = self.recv_key(inner[2])?;
        let ctype = key.etype().checksum_type();
        let ckhdr = rfc4121_ckhdr(TOK_MIC, inner[2], seq, true);
        let mut buf = data.to_vec();
        buf.extend_from_slice(&ckhdr);
        verify_checksum_type(key, usage, &buf, ctype, &inner[16..])
            .map_err(|e| map_gss_cksum(&e))?;
        self.accept_seq(seq)?;
        Ok(())
    }
}
