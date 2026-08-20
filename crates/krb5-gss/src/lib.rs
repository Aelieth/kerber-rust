//! GSS-API Kerberos V5 mechanism (RFC 4121) and SPNEGO (RFC 4178).
//!
//! Interop with MIT `libgssapi_krb5` is out-of-process only. This crate
//! never links C libraries.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use krb5_asn1::encode;
use krb5_crypto::{checksum, decrypt, encrypt, verify_checksum, KeyUsage, ProtocolKey};
use krb5_protocol::{build_ap_rep, build_ap_req_opts, verify_ap_req, ReplayCache};
use krb5_types::{ku, ApOptions, PrincipalName, Realm, Ticket};
use thiserror::Error;

/// ISO OID 1.2.840.113554.1.2.2 (Kerberos V5 GSS).
pub const KRB5_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
/// SPNEGO OID 1.3.6.1.5.5.2.
pub const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

const TOK_MIC: [u8; 2] = [0x04, 0x04];
const TOK_WRAP: [u8; 2] = [0x05, 0x04];
const TOK_AP_REQ: [u8; 2] = [0x01, 0x00];
const TOK_AP_REP: [u8; 2] = [0x02, 0x00];

/// GSS-API error.
#[derive(Debug, Error)]
pub enum Error {
    /// Protocol / crypto.
    #[error("{0}")]
    Inner(String),
    /// Integrity.
    #[error("gss integrity")]
    Integrity,
    /// Token too short.
    #[error("gss truncated")]
    Truncated,
}

impl From<krb5_protocol::Error> for Error {
    fn from(e: krb5_protocol::Error) -> Self {
        Self::Inner(e.to_string())
    }
}

impl From<krb5_crypto::Error> for Error {
    fn from(e: krb5_crypto::Error) -> Self {
        Self::Inner(e.to_string())
    }
}

impl From<krb5_asn1::Error> for Error {
    fn from(e: krb5_asn1::Error) -> Self {
        Self::Inner(e.to_string())
    }
}

/// Established GSS context (initiator or acceptor).
pub struct GssContext {
    session: ProtocolKey,
    seq: u64,
    initiator: bool,
    replay: ReplayCache,
}

impl GssContext {
    /// Initiator: wrap a service ticket as a GSS initial token (AP-REQ).
    ///
    /// # Errors
    ///
    /// Crypto / DER failures.
    pub fn init_sec_context(
        ticket: Ticket,
        session: ProtocolKey,
        crealm: &Realm,
        cname: &PrincipalName,
        mutual: bool,
    ) -> Result<(Self, Vec<u8>), Error> {
        let opts = if mutual {
            ApOptions::mutual_required()
        } else {
            ApOptions::none()
        };
        let ap = build_ap_req_opts(ticket, &session, crealm, cname, opts, None)?;
        let der = encode(&ap)?;
        let token = gss_wrap_app(TOK_AP_REQ, &der);
        Ok((
            Self {
                session,
                seq: 0,
                initiator: true,
                replay: ReplayCache::new(),
            },
            token,
        ))
    }

    /// Acceptor: verify the initial token with the service key.
    ///
    /// # Errors
    ///
    /// AP-REQ verify failures.
    pub fn accept_sec_context(
        token: &[u8],
        service_key: &ProtocolKey,
    ) -> Result<(Self, Option<Vec<u8>>), Error> {
        let inner = gss_unwrap_app(token)?;
        if inner.len() < 2 || inner[..2] != TOK_AP_REQ {
            return Err(Error::Truncated);
        }
        let ctx = Self {
            session: service_key.clone(),
            seq: 0,
            initiator: false,
            replay: ReplayCache::new(),
        };
        let ok = verify_ap_req(&inner[2..], service_key, &ctx.replay)?;
        let sess = ProtocolKey::from_bytes(
            krb5_crypto::EncryptionType::from_iana(ok.ticket_part.key.keytype)
                .or_else(|_| krb5_crypto::EncryptionType::known(ok.ticket_part.key.keytype))?,
            ok.ticket_part.key.keyvalue.as_ref(),
        )?;
        let mut out = Self {
            session: sess,
            seq: 0,
            initiator: false,
            replay: ctx.replay,
        };
        let mut ap_rep_tok = None;
        if ok.mutual_required {
            let ap_rep = build_ap_rep(&out.session, &ok.authenticator, None, Some(0))?;
            let der = encode(&ap_rep)?;
            ap_rep_tok = Some(gss_wrap_app(TOK_AP_REP, &der));
            out.seq = 1;
        }
        Ok((out, ap_rep_tok))
    }

    /// Per-message wrap (confidentiality).
    ///
    /// # Errors
    ///
    /// Crypto failures.
    pub fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let usage = seal_usage(self.initiator);
        let header = wrap_header(self.seq);
        let mut buf = header.to_vec();
        buf.extend_from_slice(plaintext);
        let cipher = encrypt(&self.session, usage, &buf)?;
        self.seq = self.seq.wrapping_add(1);
        let mut tok = TOK_WRAP.to_vec();
        tok.extend_from_slice(&header);
        tok.extend_from_slice(&cipher);
        Ok(gss_wrap_app(TOK_WRAP, &tok[2..]))
    }

    /// Unwrap a wrap token.
    ///
    /// # Errors
    ///
    /// Integrity or truncated tokens.
    pub fn unwrap(&mut self, token: &[u8]) -> Result<Vec<u8>, Error> {
        let inner = gss_unwrap_app(token)?;
        if inner.len() < 2 + 8 || inner[..2] != TOK_WRAP {
            return Err(Error::Truncated);
        }
        let usage = seal_usage(!self.initiator);
        let plain = decrypt(&self.session, usage, &inner[2 + 8..])?;
        if plain.len() < 8 {
            return Err(Error::Truncated);
        }
        Ok(plain[8..].to_vec())
    }

    /// MIC (integrity only).
    ///
    /// # Errors
    ///
    /// Crypto failures.
    pub fn get_mic(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let usage = sign_usage(self.initiator);
        let header = wrap_header(self.seq);
        let mut buf = header.to_vec();
        buf.extend_from_slice(data);
        let mic = checksum(&self.session, usage, &buf)?;
        self.seq = self.seq.wrapping_add(1);
        let mut inner = TOK_MIC.to_vec();
        inner.extend_from_slice(&header);
        inner.extend_from_slice(&mic);
        Ok(gss_wrap_app(TOK_MIC, &inner[2..]))
    }

    /// Verify a MIC.
    ///
    /// # Errors
    ///
    /// Integrity failure.
    pub fn verify_mic(&self, data: &[u8], token: &[u8]) -> Result<(), Error> {
        let inner = gss_unwrap_app(token)?;
        if inner.len() < 2 + 8 || inner[..2] != TOK_MIC {
            return Err(Error::Truncated);
        }
        let usage = sign_usage(!self.initiator);
        let mut buf = inner[2..10].to_vec();
        buf.extend_from_slice(data);
        verify_checksum(&self.session, usage, &buf, &inner[10..]).map_err(|_| Error::Integrity)
    }
}

fn seal_usage(initiator: bool) -> KeyUsage {
    KeyUsage::new(if initiator {
        ku::GSS_INITIATOR_SEAL
    } else {
        ku::GSS_ACCEPTOR_SEAL
    })
    .expect("usage")
}

fn sign_usage(initiator: bool) -> KeyUsage {
    KeyUsage::new(if initiator {
        ku::GSS_INITIATOR_SIGN
    } else {
        ku::GSS_ACCEPTOR_SIGN
    })
    .expect("usage")
}

fn wrap_header(seq: u64) -> [u8; 8] {
    seq.to_be_bytes()
}

fn gss_wrap_app(tok_id: [u8; 2], inner: &[u8]) -> Vec<u8> {
    // APPLICATION 0 + OID + tok-id + inner (simplified RFC 2743 framing).
    let mut body = Vec::new();
    body.push(0x06);
    body.push(u8::try_from(KRB5_OID.len()).unwrap_or(0));
    body.extend_from_slice(KRB5_OID);
    body.extend_from_slice(&tok_id);
    body.extend_from_slice(inner);
    let mut out = vec![0x60];
    der_len(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

fn gss_unwrap_app(token: &[u8]) -> Result<Vec<u8>, Error> {
    if token.len() < 2 || token[0] != 0x60 {
        return Err(Error::Truncated);
    }
    let (hlen, blen) = der_len_decode(&token[1..])?;
    let start = 1 + hlen;
    if start + blen > token.len() {
        return Err(Error::Truncated);
    }
    let body = &token[start..start + blen];
    if body.len() < 2 + KRB5_OID.len() + 2 || body[0] != 0x06 {
        return Err(Error::Truncated);
    }
    let oid_len = usize::from(body[1]);
    let rest = &body[2 + oid_len..];
    Ok(rest.to_vec())
}

fn der_len(out: &mut Vec<u8>, n: usize) {
    if let Ok(b) = u8::try_from(n) {
        if b < 128 {
            out.push(b);
        } else {
            out.push(0x81);
            out.push(b);
        }
        return;
    }
    out.push(0x82);
    out.extend_from_slice(&(u16::try_from(n).unwrap_or(u16::MAX)).to_be_bytes());
}

fn der_len_decode(b: &[u8]) -> Result<(usize, usize), Error> {
    if b.is_empty() {
        return Err(Error::Truncated);
    }
    if b[0] < 128 {
        return Ok((1, usize::from(b[0])));
    }
    if b[0] == 0x81 && b.len() >= 2 {
        return Ok((2, usize::from(b[1])));
    }
    if b[0] == 0x82 && b.len() >= 3 {
        return Ok((3, usize::from(u16::from_be_bytes([b[1], b[2]]))));
    }
    Err(Error::Truncated)
}

/// SPNEGO NegTokenInit wrapping a Kerberos inner token.
#[must_use]
pub fn spnego_init(krb_token: &[u8]) -> Vec<u8> {
    let mut v = vec![0x60, 0x00];
    v.push(0x06);
    v.push(u8::try_from(SPNEGO_OID.len()).unwrap_or(0));
    v.extend_from_slice(SPNEGO_OID);
    v.extend_from_slice(krb_token);
    let n = v.len() - 2;
    v[1] = u8::try_from(n).unwrap_or(0x80);
    v
}

/// Extract the inner Kerberos token from a SPNEGO blob (best-effort).
///
/// # Errors
///
/// Truncated input.
pub fn spnego_inner(token: &[u8]) -> Result<&[u8], Error> {
    if token.len() < 4 || token[0] != 0x60 {
        return Err(Error::Truncated);
    }
    let oid_len = usize::from(token.get(3).copied().unwrap_or(0));
    let start = 4 + oid_len;
    if start > token.len() {
        return Err(Error::Truncated);
    }
    Ok(&token[start..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_crypto::{string_to_key, EncryptionType};
    use krb5_kdc::{
        as_req, bootstrap_documented, documented_host, pa_enc_timestamp, tgs_req, S2K_ITERS,
        TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    };
    use krb5_types::ascii;

    #[test]
    fn wrap_unwrap_mic_round_trip() {
        let (store, _) = bootstrap_documented().unwrap();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let key = string_to_key(
            EncryptionType::Aes256CtsHmacSha196,
            TEST_USER_PASSWORD,
            cname.default_salt(TEST_REALM),
            Some(&S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = as_req(
            cname.clone(),
            TEST_REALM,
            1,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        );
        let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &cname,
            documented_host(),
            TEST_REALM,
            2,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let (mut init, token) = GssContext::init_sec_context(
            tgs_out.rep.0.ticket.clone(),
            tgs_out.session_key.clone(),
            &ascii(TEST_REALM),
            &cname,
            false,
        )
        .unwrap();
        let host = store.get_name(&documented_host()).unwrap();
        let skey = &host.best_key().unwrap().key;
        let (mut acc, _) = GssContext::accept_sec_context(&token, skey).unwrap();
        let wrapped = init.wrap(b"hello gss").unwrap();
        let plain = acc.unwrap(&wrapped).unwrap();
        assert_eq!(plain, b"hello gss");
        let mic = init.get_mic(b"hello gss").unwrap();
        acc.verify_mic(b"hello gss", &mic).unwrap();
    }
}
