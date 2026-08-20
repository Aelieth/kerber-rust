//! AD-WIN2K-PAC parse, verify, and sign (MS-PAC).

use subtle::ConstantTimeEq;

/// PAC buffer type: logon info.
pub const PAC_LOGON_INFO: u32 = 1;
/// PAC buffer type: server checksum.
pub const PAC_SERVER_CHECKSUM: u32 = 6;
/// PAC buffer type: KDC / privilege-server checksum.
pub const PAC_PRIVSVR_CHECKSUM: u32 = 7;
/// PAC buffer type: client name and ticket info.
pub const PAC_CLIENT_INFO: u32 = 10;
/// PAC buffer type: UPN/DNS info.
pub const PAC_UPN_DNS_INFO: u32 = 16;
/// PAC buffer type: client claims.
pub const PAC_CLIENT_CLAIMS: u32 = 19;
/// PAC buffer type: device info.
pub const PAC_DEVICE_INFO: u32 = 20;

/// Signature type HMAC-MD5 (RC4).
pub const CKSUM_HMAC_MD5: i32 = 0xFFFFFF76_u32 as i32;
/// Signature type HMAC-SHA1-96-AES128.
pub const CKSUM_HMAC_SHA1_96_AES128: i32 = 15;
/// Signature type HMAC-SHA1-96-AES256.
pub const CKSUM_HMAC_SHA1_96_AES256: i32 = 16;

/// One PAC info buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacBuffer {
    /// Buffer type (`PAC_*`).
    pub kind: u32,
    /// Buffer payload (not including the header).
    pub data: Vec<u8>,
}

/// Parsed PAC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pac {
    /// Version (usually 0).
    pub version: u32,
    /// Buffers in file order.
    pub buffers: Vec<PacBuffer>,
}

/// PAC parse / verify failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PacError {
    /// Truncated or internally inconsistent PAC.
    Truncated,
    /// Checksum mismatch.
    Integrity,
    /// Required buffer missing.
    MissingBuffer,
}

impl std::fmt::Display for PacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "PAC truncated"),
            Self::Integrity => write!(f, "PAC integrity check failed"),
            Self::MissingBuffer => write!(f, "PAC missing required buffer"),
        }
    }
}

impl std::error::Error for PacError {}

impl Pac {
    /// Parse a PACTYPE blob.
    ///
    /// # Errors
    ///
    /// Returns [`PacError::Truncated`] when headers or offsets are invalid.
    pub fn parse(bytes: &[u8]) -> Result<Self, PacError> {
        if bytes.len() < 8 {
            return Err(PacError::Truncated);
        }
        let c_buffers =
            u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| PacError::Truncated)?);
        let version = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| PacError::Truncated)?);
        let mut buffers = Vec::new();
        let mut off = 8usize;
        for _ in 0..c_buffers {
            if off + 16 > bytes.len() {
                return Err(PacError::Truncated);
            }
            let kind = u32::from_le_bytes(
                bytes[off..off + 4]
                    .try_into()
                    .map_err(|_| PacError::Truncated)?,
            );
            let size = u32::from_le_bytes(
                bytes[off + 4..off + 8]
                    .try_into()
                    .map_err(|_| PacError::Truncated)?,
            ) as usize;
            let offset = u64::from_le_bytes(
                bytes[off + 8..off + 16]
                    .try_into()
                    .map_err(|_| PacError::Truncated)?,
            ) as usize;
            off += 16;
            if offset
                .checked_add(size)
                .map(|e| e > bytes.len())
                .unwrap_or(true)
            {
                return Err(PacError::Truncated);
            }
            buffers.push(PacBuffer {
                kind,
                data: bytes[offset..offset + size].to_vec(),
            });
        }
        Ok(Self { version, buffers })
    }

    /// Serialize as PACTYPE (little-endian).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = u32::try_from(self.buffers.len()).unwrap_or(u32::MAX);
        let header_len = 8 + 16 * self.buffers.len();
        let mut payload_off = header_len;
        let mut payloads = Vec::new();
        let mut headers = Vec::new();
        for b in &self.buffers {
            let size = u32::try_from(b.data.len()).unwrap_or(0);
            headers.extend_from_slice(&b.kind.to_le_bytes());
            headers.extend_from_slice(&size.to_le_bytes());
            headers.extend_from_slice(&(payload_off as u64).to_le_bytes());
            payloads.extend_from_slice(&b.data);
            let pad = (8 - (b.data.len() % 8)) % 8;
            payloads.extend(vec![0u8; pad]);
            payload_off += b.data.len() + pad;
        }
        let mut out = Vec::with_capacity(header_len + payloads.len());
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&headers);
        out.extend_from_slice(&payloads);
        out
    }

    /// Zero the signature fields in server and KDC checksum buffers, then
    /// return the bytes used as HMAC input (the whole PAC with zeroed
    /// signatures).
    #[must_use]
    pub fn bytes_for_checksum(&self) -> Vec<u8> {
        let mut clone = self.clone();
        for b in &mut clone.buffers {
            if b.kind == PAC_SERVER_CHECKSUM || b.kind == PAC_PRIVSVR_CHECKSUM {
                zero_signature_payload(&mut b.data);
            }
        }
        clone.to_bytes()
    }

    /// Server checksum buffer payload, if present.
    #[must_use]
    pub fn server_checksum(&self) -> Option<&[u8]> {
        self.buffers
            .iter()
            .find(|b| b.kind == PAC_SERVER_CHECKSUM)
            .map(|b| b.data.as_slice())
    }

    /// KDC checksum buffer payload, if present.
    #[must_use]
    pub fn kdc_checksum(&self) -> Option<&[u8]> {
        self.buffers
            .iter()
            .find(|b| b.kind == PAC_PRIVSVR_CHECKSUM)
            .map(|b| b.data.as_slice())
    }
}

fn zero_signature_payload(data: &mut [u8]) {
    // SignatureType (4) + Signature (remainder). Zero the signature bytes.
    if data.len() > 4 {
        for b in &mut data[4..] {
            *b = 0;
        }
    }
}

/// Verify the server checksum (HMAC-SHA1 over the PAC with signatures zeroed).
///
/// The `mac` function is the keyed checksum of the service (typically
/// `krb5_crypto::checksum` with the service ticket session or long-term key).
///
/// # Errors
///
/// Returns [`PacError::Integrity`] on mismatch, [`PacError::MissingBuffer`]
/// when the server checksum is absent.
pub fn verify_server_checksum(pac: &Pac, expected: &[u8]) -> Result<(), PacError> {
    let Some(got) = pac.server_checksum() else {
        return Err(PacError::MissingBuffer);
    };
    if got.len() < 4 + expected.len() {
        return Err(PacError::Integrity);
    }
    let sig = &got[4..4 + expected.len()];
    if !bool::from(sig.ct_eq(expected)) {
        return Err(PacError::Integrity);
    }
    Ok(())
}

/// Build a signature buffer: little-endian type + MAC bytes.
#[must_use]
pub fn signature_buffer(cksumtype: i32, mac: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + mac.len());
    v.extend_from_slice(&cksumtype.to_le_bytes());
    v.extend_from_slice(mac);
    v
}

/// Client-info PAC buffer: little-endian NT time + UTF-16LE name.
#[must_use]
pub fn client_info_buffer(authtime_unix: u32, name: &str) -> Vec<u8> {
    // NT time = unix * 10_000_000 + 116444736000000000
    let nt = u64::from(authtime_unix)
        .saturating_mul(10_000_000)
        .saturating_add(116_444_736_000_000_000);
    let utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut v = Vec::with_capacity(10 + utf16.len());
    v.extend_from_slice(&nt.to_le_bytes());
    let n = u16::try_from(utf16.len()).unwrap_or(u16::MAX);
    v.extend_from_slice(&n.to_le_bytes());
    v.extend_from_slice(&utf16[..usize::from(n)]);
    v
}

/// Minimal logon-info placeholder: UTF-8 client principal + realm.
#[must_use]
pub fn logon_info_buffer(client: &str, realm: &str) -> Vec<u8> {
    let mut v = Vec::new();
    let c = client.as_bytes();
    let r = realm.as_bytes();
    v.extend_from_slice(&(c.len() as u32).to_le_bytes());
    v.extend_from_slice(c);
    v.extend_from_slice(&(r.len() as u32).to_le_bytes());
    v.extend_from_slice(r);
    v
}

/// Parse the placeholder logon-info written by [`logon_info_buffer`].
///
/// # Errors
///
/// Returns [`PacError::Truncated`] when the buffer is too short.
pub fn parse_logon_info(data: &[u8]) -> Result<(String, String), PacError> {
    if data.len() < 4 {
        return Err(PacError::Truncated);
    }
    let n = u32::from_le_bytes(data[0..4].try_into().map_err(|_| PacError::Truncated)?) as usize;
    if 4 + n + 4 > data.len() {
        return Err(PacError::Truncated);
    }
    let client = std::str::from_utf8(&data[4..4 + n]).map_err(|_| PacError::Truncated)?;
    let rest = &data[4 + n..];
    let m = u32::from_le_bytes(rest[0..4].try_into().map_err(|_| PacError::Truncated)?) as usize;
    if 4 + m > rest.len() {
        return Err(PacError::Truncated);
    }
    let realm = std::str::from_utf8(&rest[4..4 + m]).map_err(|_| PacError::Truncated)?;
    Ok((client.to_owned(), realm.to_owned()))
}
