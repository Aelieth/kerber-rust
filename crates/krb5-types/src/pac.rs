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

/// Signature type HMAC-MD5 (RC4). RFC 4757 cksumtype -138.
pub const CKSUM_HMAC_MD5: i32 = -138;
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
            let size = usize::try_from(u32::from_le_bytes(
                bytes[off + 4..off + 8]
                    .try_into()
                    .map_err(|_| PacError::Truncated)?,
            ))
            .map_err(|_| PacError::Truncated)?;
            let offset = usize::try_from(u64::from_le_bytes(
                bytes[off + 8..off + 16]
                    .try_into()
                    .map_err(|_| PacError::Truncated)?,
            ))
            .map_err(|_| PacError::Truncated)?;
            off += 16;
            if offset.checked_add(size).is_none_or(|e| e > bytes.len()) {
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

/// NDR32 `KERB_VALIDATION_INFO` (MS-PAC PAC_LOGON_INFO) for `client` / `realm`.
///
/// Layout is NDR32 with a type-serialization v1 header. Strings are
/// UTF-16LE `RPC_UNICODE_STRING`. This is not a full NDR64 / all-optional
/// Windows field set (ExtraSids / resource groups are empty).
#[must_use]
pub fn logon_info_buffer(client: &str, realm: &str) -> Vec<u8> {
    ndr_kerb_validation_info(client, realm, 1104, 513)
}

fn ndr_kerb_validation_info(client: &str, realm: &str, user_rid: u32, primary: u32) -> Vec<u8> {
    let name = utf16le(client);
    let dom = utf16le(realm);
    let mut body = Vec::new();
    for _ in 0..6 {
        body.extend_from_slice(&0u64.to_le_bytes());
    }
    let mut deferred: Vec<Vec<u8>> = Vec::new();
    push_rpc_unicode(&mut body, &mut deferred, &name);
    for _ in 0..5 {
        push_rpc_unicode(&mut body, &mut deferred, &[]);
    }
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&user_rid.to_le_bytes());
    body.extend_from_slice(&primary.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    let groups_id = 0x0002_0000u32 + u32::try_from(deferred.len()).unwrap_or(0) * 4;
    body.extend_from_slice(&groups_id.to_le_bytes());
    deferred.push(ndr_group_membership(primary));
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&[0u8; 16]);
    push_rpc_unicode(&mut body, &mut deferred, &[]);
    push_rpc_unicode(&mut body, &mut deferred, &dom);
    let sid_id = 0x0002_0000u32 + u32::try_from(deferred.len()).unwrap_or(0) * 4;
    body.extend_from_slice(&sid_id.to_le_bytes());
    deferred.push(ndr_sid_s1_5_21());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0x10u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    for s in deferred {
        body.extend_from_slice(&s);
    }

    let mut out = Vec::new();
    out.extend_from_slice(&[1, 0x10, 8, 0]);
    out.extend_from_slice(&0xcccc_ccceu32.to_le_bytes());
    out.extend_from_slice(&(u32::try_from(body.len()).unwrap_or(u32::MAX)).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0x0002_0000u32.to_le_bytes());
    out.extend_from_slice(&body);
    out
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn push_rpc_unicode(body: &mut Vec<u8>, deferred: &mut Vec<Vec<u8>>, utf16: &[u8]) {
    let n = u16::try_from(utf16.len()).unwrap_or(u16::MAX);
    body.extend_from_slice(&n.to_le_bytes());
    body.extend_from_slice(&n.saturating_add(2).to_le_bytes());
    if utf16.is_empty() {
        body.extend_from_slice(&0u32.to_le_bytes());
    } else {
        let id = 0x0002_0000u32 + u32::try_from(deferred.len()).unwrap_or(0) * 4;
        body.extend_from_slice(&id.to_le_bytes());
        let mut blob = Vec::new();
        ndr_conformant_string(&mut blob, utf16);
        deferred.push(blob);
    }
}

fn ndr_group_membership(primary: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&primary.to_le_bytes());
    v.extend_from_slice(&7u32.to_le_bytes());
    v
}

fn ndr_sid_s1_5_21() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&4u32.to_le_bytes());
    v.push(1);
    v.push(4);
    v.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
    v.extend_from_slice(&21u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&3u32.to_le_bytes());
    v
}

fn ndr_conformant_string(out: &mut Vec<u8>, utf16: &[u8]) {
    let chars = u32::try_from(utf16.len() / 2).unwrap_or(0);
    out.extend_from_slice(&chars.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&chars.to_le_bytes());
    out.extend_from_slice(utf16);
    let pad = (4 - (utf16.len() % 4)) % 4;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// Parse [`logon_info_buffer`] (NDR) or the legacy UTF-8 placeholder.
///
/// # Errors
///
/// Returns [`PacError::Truncated`] when the buffer is too short.
pub fn parse_logon_info(data: &[u8]) -> Result<(String, String), PacError> {
    if let Ok(v) = parse_ndr_logon_info(data) {
        return Ok(v);
    }
    parse_legacy_utf8_logon(data)
}

fn parse_legacy_utf8_logon(data: &[u8]) -> Result<(String, String), PacError> {
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

/// Type-serialization v1 header + unique pointer (8 + 8 + 4).
const NDR_TYPE_HEADER: usize = 20;
/// Fixed KERB_VALIDATION_INFO NDR32 size before deferred pointers (see encoder).
const NDR_LOGON_STRUCT: usize = 216;

fn parse_ndr_logon_info(data: &[u8]) -> Result<(String, String), PacError> {
    if data.len() < NDR_TYPE_HEADER + NDR_LOGON_STRUCT || data[0] != 1 || data[1] != 0x10 {
        return Err(PacError::Truncated);
    }
    let body = &data[NDR_TYPE_HEADER..];
    let user_rid = u32::from_le_bytes(body[100..104].try_into().map_err(|_| PacError::Truncated)?);
    if user_rid == 0 {
        return Err(PacError::Truncated);
    }
    let mut tail = &body[NDR_LOGON_STRUCT..];
    let (client, rest) = take_conformant_string(tail)?;
    tail = rest;
    if tail.len() >= 20 {
        let max = u32::from_le_bytes(tail[0..4].try_into().map_err(|_| PacError::Truncated)?);
        let actual = u32::from_le_bytes(tail[8..12].try_into().map_err(|_| PacError::Truncated)?);
        if max == 1 && actual == 1 {
            tail = &tail[20..];
        }
    }
    let realm = take_conformant_string(tail)
        .map(|(s, _)| s)
        .unwrap_or_default();
    if client.is_empty() {
        return Err(PacError::Truncated);
    }
    Ok((client, realm))
}

fn take_conformant_string(b: &[u8]) -> Result<(String, &[u8]), PacError> {
    if b.len() < 12 {
        return Err(PacError::Truncated);
    }
    let max = u32::from_le_bytes(b[0..4].try_into().map_err(|_| PacError::Truncated)?) as usize;
    let actual = u32::from_le_bytes(b[8..12].try_into().map_err(|_| PacError::Truncated)?) as usize;
    if actual > max || actual > 256 {
        return Err(PacError::Truncated);
    }
    let nbytes = actual.saturating_mul(2);
    if 12 + nbytes > b.len() {
        return Err(PacError::Truncated);
    }
    let mut u16s = Vec::with_capacity(actual);
    for k in 0..actual {
        let o = 12 + k * 2;
        u16s.push(u16::from_le_bytes([b[o], b[o + 1]]));
    }
    let s = String::from_utf16(&u16s).map_err(|_| PacError::Truncated)?;
    let pad = (4 - (nbytes % 4)) % 4;
    Ok((s, &b[12 + nbytes + pad..]))
}

#[allow(dead_code)]
fn ndr_conformant_strings(mut b: &[u8]) -> Result<Vec<String>, PacError> {
    let mut out = Vec::new();
    while b.len() >= 12 && out.len() < 2 {
        let max = u32::from_le_bytes(b[0..4].try_into().map_err(|_| PacError::Truncated)?) as usize;
        let actual =
            u32::from_le_bytes(b[8..12].try_into().map_err(|_| PacError::Truncated)?) as usize;
        if actual > max || actual > 256 {
            break;
        }
        let nbytes = actual.saturating_mul(2);
        if 12 + nbytes > b.len() {
            break;
        }
        let mut u16s = Vec::with_capacity(actual);
        for k in 0..actual {
            let o = 12 + k * 2;
            u16s.push(u16::from_le_bytes([b[o], b[o + 1]]));
        }
        out.push(String::from_utf16(&u16s).map_err(|_| PacError::Truncated)?);
        let pad = (4 - (nbytes % 4)) % 4;
        b = &b[12 + nbytes + pad..];
    }
    Ok(out)
}
