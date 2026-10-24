use std::fmt::Write as _;

use zeroize::Zeroize;

mod ndr;

use ndr::{NdrR, NdrW};

pub const PAC_LOGON_INFO: u32 = 1;

pub const PAC_CREDENTIAL_INFO: u32 = 2;

pub const PAC_SERVER_CHECKSUM: u32 = 6;

pub const PAC_PRIVSVR_CHECKSUM: u32 = 7;

pub const PAC_CLIENT_INFO: u32 = 10;

pub const PAC_DELEGATION_INFO: u32 = 11;

pub const PAC_UPN_DNS_INFO: u32 = 12;

pub const PAC_CLIENT_CLAIMS: u32 = 13;

pub const PAC_DEVICE_INFO: u32 = 14;

pub const PAC_DEVICE_CLAIMS: u32 = 15;

pub const PAC_TICKET_CHECKSUM: u32 = 16;

pub const PAC_ATTRIBUTES_INFO: u32 = 17;

pub const PAC_REQUESTER_SID: u32 = 18;

pub const PAC_FULL_CHECKSUM: u32 = 19;

pub const MAX_BUFFERS: usize = 4096;

pub const PAC_ALIGNMENT: usize = 8;

pub const CKSUM_HMAC_MD5: i32 = -138;

pub const CKSUM_HMAC_SHA1_96_AES128: i32 = 15;

pub const CKSUM_HMAC_SHA1_96_AES256: i32 = 16;

pub const SE_GROUP_DEFAULT: u32 = 7;

pub const USER_NORMAL_ACCOUNT: u32 = 0x10;

pub const PAC_ATTRIBUTE_WAS_REQUESTED: u32 = 0x0000_0001;

pub const PAC_ATTRIBUTE_WAS_GIVEN_IMPLICITLY: u32 = 0x0000_0002;

pub const PAC_UPN_DNS_HAS_SAM_AND_SID: u32 = 0x0000_0002;

pub const LOGON_EXTRA_SIDS: u32 = 0x20;

const NDR_PTR_BASE: u32 = 0x0002_0000;

/// FILETIME "never" (AD logoff / kickoff / must-change).
const NT_TIME_NEVER: u64 = 0x7fff_ffff_ffff_ffff;

const NT_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacBuffer {
    pub kind: u32,
    pub data: Vec<u8>,
    offset: usize,
}

impl PacBuffer {
    #[must_use]
    pub fn new(kind: u32, data: Vec<u8>) -> Self {
        Self {
            kind,
            data,
            offset: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pac {
    pub version: u32,
    pub buffers: Vec<PacBuffer>,
    raw: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PacError {
    Truncated,
    Integrity,
    MissingBuffer,
    Malformed,
}

impl std::fmt::Display for PacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "PAC truncated"),
            Self::Integrity => write!(f, "PAC integrity check failed"),
            Self::MissingBuffer => write!(f, "PAC missing required buffer"),
            Self::Malformed => write!(f, "PAC malformed"),
        }
    }
}

impl std::error::Error for PacError {}

impl Pac {
    #[must_use]
    pub fn built(version: u32, buffers: Vec<PacBuffer>) -> Self {
        Self {
            version,
            buffers,
            raw: Vec::new(),
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, PacError> {
        if bytes.len() < 8 {
            return Err(PacError::Truncated);
        }
        let c_buffers =
            u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| PacError::Truncated)?);
        let version = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| PacError::Truncated)?);
        if version != 0 {
            return Err(PacError::Malformed);
        }
        let count = usize::try_from(c_buffers).map_err(|_| PacError::Malformed)?;
        if !(1..=MAX_BUFFERS).contains(&count) {
            return Err(PacError::Malformed);
        }
        let header_len = 8 + 16 * count;
        if bytes.len() < header_len {
            return Err(PacError::Truncated);
        }
        let mut buffers = Vec::new();
        let mut off = 8usize;
        for _ in 0..count {
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
            if offset % PAC_ALIGNMENT != 0
                || offset < header_len
                || offset > bytes.len()
                || size > bytes.len() - offset
            {
                return Err(PacError::Malformed);
            }
            buffers.push(PacBuffer {
                kind,
                data: bytes[offset..offset + size].to_vec(),
                offset,
            });
        }
        Ok(Self {
            version,
            buffers,
            raw: bytes.to_vec(),
        })
    }

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

    #[must_use]
    pub fn buffer(&self, kind: u32) -> Option<&[u8]> {
        self.buffers
            .iter()
            .find(|b| b.kind == kind)
            .map(|b| b.data.as_slice())
    }

    pub fn unique_buffer(&self, kind: u32) -> Result<Option<&[u8]>, PacError> {
        let mut hits = self.buffers.iter().filter(|b| b.kind == kind);
        let first = hits.next();
        if hits.next().is_some() {
            return Err(PacError::Malformed);
        }
        Ok(first.map(|b| b.data.as_slice()))
    }

    #[must_use]
    pub fn bytes_for_checksum(&self) -> Vec<u8> {
        self.bytes_zeroing(&[PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM])
    }

    #[must_use]
    pub fn bytes_for_full_checksum(&self) -> Vec<u8> {
        self.bytes_zeroing(&[PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM, PAC_FULL_CHECKSUM])
    }

    fn bytes_zeroing(&self, kinds: &[u32]) -> Vec<u8> {
        let mut clone = self.clone();
        for b in &mut clone.buffers {
            if kinds.contains(&b.kind) {
                zero_signature_payload(&mut b.data);
            }
        }
        clone.to_bytes()
    }

    pub fn received_zeroed(&self, kinds: &[u32]) -> Result<Vec<u8>, PacError> {
        if self.raw.is_empty() {
            for kind in kinds {
                if !self.buffers.iter().any(|b| b.kind == *kind) {
                    return Err(PacError::MissingBuffer);
                }
            }
            return Ok(self.bytes_zeroing(kinds));
        }
        let mut copy = self.raw.clone();
        self.zero_in(&mut copy, kinds)?;
        Ok(copy)
    }

    fn zero_in(&self, copy: &mut [u8], kinds: &[u32]) -> Result<(), PacError> {
        for kind in kinds {
            let mut hits = self.buffers.iter().filter(|b| b.kind == *kind);
            let b = hits.next().ok_or(PacError::MissingBuffer)?;
            if hits.next().is_some() {
                return Err(PacError::Malformed);
            }
            if b.data.len() < 4 {
                return Err(PacError::Truncated);
            }
            let start = b.offset.checked_add(4).ok_or(PacError::Truncated)?;
            let end = b
                .offset
                .checked_add(b.data.len())
                .ok_or(PacError::Truncated)?;
            if end > copy.len() || start > end {
                return Err(PacError::Truncated);
            }
            copy[start..end].fill(0);
        }
        Ok(())
    }

    pub fn server_checksum(&self) -> Result<Option<&[u8]>, PacError> {
        self.unique_buffer(PAC_SERVER_CHECKSUM)
    }

    pub fn kdc_checksum(&self) -> Result<Option<&[u8]>, PacError> {
        self.unique_buffer(PAC_PRIVSVR_CHECKSUM)
    }

    pub fn ticket_checksum(&self) -> Result<Option<&[u8]>, PacError> {
        self.unique_buffer(PAC_TICKET_CHECKSUM)
    }

    pub fn full_checksum(&self) -> Result<Option<&[u8]>, PacError> {
        self.unique_buffer(PAC_FULL_CHECKSUM)
    }
}

fn zero_signature_payload(data: &mut [u8]) {
    if data.len() > 4 {
        for b in &mut data[4..] {
            *b = 0;
        }
    }
}

#[must_use]
pub fn signature_buffer(cksumtype: i32, mac: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + mac.len());
    v.extend_from_slice(&cksumtype.to_le_bytes());
    v.extend_from_slice(mac);
    v
}

#[must_use]
pub fn client_info_buffer(authtime_unix: u32, name: &str) -> Vec<u8> {
    let nt = unix_to_nt(authtime_unix);
    let utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut v = Vec::with_capacity(10 + utf16.len());
    v.extend_from_slice(&nt.to_le_bytes());
    let n = u16::try_from(utf16.len()).unwrap_or(u16::MAX);
    v.extend_from_slice(&n.to_le_bytes());
    v.extend_from_slice(&utf16[..usize::from(n)]);
    v
}

#[must_use]
pub fn parse_client_info(buf: &[u8]) -> Option<(u32, String)> {
    if buf.len() < 10 {
        return None;
    }
    let nt = u64::from_le_bytes(buf[0..8].try_into().ok()?);
    let nlen = usize::from(u16::from_le_bytes(buf[8..10].try_into().ok()?));
    if nlen % 2 != 0 || buf.len() < 10 + nlen {
        return None;
    }
    let units: Vec<u16> = buf[10..10 + nlen]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let name = String::from_utf16(&units).ok()?;
    let unix = nt.saturating_sub(NT_UNIX_EPOCH) / 10_000_000;
    Some((u32::try_from(unix).ok()?, name))
}

fn unix_to_nt(unix: u32) -> u64 {
    u64::from(unix)
        .saturating_mul(10_000_000)
        .saturating_add(NT_UNIX_EPOCH)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S4uDelegationInfo {
    pub proxy_target: String,
    pub transited_services: Vec<String>,
}

#[must_use]
pub fn delegation_info_buffer(info: &S4uDelegationInfo) -> Vec<u8> {
    let pt = enc_wchar(&info.proxy_target);
    let tss: Vec<Vec<u8>> = info
        .transited_services
        .iter()
        .map(|s| enc_wchar(s))
        .collect();
    let mut b = Vec::new();
    b.extend_from_slice(&[0x01, 0x10, 0x08, 0x00]);
    b.extend_from_slice(&0xcccc_ccccu32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    let mut ptr = 0u32;
    write_ndr_ptr(&mut b, &mut ptr);
    let pn = utf16_units(&info.proxy_target);
    b.extend_from_slice(&(2 * pn).to_le_bytes());
    b.extend_from_slice(&(2 * (pn + 1)).to_le_bytes());
    write_ndr_ptr(&mut b, &mut ptr);
    let n = u32::try_from(info.transited_services.len()).unwrap_or(0);
    b.extend_from_slice(&n.to_le_bytes());
    write_ndr_ptr(&mut b, &mut ptr);
    b.extend_from_slice(&pt);
    b.extend_from_slice(&n.to_le_bytes());
    for (s, raw) in info.transited_services.iter().zip(&tss) {
        let un = utf16_units(s);
        b.extend_from_slice(&(2 * un).to_le_bytes());
        b.extend_from_slice(&(2 * (un + 1)).to_le_bytes());
        write_ndr_ptr(&mut b, &mut ptr);
        let _ = raw;
    }
    for raw in &tss {
        b.extend_from_slice(raw);
    }
    if !b.len().is_multiple_of(8) {
        b.extend_from_slice(&0u32.to_le_bytes());
    }
    let payload = u32::try_from(b.len().saturating_sub(16)).unwrap_or(0);
    b[8..12].copy_from_slice(&payload.to_le_bytes());
    b
}

pub fn parse_delegation_info(data: &[u8]) -> Result<S4uDelegationInfo, PacError> {
    if data.len() < 16 {
        return Err(PacError::Truncated);
    }
    if data[0] != 1 || data[1] != 0x10 || u16::from_le_bytes([data[2], data[3]]) != 8 {
        return Err(PacError::Malformed);
    }
    let obj = u32::from_le_bytes(data[8..12].try_into().map_err(|_| PacError::Truncated)?);
    if obj as usize != data.len().saturating_sub(16) {
        return Err(PacError::Malformed);
    }
    let mut i = 16;
    skip_u32(data, &mut i)?;
    skip_u16(data, &mut i)?;
    skip_u16(data, &mut i)?;
    skip_u32(data, &mut i)?;
    skip_u32(data, &mut i)?;
    skip_u32(data, &mut i)?;
    let proxy_target = dec_wchar(data, &mut i)?;
    let n = read_u32(data, &mut i)? as usize;
    if n > data.len() / 8 {
        return Err(PacError::Malformed);
    }
    i = i.checked_add(8 * n).ok_or(PacError::Truncated)?;
    let mut transited_services = Vec::with_capacity(n);
    for _ in 0..n {
        transited_services.push(dec_wchar(data, &mut i)?);
    }
    Ok(S4uDelegationInfo {
        proxy_target,
        transited_services,
    })
}

fn utf16_units(s: &str) -> u16 {
    u16::try_from(s.encode_utf16().count()).unwrap_or(u16::MAX)
}

fn write_ndr_ptr(b: &mut Vec<u8>, pointer: &mut u32) {
    if *pointer == 0 {
        *pointer = NDR_PTR_BASE;
    }
    b.extend_from_slice(&pointer.to_le_bytes());
    *pointer = pointer.saturating_add(4);
}

fn enc_wchar(utf8: &str) -> Vec<u8> {
    let units: Vec<u16> = utf8.encode_utf16().collect();
    let n = u32::try_from(units.len()).unwrap_or(0);
    let mut b = Vec::new();
    b.extend_from_slice(&(n + 1).to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&n.to_le_bytes());
    for u in units {
        b.extend_from_slice(&u.to_le_bytes());
    }
    if n % 2 == 1 {
        b.extend_from_slice(&0u16.to_le_bytes());
    }
    b
}

fn dec_wchar(data: &[u8], i: &mut usize) -> Result<String, PacError> {
    let _max = read_u32(data, i)?;
    let _off = read_u32(data, i)?;
    let actual = read_u32(data, i)? as usize;
    let nbytes = actual.checked_mul(2).ok_or(PacError::Truncated)?;
    let end = i.checked_add(nbytes).ok_or(PacError::Truncated)?;
    if end > data.len() {
        return Err(PacError::Truncated);
    }
    let units: Vec<u16> = data[*i..end]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    *i = end;
    if actual % 2 == 1 {
        skip_u16(data, i)?;
    }
    String::from_utf16(&units).map_err(|_| PacError::Malformed)
}

fn read_u32(data: &[u8], i: &mut usize) -> Result<u32, PacError> {
    let end = i.checked_add(4).ok_or(PacError::Truncated)?;
    let v = u32::from_le_bytes(
        data.get(*i..end)
            .ok_or(PacError::Truncated)?
            .try_into()
            .map_err(|_| PacError::Truncated)?,
    );
    *i = end;
    Ok(v)
}

fn skip_u32(data: &[u8], i: &mut usize) -> Result<(), PacError> {
    read_u32(data, i).map(|_| ())
}

fn skip_u16(data: &[u8], i: &mut usize) -> Result<(), PacError> {
    let end = i.checked_add(2).ok_or(PacError::Truncated)?;
    if end > data.len() {
        return Err(PacError::Truncated);
    }
    *i = end;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcUnicode {
    pub length: u16,
    pub maximum_length: u16,
    pub pointed: bool,
    pub value: String,
}

impl RpcUnicode {
    #[must_use]
    pub fn pointed(s: &str) -> Self {
        let n = u16::try_from(s.encode_utf16().count().saturating_mul(2)).unwrap_or(u16::MAX);
        let max = if n == 0 { 0 } else { n.saturating_add(2) };
        Self {
            length: n,
            maximum_length: max,
            pointed: true,
            value: s.to_owned(),
        }
    }

    fn actual_chars(&self) -> u32 {
        u32::try_from(self.value.encode_utf16().count()).unwrap_or(0)
    }

    fn max_chars(&self) -> u32 {
        u32::from(self.maximum_length / 2)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcSid {
    pub revision: u8,
    pub identifier_authority: [u8; 6],
    pub sub_authority: Vec<u32>,
}

impl RpcSid {
    /// `S-1-5-21-1-2-3` dummy domain SID. Issued PACs must not use this.
    #[must_use]
    pub fn dummy_domain() -> Self {
        Self {
            revision: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5],
            sub_authority: vec![21, 1, 2, 3],
        }
    }

    #[must_use]
    pub fn from_sddl(s: &str) -> Option<Self> {
        let rest = s
            .strip_prefix('S')
            .or_else(|| s.strip_prefix('s'))?
            .strip_prefix('-')?;
        let mut parts = rest.split('-');
        let revision: u8 = parts.next()?.parse().ok()?;
        let ia: u64 = parts.next()?.parse().ok()?;
        let mut identifier_authority = [0u8; 6];
        identifier_authority.copy_from_slice(&ia.to_be_bytes()[2..8]);
        let mut sub_authority = Vec::new();
        for p in parts {
            sub_authority.push(p.parse().ok()?);
        }
        if sub_authority.is_empty() {
            return None;
        }
        Some(Self {
            revision,
            identifier_authority,
            sub_authority,
        })
    }

    #[must_use]
    pub fn with_rid(&self, rid: u32) -> Self {
        let mut s = self.clone();
        s.sub_authority.push(rid);
        s
    }

    #[must_use]
    pub fn is_in_domain(&self, domain: &RpcSid) -> bool {
        self.identifier_authority == domain.identifier_authority
            && self.sub_authority.len() >= domain.sub_authority.len()
            && self.sub_authority[..domain.sub_authority.len()] == domain.sub_authority[..]
    }

    #[must_use]
    pub fn to_ms_dtyp(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + self.sub_authority.len() * 4);
        v.push(self.revision);
        v.push(u8::try_from(self.sub_authority.len()).unwrap_or(0));
        v.extend_from_slice(&self.identifier_authority);
        for r in &self.sub_authority {
            v.extend_from_slice(&r.to_le_bytes());
        }
        v
    }

    #[must_use]
    pub fn from_ms_dtyp(b: &[u8]) -> Option<Self> {
        if b.len() < 8 {
            return None;
        }
        let revision = b[0];
        let n = usize::from(b[1]);
        if b.len() < 8 + n * 4 {
            return None;
        }
        let mut identifier_authority = [0u8; 6];
        identifier_authority.copy_from_slice(&b[2..8]);
        let mut sub_authority = Vec::with_capacity(n);
        let mut off = 8;
        for _ in 0..n {
            sub_authority.push(u32::from_le_bytes([
                b[off],
                b[off + 1],
                b[off + 2],
                b[off + 3],
            ]));
            off += 4;
        }
        Some(Self {
            revision,
            identifier_authority,
            sub_authority,
        })
    }

    #[must_use]
    pub fn nt_domain(a: u32, b: u32, c: u32) -> Self {
        Self {
            revision: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5],
            sub_authority: vec![21, a, b, c],
        }
    }

    #[must_use]
    pub fn to_sddl(&self) -> String {
        let ia = u64::from_be_bytes([
            0,
            0,
            self.identifier_authority[0],
            self.identifier_authority[1],
            self.identifier_authority[2],
            self.identifier_authority[3],
            self.identifier_authority[4],
            self.identifier_authority[5],
        ]);
        let mut s = format!("S-{}-{ia}", self.revision);
        for r in &self.sub_authority {
            let _ = write!(s, "-{r}");
        }
        s
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMembership {
    pub relative_id: u32,
    pub attributes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtraSid {
    pub sid: RpcSid,
    pub attributes: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct KerbValidationInfo {
    pub logon_time: u64,
    pub logoff_time: u64,
    pub kickoff_time: u64,
    pub password_last_set: u64,
    pub password_can_change: u64,
    pub password_must_change: u64,
    pub effective_name: RpcUnicode,
    pub full_name: RpcUnicode,
    pub logon_script: RpcUnicode,
    pub profile_path: RpcUnicode,
    pub home_directory: RpcUnicode,
    pub home_directory_drive: RpcUnicode,
    pub logon_count: u16,
    pub bad_password_count: u16,
    pub user_id: u32,
    pub primary_group_id: u32,
    pub groups: Vec<GroupMembership>,
    pub user_flags: u32,
    pub session_key: [u8; 16],
    pub logon_server: RpcUnicode,
    pub logon_domain_name: RpcUnicode,
    pub logon_domain_id: RpcSid,
    pub reserved1: [u32; 2],
    pub user_account_control: u32,
    pub sub_auth_status: u32,
    pub last_successful_ilogon: u64,
    pub last_failed_ilogon: u64,
    pub failed_ilogon_count: u32,
    pub reserved3: u32,
    pub extra_sids: Vec<ExtraSid>,
    pub resource_group_domain_sid: Option<RpcSid>,
    pub resource_groups: Vec<GroupMembership>,
}

impl std::fmt::Debug for KerbValidationInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KerbValidationInfo")
            .field("logon_time", &self.logon_time)
            .field("logoff_time", &self.logoff_time)
            .field("kickoff_time", &self.kickoff_time)
            .field("password_last_set", &self.password_last_set)
            .field("password_can_change", &self.password_can_change)
            .field("password_must_change", &self.password_must_change)
            .field("effective_name", &self.effective_name)
            .field("full_name", &self.full_name)
            .field("logon_script", &self.logon_script)
            .field("profile_path", &self.profile_path)
            .field("home_directory", &self.home_directory)
            .field("home_directory_drive", &self.home_directory_drive)
            .field("logon_count", &self.logon_count)
            .field("bad_password_count", &self.bad_password_count)
            .field("user_id", &self.user_id)
            .field("primary_group_id", &self.primary_group_id)
            .field("groups", &self.groups)
            .field("user_flags", &self.user_flags)
            .field("session_key", &format_args!("<redacted>"))
            .field("logon_server", &self.logon_server)
            .field("logon_domain_name", &self.logon_domain_name)
            .field("logon_domain_id", &self.logon_domain_id)
            .field("reserved1", &self.reserved1)
            .field("user_account_control", &self.user_account_control)
            .field("sub_auth_status", &self.sub_auth_status)
            .field("last_successful_ilogon", &self.last_successful_ilogon)
            .field("last_failed_ilogon", &self.last_failed_ilogon)
            .field("failed_ilogon_count", &self.failed_ilogon_count)
            .field("reserved3", &self.reserved3)
            .field("extra_sids", &self.extra_sids)
            .field("resource_group_domain_sid", &self.resource_group_domain_sid)
            .field("resource_groups", &self.resource_groups)
            .finish()
    }
}

impl Drop for KerbValidationInfo {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacIdentity {
    pub sam: String,
    pub realm: String,
    pub domain_sid: RpcSid,
    pub rid: u32,
}

impl PacIdentity {
    #[must_use]
    pub fn client_sid(&self) -> RpcSid {
        self.domain_sid.with_rid(self.rid)
    }

    #[must_use]
    pub fn upn(&self) -> String {
        format!("{}@{}", self.sam, self.realm)
    }
}

impl KerbValidationInfo {
    #[must_use]
    pub fn for_client(client: &str, realm: &str, domain_sid: &RpcSid, rid: u32) -> Self {
        Self {
            logon_time: 0,
            logoff_time: NT_TIME_NEVER,
            kickoff_time: NT_TIME_NEVER,
            password_last_set: 0,
            password_can_change: 0,
            password_must_change: NT_TIME_NEVER,
            effective_name: RpcUnicode::pointed(client),
            full_name: RpcUnicode::pointed(""),
            logon_script: RpcUnicode::pointed(""),
            profile_path: RpcUnicode::pointed(""),
            home_directory: RpcUnicode::pointed(""),
            home_directory_drive: RpcUnicode::pointed(""),
            logon_count: 1,
            bad_password_count: 0,
            user_id: rid,
            primary_group_id: 513,
            groups: vec![GroupMembership {
                relative_id: 513,
                attributes: SE_GROUP_DEFAULT,
            }],
            user_flags: LOGON_EXTRA_SIDS,
            session_key: [0; 16],
            logon_server: RpcUnicode::pointed(""),
            logon_domain_name: RpcUnicode::pointed(realm),
            logon_domain_id: domain_sid.clone(),
            reserved1: [0; 2],
            user_account_control: USER_NORMAL_ACCOUNT,
            sub_auth_status: 0,
            last_successful_ilogon: 0,
            last_failed_ilogon: 0,
            failed_ilogon_count: 0,
            reserved3: 0,
            extra_sids: vec![ExtraSid {
                sid: RpcSid {
                    revision: 1,
                    identifier_authority: [0, 0, 0, 0, 0, 18],
                    sub_authority: vec![1],
                },
                attributes: SE_GROUP_DEFAULT,
            }],
            resource_group_domain_sid: None,
            resource_groups: Vec::new(),
        }
    }

    #[must_use]
    pub fn to_ndr(&self) -> Vec<u8> {
        encode_kerb_validation_info(self)
    }
}

#[must_use]
pub fn logon_info_buffer(client: &str, realm: &str, domain_sid: &RpcSid, rid: u32) -> Vec<u8> {
    KerbValidationInfo::for_client(client, realm, domain_sid, rid).to_ndr()
}

#[must_use]
pub fn attributes_info_buffer() -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&PAC_ATTRIBUTE_WAS_REQUESTED.to_le_bytes());
    v
}

#[must_use]
pub fn requester_sid_buffer(sid: &RpcSid) -> Vec<u8> {
    sid.to_ms_dtyp()
}

#[must_use]
pub fn upn_dns_buffer(identity: &PacIdentity) -> Vec<u8> {
    let upn = utf16_bytes(&identity.upn());
    let dns = utf16_bytes(&identity.realm.to_ascii_lowercase());
    let sam = utf16_bytes(&identity.sam);
    let sid = identity.client_sid().to_ms_dtyp();
    let mut data = vec![0u8; 24];
    let upn_off = data.len();
    data.extend_from_slice(&upn);
    let dns_off = data.len();
    data.extend_from_slice(&dns);
    while !data.len().is_multiple_of(2) {
        data.push(0);
    }
    let sam_off = data.len();
    data.extend_from_slice(&sam);
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    let sid_off = data.len();
    data.extend_from_slice(&sid);
    put_u16(&mut data, 0, u16::try_from(upn.len()).unwrap_or(u16::MAX));
    put_u16(&mut data, 2, u16::try_from(upn_off).unwrap_or(u16::MAX));
    put_u16(&mut data, 4, u16::try_from(dns.len()).unwrap_or(u16::MAX));
    put_u16(&mut data, 6, u16::try_from(dns_off).unwrap_or(u16::MAX));
    data[8..12].copy_from_slice(&PAC_UPN_DNS_HAS_SAM_AND_SID.to_le_bytes());
    put_u16(&mut data, 12, u16::try_from(sam.len()).unwrap_or(u16::MAX));
    put_u16(&mut data, 14, u16::try_from(sam_off).unwrap_or(u16::MAX));
    put_u16(&mut data, 16, u16::try_from(sid.len()).unwrap_or(u16::MAX));
    put_u16(&mut data, 18, u16::try_from(sid_off).unwrap_or(u16::MAX));
    data
}

fn utf16_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpnDnsInfo {
    pub upn: String,
    pub dns_domain: String,
    pub sam: Option<String>,
    pub sid: Option<RpcSid>,
}

pub fn parse_upn_dns(data: &[u8]) -> Result<UpnDnsInfo, PacError> {
    if data.len() < 12 {
        return Err(PacError::Truncated);
    }
    let upn_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let upn_off = u16::from_le_bytes([data[2], data[3]]) as usize;
    let dns_len = u16::from_le_bytes([data[4], data[5]]) as usize;
    let dns_off = u16::from_le_bytes([data[6], data[7]]) as usize;
    let flags = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let upn = utf16_str(data, upn_off, upn_len)?;
    let dns = utf16_str(data, dns_off, dns_len)?;
    if flags & PAC_UPN_DNS_HAS_SAM_AND_SID == 0 || data.len() < 20 {
        return Ok(UpnDnsInfo {
            upn,
            dns_domain: dns,
            sam: None,
            sid: None,
        });
    }
    let sam_len = u16::from_le_bytes([data[12], data[13]]) as usize;
    let sam_off = u16::from_le_bytes([data[14], data[15]]) as usize;
    let sid_len = u16::from_le_bytes([data[16], data[17]]) as usize;
    let sid_off = u16::from_le_bytes([data[18], data[19]]) as usize;
    let sam = utf16_str(data, sam_off, sam_len)?;
    if sid_off + sid_len > data.len() {
        return Err(PacError::Truncated);
    }
    let sid = RpcSid::from_ms_dtyp(&data[sid_off..sid_off + sid_len]).ok_or(PacError::Truncated)?;
    Ok(UpnDnsInfo {
        upn,
        dns_domain: dns,
        sam: Some(sam),
        sid: Some(sid),
    })
}

fn utf16_str(data: &[u8], off: usize, len: usize) -> Result<String, PacError> {
    if off.checked_add(len).is_none_or(|e| e > data.len()) || !len.is_multiple_of(2) {
        return Err(PacError::Truncated);
    }
    let mut u16s = Vec::with_capacity(len / 2);
    for k in 0..len / 2 {
        u16s.push(u16::from_le_bytes([
            data[off + k * 2],
            data[off + k * 2 + 1],
        ]));
    }
    String::from_utf16(&u16s).map_err(|_| PacError::Truncated)
}

pub fn parse_logon_info(data: &[u8]) -> Result<(String, String), PacError> {
    if let Ok(v) = parse_kerb_validation_info(data) {
        return Ok((
            v.effective_name.value.clone(),
            v.logon_domain_name.value.clone(),
        ));
    }
    parse_legacy_utf8_logon(data)
}

pub fn parse_kerb_validation_info(data: &[u8]) -> Result<KerbValidationInfo, PacError> {
    let mut r = NdrR { b: data, i: 0 };
    if r.u8()? != 1 || r.u8()? != 0x10 {
        return Err(PacError::Truncated);
    }
    let _hlen = r.u16()?;
    let _filler = r.u32()?;
    let _objlen = r.u32()?;
    let _pfiller = r.u32()?;
    let top = r.u32()?;
    if top == 0 {
        return Err(PacError::Truncated);
    }
    let logon_time = r.u64()?;
    let logoff_time = r.u64()?;
    let kickoff_time = r.u64()?;
    let password_last_set = r.u64()?;
    let password_can_change = r.u64()?;
    let password_must_change = r.u64()?;
    let effective_name = r.ustr()?;
    let full_name = r.ustr()?;
    let logon_script = r.ustr()?;
    let profile_path = r.ustr()?;
    let home_directory = r.ustr()?;
    let home_directory_drive = r.ustr()?;
    let logon_count = r.u16()?;
    let bad_password_count = r.u16()?;
    let user_id = r.u32()?;
    let primary_group_id = r.u32()?;
    let group_count = r.u32()?;
    let groups_ptr = r.u32()?;
    let user_flags = r.u32()?;
    let mut session_key = [0u8; 16];
    session_key.copy_from_slice(r.bytes(16)?);
    let logon_server = r.ustr()?;
    let logon_domain_name = r.ustr()?;
    let domain_sid_ptr = r.u32()?;
    let reserved1 = [r.u32()?, r.u32()?];
    let user_account_control = r.u32()?;
    let sub_auth_status = r.u32()?;
    let last_successful_ilogon = r.u64()?;
    let last_failed_ilogon = r.u64()?;
    let failed_ilogon_count = r.u32()?;
    let reserved3 = r.u32()?;
    let sid_count = r.u32()?;
    let extra_ptr = r.u32()?;
    let rg_sid_ptr = r.u32()?;
    let rg_count = r.u32()?;
    let rg_ptr = r.u32()?;

    let effective_name = r.take_str(effective_name)?;
    let full_name = r.take_str(full_name)?;
    let logon_script = r.take_str(logon_script)?;
    let profile_path = r.take_str(profile_path)?;
    let home_directory = r.take_str(home_directory)?;
    let home_directory_drive = r.take_str(home_directory_drive)?;

    let groups = if groups_ptr == 0 {
        Vec::new()
    } else {
        r.group_array(group_count)?
    };
    let logon_server = r.take_str(logon_server)?;
    let logon_domain_name = r.take_str(logon_domain_name)?;
    let logon_domain_id = if domain_sid_ptr == 0 {
        return Err(PacError::Truncated);
    } else {
        r.sid()?
    };
    let extra_sids = if extra_ptr == 0 {
        Vec::new()
    } else {
        r.extra_sids(sid_count)?
    };
    let resource_group_domain_sid = if rg_sid_ptr == 0 {
        None
    } else {
        Some(r.sid()?)
    };
    let resource_groups = if rg_ptr == 0 {
        Vec::new()
    } else {
        r.group_array(rg_count)?
    };

    if effective_name.value.is_empty() {
        return Err(PacError::Truncated);
    }
    Ok(KerbValidationInfo {
        logon_time,
        logoff_time,
        kickoff_time,
        password_last_set,
        password_can_change,
        password_must_change,
        effective_name,
        full_name,
        logon_script,
        profile_path,
        home_directory,
        home_directory_drive,
        logon_count,
        bad_password_count,
        user_id,
        primary_group_id,
        groups,
        user_flags,
        session_key,
        logon_server,
        logon_domain_name,
        logon_domain_id,
        reserved1,
        user_account_control,
        sub_auth_status,
        last_successful_ilogon,
        last_failed_ilogon,
        failed_ilogon_count,
        reserved3,
        extra_sids,
        resource_group_domain_sid,
        resource_groups,
    })
}

fn encode_kerb_validation_info(info: &KerbValidationInfo) -> Vec<u8> {
    let mut w = NdrW::default();
    w.u8(1);
    w.u8(0x10);
    w.u16(8);
    w.u32(0xcccc_cccc);
    let obj_at = w.b.len();
    w.u32(0);
    w.u32(0);
    w.ptr(true);
    w.u64(info.logon_time);
    w.u64(info.logoff_time);
    w.u64(info.kickoff_time);
    w.u64(info.password_last_set);
    w.u64(info.password_can_change);
    w.u64(info.password_must_change);
    w.ustr_hdr(&info.effective_name);
    w.ustr_hdr(&info.full_name);
    w.ustr_hdr(&info.logon_script);
    w.ustr_hdr(&info.profile_path);
    w.ustr_hdr(&info.home_directory);
    w.ustr_hdr(&info.home_directory_drive);
    w.u16(info.logon_count);
    w.u16(info.bad_password_count);
    w.u32(info.user_id);
    w.u32(info.primary_group_id);
    w.u32(u32::try_from(info.groups.len()).unwrap_or(0));
    w.ptr(!info.groups.is_empty());
    w.u32(info.user_flags);
    w.b.extend_from_slice(&info.session_key);
    w.ustr_hdr(&info.logon_server);
    w.ustr_hdr(&info.logon_domain_name);
    w.ptr(true);
    w.u32(info.reserved1[0]);
    w.u32(info.reserved1[1]);
    w.u32(info.user_account_control);
    w.u32(info.sub_auth_status);
    w.u64(info.last_successful_ilogon);
    w.u64(info.last_failed_ilogon);
    w.u32(info.failed_ilogon_count);
    w.u32(info.reserved3);
    w.u32(u32::try_from(info.extra_sids.len()).unwrap_or(0));
    w.ptr(!info.extra_sids.is_empty());
    w.ptr(info.resource_group_domain_sid.is_some());
    w.u32(u32::try_from(info.resource_groups.len()).unwrap_or(0));
    w.ptr(!info.resource_groups.is_empty());

    w.ustr_body(&info.effective_name);
    w.ustr_body(&info.full_name);
    w.ustr_body(&info.logon_script);
    w.ustr_body(&info.profile_path);
    w.ustr_body(&info.home_directory);
    w.ustr_body(&info.home_directory_drive);
    if !info.groups.is_empty() {
        w.group_array(&info.groups);
    }
    w.ustr_body(&info.logon_server);
    w.ustr_body(&info.logon_domain_name);
    w.sid(&info.logon_domain_id);
    if !info.extra_sids.is_empty() {
        w.extra_sids(&info.extra_sids);
    }
    if let Some(sid) = &info.resource_group_domain_sid {
        w.sid(sid);
    }
    if !info.resource_groups.is_empty() {
        w.group_array(&info.resource_groups);
    }

    let objlen = u32::try_from(w.b.len().saturating_sub(16)).unwrap_or(u32::MAX);
    w.b[obj_at..obj_at + 4].copy_from_slice(&objlen.to_le_bytes());
    w.b
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

#[must_use]
pub fn authorization_with_zeroed_pac(
    ad: &[crate::AuthorizationDataValue],
) -> crate::AuthorizationData {
    ad.iter()
        .map(|el| {
            if el.ad_type == crate::pa::AD_WIN2K_PAC {
                crate::AuthorizationDataValue {
                    ad_type: el.ad_type,
                    ad_data: vec![0u8].into(),
                }
            } else if el.ad_type == crate::pa::AD_IF_RELEVANT {
                if let Ok(inner) =
                    rasn::der::decode::<crate::AuthorizationData>(el.ad_data.as_ref())
                    && let Ok(bytes) = rasn::der::encode(&authorization_with_zeroed_pac(&inner))
                {
                    return crate::AuthorizationDataValue {
                        ad_type: el.ad_type,
                        ad_data: bytes.into(),
                    };
                }
                el.clone()
            } else {
                el.clone()
            }
        })
        .collect()
}

#[must_use]
pub fn zero_pac_ad_data(enc_tkt: &[u8], pac: &[u8]) -> Option<Vec<u8>> {
    if pac.is_empty() {
        return None;
    }
    let (out, replaced, n) = rewrite_one(enc_tkt, 0, pac)?;
    if replaced && n == enc_tkt.len() {
        Some(out)
    } else {
        None
    }
}

fn rewrite_one(data: &[u8], off: usize, pac: &[u8]) -> Option<(Vec<u8>, bool, usize)> {
    let (tag, constructed, content, tlv_len) = read_tlv(data, off)?;
    let orig = data[off..off + tlv_len].to_vec();
    if tag == 0x04 && content == pac {
        return Some((encode_tlv(0x04, &[0]), true, tlv_len));
    }
    if constructed {
        let mut children = Vec::new();
        let mut pos = 0;
        let mut any = false;
        while pos < content.len() {
            let (ch, r, n) = rewrite_one(content, pos, pac)?;
            children.extend_from_slice(&ch);
            any |= r;
            pos += n;
        }
        if pos != content.len() {
            return None;
        }
        if any {
            return Some((encode_tlv(tag, &children), true, tlv_len));
        }
        return Some((orig, false, tlv_len));
    }
    if tag == 0x04
        && content.first().is_some_and(|b| *b == 0x30)
        && let Some((inner, true, n)) = rewrite_one(content, 0, pac)
        && n == content.len()
    {
        return Some((encode_tlv(tag, &inner), true, tlv_len));
    }
    Some((orig, false, tlv_len))
}

fn read_tlv(data: &[u8], off: usize) -> Option<(u8, bool, &[u8], usize)> {
    if off >= data.len() {
        return None;
    }
    let tag = data[off];
    if tag & 0x1f == 0x1f {
        return None;
    }
    let constructed = tag & 0x20 != 0;
    let (len, len_bytes) = crate::der::read_len(data.get(off + 1..)?)?;
    let hdr = 1 + len_bytes;
    let start = off + hdr;
    let end = start.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((tag, constructed, &data[start..end], hdr + len))
}

fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + crate::der::len_len(content.len()) + content.len());
    crate::der::push_tlv(&mut out, tag, content);
    out
}

#[cfg(test)]
mod tests;
