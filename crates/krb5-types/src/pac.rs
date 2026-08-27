//! AD-WIN2K-PAC parse, verify, and sign (MS-PAC).
//!
//! `PAC_LOGON_INFO` is MS-RPCE Type-Serialization v1 / NDR32
//! `KERB_VALIDATION_INFO`. Pointer referents are deferred in
//! field-encounter order (not dumped after the whole struct as a bag).

use std::fmt::Write as _;

use subtle::ConstantTimeEq;

/// PAC buffer type: logon info (`KERB_VALIDATION_INFO`).
pub const PAC_LOGON_INFO: u32 = 1;
/// PAC buffer type: credentials.
pub const PAC_CREDENTIAL_INFO: u32 = 2;
/// PAC buffer type: server checksum.
pub const PAC_SERVER_CHECKSUM: u32 = 6;
/// PAC buffer type: KDC / privilege-server checksum.
pub const PAC_PRIVSVR_CHECKSUM: u32 = 7;
/// PAC buffer type: client name and ticket info.
pub const PAC_CLIENT_INFO: u32 = 10;
/// PAC buffer type: constrained delegation info.
pub const PAC_DELEGATION_INFO: u32 = 11;
/// PAC buffer type: UPN/DNS info (MS-PAC `ulType` 12, not 16).
pub const PAC_UPN_DNS_INFO: u32 = 12;
/// PAC buffer type: client claims.
pub const PAC_CLIENT_CLAIMS: u32 = 13;
/// PAC buffer type: device info.
pub const PAC_DEVICE_INFO: u32 = 14;
/// PAC buffer type: device claims.
pub const PAC_DEVICE_CLAIMS: u32 = 15;
/// PAC buffer type: ticket checksum (CVE-2020-17049). **Not** UPN/DNS.
pub const PAC_TICKET_CHECKSUM: u32 = 16;
/// PAC buffer type: PAC attributes.
pub const PAC_ATTRIBUTES_INFO: u32 = 17;
/// PAC buffer type: requester SID.
pub const PAC_REQUESTER_SID: u32 = 18;
/// PAC buffer type: extended KDC / full PAC checksum (CVE-2022-37967).
pub const PAC_FULL_CHECKSUM: u32 = 19;

/// Signature type HMAC-MD5 (RC4). RFC 4757 cksumtype -138.
pub const CKSUM_HMAC_MD5: i32 = -138;
/// Signature type HMAC-SHA1-96-AES128.
pub const CKSUM_HMAC_SHA1_96_AES128: i32 = 15;
/// Signature type HMAC-SHA1-96-AES256.
pub const CKSUM_HMAC_SHA1_96_AES256: i32 = 16;

/// SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED.
pub const SE_GROUP_DEFAULT: u32 = 7;
/// `USER_NORMAL_ACCOUNT`.
pub const USER_NORMAL_ACCOUNT: u32 = 0x10;
/// PAC attributes: `PAC_WAS_REQUESTED`.
pub const PAC_ATTRIBUTE_WAS_REQUESTED: u32 = 0x0000_0001;
/// UPN/DNS: SAM name + SID extension present.
pub const PAC_UPN_DNS_HAS_SAM_AND_SID: u32 = 0x0000_0002;
/// `LOGON_EXTRA_SIDS`.
pub const LOGON_EXTRA_SIDS: u32 = 0x20;
/// NDR unique-pointer IDs start here and increment by 4 (Windows).
const NDR_PTR_BASE: u32 = 0x0002_0000;
/// FILETIME "never" (AD logoff / kickoff / must-change).
const NT_TIME_NEVER: u64 = 0x7fff_ffff_ffff_ffff;
/// NT time of Unix epoch.
const NT_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

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

    /// First buffer of `kind`.
    #[must_use]
    pub fn buffer(&self, kind: u32) -> Option<&[u8]> {
        self.buffers
            .iter()
            .find(|b| b.kind == kind)
            .map(|b| b.data.as_slice())
    }

    /// Zero server (6) and KDC (7) signature payloads. Ticket (16) and full
    /// (19) checksums stay populated — that is the AD server-checksum region.
    #[must_use]
    pub fn bytes_for_checksum(&self) -> Vec<u8> {
        self.bytes_zeroing(&[PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM])
    }

    /// Zero server, KDC, and full-PAC (19) signatures. Ticket checksum (16)
    /// stays filled. MS-PAC extended-KDC hash region.
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

    /// Server checksum buffer payload, if present.
    #[must_use]
    pub fn server_checksum(&self) -> Option<&[u8]> {
        self.buffer(PAC_SERVER_CHECKSUM)
    }

    /// KDC checksum buffer payload, if present.
    #[must_use]
    pub fn kdc_checksum(&self) -> Option<&[u8]> {
        self.buffer(PAC_PRIVSVR_CHECKSUM)
    }

    /// Ticket checksum (type 16) payload, if present.
    #[must_use]
    pub fn ticket_checksum(&self) -> Option<&[u8]> {
        self.buffer(PAC_TICKET_CHECKSUM)
    }

    /// Full PAC checksum (type 19) payload, if present.
    #[must_use]
    pub fn full_checksum(&self) -> Option<&[u8]> {
        self.buffer(PAC_FULL_CHECKSUM)
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

/// Verify the server checksum (HMAC over the PAC with signatures 6/7 zeroed).
///
/// # Errors
///
/// Returns [`PacError::Integrity`] on mismatch, [`PacError::MissingBuffer`]
/// when the server checksum is absent.
pub fn verify_server_checksum(pac: &Pac, expected: &[u8]) -> Result<(), PacError> {
    verify_sig_buf(pac.server_checksum(), expected)
}

/// Verify a signature buffer (`SignatureType` + MAC) against `expected` MAC.
///
/// # Errors
///
/// Missing buffer or mismatch.
pub fn verify_sig_buf(got: Option<&[u8]>, expected: &[u8]) -> Result<(), PacError> {
    let Some(got) = got else {
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
    let nt = unix_to_nt(authtime_unix);
    let utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut v = Vec::with_capacity(10 + utf16.len());
    v.extend_from_slice(&nt.to_le_bytes());
    let n = u16::try_from(utf16.len()).unwrap_or(u16::MAX);
    v.extend_from_slice(&n.to_le_bytes());
    v.extend_from_slice(&utf16[..usize::from(n)]);
    v
}

fn unix_to_nt(unix: u32) -> u64 {
    u64::from(unix)
        .saturating_mul(10_000_000)
        .saturating_add(NT_UNIX_EPOCH)
}

/// NDR32 `RPC_UNICODE_STRING` (embedded, Buffer deferred).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcUnicode {
    /// `Length` in bytes (not including a terminator).
    pub length: u16,
    /// `MaximumLength` in bytes (often `Length + 2`).
    pub maximum_length: u16,
    /// Whether `Buffer` is a non-null referent. AD empty strings are non-null.
    pub pointed: bool,
    /// UTF-16 decoded text.
    pub value: String,
}

impl RpcUnicode {
    /// Non-null string; empty uses Length=Max=0 still pointed (AD style).
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

/// NDR32 `RPC_SID`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcSid {
    /// Revision (1).
    pub revision: u8,
    /// 6-byte identifier authority (NT Authority is `{0,0,0,0,0,5}`).
    pub identifier_authority: [u8; 6],
    /// Sub-authorities (RID path).
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

    /// Parse SDDL `S-R-I-…`.
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

    /// Domain SID with `rid` appended (client / PAC_REQUESTOR).
    #[must_use]
    pub fn with_rid(&self, rid: u32) -> Self {
        let mut s = self.clone();
        s.sub_authority.push(rid);
        s
    }

    /// MS-DTYP packet SID (revision, count, authority, sub-authorities).
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

    /// Parse [`Self::to_ms_dtyp`].
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

    /// NT Authority domain SID `S-1-5-21-a-b-c`.
    #[must_use]
    pub fn nt_domain(a: u32, b: u32, c: u32) -> Self {
        Self {
            revision: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5],
            sub_authority: vec![21, a, b, c],
        }
    }

    /// SDDL-ish `S-1-…` form for assertions.
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

/// `GROUP_MEMBERSHIP`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMembership {
    /// Relative ID.
    pub relative_id: u32,
    /// `SE_GROUP_*` bits.
    pub attributes: u32,
}

/// `KERB_SID_AND_ATTRIBUTES`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtraSid {
    /// SID.
    pub sid: RpcSid,
    /// Attributes.
    pub attributes: u32,
}

/// MS-PAC `KERB_VALIDATION_INFO` (NDR32).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KerbValidationInfo {
    /// LogonTime FILETIME.
    pub logon_time: u64,
    /// LogoffTime FILETIME.
    pub logoff_time: u64,
    /// KickOffTime FILETIME.
    pub kickoff_time: u64,
    /// PasswordLastSet FILETIME.
    pub password_last_set: u64,
    /// PasswordCanChange FILETIME.
    pub password_can_change: u64,
    /// PasswordMustChange FILETIME.
    pub password_must_change: u64,
    /// SamAccountName.
    pub effective_name: RpcUnicode,
    /// Display name.
    pub full_name: RpcUnicode,
    /// Logon script.
    pub logon_script: RpcUnicode,
    /// Profile path.
    pub profile_path: RpcUnicode,
    /// Home directory.
    pub home_directory: RpcUnicode,
    /// Home drive.
    pub home_directory_drive: RpcUnicode,
    /// Logon count.
    pub logon_count: u16,
    /// Bad password count.
    pub bad_password_count: u16,
    /// User RID.
    pub user_id: u32,
    /// Primary group RID.
    pub primary_group_id: u32,
    /// Group memberships (`GroupCount` / `GroupIds`).
    pub groups: Vec<GroupMembership>,
    /// UserFlags.
    pub user_flags: u32,
    /// Session key (often zeros in the PAC).
    pub session_key: [u8; 16],
    /// Logon server (DC NetBIOS).
    pub logon_server: RpcUnicode,
    /// NetBIOS domain.
    pub logon_domain_name: RpcUnicode,
    /// Domain SID.
    pub logon_domain_id: RpcSid,
    /// Reserved1[2].
    pub reserved1: [u32; 2],
    /// UserAccountControl.
    pub user_account_control: u32,
    /// SubAuthStatus.
    pub sub_auth_status: u32,
    /// LastSuccessfulILogon.
    pub last_successful_ilogon: u64,
    /// LastFailedILogon.
    pub last_failed_ilogon: u64,
    /// FailedILogonCount.
    pub failed_ilogon_count: u32,
    /// Reserved3.
    pub reserved3: u32,
    /// Extra SIDs.
    pub extra_sids: Vec<ExtraSid>,
    /// Resource group domain SID.
    pub resource_group_domain_sid: Option<RpcSid>,
    /// Resource group memberships.
    pub resource_groups: Vec<GroupMembership>,
}

/// Client identity for PAC issuance (domain SID + RID from the store).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacIdentity {
    /// SAM account name (`user`, not `user@REALM`).
    pub sam: String,
    /// Kerberos realm / DNS domain.
    pub realm: String,
    /// Per-realm domain SID (`S-1-5-21-…`, not dummy `S-1-5-21-1-2-3`).
    pub domain_sid: RpcSid,
    /// Relative ID of this principal.
    pub rid: u32,
}

impl PacIdentity {
    /// Client SID = domain SID + RID.
    #[must_use]
    pub fn client_sid(&self) -> RpcSid {
        self.domain_sid.with_rid(self.rid)
    }

    /// `sam@realm` UPN.
    #[must_use]
    pub fn upn(&self) -> String {
        format!("{}@{}", self.sam, self.realm)
    }
}

impl KerbValidationInfo {
    /// PAC logon info for a KDC-issued ticket using store identity.
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

    /// Type-serialization v1 + NDR32 of this struct.
    #[must_use]
    pub fn to_ndr(&self) -> Vec<u8> {
        encode_kerb_validation_info(self)
    }
}

/// NDR32 `KERB_VALIDATION_INFO` for `client` / `realm` (KDC issuance).
#[must_use]
pub fn logon_info_buffer(client: &str, realm: &str, domain_sid: &RpcSid, rid: u32) -> Vec<u8> {
    KerbValidationInfo::for_client(client, realm, domain_sid, rid).to_ndr()
}

/// PAC buffer 17: `PAC_WAS_REQUESTED`.
#[must_use]
pub fn attributes_info_buffer() -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&2u32.to_le_bytes());
    v.extend_from_slice(&PAC_ATTRIBUTE_WAS_REQUESTED.to_le_bytes());
    v
}

/// PAC buffer 18: requester SID (MS-DTYP packet).
#[must_use]
pub fn requester_sid_buffer(sid: &RpcSid) -> Vec<u8> {
    sid.to_ms_dtyp()
}

/// PAC buffer 12: UPN + DNS + SAM + SID (`PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID`).
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

/// Parsed PAC buffer 12.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpnDnsInfo {
    /// `user@REALM`.
    pub upn: String,
    /// DNS domain (lowercase realm).
    pub dns_domain: String,
    /// SAM name when the SID extension is present.
    pub sam: Option<String>,
    /// Object SID when the SID extension is present.
    pub sid: Option<RpcSid>,
}

/// Parse [`upn_dns_buffer`].
///
/// # Errors
///
/// Truncated header or offsets.
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

/// Parse [`logon_info_buffer`] (NDR) or the legacy UTF-8 placeholder.
///
/// # Errors
///
/// Returns [`PacError::Truncated`] when the buffer is too short.
pub fn parse_logon_info(data: &[u8]) -> Result<(String, String), PacError> {
    if let Ok(v) = parse_kerb_validation_info(data) {
        return Ok((v.effective_name.value, v.logon_domain_name.value));
    }
    parse_legacy_utf8_logon(data)
}

/// Decode Type-Serialization v1 + NDR32 `KERB_VALIDATION_INFO`.
///
/// # Errors
///
/// Truncated or malformed NDR.
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

struct NdrR<'a> {
    b: &'a [u8],
    i: usize,
}

impl NdrR<'_> {
    fn need(&self, n: usize) -> Result<(), PacError> {
        if self.i.checked_add(n).is_none_or(|e| e > self.b.len()) {
            Err(PacError::Truncated)
        } else {
            Ok(())
        }
    }

    fn align4(&mut self) {
        let pad = (4 - (self.i % 4)) % 4;
        self.i = self.i.saturating_add(pad).min(self.b.len());
    }

    fn u8(&mut self) -> Result<u8, PacError> {
        self.need(1)?;
        let v = self.b[self.i];
        self.i += 1;
        Ok(v)
    }

    fn u16(&mut self) -> Result<u16, PacError> {
        self.need(2)?;
        let v = u16::from_le_bytes(
            self.b[self.i..self.i + 2]
                .try_into()
                .map_err(|_| PacError::Truncated)?,
        );
        self.i += 2;
        Ok(v)
    }

    fn u32(&mut self) -> Result<u32, PacError> {
        self.need(4)?;
        let v = u32::from_le_bytes(
            self.b[self.i..self.i + 4]
                .try_into()
                .map_err(|_| PacError::Truncated)?,
        );
        self.i += 4;
        Ok(v)
    }

    fn u64(&mut self) -> Result<u64, PacError> {
        self.need(8)?;
        let v = u64::from_le_bytes(
            self.b[self.i..self.i + 8]
                .try_into()
                .map_err(|_| PacError::Truncated)?,
        );
        self.i += 8;
        Ok(v)
    }

    fn take_str(&mut self, s: RpcUnicode) -> Result<RpcUnicode, PacError> {
        if s.pointed {
            self.conf_string(s)
        } else {
            Ok(s)
        }
    }

    fn bytes(&mut self, n: usize) -> Result<&[u8], PacError> {
        self.need(n)?;
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }

    fn ustr(&mut self) -> Result<RpcUnicode, PacError> {
        let length = self.u16()?;
        let maximum_length = self.u16()?;
        let ptr = self.u32()?;
        Ok(RpcUnicode {
            length,
            maximum_length,
            pointed: ptr != 0,
            value: String::new(),
        })
    }

    fn conf_string(&mut self, mut s: RpcUnicode) -> Result<RpcUnicode, PacError> {
        self.align4();
        let maxc = self.u32()?;
        let _off = self.u32()?;
        let act = self.u32()?;
        if act > maxc || act > 1024 {
            return Err(PacError::Truncated);
        }
        let nbytes = usize::try_from(act.saturating_mul(2)).map_err(|_| PacError::Truncated)?;
        let raw = self.bytes(nbytes)?;
        let mut u16s = Vec::with_capacity(act as usize);
        for k in 0..act as usize {
            u16s.push(u16::from_le_bytes([raw[k * 2], raw[k * 2 + 1]]));
        }
        s.value = String::from_utf16(&u16s).map_err(|_| PacError::Truncated)?;
        let pad = (4 - (nbytes % 4)) % 4;
        self.i = self.i.saturating_add(pad).min(self.b.len());
        Ok(s)
    }

    fn group_array(&mut self, expect: u32) -> Result<Vec<GroupMembership>, PacError> {
        self.align4();
        let maxc = self.u32()?;
        if maxc != expect || maxc > 1024 {
            return Err(PacError::Truncated);
        }
        let mut out = Vec::with_capacity(maxc as usize);
        for _ in 0..maxc {
            out.push(GroupMembership {
                relative_id: self.u32()?,
                attributes: self.u32()?,
            });
        }
        Ok(out)
    }

    fn sid(&mut self) -> Result<RpcSid, PacError> {
        self.align4();
        let maxc = self.u32()?;
        let revision = self.u8()?;
        let subc = self.u8()?;
        if u32::from(subc) > maxc || subc > 15 {
            return Err(PacError::Truncated);
        }
        let ia = self.bytes(6)?;
        let mut identifier_authority = [0u8; 6];
        identifier_authority.copy_from_slice(ia);
        let mut sub_authority = Vec::with_capacity(usize::from(subc));
        for _ in 0..subc {
            sub_authority.push(self.u32()?);
        }
        Ok(RpcSid {
            revision,
            identifier_authority,
            sub_authority,
        })
    }

    fn extra_sids(&mut self, expect: u32) -> Result<Vec<ExtraSid>, PacError> {
        self.align4();
        let maxc = self.u32()?;
        if maxc != expect || maxc > 64 {
            return Err(PacError::Truncated);
        }
        let mut hdrs = Vec::with_capacity(maxc as usize);
        for _ in 0..maxc {
            let ptr = self.u32()?;
            let attributes = self.u32()?;
            hdrs.push((ptr, attributes));
        }
        let mut out = Vec::with_capacity(hdrs.len());
        for (ptr, attributes) in hdrs {
            if ptr == 0 {
                return Err(PacError::Truncated);
            }
            out.push(ExtraSid {
                sid: self.sid()?,
                attributes,
            });
        }
        Ok(out)
    }
}

struct NdrW {
    b: Vec<u8>,
    next: u32,
}

impl Default for NdrW {
    fn default() -> Self {
        Self {
            b: Vec::new(),
            next: NDR_PTR_BASE,
        }
    }
}

impl NdrW {
    fn u8(&mut self, v: u8) {
        self.b.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn align4(&mut self) {
        while !self.b.len().is_multiple_of(4) {
            self.b.push(0);
        }
    }
    fn ptr(&mut self, present: bool) {
        if present {
            self.u32(self.next);
            self.next = self.next.saturating_add(4);
        } else {
            self.u32(0);
        }
    }
    fn ustr_hdr(&mut self, s: &RpcUnicode) {
        self.u16(s.length);
        self.u16(s.maximum_length);
        self.ptr(s.pointed);
    }
    fn ustr_body(&mut self, s: &RpcUnicode) {
        if !s.pointed {
            return;
        }
        self.align4();
        self.u32(s.max_chars());
        self.u32(0);
        self.u32(s.actual_chars());
        let utf16: Vec<u8> = s.value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        self.b.extend_from_slice(&utf16);
        self.align4();
    }
    fn group_array(&mut self, g: &[GroupMembership]) {
        self.align4();
        self.u32(u32::try_from(g.len()).unwrap_or(0));
        for m in g {
            self.u32(m.relative_id);
            self.u32(m.attributes);
        }
    }
    fn sid(&mut self, s: &RpcSid) {
        self.align4();
        let n = u32::try_from(s.sub_authority.len()).unwrap_or(0);
        self.u32(n);
        self.u8(s.revision);
        self.u8(u8::try_from(s.sub_authority.len()).unwrap_or(0));
        self.b.extend_from_slice(&s.identifier_authority);
        for r in &s.sub_authority {
            self.u32(*r);
        }
    }
    fn extra_sids(&mut self, extras: &[ExtraSid]) {
        self.align4();
        self.u32(u32::try_from(extras.len()).unwrap_or(0));
        for e in extras {
            self.ptr(true);
            self.u32(e.attributes);
        }
        for e in extras {
            self.sid(&e.sid);
        }
    }
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

/// Replace AD-WIN2K-PAC `ad-data` with a single zero byte (MS-PAC ticket checksum).
///
/// Walks `AD-IF-RELEVANT` wrappers. Other elements are copied.
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

/// EncTicketPart DER with PAC `ad-data` replaced by a single zero byte.
///
/// Preserves the issuer's TLV encodings (MS-PAC type 16). A rasn
/// re-encode of a Samba/Heimdal ticket will not match.
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
    let (len, len_bytes) = read_der_len(data, off + 1)?;
    let hdr = 1 + len_bytes;
    let start = off + hdr;
    let end = start.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((tag, constructed, &data[start..end], hdr + len))
}

fn read_der_len(data: &[u8], off: usize) -> Option<(usize, usize)> {
    let b = *data.get(off)?;
    if b < 0x80 {
        return Some((b as usize, 1));
    }
    let nbytes = (b & 0x7f) as usize;
    if nbytes == 0 || nbytes > 4 || off + 1 + nbytes > data.len() {
        return None;
    }
    let mut n = 0usize;
    for i in 0..nbytes {
        n = (n << 8) | usize::from(data[off + 1 + i]);
    }
    Some((n, 1 + nbytes))
}

fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(tag);
    out.extend(encode_der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn encode_der_len(n: usize) -> Vec<u8> {
    fn b(v: usize) -> u8 {
        u8::try_from(v & 0xff).unwrap_or(0)
    }
    match n {
        0..=127 => vec![b(n)],
        128..=255 => vec![0x81, b(n)],
        256..=65535 => vec![0x82, b(n >> 8), b(n)],
        65536..=16_777_215 => vec![0x83, b(n >> 16), b(n >> 8), b(n)],
        _ => vec![0x84, b(n >> 24), b(n >> 16), b(n >> 8), b(n)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ultype_16_is_ticket_checksum_not_upn_dns() {
        assert_eq!(PAC_UPN_DNS_INFO, 12);
        assert_eq!(PAC_TICKET_CHECKSUM, 16);
        assert_eq!(PAC_FULL_CHECKSUM, 19);
        assert_ne!(PAC_UPN_DNS_INFO, PAC_TICKET_CHECKSUM);
    }

    fn u8_len(n: usize) -> u8 {
        u8::try_from(n).expect("test DER fits in a short length")
    }

    #[test]
    fn zero_pac_ad_data_preserves_sibling_encoding() {
        let pac = vec![0x09, 0, 0, 0, 0, 0, 0, 0, 1, 2];
        // SEQUENCE { INTEGER 1 with non-minimal length, OCTET STRING pac }
        let mut der = vec![0x30, 0];
        der.extend_from_slice(&[0x02, 0x81, 0x01, 0x01]);
        der.push(0x04);
        der.push(u8_len(pac.len()));
        der.extend_from_slice(&pac);
        der[1] = u8_len(der.len() - 2);
        let out = zero_pac_ad_data(&der, &pac).expect("PAC in DER");
        assert_eq!(&out[2..6], &[0x02, 0x81, 0x01, 0x01]);
        assert_eq!(&out[6..], &[0x04, 0x01, 0x00]);
        assert!(zero_pac_ad_data(&der, b"nope").is_none());
    }

    #[test]
    fn zero_pac_ad_data_walks_ad_if_relevant() {
        let pac = vec![0x09, 0, 0, 0, 0, 0, 0, 0, 3, 4];
        // AD-WIN2K-PAC inner SEQUENCE { INTEGER 128, OCTET STRING pac }
        let mut inner = vec![0x30, 0];
        inner.extend_from_slice(&[0x02, 0x02, 0x00, 0x80]);
        inner.push(0x04);
        inner.push(u8_len(pac.len()));
        inner.extend_from_slice(&pac);
        inner[1] = u8_len(inner.len() - 2);
        // AD-IF-RELEVANT SEQUENCE { INTEGER 1, OCTET STRING inner }
        let mut outer = vec![0x30, 0];
        outer.extend_from_slice(&[0x02, 0x01, 0x01]);
        outer.push(0x04);
        outer.push(u8_len(inner.len()));
        outer.extend_from_slice(&inner);
        outer[1] = u8_len(outer.len() - 2);
        // APPLICATION 3 wrapping SEQUENCE
        let mut app = vec![0x63, 0];
        app.extend_from_slice(&outer);
        app[1] = u8_len(app.len() - 2);
        let out = zero_pac_ad_data(&app, &pac).expect("nested PAC");
        assert_eq!(out[0], 0x63);
        assert!(
            out.windows(3).any(|w| w == [0x04, 0x01, 0x00]),
            "PAC octet string must be a single zero: {out:02x?}"
        );
        assert!(!out.windows(pac.len()).any(|w| w == pac.as_slice()));
    }

    #[test]
    fn issued_logon_round_trip_is_byte_identical() {
        let sid = RpcSid::nt_domain(9, 8, 7);
        let raw = logon_info_buffer("user", "KERBER.TEST", &sid, 1000);
        let parsed = parse_kerb_validation_info(&raw).expect("NDR");
        assert_eq!(parsed.effective_name.value, "user");
        assert_eq!(parsed.logon_domain_name.value, "KERBER.TEST");
        assert_eq!(parsed.user_id, 1000);
        assert_eq!(parsed.primary_group_id, 513);
        assert_eq!(parsed.logon_domain_id.to_sddl(), "S-1-5-21-9-8-7");
        assert_ne!(
            parsed.logon_domain_id.to_sddl(),
            RpcSid::dummy_domain().to_sddl()
        );
        let again = parsed.to_ndr();
        assert_eq!(again, raw, "issued NDR must round-trip byte-for-byte");
    }

    #[test]
    fn upn_dns_attributes_requester_round_trip() {
        let ident = PacIdentity {
            sam: "user".into(),
            realm: "KERBER.TEST".into(),
            domain_sid: RpcSid::nt_domain(9, 8, 7),
            rid: 1000,
        };
        let upn = upn_dns_buffer(&ident);
        let parsed = parse_upn_dns(&upn).expect("upn");
        assert_eq!(parsed.upn, "user@KERBER.TEST");
        assert_eq!(parsed.dns_domain, "kerber.test");
        assert_eq!(parsed.sam.as_deref(), Some("user"));
        assert_eq!(parsed.sid.unwrap().to_sddl(), ident.client_sid().to_sddl());
        let attr = attributes_info_buffer();
        assert_eq!(&attr[0..4], &2u32.to_le_bytes());
        assert_eq!(&attr[4..8], &PAC_ATTRIBUTE_WAS_REQUESTED.to_le_bytes());
        let req = requester_sid_buffer(&ident.client_sid());
        assert_eq!(
            RpcSid::from_ms_dtyp(&req).unwrap().to_sddl(),
            "S-1-5-21-9-8-7-1000"
        );
    }

    #[test]
    fn sddl_round_trip_and_with_rid() {
        let s = RpcSid::from_sddl("S-1-5-21-891046300-1937985867-1481223175").unwrap();
        assert_eq!(s.to_sddl(), "S-1-5-21-891046300-1937985867-1481223175");
        assert_eq!(
            s.with_rid(1103).to_sddl(),
            "S-1-5-21-891046300-1937985867-1481223175-1103"
        );
        assert!(RpcSid::from_sddl("not-a-sid").is_none());
    }

    #[test]
    fn ad_golden_kbruser_fields_and_reencode() {
        let raw = include_bytes!("../../../tests/traces/pac-kbruser.ndr");
        let v = parse_kerb_validation_info(raw).expect("AD NDR");
        assert_eq!(v.effective_name.value, "kbruser");
        assert_eq!(v.logon_domain_name.value, "ADKERBER");
        assert_eq!(v.logon_server.value, "TEST-SERVER");
        assert_eq!(v.user_id, 1103);
        assert_eq!(v.primary_group_id, 513);
        assert!(
            v.groups.iter().any(|g| g.relative_id == 1104),
            "kbrgroup RID 1104: {:?}",
            v.groups
        );
        assert_eq!(
            v.logon_domain_id.to_sddl(),
            "S-1-5-21-1662395604-3502713894-542445324"
        );
        assert_eq!(v.extra_sids.len(), 1);
        assert_eq!(v.extra_sids[0].sid.to_sddl(), "S-1-18-1");
        let again = v.to_ndr();
        assert_eq!(
            again.as_slice(),
            raw.as_slice(),
            "re-encode must match captured AD NDR"
        );
    }
}
