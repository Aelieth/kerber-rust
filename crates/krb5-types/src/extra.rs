//! RFC 4120 AP-REP, KRB-SAFE, KRB-PRIV, and KRB-CRED.

use rasn::prelude::*;

use crate::{
    Checksum, EncryptedData, EncryptionKey, HostAddress, KerberosTime, Microseconds, OctetString,
    PrincipalName, Realm, Ticket,
};

/// AP-REP ::= [APPLICATION 15] SEQUENCE { pvno, msg-type, enc-part }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 15)))]
pub struct ApRep {
    /// Protocol version.
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    /// Message type (15).
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    /// Encrypted [`EncApRepPart`].
    #[rasn(tag(explicit(2)))]
    pub enc_part: EncryptedData,
}

impl ApRep {
    /// Protocol version.
    pub const PVNO: i32 = 5;
    /// AP-REP msg-type.
    pub const MSG_TYPE: i32 = 15;
}

/// EncAPRepPart ::= [APPLICATION 27] SEQUENCE { ctime, cusec, subkey, seq-number }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 27)))]
pub struct EncApRepPart {
    /// Client time from the AP-REQ authenticator.
    #[rasn(tag(explicit(0)))]
    pub ctime: KerberosTime,
    /// Client microseconds from the AP-REQ authenticator.
    #[rasn(tag(explicit(1)))]
    pub cusec: Microseconds,
    /// Optional negotiated sub-session key.
    #[rasn(tag(explicit(2)))]
    pub subkey: Option<EncryptionKey>,
    /// Optional sequence number.
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<u32>,
}

/// KRB-SAFE ::= [APPLICATION 20] SEQUENCE { pvno, msg-type, safe-body, cksum }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 20)))]
pub struct KrbSafe {
    /// Protocol version.
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    /// Message type (20).
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    /// Integrity-protected body.
    #[rasn(tag(explicit(2)))]
    pub safe_body: KrbSafeBody,
    /// Checksum over the body (key usage 15).
    #[rasn(tag(explicit(3)))]
    pub cksum: Checksum,
}

impl KrbSafe {
    /// Protocol version.
    pub const PVNO: i32 = 5;
    /// KRB-SAFE msg-type.
    pub const MSG_TYPE: i32 = 20;
}

/// KRB-SAFE-BODY
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbSafeBody {
    /// Application payload.
    #[rasn(tag(explicit(0)))]
    pub user_data: OctetString,
    /// Optional timestamp.
    #[rasn(tag(explicit(1)))]
    pub timestamp: Option<KerberosTime>,
    /// Optional microseconds.
    #[rasn(tag(explicit(2)))]
    pub usec: Option<Microseconds>,
    /// Optional sequence number.
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<u32>,
    /// Sender address.
    #[rasn(tag(explicit(4)))]
    pub s_address: HostAddress,
    /// Optional recipient address.
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddress>,
}

/// KRB-PRIV ::= [APPLICATION 21] SEQUENCE { pvno, msg-type, enc-part }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 21)))]
pub struct KrbPriv {
    /// Protocol version.
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    /// Message type (21).
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    /// Encrypted [`EncKrbPrivPart`] (key usage 13).
    #[rasn(tag(explicit(3)))]
    pub enc_part: EncryptedData,
}

impl KrbPriv {
    /// Protocol version.
    pub const PVNO: i32 = 5;
    /// KRB-PRIV msg-type.
    pub const MSG_TYPE: i32 = 21;
}

/// EncKrbPrivPart ::= [APPLICATION 28] SEQUENCE { ... }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 28)))]
pub struct EncKrbPrivPart {
    /// Application payload.
    #[rasn(tag(explicit(0)))]
    pub user_data: OctetString,
    /// Optional timestamp.
    #[rasn(tag(explicit(1)))]
    pub timestamp: Option<KerberosTime>,
    /// Optional microseconds.
    #[rasn(tag(explicit(2)))]
    pub usec: Option<Microseconds>,
    /// Optional sequence number.
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<u32>,
    /// Sender address.
    #[rasn(tag(explicit(4)))]
    pub s_address: HostAddress,
    /// Optional recipient address.
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddress>,
}

/// KRB-CRED ::= [APPLICATION 22] SEQUENCE { pvno, msg-type, tickets, enc-part }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 22)))]
pub struct KrbCred {
    /// Protocol version.
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    /// Message type (22).
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    /// Forwarded tickets.
    #[rasn(tag(explicit(2)))]
    pub tickets: SequenceOf<Ticket>,
    /// Encrypted [`EncKrbCredPart`] (key usage 14).
    #[rasn(tag(explicit(3)))]
    pub enc_part: EncryptedData,
}

impl KrbCred {
    /// Protocol version.
    pub const PVNO: i32 = 5;
    /// KRB-CRED msg-type.
    pub const MSG_TYPE: i32 = 22;
}

/// EncKrbCredPart ::= [APPLICATION 29] SEQUENCE { ... }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 29)))]
pub struct EncKrbCredPart {
    /// Per-ticket info aligned with [`KrbCred::tickets`].
    #[rasn(tag(explicit(0)))]
    pub ticket_info: SequenceOf<KrbCredInfo>,
    /// Optional nonce.
    #[rasn(tag(explicit(1)))]
    pub nonce: Option<u32>,
    /// Optional timestamp.
    #[rasn(tag(explicit(2)))]
    pub timestamp: Option<KerberosTime>,
    /// Optional microseconds.
    #[rasn(tag(explicit(3)))]
    pub usec: Option<Microseconds>,
    /// Optional sender address.
    #[rasn(tag(explicit(4)))]
    pub s_address: Option<HostAddress>,
    /// Optional recipient address.
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddress>,
}

/// KrbCredInfo ::= SEQUENCE { key, prealm, pname, flags, authtime, ... }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbCredInfo {
    /// Session key for the forwarded ticket.
    #[rasn(tag(explicit(0)))]
    pub key: EncryptionKey,
    /// Client realm.
    #[rasn(tag(explicit(1)))]
    pub prealm: Option<Realm>,
    /// Client name.
    #[rasn(tag(explicit(2)))]
    pub pname: Option<PrincipalName>,
    /// Ticket flags.
    #[rasn(tag(explicit(3)))]
    pub flags: Option<crate::TicketFlags>,
    /// Auth time.
    #[rasn(tag(explicit(4)))]
    pub authtime: Option<KerberosTime>,
    /// Start time.
    #[rasn(tag(explicit(5)))]
    pub starttime: Option<KerberosTime>,
    /// End time.
    #[rasn(tag(explicit(6)))]
    pub endtime: Option<KerberosTime>,
    /// Renew-till.
    #[rasn(tag(explicit(7)))]
    pub renew_till: Option<KerberosTime>,
    /// Server realm.
    #[rasn(tag(explicit(8)))]
    pub srealm: Option<Realm>,
    /// Server name.
    #[rasn(tag(explicit(9)))]
    pub sname: Option<PrincipalName>,
    /// Addresses.
    #[rasn(tag(explicit(10)))]
    pub caddr: Option<crate::HostAddresses>,
}

/// RFC 3244 `ChangePasswdData`.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct ChangePasswdData {
    /// New password octets.
    #[rasn(tag(explicit(0)))]
    pub newpasswd: OctetString,
    /// Optional target name.
    #[rasn(tag(explicit(1)))]
    pub targname: Option<PrincipalName>,
    /// Optional target realm.
    #[rasn(tag(explicit(2)))]
    pub targrealm: Option<Realm>,
}
