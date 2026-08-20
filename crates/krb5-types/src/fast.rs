//! RFC 6113 FAST types (armor, KrbFastReq/Rep, cookie).

use rasn::prelude::*;

use crate::{Checksum, EncryptedData, EncryptionKey, KdcReqBody, KerberosTime, PaData};

/// FAST armor type: FX_FAST_ARMOR_AP_REQUEST.
pub const ARMOR_AP_REQUEST: i32 = 1;

/// KrbFastArmor ::= SEQUENCE { armor-type, armor-value }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbFastArmor {
    /// Armor type (1 = AP-REQ).
    #[rasn(tag(explicit(0)))]
    pub armor_type: i32,
    /// Encoded AP-REQ or other armor blob.
    #[rasn(tag(explicit(1)))]
    pub armor_value: OctetString,
}

/// KrbFastArmoredReq ::= SEQUENCE { armor, req-checksum, enc-fast-req }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbFastArmoredReq {
    /// Optional armor (present on the first FAST request).
    #[rasn(tag(explicit(0)))]
    pub armor: Option<KrbFastArmor>,
    /// Checksum over the KDC-REQ-BODY using the armor key.
    #[rasn(tag(explicit(1)))]
    pub req_checksum: Checksum,
    /// Encrypted [`KrbFastReq`].
    #[rasn(tag(explicit(2)))]
    pub enc_fast_req: EncryptedData,
}

/// FastOptions ::= KerberosFlags
pub type FastOptions = crate::KerberosFlags;

/// KrbFastReq ::= SEQUENCE { fast-options, padata, req-body }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbFastReq {
    /// FAST options bit string.
    #[rasn(tag(explicit(0)))]
    pub fast_options: FastOptions,
    /// Inner padata (encrypted timestamp, cookie, …).
    #[rasn(tag(explicit(1)))]
    pub padata: SequenceOf<PaData>,
    /// Copy of the outer request body.
    #[rasn(tag(explicit(2)))]
    pub req_body: KdcReqBody,
}

/// KrbFastFinished ::= SEQUENCE { timestamp, usec, crealm, cname, ticket-checksum }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbFastFinished {
    /// KDC timestamp.
    #[rasn(tag(explicit(0)))]
    pub timestamp: KerberosTime,
    /// Microseconds.
    #[rasn(tag(explicit(1)))]
    pub usec: crate::Microseconds,
    /// Client realm.
    #[rasn(tag(explicit(2)))]
    pub crealm: crate::Realm,
    /// Client name.
    #[rasn(tag(explicit(3)))]
    pub cname: crate::PrincipalName,
    /// Checksum of the issued ticket.
    #[rasn(tag(explicit(4)))]
    pub ticket_checksum: Checksum,
}

/// KrbFastResponse ::= SEQUENCE { padata, strengthen-key, finished, nonce }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbFastResponse {
    /// Inner padata (ETYPE-INFO2, cookie, …).
    #[rasn(tag(explicit(0)))]
    pub padata: SequenceOf<PaData>,
    /// Optional strengthen key mixed into the reply key.
    #[rasn(tag(explicit(1)))]
    pub strengthen_key: Option<EncryptionKey>,
    /// Optional finished (on the last FAST reply).
    #[rasn(tag(explicit(2)))]
    pub finished: Option<KrbFastFinished>,
    /// Echo of the request nonce.
    #[rasn(tag(explicit(3)))]
    pub nonce: u32,
}

/// KrbFastArmoredRep ::= SEQUENCE { enc-fast-rep }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbFastArmoredRep {
    /// Encrypted [`KrbFastResponse`].
    #[rasn(tag(explicit(0)))]
    pub enc_fast_rep: EncryptedData,
}

/// Empty FAST options (32 zero bits).
#[must_use]
pub fn fast_options_none() -> FastOptions {
    FastOptions::repeat(false, 32)
}
