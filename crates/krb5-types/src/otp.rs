//! RFC 6560 OTP preauth messages: `OTP-TOKENINFO`, the `PA-OTP-CHALLENGE` and
//! `PA-OTP-REQUEST` padata that carry it, and the `PA-OTP-ENC-REQUEST` that is
//! one plaintext a request's `encData` can hold.
//!
//! MIT's `otp.asn1` is `DEFINITIONS IMPLICIT TAGS`, so each `[n]` here is an
//! implicit tag (`#[rasn(tag(n))]`). The explicit tags of `spake` are that
//! module's own choice.
//!
//! MIT `utf8string` (`lib/krb5/asn.1/asn1_k_encode.c:89-91`): a byte string that is never checked as
//! UTF-8. So the text fields `vendor`, `alg_id`, `service` and `pin` are octets here too, and one
//! non-UTF-8 octet fails no decode.

use std::fmt;

use rasn::prelude::*;

use crate::pkinit::CmsAlgorithmIdentifier;
use crate::{EncryptedData, KerberosFlags, KerberosString, KerberosTime, OctetString};

/// Named bit 1 of `OTPFlags`, `nextOTP`.
/// MIT `KRB5_OTP_FLAG_NEXTOTP` (`include/k5-int.h:511-511`): 0x40000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_NEXTOTP: u32 = 0x4000_0000;
/// Named bit 2 of `OTPFlags`, `combine`.
/// MIT `KRB5_OTP_FLAG_COMBINE` (`include/k5-int.h:512-512`): 0x20000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_COMBINE: u32 = 0x2000_0000;
/// Named bit 3 of `OTPFlags`, `collect-pin`.
/// MIT `KRB5_OTP_FLAG_COLLECT_PIN` (`include/k5-int.h:513-513`): 0x10000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_COLLECT_PIN: u32 = 0x1000_0000;
/// Named bit 4 of `OTPFlags`, `do-not-collect-pin`.
/// MIT `KRB5_OTP_FLAG_NO_COLLECT_PIN` (`include/k5-int.h:514-514`): 0x08000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_NO_COLLECT_PIN: u32 = 0x0800_0000;
/// Named bit 5 of `OTPFlags`, `must-encrypt-nonce`.
/// MIT `KRB5_OTP_FLAG_ENCRYPT_NONCE` (`include/k5-int.h:515-515`): 0x04000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_ENCRYPT_NONCE: u32 = 0x0400_0000;
/// Named bit 6 of `OTPFlags`, `separate-pin-required`.
/// MIT `KRB5_OTP_FLAG_SEPARATE_PIN` (`include/k5-int.h:516-516`): 0x02000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_SEPARATE_PIN: u32 = 0x0200_0000;
/// Named bit 7 of `OTPFlags`, `check-digit`.
/// MIT `KRB5_OTP_FLAG_CHECK_DIGIT` (`include/k5-int.h:517-517`): 0x01000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_CHECK_DIGIT: u32 = 0x0100_0000;

/// `OTPFormat` `decimal(0)`.
/// MIT `KRB5_OTP_FORMAT_DECIMAL` (`include/k5-int.h:519-519`): 0, the value of `decimal`.
pub const OTP_FORMAT_DECIMAL: i32 = 0;
/// `OTPFormat` `hexadecimal(1)`.
/// MIT `KRB5_OTP_FORMAT_HEXADECIMAL` (`include/k5-int.h:520-520`): 1, the value of `hexadecimal`.
pub const OTP_FORMAT_HEXADECIMAL: i32 = 1;
/// `OTPFormat` `alphanumeric(2)`.
/// MIT `KRB5_OTP_FORMAT_ALPHANUMERIC` (`include/k5-int.h:521-521`): 2, the value of `alphanumeric`.
pub const OTP_FORMAT_ALPHANUMERIC: i32 = 2;
/// `OTPFormat` `binary(3)`.
/// MIT `KRB5_OTP_FORMAT_BINARY` (`include/k5-int.h:522-522`): 3, the value of `binary`.
pub const OTP_FORMAT_BINARY: i32 = 3;
/// `OTPFormat` `base64(4)`.
/// MIT `KRB5_OTP_FORMAT_BASE64` (`include/k5-int.h:523-523`): 4, the value of `base64`.
pub const OTP_FORMAT_BASE64: i32 = 4;

/// `OTP-TOKENINFO ::= SEQUENCE { flags [0] OTPFlags, otp-vendor [1] UTF8String OPTIONAL, ... }`
///
/// One token the KDC offers in [`PaOtpChallenge::token_info`]. A field the KDC does not send is `None`.
/// MIT `otp_tokeninfo` (`lib/krb5/asn.1/asn1_k_encode.c:1579-1579`): the SEQUENCE of `krb5_otp_tokeninfo` with the field table `otp_tokeninfo_fields`.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct OtpTokenInfo {
    /// `flags [0]`: the `OTP_FLAG_*` bits, in a 32-bit bit string.
    #[rasn(tag(0))]
    pub flags: KerberosFlags,
    /// `otp-vendor [1]`: the token's vendor.
    #[rasn(tag(1))]
    pub vendor: Option<OctetString>,
    /// `otp-challenge [2]`: the challenge the token answers.
    #[rasn(tag(2))]
    pub challenge: Option<OctetString>,
    /// `otp-length [3]`: the OTP's length. `format` and `iteration_count` are absent the same way.
    /// MIT `opt_int32_minus1` (`lib/krb5/asn.1/asn1_k_encode.c:49-49`): an int32 of -1 is absent, so `None` is MIT's -1.
    #[rasn(tag(3))]
    pub length: Option<i32>,
    /// `otp-format [4]`: one of the `OTP_FORMAT_*` values.
    #[rasn(tag(4))]
    pub format: Option<i32>,
    /// `otp-tokenID [5]`: the token's identifier.
    #[rasn(tag(5))]
    pub token_id: Option<OctetString>,
    /// `otp-algID [6]`: the token's algorithm, an AnyURI.
    #[rasn(tag(6))]
    pub alg_id: Option<OctetString>,
    /// `supportedHashAlg [7]`: the listed hash algorithms, as AlgorithmIdentifiers.
    /// MIT `tokinfo_7` (`lib/krb5/asn.1/asn1_k_encode.c:1570-1571`): `supported_hash_alg` is the optional SEQUENCE OF AlgorithmIdentifier under implicit tag 7.
    #[rasn(tag(7))]
    pub supported_hash_alg: Option<SequenceOf<CmsAlgorithmIdentifier>>,
    /// `iterationCount [8]`: the hash iteration count.
    #[rasn(tag(8))]
    pub iteration_count: Option<i32>,
}

/// `PA-OTP-CHALLENGE ::= SEQUENCE { nonce [0] OCTET STRING, otp-service [1] UTF8String OPTIONAL, otp-tokenInfo [2] SEQUENCE (SIZE(1..MAX)) OF OTP-TOKENINFO, salt [3] KerberosString OPTIONAL, s2kparams [4] OCTET STRING OPTIONAL, ... }`
///
/// The KDC's challenge, carried by the padata of type 141.
/// MIT `KRB5_PADATA_OTP_CHALLENGE` (`krb5.hin:1838-1838`): 141, the padata type that carries it.
/// MIT `pa_otp_challenge` (`lib/krb5/asn.1/asn1_k_encode.c:1598-1598`): the SEQUENCE of `krb5_pa_otp_challenge` with the field table `pa_otp_challenge_fields`.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaOtpChallenge {
    /// `nonce [0]`: the nonce.
    #[rasn(tag(0))]
    pub nonce: OctetString,
    /// `otp-service [1]`: the service the OTP is for.
    #[rasn(tag(1))]
    pub service: Option<OctetString>,
    /// `otp-tokenInfo [2]`: one `OTP-TOKENINFO` per token the KDC offers.
    /// MIT `otp_ch_2` (`lib/krb5/asn.1/asn1_k_encode.c:1589-1590`): `token_info` is the SEQUENCE OF OTP-TOKENINFO under implicit tag 2.
    #[rasn(tag(2))]
    pub token_info: SequenceOf<OtpTokenInfo>,
    /// `salt [3]`: the salt.
    #[rasn(tag(3))]
    pub salt: Option<KerberosString>,
    /// `s2kparams [4]`: the string-to-key parameters.
    #[rasn(tag(4))]
    pub s2kparams: Option<OctetString>,
}

/// `PA-OTP-REQUEST ::= SEQUENCE { flags [0] OTPFlags, nonce [1] OCTET STRING OPTIONAL, encData [2] EncryptedData, hashAlg [3] AlgorithmIdentifier OPTIONAL, ... }`
///
/// The client's answer, carried by the padata of type 142. Its `Debug` output shows
/// no PIN and no OTP value.
/// MIT `KRB5_PADATA_OTP_REQUEST` (`krb5.hin:1839-1839`): 142, the padata type that carries it.
/// MIT `pa_otp_req` (`lib/krb5/asn.1/asn1_k_encode.c:1625-1625`): the SEQUENCE of `krb5_pa_otp_req` with the field table `pa_otp_req_fields`.
#[derive(AsnType, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaOtpRequest {
    /// `flags [0]`: the `OTP_FLAG_*` bits, in a 32-bit bit string.
    #[rasn(tag(0))]
    pub flags: KerberosFlags,
    /// `nonce [1]`: the nonce.
    #[rasn(tag(1))]
    pub nonce: Option<OctetString>,
    /// `encData [2]`: a PA-OTP-ENC-REQUEST or a PA-ENC-TS-ENC, encrypted under key usage 45.
    /// MIT `otp_req_2` (`lib/krb5/asn.1/asn1_k_encode.c:1604-1604`): `enc_data` is an `encrypted_data` under implicit tag 2.
    #[rasn(tag(2))]
    pub enc_data: EncryptedData,
    /// `hashAlg [3]`: the hash algorithm.
    /// MIT `otp_req_3` (`lib/krb5/asn.1/asn1_k_encode.c:1605-1606`): `hash_alg` is an optional AlgorithmIdentifier under implicit tag 3.
    #[rasn(tag(3))]
    pub hash_alg: Option<CmsAlgorithmIdentifier>,
    /// `iterationCount [4]`: the hash iteration count.
    #[rasn(tag(4))]
    pub iteration_count: Option<i32>,
    /// `otp-value [5]`: the OTP the token produced. A secret, so `Debug` redacts it.
    #[rasn(tag(5))]
    pub otp_value: Option<OctetString>,
    /// `otp-pin [6]`: the user's PIN. A secret, so `Debug` redacts it.
    #[rasn(tag(6))]
    pub pin: Option<OctetString>,
    /// `otp-challenge [7]`: the challenge the token answers.
    #[rasn(tag(7))]
    pub challenge: Option<OctetString>,
    /// `otp-time [8]`: a time, as a KerberosTime.
    /// MIT `otp_req_8` (`lib/krb5/asn.1/asn1_k_encode.c:1612-1612`): `time` is an optional KerberosTime under implicit tag 8.
    #[rasn(tag(8))]
    pub time: Option<KerberosTime>,
    /// `otp-counter [9]`: the token's counter.
    #[rasn(tag(9))]
    pub counter: Option<OctetString>,
    /// `otp-format [10]`: one of the `OTP_FORMAT_*` values.
    #[rasn(tag(10))]
    pub format: Option<i32>,
    /// `otp-tokenID [11]`: the token's identifier.
    #[rasn(tag(11))]
    pub token_id: Option<OctetString>,
    /// `otp-algID [12]`: the token's algorithm, an AnyURI.
    #[rasn(tag(12))]
    pub alg_id: Option<OctetString>,
    /// `otp-vendor [13]`: the token's vendor.
    #[rasn(tag(13))]
    pub vendor: Option<OctetString>,
}

/// Stands for a PIN or an OTP value in a `Debug` output, printed as `<redacted>`.
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Debug for PaOtpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaOtpRequest")
            .field("flags", &self.flags)
            .field("nonce", &self.nonce)
            .field("enc_data", &self.enc_data)
            .field("hash_alg", &self.hash_alg)
            .field("iteration_count", &self.iteration_count)
            .field("otp_value", &self.otp_value.as_ref().map(|_| Redacted))
            .field("pin", &self.pin.as_ref().map(|_| Redacted))
            .field("challenge", &self.challenge)
            .field("time", &self.time)
            .field("counter", &self.counter)
            .field("format", &self.format)
            .field("token_id", &self.token_id)
            .field("alg_id", &self.alg_id)
            .field("vendor", &self.vendor)
            .finish()
    }
}

/// `PA-OTP-ENC-REQUEST ::= SEQUENCE { nonce [0] OCTET STRING, ... }`
///
/// One plaintext a [`PaOtpRequest`]'s `encData` can hold (the other is PA-ENC-TS-ENC),
/// encrypted under key usage 45 ([`crate::ku::PA_OTP_REQUEST`]).
/// MIT `pa_otp_enc_req` (`lib/krb5/asn.1/asn1_k_encode.c:1633-1633`): the SEQUENCE of `krb5_data` with the field table `pa_otp_enc_req_fields`.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaOtpEncRequest {
    /// `nonce [0]`: the nonce.
    #[rasn(tag(0))]
    pub nonce: OctetString,
}
