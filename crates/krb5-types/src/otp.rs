// MIT: `utf8string` (lib/krb5/asn.1/asn1_k_encode.c:89-91)
// a byte string that is never checked as

use std::fmt;

use rasn::prelude::*;

use crate::pkinit::CmsAlgorithmIdentifier;
use crate::{EncryptedData, KerberosFlags, KerberosString, KerberosTime, OctetString};

// MIT: `KRB5_OTP_FLAG_NEXTOTP` (include/k5-int.h:511-511)
// 0x40000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_NEXTOTP: u32 = 0x4000_0000;
// MIT: `KRB5_OTP_FLAG_COMBINE` (include/k5-int.h:512-512)
// 0x20000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_COMBINE: u32 = 0x2000_0000;
// MIT: `KRB5_OTP_FLAG_COLLECT_PIN` (include/k5-int.h:513-513)
// 0x10000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_COLLECT_PIN: u32 = 0x1000_0000;
// MIT: `KRB5_OTP_FLAG_NO_COLLECT_PIN` (include/k5-int.h:514-514)
// 0x08000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_NO_COLLECT_PIN: u32 = 0x0800_0000;
// MIT: `KRB5_OTP_FLAG_ENCRYPT_NONCE` (include/k5-int.h:515-515)
// 0x04000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_ENCRYPT_NONCE: u32 = 0x0400_0000;
// MIT: `KRB5_OTP_FLAG_SEPARATE_PIN` (include/k5-int.h:516-516)
// 0x02000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_SEPARATE_PIN: u32 = 0x0200_0000;
// MIT: `KRB5_OTP_FLAG_CHECK_DIGIT` (include/k5-int.h:517-517)
// 0x01000000 in MIT's 32-bit flag word.
pub const OTP_FLAG_CHECK_DIGIT: u32 = 0x0100_0000;

// MIT: `KRB5_OTP_FORMAT_DECIMAL` (include/k5-int.h:519-519)
// 0, the value of `decimal`.
pub const OTP_FORMAT_DECIMAL: i32 = 0;
// MIT: `KRB5_OTP_FORMAT_HEXADECIMAL` (include/k5-int.h:520-520)
// 1, the value of `hexadecimal`.
pub const OTP_FORMAT_HEXADECIMAL: i32 = 1;
// MIT: `KRB5_OTP_FORMAT_ALPHANUMERIC` (include/k5-int.h:521-521)
// 2, the value of `alphanumeric`.
pub const OTP_FORMAT_ALPHANUMERIC: i32 = 2;
// MIT: `KRB5_OTP_FORMAT_BINARY` (include/k5-int.h:522-522)
// 3, the value of `binary`.
pub const OTP_FORMAT_BINARY: i32 = 3;
// MIT: `KRB5_OTP_FORMAT_BASE64` (include/k5-int.h:523-523)
// 4, the value of `base64`.
pub const OTP_FORMAT_BASE64: i32 = 4;

// MIT: `otp_tokeninfo` (lib/krb5/asn.1/asn1_k_encode.c:1579-1579)
// the SEQUENCE of `krb5_otp_tokeninfo` with the field table `otp_tokeninfo_fields`.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct OtpTokenInfo {
    #[rasn(tag(0))]
    pub flags: KerberosFlags,
    #[rasn(tag(1))]
    pub vendor: Option<OctetString>,
    #[rasn(tag(2))]
    pub challenge: Option<OctetString>,
    // MIT: `opt_int32_minus1` (lib/krb5/asn.1/asn1_k_encode.c:49-49)
    // an int32 of -1 is absent, so `None` is MIT's -1.
    #[rasn(tag(3))]
    pub length: Option<i32>,
    #[rasn(tag(4))]
    pub format: Option<i32>,
    #[rasn(tag(5))]
    pub token_id: Option<OctetString>,
    #[rasn(tag(6))]
    pub alg_id: Option<OctetString>,
    // MIT: `tokinfo_7` (lib/krb5/asn.1/asn1_k_encode.c:1570-1571)
    // `supported_hash_alg` is the optional SEQUENCE OF AlgorithmIdentifier under implicit tag 7.
    #[rasn(tag(7))]
    pub supported_hash_alg: Option<SequenceOf<CmsAlgorithmIdentifier>>,
    #[rasn(tag(8))]
    pub iteration_count: Option<i32>,
}

// MIT: `KRB5_PADATA_OTP_CHALLENGE` (krb5.hin:1838-1838)
// 141, the padata type that carries it.
// MIT: `pa_otp_challenge` (lib/krb5/asn.1/asn1_k_encode.c:1598-1598)
// the SEQUENCE of `krb5_pa_otp_challenge` with the field table `pa_otp_challenge_fields`.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaOtpChallenge {
    #[rasn(tag(0))]
    pub nonce: OctetString,
    #[rasn(tag(1))]
    pub service: Option<OctetString>,
    // MIT: `otp_ch_2` (lib/krb5/asn.1/asn1_k_encode.c:1589-1590)
    // `token_info` is the SEQUENCE OF OTP-TOKENINFO under implicit tag 2.
    #[rasn(tag(2))]
    pub token_info: SequenceOf<OtpTokenInfo>,
    #[rasn(tag(3))]
    pub salt: Option<KerberosString>,
    #[rasn(tag(4))]
    pub s2kparams: Option<OctetString>,
}

// MIT: `KRB5_PADATA_OTP_REQUEST` (krb5.hin:1839-1839)
// 142, the padata type that carries it.
// MIT: `pa_otp_req` (lib/krb5/asn.1/asn1_k_encode.c:1625-1625)
// the SEQUENCE of `krb5_pa_otp_req` with the field table `pa_otp_req_fields`.
#[derive(AsnType, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaOtpRequest {
    #[rasn(tag(0))]
    pub flags: KerberosFlags,
    #[rasn(tag(1))]
    pub nonce: Option<OctetString>,
    // MIT: `otp_req_2` (lib/krb5/asn.1/asn1_k_encode.c:1604-1604)
    // `enc_data` is an `encrypted_data` under implicit tag 2.
    #[rasn(tag(2))]
    pub enc_data: EncryptedData,
    // MIT: `otp_req_3` (lib/krb5/asn.1/asn1_k_encode.c:1605-1606)
    // `hash_alg` is an optional AlgorithmIdentifier under implicit tag 3.
    #[rasn(tag(3))]
    pub hash_alg: Option<CmsAlgorithmIdentifier>,
    #[rasn(tag(4))]
    pub iteration_count: Option<i32>,
    #[rasn(tag(5))]
    pub otp_value: Option<OctetString>,
    #[rasn(tag(6))]
    pub pin: Option<OctetString>,
    #[rasn(tag(7))]
    pub challenge: Option<OctetString>,
    // MIT: `otp_req_8` (lib/krb5/asn.1/asn1_k_encode.c:1612-1612)
    // `time` is an optional KerberosTime under implicit tag 8.
    #[rasn(tag(8))]
    pub time: Option<KerberosTime>,
    #[rasn(tag(9))]
    pub counter: Option<OctetString>,
    #[rasn(tag(10))]
    pub format: Option<i32>,
    #[rasn(tag(11))]
    pub token_id: Option<OctetString>,
    #[rasn(tag(12))]
    pub alg_id: Option<OctetString>,
    #[rasn(tag(13))]
    pub vendor: Option<OctetString>,
}

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

// MIT: `k5_free_pa_otp_req` (lib/krb5/krb/kfree.c:813)
impl Drop for PaOtpRequest {
    fn drop(&mut self) {
        if let Some(v) = self.otp_value.take() {
            crate::wipe::wipe_octets(v);
        }
        if let Some(p) = self.pin.take() {
            crate::wipe::wipe_octets(p);
        }
    }
}

// MIT: `pa_otp_enc_req` (lib/krb5/asn.1/asn1_k_encode.c:1633-1633)
// the SEQUENCE of `krb5_data` with the field table `pa_otp_enc_req_fields`.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaOtpEncRequest {
    #[rasn(tag(0))]
    pub nonce: OctetString,
}
