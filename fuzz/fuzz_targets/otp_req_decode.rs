#![no_main]
use libfuzzer_sys::fuzz_target;

// The KDC decodes PA-OTP-REQUEST (padata type 142) straight from a client's packet, so its
// decoder and the OTP wire types it reaches are untrusted-input attack surface.
fuzz_target!(|data: &[u8]| {
    let _ = krb5_asn1::decode::<krb5_types::otp::PaOtpRequest>(data);
    let _ = krb5_asn1::decode::<krb5_types::otp::PaOtpEncRequest>(data);
    let _ = krb5_asn1::decode::<krb5_types::otp::PaOtpChallenge>(data);
    let _ = krb5_asn1::decode::<krb5_types::otp::OtpTokenInfo>(data);
});
