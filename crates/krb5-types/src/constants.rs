pub mod err {
    pub const NONE: i32 = 0;
    pub const NAME_EXP: i32 = 1;
    pub const SERVICE_EXP: i32 = 2;
    pub const BAD_PVNO: i32 = 3;
    pub const C_OLD_MAST_KVNO: i32 = 4;
    pub const S_OLD_MAST_KVNO: i32 = 5;
    pub const C_PRINCIPAL_UNKNOWN: i32 = 6;
    pub const S_PRINCIPAL_UNKNOWN: i32 = 7;
    pub const PRINCIPAL_NOT_UNIQUE: i32 = 8;
    pub const NULL_KEY: i32 = 9;
    pub const CANNOT_POSTDATE: i32 = 10;
    pub const NEVER_VALID: i32 = 11;
    pub const POLICY: i32 = 12;
    pub const BADOPTION: i32 = 13;
    pub const ETYPE_NOSUPP: i32 = 14;
    pub const SUMTYPE_NOSUPP: i32 = 15;
    pub const PADATA_TYPE_NOSUPP: i32 = 16;
    pub const TRTYPE_NOSUPP: i32 = 17;
    pub const CLIENT_REVOKED: i32 = 18;
    pub const SERVICE_REVOKED: i32 = 19;
    pub const TGT_REVOKED: i32 = 20;
    pub const CLIENT_NOTYET: i32 = 21;
    pub const SERVICE_NOTYET: i32 = 22;
    pub const KEY_EXPIRED: i32 = 23;
    pub const PREAUTH_FAILED: i32 = 24;
    pub const PREAUTH_REQUIRED: i32 = 25;
    pub const SERVER_NOMATCH: i32 = 26;
    pub const MUST_USE_USER2USER: i32 = 27;
    pub const PATH_NOT_ACCEPTED: i32 = 28;
    pub const SVC_UNAVAILABLE: i32 = 29;
    pub const BAD_INTEGRITY: i32 = 31;
    pub const TKT_EXPIRED: i32 = 32;
    pub const TKT_NYV: i32 = 33;
    pub const REPEAT: i32 = 34;
    pub const NOT_US: i32 = 35;
    pub const BADMATCH: i32 = 36;
    pub const SKEW: i32 = 37;
    pub const BADADDR: i32 = 38;
    pub const BADVERSION: i32 = 39;
    pub const MSG_TYPE: i32 = 40;
    pub const MODIFIED: i32 = 41;
    /// KDC_ERR_PREAUTH_EXPIRED (RFC 6113; IANA 90). Filter maps this to 24.
    pub const PREAUTH_EXPIRED: i32 = 90;
    pub const MORE_PREAUTH_DATA_REQUIRED: i32 = 91;
    pub const UNKNOWN_CRITICAL_FAST_OPTION: i32 = 93;
    pub const BADORDER: i32 = 42;
    pub const ILL_CR_TKT: i32 = 43;
    pub const BADKEYVER: i32 = 44;
    pub const NOKEY: i32 = 45;
    pub const MUT_FAIL: i32 = 46;
    pub const BADDIRECTION: i32 = 47;
    pub const METHOD: i32 = 48;
    pub const BADSEQ: i32 = 49;
    pub const INAPP_CKSUM: i32 = 50;
    pub const AP_PATH_NOT_ACCEPTED: i32 = 51;
    pub const RESPONSE_TOO_BIG: i32 = 52;
    pub const GENERIC: i32 = 60;
    pub const FIELD_TOOLONG: i32 = 61;
    pub const CLIENT_NOT_TRUSTED: i32 = 62;
    pub const INVALID_SIG: i32 = 64;
    pub const DH_KEY_PARAMETERS_NOT_ACCEPTED: i32 = 65;
    pub const CERTIFICATE_MISMATCH: i32 = 66;
    pub const NO_TGT: i32 = 67;
    pub const WRONG_REALM: i32 = 68;
    pub const USER_TO_USER_REQUIRED: i32 = 69;
    pub const CANT_VERIFY_CERTIFICATE: i32 = 70;
    pub const INVALID_CERTIFICATE: i32 = 71;
    pub const CLIENT_NAME_MISMATCH: i32 = 75;
    pub const KDC_NAME_MISMATCH: i32 = 76;
    pub const INCONSISTENT_KEY_PURPOSE: i32 = 77;
    pub const DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED: i32 = 80;
    /// invalid flag set". A library-local code, not an RFC 4120 wire number.
    // MIT: `errcode_to_protocol` (kdc_util.c:691-697)
    // clamps offsets over 128 to `GENERIC`
    pub const TKT_INVALID: i32 = 145;
    /// com_err base ×256 with the 2³² wrap). Library-local: not an RFC 4120
    // MIT filter_preauth_error; see docs/parity/a3-preauth.md
    // MIT finish_process_as_req; see docs/parity/b1-crypto-keys.md
    // MIT: `finish_dispatch_cache` (dispatch.c:78-78)
    // keeps the request's null lookaside
    pub const DISCARD: i32 = -1_750_600_189;
}

pub mod ku {
    pub const PA_ENC_TIMESTAMP: u32 = 1;
    pub const TICKET: u32 = 2;
    pub const AS_REP_ENC_PART: u32 = 3;
    pub const TGS_REQ_AD_SESSKEY: u32 = 4;
    pub const TGS_REQ_AD_SUBKEY: u32 = 5;
    pub const TGS_REQ_AUTH_CKSUM: u32 = 6;
    pub const TGS_REQ_AUTHENTICATOR: u32 = 7;
    pub const TGS_REP_ENC_PART: u32 = 8;
    pub const TGS_REP_ENC_PART_SUBKEY: u32 = 9;
    pub const AP_REQ_AUTH_CKSUM: u32 = 10;
    pub const AP_REQ_AUTHENTICATOR: u32 = 11;
    pub const AP_REP_ENC_PART: u32 = 12;
    pub const KRB_PRIV_ENC_PART: u32 = 13;
    pub const KRB_CRED_ENC_PART: u32 = 14;
    pub const KRB_SAFE_CKSUM: u32 = 15;
    pub const PA_FOR_USER: u32 = 17;
    pub const KERB_NON_KERB_CKSUM_SALT: u32 = 17;
    pub const GSS_ACCEPTOR_SEAL: u32 = 22;
    pub const GSS_ACCEPTOR_SIGN: u32 = 23;
    pub const GSS_INITIATOR_SEAL: u32 = 24;
    pub const GSS_INITIATOR_SIGN: u32 = 25;
    // MIT: `verify_s4u_x509_user_checksum` (kdc_util.c:1374-1374)
    // the request checksum is
    pub const PA_S4U_X509_USER_REQUEST: u32 = 26;
    // MIT kdc_make_s4u2self_rep; see docs/parity/a2-as.md
    pub const PA_S4U_X509_USER_REPLY: u32 = 27;
    pub const FAST_REQ_CHKSUM: u32 = 50;
    pub const FAST_ENC: u32 = 51;
    pub const FAST_REP: u32 = 52;
    pub const FAST_FINISHED: u32 = 53;
    #[allow(dead_code)]
    pub const FAST_COOKIE: u32 = 54;
    // MIT: `KRB5_KEYUSAGE_PA_FX_COOKIE` (krb5.hin:1006-1006)
    // 513, used for encrypted FAST
    pub const PA_FX_COOKIE: u32 = 513;
    // MIT: `KRB5_KEYUSAGE_PA_AS_FRESHNESS` (krb5.hin:1007-1007)
    // 514, used for freshness
    pub const PA_AS_FRESHNESS: u32 = 514;
    pub const ENC_CHALLENGE_CLIENT: u32 = 54;
    pub const ENC_CHALLENGE_KDC: u32 = 55;
    pub const AS_REQ: u32 = 56;
    pub const AD_KDCISSUED_CKSUM: u32 = 19;
    pub const CAMMAC: u32 = 64;
    pub const SPAKE: u32 = 65;
    // MIT: `KRB5_KEYUSAGE_PA_PKINIT_KX` (krb5.hin:991-991)
    // the PA-PKINIT-KX key usage, 44.
    pub const PA_PKINIT_KX: u32 = 44;
    // MIT: `KRB5_KEYUSAGE_PA_OTP_REQUEST` (krb5.hin:992-992)
    // 45, the key usage of PA-OTP-REQUEST (see RFC 6560 section 4.2).
    pub const PA_OTP_REQUEST: u32 = 45;
}

pub mod pa {
    pub const TGS_REQ: i32 = 1;
    pub const ENC_TIMESTAMP: i32 = 2;
    pub const PW_SALT: i32 = 3;
    pub const ENC_UNIX_TIME: i32 = 5;
    pub const SANDIA_SECUREID: i32 = 6;
    pub const SESAME: i32 = 7;
    pub const OSF_DCE: i32 = 8;
    pub const CYBERSAFE_SECUREID: i32 = 9;
    pub const AFS3_SALT: i32 = 10;
    pub const ETYPE_INFO: i32 = 11;
    pub const SAM_CHALLENGE: i32 = 12;
    pub const SAM_RESPONSE: i32 = 13;
    pub const PK_AS_REQ: i32 = 16;
    pub const PK_AS_REP: i32 = 17;
    pub const ETYPE_INFO2: i32 = 19;
    pub const TD_TRUSTED_CERTIFIERS: i32 = 104;
    pub const TD_INVALID_CERTIFICATES: i32 = 105;
    pub const TD_DH_PARAMETERS: i32 = 109;
    pub const SVR_REFERRAL_INFO: i32 = 20;
    pub const PAC_REQUEST: i32 = 128;
    pub const FOR_USER: i32 = 129;
    pub const FOR_X509_USER: i32 = 130;
    pub const FX_COOKIE: i32 = 133;
    pub const FX_FAST: i32 = 136;
    pub const FX_ERROR: i32 = 137;
    pub const ENCRYPTED_CHALLENGE: i32 = 138;
    pub const OTP_CHALLENGE: i32 = 141;
    pub const OTP_REQUEST: i32 = 142;
    pub const OTP_PIN_CHANGE: i32 = 144;
    pub const PKINIT_KX: i32 = 147;
    pub const REQ_ENC_PA_REP: i32 = 149;
    pub const AS_FRESHNESS: i32 = 150;
    pub const SPAKE: i32 = 151;
    pub const REDHAT_IDP_OAUTH2: i32 = 152;
    pub const AD_WIN2K_PAC: i32 = 128;
    pub const AD_IF_RELEVANT: i32 = 1;
    pub const AD_KDC_ISSUED: i32 = 4;
    pub const AD_AND_OR: i32 = 5;
    pub const AD_MANDATORY_FOR_KDC: i32 = 8;
    pub const AD_FX_ARMOR: i32 = 71;
    pub const AD_CAMMAC: i32 = 96;
    pub const AD_AUTH_INDICATOR: i32 = 97;
    pub const AD_ETYPE_NEGOTIATION: i32 = 129;
    pub const AD_SIGNTICKET: i32 = 512;
    pub const PAC_OPTIONS: i32 = 167;
}

pub mod flag_bit {
    pub const RESERVED: usize = 0;
    pub const FORWARDABLE: usize = 1;
    pub const FORWARDED: usize = 2;
    pub const PROXIABLE: usize = 3;
    pub const PROXY: usize = 4;
    pub const MAY_POSTDATE: usize = 5;
    pub const POSTDATED: usize = 6;
    pub const INVALID: usize = 7;
    pub const RENEWABLE: usize = 8;
    pub const INITIAL: usize = 9;
    pub const PRE_AUTHENT: usize = 10;
    pub const HW_AUTHENT: usize = 11;
    pub const TRANSITED_POLICY_CHECKED: usize = 12;
    pub const OK_AS_DELEGATE: usize = 13;
    pub const CNAME_IN_ADDL_TKT: usize = 14;
    /// canonicalize(15) (KDCOptions). TicketFlags bit 15 is RFC 6806 `enc-pa-rep`.
    pub const CANONICALIZE: usize = 15;
    pub const ENC_PA_REP: usize = 15;
    pub const ANONYMOUS: usize = 16;
    pub const DISABLE_TRANSITED_CHECK: usize = 26;
    pub const RENEWABLE_OK: usize = 27;
    pub const ENC_TKT_IN_SKEY: usize = 28;
    pub const RENEW: usize = 30;
    pub const VALIDATE: usize = 31;
}

pub mod ap_bit {
    pub const RESERVED: usize = 0;
    pub const USE_SESSION_KEY: usize = 1;
    pub const MUTUAL_REQUIRED: usize = 2;
}
