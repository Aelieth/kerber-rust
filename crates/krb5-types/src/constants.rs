//! RFC 4120 error codes, key-usage numbers, and PA-DATA types.

/// RFC 4120 and related error codes used by the client and KDC.
pub mod err {
    /// KDC_ERR_NONE
    pub const NONE: i32 = 0;
    /// KDC_ERR_NAME_EXP
    pub const NAME_EXP: i32 = 1;
    /// KDC_ERR_SERVICE_EXP
    pub const SERVICE_EXP: i32 = 2;
    /// KDC_ERR_BAD_PVNO
    pub const BAD_PVNO: i32 = 3;
    /// KDC_ERR_C_OLD_MAST_KVNO
    pub const C_OLD_MAST_KVNO: i32 = 4;
    /// KDC_ERR_S_OLD_MAST_KVNO
    pub const S_OLD_MAST_KVNO: i32 = 5;
    /// KDC_ERR_C_PRINCIPAL_UNKNOWN
    pub const C_PRINCIPAL_UNKNOWN: i32 = 6;
    /// KDC_ERR_S_PRINCIPAL_UNKNOWN
    pub const S_PRINCIPAL_UNKNOWN: i32 = 7;
    /// KDC_ERR_PRINCIPAL_NOT_UNIQUE
    pub const PRINCIPAL_NOT_UNIQUE: i32 = 8;
    /// KDC_ERR_NULL_KEY
    pub const NULL_KEY: i32 = 9;
    /// KDC_ERR_CANNOT_POSTDATE
    pub const CANNOT_POSTDATE: i32 = 10;
    /// KDC_ERR_NEVER_VALID
    pub const NEVER_VALID: i32 = 11;
    /// KDC_ERR_POLICY
    pub const POLICY: i32 = 12;
    /// KDC_ERR_BADOPTION
    pub const BADOPTION: i32 = 13;
    /// KDC_ERR_ETYPE_NOSUPP
    pub const ETYPE_NOSUPP: i32 = 14;
    /// KDC_ERR_SUMTYPE_NOSUPP
    pub const SUMTYPE_NOSUPP: i32 = 15;
    /// KDC_ERR_PADATA_TYPE_NOSUPP
    pub const PADATA_TYPE_NOSUPP: i32 = 16;
    /// KDC_ERR_TRTYPE_NOSUPP
    pub const TRTYPE_NOSUPP: i32 = 17;
    /// KDC_ERR_CLIENT_REVOKED
    pub const CLIENT_REVOKED: i32 = 18;
    /// KDC_ERR_SERVICE_REVOKED
    pub const SERVICE_REVOKED: i32 = 19;
    /// KDC_ERR_TGT_REVOKED
    pub const TGT_REVOKED: i32 = 20;
    /// KDC_ERR_CLIENT_NOTYET
    pub const CLIENT_NOTYET: i32 = 21;
    /// KDC_ERR_SERVICE_NOTYET
    pub const SERVICE_NOTYET: i32 = 22;
    /// KDC_ERR_KEY_EXPIRED
    pub const KEY_EXPIRED: i32 = 23;
    /// KDC_ERR_PREAUTH_FAILED
    pub const PREAUTH_FAILED: i32 = 24;
    /// KDC_ERR_PREAUTH_REQUIRED
    pub const PREAUTH_REQUIRED: i32 = 25;
    /// KDC_ERR_SERVER_NOMATCH
    pub const SERVER_NOMATCH: i32 = 26;
    /// KDC_ERR_MUST_USE_USER2USER
    pub const MUST_USE_USER2USER: i32 = 27;
    /// KDC_ERR_PATH_NOT_ACCEPTED
    pub const PATH_NOT_ACCEPTED: i32 = 28;
    /// KDC_ERR_SVC_UNAVAILABLE
    pub const SVC_UNAVAILABLE: i32 = 29;
    /// KRB_AP_ERR_BAD_INTEGRITY
    pub const BAD_INTEGRITY: i32 = 31;
    /// KRB_AP_ERR_TKT_EXPIRED
    pub const TKT_EXPIRED: i32 = 32;
    /// KRB_AP_ERR_TKT_NYV
    pub const TKT_NYV: i32 = 33;
    /// KRB_AP_ERR_REPEAT
    pub const REPEAT: i32 = 34;
    /// KRB_AP_ERR_NOT_US
    pub const NOT_US: i32 = 35;
    /// KRB_AP_ERR_BADMATCH
    pub const BADMATCH: i32 = 36;
    /// KRB_AP_ERR_SKEW
    pub const SKEW: i32 = 37;
    /// KRB_AP_ERR_BADADDR
    pub const BADADDR: i32 = 38;
    /// KRB_AP_ERR_BADVERSION
    pub const BADVERSION: i32 = 39;
    /// KRB_AP_ERR_MSG_TYPE
    pub const MSG_TYPE: i32 = 40;
    /// KRB_AP_ERR_MODIFIED
    pub const MODIFIED: i32 = 41;
    /// KDC_ERR_MORE_PREAUTH_DATA_REQUIRED (RFC 6113; IANA 91)
    pub const MORE_PREAUTH_DATA_REQUIRED: i32 = 91;
    /// KRB_AP_ERR_BADORDER
    pub const BADORDER: i32 = 42;
    /// KRB_AP_ERR_BADKEYVER
    pub const BADKEYVER: i32 = 44;
    /// KRB_AP_ERR_NOKEY
    pub const NOKEY: i32 = 45;
    /// KRB_AP_ERR_MUT_FAIL
    pub const MUT_FAIL: i32 = 46;
    /// KRB_AP_ERR_BADDIRECTION
    pub const BADDIRECTION: i32 = 47;
    /// KRB_AP_ERR_METHOD
    pub const METHOD: i32 = 48;
    /// KRB_AP_ERR_BADSEQ
    pub const BADSEQ: i32 = 49;
    /// KRB_AP_ERR_INAPP_CKSUM
    pub const INAPP_CKSUM: i32 = 50;
    /// KRB_AP_PATH_NOT_ACCEPTED
    pub const AP_PATH_NOT_ACCEPTED: i32 = 51;
    /// KRB_ERR_RESPONSE_TOO_BIG
    pub const RESPONSE_TOO_BIG: i32 = 52;
    /// KRB_ERR_GENERIC
    pub const GENERIC: i32 = 60;
    /// KRB_ERR_FIELD_TOOLONG
    pub const FIELD_TOOLONG: i32 = 61;
    /// KDC_ERR_CLIENT_NOT_TRUSTED (PKINIT)
    pub const CLIENT_NOT_TRUSTED: i32 = 62;
    /// KDC_ERR_INVALID_SIG
    pub const INVALID_SIG: i32 = 64;
    /// KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED (PKINIT)
    pub const DH_KEY_PARAMETERS_NOT_ACCEPTED: i32 = 65;
    /// KRB_AP_ERR_NO_TGT
    pub const NO_TGT: i32 = 67;
    /// KDC_ERR_WRONG_REALM
    pub const WRONG_REALM: i32 = 68;
    /// KRB_AP_ERR_USER_TO_USER_REQUIRED
    pub const USER_TO_USER_REQUIRED: i32 = 69;
}

/// RFC 4120 / 4121 / 6113 key-usage numbers.
pub mod ku {
    /// AS-REQ PA-ENC-TIMESTAMP.
    pub const PA_ENC_TIMESTAMP: u32 = 1;
    /// Ticket enc-part (service long-term key).
    pub const TICKET: u32 = 2;
    /// AS-REP encrypted part (client long-term key).
    pub const AS_REP_ENC_PART: u32 = 3;
    /// TGS-REQ KDC-REQ-BODY AuthorizationData, session key.
    pub const TGS_REQ_AD_SESSKEY: u32 = 4;
    /// TGS-REQ KDC-REQ-BODY AuthorizationData, subkey.
    pub const TGS_REQ_AD_SUBKEY: u32 = 5;
    /// TGS-REQ authenticator checksum.
    pub const TGS_REQ_AUTH_CKSUM: u32 = 6;
    /// TGS-REQ authenticator.
    pub const TGS_REQ_AUTHENTICATOR: u32 = 7;
    /// TGS-REP encrypted part (TGT session key).
    pub const TGS_REP_ENC_PART: u32 = 8;
    /// TGS-REP encrypted part (authenticator subkey).
    pub const TGS_REP_ENC_PART_SUBKEY: u32 = 9;
    /// AP-REQ authenticator checksum.
    pub const AP_REQ_AUTH_CKSUM: u32 = 10;
    /// AP-REQ authenticator.
    pub const AP_REQ_AUTHENTICATOR: u32 = 11;
    /// AP-REP encrypted part.
    pub const AP_REP_ENC_PART: u32 = 12;
    /// KRB-PRIV encrypted part.
    pub const KRB_PRIV_ENC_PART: u32 = 13;
    /// KRB-CRED encrypted part.
    pub const KRB_CRED_ENC_PART: u32 = 14;
    /// KRB-SAFE checksum.
    pub const KRB_SAFE_CKSUM: u32 = 15;
    /// PA-FOR-USER checksum (S4U2Self). Same number as KERB_NON_KERB_CKSUM_SALT.
    pub const PA_FOR_USER: u32 = 17;
    /// PAC checksum key usage (MS-PAC `KERB_NON_KERB_CKSUM_SALT`).
    pub const KERB_NON_KERB_CKSUM_SALT: u32 = 17;
    /// GSS acceptor seal (RFC 4121).
    pub const GSS_ACCEPTOR_SEAL: u32 = 22;
    /// GSS acceptor sign (RFC 4121).
    pub const GSS_ACCEPTOR_SIGN: u32 = 23;
    /// GSS initiator seal (RFC 4121).
    pub const GSS_INITIATOR_SEAL: u32 = 24;
    /// GSS initiator sign (RFC 4121).
    pub const GSS_INITIATOR_SIGN: u32 = 25;
    /// RFC 6113 FAST request checksum.
    pub const FAST_REQ_CHKSUM: u32 = 50;
    /// RFC 6113 FAST encrypted request.
    pub const FAST_ENC: u32 = 51;
    /// RFC 6113 FAST response.
    pub const FAST_REP: u32 = 52;
    /// RFC 6113 FAST finished.
    pub const FAST_FINISHED: u32 = 53;
    /// Cookie encrypted under the krbtgt key (local helper, not an RFC number).
    pub const FAST_COOKIE: u32 = 54;
    /// SPAKE factor encryption (MIT `KRB5_KEYUSAGE_SPAKE`).
    pub const SPAKE: u32 = 65;
}

/// RFC 4120 / 6113 / 4556 PA-DATA type numbers.
pub mod pa {
    /// PA-TGS-REQ (AP-REQ in TGS-REQ padata).
    pub const TGS_REQ: i32 = 1;
    /// PA-ENC-TIMESTAMP.
    pub const ENC_TIMESTAMP: i32 = 2;
    /// PA-PW-SALT.
    pub const PW_SALT: i32 = 3;
    /// PA-ENC-UNIX-TIME (obsolete).
    pub const ENC_UNIX_TIME: i32 = 5;
    /// PA-SANDIA-SECUREID.
    pub const SANDIA_SECUREID: i32 = 6;
    /// PA-SESAME.
    pub const SESAME: i32 = 7;
    /// PA-OSF-DCE.
    pub const OSF_DCE: i32 = 8;
    /// PA-CYBERSAFE-SECUREID.
    pub const CYBERSAFE_SECUREID: i32 = 9;
    /// PA-AFS3-SALT.
    pub const AFS3_SALT: i32 = 10;
    /// PA-ETYPE-INFO.
    pub const ETYPE_INFO: i32 = 11;
    /// PA-SAM-CHALLENGE.
    pub const SAM_CHALLENGE: i32 = 12;
    /// PA-SAM-RESPONSE.
    pub const SAM_RESPONSE: i32 = 13;
    /// PA-PK-AS-REQ (PKINIT).
    pub const PK_AS_REQ: i32 = 16;
    /// PA-PK-AS-REP (PKINIT).
    pub const PK_AS_REP: i32 = 17;
    /// PA-ETYPE-INFO2.
    pub const ETYPE_INFO2: i32 = 19;
    /// TD-DH-PARAMETERS (PKINIT RFC 4556).
    pub const TD_DH_PARAMETERS: i32 = 109;
    /// PA-SVR-REFERRAL-INFO.
    pub const SVR_REFERRAL_INFO: i32 = 20;
    /// PA-PAC-REQUEST.
    pub const PAC_REQUEST: i32 = 128;
    /// PA-FOR-USER (S4U2Self).
    pub const FOR_USER: i32 = 129;
    /// PA-FOR-X509-USER.
    pub const FOR_X509_USER: i32 = 130;
    /// PA-FX-COOKIE (FAST).
    pub const FX_COOKIE: i32 = 133;
    /// PA-FX-FAST.
    pub const FX_FAST: i32 = 136;
    /// PA-FX-ERROR.
    pub const FX_ERROR: i32 = 137;
    /// PA-ENCRYPTED-CHALLENGE.
    pub const ENCRYPTED_CHALLENGE: i32 = 138;
    /// PA-OTP-CHALLENGE.
    pub const OTP_CHALLENGE: i32 = 141;
    /// PA-OTP-REQUEST.
    pub const OTP_REQUEST: i32 = 142;
    /// PA-OTP-PIN-CHANGE.
    pub const OTP_PIN_CHANGE: i32 = 144;
    /// PA-PKINIT-KX.
    pub const PKINIT_KX: i32 = 147;
    /// PA-SPAKE.
    pub const SPAKE: i32 = 151;
    /// PA-REDHAT-IDP-OAUTH2.
    pub const REDHAT_IDP_OAUTH2: i32 = 152;
    /// AD-WIN2K-PAC authorization-data type.
    pub const AD_WIN2K_PAC: i32 = 128;
    /// AD-IF-RELEVANT.
    pub const AD_IF_RELEVANT: i32 = 1;
    /// AD-KDC-ISSUED.
    pub const AD_KDC_ISSUED: i32 = 4;
    /// AD-AND-OR.
    pub const AD_AND_OR: i32 = 5;
    /// AD-MANDATORY-FOR-KDC.
    pub const AD_MANDATORY_FOR_KDC: i32 = 8;
    /// PA-SUPPORTED-ENCTYPES (Windows).
    pub const SUPPORTED_ENCTYPES: i32 = 165;
    /// PA-PAC-OPTIONS.
    pub const PAC_OPTIONS: i32 = 167;
}

/// RFC 4120 TicketFlags / KDCOptions bit positions (bit 0 is MSB of the first octet).
pub mod flag_bit {
    /// reserved(0)
    pub const RESERVED: usize = 0;
    /// forwardable(1)
    pub const FORWARDABLE: usize = 1;
    /// forwarded(2)
    pub const FORWARDED: usize = 2;
    /// proxiable(3)
    pub const PROXIABLE: usize = 3;
    /// proxy(4)
    pub const PROXY: usize = 4;
    /// may-postdate / allow-postdate(5)
    pub const MAY_POSTDATE: usize = 5;
    /// postdated(6)
    pub const POSTDATED: usize = 6;
    /// invalid(7)
    pub const INVALID: usize = 7;
    /// renewable(8)
    pub const RENEWABLE: usize = 8;
    /// initial(9)
    pub const INITIAL: usize = 9;
    /// pre-authent(10)
    pub const PRE_AUTHENT: usize = 10;
    /// hw-authent(11)
    pub const HW_AUTHENT: usize = 11;
    /// transited-policy-checked(12)
    pub const TRANSITED_POLICY_CHECKED: usize = 12;
    /// ok-as-delegate(13)
    pub const OK_AS_DELEGATE: usize = 13;
    /// canonicalize(15) on KDCOptions; CNAME-IN-ADDL-TKT is 14
    pub const CNAME_IN_ADDL_TKT: usize = 14;
    /// canonicalize(15)
    pub const CANONICALIZE: usize = 15;
    /// disable-transited-check(26)
    pub const DISABLE_TRANSITED_CHECK: usize = 26;
    /// renewable-ok(27)
    pub const RENEWABLE_OK: usize = 27;
    /// enc-tkt-in-skey(28) user-to-user
    pub const ENC_TKT_IN_SKEY: usize = 28;
    /// renew(30)
    pub const RENEW: usize = 30;
    /// validate(31)
    pub const VALIDATE: usize = 31;
}

/// APOptions bits.
pub mod ap_bit {
    /// reserved(0)
    pub const RESERVED: usize = 0;
    /// use-session-key(1)
    pub const USE_SESSION_KEY: usize = 1;
    /// mutual-required(2)
    pub const MUTUAL_REQUIRED: usize = 2;
}
