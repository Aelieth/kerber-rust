//! MIT's `krb5` error table, the texts `{kerr}` prints: entry `n` is the text of code
//! `ERROR_TABLE_BASE_krb5 + n` (`-1765328384 + n`), generated verbatim from MIT's
//! `lib/krb5/error_tables/krb5_err.et`, whose 256 entries run from `KRB5KDC_ERR_NONE` to
//! `KRB5_TRACE_NOSUPP`.

/// The 256 texts, by offset from `ERROR_TABLE_BASE_krb5`.
pub(super) const TEXTS: [&str; 256] = [
    "No error",                                                            // KRB5KDC_ERR_NONE
    "Client's entry in database has expired",                              // KRB5KDC_ERR_NAME_EXP
    "Server's entry in database has expired", // KRB5KDC_ERR_SERVICE_EXP
    "Requested protocol version not supported", // KRB5KDC_ERR_BAD_PVNO
    "Client's key is encrypted in an old master key", // KRB5KDC_ERR_C_OLD_MAST_KVNO
    "Server's key is encrypted in an old master key", // KRB5KDC_ERR_S_OLD_MAST_KVNO
    "Client not found in Kerberos database",  // KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN
    "Server not found in Kerberos database",  // KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN
    "Principal has multiple entries in Kerberos database", // KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE
    "Client or server has a null key",        // KRB5KDC_ERR_NULL_KEY
    "Ticket is ineligible for postdating",    // KRB5KDC_ERR_CANNOT_POSTDATE
    "Requested effective lifetime is negative or too short", // KRB5KDC_ERR_NEVER_VALID
    "KDC policy rejects request",             // KRB5KDC_ERR_POLICY
    "KDC can't fulfill requested option",     // KRB5KDC_ERR_BADOPTION
    "KDC has no support for encryption type", // KRB5KDC_ERR_ETYPE_NOSUPP
    "KDC has no support for checksum type",   // KRB5KDC_ERR_SUMTYPE_NOSUPP
    "KDC has no support for padata type",     // KRB5KDC_ERR_PADATA_TYPE_NOSUPP
    "KDC has no support for transited type",  // KRB5KDC_ERR_TRTYPE_NOSUPP
    "Client's credentials have been revoked", // KRB5KDC_ERR_CLIENT_REVOKED
    "Credentials for server have been revoked", // KRB5KDC_ERR_SERVICE_REVOKED
    "TGT has been revoked",                   // KRB5KDC_ERR_TGT_REVOKED
    "Client not yet valid - try again later", // KRB5KDC_ERR_CLIENT_NOTYET
    "Server not yet valid - try again later", // KRB5KDC_ERR_SERVICE_NOTYET
    "Password has expired",                   // KRB5KDC_ERR_KEY_EXP
    "Preauthentication failed",               // KRB5KDC_ERR_PREAUTH_FAILED
    "Additional pre-authentication required", // KRB5KDC_ERR_PREAUTH_REQUIRED
    "Requested server and ticket don't match", // KRB5KDC_ERR_SERVER_NOMATCH
    "Server principal valid for user2user only", // KRB5KDC_ERR_MUST_USE_USER2USER
    "KDC policy rejects transited path",      // KRB5KDC_ERR_PATH_NOT_ACCEPTED
    "A service is not available that is required to process the request", // KRB5KDC_ERR_SVC_UNAVAILABLE
    "KRB5 error code 30",                                                 // KRB5PLACEHOLD_30
    "Decrypt integrity check failed", // KRB5KRB_AP_ERR_BAD_INTEGRITY
    "Ticket expired",                 // KRB5KRB_AP_ERR_TKT_EXPIRED
    "Ticket not yet valid",           // KRB5KRB_AP_ERR_TKT_NYV
    "Request is a replay",            // KRB5KRB_AP_ERR_REPEAT
    "The ticket isn't for us",        // KRB5KRB_AP_ERR_NOT_US
    "Ticket/authenticator don't match", // KRB5KRB_AP_ERR_BADMATCH
    "Clock skew too great",           // KRB5KRB_AP_ERR_SKEW
    "Incorrect net address",          // KRB5KRB_AP_ERR_BADADDR
    "Protocol version mismatch",      // KRB5KRB_AP_ERR_BADVERSION
    "Invalid message type",           // KRB5KRB_AP_ERR_MSG_TYPE
    "Message stream modified",        // KRB5KRB_AP_ERR_MODIFIED
    "Message out of order",           // KRB5KRB_AP_ERR_BADORDER
    "Illegal cross-realm ticket",     // KRB5KRB_AP_ERR_ILL_CR_TKT
    "Key version is not available",   // KRB5KRB_AP_ERR_BADKEYVER
    "Service key not available",      // KRB5KRB_AP_ERR_NOKEY
    "Mutual authentication failed",   // KRB5KRB_AP_ERR_MUT_FAIL
    "Incorrect message direction",    // KRB5KRB_AP_ERR_BADDIRECTION
    "Alternative authentication method required", // KRB5KRB_AP_ERR_METHOD
    "Incorrect sequence number in message", // KRB5KRB_AP_ERR_BADSEQ
    "Inappropriate type of checksum in message", // KRB5KRB_AP_ERR_INAPP_CKSUM
    "Policy rejects transited path",  // KRB5KRB_AP_PATH_NOT_ACCEPTED
    "Response too big for UDP, retry with TCP", // KRB5KRB_ERR_RESPONSE_TOO_BIG
    "KRB5 error code 53",             // KRB5PLACEHOLD_53
    "KRB5 error code 54",             // KRB5PLACEHOLD_54
    "KRB5 error code 55",             // KRB5PLACEHOLD_55
    "KRB5 error code 56",             // KRB5PLACEHOLD_56
    "KRB5 error code 57",             // KRB5PLACEHOLD_57
    "KRB5 error code 58",             // KRB5PLACEHOLD_58
    "KRB5 error code 59",             // KRB5PLACEHOLD_59
    "Generic error (see e-text)",     // KRB5KRB_ERR_GENERIC
    "Field is too long for this implementation", // KRB5KRB_ERR_FIELD_TOOLONG
    "Client not trusted",             // KRB5KDC_ERR_CLIENT_NOT_TRUSTED
    "KDC not trusted",                // KRB5KDC_ERR_KDC_NOT_TRUSTED
    "Invalid signature",              // KRB5KDC_ERR_INVALID_SIG
    "Key parameters not accepted",    // KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED
    "Certificate mismatch",           // KRB5KDC_ERR_CERTIFICATE_MISMATCH
    "No ticket granting ticket",      // KRB5KRB_AP_ERR_NO_TGT
    "Realm not local to KDC",         // KRB5KDC_ERR_WRONG_REALM
    "User to user required",          // KRB5KRB_AP_ERR_USER_TO_USER_REQUIRED
    "Can't verify certificate",       // KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE
    "Invalid certificate",            // KRB5KDC_ERR_INVALID_CERTIFICATE
    "Revoked certificate",            // KRB5KDC_ERR_REVOKED_CERTIFICATE
    "Revocation status unknown",      // KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN
    "Revocation status unavailable",  // KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE
    "Client name mismatch",           // KRB5KDC_ERR_CLIENT_NAME_MISMATCH
    "KDC name mismatch",              // KRB5KDC_ERR_KDC_NAME_MISMATCH
    "Inconsistent key purpose",       // KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE
    "Digest in certificate not accepted", // KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED
    "Checksum must be included",      // KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED
    "Digest in signed-data not accepted", // KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED
    "Public key encryption not supported", // KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED
    "KRB5 error code 82",             // KRB5PLACEHOLD_82
    "KRB5 error code 83",             // KRB5PLACEHOLD_83
    "KRB5 error code 84",             // KRB5PLACEHOLD_84
    "The IAKERB proxy could not find a KDC", // KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND
    "The KDC did not respond to the IAKERB proxy", // KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE
    "KRB5 error code 87",             // KRB5PLACEHOLD_87
    "KRB5 error code 88",             // KRB5PLACEHOLD_88
    "KRB5 error code 89",             // KRB5PLACEHOLD_89
    "Preauthentication expired",      // KRB5KDC_ERR_PREAUTH_EXPIRED
    "More preauthentication data is required", // KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED
    "KRB5 error code 92",             // KRB5PLACEHOLD_92
    "An unsupported critical FAST option was requested", // KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION
    "KRB5 error code 94",             // KRB5PLACEHOLD_94
    "KRB5 error code 95",             // KRB5PLACEHOLD_95
    "KRB5 error code 96",             // KRB5PLACEHOLD_96
    "KRB5 error code 97",             // KRB5PLACEHOLD_97
    "KRB5 error code 98",             // KRB5PLACEHOLD_98
    "KRB5 error code 99",             // KRB5PLACEHOLD_99
    "No acceptable KDF offered",      // KRB5KDC_ERR_NO_ACCEPTABLE_KDF
    "KRB5 error code 101",            // KRB5PLACEHOLD_101
    "KRB5 error code 102",            // KRB5PLACEHOLD_102
    "KRB5 error code 103",            // KRB5PLACEHOLD_103
    "KRB5 error code 104",            // KRB5PLACEHOLD_104
    "KRB5 error code 105",            // KRB5PLACEHOLD_105
    "KRB5 error code 106",            // KRB5PLACEHOLD_106
    "KRB5 error code 107",            // KRB5PLACEHOLD_107
    "KRB5 error code 108",            // KRB5PLACEHOLD_108
    "KRB5 error code 109",            // KRB5PLACEHOLD_109
    "KRB5 error code 110",            // KRB5PLACEHOLD_110
    "KRB5 error code 111",            // KRB5PLACEHOLD_111
    "KRB5 error code 112",            // KRB5PLACEHOLD_112
    "KRB5 error code 113",            // KRB5PLACEHOLD_113
    "KRB5 error code 114",            // KRB5PLACEHOLD_114
    "KRB5 error code 115",            // KRB5PLACEHOLD_115
    "KRB5 error code 116",            // KRB5PLACEHOLD_116
    "KRB5 error code 117",            // KRB5PLACEHOLD_117
    "KRB5 error code 118",            // KRB5PLACEHOLD_118
    "KRB5 error code 119",            // KRB5PLACEHOLD_119
    "KRB5 error code 120",            // KRB5PLACEHOLD_120
    "KRB5 error code 121",            // KRB5PLACEHOLD_121
    "KRB5 error code 122",            // KRB5PLACEHOLD_122
    "KRB5 error code 123",            // KRB5PLACEHOLD_123
    "KRB5 error code 124",            // KRB5PLACEHOLD_124
    "KRB5 error code 125",            // KRB5PLACEHOLD_125
    "KRB5 error code 126",            // KRB5PLACEHOLD_126
    "KRB5 error code 127",            // KRB5PLACEHOLD_127
    "$Id$",                           // KRB5_ERR_RCSID
    "Invalid flag for file lock mode", // KRB5_LIBOS_BADLOCKFLAG
    "Cannot read password",           // KRB5_LIBOS_CANTREADPWD
    "Password mismatch",              // KRB5_LIBOS_BADPWDMATCH
    "Password read interrupted",      // KRB5_LIBOS_PWDINTR
    "Illegal character in component name", // KRB5_PARSE_ILLCHAR
    "Malformed representation of principal", // KRB5_PARSE_MALFORMED
    "Can't open/find Kerberos configuration file", // KRB5_CONFIG_CANTOPEN
    "Improper format of Kerberos configuration file", // KRB5_CONFIG_BADFORMAT
    "Insufficient space to return complete information", // KRB5_CONFIG_NOTENUFSPACE
    "Invalid message type specified for encoding", // KRB5_BADMSGTYPE
    "Credential cache name malformed", // KRB5_CC_BADNAME
    "Unknown credential cache type",  // KRB5_CC_UNKNOWN_TYPE
    "Matching credential not found",  // KRB5_CC_NOTFOUND
    "End of credential cache reached", // KRB5_CC_END
    "Request did not supply a ticket", // KRB5_NO_TKT_SUPPLIED
    "Wrong principal in request",     // KRB5KRB_AP_WRONG_PRINC
    "Ticket has invalid flag set",    // KRB5KRB_AP_ERR_TKT_INVALID
    "Requested principal and ticket don't match", // KRB5_PRINC_NOMATCH
    "KDC reply did not match expectations", // KRB5_KDCREP_MODIFIED
    "Clock skew too great in KDC reply", // KRB5_KDCREP_SKEW
    "Client/server realm mismatch in initial ticket request", // KRB5_IN_TKT_REALM_MISMATCH
    "Program lacks support for encryption type", // KRB5_PROG_ETYPE_NOSUPP
    "Program lacks support for key type", // KRB5_PROG_KEYTYPE_NOSUPP
    "Requested encryption type not used in message", // KRB5_WRONG_ETYPE
    "Program lacks support for checksum type", // KRB5_PROG_SUMTYPE_NOSUPP
    "Cannot find KDC for requested realm", // KRB5_REALM_UNKNOWN
    "Kerberos service unknown",       // KRB5_SERVICE_UNKNOWN
    "Cannot contact any KDC for requested realm", // KRB5_KDC_UNREACH
    "No local name found for principal name", // KRB5_NO_LOCALNAME
    "Mutual authentication failed",   // KRB5_MUTUAL_FAILED
    "Replay cache type is already registered", // KRB5_RC_TYPE_EXISTS
    "No more memory to allocate (in replay cache code)", // KRB5_RC_MALLOC
    "Replay cache type is unknown",   // KRB5_RC_TYPE_NOTFOUND
    "Generic unknown RC error",       // KRB5_RC_UNKNOWN
    "Message is a replay",            // KRB5_RC_REPLAY
    "Replay cache I/O operation failed", // KRB5_RC_IO
    "Replay cache type does not support non-volatile storage", // KRB5_RC_NOIO
    "Replay cache name parse/format error", // KRB5_RC_PARSE
    "End-of-file on replay cache I/O", // KRB5_RC_IO_EOF
    "No more memory to allocate (in replay cache I/O code)", // KRB5_RC_IO_MALLOC
    "Permission denied in replay cache code", // KRB5_RC_IO_PERM
    "I/O error in replay cache i/o code", // KRB5_RC_IO_IO
    "Generic unknown RC/IO error",    // KRB5_RC_IO_UNKNOWN
    "Insufficient system space to store replay information", // KRB5_RC_IO_SPACE
    "Can't open/find realm translation file", // KRB5_TRANS_CANTOPEN
    "Improper format of realm translation file", // KRB5_TRANS_BADFORMAT
    "Can't open/find lname translation database", // KRB5_LNAME_CANTOPEN
    "No translation available for requested principal", // KRB5_LNAME_NOTRANS
    "Improper format of translation database entry", // KRB5_LNAME_BADFORMAT
    "Cryptosystem internal error",    // KRB5_CRYPTO_INTERNAL
    "Key table name malformed",       // KRB5_KT_BADNAME
    "Unknown Key table type",         // KRB5_KT_UNKNOWN_TYPE
    "Key table entry not found",      // KRB5_KT_NOTFOUND
    "End of key table reached",       // KRB5_KT_END
    "Cannot write to specified key table", // KRB5_KT_NOWRITE
    "Error writing to key table",     // KRB5_KT_IOERR
    "Cannot find ticket for requested realm", // KRB5_NO_TKT_IN_RLM
    "DES key has bad parity",         // KRB5DES_BAD_KEYPAR
    "DES key is a weak key",          // KRB5DES_WEAK_KEY
    "Bad encryption type",            // KRB5_BAD_ENCTYPE
    "Key size is incompatible with encryption type", // KRB5_BAD_KEYSIZE
    "Message size is incompatible with encryption type", // KRB5_BAD_MSIZE
    "Credentials cache type is already registered.", // KRB5_CC_TYPE_EXISTS
    "Key table type is already registered.", // KRB5_KT_TYPE_EXISTS
    "Credentials cache I/O operation failed", // KRB5_CC_IO
    "Credentials cache permissions incorrect", // KRB5_FCC_PERM
    "No credentials cache found",     // KRB5_FCC_NOFILE
    "Internal credentials cache error", // KRB5_FCC_INTERNAL
    "Error writing to credentials cache", // KRB5_CC_WRITE
    "No more memory to allocate (in credentials cache code)", // KRB5_CC_NOMEM
    "Bad format in credentials cache", // KRB5_CC_FORMAT
    "No credentials found with supported encryption types", // KRB5_CC_NOT_KTYPE
    "Invalid KDC option combination (library internal error)", // KRB5_INVALID_FLAGS
    "Request missing second ticket",  // KRB5_NO_2ND_TKT
    "No credentials supplied to library routine", // KRB5_NOCREDS_SUPPLIED
    "Bad sendauth version was sent",  // KRB5_SENDAUTH_BADAUTHVERS
    "Bad application version was sent (via sendauth)", // KRB5_SENDAUTH_BADAPPLVERS
    "Bad response (during sendauth exchange)", // KRB5_SENDAUTH_BADRESPONSE
    "Server rejected authentication (during sendauth exchange)", // KRB5_SENDAUTH_REJECTED
    "Unsupported preauthentication type", // KRB5_PREAUTH_BAD_TYPE
    "Required preauthentication key not supplied", // KRB5_PREAUTH_NO_KEY
    "Generic preauthentication failure", // KRB5_PREAUTH_FAILED
    "Unsupported replay cache format version number", // KRB5_RCACHE_BADVNO
    "Unsupported credentials cache format version number", // KRB5_CCACHE_BADVNO
    "Unsupported key table format version number", // KRB5_KEYTAB_BADVNO
    "Program lacks support for address type", // KRB5_PROG_ATYPE_NOSUPP
    "Message replay detection requires rcache parameter", // KRB5_RC_REQUIRED
    "Hostname cannot be canonicalized", // KRB5_ERR_BAD_HOSTNAME
    "Cannot determine realm for host", // KRB5_ERR_HOST_REALM_UNKNOWN
    "Conversion to service principal undefined for name type", // KRB5_SNAME_UNSUPP_NAMETYPE
    "Initial Ticket response appears to be Version 4 error", // KRB5KRB_AP_ERR_V4_REPLY
    "Cannot resolve network address for KDC in requested realm", // KRB5_REALM_CANT_RESOLVE
    "Requesting ticket can't get forwardable tickets", // KRB5_TKT_NOT_FORWARDABLE
    "Bad principal name while trying to forward credentials", // KRB5_FWD_BAD_PRINCIPAL
    "Looping detected inside krb5_get_in_tkt", // KRB5_GET_IN_TKT_LOOP
    "Configuration file does not specify default realm", // KRB5_CONFIG_NODEFREALM
    "Bad SAM flags in obtain_sam_padata", // KRB5_SAM_UNSUPPORTED
    "Invalid encryption type in SAM challenge", // KRB5_SAM_INVALID_ETYPE
    "Missing checksum in SAM challenge", // KRB5_SAM_NO_CHECKSUM
    "Bad checksum in SAM challenge",  // KRB5_SAM_BAD_CHECKSUM
    "Keytab name too long",           // KRB5_KT_NAME_TOOLONG
    "Key version number for principal in key table is incorrect", // KRB5_KT_KVNONOTFOUND
    "This application has expired",   // KRB5_APPL_EXPIRED
    "This Krb5 library has expired",  // KRB5_LIB_EXPIRED
    "New password cannot be zero length", // KRB5_CHPW_PWDNULL
    "Password change failed",         // KRB5_CHPW_FAIL
    "Bad format in keytab",           // KRB5_KT_FORMAT
    "Encryption type not permitted",  // KRB5_NOPERM_ETYPE
    "No supported encryption types (config file error?)", // KRB5_CONFIG_ETYPE_NOSUPP
    "Program called an obsolete, deleted function", // KRB5_OBSOLETE_FN
    "unknown getaddrinfo failure",    // KRB5_EAI_FAIL
    "no data available for host/domain name", // KRB5_EAI_NODATA
    "host/domain name not found",     // KRB5_EAI_NONAME
    "service name unknown",           // KRB5_EAI_SERVICE
    "Cannot determine realm for numeric host address", // KRB5_ERR_NUMERIC_REALM
    "Invalid key generation parameters from KDC", // KRB5_ERR_BAD_S2K_PARAMS
    "service not available",          // KRB5_ERR_NO_SERVICE
    "Ccache function not supported: read-only ccache type", // KRB5_CC_READONLY
    "Ccache function not supported: not implemented", // KRB5_CC_NOSUPP
    "Invalid format of Kerberos lifetime or clock skew string", // KRB5_DELTAT_BADFORMAT
    "Supplied data not handled by this plugin", // KRB5_PLUGIN_NO_HANDLE
    "Plugin does not support the operation", // KRB5_PLUGIN_OP_NOTSUPP
    "Invalid UTF-8 string",           // KRB5_ERR_INVALID_UTF8
    "FAST protected pre-authentication required but not supported by KDC", // KRB5_ERR_FAST_REQUIRED
    "Auth context must contain local address", // KRB5_LOCAL_ADDR_REQUIRED
    "Auth context must contain remote address", // KRB5_REMOTE_ADDR_REQUIRED
    "Tracing unsupported",            // KRB5_TRACE_NOSUPP
];
