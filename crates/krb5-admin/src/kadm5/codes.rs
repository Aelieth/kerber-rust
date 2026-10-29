pub(super) const LAST_FRAG: u32 = 0x8000_0000;
pub(super) const RPC_VERSION: u32 = 2;
pub(super) const KADM_PROG: u32 = 2112;
pub(super) const KADM_VERS: u32 = 2;
pub(super) const IPROP_PROG: u32 = 100_423;
pub(super) const IPROP_VERS: u32 = 1;
pub(super) const IPROP_NULL: u32 = 0;
pub(super) const IPROP_GET_UPDATES: u32 = 1;
pub(super) const IPROP_FULL_RESYNC: u32 = 2;
pub(super) const IPROP_FULL_RESYNC_EXT: u32 = 3;
pub(super) const FLAVOR_GSS: u32 = 6;
pub(super) const FLAVOR_NONE: u32 = 0;
pub(super) const FLAVOR_AUTH_GSSAPI: u32 = 300_001;
pub(super) const AUTH_GSSAPI_INIT: u32 = 1;
pub(super) const AUTH_GSSAPI_CONTINUE_INIT: u32 = 2;
pub(super) const AUTH_GSSAPI_MSG: u32 = 3;
pub(super) const AUTH_GSSAPI_DESTROY: u32 = 4;
pub(super) const AUTH_GSSAPI_CREDS_VERS: u32 = 2;
pub(super) const RPCSEC_GSS_VERS: u32 = 1;
pub(super) const RPG_DATA: u32 = 0;
pub(super) const RPG_INIT: u32 = 1;
pub(super) const RPG_CONTINUE: u32 = 2;
pub(super) const RPG_DESTROY: u32 = 3;
/// Not `FLAVOR_NONE`.
pub(super) const GSS_NONE: u32 = 1;
pub(super) const GSS_INTEGRITY: u32 = 2;
pub(super) const GSS_PRIVACY: u32 = 3;
pub(super) const AUTH_REJECTEDCRED: u32 = 2;
pub(super) const MAXSEQ: u32 = 0x8000_0000;
pub(super) const SYSTEM_ERR: u32 = 5;
pub(super) const MSG_CALL: u32 = 0;
pub(super) const MSG_REPLY: u32 = 1;
pub(super) const MSG_ACCEPTED: u32 = 0;
pub(super) const MSG_DENIED: u32 = 1;
pub(super) const SUCCESS: u32 = 0;
pub(super) const PROG_UNAVAIL: u32 = 1;
pub(super) const PROG_MISMATCH: u32 = 2;
pub(super) const PROC_UNAVAIL: u32 = 3;
pub(super) const GARBAGE_ARGS: u32 = 4;
pub(super) const REJECT_RPC_MISMATCH: u32 = 0;
pub(super) const REJECT_AUTH_ERROR: u32 = 1;
pub(super) const AUTH_TOOWEAK: u32 = 5;
pub(super) const AUTH_BADCRED: u32 = 1;
pub(super) const AUTH_BADVERF: u32 = 3;
pub(super) const AUTH_REJECTEDVERF: u32 = 4;
pub(super) const AUTH_INVALIDRESP: u32 = 6;
pub(super) const AUTH_FAILED: u32 = 7;
/// Do not decode past this.
pub(super) const MAX_AUTH_BYTES: usize = 400;
pub(super) const FLAVOR_UNIX: u32 = 1;
pub(super) const MAX_MACHINE_NAME: usize = 255;
pub(super) const NGRPS: u32 = 16;
pub(super) const GSS_S_COMPLETE: u32 = 0;
pub(super) const GSS_S_CONTINUE_NEEDED: u32 = 1;
pub(super) const GSS_S_BAD_BINDINGS: u32 = 0x0004_0000;
pub(super) const GSS_S_DEFECTIVE_TOKEN: u32 = 0x0009_0000;
pub(super) const GSS_S_FAILURE: u32 = 0x000d_0000;
pub(super) const AGSS_INITIATION_TIMEOUT: u32 = 60 * 15;
pub(super) const AGSS_INDEF_EXPIRE: u32 = 60 * 60 * 24;
pub(super) const RPCSEC_GSS_CREDPROBLEM: u32 = 13;
pub(super) const RPCSEC_GSS_CTXPROBLEM: u32 = 14;
pub(super) const RPCSEC_SEQ_WINDOW: u32 = 32;

pub(super) const CREATE_PRINCIPAL: u32 = 1;
pub(super) const DELETE_PRINCIPAL: u32 = 2;
pub(super) const MODIFY_PRINCIPAL: u32 = 3;
pub(super) const RENAME_PRINCIPAL: u32 = 4;
pub(super) const GET_PRINCIPAL: u32 = 5;
pub(super) const CHPASS_PRINCIPAL: u32 = 6;
pub(super) const CHRAND_PRINCIPAL: u32 = 7;
pub(super) const CREATE_POLICY: u32 = 8;
pub(super) const DELETE_POLICY: u32 = 9;
pub(super) const MODIFY_POLICY: u32 = 10;
pub(super) const GET_POLICY: u32 = 11;
pub(super) const GET_PRIVS: u32 = 12;
pub(super) const INIT: u32 = 13;
pub(super) const GET_PRINCS: u32 = 14;
pub(super) const GET_POLS: u32 = 15;
pub(super) const CREATE_PRINCIPAL3: u32 = 18;
pub(super) const CHPASS_PRINCIPAL3: u32 = 19;
pub(super) const CHRAND_PRINCIPAL3: u32 = 20;
pub(super) const SETKEY_PRINCIPAL: u32 = 16;
/// Retired. No `kadm_1`.
pub(super) const SETV4KEY_PRINCIPAL: u32 = 17;
pub(super) const SETKEY_PRINCIPAL3: u32 = 21;
pub(super) const SETKEY_PRINCIPAL4: u32 = 25;
pub(super) const PURGEKEYS: u32 = 22;
pub(super) const GET_STRINGS: u32 = 23;
pub(super) const SET_STRING: u32 = 24;
pub(super) const EXTRACT_KEYS: u32 = 26;
pub(super) const CREATE_ALIAS: u32 = 27;

pub(super) const KADM5_UNK_PRINC: u32 = 43_787_532;
pub(super) const KADM5_UNK_POLICY: u32 = 43_787_533;
pub(super) const KADM5_BAD_MASK: u32 = 43_787_534;
pub(super) const KADM5_BAD_CLASS: u32 = 43_787_535;
pub(super) const KADM5_BAD_LENGTH: u32 = 43_787_536;
pub(super) const KADM5_BAD_POLICY: u32 = 43_787_537;
pub(super) const KADM5_BAD_HISTORY: u32 = 43_787_540;
pub(super) const KADM5_BAD_MIN_PASS_LIFE: u32 = 43_787_541;
pub(super) const KADM5_DUP: u32 = 43_787_527;
// MIT: `OSA_ADB_DUP` (lib/kdb/adb_err.et)
/// Locked create hit it.
pub(super) const OSA_ADB_DUP: u32 = 28_810_241;
// MIT: `OSA_ADB_NOENT` (lib/kdb/adb_err.et)
/// Locked write or delete missed it.
pub(super) const OSA_ADB_NOENT: u32 = 28_810_242;
pub(super) const KADM5_FAILURE: u32 = 43_787_520;
/// Client `init`.
pub(crate) const KADM5_RPC_ERROR: u32 = KADM5_FAILURE + 8;
pub(crate) const KADM5_BAD_PASSWORD: u32 = KADM5_FAILURE + 29;
pub(super) const KADM5_PROTECT_PRINCIPAL: u32 = KADM5_FAILURE + 30;
pub(crate) const KADM5_SECURE_PRINC_MISSING: u32 = KADM5_FAILURE + 40;
pub(crate) const KADM5_GSS_ERROR: u32 = KADM5_FAILURE + 46;
pub(crate) const KADM5_MISSING_KRB5_CONF_PARAMS: u32 = KADM5_FAILURE + 54;
pub(crate) const KADM5_CANT_RESOLVE: u32 = KADM5_FAILURE + 56;
pub(super) const KADM5_PASS_Q_TOOSHORT: u32 = 43_787_542;
pub(super) const KADM5_PASS_Q_CLASS: u32 = 43_787_543;
/// Also `princ`.
pub(super) const KADM5_PASS_Q_DICT: u32 = 43_787_544;
pub(super) const KADM5_PASS_REUSE: u32 = 43_787_545;
pub(super) const KADM5_PASS_TOOSOON: u32 = 43_787_546;
pub(super) const KADM5_AUTH_ADD: u32 = 43_787_522;
pub(super) const KADM5_AUTH_MODIFY: u32 = 43_787_523;
pub(super) const KADM5_AUTH_DELETE: u32 = 43_787_524;
pub(super) const KADM5_AUTH_INSUFFICIENT: u32 = 43_787_525;
pub(super) const KADM5_ALIAS_REALM: u32 = 43_787_583;
/// -1780008402.
pub(super) const KRB5_KDB_ALIAS_UNSUPPORTED: u32 = 2_514_958_894;
/// -1780008424: "Insufficient access to lock database".
// MIT: `KRB5_KDB_CANTLOCK_DB` (lib/krb5/error_tables/kdb5_err.et:64-64)
pub(super) const KRB5_KDB_CANTLOCK_DB: u32 = 2_514_958_872;
// MIT: `KRB5_KDB_BAD_SALTTYPE` (lib/krb5/error_tables/kdb5_err.et:69-69)
pub(super) const KRB5_KDB_BAD_SALTTYPE: u32 = 2_514_958_875;
pub(super) const KADM5_AUTH_GET: u32 = 43_787_521;
pub(super) const KADM5_AUTH_LIST: u32 = 43_787_564;
pub(super) const KADM5_AUTH_INITIAL: u32 = 43_787_582;
pub(super) const KADM5_AUTH_CHANGEPW: u32 = 43_787_565;
pub(super) const KADM5_AUTH_SETKEY: u32 = 43_787_570;
pub(super) const KADM5_SETKEY_DUP_ENCTYPES: u32 = 43_787_571;
pub(super) const KADM5_SETKEY3_ETYPE_MISMATCH: u32 = 43_787_573;
pub(super) const KADM5_BAD_KEYSALTS: u32 = 43_787_578;
pub(super) const KADM5_SETKEY_BAD_KVNO: u32 = 43_787_579;
pub(super) const KADM5_AUTH_EXTRACT: u32 = 43_787_580;
pub(super) const KADM5_ATTRIBUTES: u32 = 0x0000_0010;
pub(super) const KADM5_FAIL_AUTH_COUNT: u32 = 0x0001_0000;
pub(super) const KADM5_TL_DATA: u32 = 0x0004_0000;
pub(super) const KADM5_KEY_DATA: u32 = 0x0002_0000;
pub(super) const KADM5_BAD_SERVER_PARAMS: u32 = 43_787_563;
// MIT: `KADM5_BAD_TL_TYPE` (kadm_err.et:54-54)
pub(super) const KADM5_BAD_TL_TYPE: u32 = 43_787_567;
pub(super) const KADM5_MAX_LIFE: u32 = 0x0000_0020;
pub(super) const KADM5_PRINCIPAL: u32 = 0x0000_0001;
pub(super) const KADM5_PRINC_EXPIRE_TIME: u32 = 0x0000_0002;
pub(super) const KADM5_PW_EXPIRATION: u32 = 0x0000_0004;
pub(super) const KADM5_LAST_PWD_CHANGE: u32 = 0x0000_0008;
pub(super) const KADM5_MOD_TIME: u32 = 0x0000_0040;
pub(super) const KADM5_MOD_NAME: u32 = 0x0000_0080;
pub(super) const KADM5_KVNO: u32 = 0x0000_0100;
pub(super) const KADM5_MKVNO: u32 = 0x0000_0200;
pub(super) const KADM5_AUX_ATTRIBUTES: u32 = 0x0000_0400;
pub(super) const KADM5_MAX_RLIFE: u32 = 0x0000_2000;
pub(super) const KADM5_LAST_SUCCESS: u32 = 0x0000_4000;
pub(super) const KADM5_LAST_FAILED: u32 = 0x0000_8000;
/// Policy mask, not `KADM5_LAST_SUCCESS`.
pub(super) const KADM5_PW_MAX_LIFE: u32 = 0x0000_4000;
/// Policy mask, not `KADM5_LAST_FAILED`.
pub(super) const KADM5_PW_MIN_LIFE: u32 = 0x0000_8000;
pub(super) const KADM5_POLICY: u32 = 0x0000_0800;
pub(super) const KADM5_POLICY_CLR: u32 = 0x0000_1000;
pub(super) const ALL_PRINC_MASK: u32 = KADM5_PRINCIPAL
    | KADM5_PRINC_EXPIRE_TIME
    | KADM5_PW_EXPIRATION
    | KADM5_LAST_PWD_CHANGE
    | KADM5_ATTRIBUTES
    | KADM5_MAX_LIFE
    | KADM5_MOD_TIME
    | KADM5_MOD_NAME
    | KADM5_KVNO
    | KADM5_MKVNO
    | KADM5_AUX_ATTRIBUTES
    | KADM5_POLICY_CLR
    | KADM5_POLICY
    | KADM5_MAX_RLIFE
    | KADM5_TL_DATA
    | KADM5_KEY_DATA
    | KADM5_FAIL_AUTH_COUNT;
pub(super) const KADM5_PW_MIN_LENGTH: u32 = 0x0001_0000;
pub(super) const KADM5_PW_MIN_CLASSES: u32 = 0x0002_0000;
pub(super) const KADM5_PW_HISTORY_NUM: u32 = 0x0004_0000;
pub(super) const KADM5_PW_MAX_FAILURE: u32 = 0x0010_0000;
pub(super) const KADM5_PW_FAILURE_COUNT_INTERVAL: u32 = 0x0020_0000;
pub(super) const KADM5_PW_LOCKOUT_DURATION: u32 = 0x0040_0000;
const KADM5_REF_COUNT: u32 = 0x0008_0000;
const KADM5_POLICY_ATTRIBUTES: u32 = 0x0080_0000;
const KADM5_POLICY_MAX_LIFE: u32 = 0x0100_0000;
const KADM5_POLICY_MAX_RLIFE: u32 = 0x0200_0000;
pub(super) const KADM5_POLICY_ALLOWED_KEYSALTS: u32 = 0x0400_0000;
const KADM5_POLICY_TL_DATA: u32 = 0x0800_0000;
pub(super) const ALL_POLICY_MASK: u32 = KADM5_POLICY
    | KADM5_PW_MAX_LIFE
    | KADM5_PW_MIN_LIFE
    | KADM5_PW_MIN_LENGTH
    | KADM5_PW_MIN_CLASSES
    | KADM5_PW_HISTORY_NUM
    | KADM5_REF_COUNT
    | KADM5_PW_MAX_FAILURE
    | KADM5_PW_FAILURE_COUNT_INTERVAL
    | KADM5_PW_LOCKOUT_DURATION
    | KADM5_POLICY_ATTRIBUTES
    | KADM5_POLICY_MAX_LIFE
    | KADM5_POLICY_MAX_RLIFE
    | KADM5_POLICY_ALLOWED_KEYSALTS
    | KADM5_POLICY_TL_DATA;

pub(super) const API_V2: u32 = 0x1234_5702;
pub(super) const API_V3: u32 = 0x1234_5703;
pub(super) const API_V4: u32 = 0x1234_5704;

// MIT: `glob_to_regexp` (svr_iters.c:61-62)
/// Trailing `\`.
pub(super) const EINVAL: u32 = 22;
