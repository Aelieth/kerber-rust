//! The trace points, one function per MIT `TRACE_*` macro the client paths reach, its text
//! verbatim from MIT's header. Each writes one line when `KRB5_TRACE` is set and does nothing
//! otherwise.

use krb5_types::PaData;

use super::{Arg, Key, Princ, RemoteAddr, krb5int_trace};

/// MIT `TRACE_CC_CACHE_MATCH` (`include/k5-trace.h:108-110`): the result of matching a principal against the default collection.
pub fn cc_cache_match(princ: Princ<'_>, code: i64, msg: Option<&str>) {
    krb5int_trace(
        "Matching {princ} in collection with result: {kerr}",
        &[Arg::Princ(Some(princ)), Arg::Kerr(code, msg)],
    );
}

/// MIT `TRACE_CC_DESTROY` (`include/k5-trace.h:111-112`): a cache about to be destroyed.
pub fn cc_destroy(cache: &str) {
    krb5int_trace("Destroying ccache {ccache}", &[Arg::Ccache(cache)]);
}

/// MIT `TRACE_CC_GET_CONFIG` (`include/k5-trace.h:115-117`): a configuration entry read from a cache.
pub fn cc_get_config(cache: &str, princ: Option<&str>, key: &str, data: &[u8]) {
    krb5int_trace(
        "Read config in {ccache} for {princ}: {str}: {data}",
        &[
            Arg::Ccache(cache),
            Arg::PrincName(princ),
            Arg::Str(Some(key.as_bytes())),
            Arg::Data(Some(data)),
        ],
    );
}

/// MIT `TRACE_CC_INIT` (`include/k5-trace.h:118-120`): a cache initialized for its default principal.
pub fn cc_init(cache: &str, princ: Princ<'_>) {
    krb5int_trace(
        "Initializing {ccache} with default princ {princ}",
        &[Arg::Ccache(cache), Arg::Princ(Some(princ))],
    );
}

/// MIT `TRACE_CC_MOVE` (`include/k5-trace.h:121-122`): a cache's contents moved into another.
pub fn cc_move(src: &str, dst: &str) {
    krb5int_trace(
        "Moving ccache {ccache} to {ccache}",
        &[Arg::Ccache(src), Arg::Ccache(dst)],
    );
}

/// MIT `TRACE_CC_NEW_UNIQUE` (`include/k5-trace.h:123-124`): a new unique cache of a type.
pub fn cc_new_unique(cache_type: &str) {
    krb5int_trace(
        "Resolving unique ccache of type {str}",
        &[Arg::Str(Some(cache_type.as_bytes()))],
    );
}

/// MIT `TRACE_CC_RETRIEVE` (`include/k5-trace.h:127-129`): a credential looked up in a cache, with the result; no client matches any.
pub fn cc_retrieve(
    cache: &str,
    client: Option<Princ<'_>>,
    server: Princ<'_>,
    code: i64,
    msg: Option<&str>,
) {
    krb5int_trace(
        "Retrieving {creds} from {ccache} with result: {kerr}",
        &[
            Arg::Creds(client, server),
            Arg::Ccache(cache),
            Arg::Kerr(code, msg),
        ],
    );
}

/// MIT `TRACE_CC_RETRIEVE_REF` (`include/k5-trace.h:130-131`): a cache lookup for a server in the referral realm, tried again in the client's realm.
pub fn cc_retrieve_ref(client: Option<Princ<'_>>, server: Princ<'_>, code: i64, msg: Option<&str>) {
    krb5int_trace(
        "Retrying {creds} with result: {kerr}",
        &[Arg::Creds(client, server), Arg::Kerr(code, msg)],
    );
}

/// MIT `TRACE_CC_SET_CONFIG` (`include/k5-trace.h:132-134`): a configuration entry about to be stored in a cache.
pub fn cc_set_config(cache: &str, princ: Option<&str>, key: &str, data: &[u8]) {
    krb5int_trace(
        "Storing config in {ccache} for {princ}: {str}: {data}",
        &[
            Arg::Ccache(cache),
            Arg::PrincName(princ),
            Arg::Str(Some(key.as_bytes())),
            Arg::Data(Some(data)),
        ],
    );
}

/// MIT `TRACE_CC_STORE` (`include/k5-trace.h:135-136`): a credential about to be stored in a cache.
pub fn cc_store(cache: &str, client: Princ<'_>, server: Princ<'_>) {
    krb5int_trace(
        "Storing {creds} in {ccache}",
        &[Arg::Creds(Some(client), server), Arg::Ccache(cache)],
    );
}

/// MIT `TRACE_FAST_ARMOR_CCACHE` (`include/k5-trace.h:176-177`): the armor cache named for FAST.
pub fn fast_armor_ccache(ccache_name: &str) {
    krb5int_trace(
        "FAST armor ccache: {str}",
        &[Arg::Str(Some(ccache_name.as_bytes()))],
    );
}

/// MIT `TRACE_FAST_ARMOR_CCACHE_KEY` (`include/k5-trace.h:178-179`): the armor ticket's session key, as a hash.
pub fn fast_armor_ccache_key(key: Key<'_>) {
    krb5int_trace(
        "Armor ccache session key: {keyblock}",
        &[Arg::Keyblock(Some(key))],
    );
}

/// MIT `TRACE_FAST_ARMOR_KEY` (`include/k5-trace.h:180-181`): the FAST armor key, as a hash.
pub fn fast_armor_key(key: Key<'_>) {
    krb5int_trace("FAST armor key: {keyblock}", &[Arg::Keyblock(Some(key))]);
}

/// MIT `TRACE_FAST_CCACHE_CONFIG` (`include/k5-trace.h:182-183`): FAST chosen because the armor cache says the KDC has it.
pub fn fast_ccache_config() {
    krb5int_trace("Using FAST due to armor ccache negotiation result", &[]);
}

/// MIT `TRACE_FAST_DECODE` (`include/k5-trace.h:184-185`): a FAST reply about to be unwrapped.
pub fn fast_decode() {
    krb5int_trace("Decoding FAST response", &[]);
}

/// MIT `TRACE_FAST_ENCODE` (`include/k5-trace.h:186-187`): a request about to be wrapped in FAST.
pub fn fast_encode() {
    krb5int_trace("Encoding request body and padata into FAST request", &[]);
}

/// MIT `TRACE_FAST_NEGO` (`include/k5-trace.h:188-189`): whether the AS reply says the KDC has FAST.
pub fn fast_nego(avail: bool) {
    krb5int_trace(
        "FAST negotiation: {str}available",
        &[Arg::Str(Some(if avail { b"" } else { b"un" }))],
    );
}

/// MIT `TRACE_FAST_PADATA_UPGRADE` (`include/k5-trace.h:190-191`): a restart with FAST because the error offered it.
pub fn fast_padata_upgrade() {
    krb5int_trace(
        "Upgrading to FAST due to presence of PA_FX_FAST in reply",
        &[],
    );
}

/// MIT `TRACE_FAST_REPLY_KEY` (`include/k5-trace.h:192-193`): the strengthened FAST reply key, as a hash.
pub fn fast_reply_key(key: Key<'_>) {
    krb5int_trace("FAST reply key: {keyblock}", &[Arg::Keyblock(Some(key))]);
}

/// MIT `TRACE_FAST_REQUIRED` (`include/k5-trace.h:194-195`): FAST chosen because it is required.
pub fn fast_required() {
    krb5int_trace("Using FAST due to KRB5_FAST_REQUIRED flag", &[]);
}

/// MIT `TRACE_GIC_PWD_CHANGED` (`include/k5-trace.h:200-201`): the final AS request after an expired password changed.
pub fn gic_pwd_changed() {
    krb5int_trace("Getting initial TGT with changed password", &[]);
}

/// MIT `TRACE_GIC_PWD_CHANGEPW` (`include/k5-trace.h:202-203`): one try of an expired password's change.
pub fn gic_pwd_changepw(tries: i32) {
    krb5int_trace(
        "Attempting password change; {int} tries remaining",
        &[Arg::Int(i64::from(tries))],
    );
}

/// MIT `TRACE_GIC_PWD_EXPIRED` (`include/k5-trace.h:204-205`): an expired password, a change ticket to get.
pub fn gic_pwd_expired() {
    krb5int_trace("Principal expired; getting changepw ticket", &[]);
}

/// MIT `TRACE_INIT_CREDS` (`include/k5-trace.h:218-219`): the first line of an initial-credentials request.
pub fn init_creds(client: Princ<'_>) {
    krb5int_trace(
        "Getting initial credentials for {princ}",
        &[Arg::Princ(Some(client))],
    );
}

/// MIT `TRACE_INIT_CREDS_AS_KEY_GAK` (`include/k5-trace.h:220-221`): the reply key from the password or keytab, as a hash.
pub fn init_creds_as_key_gak(key: Key<'_>) {
    krb5int_trace(
        "AS key obtained from gak_fct: {keyblock}",
        &[Arg::Keyblock(Some(key))],
    );
}

/// MIT `TRACE_INIT_CREDS_AS_KEY_PREAUTH` (`include/k5-trace.h:222-223`): the reply key preauth set, as a hash.
pub fn init_creds_as_key_preauth(key: Key<'_>) {
    krb5int_trace(
        "AS key determined by preauth: {keyblock}",
        &[Arg::Keyblock(Some(key))],
    );
}

/// MIT `TRACE_INIT_CREDS_DECRYPTED_REPLY` (`include/k5-trace.h:224-225`): the AS reply's session key, as a hash.
pub fn init_creds_decrypted_reply(key: Key<'_>) {
    krb5int_trace(
        "Decrypted AS reply; session key is: {keyblock}",
        &[Arg::Keyblock(Some(key))],
    );
}

/// MIT `TRACE_INIT_CREDS_ERROR_REPLY` (`include/k5-trace.h:226-227`): a KRB-ERROR answering an AS request.
pub fn init_creds_error_reply(code: i64) {
    krb5int_trace("Received error from KDC: {kerr}", &[Arg::Kerr(code, None)]);
}

/// MIT `TRACE_INIT_CREDS_GAK` (`include/k5-trace.h:228-230`): the salt and parameters the reply key is made from.
pub fn init_creds_gak(salt: &[u8], s2kparams: &[u8]) {
    krb5int_trace(
        "Getting AS key, salt \"{data}\", params \"{data}\"",
        &[Arg::Data(Some(salt)), Arg::Data(Some(s2kparams))],
    );
}

/// MIT `TRACE_INIT_CREDS_KEYTAB_LOOKUP` (`include/k5-trace.h:233-234`): the enctypes the keytab has for the client.
pub fn init_creds_keytab_lookup(client: Princ<'_>, etypes: &[i32]) {
    krb5int_trace(
        "Found entries for {princ} in keytab: {etypes}",
        &[Arg::Princ(Some(client)), Arg::Etypes(etypes)],
    );
}

/// MIT `TRACE_INIT_CREDS_KEYTAB_LOOKUP_FAILED` (`include/k5-trace.h:235-236`): a keytab that could not be read.
pub fn init_creds_keytab_lookup_failed(code: i64, msg: Option<&str>) {
    krb5int_trace(
        "Couldn't lookup etypes in keytab: {kerr}",
        &[Arg::Kerr(code, msg)],
    );
}

/// MIT `TRACE_INIT_CREDS_PREAUTH` (`include/k5-trace.h:237-238`): a request preauthenticated from the KDC's method data.
pub fn init_creds_preauth() {
    krb5int_trace("Preauthenticating using KDC method data", &[]);
}

/// MIT `TRACE_INIT_CREDS_PREAUTH_DECRYPT_FAIL` (`include/k5-trace.h:239-240`): a reply the preauth key did not decrypt.
pub fn init_creds_preauth_decrypt_fail(code: i64, msg: Option<&str>) {
    krb5int_trace(
        "Decrypt with preauth AS key failed: {kerr}",
        &[Arg::Kerr(code, msg)],
    );
}

/// MIT `TRACE_INIT_CREDS_PREAUTH_MORE` (`include/k5-trace.h:241-242`): the next round of a multi-round mechanism.
pub fn init_creds_preauth_more(patype: i32) {
    krb5int_trace("Continuing preauth mech {patype}", &[Arg::Patype(patype)]);
}

/// MIT `TRACE_INIT_CREDS_PREAUTH_NONE` (`include/k5-trace.h:243-244`): a request carrying no preauth.
pub fn init_creds_preauth_none() {
    krb5int_trace("Sending unauthenticated request", &[]);
}

/// MIT `TRACE_INIT_CREDS_PREAUTH_TRYAGAIN` (`include/k5-trace.h:247-249`): a mechanism retried after a KDC error.
/// The macro names its arguments `patype, code` but hands them to `{int}` and `{patype}` in that
/// order, so the line reads the error first, as its one caller passes it.
/// MIT `init_creds_step_request` (`lib/krb5/krb/get_in_tkt.c:1321-1322`): the KDC's error, then the selected mechanism.
pub fn init_creds_preauth_tryagain(code: i32, patype: i32) {
    krb5int_trace(
        "Recovering from KDC error {int} using preauth mech {patype}",
        &[Arg::Int(i64::from(code)), Arg::Patype(patype)],
    );
}

/// MIT `TRACE_INIT_CREDS_REFERRAL` (`include/k5-trace.h:256-257`): an AS referral to another realm.
pub fn init_creds_referral(realm: &[u8]) {
    krb5int_trace(
        "Following referral to realm {data}",
        &[Arg::Data(Some(realm))],
    );
}

/// MIT `TRACE_INIT_CREDS_RETRY_TCP` (`include/k5-trace.h:258-259`): an AS request retried over TCP.
pub fn init_creds_retry_tcp() {
    krb5int_trace(
        "Request or response is too big for UDP; retrying with TCP",
        &[],
    );
}

/// MIT `TRACE_INIT_CREDS_SALT_PRINC` (`include/k5-trace.h:260-261`): the salt taken from the reply's client.
pub fn init_creds_salt_princ(salt: &[u8]) {
    krb5int_trace(
        "Salt derived from principal: {data}",
        &[Arg::Data(Some(salt))],
    );
}

/// MIT `TRACE_INIT_CREDS_SERVICE` (`include/k5-trace.h:262-263`): the initial ticket's service.
pub fn init_creds_service(service: &str) {
    krb5int_trace(
        "Setting initial creds service to {str}",
        &[Arg::Str(Some(service.as_bytes()))],
    );
}

/// MIT `TRACE_KT_GET_ENTRY` (`include/k5-trace.h:272-274`): a key looked up in a keytab, with the result.
pub fn kt_get_entry(
    keytab: &str,
    princ: Princ<'_>,
    vno: i32,
    enctype: i32,
    code: i64,
    msg: Option<&str>,
) {
    krb5int_trace(
        "Retrieving {princ} from {keytab} (vno {int}, enctype {etype}) with result: {kerr}",
        &[
            Arg::Princ(Some(princ)),
            Arg::Keytab(keytab),
            Arg::Int(i64::from(vno)),
            Arg::Etype(enctype),
            Arg::Kerr(code, msg),
        ],
    );
}

/// MIT `TRACE_MK_REQ` (`include/k5-trace.h:288-291`): an authenticator made, its keys as hashes.
pub fn mk_req(
    client: Princ<'_>,
    server: Princ<'_>,
    seqnum: i32,
    subkey: Option<Key<'_>>,
    session: Key<'_>,
) {
    krb5int_trace(
        "Creating authenticator for {creds}, seqnum {int}, subkey {key}, session key {keyblock}",
        &[
            Arg::Creds(Some(client), server),
            Arg::Int(i64::from(seqnum)),
            Arg::Key(subkey),
            Arg::Keyblock(Some(session)),
        ],
    );
}

/// MIT `TRACE_RD_REP` (`include/k5-trace.h:358-360`): an AP-REP read, its subkey as a hash.
pub fn rd_rep(ctime: i64, cusec: i32, subkey: Option<Key<'_>>, seqnum: i32) {
    krb5int_trace(
        "Read AP-REP, time {long}.{int}, subkey {keyblock}, seqnum {int}",
        &[
            Arg::Long(ctime),
            Arg::Int(i64::from(cusec)),
            Arg::Keyblock(subkey),
            Arg::Int(i64::from(seqnum)),
        ],
    );
}

/// MIT `TRACE_PREAUTH_COOKIE` (`include/k5-trace.h:313-314`): the KDC's cookie, sent back as it came.
pub fn preauth_cookie(cookie: &[u8]) {
    krb5int_trace("Received cookie: {lenstr}", &[Arg::LenStr(Some(cookie))]);
}

/// MIT `TRACE_PREAUTH_ENC_TS_KEY_GAK` (`include/k5-trace.h:315-316`): the encrypted timestamp's key, as a hash.
pub fn preauth_enc_ts_key_gak(key: Key<'_>) {
    krb5int_trace(
        "AS key obtained for encrypted timestamp: {keyblock}",
        &[Arg::Keyblock(Some(key))],
    );
}

/// MIT `TRACE_PREAUTH_ENC_TS` (`include/k5-trace.h:317-319`): the timestamp and its ciphertext, both as on the wire.
pub fn preauth_enc_ts(sec: i64, usec: i32, plain: &[u8], enc: &[u8]) {
    krb5int_trace(
        "Encrypted timestamp (for {long}.{int}): plain {hexdata}, encrypted {hexdata}",
        &[
            Arg::Long(sec),
            Arg::Int(i64::from(usec)),
            Arg::HexData(Some(plain)),
            Arg::HexData(Some(enc)),
        ],
    );
}

/// MIT `TRACE_PREAUTH_ETYPE_INFO` (`include/k5-trace.h:322-324`): the etype-info entry chosen.
pub fn preauth_etype_info(etype: i32, salt: &[u8], s2kparams: &[u8]) {
    krb5int_trace(
        "Selected etype info: etype {etype}, salt \"{data}\", params \"{data}\"",
        &[
            Arg::Etype(etype),
            Arg::Data(Some(salt)),
            Arg::Data(Some(s2kparams)),
        ],
    );
}

/// MIT `TRACE_PREAUTH_INPUT` (`include/k5-trace.h:328-329`): the padata types a KDC message carries.
pub fn preauth_input(padata: &[PaData]) {
    krb5int_trace(
        "Processing preauth types: {patypes}",
        &[Arg::Patypes(padata)],
    );
}

/// MIT `TRACE_PREAUTH_OUTPUT` (`include/k5-trace.h:330-331`): the padata types of the next request.
pub fn preauth_output(padata: &[PaData]) {
    krb5int_trace(
        "Produced preauth for next request: {patypes}",
        &[Arg::Patypes(padata)],
    );
}

/// MIT `TRACE_PREAUTH_PROCESS` (`include/k5-trace.h:332-334`): what a preauth module returned.
pub fn preauth_process(name: &str, patype: i32, real: bool, code: i64, msg: Option<&str>) {
    krb5int_trace(
        "Preauth module {str} ({int}) ({str}) returned: {kerr}",
        &[
            Arg::Str(Some(name.as_bytes())),
            Arg::Int(i64::from(patype)),
            Arg::Str(Some(if real { b"real" } else { b"info" })),
            Arg::Kerr(code, msg),
        ],
    );
}

/// MIT `TRACE_PREAUTH_SALT` (`include/k5-trace.h:337-339`): a salt from a pw-salt or afs3-salt.
pub fn preauth_salt(salt: &[u8], patype: i32) {
    krb5int_trace(
        "Received salt \"{data}\" via padata type {patype}",
        &[Arg::Data(Some(salt)), Arg::Patype(patype)],
    );
}

/// MIT `TRACE_PREAUTH_TRYAGAIN_INPUT` (`include/k5-trace.h:343-344`): the error padata a mechanism retries with.
pub fn preauth_tryagain_input(patype: i32, padata: &[PaData]) {
    krb5int_trace(
        "Preauth tryagain input types ({int}): {patypes}",
        &[Arg::Int(i64::from(patype)), Arg::Patypes(padata)],
    );
}

/// MIT `TRACE_PREAUTH_TRYAGAIN` (`include/k5-trace.h:345-347`): what a mechanism's retry returned.
pub fn preauth_tryagain(name: &str, patype: i32, code: i64, msg: Option<&str>) {
    krb5int_trace(
        "Preauth module {str} ({int}) tryagain returned: {kerr}",
        &[
            Arg::Str(Some(name.as_bytes())),
            Arg::Int(i64::from(patype)),
            Arg::Kerr(code, msg),
        ],
    );
}

/// MIT `TRACE_PREAUTH_TRYAGAIN_OUTPUT` (`include/k5-trace.h:348-349`): the padata types of the retried request.
pub fn preauth_tryagain_output(padata: &[PaData]) {
    krb5int_trace(
        "Followup preauth for next request: {patypes}",
        &[Arg::Patypes(padata)],
    );
}

/// MIT `TRACE_SENDTO_KDC` (`include/k5-trace.h:385-387`): a request about to go to a realm's KDCs.
pub fn sendto_kdc(len: usize, realm: &[u8], primary: bool, tcp_only: bool) {
    krb5int_trace(
        "Sending request ({int} bytes) to {data}{str}{str}",
        &[
            Arg::Int(i64::try_from(len).unwrap_or(i64::MAX)),
            Arg::Data(Some(realm)),
            Arg::Str(Some(if primary { b" (primary)" } else { b"" })),
            Arg::Str(Some(if tcp_only { b" (tcp only)" } else { b"" })),
        ],
    );
}

/// MIT `TRACE_SENDTO_KDC_RESOLVING` (`include/k5-trace.h:390-391`): a KDC host name about to be resolved.
pub fn sendto_kdc_resolving(hostname: &str) {
    krb5int_trace(
        "Resolving hostname {str}",
        &[Arg::Str(Some(hostname.as_bytes()))],
    );
}

/// MIT `TRACE_SENDTO_KDC_RESPONSE` (`include/k5-trace.h:392-393`): the answer and the address it came from.
pub fn sendto_kdc_response(len: usize, ra: &RemoteAddr) {
    krb5int_trace(
        "Received answer ({int} bytes) from {raddr}",
        &[
            Arg::Int(i64::try_from(len).unwrap_or(i64::MAX)),
            Arg::Raddr(ra),
        ],
    );
}

/// MIT `TRACE_SENDTO_KDC_TCP_CONNECT` (`include/k5-trace.h:404-405`): a TCP connection started.
pub fn sendto_kdc_tcp_connect(ra: &RemoteAddr) {
    krb5int_trace("Initiating TCP connection to {raddr}", &[Arg::Raddr(ra)]);
}

/// MIT `TRACE_SENDTO_KDC_TCP_DISCONNECT` (`include/k5-trace.h:406-407`): a TCP connection closed.
pub fn sendto_kdc_tcp_disconnect(ra: &RemoteAddr) {
    krb5int_trace("Terminating TCP connection to {raddr}", &[Arg::Raddr(ra)]);
}

/// MIT `TRACE_SENDTO_KDC_TCP_ERROR_CONNECT` (`include/k5-trace.h:408-409`): a TCP connection that failed.
pub fn sendto_kdc_tcp_error_connect(ra: &RemoteAddr, err: i32) {
    krb5int_trace(
        "TCP error connecting to {raddr}: {errno}",
        &[Arg::Raddr(ra), Arg::Errno(err)],
    );
}

/// MIT `TRACE_SENDTO_KDC_TCP_ERROR_RECV` (`include/k5-trace.h:410-411`): a TCP read that failed.
pub fn sendto_kdc_tcp_error_recv(ra: &RemoteAddr, err: i32) {
    krb5int_trace(
        "TCP error receiving from {raddr}: {errno}",
        &[Arg::Raddr(ra), Arg::Errno(err)],
    );
}

/// MIT `TRACE_SENDTO_KDC_TCP_ERROR_RECV_LEN` (`include/k5-trace.h:412-413`): a TCP length that failed to read or was bad.
pub fn sendto_kdc_tcp_error_recv_len(ra: &RemoteAddr, err: i32) {
    krb5int_trace(
        "TCP error receiving from {raddr}: {errno}",
        &[Arg::Raddr(ra), Arg::Errno(err)],
    );
}

/// MIT `TRACE_SENDTO_KDC_TCP_ERROR_SEND` (`include/k5-trace.h:414-415`): a TCP write that failed.
pub fn sendto_kdc_tcp_error_send(ra: &RemoteAddr, err: i32) {
    krb5int_trace(
        "TCP error sending to {raddr}: {errno}",
        &[Arg::Raddr(ra), Arg::Errno(err)],
    );
}

/// MIT `TRACE_SENDTO_KDC_TCP_SEND` (`include/k5-trace.h:416-417`): a request about to be written on TCP.
pub fn sendto_kdc_tcp_send(ra: &RemoteAddr) {
    krb5int_trace("Sending TCP request to {raddr}", &[Arg::Raddr(ra)]);
}

/// MIT `TRACE_SENDTO_KDC_UDP_ERROR_RECV` (`include/k5-trace.h:418-419`): a UDP read that failed.
pub fn sendto_kdc_udp_error_recv(ra: &RemoteAddr, err: i32) {
    krb5int_trace(
        "UDP error receiving from {raddr}: {errno}",
        &[Arg::Raddr(ra), Arg::Errno(err)],
    );
}

/// MIT `TRACE_SENDTO_KDC_UDP_ERROR_SEND_INITIAL` (`include/k5-trace.h:420-421`): a first UDP send that failed.
pub fn sendto_kdc_udp_error_send_initial(ra: &RemoteAddr, err: i32) {
    krb5int_trace(
        "UDP error sending to {raddr}: {errno}",
        &[Arg::Raddr(ra), Arg::Errno(err)],
    );
}

/// MIT `TRACE_SENDTO_KDC_UDP_ERROR_SEND_RETRY` (`include/k5-trace.h:422-423`): a UDP resend that failed.
pub fn sendto_kdc_udp_error_send_retry(ra: &RemoteAddr, err: i32) {
    krb5int_trace(
        "UDP error sending to {raddr}: {errno}",
        &[Arg::Raddr(ra), Arg::Errno(err)],
    );
}

/// MIT `TRACE_SENDTO_KDC_UDP_SEND_INITIAL` (`include/k5-trace.h:424-425`): a first UDP send.
pub fn sendto_kdc_udp_send_initial(ra: &RemoteAddr) {
    krb5int_trace("Sending initial UDP request to {raddr}", &[Arg::Raddr(ra)]);
}

/// MIT `TRACE_SENDTO_KDC_UDP_SEND_RETRY` (`include/k5-trace.h:426-427`): a UDP resend.
pub fn sendto_kdc_udp_send_retry(ra: &RemoteAddr) {
    krb5int_trace("Sending retry UDP request to {raddr}", &[Arg::Raddr(ra)]);
}

/// MIT `TRACE_SEND_TGS_ETYPES` (`include/k5-trace.h:429-430`): the enctypes a TGS request asks for.
pub fn send_tgs_etypes(etypes: &[i32]) {
    krb5int_trace(
        "etypes requested in TGS request: {etypes}",
        &[Arg::Etypes(etypes)],
    );
}

/// MIT `TRACE_SEND_TGS_SUBKEY` (`include/k5-trace.h:431-432`): the TGS request's subkey, as a hash.
pub fn send_tgs_subkey(key: Key<'_>) {
    krb5int_trace(
        "Generated subkey for TGS request: {keyblock}",
        &[Arg::Keyblock(Some(key))],
    );
}

/// MIT `TRACE_TGS_REPLY` (`include/k5-trace.h:434-436`): a TGS reply's names and session key, the key as a hash.
pub fn tgs_reply(client: Princ<'_>, server: Princ<'_>, key: Key<'_>) {
    krb5int_trace(
        "TGS reply is for {princ} -> {princ} with session key {keyblock}",
        &[
            Arg::Princ(Some(client)),
            Arg::Princ(Some(server)),
            Arg::Keyblock(Some(key)),
        ],
    );
}

/// MIT `TRACE_TKT_CREDS` (`include/k5-trace.h:454-456`): the first line of a credentials request.
pub fn tkt_creds(client: Princ<'_>, server: Princ<'_>, cache: &str) {
    krb5int_trace(
        "Getting credentials {creds} using ccache {ccache}",
        &[Arg::Creds(Some(client), server), Arg::Ccache(cache)],
    );
}

/// MIT `TRACE_TKT_CREDS_ADVANCE` (`include/k5-trace.h:457-458`): a TGT for the next realm of the path.
pub fn tkt_creds_advance(realm: &[u8]) {
    krb5int_trace(
        "Received TGT for {data}; advancing current realm",
        &[Arg::Data(Some(realm))],
    );
}

/// MIT `TRACE_TKT_CREDS_CACHED_INTERMEDIATE_TGT` (`include/k5-trace.h:459-460`): a cached TGT for an intermediate realm.
pub fn tkt_creds_cached_intermediate_tgt(client: Princ<'_>, server: Princ<'_>) {
    krb5int_trace(
        "Found cached TGT for intermediate realm: {creds}",
        &[Arg::Creds(Some(client), server)],
    );
}

/// MIT `TRACE_TKT_CREDS_CACHED_SERVICE_TGT` (`include/k5-trace.h:461-462`): a cached TGT for the service's realm.
pub fn tkt_creds_cached_service_tgt(client: Princ<'_>, server: Princ<'_>) {
    krb5int_trace(
        "Found cached TGT for service realm: {creds}",
        &[Arg::Creds(Some(client), server)],
    );
}

/// MIT `TRACE_TKT_CREDS_CLOSER_REALM` (`include/k5-trace.h:463-464`): the next closer realm of the path.
pub fn tkt_creds_closer_realm(realm: &[u8]) {
    krb5int_trace(
        "Trying next closer realm in path: {data}",
        &[Arg::Data(Some(realm))],
    );
}

/// MIT `TRACE_TKT_CREDS_COMPLETE` (`include/k5-trace.h:465-466`): the service's credential received.
pub fn tkt_creds_complete(server: Princ<'_>) {
    krb5int_trace(
        "Received creds for desired service {princ}",
        &[Arg::Princ(Some(server))],
    );
}

/// MIT `TRACE_TKT_CREDS_FALLBACK` (`include/k5-trace.h:467-469`): the fallback realm after a failed referral.
pub fn tkt_creds_fallback(realm: &[u8]) {
    krb5int_trace(
        "Local realm referral failed; trying fallback realm {data}",
        &[Arg::Data(Some(realm))],
    );
}

/// MIT `TRACE_TKT_CREDS_LOCAL_TGT` (`include/k5-trace.h:470-471`): the client realm's TGT a request starts from.
pub fn tkt_creds_local_tgt(client: Princ<'_>, server: Princ<'_>) {
    krb5int_trace(
        "Starting with TGT for client realm: {creds}",
        &[Arg::Creds(Some(client), server)],
    );
}

/// MIT `TRACE_TKT_CREDS_NON_TGT` (`include/k5-trace.h:472-474`): a referral answer that is no TGT.
pub fn tkt_creds_non_tgt(server: Princ<'_>) {
    krb5int_trace(
        "Received non-TGT referral response ({princ}); trying again without referrals",
        &[Arg::Princ(Some(server))],
    );
}

/// MIT `TRACE_TKT_CREDS_OFFPATH` (`include/k5-trace.h:475-476`): a TGT for a realm off the path.
pub fn tkt_creds_offpath(realm: &[u8]) {
    krb5int_trace(
        "Received TGT for offpath realm {data}",
        &[Arg::Data(Some(realm))],
    );
}

/// MIT `TRACE_TKT_CREDS_REFERRAL` (`include/k5-trace.h:477-478`): a referral TGT followed.
pub fn tkt_creds_referral(server: Princ<'_>) {
    krb5int_trace(
        "Following referral TGT {princ}",
        &[Arg::Princ(Some(server))],
    );
}

/// MIT `TRACE_TKT_CREDS_REFERRAL_REALM` (`include/k5-trace.h:479-480`): a server in the referral realm.
pub fn tkt_creds_referral_realm(server: Princ<'_>) {
    krb5int_trace(
        "Server has referral realm; starting with {princ}",
        &[Arg::Princ(Some(server))],
    );
}

/// MIT `TRACE_TKT_CREDS_RESPONSE_CODE` (`include/k5-trace.h:481-482`): the result of a TGS request.
pub fn tkt_creds_response_code(code: i64, msg: Option<&str>) {
    krb5int_trace("TGS request result: {kerr}", &[Arg::Kerr(code, msg)]);
}

/// MIT `TRACE_TKT_CREDS_RETRY_TCP` (`include/k5-trace.h:483-484`): a TGS request retried over TCP.
pub fn tkt_creds_retry_tcp() {
    krb5int_trace(
        "Request or response is too big for UDP; retrying with TCP",
        &[],
    );
}

/// MIT `TRACE_TKT_CREDS_SAME_REALM_TGT` (`include/k5-trace.h:485-487`): a referral back to the same realm.
pub fn tkt_creds_same_realm_tgt(realm: &[u8]) {
    krb5int_trace(
        "Received TGT referral back to same realm ({data}); trying again without referrals",
        &[Arg::Data(Some(realm))],
    );
}

/// MIT `TRACE_TKT_CREDS_SERVICE_REQ` (`include/k5-trace.h:488-490`): a service request, with or without referrals.
pub fn tkt_creds_service_req(server: Princ<'_>, referral: bool) {
    krb5int_trace(
        "Requesting tickets for {princ}, referrals {str}",
        &[
            Arg::Princ(Some(server)),
            Arg::Str(Some(if referral { b"on" } else { b"off" })),
        ],
    );
}

/// MIT `TRACE_TKT_CREDS_TARGET_TGT` (`include/k5-trace.h:491-492`): the service realm's TGT received.
pub fn tkt_creds_target_tgt(server: Princ<'_>) {
    krb5int_trace(
        "Received TGT for service realm: {princ}",
        &[Arg::Princ(Some(server))],
    );
}

/// MIT `TRACE_TKT_CREDS_TARGET_TGT_OFFPATH` (`include/k5-trace.h:493-494`): the service realm's TGT received off the path.
pub fn tkt_creds_target_tgt_offpath(server: Princ<'_>) {
    krb5int_trace(
        "Received TGT for service realm: {princ}",
        &[Arg::Princ(Some(server))],
    );
}

/// MIT `TRACE_TKT_CREDS_TGT_REQ` (`include/k5-trace.h:495-496`): a TGT requested with the current one.
pub fn tkt_creds_tgt_req(next: Princ<'_>, cur: Princ<'_>) {
    krb5int_trace(
        "Requesting TGT {princ} using TGT {princ}",
        &[Arg::Princ(Some(next)), Arg::Princ(Some(cur))],
    );
}

/// MIT `TRACE_TKT_CREDS_WRONG_ENCTYPE` (`include/k5-trace.h:497-498`): a service ticket asked again with the desired enctypes.
pub fn tkt_creds_wrong_enctype() {
    krb5int_trace(
        "Retrying TGS request with desired service ticket enctypes",
        &[],
    );
}

/// MIT `TRACE_CHECK_REPLY_SERVER_DIFFERS` (`include/k5-trace.h:505-507`): a reply server other than the one requested.
pub fn check_reply_server_differs(request: Princ<'_>, reply: Princ<'_>) {
    krb5int_trace(
        "Reply server {princ} differs from requested {princ}",
        &[Arg::Princ(Some(reply)), Arg::Princ(Some(request))],
    );
}

/// MIT `TRACE_GET_CRED_VIA_TKT_EXT` (`include/k5-trace.h:509-512`): a credential asked for with a TGT.
pub fn get_cred_via_tkt_ext(request: Princ<'_>, reply: Princ<'_>, canonicalize: bool) {
    krb5int_trace(
        "Get cred via TGT {princ} after requesting {princ} (canonicalize {str})",
        &[
            Arg::Princ(Some(reply)),
            Arg::Princ(Some(request)),
            Arg::Str(Some(if canonicalize { b"on" } else { b"off" })),
        ],
    );
}

/// MIT `TRACE_GET_CRED_VIA_TKT_EXT_RETURN` (`include/k5-trace.h:513-514`): the result of that request.
pub fn get_cred_via_tkt_ext_return(code: i64, msg: Option<&str>) {
    krb5int_trace("Got cred; {kerr}", &[Arg::Kerr(code, msg)]);
}

/// MIT `TRACE_SPAKE_CLIENT_THASH` (`plugins/preauth/spake/trace.h:44-45`): the final transcript hash, a hash of public values.
pub fn spake_client_thash(thash: &[u8]) {
    krb5int_trace(
        "SPAKE final transcript hash: {hexdata}",
        &[Arg::HexData(Some(thash))],
    );
}

/// MIT `TRACE_SPAKE_KEYGEN` (`plugins/preauth/spake/trace.h:50-51`): the client's public value.
pub fn spake_keygen(pubkey: &[u8]) {
    krb5int_trace(
        "SPAKE key generated with pubkey {hexdata}",
        &[Arg::HexData(Some(pubkey))],
    );
}

/// MIT `TRACE_SPAKE_RECEIVE_CHALLENGE` (`plugins/preauth/spake/trace.h:52-54`): the KDC's challenge, its group and public value.
pub fn spake_receive_challenge(group: i32, pubkey: &[u8]) {
    krb5int_trace(
        "SPAKE challenge received with group {int}, pubkey {hexdata}",
        &[Arg::Int(i64::from(group)), Arg::HexData(Some(pubkey))],
    );
}

/// MIT `TRACE_SPAKE_REJECT_CHALLENGE` (`plugins/preauth/spake/trace.h:59-60`): a challenge in a group not offered.
pub fn spake_reject_challenge(group: i32) {
    krb5int_trace(
        "SPAKE challenge with group {int} rejected",
        &[Arg::Int(i64::from(group))],
    );
}

/// MIT `TRACE_SPAKE_SEND_RESPONSE` (`plugins/preauth/spake/trace.h:67-68`): the SPAKE response sent.
pub fn spake_send_response() {
    krb5int_trace("Sending SPAKE response", &[]);
}

/// MIT `TRACE_SPAKE_SEND_SUPPORT` (`plugins/preauth/spake/trace.h:69-70`): the SPAKE support message sent.
pub fn spake_send_support() {
    krb5int_trace("Sending SPAKE support message", &[]);
}

/// MIT `TRACE_SPAKE_UNKNOWN_GROUP` (`plugins/preauth/spake/trace.h:71-72`): a group name the profile names and SPAKE lacks.
pub fn spake_unknown_group(name: &str) {
    krb5int_trace(
        "Unrecognized SPAKE group name: {str}",
        &[Arg::Str(Some(name.as_bytes()))],
    );
}

/// MIT `TRACE_SPAKE_RESULT` (`plugins/preauth/spake/trace.h:63-64`): the SPAKE group operation's
/// result, the secret the reply key is derived from. MIT prints it whole as `{hexdata}`; this port
/// prints only its `{hashlenstr}`, as `{keyblock}` prints a key.
pub fn spake_result(result: &[u8]) {
    krb5int_trace(
        "SPAKE algorithm result: {hashlenstr}",
        &[Arg::HashLenStr(Some(result))],
    );
}

/// MIT `TRACE_PREAUTH_ENC_TS` (`include/k5-trace.h:317-319`): the timestamp, for one sent inside FAST armor.
/// Its ciphertext is under the client's long-term key and the armor hides it from the wire, so it
/// prints only as its `{hashlenstr}`, as `{keyblock}` prints a key: the trace gives no offline
/// password check that the wire does not.
/// MIT `enc_ts_get` (`kdc/kdc_preauth_encts.c:37-40`): the KDC offers no timestamp under FAST, so MIT's FAST client sends an encrypted challenge and never traces one.
pub fn preauth_enc_ts_armored(sec: i64, usec: i32, plain: &[u8], enc: &[u8]) {
    krb5int_trace(
        "Encrypted timestamp (for {long}.{int}): plain {hexdata}, encrypted {hashlenstr}",
        &[
            Arg::Long(sec),
            Arg::Int(i64::from(usec)),
            Arg::HexData(Some(plain)),
            Arg::HashLenStr(Some(enc)),
        ],
    );
}
