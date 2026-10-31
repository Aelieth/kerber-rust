/* Live MIT 1.22.2 krb5_rd_req, krb5_rd_priv and krb5_rd_safe over the cases `rd-sweep cases`
 * writes (crates/krb5-tools/src/bin/rd-sweep.rs): an AP-REQ, a KRB-PRIV or a KRB-SAFE whose
 * authenticator, EncKrbPrivPart or KRB-SAFE-BODY is broken, re-encrypted or re-signed.
 *
 * The first stdin line is `#key <enctype> <kvno> <hex> <principal>`, put in a FILE keytab;
 * each other line is `id<TAB>req|priv|safe<TAB>ap-req<TAB>message|-`. The AP-REQ goes through
 * krb5_rd_req; a KRB-PRIV or KRB-SAFE then goes through krb5_rd_priv or krb5_rd_safe on that
 * auth context, its addresses 10.0.0.1 (local) and 127.0.0.1 (remote). Written: `id<TAB>answer`,
 * `0` when MIT accepts, `asn1` for an ASN.1 decode error, `krb5:<n>` for code n of the krb5
 * table, else `other:<code>`. Run with KRB5RCACHETYPE=none. No Rust code runs.
 * `rd-priv-oracle text` adds MIT's message to a refusal (`id<TAB>krb5:<n><TAB>message`); a
 * `req-named` case names the keytab's principal as the server, `req-matching` names host/ in
 * its realm (a name that matches any host), where `req` names none.
 *
 * Built with -DKPASSWD_KDB (and the kadm-server and kdb libraries) it also has a `kpasswd` mode,
 * `rd-priv-oracle kpasswd`, which does what kadmind's kpasswd acceptor does (schpw.c
 * process_chpw_request): each stdin line is `id<TAB>frame-hex` (`rd-sweep kpasswd`: [plen][vno]
 * [aplen][AP-REQ][KRB-PRIV], version 1); the auth context does sequence numbers only
 * (KRB5_AUTH_CONTEXT_DO_SEQUENCE), krb5_rd_req names kadmin/changepw in the default realm against
 * the KDB: keytab of the realm's database (the key lookup kadmind makes), krb5_mk_rep follows, and
 * krb5_rd_priv reads the KRB-PRIV with no address set. Written: `id<TAB>answer`, `0` when both are
 * read, `req:<code>` when krb5_rd_req or krb5_mk_rep refuses (kpasswd answers AUTHERROR),
 * `priv:<code>` when krb5_rd_priv does (HARDERROR), `drop` when the frame is one kpasswd does not
 * answer. A first line `#local <addr>,...` lists krb5_os_localaddr, the host addresses a KRB-PRIV's
 * receiver address is searched in.
 *
 * With the same define it has a `kadmind` mode, `rd-priv-oracle kadmind`, which does what kadmind's GSS
 * acceptor does with an AP-REQ (accept_sec_context.c kg_accept_krb5): krb5_rd_req against the KDB: keytab
 * with no server (GSS_C_NO_NAME, RPCSEC_GSS), then with kadmin/admin and with kadmin/changepw
 * (AUTH_GSSAPI's two names). Each stdin line is `id<TAB>ap-req-hex` (`rd-sweep kadmind`); written:
 * `id<TAB>noname<TAB>admin<TAB>changepw`, each `0` or the code as above. */
#include <krb5.h>
#ifdef KPASSWD_KDB
#include <arpa/inet.h>
#include <kadm5/admin.h>
#include <kdb.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KT_PATH "/tmp/rd-sweep.keytab"
#define ASN1_BASE 1859794432L    /* ERROR_TABLE_BASE_asn1 */
#define KRB5_BASE (-1765328384L) /* ERROR_TABLE_BASE_krb5 */

static void code_text(krb5_error_code ret, char *out, size_t n)
{
    long c = (long)ret;
    if (c == 0)
        snprintf(out, n, "0");
    else if (c >= ASN1_BASE && c < ASN1_BASE + 256)
        snprintf(out, n, "asn1");
    else if (c >= KRB5_BASE && c < KRB5_BASE + 256)
        snprintf(out, n, "krb5:%ld", c - KRB5_BASE);
    else
        snprintf(out, n, "other:%ld", c);
}

static void answer(const char *id, krb5_error_code ret)
{
    char text[64];
    code_text(ret, text, sizeof(text));
    printf("%s\t%s\n", id, text);
}

static void say(krb5_context ctx, const char *id, krb5_error_code ret, int with_text)
{
    char text[64];
    const char *msg;

    if (!with_text || ret == 0) {
        answer(id, ret);
        return;
    }
    code_text(ret, text, sizeof(text));
    msg = krb5_get_error_message(ctx, ret);
    printf("%s\t%s\t%s\n", id, text, msg);
    krb5_free_error_message(ctx, msg);
}

static unsigned char *unhex(const char *s, unsigned int *n)
{
    size_t len = strlen(s), i;
    unsigned char *out = malloc(len / 2 + 1);
    if (out == NULL || len % 2 != 0) {
        free(out);
        return NULL;
    }
    for (i = 0; i < len / 2; i++) {
        unsigned int b;
        if (sscanf(s + 2 * i, "%2x", &b) != 1) {
            free(out);
            return NULL;
        }
        out[i] = (unsigned char)b;
    }
    *n = (unsigned int)(len / 2);
    return out;
}

#ifdef KPASSWD_KDB
/* The default realm's database, as kadmind opens it for the KDB: keytab (kadmin/server/ovsec_kadmd.c
 * setup_kdb_keytab; kinit_kdb.c opens it the same way). */
static int kdb_keytab(krb5_context *ctx, char **realm, krb5_keytab *kt)
{
    kadm5_config_params config;
    void *handle = NULL;

    if (kadm5_init_krb5_context(ctx) != 0 || krb5_get_default_realm(*ctx, realm) != 0)
        return -1;
    memset(&config, 0, sizeof(config));
    config.mask = KADM5_CONFIG_REALM;
    config.realm = *realm;
    if (kadm5_init(*ctx, "kinit", NULL, "kinit", &config, KADM5_STRUCT_VERSION,
                   KADM5_API_VERSION_4, NULL, &handle) != 0)
        return -1;
    if (krb5_db_register_keytab(*ctx) != 0 || krb5_kt_resolve(*ctx, "KDB:", kt) != 0)
        return -1;
    return 0;
}

static void print_local(krb5_context ctx)
{
    krb5_address **addrs = NULL;
    char text[INET6_ADDRSTRLEN];
    int i;

    printf("#local ");
    if (krb5_os_localaddr(ctx, &addrs) == 0 && addrs != NULL) {
        for (i = 0; addrs[i] != NULL; i++) {
            int af = addrs[i]->addrtype == ADDRTYPE_INET ? AF_INET : AF_INET6;
            if (inet_ntop(af, addrs[i]->contents, text, sizeof(text)) != NULL)
                printf("%s%s", i ? "," : "", text);
        }
    }
    printf("\n");
}

static int kpasswd_mode(void)
{
    static char line[1 << 20];
    krb5_context ctx = NULL;
    krb5_keytab kt = NULL;
    krb5_principal changepw = NULL;
    char *realm = NULL;

    if (kdb_keytab(&ctx, &realm, &kt) != 0)
        return 2;
    if (krb5_build_principal(ctx, &changepw, strlen(realm), realm, "kadmin", "changepw", NULL) != 0)
        return 2;
    print_local(ctx);
    while (fgets(line, sizeof(line), stdin) != NULL) {
        char *nl = strchr(line, '\n'), *id = line, *hex, text[64];
        krb5_auth_context ac = NULL;
        krb5_ticket *ticket = NULL;
        krb5_data ap, cipher, rep, clear;
        krb5_replay_data replay;
        krb5_error_code ret;
        unsigned char *f;
        unsigned int n, plen, vno, aplen;

        if (nl != NULL)
            *nl = '\0';
        hex = strchr(id, '\t');
        if (hex == NULL)
            continue;
        *hex++ = '\0';
        f = unhex(hex, &n);
        if (f == NULL)
            return 2;
        /* process_chpw_request: the frame checks that answer nothing (schpw.c:47-95). */
        plen = n >= 6 ? (f[0] << 8 | f[1]) : 0;
        vno = n >= 6 ? (f[2] << 8 | f[3]) : 0;
        aplen = n >= 6 ? (f[4] << 8 | f[5]) : 0;
        if (n < 6 || plen != n || vno != 1 || 6 + aplen >= n) {
            printf("%s\tdrop\n", id);
            free(f);
            continue;
        }
        ap.data = (char *)f + 6;
        ap.length = aplen;
        cipher.data = (char *)f + 6 + aplen;
        cipher.length = n - 6 - aplen;
        memset(&rep, 0, sizeof(rep));
        memset(&clear, 0, sizeof(clear));
        if (krb5_auth_con_init(ctx, &ac) != 0 ||
            krb5_auth_con_setflags(ctx, ac, KRB5_AUTH_CONTEXT_DO_SEQUENCE) != 0)
            return 2;
        ret = krb5_rd_req(ctx, &ac, &ap, changepw, kt, NULL, &ticket);
        if (ret != 0) {
            code_text(ret, text, sizeof(text));
            printf("%s\treq:%s\n", id, text);
        } else if ((ret = krb5_mk_rep(ctx, ac, &rep)) != 0) {
            code_text(ret, text, sizeof(text));
            printf("%s\treq:%s\n", id, text);
        } else if ((ret = krb5_rd_priv(ctx, ac, &cipher, &clear, &replay)) != 0) {
            code_text(ret, text, sizeof(text));
            printf("%s\tpriv:%s\n", id, text);
        } else {
            printf("%s\t0\n", id);
        }
        krb5_free_data_contents(ctx, &rep);
        krb5_free_data_contents(ctx, &clear);
        krb5_free_ticket(ctx, ticket);
        krb5_auth_con_free(ctx, ac);
        free(f);
    }
    return 0;
}

static int kadmind_mode(void)
{
    static char line[1 << 20];
    krb5_context ctx = NULL;
    krb5_keytab kt = NULL;
    krb5_principal servers[3] = {NULL, NULL, NULL};
    char *realm = NULL;

    if (kdb_keytab(&ctx, &realm, &kt) != 0)
        return 2;
    if (krb5_build_principal(ctx, &servers[1], strlen(realm), realm, "kadmin", "admin", NULL) != 0 ||
        krb5_build_principal(ctx, &servers[2], strlen(realm), realm, "kadmin", "changepw", NULL) != 0)
        return 2;
    while (fgets(line, sizeof(line), stdin) != NULL) {
        char *nl = strchr(line, '\n'), *id = line, *hex, text[3][64];
        krb5_data ap;
        unsigned char *f;
        unsigned int n;
        int i;

        if (nl != NULL)
            *nl = '\0';
        hex = strchr(id, '\t');
        if (hex == NULL)
            continue;
        *hex++ = '\0';
        f = unhex(hex, &n);
        if (f == NULL)
            return 2;
        ap.data = (char *)f;
        ap.length = n;
        for (i = 0; i < 3; i++) {
            krb5_auth_context ac = NULL;
            krb5_ticket *ticket = NULL;
            krb5_error_code ret;

            if (krb5_auth_con_init(ctx, &ac) != 0 ||
                krb5_auth_con_setflags(ctx, ac, KRB5_AUTH_CONTEXT_DO_SEQUENCE) != 0)
                return 2;
            ret = krb5_rd_req(ctx, &ac, &ap, servers[i], kt, NULL, &ticket);
            code_text(ret, text[i], sizeof(text[i]));
            krb5_free_ticket(ctx, ticket);
            krb5_auth_con_free(ctx, ac);
        }
        printf("%s\t%s\t%s\t%s\n", id, text[0], text[1], text[2]);
        free(f);
    }
    return 0;
}
#endif

int main(int argc, char **argv)
{
    static char line[1 << 20];
    krb5_context ctx;
    krb5_keytab kt;
    krb5_keytab_entry ent;
    krb5_principal matching = NULL;
    unsigned char local4[4] = {10, 0, 0, 1}, remote4[4] = {127, 0, 0, 1};
    krb5_address local, remote;
    int with_text = argc > 1 && strcmp(argv[1], "text") == 0;

    if (argc > 1 && strcmp(argv[1], "kpasswd") == 0) {
#ifdef KPASSWD_KDB
        return kpasswd_mode();
#else
        fprintf(stderr, "rd-priv-oracle: built without KPASSWD_KDB\n");
        return 2;
#endif
    }
    if (argc > 1 && strcmp(argv[1], "kadmind") == 0) {
#ifdef KPASSWD_KDB
        return kadmind_mode();
#else
        fprintf(stderr, "rd-priv-oracle: built without KPASSWD_KDB\n");
        return 2;
#endif
    }
    if (krb5_init_context(&ctx) != 0)
        return 2;
    if (krb5_build_principal(ctx, &matching, 11, "KERBER.TEST", "host", "", (char *)NULL) != 0)
        return 2;
    matching->type = KRB5_NT_SRV_HST;
    remove(KT_PATH);
    if (krb5_kt_resolve(ctx, "FILE:" KT_PATH, &kt) != 0)
        return 2;
    local.magic = remote.magic = KV5M_ADDRESS;
    local.addrtype = remote.addrtype = ADDRTYPE_INET;
    local.length = remote.length = 4;
    local.contents = local4;
    remote.contents = remote4;
    while (fgets(line, sizeof(line), stdin) != NULL) {
        char *nl = strchr(line, '\n'), *id = line, *kind, *aphex, *msghex;
        krb5_auth_context ac = NULL;
        krb5_data ap, msg, out;
        krb5_error_code ret;
        unsigned int n;

        if (nl != NULL)
            *nl = '\0';
        if (strncmp(line, "#key ", 5) == 0) {
            int enctype, kvno;
            char hexkey[256], princ[512];
            if (sscanf(line + 5, "%d %d %255s %511s", &enctype, &kvno, hexkey, princ) != 4)
                return 2;
            memset(&ent, 0, sizeof(ent));
            if (krb5_parse_name(ctx, princ, &ent.principal) != 0)
                return 2;
            ent.vno = (krb5_kvno)kvno;
            ent.key.enctype = enctype;
            ent.key.contents = unhex(hexkey, &n);
            ent.key.length = n;
            if (ent.key.contents == NULL || krb5_kt_add_entry(ctx, kt, &ent) != 0)
                return 2;
            continue;
        }
        kind = strchr(id, '\t');
        if (kind == NULL)
            continue;
        *kind++ = '\0';
        aphex = strchr(kind, '\t');
        if (aphex == NULL)
            continue;
        *aphex++ = '\0';
        msghex = strchr(aphex, '\t');
        if (msghex == NULL)
            continue;
        *msghex++ = '\0';
        memset(&ap, 0, sizeof(ap));
        ap.data = (char *)unhex(aphex, &ap.length);
        if (ap.data == NULL || krb5_auth_con_init(ctx, &ac) != 0)
            return 2;
        krb5_clear_error_message(ctx);
        ret = krb5_rd_req(ctx, &ac, &ap,
                          strcmp(kind, "req-named") == 0 ? ent.principal :
                          strcmp(kind, "req-matching") == 0 ? matching : NULL,
                          kt, NULL, NULL);
        if (ret != 0 || strncmp(kind, "req", 3) == 0) {
            say(ctx, id, ret, with_text);
        } else {
            memset(&msg, 0, sizeof(msg));
            msg.data = (char *)unhex(msghex, &msg.length);
            if (msg.data == NULL)
                return 2;
            krb5_auth_con_setaddrs(ctx, ac, &local, &remote);
            memset(&out, 0, sizeof(out));
            if (strcmp(kind, "priv") == 0)
                ret = krb5_rd_priv(ctx, ac, &msg, &out, NULL);
            else
                ret = krb5_rd_safe(ctx, ac, &msg, &out, NULL);
            say(ctx, id, ret, with_text);
            krb5_free_data_contents(ctx, &out);
            free(msg.data);
        }
        free(ap.data);
        krb5_auth_con_free(ctx, ac);
    }
    krb5_kt_close(ctx, kt);
    krb5_free_context(ctx);
    return 0;
}
