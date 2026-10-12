/* Live MIT 1.22.2 krb5_rd_req, krb5_rd_priv and krb5_rd_safe over the cases `rd-sweep cases`
 * writes (crates/krb5-tools/src/bin/rd-sweep.rs): an AP-REQ, a KRB-PRIV or a KRB-SAFE whose
 * authenticator, EncKrbPrivPart or KRB-SAFE-BODY is broken, re-encrypted or re-signed.
 *
 * The first stdin line is `#key <enctype> <kvno> <hex> <principal>`, put in a MEMORY keytab;
 * each other line is `id<TAB>req|priv|safe<TAB>ap-req<TAB>message|-`. The AP-REQ goes through
 * krb5_rd_req; a KRB-PRIV or KRB-SAFE then goes through krb5_rd_priv or krb5_rd_safe on that
 * auth context, its addresses 10.0.0.1 (local) and 127.0.0.1 (remote). Written: `id<TAB>answer`,
 * `0` when MIT accepts, `asn1` for an ASN.1 decode error, `krb5:<n>` for code n of the krb5
 * table, else `other:<code>`. Run with KRB5RCACHETYPE=none. No Rust code runs. */
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASN1_BASE 1859794432L    /* ERROR_TABLE_BASE_asn1 */
#define KRB5_BASE (-1765328384L) /* ERROR_TABLE_BASE_krb5 */

static void answer(const char *id, krb5_error_code ret)
{
    long c = (long)ret;
    if (c == 0)
        printf("%s\t0\n", id);
    else if (c >= ASN1_BASE && c < ASN1_BASE + 256)
        printf("%s\tasn1\n", id);
    else if (c >= KRB5_BASE && c < KRB5_BASE + 256)
        printf("%s\tkrb5:%ld\n", id, c - KRB5_BASE);
    else
        printf("%s\tother:%ld\n", id, c);
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

int main(void)
{
    static char line[1 << 20];
    krb5_context ctx;
    krb5_keytab kt;
    krb5_keytab_entry ent;
    unsigned char local4[4] = {10, 0, 0, 1}, remote4[4] = {127, 0, 0, 1};
    krb5_address local, remote;

    if (krb5_init_context(&ctx) != 0)
        return 2;
    if (krb5_kt_resolve(ctx, "MEMORY:rd-sweep", &kt) != 0)
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
        ret = krb5_rd_req(ctx, &ac, &ap, NULL, kt, NULL, NULL);
        if (ret != 0 || strcmp(kind, "req") == 0) {
            answer(id, ret);
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
            answer(id, ret);
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
