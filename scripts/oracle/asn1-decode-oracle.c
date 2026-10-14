/* Live MIT 1.22.2 decoder oracle for the decode sweep (crates/krb5-tools/src/asn1_sweep.rs).
 *
 * Each stdin line is `id<TAB>type<TAB>hex`. The DER is decoded with libkrb5's own
 * decode_krb5_<type>; the line written is `id<TAB>ERR<TAB>code<TAB>message` when MIT refuses it,
 * else `id<TAB>OK<TAB>fnv` with the 64-bit FNV-1a of what encode_krb5_<type> makes of the decoded
 * value (`-` for a type libkrb5 decodes but has no encoder for). No Rust code runs. */
#include <krb5.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* libkrb5's private codec entry points (k5-int.h), declared with the opaque pointers they take. */
typedef krb5_error_code (*dec_fn)(const krb5_data *, void **);
typedef krb5_error_code (*enc_fn)(const void *, krb5_data **);

#define CODEC(n)                                                         \
    krb5_error_code decode_krb5_##n(const krb5_data *, void **);         \
    krb5_error_code encode_krb5_##n(const void *, krb5_data **);
#define DECODER(n) krb5_error_code decode_krb5_##n(const krb5_data *, void **);

CODEC(as_req) CODEC(tgs_req) CODEC(kdc_req_body) CODEC(ap_req) CODEC(authenticator)
CODEC(ap_rep) CODEC(ap_rep_enc_part) CODEC(as_rep) CODEC(tgs_rep) CODEC(enc_kdc_rep_part)
CODEC(enc_tkt_part) CODEC(ticket) CODEC(error) CODEC(safe) CODEC(priv) CODEC(enc_priv_part)
CODEC(cred) CODEC(enc_cred_part) CODEC(pa_enc_ts) CODEC(etype_info2) CODEC(etype_info)
CODEC(padata_sequence) CODEC(pa_for_user) CODEC(pa_s4u_x509_user) CODEC(pa_pac_options)
CODEC(pa_fx_fast_reply) CODEC(fast_response) CODEC(secure_cookie) CODEC(pa_spake)
CODEC(spake_factor) CODEC(cammac) CODEC(ad_kdcissued) CODEC(typed_data) CODEC(authdata)
CODEC(enc_data)
DECODER(pa_pac_req) DECODER(fast_req) DECODER(pa_fx_fast_request)
krb5_error_code decode_krb5_setpw_req(const krb5_data *, krb5_data **, krb5_principal *);

static krb5_error_code dec_setpw_req(const krb5_data *code, void **out)
{
    krb5_data *password = NULL;
    krb5_principal target = NULL;
    krb5_error_code ret = decode_krb5_setpw_req(code, &password, &target);
    *out = password;
    return ret;
}

#define BOTH(n) { #n, (dec_fn)decode_krb5_##n, (enc_fn)encode_krb5_##n }
#define DEC_ONLY(n) { #n, (dec_fn)decode_krb5_##n, NULL }

static const struct {
    const char *name;
    dec_fn dec;
    enc_fn enc;
} codecs[] = {
    BOTH(as_req), BOTH(tgs_req), BOTH(kdc_req_body), BOTH(ap_req), BOTH(authenticator),
    BOTH(ap_rep), BOTH(ap_rep_enc_part), BOTH(as_rep), BOTH(tgs_rep), BOTH(enc_kdc_rep_part),
    BOTH(enc_tkt_part), BOTH(ticket), BOTH(error), BOTH(safe), BOTH(priv), BOTH(enc_priv_part),
    BOTH(cred), BOTH(enc_cred_part), BOTH(pa_enc_ts), BOTH(etype_info2), BOTH(etype_info),
    BOTH(padata_sequence), BOTH(pa_for_user), BOTH(pa_s4u_x509_user), BOTH(pa_pac_options),
    BOTH(pa_fx_fast_reply), BOTH(fast_response), BOTH(secure_cookie), BOTH(pa_spake),
    BOTH(spake_factor), BOTH(cammac), BOTH(ad_kdcissued), BOTH(typed_data), BOTH(authdata),
    BOTH(enc_data), DEC_ONLY(pa_pac_req), DEC_ONLY(fast_req), DEC_ONLY(pa_fx_fast_request),
    { "setpw_req", dec_setpw_req, NULL },
};

static uint64_t fnv64(const unsigned char *p, size_t n)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static int unhex(const char *s, size_t n, unsigned char *out)
{
    size_t i;
    for (i = 0; i < n / 2; i++) {
        unsigned int b;
        if (sscanf(s + 2 * i, "%2x", &b) != 1)
            return -1;
        out[i] = (unsigned char)b;
    }
    return 0;
}

int main(void)
{
    static char line[1 << 20];
    krb5_context ctx;
    size_t i;

    if (krb5_init_context(&ctx) != 0)
        return 2;
    while (fgets(line, sizeof(line), stdin) != NULL) {
        char *id = line, *type, *hex, *nl;
        unsigned char *der;
        size_t hlen;
        krb5_data in;
        void *val = NULL;
        krb5_error_code ret;

        nl = strchr(line, '\n');
        if (nl != NULL)
            *nl = '\0';
        type = strchr(id, '\t');
        if (type == NULL)
            continue;
        *type++ = '\0';
        hex = strchr(type, '\t');
        if (hex == NULL)
            continue;
        *hex++ = '\0';
        for (i = 0; i < sizeof(codecs) / sizeof(codecs[0]); i++) {
            if (strcmp(codecs[i].name, type) == 0)
                break;
        }
        if (i == sizeof(codecs) / sizeof(codecs[0])) {
            printf("%s\tNOTYPE\t%s\n", id, type);
            continue;
        }
        hlen = strlen(hex);
        der = malloc(hlen / 2 + 1);
        if (der == NULL || unhex(hex, hlen, der) != 0) {
            printf("%s\tBADHEX\n", id);
            free(der);
            continue;
        }
        in.magic = KV5M_DATA;
        in.data = (char *)der;
        in.length = (unsigned int)(hlen / 2);
        ret = codecs[i].dec(&in, &val);
        if (ret != 0) {
            const char *m = krb5_get_error_message(ctx, ret);
            printf("%s\tERR\t%ld\t%s\n", id, (long)ret, m);
            krb5_free_error_message(ctx, m);
        } else if (codecs[i].enc == NULL) {
            printf("%s\tOK\t-\n", id);
        } else {
            krb5_data *out = NULL;
            ret = codecs[i].enc(val, &out);
            if (ret != 0)
                printf("%s\tOK\tenc-%ld\n", id, (long)ret);
            else if (getenv("ORACLE_HEX") != NULL) {
                unsigned int k;
                printf("%s\tOK\t", id);
                for (k = 0; k < out->length; k++)
                    printf("%02x", (unsigned char)out->data[k]);
                printf("\n");
            } else
                printf("%s\tOK\t%016llx\n", id,
                       (unsigned long long)fnv64((unsigned char *)out->data, out->length));
            krb5_free_data(ctx, out);
        }
        /* The decoded values are leaked: the oracle is short-lived. */
        free(der);
    }
    krb5_free_context(ctx);
    return 0;
}
