/*
 * Known answers for MIT krb5 1.22.2's refusal of a des3-cbc-sha1 key by its parity or its weakness, from libkrb5 itself.
 *
 * The oracle build is the release tarball's default (--with-crypto-impl=builtin), whose des3 enc provider
 * (lib/crypto/builtin/enc_provider/des3.c validate_and_schedule) schedules the key with mit_des3_key_sched
 * (lib/crypto/builtin/des/d3_kysched.c): for each of the three DES keys in turn, mit_des_check_key_parity
 * (a bad octet returns -1, KRB5DES_BAD_KEYPAR), then mit_des_is_weak_key (-2, KRB5DES_WEAK_KEY).
 * Every use of the key goes through it: krb5_c_encrypt, krb5_c_decrypt, krb5_c_make_checksum and
 * krb5_c_verify_checksum (cksumtype 12) and krb5_c_prf derive their keys with the base key first.
 *
 * Lines:
 *   code NAME NUMBER MESSAGE            the codes seen and error_message() of each
 *   key  NAME KEY24                     a des3 key
 *   ct   USAGE CIPHERTEXT               krb5_c_encrypt of 24 octets under the key `good`
 *   cs   USAGE DATA CHECKSUM20          krb5_c_make_checksum (cksumtype 12) of DATA under the key `good`
 *   enc|dec|sum|ver|prf NAME USAGE CODE   what the operation returned under the key NAME (ver: the code of
 *                                       krb5_c_verify_checksum of the `cs` checksum; prf: USAGE is 0)
 *
 * cc -o mit-des3-parity mit-des3-parity.c $(krb5-config --cflags --libs krb5)
 */
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NKEYS 200

static struct {
    char name[40];
    unsigned char k[24];
} keys[NKEYS];
static int nkeys;

static void hexn(const unsigned char *p, size_t n)
{
    size_t i;
    if (n == 0) {
        printf("-");
        return;
    }
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
}

static const char *codename(long c)
{
    static char buf[32];
    if (c == 0)
        return "OK";
    if (c == KRB5DES_BAD_KEYPAR)
        return "BAD_KEYPAR";
    if (c == KRB5DES_WEAK_KEY)
        return "WEAK_KEY";
    if (c == 100000)
        return "INVALID";
    snprintf(buf, sizeof(buf), "OTHER%ld", c);
    return buf;
}

static void addkey(const char *name, const unsigned char *k)
{
    if (nkeys >= NKEYS) {
        fprintf(stderr, "too many keys\n");
        exit(9);
    }
    snprintf(keys[nkeys].name, sizeof(keys[nkeys].name), "%s", name);
    memcpy(keys[nkeys].k, k, 24);
    nkeys++;
}

static const unsigned char weak4[4][8] = {
    { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
    { 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe },
    { 0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e },
    { 0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1 },
};
static const unsigned char semi12[12][8] = {
    { 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe },
    { 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01 },
    { 0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1 },
    { 0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e },
    { 0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1 },
    { 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01 },
    { 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe },
    { 0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e },
    { 0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e },
    { 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01 },
    { 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe },
    { 0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1 },
};

/* The 24 octets of a good key with DES key `j` replaced by `w`. */
static void with_sub(unsigned char *out, const unsigned char *good, int j, const unsigned char *w)
{
    memcpy(out, good, 24);
    memcpy(out + 8 * j, w, 8);
}

static long try_op(krb5_context ctx, const char *op, const unsigned char *kbytes, krb5_keyusage usage,
                   const unsigned char *ct, size_t ctlen, const unsigned char *ck, size_t cklen)
{
    krb5_keyblock kb;
    long code = 0;
    unsigned char kcopy[24];

    memcpy(kcopy, kbytes, 24);
    kb.magic = KV5M_KEYBLOCK;
    kb.enctype = ENCTYPE_DES3_CBC_SHA1;
    kb.length = 24;
    kb.contents = kcopy;

    if (!strcmp(op, "enc")) {
        unsigned char pt[24];
        krb5_data in;
        krb5_enc_data out;
        size_t outlen = 0, i;
        for (i = 0; i < 24; i++)
            pt[i] = (unsigned char)(i * 5 + 1);
        in.magic = KV5M_DATA;
        in.length = 24;
        in.data = (char *)pt;
        krb5_c_encrypt_length(ctx, ENCTYPE_DES3_CBC_SHA1, 24, &outlen);
        out.magic = KV5M_ENC_DATA;
        out.enctype = ENCTYPE_DES3_CBC_SHA1;
        out.kvno = 0;
        out.ciphertext.magic = KV5M_DATA;
        out.ciphertext.length = outlen;
        out.ciphertext.data = malloc(outlen);
        code = krb5_c_encrypt(ctx, &kb, usage, NULL, &in, &out);
        free(out.ciphertext.data);
    } else if (!strcmp(op, "dec")) {
        krb5_enc_data in;
        krb5_data out;
        in.magic = KV5M_ENC_DATA;
        in.enctype = ENCTYPE_DES3_CBC_SHA1;
        in.kvno = 0;
        in.ciphertext.magic = KV5M_DATA;
        in.ciphertext.length = ctlen;
        in.ciphertext.data = (char *)ct;
        out.magic = KV5M_DATA;
        out.length = ctlen;
        out.data = malloc(ctlen);
        code = krb5_c_decrypt(ctx, &kb, usage, NULL, &in, &out);
        free(out.data);
    } else if (!strcmp(op, "sum")) {
        krb5_data d;
        krb5_checksum c;
        d.magic = KV5M_DATA;
        d.length = 5;
        d.data = "hello";
        code = krb5_c_make_checksum(ctx, CKSUMTYPE_HMAC_SHA1_DES3, &kb, usage, &d, &c);
        if (!code)
            krb5_free_checksum_contents(ctx, &c);
    } else if (!strcmp(op, "ver")) {
        krb5_data d;
        krb5_checksum c;
        krb5_boolean valid = 0;
        d.magic = KV5M_DATA;
        d.length = 5;
        d.data = "hello";
        c.magic = KV5M_CHECKSUM;
        c.checksum_type = CKSUMTYPE_HMAC_SHA1_DES3;
        c.length = cklen;
        c.contents = (unsigned char *)ck;
        code = krb5_c_verify_checksum(ctx, &kb, usage, &d, &c, &valid);
        if (!code && !valid)
            code = 100000; /* "invalid", not an error */
    } else if (!strcmp(op, "prf")) {
        krb5_data in, out;
        size_t plen = 0;
        in.magic = KV5M_DATA;
        in.length = 4;
        in.data = "test";
        krb5_c_prf_length(ctx, ENCTYPE_DES3_CBC_SHA1, &plen);
        out.magic = KV5M_DATA;
        out.length = plen;
        out.data = malloc(plen);
        code = krb5_c_prf(ctx, &kb, &in, &out);
        free(out.data);
    }
    return code;
}

int main(void)
{
    krb5_context ctx;
    unsigned char good[24], ct[64], ck[20], tmp[24];
    size_t ctlen = 0, i;
    int j, k, n;
    long seen[16];
    int nseen = 0;
    static const char *ops[] = { "enc", "dec", "sum", "ver", "prf" };

    if (krb5_init_context(&ctx))
        return 2;

    /* the good key: krb5_c_random_to_key of a fixed pattern (odd parity on every octet, no weak key) */
    {
        unsigned char rnd[21];
        krb5_data rd;
        krb5_keyblock rk;
        for (i = 0; i < 21; i++)
            rnd[i] = (unsigned char)(i * 29 + 7);
        rd.magic = KV5M_DATA;
        rd.length = 21;
        rd.data = (char *)rnd;
        rk.magic = KV5M_KEYBLOCK;
        rk.enctype = ENCTYPE_DES3_CBC_SHA1;
        rk.length = 24;
        rk.contents = malloc(24);
        if (rk.contents == NULL || krb5_c_random_to_key(ctx, ENCTYPE_DES3_CBC_SHA1, &rd, &rk)) {
            fprintf(stderr, "random_to_key failed\n");
            return 3;
        }
        memcpy(good, rk.contents, 24);
        free(rk.contents);
    }
    addkey("good", good);

    /* a second good key whose three DES keys are all different from the first's */
    for (i = 0; i < 24; i++)
        tmp[i] = good[(i + 8) % 24];
    addkey("good-rotated", tmp);
    /* 2-key and 1-key layouts: K1 K2 K1, K1 K1 K1 (valid parity: accepted) */
    memcpy(tmp, good, 24);
    memcpy(tmp + 16, good, 8);
    addkey("two-key-k1k2k1", tmp);
    memcpy(tmp + 8, good, 8);
    addkey("one-key-k1k1k1", tmp);

    /* bad parity: one octet of DES key j (octet k) has its low bit flipped (even parity) */
    for (j = 0; j < 3; j++) {
        static const int octets[] = { 0, 3, 7 };
        for (n = 0; n < 3; n++) {
            char nm[40];
            k = octets[n];
            memcpy(tmp, good, 24);
            tmp[8 * j + k] ^= 1;
            snprintf(nm, sizeof(nm), "badpar-k%d-o%d", j, k);
            addkey(nm, tmp);
        }
    }
    /* every octet of all three keys wrong; all-zero key; all-0xff key (0xff has 8 bits: even) */
    memcpy(tmp, good, 24);
    for (i = 0; i < 24; i++)
        tmp[i] ^= 1;
    addkey("badpar-all-octets", tmp);
    memset(tmp, 0, 24);
    addkey("all-zero", tmp);
    memset(tmp, 0xff, 24);
    addkey("all-ff", tmp);
    /* two bad octets in different DES keys */
    memcpy(tmp, good, 24);
    tmp[2] ^= 1;
    tmp[18] ^= 1;
    addkey("badpar-k0-o2-and-k2-o2", tmp);
    /* the bad-parity flip of a weak key's octet makes it a non-weak key of bad parity */
    with_sub(tmp, good, 0, weak4[0]);
    tmp[0] ^= 1;
    addkey("weak01-with-bad-octet-k0", tmp);

    /* weak keys, in each position */
    for (j = 0; j < 3; j++) {
        for (n = 0; n < 4; n++) {
            char nm[40];
            with_sub(tmp, good, j, weak4[n]);
            snprintf(nm, sizeof(nm), "weak%d-k%d", n, j);
            addkey(nm, tmp);
        }
    }
    /* semi-weak keys, in position 0, and a few in positions 1 and 2 */
    for (n = 0; n < 12; n++) {
        char nm[40];
        with_sub(tmp, good, 0, semi12[n]);
        snprintf(nm, sizeof(nm), "semi%d-k0", n);
        addkey(nm, tmp);
    }
    for (n = 0; n < 12; n += 5) {
        char nm[40];
        with_sub(tmp, good, 1, semi12[n]);
        snprintf(nm, sizeof(nm), "semi%d-k1", n);
        addkey(nm, tmp);
        with_sub(tmp, good, 2, semi12[n]);
        snprintf(nm, sizeof(nm), "semi%d-k2", n);
        addkey(nm, tmp);
    }
    /* a weak key twice and thrice (the 1-key layouts of a weak key) */
    memcpy(tmp, weak4[2], 8);
    memcpy(tmp + 8, weak4[2], 8);
    memcpy(tmp + 16, weak4[2], 8);
    addkey("weak2-k0k1k2", tmp);

    /* the order of the checks: parity then weakness of DES key 0, then of 1, then of 2 */
    with_sub(tmp, good, 0, weak4[0]);
    tmp[8 + 3] ^= 1;
    addkey("order-k0-weak-k1-badpar", tmp);
    memcpy(tmp, good, 24);
    tmp[3] ^= 1;
    memcpy(tmp + 8, weak4[0], 8);
    addkey("order-k0-badpar-k1-weak", tmp);
    memcpy(tmp, good, 24);
    memcpy(tmp + 8, weak4[1], 8);
    tmp[16 + 5] ^= 1;
    addkey("order-k1-weak-k2-badpar", tmp);
    memcpy(tmp, good, 24);
    tmp[8 + 5] ^= 1;
    memcpy(tmp + 16, weak4[1], 8);
    addkey("order-k1-badpar-k2-weak", tmp);

    /* the reference ciphertext and checksum, under the good key */
    {
        krb5_keyblock kb;
        unsigned char pt[24];
        krb5_data in, d;
        krb5_enc_data out;
        krb5_checksum c;
        size_t outlen = 0;
        unsigned char gcopy[24];
        memcpy(gcopy, good, 24);
        kb.magic = KV5M_KEYBLOCK;
        kb.enctype = ENCTYPE_DES3_CBC_SHA1;
        kb.length = 24;
        kb.contents = gcopy;
        for (i = 0; i < 24; i++)
            pt[i] = (unsigned char)(i * 5 + 1);
        in.magic = KV5M_DATA;
        in.length = 24;
        in.data = (char *)pt;
        krb5_c_encrypt_length(ctx, ENCTYPE_DES3_CBC_SHA1, 24, &outlen);
        out.magic = KV5M_ENC_DATA;
        out.enctype = ENCTYPE_DES3_CBC_SHA1;
        out.kvno = 0;
        out.ciphertext.magic = KV5M_DATA;
        out.ciphertext.length = outlen;
        out.ciphertext.data = (char *)ct;
        if (outlen > sizeof(ct) || krb5_c_encrypt(ctx, &kb, 1, NULL, &in, &out)) {
            fprintf(stderr, "reference encrypt failed\n");
            return 4;
        }
        ctlen = outlen;
        d.magic = KV5M_DATA;
        d.length = 5;
        d.data = "hello";
        if (krb5_c_make_checksum(ctx, CKSUMTYPE_HMAC_SHA1_DES3, &kb, 6, &d, &c) || c.length != 20) {
            fprintf(stderr, "reference checksum failed\n");
            return 5;
        }
        memcpy(ck, c.contents, 20);
        krb5_free_checksum_contents(ctx, &c);
    }

    for (i = 0; i < (size_t)nkeys; i++) {
        printf("key %s ", keys[i].name);
        hexn(keys[i].k, 24);
        printf("\n");
    }
    printf("ct 1 ");
    hexn(ct, ctlen);
    printf("\n");
    printf("cs 6 ");
    hexn((const unsigned char *)"hello", 5);
    printf(" ");
    hexn(ck, 20);
    printf("\n");

    for (i = 0; i < (size_t)nkeys; i++) {
        size_t o;
        for (o = 0; o < sizeof(ops) / sizeof(ops[0]); o++) {
            krb5_keyusage us[3] = { 1, 6, 24 };
            int u, nu = (!strcmp(ops[o], "prf")) ? 1 : 3;
            for (u = 0; u < nu; u++) {
                long code = try_op(ctx, ops[o], keys[i].k, us[u], ct, ctlen, ck, 20);
                int s, found = 0;
                for (s = 0; s < nseen; s++)
                    if (seen[s] == code)
                        found = 1;
                if (!found && nseen < 16)
                    seen[nseen++] = code;
                printf("%s %s %u %s\n", ops[o], keys[i].name, !strcmp(ops[o], "prf") ? 0 : (unsigned)us[u], codename(code));
            }
        }
    }
    for (j = 0; j < nseen; j++)
        printf("code %s %ld %s\n", codename(seen[j]), seen[j], seen[j] == 0 ? "-" : (seen[j] == 100000 ? "checksum invalid (not an error)" : error_message(seen[j])));
    return 0;
}
