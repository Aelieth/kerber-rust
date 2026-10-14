/*
 * Known answers for MIT krb5 1.22.2's des3-cbc-sha1 keys and its hmac-sha1-des3-kd checksum, from libkrb5 itself.
 *
 *  - `rtk`: krb5_c_random_to_key (k5_rand2key_des3) of 21 octets: the 24 octets of key, seven of the random octets
 *    to each DES key, the eighth taking their low bits, and every octet given odd parity. A weak key stays as it is.
 *  - `s2k`: krb5_c_string_to_key of a password and a salt (the RFC 3961 des3 string-to-key: the n-folded password
 *    through random-to-key, then DK of "kerberos"), the password and the salt in hex.
 *  - `key`: a des3 key, and after it the checksum krb5_c_make_checksum gives it (cksumtype 12, krb5int_dk_checksum)
 *    as `sum`, for several key usages and lengths of data (the data of a length is a function of the length alone,
 *    see fill(); none at all is "-"). Each is checked by krb5_c_verify_checksum, which must call it valid, and
 *    the same checksum with its last octet changed invalid. The three keys are the random-to-key of one of the
 *    patterns above (`key rtk`), the string-to-key of the first password (`key s2k`), and one that
 *    krb5_c_make_random_key drew (`key mrk`), whose octets all have odd parity as MIT's rule makes them.
 *
 * Lines: rtk RANDOM21 KEY24 / s2k PASSWORD SALT KEY24 / key rtk|s2k|mrk KEY24 / sum USAGE DATA CHECKSUM20
 *
 * cc -o mit-des3 mit-des3.c $(krb5-config --cflags --libs krb5)
 */
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* The data of a checksum: `len` octets, a function of the length alone. */
static void fill(unsigned char *p, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
        p[i] = (unsigned char)(i * 7 + len);
}

static void sums(krb5_context ctx, const char *label, krb5_keyblock *key)
{
    static const krb5_keyusage usages[] = { 1, 2, 3, 6, 7, 11, 22, 25 };
    static const size_t lens[] = { 0, 1, 8, 20, 21, 64, 100, 300 };
    size_t u, l;

    printf("key %s ", label);
    hexn(key->contents, key->length);
    printf("\n");
    for (u = 0; u < sizeof(usages) / sizeof(usages[0]); u++) {
        for (l = 0; l < sizeof(lens) / sizeof(lens[0]); l++) {
            unsigned char msg[300];
            krb5_data d;
            krb5_checksum ck;
            krb5_boolean valid = 0;

            fill(msg, lens[l]);
            d.magic = KV5M_DATA;
            d.length = lens[l];
            d.data = (char *)msg;
            if (krb5_c_make_checksum(ctx, CKSUMTYPE_HMAC_SHA1_DES3, key, usages[u], &d, &ck) ||
                ck.checksum_type != 12 || ck.length != 20) {
                fprintf(stderr, "make_checksum failed\n");
                exit(4);
            }
            if (krb5_c_verify_checksum(ctx, key, usages[u], &d, &ck, &valid) || !valid) {
                fprintf(stderr, "MIT does not verify its own checksum\n");
                exit(5);
            }
            ck.contents[ck.length - 1] ^= 1;
            if (krb5_c_verify_checksum(ctx, key, usages[u], &d, &ck, &valid) || valid) {
                fprintf(stderr, "MIT verifies a changed checksum\n");
                exit(6);
            }
            ck.contents[ck.length - 1] ^= 1;
            printf("sum %u ", (unsigned)usages[u]);
            hexn(msg, lens[l]);
            printf(" ");
            hexn(ck.contents, ck.length);
            printf("\n");
            krb5_free_checksum_contents(ctx, &ck);
        }
    }
}

int main(void)
{
    krb5_context ctx;
    krb5_keyblock key;
    unsigned char rnd[21];
    size_t i, n;
    static const struct {
        const char *pw, *salt;
    } s2k[] = {
        { "password", "KERBER.TESTuser" },
        { "", "KERBER.TESTempty" },
        { "a much longer password, with punctuation and spaces: 0123456789!", "KERBER.TESThostsvc.example.test" },
    };

    if (krb5_init_context(&ctx))
        return 2;

    /* random-to-key of several 21-octet inputs, the weak and semi-weak keys among them */
    for (n = 0; n < 12; n++) {
        krb5_data rd;
        krb5_keyblock rk;
        for (i = 0; i < 21; i++) {
            switch (n) {
            case 0: rnd[i] = 0x00; break;
            case 1: rnd[i] = 0xff; break;
            case 2: rnd[i] = (i % 7 == 1 || i % 7 == 3 || i % 7 == 5) ? 0xff : 0x01; break; /* 01fe01fe01fe01fe */
            default: rnd[i] = (unsigned char)(i * (n + 3) * 13 + n * 29 + 5); break;
            }
        }
        rd.magic = KV5M_DATA;
        rd.length = 21;
        rd.data = (char *)rnd;
        rk.magic = KV5M_KEYBLOCK;
        rk.enctype = ENCTYPE_DES3_CBC_SHA1;
        rk.length = 24;
        rk.contents = malloc(24);
        if (rk.contents == NULL || krb5_c_random_to_key(ctx, ENCTYPE_DES3_CBC_SHA1, &rd, &rk))
            return 3;
        printf("rtk ");
        hexn(rnd, 21);
        printf(" ");
        hexn(rk.contents, 24);
        printf("\n");
        if (n == 5)
            sums(ctx, "rtk", &rk);
        free(rk.contents);
    }

    /* string-to-key */
    for (n = 0; n < sizeof(s2k) / sizeof(s2k[0]); n++) {
        krb5_data pw, salt;
        krb5_keyblock sk;
        pw.magic = KV5M_DATA;
        pw.length = strlen(s2k[n].pw);
        pw.data = (char *)s2k[n].pw;
        salt.magic = KV5M_DATA;
        salt.length = strlen(s2k[n].salt);
        salt.data = (char *)s2k[n].salt;
        sk.magic = KV5M_KEYBLOCK;
        sk.enctype = ENCTYPE_DES3_CBC_SHA1;
        sk.length = 24;
        sk.contents = malloc(24);
        if (sk.contents == NULL || krb5_c_string_to_key(ctx, ENCTYPE_DES3_CBC_SHA1, &pw, &salt, &sk))
            return 3;
        printf("s2k ");
        hexn((const unsigned char *)s2k[n].pw, pw.length);
        printf(" ");
        hexn((const unsigned char *)s2k[n].salt, salt.length);
        printf(" ");
        hexn(sk.contents, 24);
        printf("\n");
        if (n == 0)
            sums(ctx, "s2k", &sk);
        free(sk.contents);
    }

    /* a key MIT drew itself */
    if (krb5_c_make_random_key(ctx, ENCTYPE_DES3_CBC_SHA1, &key))
        return 3;
    sums(ctx, "mrk", &key);
    krb5_free_keyblock_contents(ctx, &key);
    krb5_free_context(ctx);
    return 0;
}
