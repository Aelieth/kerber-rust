/*
 * Known answers for MIT krb5 1.22.2's AES and Camellia encryption, from libkrb5 itself: for each enctype a fixed key,
 *
 *  - `single`: messages of several lengths (no data at all, which leaves the confounder as the one block;
 *    whole blocks; a short last block) each encrypted alone, with no cipher state, as a ticket or an authenticator is.
 *    The line gives the confounder MIT drew (read back from the header of krb5_c_decrypt_iov), the plaintext and
 *    the ciphertext, so that a port given the same confounder must produce the same bytes;
 *  - then a chain of messages encrypted with one cipher state (the chaining of krb5_c_encrypt / krb5_c_decrypt between
 *    messages, as kprop and kpropd use it through krb5_mk_priv / krb5_rd_priv), printing the confounder it drew, the
 *    plaintext, the ciphertext and the state after each. A second, fresh state decrypts the chain (by iov, which gives
 *    the confounder back) and must reach the same states; the program stops if MIT does not;
 *  - `tamper`, after a message of the chain: that ciphertext with its last octet changed, and the state the second
 *    state is left in when it decrypts that from where it stood before the message (the decrypt fails its integrity check).
 *
 * Lines: etype N / key HEX / state0 HEX / single CONF PLAIN CIPHER (an empty string is "-") ... /
 *        conf HEX / plain HEX / cipher HEX / state HEX [/ tamper CIPHER STATE] ... / end
 *
 * cc -o mit-cipher-state mit-cipher-state.c $(krb5-config --cflags --libs krb5)
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

static void hex(const char *tag, const unsigned char *p, size_t n)
{
    printf("%s ", tag);
    hexn(p, n);
    printf("\n");
}

/* The messages of the chain, by the length of their data. The first seven are the ones the chain began with;
 * those after them add a message of no data (one block), whole blocks, a short last block of 15 octets and of 1,
 * and a one-block message twice running. */
static const size_t lens[] = { 40, 100, 33, 16, 17, 64, 5, 0, 48, 0, 0, 32, 15, 1 };
/* The messages sent alone. */
static const size_t single_lens[] = { 0, 1, 15, 16, 17, 32, 33, 48, 64, 100 };
/* The messages of the chain (by index) whose ciphertext is also tried with its last octet changed. */
static const size_t tamper_at[] = { 1, 3, 7 };

static int is_tamper(size_t i)
{
    size_t t;
    for (t = 0; t < sizeof(tamper_at) / sizeof(tamper_at[0]); t++)
        if (tamper_at[t] == i)
            return 1;
    return 0;
}

/* Decrypt `enc` by iov under `state` (NULL for none): the plaintext comes back in `plain` (`*plen` octets) and the
 * confounder MIT drew, which is the decrypted header, in `conf`. Returns 0, or what krb5_c_decrypt_iov returned. */
static int decrypt_iov(krb5_context ctx, krb5_keyblock *key, krb5_keyusage usage, const krb5_data *state,
                       const krb5_enc_data *enc, unsigned char *conf, unsigned char *plain, size_t *plen)
{
    unsigned int hdr, trl;
    size_t n = enc->ciphertext.length;
    unsigned char *buf = malloc(n);
    krb5_crypto_iov iov[3];
    int r;

    if (krb5_c_crypto_length(ctx, key->enctype, KRB5_CRYPTO_TYPE_HEADER, &hdr) ||
        krb5_c_crypto_length(ctx, key->enctype, KRB5_CRYPTO_TYPE_TRAILER, &trl) || hdr != 16)
        return -1;
    memcpy(buf, enc->ciphertext.data, n);
    iov[0].flags = KRB5_CRYPTO_TYPE_HEADER;
    iov[0].data.magic = KV5M_DATA; iov[0].data.length = hdr; iov[0].data.data = (char *)buf;
    iov[1].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[1].data.magic = KV5M_DATA; iov[1].data.length = n - hdr - trl; iov[1].data.data = (char *)buf + hdr;
    iov[2].flags = KRB5_CRYPTO_TYPE_TRAILER;
    iov[2].data.magic = KV5M_DATA; iov[2].data.length = trl; iov[2].data.data = (char *)buf + n - trl;
    r = krb5_c_decrypt_iov(ctx, key, usage, state, iov, 3);
    if (r == 0) {
        memcpy(conf, buf, hdr);
        *plen = n - hdr - trl;
        memcpy(plain, buf + hdr, *plen);
    }
    free(buf);
    return r;
}

int main(void)
{
    krb5_context ctx;
    krb5_enctype etypes[] = { 17, 18, 19, 20, 25, 26 };
    size_t e, i, k;
    const krb5_keyusage usage = KRB5_KEYUSAGE_KRB_PRIV_ENCPART;

    if (krb5_init_context(&ctx))
        return 2;
    for (e = 0; e < sizeof(etypes) / sizeof(etypes[0]); e++) {
        krb5_keyblock key;
        krb5_data st_enc = { 0, 0, NULL }, st_dec = { 0, 0, NULL };
        size_t keylen;
        unsigned char kbytes[32];

        if (krb5_c_keylengths(ctx, etypes[e], &keylen, &keylen))
            return 3;
        for (k = 0; k < keylen; k++)
            kbytes[k] = (unsigned char)(0x11 * (e + 1) + 7 * k);
        key.magic = KV5M_KEYBLOCK;
        key.enctype = etypes[e];
        key.length = keylen;
        key.contents = kbytes;
        if (krb5_c_init_state(ctx, &key, usage, &st_enc) ||
            krb5_c_init_state(ctx, &key, usage, &st_dec))
            return 4;
        printf("etype %d\nkey ", (int)etypes[e]);
        for (k = 0; k < keylen; k++)
            printf("%02x", kbytes[k]);
        printf("\nstate0 ");
        for (k = 0; k < st_enc.length; k++)
            printf("%02x", (unsigned char)st_enc.data[k]);
        printf("\n");

        for (i = 0; i < sizeof(single_lens) / sizeof(single_lens[0]); i++) {
            unsigned char plain[128], conf[16], back[160];
            krb5_data in;
            krb5_enc_data enc;
            size_t clen, blen;

            for (k = 0; k < single_lens[i]; k++)
                plain[k] = (unsigned char)(i * 17 + k * 5 + 3);
            in.magic = KV5M_DATA; in.length = single_lens[i]; in.data = (char *)plain;
            if (krb5_c_encrypt_length(ctx, etypes[e], single_lens[i], &clen))
                return 10;
            enc.magic = KV5M_ENC_DATA; enc.enctype = etypes[e]; enc.kvno = 0;
            enc.ciphertext.magic = KV5M_DATA; enc.ciphertext.length = clen;
            enc.ciphertext.data = malloc(clen);
            if (krb5_c_encrypt(ctx, &key, usage, NULL, &in, &enc))
                return 11;
            if (decrypt_iov(ctx, &key, usage, NULL, &enc, conf, back, &blen))
                return 12;
            if (blen != single_lens[i] || memcmp(back, plain, single_lens[i]))
                return 13;
            printf("single ");
            hexn(conf, 16);
            printf(" ");
            hexn(plain, single_lens[i]);
            printf(" ");
            hexn((unsigned char *)enc.ciphertext.data, enc.ciphertext.length);
            printf("\n");
            free(enc.ciphertext.data);
        }

        for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
            unsigned char plain[128], conf[16], back[160];
            krb5_data in;
            krb5_enc_data enc;
            size_t clen, blen;
            char tamper_line[2 * 512 + 2 * 16 + 64];
            int have_tamper = 0;

            for (k = 0; k < lens[i]; k++)
                plain[k] = (unsigned char)(i * 31 + k * 3 + 1);
            in.magic = KV5M_DATA; in.length = lens[i]; in.data = (char *)plain;
            if (krb5_c_encrypt_length(ctx, etypes[e], lens[i], &clen))
                return 5;
            enc.magic = KV5M_ENC_DATA; enc.enctype = etypes[e]; enc.kvno = 0;
            enc.ciphertext.magic = KV5M_DATA; enc.ciphertext.length = clen;
            enc.ciphertext.data = malloc(clen);
            if (krb5_c_encrypt(ctx, &key, usage, &st_enc, &in, &enc))
                return 6;

            if (is_tamper(i)) {
                /* The state the real decrypt below starts from, and a ciphertext with its last octet changed. */
                krb5_data st_t = { 0, 0, NULL }, junk;
                krb5_enc_data bad = enc;
                unsigned char *copy = malloc(clen);
                size_t o = 0;

                memcpy(copy, enc.ciphertext.data, clen);
                copy[clen - 1] ^= 1;
                bad.ciphertext.data = (char *)copy;
                if (krb5_c_init_state(ctx, &key, usage, &st_t))
                    return 15;
                memcpy(st_t.data, st_dec.data, st_dec.length);
                junk.magic = KV5M_DATA; junk.length = clen + 64; junk.data = malloc(clen + 64);
                if (krb5_c_decrypt(ctx, &key, usage, &st_t, &bad, &junk) != KRB5KRB_AP_ERR_BAD_INTEGRITY)
                    return 16;
                o += sprintf(tamper_line + o, "tamper ");
                for (k = 0; k < clen; k++)
                    o += sprintf(tamper_line + o, "%02x", copy[k]);
                o += sprintf(tamper_line + o, " ");
                for (k = 0; k < st_t.length; k++)
                    o += sprintf(tamper_line + o, "%02x", (unsigned char)st_t.data[k]);
                have_tamper = 1;
                free(junk.data);
                free(copy);
                krb5_c_free_state(ctx, &key, &st_t);
            }

            if (decrypt_iov(ctx, &key, usage, &st_dec, &enc, conf, back, &blen))
                return 7;
            if (blen != lens[i] || memcmp(back, plain, lens[i]))
                return 8;
            if (st_enc.length != st_dec.length || memcmp(st_enc.data, st_dec.data, st_enc.length))
                return 9;
            hex("conf", conf, 16);
            hex("plain", plain, lens[i]);
            hex("cipher", (unsigned char *)enc.ciphertext.data, enc.ciphertext.length);
            hex("state", (unsigned char *)st_enc.data, st_enc.length);
            if (have_tamper)
                printf("%s\n", tamper_line);
            free(enc.ciphertext.data);
        }
        printf("end\n");
        krb5_c_free_state(ctx, &key, &st_enc);
        krb5_c_free_state(ctx, &key, &st_dec);
    }
    krb5_free_context(ctx);
    return 0;
}
