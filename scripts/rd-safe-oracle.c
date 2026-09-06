/* Live MIT 1.22.2 krb5_rd_safe oracle: canonical, non-canonical body, seq 2^31. */
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die_k5(krb5_context ctx, krb5_error_code ret, const char *what)
{
    const char *m = ctx ? krb5_get_error_message(ctx, ret) : NULL;
    fprintf(stderr, "%s: %d %s\n", what, (int)ret, m ? m : "");
    if (ctx && m)
        krb5_free_error_message(ctx, m);
    exit(1);
}

static int der_len_at(const unsigned char *d, size_t n, size_t off, size_t *ln, size_t *hdr)
{
    unsigned char b;
    size_t nbytes, i, v;
    if (off >= n)
        return -1;
    b = d[off];
    if (b < 0x80) {
        *ln = b;
        *hdr = 1;
        return 0;
    }
    nbytes = b & 0x7f;
    if (nbytes == 0 || nbytes > 4 || off + 1 + nbytes > n)
        return -1;
    v = 0;
    for (i = 0; i < nbytes; i++)
        v = (v << 8) | d[off + 1 + i];
    *ln = v;
    *hdr = 1 + nbytes;
    return 0;
}

static int take(const unsigned char *d, size_t n, size_t *i, unsigned char *tag,
                const unsigned char **inner, size_t *ilen)
{
    size_t ln, hdr, start;
    if (*i >= n)
        return -1;
    *tag = d[*i];
    if (der_len_at(d, n, *i + 1, &ln, &hdr) != 0)
        return -1;
    start = *i + 1 + hdr;
    if (start + ln > n)
        return -1;
    *inner = d + start;
    *ilen = ln;
    *i = start + ln;
    return 0;
}

static void tlv_append(unsigned char **out, size_t *olen, unsigned char tag,
                       const unsigned char *content, size_t clen)
{
    unsigned char hdr[6];
    size_t hlen;
    hdr[0] = tag;
    if (clen < 0x80) {
        hdr[1] = (unsigned char)clen;
        hlen = 2;
    } else if (clen <= 0xff) {
        hdr[1] = 0x81;
        hdr[2] = (unsigned char)clen;
        hlen = 3;
    } else {
        hdr[1] = 0x82;
        hdr[2] = (unsigned char)(clen >> 8);
        hdr[3] = (unsigned char)clen;
        hlen = 4;
    }
    *out = realloc(*out, *olen + hlen + clen);
    if (!*out)
        exit(2);
    memcpy(*out + *olen, hdr, hlen);
    memcpy(*out + *olen + hlen, content, clen);
    *olen += hlen + clen;
}

static unsigned char *expand_int(const unsigned char *der, size_t n, size_t *outn)
{
    unsigned char tag;
    const unsigned char *inner;
    size_t ilen, i = 0, padded_len;
    unsigned char *padded, *out = NULL;
    *outn = 0;
    if (take(der, n, &i, &tag, &inner, &ilen) != 0 || tag != 0x02)
        return NULL;
    padded_len = ilen + 1;
    padded = malloc(padded_len);
    if (!padded)
        return NULL;
    padded[0] = 0;
    memcpy(padded + 1, inner, ilen);
    tlv_append(&out, outn, 0x02, padded, padded_len);
    free(padded);
    return out;
}

static unsigned char *rewrite_seq_int(const unsigned char *safe, size_t n, int high,
                                      size_t *outn)
{
    unsigned char atag, stag, ftag, btag;
    const unsigned char *app, *seq, *finner, *bseq, *binner;
    size_t alen, slen, flen, blen, binlen, i = 0, si, bi;
    unsigned char *newseq = NULL, *newbody = NULL, *newbseq = NULL, *out = NULL;
    size_t nseq = 0, nbody = 0, nbseq = 0;
    *outn = 0;
    if (take(safe, n, &i, &atag, &app, &alen) != 0)
        return NULL;
    i = 0;
    if (take(app, alen, &i, &stag, &seq, &slen) != 0)
        return NULL;
    si = 0;
    while (si < slen) {
        if (take(seq, slen, &si, &ftag, &finner, &flen) != 0)
            return NULL;
        if ((ftag & 0x1f) == 2) {
            size_t bj = 0;
            if (take(finner, flen, &bj, &btag, &bseq, &blen) != 0)
                return NULL;
            bi = 0;
            while (bi < blen) {
                if (take(bseq, blen, &bi, &btag, &binner, &binlen) != 0)
                    return NULL;
                if ((btag & 0x1f) == 3) {
                    unsigned char *nint = NULL;
                    size_t nintn = 0;
                    if (high) {
                        static const unsigned char hi[] = {0x00, 0x80, 0x00, 0x00, 0x00};
                        tlv_append(&nint, &nintn, 0x02, hi, sizeof(hi));
                    } else {
                        nint = expand_int(binner, binlen, &nintn);
                    }
                    if (!nint)
                        return NULL;
                    tlv_append(&newbseq, &nbseq, btag, nint, nintn);
                    free(nint);
                } else {
                    tlv_append(&newbseq, &nbseq, btag, binner, binlen);
                }
            }
            tlv_append(&newbody, &nbody, 0x30, newbseq, nbseq);
            tlv_append(&newseq, &nseq, ftag, newbody, nbody);
            free(newbseq);
            free(newbody);
            newbseq = newbody = NULL;
            nbseq = nbody = 0;
        } else {
            tlv_append(&newseq, &nseq, ftag, finner, flen);
        }
    }
    {
        unsigned char *inner = NULL;
        size_t innern = 0;
        tlv_append(&inner, &innern, 0x30, newseq, nseq);
        tlv_append(&out, outn, atag, inner, innern);
        free(inner);
    }
    free(newseq);
    return out;
}

static int extract_body(const unsigned char *safe, size_t n, const unsigned char **body,
                        size_t *blen)
{
    unsigned char tag;
    const unsigned char *app, *seq, *inner;
    size_t alen, slen, ilen, i = 0;
    if (take(safe, n, &i, &tag, &app, &alen) != 0)
        return -1;
    i = 0;
    if (take(app, alen, &i, &tag, &seq, &slen) != 0)
        return -1;
    i = 0;
    while (i < slen) {
        if (take(seq, slen, &i, &tag, &inner, &ilen) != 0)
            return -1;
        if ((tag & 0x1f) == 2) {
            *body = inner;
            *blen = ilen;
            return 0;
        }
    }
    return -1;
}

static unsigned char *replace_cksum(const unsigned char *safe, size_t n,
                                    const unsigned char *mac, size_t macn, size_t *outn)
{
    unsigned char atag, stag, ftag, ctag, itag;
    const unsigned char *app, *seq, *finner, *cseq, *cinner;
    size_t alen, slen, flen, clen, cilen, i = 0, si, ci;
    unsigned char *newseq = NULL, *newck = NULL, *out = NULL;
    size_t nseq = 0, nck = 0;
    *outn = 0;
    if (take(safe, n, &i, &atag, &app, &alen) != 0)
        return NULL;
    i = 0;
    if (take(app, alen, &i, &stag, &seq, &slen) != 0)
        return NULL;
    si = 0;
    while (si < slen) {
        if (take(seq, slen, &si, &ftag, &finner, &flen) != 0)
            return NULL;
        if ((ftag & 0x1f) == 3) {
            size_t cj = 0;
            if (take(finner, flen, &cj, &ctag, &cseq, &clen) != 0)
                return NULL;
            ci = 0;
            while (ci < clen) {
                if (take(cseq, clen, &ci, &itag, &cinner, &cilen) != 0)
                    return NULL;
                if ((itag & 0x1f) == 1) {
                    unsigned char *oct = NULL;
                    size_t octn = 0;
                    tlv_append(&oct, &octn, 0x04, mac, macn);
                    tlv_append(&newck, &nck, itag, oct, octn);
                    free(oct);
                } else {
                    tlv_append(&newck, &nck, itag, cinner, cilen);
                }
            }
            {
                unsigned char *wrapped = NULL;
                size_t wrappedn = 0;
                tlv_append(&wrapped, &wrappedn, 0x30, newck, nck);
                tlv_append(&newseq, &nseq, ftag, wrapped, wrappedn);
                free(wrapped);
            }
            free(newck);
            newck = NULL;
            nck = 0;
        } else {
            tlv_append(&newseq, &nseq, ftag, finner, flen);
        }
    }
    {
        unsigned char *inner = NULL;
        size_t innern = 0;
        tlv_append(&inner, &innern, 0x30, newseq, nseq);
        tlv_append(&out, outn, atag, inner, innern);
        free(inner);
    }
    free(newseq);
    return out;
}

static krb5_error_code resign_body(krb5_context ctx, krb5_keyblock *key,
                                   unsigned char *der, size_t n, unsigned char **out,
                                   size_t *outn)
{
    const unsigned char *body;
    size_t blen;
    krb5_data input;
    krb5_checksum cksum;
    krb5_error_code ret;
    if (extract_body(der, n, &body, &blen) != 0)
        return KRB5KRB_AP_ERR_BADADDR;
    memset(&input, 0, sizeof(input));
    input.data = (char *)body;
    input.length = blen;
    memset(&cksum, 0, sizeof(cksum));
    ret = krb5_c_make_checksum(ctx, 0, key, KRB5_KEYUSAGE_KRB_SAFE_CKSUM, &input, &cksum);
    if (ret)
        return ret;
    *out = replace_cksum(der, n, cksum.contents, cksum.length, outn);
    krb5_free_checksum_contents(ctx, &cksum);
    return *out ? 0 : KRB5KRB_AP_ERR_MODIFIED;
}

static void setup_ac(krb5_context ctx, krb5_auth_context *ac, krb5_keyblock *key,
                    krb5_address *local, krb5_address *remote, krb5_int32 flags)
{
    krb5_error_code ret = krb5_auth_con_init(ctx, ac);
    if (ret)
        die_k5(ctx, ret, "auth_con_init");
    ret = krb5_auth_con_setuseruserkey(ctx, *ac, key);
    if (ret)
        die_k5(ctx, ret, "setuseruserkey");
    ret = krb5_auth_con_setaddrs(ctx, *ac, local, remote);
    if (ret)
        die_k5(ctx, ret, "setaddrs");
    ret = krb5_auth_con_setflags(ctx, *ac, flags);
    if (ret)
        die_k5(ctx, ret, "setflags");
}

int main(void)
{
    krb5_context ctx;
    krb5_error_code ret;
    krb5_keyblock key;
    unsigned char keybytes[32];
    krb5_address addr_a, addr_b;
    unsigned char a4[4] = {127, 0, 0, 1};
    unsigned char b4[4] = {10, 0, 0, 1};
    krb5_auth_context sender, receiver;
    krb5_data userdata, der, got;
    unsigned char *mut = NULL, *signed_der = NULL;
    size_t mutn = 0, signedn = 0;
    memset(keybytes, 0x42, sizeof(keybytes));
    ret = krb5_init_context(&ctx);
    if (ret)
        die_k5(NULL, ret, "init_context");
    memset(&key, 0, sizeof(key));
    key.enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
    key.length = 32;
    key.contents = keybytes;
    addr_a.addrtype = ADDRTYPE_INET;
    addr_a.length = 4;
    addr_a.contents = a4;
    addr_b.addrtype = ADDRTYPE_INET;
    addr_b.length = 4;
    addr_b.contents = b4;
    setup_ac(ctx, &sender, &key, &addr_a, &addr_b, KRB5_AUTH_CONTEXT_DO_SEQUENCE);
    setup_ac(ctx, &receiver, &key, &addr_b, &addr_a, 0);
    {
        static char user[] = "safe-oracle";
        memset(&userdata, 0, sizeof(userdata));
        userdata.data = user;
        userdata.length = sizeof(user) - 1;
    }
    ret = krb5_mk_safe(ctx, sender, &userdata, &der, NULL);
    if (ret)
        die_k5(ctx, ret, "mk_safe");
    ret = krb5_rd_safe(ctx, receiver, &der, &got, NULL);
    if (ret)
        die_k5(ctx, ret, "rd_safe canon");
    if (got.length != userdata.length || memcmp(got.data, userdata.data, got.length) != 0)
        die_k5(ctx, KRB5KRB_AP_ERR_MODIFIED, "canon userdata");
    krb5_free_data_contents(ctx, &got);
    printf("SAFE_CANON_OK\n");
    mut = rewrite_seq_int((unsigned char *)der.data, der.length, 0, &mutn);
    if (!mut)
        die_k5(ctx, KRB5KRB_AP_ERR_MODIFIED, "expand seq");
    ret = resign_body(ctx, &key, mut, mutn, &signed_der, &signedn);
    if (ret)
        die_k5(ctx, ret, "resign noncanon");
    {
        krb5_data mutated;
        memset(&mutated, 0, sizeof(mutated));
        mutated.data = (char *)signed_der;
        mutated.length = signedn;
        ret = krb5_rd_safe(ctx, receiver, &mutated, &got, NULL);
        if (ret)
            die_k5(ctx, ret, "rd_safe noncanon");
        if (got.length != userdata.length || memcmp(got.data, userdata.data, got.length) != 0)
            die_k5(ctx, KRB5KRB_AP_ERR_MODIFIED, "noncanon userdata");
        krb5_free_data_contents(ctx, &got);
    }
    printf("SAFE_NONCANON_BODY_OK\n");
    free(mut);
    free(signed_der);
    mut = rewrite_seq_int((unsigned char *)der.data, der.length, 1, &mutn);
    if (!mut)
        die_k5(ctx, KRB5KRB_AP_ERR_MODIFIED, "seq 2^31 rewrite");
    ret = resign_body(ctx, &key, mut, mutn, &signed_der, &signedn);
    if (ret)
        die_k5(ctx, ret, "resign 2^31");
    {
        krb5_data mutated;
        memset(&mutated, 0, sizeof(mutated));
        mutated.data = (char *)signed_der;
        mutated.length = signedn;
        ret = krb5_rd_safe(ctx, receiver, &mutated, &got, NULL);
        if (ret)
            die_k5(ctx, ret, "rd_safe seq 2^31");
        if (got.length != userdata.length || memcmp(got.data, userdata.data, got.length) != 0)
            die_k5(ctx, KRB5KRB_AP_ERR_MODIFIED, "2^31 userdata");
        krb5_free_data_contents(ctx, &got);
    }
    printf("SAFE_SEQ_2_31_OK\n");
    free(mut);
    free(signed_der);
    krb5_free_data_contents(ctx, &der);
    krb5_auth_con_free(ctx, sender);
    krb5_auth_con_free(ctx, receiver);
    krb5_free_context(ctx);
    return 0;
}
