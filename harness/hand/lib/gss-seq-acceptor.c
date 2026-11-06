/* gss-seq-acceptor.c: a decoding acceptor for the initial-sequence-number settle (scratch; not part of the product).
 *
 * usage: gss-seq-acceptor LABEL PORT OUTPREFIX     (service key: the keytab KRB5_KTNAME names; run with KRB5RCACHETYPE=none)
 *
 * For each connection (4-byte big-endian length, then a token; sequential):
 *  1. the initial token is decoded with MIT libkrb5 and the service key: krb5_rd_req, then the authenticator is decrypted with the
 *     ticket's session key (krb5_c_decrypt, usage 11) and its DER is read field by field: which of [0]..[8] are present, the
 *     seq-number [7] (absent or its value), the subkey [6] (type, length, a short id of the key, never the key), the checksum [3]
 *     (type, and for 0x8003 the GSS flags), the authorization data [8] (types, AD-IF-RELEVANT opened). MIT's own decoding of the
 *     same authenticator (krb5_auth_con_getauthenticator) is printed beside it;
 *  2. the token is given to MIT's gss_accept_sec_context, and its output (the AP-REP) goes back;
 *  3. every later token is read: a CFX wrap or MIC token's header is printed (flags, EC, RRC, SND_SEQ) and the token is given to
 *     gss_unwrap / gss_verify_mic. The first wrap token is then also given a second time to the same context (replay in the
 *     context) and the previous connection's first wrap token to this context (replay across contexts).
 */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static krb5_context kctx;
static krb5_keytab kt;
static int conn_no;
static const char *label, *outprefix;
static unsigned char *prev_wrap;
static size_t prev_wrap_len;
static int prev_wrap_ctx;

/* ---- framing ---- */
static int read_full(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r <= 0)
            return 0;
        got += (size_t)r;
    }
    return 1;
}

static unsigned char *recv_tok(int fd, size_t *len)
{
    uint32_t n;
    if (!read_full(fd, &n, 4))
        return NULL;
    n = ntohl(n);
    if (n > (1u << 20))
        return NULL;
    unsigned char *b = malloc(n ? n : 1);
    if (n && !read_full(fd, b, n)) {
        free(b);
        return NULL;
    }
    *len = n;
    return b;
}

static void send_tok(int fd, const void *p, size_t n)
{
    uint32_t len = htonl((uint32_t)n);
    if (write(fd, &len, 4) != 4 || (n && write(fd, p, n) != (ssize_t)n))
        perror("write");
}

static void dump(const char *what, int idx, const void *p, size_t n)
{
    char path[512];
    snprintf(path, sizeof path, "%s-ctx%02d-%s.bin", outprefix, conn_no, what);
    (void)idx;
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(p, 1, n, f);
        fclose(f);
    }
}

/* ---- DER ---- */
static int next_tlv(const unsigned char *buf, size_t len, size_t *pos, unsigned *tag, const unsigned char **val, size_t *vlen)
{
    if (*pos + 2 > len)
        return 0;
    *tag = buf[*pos];
    size_t i = *pos + 1, l = buf[i++];
    if (l & 0x80) {
        size_t nb = l & 0x7f;
        if (nb == 0 || nb > 4 || i + nb > len)
            return 0;
        l = 0;
        while (nb--)
            l = (l << 8) | buf[i++];
    }
    if (i + l > len)
        return 0;
    *val = buf + i;
    *vlen = l;
    *pos = i + l;
    return 1;
}

static int find_child(const unsigned char *buf, size_t len, unsigned want, const unsigned char **val, size_t *vlen)
{
    size_t pos = 0;
    unsigned tag;
    const unsigned char *v;
    size_t vl;
    while (next_tlv(buf, len, &pos, &tag, &v, &vl)) {
        if (tag == want) {
            *val = v;
            *vlen = vl;
            return 1;
        }
    }
    return 0;
}

static long long der_int(const unsigned char *v, size_t n) /* the INTEGER inside a context tag's body */
{
    size_t pos = 0;
    unsigned tag;
    const unsigned char *iv;
    size_t il;
    if (!next_tlv(v, n, &pos, &tag, &iv, &il) || tag != 0x02 || il == 0 || il > 8)
        return -1;
    long long x = (iv[0] & 0x80) ? -1 : 0;
    for (size_t i = 0; i < il; i++)
        x = (x << 8) | iv[i];
    return x;
}

static uint32_t fnv(const unsigned char *p, size_t n)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++)
        h = (h ^ p[i]) * 16777619u;
    return h;
}

/* authorization data: SEQUENCE OF SEQUENCE { ad-type [0] INTEGER, ad-data [1] OCTET STRING } */
static void print_authdata(const unsigned char *seq, size_t n, int depth)
{
    size_t pos = 0;
    unsigned tag;
    const unsigned char *v;
    size_t vl;
    while (next_tlv(seq, n, &pos, &tag, &v, &vl)) {
        if (tag != 0x30)
            continue;
        const unsigned char *t, *d;
        size_t tl, dl;
        if (!find_child(v, vl, 0xa0, &t, &tl) || !find_child(v, vl, 0xa1, &d, &dl))
            continue;
        long long adtype = der_int(t, tl);
        size_t dp = 0;
        unsigned dtag;
        const unsigned char *dv;
        size_t dvl;
        if (!next_tlv(d, dl, &dp, &dtag, &dv, &dvl) || dtag != 0x04)
            continue;
        printf("%*sad-type %lld (%zu octets)", 4 + 2 * depth, "", adtype, dvl);
        if (adtype == 1) {
            printf(" = AD-IF-RELEVANT, holding:\n");
            size_t ip = 0;
            unsigned itag;
            const unsigned char *iv;
            size_t ivl;
            if (next_tlv(dv, dvl, &ip, &itag, &iv, &ivl) && itag == 0x30)
                print_authdata(iv, ivl, depth + 1);
        } else if (adtype == 143 && dvl == 4) {
            printf(" = AD-AP-OPTIONS, flags 0x%04x%s\n", (unsigned)(dv[0] | dv[1] << 8 | dv[2] << 16 | (unsigned)dv[3] << 24),
                   (dv[1] & 0x40) ? " (KERB_AP_OPTIONS_CBT)" : "");
        } else {
            printf("\n");
        }
    }
}

static void print_authenticator(const unsigned char *a, size_t n)
{
    size_t pos = 0;
    unsigned tag;
    const unsigned char *v;
    size_t vl;
    if (!next_tlv(a, n, &pos, &tag, &v, &vl) || tag != 0x62) {
        printf("  authenticator: not [APPLICATION 2]\n");
        return;
    }
    const unsigned char *s;
    size_t sl;
    pos = 0;
    if (!next_tlv(v, vl, &pos, &tag, &s, &sl) || tag != 0x30) {
        printf("  authenticator: no SEQUENCE\n");
        return;
    }
    printf("  authenticator DER: %zu octets; fields (tag:length):", n);
    size_t p = 0;
    unsigned ft;
    const unsigned char *fv;
    size_t fl;
    while (next_tlv(s, sl, &p, &ft, &fv, &fl))
        printf(" %02x:%zu", ft, fl);
    printf("\n");
    const unsigned char *f;
    size_t l;
    if (find_child(s, sl, 0xa7, &f, &l))
        printf("  authenticator seq-number [7]: PRESENT, value %lld\n", der_int(f, l));
    else
        printf("  authenticator seq-number [7]: ABSENT\n");
    if (find_child(s, sl, 0xa6, &f, &l)) {
        size_t sp = 0;
        unsigned st;
        const unsigned char *sv;
        size_t svl;
        if (next_tlv(f, l, &sp, &st, &sv, &svl) && st == 0x30) {
            const unsigned char *kt_, *kv;
            size_t ktl, kvl;
            if (find_child(sv, svl, 0xa0, &kt_, &ktl) && find_child(sv, svl, 0xa1, &kv, &kvl)) {
                size_t kp = 0;
                unsigned ktag;
                const unsigned char *key;
                size_t keyl;
                if (next_tlv(kv, kvl, &kp, &ktag, &key, &keyl))
                    printf("  authenticator subkey [6]: PRESENT, keytype %lld, %zu octets, id %08x\n", der_int(kt_, ktl), keyl, fnv(key, keyl));
            }
        }
    } else {
        printf("  authenticator subkey [6]: ABSENT\n");
    }
    if (find_child(s, sl, 0xa3, &f, &l)) {
        size_t sp = 0;
        unsigned st;
        const unsigned char *sv;
        size_t svl;
        if (next_tlv(f, l, &sp, &st, &sv, &svl) && st == 0x30) {
            const unsigned char *ct, *cv;
            size_t ctl, cvl;
            if (find_child(sv, svl, 0xa0, &ct, &ctl) && find_child(sv, svl, 0xa1, &cv, &cvl)) {
                size_t cp = 0;
                unsigned ctag;
                const unsigned char *data;
                size_t dl;
                long long type = der_int(ct, ctl);
                if (next_tlv(cv, cvl, &cp, &ctag, &data, &dl)) {
                    printf("  authenticator cksum [3]: PRESENT, type %lld (0x%llx), %zu octets", type, type, dl);
                    if (type == 0x8003 && dl >= 24)
                        printf("; GSS flags 0x%08x", (unsigned)(data[20] | data[21] << 8 | data[22] << 16 | (unsigned)data[23] << 24));
                    printf("\n");
                }
            }
        }
    } else {
        printf("  authenticator cksum [3]: ABSENT\n");
    }
    if (find_child(s, sl, 0xa8, &f, &l)) {
        printf("  authenticator authorization-data [8]: PRESENT\n");
        size_t sp = 0;
        unsigned st;
        const unsigned char *sv;
        size_t svl;
        if (next_tlv(f, l, &sp, &st, &sv, &svl) && st == 0x30)
            print_authdata(sv, svl, 0);
    } else {
        printf("  authenticator authorization-data [8]: ABSENT\n");
    }
}

/* the GSS framing of the initial token: 0x60 len, OID, two token-id octets, then the AP-REQ */
static int unframe(const unsigned char *t, size_t n, const unsigned char **ap, size_t *aplen)
{
    size_t pos = 0;
    unsigned tag;
    const unsigned char *v;
    size_t vl;
    if (!next_tlv(t, n, &pos, &tag, &v, &vl) || tag != 0x60)
        return 0;
    size_t p2 = 0;
    unsigned t2;
    const unsigned char *ov;
    size_t ol;
    if (!next_tlv(v, vl, &p2, &t2, &ov, &ol) || t2 != 0x06 || p2 + 2 > vl)
        return 0;
    *ap = v + p2 + 2;
    *aplen = vl - p2 - 2;
    return 1;
}

static void decode_initial(const unsigned char *tok, size_t n)
{
    const unsigned char *ap;
    size_t aplen;
    if (!unframe(tok, n, &ap, &aplen)) {
        printf("  initial token: not a GSS-framed token\n");
        return;
    }
    printf("  initial token: %zu octets, AP-REQ %zu octets\n", n, aplen);
    krb5_data apreq = { 0, (unsigned int)aplen, (char *)ap };
    krb5_auth_context ac = NULL;
    krb5_ticket *tkt = NULL;
    krb5_flags opts = 0;
    krb5_error_code code = krb5_rd_req(kctx, &ac, &apreq, NULL, kt, &opts, &tkt);
    if (code) {
        printf("  krb5_rd_req: %s\n", krb5_get_error_message(kctx, code));
        return;
    }
    char *cname = NULL;
    krb5_unparse_name(kctx, tkt->enc_part2->client, &cname);
    printf("  krb5_rd_req ok: client %s, ap_options 0x%x%s, ticket enctype %d\n", cname, (unsigned)opts,
           (opts & AP_OPTS_MUTUAL_REQUIRED) ? " (MUTUAL_REQUIRED)" : "", tkt->enc_part.enctype);
    krb5_free_unparsed_name(kctx, cname);

    /* the authenticator's ciphertext: AP-REQ ::= [APPLICATION 14] SEQUENCE { pvno [0], msg-type [1], ap-options [2], ticket [3], authenticator [4] } */
    size_t pos = 0;
    unsigned tag;
    const unsigned char *v, *seq, *a4, *enc;
    size_t vl, sl, a4l, el;
    pos = 0;
    if (next_tlv(ap, aplen, &pos, &tag, &v, &vl) && tag == 0x6e) {
        pos = 0;
        if (next_tlv(v, vl, &pos, &tag, &seq, &sl) && tag == 0x30 && find_child(seq, sl, 0xa4, &a4, &a4l)) {
            pos = 0;
            if (next_tlv(a4, a4l, &pos, &tag, &enc, &el) && tag == 0x30) {
                const unsigned char *et, *ci;
                size_t etl, cil;
                if (find_child(enc, el, 0xa0, &et, &etl) && find_child(enc, el, 0xa2, &ci, &cil)) {
                    size_t cp = 0;
                    unsigned ctag;
                    const unsigned char *cv;
                    size_t cvl;
                    if (next_tlv(ci, cil, &cp, &ctag, &cv, &cvl) && ctag == 0x04) {
                        krb5_enc_data ed;
                        memset(&ed, 0, sizeof ed);
                        ed.enctype = (krb5_enctype)der_int(et, etl);
                        ed.ciphertext.length = (unsigned int)cvl;
                        ed.ciphertext.data = (char *)cv;
                        krb5_data plain;
                        plain.length = (unsigned int)cvl;
                        plain.data = malloc(cvl ? cvl : 1);
                        code = krb5_c_decrypt(kctx, tkt->enc_part2->session, 11, NULL, &ed, &plain);
                        if (code) {
                            printf("  authenticator decrypt: %s\n", krb5_get_error_message(kctx, code));
                        } else {
                            printf("  authenticator ciphertext: %zu octets, etype %d\n", cvl, (int)ed.enctype);
                            print_authenticator((unsigned char *)plain.data, plain.length);
                        }
                        free(plain.data);
                    }
                }
            }
        }
    }
    krb5_authenticator *au = NULL;
    if (!krb5_auth_con_getauthenticator(kctx, ac, &au)) {
        printf("  MIT's own decoding: seq_number %u, subkey %s, checksum %s, authorization_data %s\n", (unsigned)au->seq_number,
               au->subkey ? "present" : "absent", au->checksum ? "present" : "absent", au->authorization_data ? "present" : "absent");
        krb5_free_authenticator(kctx, au);
    }
    krb5_free_ticket(kctx, tkt);
    krb5_auth_con_free(kctx, ac);
}

/* ---- GSS ---- */
static void status_line(const char *what, OM_uint32 maj, OM_uint32 min)
{
    OM_uint32 mctx = 0, mj, mn;
    gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
    printf("  %s: major 0x%08x minor %u", what, maj, min);
    do {
        mj = gss_display_status(&mn, maj, GSS_C_GSS_CODE, GSS_C_NO_OID, &mctx, &msg);
        if (msg.length)
            printf(" [%.*s]", (int)msg.length, (char *)msg.value);
        gss_release_buffer(&mn, &msg);
    } while (mctx && mj == GSS_S_COMPLETE);
    if (min) {
        mctx = 0;
        mj = gss_display_status(&mn, min, GSS_C_MECH_CODE, GSS_C_NO_OID, &mctx, &msg);
        if (msg.length)
            printf(" [%.*s]", (int)msg.length, (char *)msg.value);
        gss_release_buffer(&mn, &msg);
    }
    printf("\n");
}

static void flags_text(OM_uint32 f)
{
    printf("0x%x =", f);
    if (f & GSS_C_DELEG_FLAG) printf(" DELEG");
    if (f & GSS_C_MUTUAL_FLAG) printf(" MUTUAL");
    if (f & GSS_C_REPLAY_FLAG) printf(" REPLAY");
    if (f & GSS_C_SEQUENCE_FLAG) printf(" SEQUENCE");
    if (f & GSS_C_CONF_FLAG) printf(" CONF");
    if (f & GSS_C_INTEG_FLAG) printf(" INTEG");
    if (f & GSS_C_TRANS_FLAG) printf(" TRANS");
    if (f & GSS_C_PROT_READY_FLAG) printf(" PROT_READY");
    if (f & GSS_C_CHANNEL_BOUND_FLAG) printf(" CHANNEL_BOUND");
}

static uint64_t be64(const unsigned char *p)
{
    uint64_t x = 0;
    for (int i = 0; i < 8; i++)
        x = (x << 8) | p[i];
    return x;
}

static void token_header(const unsigned char *t, size_t n, uint64_t *seq_out, int *is_wrap)
{
    *is_wrap = 0;
    if (n >= 16 && t[0] == 0x05 && t[1] == 0x04) {
        *is_wrap = 1;
        *seq_out = be64(t + 8);
        printf("  token header: CFX wrap (0504) flags 0x%02x (SentByAcceptor %u, Sealed %u, AcceptorSubkey %u) EC %u RRC %u SND_SEQ %llu\n", t[2],
               t[2] & 1, (t[2] >> 1) & 1, (t[2] >> 2) & 1, t[4] << 8 | t[5], t[6] << 8 | t[7], (unsigned long long)*seq_out);
    } else if (n >= 16 && t[0] == 0x04 && t[1] == 0x04) {
        *seq_out = be64(t + 8);
        printf("  token header: CFX MIC (0404) flags 0x%02x (SentByAcceptor %u, Sealed %u, AcceptorSubkey %u) SND_SEQ %llu\n", t[2], t[2] & 1,
               (t[2] >> 1) & 1, (t[2] >> 2) & 1, (unsigned long long)*seq_out);
    } else {
        *seq_out = 0;
        printf("  token header: not a CFX wrap or MIC token (%zu octets, first octets %02x %02x)\n", n, n > 0 ? t[0] : 0, n > 1 ? t[1] : 0);
    }
}

static void handle(int fd)
{
    ++conn_no;
    printf("== CTX %d (%s)\n", conn_no, label);
    size_t n;
    unsigned char *tok = recv_tok(fd, &n);
    if (!tok) {
        printf("  no token\n");
        return;
    }
    dump("initial", 0, tok, n);
    decode_initial(tok, n);

    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc in = { n, tok }, out = GSS_C_EMPTY_BUFFER;
    gss_name_t src = GSS_C_NO_NAME;
    gss_OID mech = GSS_C_NO_OID;
    OM_uint32 maj, min, ret_flags = 0;
    maj = gss_accept_sec_context(&min, &ctx, GSS_C_NO_CREDENTIAL, &in, GSS_C_NO_CHANNEL_BINDINGS, &src, &mech, &out, &ret_flags, NULL, NULL);
    status_line("gss_accept_sec_context", maj, min);
    printf("  acceptor ret_flags ");
    flags_text(ret_flags);
    printf("\n");
    if (out.length) {
        dump("ap-rep", 0, out.value, out.length);
        send_tok(fd, out.value, out.length);
        gss_release_buffer(&min, &out);
    }
    free(tok);
    if (maj != GSS_S_COMPLETE) {
        return;
    }
    if (src != GSS_C_NO_NAME) {
        gss_buffer_desc nm = GSS_C_EMPTY_BUFFER;
        gss_display_name(&min, src, &nm, NULL);
        printf("  initiator name %.*s\n", (int)nm.length, (char *)nm.value);
        gss_release_buffer(&min, &nm);
        gss_release_name(&min, &src);
    }

    int idx = 0, first_wrap_done = 0;
    unsigned char *last_plain = NULL;
    size_t last_plain_len = 0;
    for (;;) {
        size_t mn_len;
        unsigned char *m = recv_tok(fd, &mn_len);
        if (!m)
            break;
        ++idx;
        char nm[32];
        snprintf(nm, sizeof nm, "msg%d", idx);
        dump(nm, idx, m, mn_len);
        printf(" per-message item %d (%zu octets)\n", idx, mn_len);
        uint64_t seq;
        int is_wrap;
        token_header(m, mn_len, &seq, &is_wrap);
        gss_buffer_desc item = { mn_len, m }, res = GSS_C_EMPTY_BUFFER;
        int conf = 0;
        gss_qop_t qop = 0;
        if (mn_len >= 16 && m[0] == 0x05 && m[1] == 0x04) {
            maj = gss_unwrap(&min, ctx, &item, &res, &conf, &qop);
            status_line("gss_unwrap", maj, min);
            if (maj == GSS_S_COMPLETE) {
                printf("  unwrapped (conf %d): %.*s\n", conf, (int)res.length, (char *)res.value);
                gss_release_buffer(&min, &res);
            }
            if (!first_wrap_done) {
                first_wrap_done = 1;
                gss_buffer_desc again = { mn_len, m }, res2 = GSS_C_EMPTY_BUFFER;
                maj = gss_unwrap(&min, ctx, &again, &res2, &conf, &qop);
                status_line("replay in this context: the same wrap token again, gss_unwrap", maj, min);
                gss_release_buffer(&min, &res2);
                if (prev_wrap) {
                    gss_buffer_desc old = { prev_wrap_len, prev_wrap }, res3 = GSS_C_EMPTY_BUFFER;
                    maj = gss_unwrap(&min, ctx, &old, &res3, &conf, &qop);
                    char what[260];
                    snprintf(what, sizeof what,
                             "replay across contexts: the first wrap token of context %d (SND_SEQ %llu; this context's first token has SND_SEQ %llu) given to this context %d, gss_unwrap",
                             prev_wrap_ctx, (unsigned long long)be64(prev_wrap + 8), (unsigned long long)seq, conn_no);
                    status_line(what, maj, min);
                    gss_release_buffer(&min, &res3);
                }
                free(prev_wrap);
                prev_wrap = malloc(mn_len);
                memcpy(prev_wrap, m, mn_len);
                prev_wrap_len = mn_len;
                prev_wrap_ctx = conn_no;
            }
            free(m);
        } else if (mn_len >= 16 && m[0] == 0x04 && m[1] == 0x04) {
            if (last_plain) {
                gss_buffer_desc msg = { last_plain_len, last_plain };
                maj = gss_verify_mic(&min, ctx, &msg, &item, &qop);
                status_line("gss_verify_mic over the plaintext item before it", maj, min);
            }
            free(m);
        } else {
            printf("  (plaintext item: %.*s)\n", (int)(mn_len > 60 ? 60 : mn_len), (char *)m);
            free(last_plain);
            last_plain = m;
            last_plain_len = mn_len;
        }
    }
    free(last_plain);
    gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s LABEL PORT OUTPREFIX\n", argv[0]);
        return 2;
    }
    label = argv[1];
    outprefix = argv[3];
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (krb5_init_context(&kctx) || krb5_kt_default(kctx, &kt)) {
        fprintf(stderr, "krb5 init / default keytab failed\n");
        return 1;
    }
    int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)atoi(argv[2]));
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) || listen(ls, 8)) {
        perror("bind/listen");
        return 1;
    }
    printf("listening %s:%s (%s)\n", "127.0.0.1", argv[2], label);
    for (;;) {
        int fd = accept(ls, NULL, NULL);
        if (fd < 0)
            continue;
        handle(fd);
        close(fd);
    }
}
