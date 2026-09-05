/* RPCSEC_GSS reject-machine probe: after authgss_create establishes the
 * context, hand-frame a malformed GET_PRINCS DATA call and print the reply's
 * auth/accept status. Out-of-process only; compiled in the MIT 1.22.2 image.
 * The context handle and MICs come from libgssrpc; only the framing is by hand.
 * The header MIC is taken before the databody MIC so the GSS sequence numbers
 * match a normal client (svc_auth_gss.c expects the header seq first).
 * usage: kadm5-rpc-probe <host> <service> <mode> [port]
 *   mode: valid | corrupt-verf | maxseq | wrong-handle | destroy-then-data | garbage-args
 */
#include <gssrpc/rpc.h>
#include <gssrpc/auth_gss.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <kadm5/admin.h>
#include <krb5.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define KADM 2112
#define KADMVERS 2
#define GET_PRINCS 14
#define KADMIND_PORT 749

static int connect_to(const char *host, int port) {
    struct addrinfo hint, *addrs, *a;
    char portbuf[16];
    int s = -1;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    if (getaddrinfo(host, portbuf, &hint, &addrs) != 0)
        return -1;
    for (a = addrs; a != NULL; a = a->ai_next) {
        s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (s < 0)
            continue;
        if (connect(s, a->ai_addr, a->ai_addrlen) == 0)
            break;
        close(s);
        s = -1;
    }
    freeaddrinfo(addrs);
    return s;
}

static void xdr_u32(unsigned char *p, uint32_t n) {
    p[0] = (unsigned char)(n >> 24);
    p[1] = (unsigned char)(n >> 16);
    p[2] = (unsigned char)(n >> 8);
    p[3] = (unsigned char)n;
}

static uint32_t rd_u32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static size_t put_opaque(unsigned char *p, const unsigned char *v, size_t n) {
    size_t pad = (4 - (n % 4)) % 4;
    xdr_u32(p, (uint32_t)n);
    memcpy(p + 4, v, n);
    memset(p + 4 + n, 0, pad);
    return 4 + n + pad;
}

static int read_full(int fd, unsigned char *p, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r <= 0)
            return -1;
        got += (size_t)r;
    }
    return 0;
}

/* Build and send one RPCSEC_GSS call. gc_proc: 0=DATA, 3=DESTROY. When body is
 * non-NULL the args are integrity-wrapped (opaque(seq‖body) + opaque(mic)). */
static int send_call(int fd, gss_ctx_id_t ctx, uint32_t xid, uint32_t gc_proc,
                     uint32_t rq_proc, uint32_t seq, const unsigned char *handle,
                     size_t hlen, int corrupt_verf, const unsigned char *body,
                     size_t bodylen) {
    unsigned char cred[1024];
    size_t ci = 0;
    xdr_u32(cred + ci, 1);
    ci += 4;
    xdr_u32(cred + ci, gc_proc);
    ci += 4;
    xdr_u32(cred + ci, seq);
    ci += 4;
    xdr_u32(cred + ci, RPCSEC_GSS_SVC_INTEGRITY);
    ci += 4;
    ci += put_opaque(cred + ci, handle, hlen);

    unsigned char header[2048];
    size_t hi = 0;
    xdr_u32(header + hi, xid);
    hi += 4;
    xdr_u32(header + hi, 0);
    hi += 4;
    xdr_u32(header + hi, 2);
    hi += 4;
    xdr_u32(header + hi, KADM);
    hi += 4;
    xdr_u32(header + hi, KADMVERS);
    hi += 4;
    xdr_u32(header + hi, rq_proc);
    hi += 4;
    xdr_u32(header + hi, 6);
    hi += 4;
    hi += put_opaque(header + hi, cred, ci);

    /* Header MIC first (GSS seq N). */
    gss_buffer_desc hbuf, hverf;
    OM_uint32 maj, min;
    hbuf.value = header;
    hbuf.length = hi;
    hverf.value = NULL;
    hverf.length = 0;
    maj = gss_get_mic(&min, ctx, GSS_C_QOP_DEFAULT, &hbuf, &hverf);
    if (maj != GSS_S_COMPLETE) {
        printf("header_mic=fail=%u\n", (unsigned)maj);
        return 1;
    }
    if (corrupt_verf && hverf.length > 0)
        ((unsigned char *)hverf.value)[hverf.length - 1] ^= 0xff;

    /* Integrity args, MIC second (GSS seq N+1). */
    unsigned char args[512];
    size_t arglen = 0;
    gss_buffer_desc mic;
    mic.value = NULL;
    mic.length = 0;
    if (body != NULL) {
        unsigned char db[256];
        xdr_u32(db, seq);
        memcpy(db + 4, body, bodylen);
        size_t dblen = 4 + bodylen;
        gss_buffer_desc in;
        in.value = db;
        in.length = dblen;
        maj = gss_get_mic(&min, ctx, GSS_C_QOP_DEFAULT, &in, &mic);
        if (maj != GSS_S_COMPLETE) {
            printf("data_mic=fail=%u\n", (unsigned)maj);
            return 1;
        }
        arglen += put_opaque(args + arglen, db, dblen);
        arglen += put_opaque(args + arglen, (unsigned char *)mic.value, mic.length);
    }

    unsigned char rec[4096];
    memcpy(rec, header, hi);
    size_t ri = hi;
    xdr_u32(rec + ri, 6);
    ri += 4;
    ri += put_opaque(rec + ri, hverf.value, hverf.length);
    if (arglen > 0) {
        memcpy(rec + ri, args, arglen);
        ri += arglen;
    }
    gss_release_buffer(&min, &hverf);
    if (mic.value != NULL)
        gss_release_buffer(&min, &mic);

    unsigned char fb[4];
    xdr_u32(fb, 0x80000000u | (uint32_t)ri);
    if (write(fd, fb, 4) != 4 || write(fd, rec, ri) != (ssize_t)ri) {
        printf("write=fail\n");
        return 1;
    }
    return 0;
}

static void recv_report(int fd, const char *tag) {
    unsigned char rh[4];
    if (read_full(fd, rh, 4) != 0) {
        printf("%s label=EOF\n", tag);
        return;
    }
    uint32_t n = rd_u32(rh) & 0x7fffffffu;
    if (n < 12 || n > 8192) {
        printf("%s label=BADLEN n=%u\n", tag, n);
        return;
    }
    unsigned char body[8192];
    if (read_full(fd, body, n) != 0) {
        printf("%s label=EOF2\n", tag);
        return;
    }
    uint32_t reply_stat = rd_u32(body + 8);
    const char *label = "UNKNOWN";
    uint32_t code = 0;
    if (reply_stat == 1) {
        uint32_t rej = rd_u32(body + 12);
        code = rd_u32(body + 16);
        if (rej == 1) {
            if (code == 1)
                label = "AUTH_BADCRED";
            else if (code == 2)
                label = "AUTH_REJECTEDCRED";
            else if (code == 7)
                label = "AUTH_FAILED";
            else if (code == 13)
                label = "CREDPROBLEM";
            else if (code == 14)
                label = "CTXPROBLEM";
            else
                label = "AUTH_ERROR";
        } else {
            label = "DENIED";
        }
    } else {
        size_t off = 12;
        off += 4;
        uint32_t vn = rd_u32(body + off);
        off += 4 + vn + ((4 - (vn % 4)) % 4);
        if (off + 4 <= n) {
            code = rd_u32(body + off);
            if (code == 0)
                label = "SUCCESS";
            else if (code == 4)
                label = "GARBAGE_ARGS";
            else
                label = "ACCEPT";
        }
    }
    printf("%s label=%s code=%u reply_stat=%u\n", tag, label, code, reply_stat);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s host service mode [port]\n", argv[0]);
        return 2;
    }
    char *host = argv[1];
    char *service = argv[2];
    char *mode = argv[3];
    int port = (argc >= 5 && argv[4][0]) ? atoi(argv[4]) : KADMIND_PORT;

    int fd = connect_to(host, port);
    if (fd < 0) {
        printf("connect=fail\n");
        return 1;
    }
    CLIENT *clnt = clnttcp_create(NULL, KADM, KADMVERS, &fd, 0, 0);
    if (clnt == NULL) {
        printf("clnttcp_create=fail\n");
        return 1;
    }
    gss_buffer_desc nbuf;
    nbuf.value = service;
    nbuf.length = strlen(service);
    gss_name_t target = GSS_C_NO_NAME;
    OM_uint32 maj, min;
    maj = gss_import_name(&min, &nbuf, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &target);
    if (maj != GSS_S_COMPLETE) {
        printf("import_name=fail=%u\n", (unsigned)maj);
        return 1;
    }
    struct rpc_gss_sec sec;
    sec.mech = (gss_OID)gss_mech_krb5;
    sec.qop = GSS_C_QOP_DEFAULT;
    sec.svc = RPCSEC_GSS_SVC_INTEGRITY;
    sec.cred = GSS_C_NO_CREDENTIAL;
    sec.req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;
    clnt->cl_auth = authgss_create(clnt, target, &sec);
    if (clnt->cl_auth == NULL) {
        printf("authgss_create=fail\n");
        return 1;
    }
    struct authgss_private_data pd;
    memset(&pd, 0, sizeof(pd));
    if (!authgss_get_private_data(clnt->cl_auth, &pd) || pd.pd_ctx == GSS_C_NO_CONTEXT) {
        printf("private_data=fail\n");
        return 1;
    }
    printf("init_code=0\n");

    unsigned char handle[512];
    size_t hlen = pd.pd_ctx_hndl.length;
    if (hlen > sizeof(handle))
        hlen = sizeof(handle);
    memcpy(handle, pd.pd_ctx_hndl.value, hlen);

    unsigned char lst[64];
    xdr_u32(lst, KADM5_API_VERSION_2);
    size_t lstlen = 4 + put_opaque(lst + 4, (const unsigned char *)"*", 2);

    if (!strcmp(mode, "corrupt-verf")) {
        send_call(fd, pd.pd_ctx, 0x50524231, 0, GET_PRINCS, 1, handle, hlen, 1, lst, lstlen);
        recv_report(fd, "corrupt-verf");
    } else if (!strcmp(mode, "maxseq")) {
        send_call(fd, pd.pd_ctx, 0x50524232, 0, GET_PRINCS, 0x80000001u, handle, hlen, 0, lst, lstlen);
        recv_report(fd, "maxseq");
    } else if (!strcmp(mode, "wrong-handle")) {
        unsigned char wh[512];
        memcpy(wh, handle, hlen);
        if (hlen > 0)
            wh[hlen - 1] ^= 0xff;
        send_call(fd, pd.pd_ctx, 0x50524233, 0, GET_PRINCS, 1, wh, hlen, 0, lst, lstlen);
        recv_report(fd, "wrong-handle");
    } else if (!strcmp(mode, "destroy-then-data")) {
        send_call(fd, pd.pd_ctx, 0x50524234, 3, 0, 1, handle, hlen, 0, NULL, 0);
        recv_report(fd, "destroy");
        send_call(fd, pd.pd_ctx, 0x50524235, 0, GET_PRINCS, 2, handle, hlen, 0, lst, lstlen);
        recv_report(fd, "data-after-destroy");
    } else if (!strcmp(mode, "garbage-args")) {
        unsigned char junk[2] = {0x00, 0x01};
        send_call(fd, pd.pd_ctx, 0x50524236, 0, GET_PRINCS, 1, handle, hlen, 0, junk, sizeof(junk));
        recv_report(fd, "garbage-args");
    } else {
        send_call(fd, pd.pd_ctx, 0x50524237, 0, GET_PRINCS, 1, handle, hlen, 0, lst, lstlen);
        recv_report(fd, "valid");
    }
    return 0;
}
