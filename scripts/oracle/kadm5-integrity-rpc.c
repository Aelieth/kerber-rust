/* RPCSEC_GSS integrity-service client: GET_PRINCS over rpc_gss_svc_integrity
 * (RFC 2203 databody_integ + checksum). Out-of-process only; compiled in the
 * MIT 1.22.2 image. gprincs_arg/ret mirror kadm_rpc.h (not a public header).
 * usage: kadm5-integrity-rpc <host> <service-princ> [none|integrity|privacy|tamper]
 */
#include <gssrpc/rpc.h>
#include <gssrpc/auth_gss.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <kadm5/admin.h>
#include <krb5.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define KADM 2112
#define KADMVERS 2
#define GET_PRINCS 14
#define KADMIND_PORT 749

/* Connect a TCP socket to host:port (kadmind is not in the portmapper), like
 * the MIT client's connect_to_server (client_init.c:521). */
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

struct gprincs_arg {
    krb5_ui_4 api_version;
    char *exp;
};
struct gprincs_ret {
    krb5_ui_4 api_version;
    kadm5_ret_t code;
    char **princs;
    int count;
};
extern bool_t xdr_gprincs_arg(XDR *, struct gprincs_arg *);
extern bool_t xdr_gprincs_ret(XDR *, struct gprincs_ret *);

static void xdr_u32(unsigned char *p, uint32_t n) {
    p[0] = (unsigned char)(n >> 24);
    p[1] = (unsigned char)(n >> 16);
    p[2] = (unsigned char)(n >> 8);
    p[3] = (unsigned char)n;
}

static size_t xdr_opaque_put(unsigned char *p, const unsigned char *v, size_t n) {
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

/* After RPCSEC INIT, send GET_PRINCS DATA with a flipped integrity checksum. */
static int send_tampered(int fd, AUTH *auth) {
    struct authgss_private_data pd;
    memset(&pd, 0, sizeof(pd));
    if (!authgss_get_private_data(auth, &pd) || pd.pd_ctx == GSS_C_NO_CONTEXT) {
        printf("private_data=fail\n");
        fflush(stdout);
        return 1;
    }
    printf("hndl_len=%u\n", (unsigned)pd.pd_ctx_hndl.length);
    fflush(stdout);
    uint32_t seq = 1;
    unsigned char arg[64];
    size_t argn = 0;
    xdr_u32(arg, KADM5_API_VERSION_2);
    argn = 4 + xdr_opaque_put(arg + 4, (const unsigned char *)"*", 2);
    unsigned char databody[80];
    xdr_u32(databody, seq);
    memcpy(databody + 4, arg, argn);
    size_t dblen = 4 + argn;
    gss_buffer_desc in, mic;
    OM_uint32 maj, min;
    in.value = databody;
    in.length = dblen;
    mic.value = NULL;
    mic.length = 0;
    maj = gss_get_mic(&min, pd.pd_ctx, GSS_C_QOP_DEFAULT, &in, &mic);
    if (maj != GSS_S_COMPLETE || mic.length == 0) {
        printf("get_mic=fail=%u\n", (unsigned)maj);
        return 1;
    }
    ((unsigned char *)mic.value)[mic.length - 1] ^= 0xff;

    unsigned char cred[128];
    size_t ci = 0;
    xdr_u32(cred + ci, 1); ci += 4;
    xdr_u32(cred + ci, 0); ci += 4;
    xdr_u32(cred + ci, seq); ci += 4;
    xdr_u32(cred + ci, RPCSEC_GSS_SVC_INTEGRITY); ci += 4;
    ci += xdr_opaque_put(cred + ci, pd.pd_ctx_hndl.value, pd.pd_ctx_hndl.length);

    unsigned char header[256];
    uint32_t xid = 0x494e5447;
    size_t hi = 0;
    xdr_u32(header + hi, xid); hi += 4;
    xdr_u32(header + hi, 0); hi += 4;
    xdr_u32(header + hi, 2); hi += 4;
    xdr_u32(header + hi, KADM); hi += 4;
    xdr_u32(header + hi, KADMVERS); hi += 4;
    xdr_u32(header + hi, GET_PRINCS); hi += 4;
    xdr_u32(header + hi, 6); hi += 4;
    hi += xdr_opaque_put(header + hi, cred, ci);

    gss_buffer_desc hbuf, hverf;
    hbuf.value = header;
    hbuf.length = hi;
    hverf.value = NULL;
    hverf.length = 0;
    maj = gss_get_mic(&min, pd.pd_ctx, GSS_C_QOP_DEFAULT, &hbuf, &hverf);
    if (maj != GSS_S_COMPLETE) {
        printf("header_mic=fail=%u\n", (unsigned)maj);
        return 1;
    }

    unsigned char rec[512];
    memcpy(rec, header, hi);
    size_t ri = hi;
    xdr_u32(rec + ri, 6); ri += 4;
    ri += xdr_opaque_put(rec + ri, hverf.value, hverf.length);
    ri += xdr_opaque_put(rec + ri, databody, dblen);
    ri += xdr_opaque_put(rec + ri, mic.value, mic.length);
    gss_release_buffer(&min, &mic);
    gss_release_buffer(&min, &hverf);

    uint32_t flen = 0x80000000u | (uint32_t)ri;
    unsigned char flenb[4];
    xdr_u32(flenb, flen);
    if (write(fd, flenb, 4) != 4 || write(fd, rec, ri) != (ssize_t)ri) {
        printf("write=fail\n");
        return 1;
    }
    unsigned char rh[4];
    if (read_full(fd, rh, 4) != 0) {
        printf("read_hdr=fail\n");
        return 1;
    }
    uint32_t n = ((uint32_t)rh[0] << 24) | ((uint32_t)rh[1] << 16) |
                 ((uint32_t)rh[2] << 8) | (uint32_t)rh[3];
    n &= 0x7fffffffu;
    if (n < 20 || n > 4096) {
        printf("reply_len=%u\n", n);
        return 1;
    }
    unsigned char body[4096];
    if (read_full(fd, body, n) != 0) {
        printf("read_body=fail\n");
        return 1;
    }
    uint32_t mtype = ((uint32_t)body[4] << 24) | ((uint32_t)body[5] << 16) |
                     ((uint32_t)body[6] << 8) | (uint32_t)body[7];
    uint32_t reply_stat = ((uint32_t)body[8] << 24) | ((uint32_t)body[9] << 16) |
                          ((uint32_t)body[10] << 8) | (uint32_t)body[11];
    printf("mtype=%u\n", mtype);
    printf("reply_stat=%u\n", reply_stat);
    printf("reply_words=%u,%u,%u,%u,%u,%u\n",
           ((uint32_t)body[0] << 24) | ((uint32_t)body[1] << 16) | ((uint32_t)body[2] << 8) | (uint32_t)body[3],
           ((uint32_t)body[4] << 24) | ((uint32_t)body[5] << 16) | ((uint32_t)body[6] << 8) | (uint32_t)body[7],
           ((uint32_t)body[8] << 24) | ((uint32_t)body[9] << 16) | ((uint32_t)body[10] << 8) | (uint32_t)body[11],
           n > 16 ? ((uint32_t)body[12] << 24) | ((uint32_t)body[13] << 16) | ((uint32_t)body[14] << 8) | (uint32_t)body[15] : 0,
           n > 20 ? ((uint32_t)body[16] << 24) | ((uint32_t)body[17] << 16) | ((uint32_t)body[18] << 8) | (uint32_t)body[19] : 0,
           n > 24 ? ((uint32_t)body[20] << 24) | ((uint32_t)body[21] << 16) | ((uint32_t)body[22] << 8) | (uint32_t)body[23] : 0);
    fflush(stdout);
    /* Skip verifier: flavor u32 + opaque. */
    size_t off = 12;
    uint32_t vflav = ((uint32_t)body[off] << 24) | ((uint32_t)body[off + 1] << 16) |
                     ((uint32_t)body[off + 2] << 8) | (uint32_t)body[off + 3];
    (void)vflav;
    off += 4;
    uint32_t vn = ((uint32_t)body[off] << 24) | ((uint32_t)body[off + 1] << 16) |
                  ((uint32_t)body[off + 2] << 8) | (uint32_t)body[off + 3];
    off += 4 + vn + ((4 - (vn % 4)) % 4);
    if (reply_stat == 0 && off + 4 <= n) {
        uint32_t ast = ((uint32_t)body[off] << 24) | ((uint32_t)body[off + 1] << 16) |
                       ((uint32_t)body[off + 2] << 8) | (uint32_t)body[off + 3];
        printf("accept_stat=%u\n", ast);
        if (ast == 4)
            printf("garbage_args=1\n");
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s host service [none|integrity|privacy|tamper]\n", argv[0]);
        return 2;
    }
    char *host = argv[1];
    char *service = argv[2];
    rpc_gss_svc_t svc = RPCSEC_GSS_SVC_INTEGRITY;
    int tamper = 0;
    if (argc >= 4) {
        if (!strcmp(argv[3], "none"))
            svc = RPCSEC_GSS_SVC_NONE;
        else if (!strcmp(argv[3], "privacy"))
            svc = RPCSEC_GSS_SVC_PRIVACY;
        else if (!strcmp(argv[3], "tamper")) {
            svc = RPCSEC_GSS_SVC_INTEGRITY;
            tamper = 1;
        }
    }

    int port = KADMIND_PORT;
    if (argc >= 5 && argv[4][0])
        port = atoi(argv[4]);
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
    sec.svc = svc;
    sec.cred = GSS_C_NO_CREDENTIAL;
    sec.req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;

    clnt->cl_auth = authgss_create(clnt, target, &sec);
    if (clnt->cl_auth == NULL) {
        printf("authgss_create=fail\n");
        return 1;
    }
    printf("init_code=0\n");
    printf("svc=%d\n", (int)svc);
    if (tamper)
        return send_tampered(fd, clnt->cl_auth);

    struct gprincs_arg arg;
    struct gprincs_ret ret;
    memset(&arg, 0, sizeof(arg));
    memset(&ret, 0, sizeof(ret));
    arg.api_version = KADM5_API_VERSION_2;
    arg.exp = "*";
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    enum clnt_stat st = clnt_call(clnt, GET_PRINCS, (xdrproc_t)xdr_gprincs_arg,
                                  (caddr_t)&arg, (xdrproc_t)xdr_gprincs_ret,
                                  (caddr_t)&ret, tv);
    printf("clnt_stat=%d\n", (int)st);
    if (st != RPC_SUCCESS) {
        printf("list_code=-1\n");
        return 1;
    }
    printf("list_code=%ld\n", (long)ret.code);
    printf("count=%d\n", ret.count);
    return 0;
}
