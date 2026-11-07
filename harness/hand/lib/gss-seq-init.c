/* gss-seq-init.c: MIT libgssapi_krb5 initiator for the initial-sequence-number settle (scratch; not part of the product).
 *
 * usage: gss-seq-init HOST SERVICE IP PORT
 *   HOST SERVICE   the target, host-based: SERVICE@HOST (host/testhost.kerber.test with dns_canonicalize_hostname = false)
 *   env GSS_NOSEQ=1          request neither GSS_C_REPLAY_FLAG nor GSS_C_SEQUENCE_FLAG (the flags of scripts/oracle/gss-mit-client.c)
 *   env GSS_CHANNEL_BOUND=1  request GSS_C_CHANNEL_BOUND_FLAG and pass channel bindings (application data "tls-unique-test")
 *   env GSS_BINDINGS_ONLY=1  pass the same channel bindings without the flag
 *
 * Sends, each as a 4-byte big-endian length and the token: the initial token (AP-REQ), then once the AP-REP is read a wrap token
 * (confidentiality) of "hello-from-mit-gss", the plaintext "mic-message" and its MIC token. Prints what MIT's initiator reports of itself.
 */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void show(const char *what, OM_uint32 maj, OM_uint32 min)
{
    OM_uint32 mctx = 0, mj, mn;
    gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
    fprintf(stderr, "%s: maj=0x%x min=%u\n", what, maj, min);
    do {
        mj = gss_display_status(&mn, maj, GSS_C_GSS_CODE, GSS_C_NO_OID, &mctx, &msg);
        if (msg.length)
            fprintf(stderr, "  gss: %.*s\n", (int)msg.length, (char *)msg.value);
        gss_release_buffer(&mn, &msg);
    } while (mctx && mj == GSS_S_COMPLETE);
    mctx = 0;
    do {
        mj = gss_display_status(&mn, min, GSS_C_MECH_CODE, GSS_C_NO_OID, &mctx, &msg);
        if (msg.length)
            fprintf(stderr, "  mech: %.*s\n", (int)msg.length, (char *)msg.value);
        gss_release_buffer(&mn, &msg);
    } while (mctx && mj == GSS_S_COMPLETE);
}

static void die(const char *what, OM_uint32 maj, OM_uint32 min)
{
    show(what, maj, min);
    exit(1);
}

static void send_tok(int fd, const void *p, size_t n)
{
    uint32_t len = htonl((uint32_t)n);
    if (write(fd, &len, 4) != 4 || (n && write(fd, p, n) != (ssize_t)n)) {
        perror("write");
        exit(1);
    }
}

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

static void recv_tok(int fd, gss_buffer_desc *tok)
{
    uint32_t n = 0;
    if (!read_full(fd, &n, 4)) {
        perror("read length");
        exit(1);
    }
    n = ntohl(n);
    tok->length = n;
    tok->value = malloc(n ? n : 1);
    if (n && !read_full(fd, tok->value, n)) {
        perror("read token");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: %s HOST SERVICE IP PORT\n", argv[0]);
        return 2;
    }
    char namebuf[256];
    snprintf(namebuf, sizeof namebuf, "%s@%s", argv[2], argv[1]);
    gss_buffer_desc name_buf = { strlen(namebuf), namebuf };
    gss_name_t target = GSS_C_NO_NAME;
    OM_uint32 maj, min;
    maj = gss_import_name(&min, &name_buf, GSS_C_NT_HOSTBASED_SERVICE, &target);
    if (maj != GSS_S_COMPLETE)
        die("import_name", maj, min);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)atoi(argv[4]));
    inet_pton(AF_INET, argv[3], &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        perror("connect");
        return 1;
    }

    OM_uint32 req_flags = GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;
    if (getenv("GSS_NOMUTUAL"))
        req_flags &= ~GSS_C_MUTUAL_FLAG;
    if (!getenv("GSS_NOSEQ"))
        req_flags |= GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG;
    struct gss_channel_bindings_struct cb;
    memset(&cb, 0, sizeof cb);
    gss_channel_bindings_t cbt = GSS_C_NO_CHANNEL_BINDINGS;
    if (getenv("GSS_CHANNEL_BOUND") || getenv("GSS_BINDINGS_ONLY")) {
        if (getenv("GSS_CHANNEL_BOUND"))
            req_flags |= GSS_C_CHANNEL_BOUND_FLAG;
        cb.application_data.value = "tls-unique-test";
        cb.application_data.length = strlen("tls-unique-test");
        cbt = &cb;
    }

    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc in = { 0, NULL }, out = { 0, NULL };
    OM_uint32 ret_flags = 0;
    do {
        maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &ctx, target, (gss_OID)gss_mech_krb5, req_flags, 0, cbt,
                                   in.length ? &in : GSS_C_NO_BUFFER, NULL, &out, &ret_flags, NULL);
        if (in.value) {
            free(in.value);
            in.value = NULL;
            in.length = 0;
        }
        if (out.length) {
            send_tok(fd, out.value, out.length);
            gss_release_buffer(&min, &out);
        }
        if (maj == GSS_S_CONTINUE_NEEDED)
            recv_tok(fd, &in);
        else if (maj != GSS_S_COMPLETE)
            die("init_sec_context", maj, min);
    } while (maj == GSS_S_CONTINUE_NEEDED);
    fprintf(stderr, "mit-gss init: requested=0x%x ret_flags=0x%x\n", req_flags, ret_flags);

    int conf = 0;
    gss_buffer_desc payload = { strlen("hello-from-mit-gss"), "hello-from-mit-gss" }, wrapped = { 0, NULL };
    maj = gss_wrap(&min, ctx, 1, GSS_C_QOP_DEFAULT, &payload, &conf, &wrapped);
    if (maj != GSS_S_COMPLETE)
        die("wrap", maj, min);
    send_tok(fd, wrapped.value, wrapped.length);
    gss_release_buffer(&min, &wrapped);

    gss_buffer_desc msg = { strlen("mic-message"), "mic-message" }, mic = { 0, NULL };
    maj = gss_get_mic(&min, ctx, GSS_C_QOP_DEFAULT, &msg, &mic);
    if (maj != GSS_S_COMPLETE)
        die("get_mic", maj, min);
    send_tok(fd, msg.value, msg.length);
    send_tok(fd, mic.value, mic.length);
    gss_release_buffer(&min, &mic);
    fprintf(stderr, "mit-gss sent: wrap, then the message and its MIC\n");

    gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
    gss_release_name(&min, &target);
    close(fd);
    return 0;
}
