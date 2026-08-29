/* Minimal MIT libgssapi_krb5 initiator: AP-REQ + wrap to krb5-gss-accept.
 * Out-of-process only; not linked into the Rust product.
 */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void die_gss(const char *what, OM_uint32 maj, OM_uint32 min) {
    fprintf(stderr, "%s: maj=%u min=%u\n", what, maj, min);
    exit(1);
}

static void send_token(int fd, gss_buffer_t tok) {
    uint32_t n = htonl((uint32_t)tok->length);
    if (write(fd, &n, 4) != 4) {
        perror("write len");
        exit(1);
    }
    if (tok->length && write(fd, tok->value, tok->length) != (ssize_t)tok->length) {
        perror("write tok");
        exit(1);
    }
}

static void recv_token(int fd, gss_buffer_desc *tok) {
    uint32_t n = 0;
    if (read(fd, &n, 4) != 4) {
        perror("read len");
        exit(1);
    }
    n = ntohl(n);
    tok->length = n;
    tok->value = malloc(n ? n : 1);
    if (n && read(fd, tok->value, n) != (ssize_t)n) {
        perror("read tok");
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s host service msg ip port\n", argv[0]);
        return 2;
    }
    const char *host = argv[1];
    const char *service = argv[2];
    const char *msg = argv[3];
    const char *ip = argv[4];
    int port = atoi(argv[5]);
    int want_deleg = argc >= 7 && strcmp(argv[6], "deleg") == 0;

    char namebuf[256];
    snprintf(namebuf, sizeof namebuf, "%s@%s", service, host);

    gss_buffer_desc name_buf = { strlen(namebuf), namebuf };
    gss_name_t target = GSS_C_NO_NAME;
    OM_uint32 maj, min;
    maj = gss_import_name(&min, &name_buf, GSS_C_NT_HOSTBASED_SERVICE, &target);
    if (maj != GSS_S_COMPLETE) {
        die_gss("import_name", maj, min);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        perror("connect");
        return 1;
    }

    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc in = { 0, NULL };
    gss_buffer_desc out = { 0, NULL };
    OM_uint32 ret_flags = 0;
    do {
        maj = gss_init_sec_context(
            &min,
            GSS_C_NO_CREDENTIAL,
            &ctx,
            target,
            (gss_OID)gss_mech_krb5,
            GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG
                | (want_deleg ? GSS_C_DELEG_FLAG : 0),
            0,
            GSS_C_NO_CHANNEL_BINDINGS,
            (in.length ? &in : GSS_C_NO_BUFFER),
            NULL,
            &out,
            &ret_flags,
            NULL);
        if (in.value) {
            free(in.value);
            in.value = NULL;
            in.length = 0;
        }
        if (out.length) {
            send_token(fd, &out);
            gss_release_buffer(&min, &out);
        }
        if (maj == GSS_S_CONTINUE_NEEDED) {
            recv_token(fd, &in);
        } else if (maj != GSS_S_COMPLETE) {
            die_gss("init_sec_context", maj, min);
        }
    } while (maj == GSS_S_CONTINUE_NEEDED);

    gss_buffer_desc payload = { strlen(msg), (void *)msg };
    gss_buffer_desc wrapped = { 0, NULL };
    int conf = 0;
    maj = gss_wrap(&min, ctx, 1, GSS_C_QOP_DEFAULT, &payload, &conf, &wrapped);
    if (maj != GSS_S_COMPLETE) {
        die_gss("wrap", maj, min);
    }
    send_token(fd, &wrapped);
    gss_release_buffer(&min, &wrapped);
    gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
    gss_release_name(&min, &target);
    close(fd);
    fprintf(stderr, "mit-gss wrap sent %s\n", msg);
    return 0;
}
