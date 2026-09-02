/* Minimal MIT libgssapi_krb5 initiator: AP-REQ + wrap to krb5-gss-accept.
 * Out-of-process only; not linked into the Rust product.
 */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
static gss_OID_desc oid_spnego = { 6, (void *)"\x2b\x06\x01\x05\x05\x02" };
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
    int want_deleg = 0;
    int want_iov = 0;
    int want_sign = 0;
    gss_OID mech = (gss_OID)gss_mech_krb5;
    if (argc >= 7) {
        if (strcmp(argv[6], "deleg") == 0) {
            want_deleg = 1;
        } else if (strcmp(argv[6], "spnego") == 0) {
            mech = &oid_spnego;
        } else if (strcmp(argv[6], "iov") == 0) {
            want_iov = 1;
        } else if (strcmp(argv[6], "sign") == 0) {
            want_iov = 1;
            want_sign = 1;
        }
    }

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
    const char *dump_path = getenv("GSS_DUMP_TOKEN");
    int dumped = 0;
    do {
        maj = gss_init_sec_context(
            &min,
            GSS_C_NO_CREDENTIAL,
            &ctx,
            target,
            mech,
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
            if (dump_path && !dumped) {
                FILE *df = fopen(dump_path, "wb");
                if (!df) {
                    perror("GSS_DUMP_TOKEN");
                    exit(1);
                }
                if (fwrite(out.value, 1, out.length, df) != out.length) {
                    perror("GSS_DUMP_TOKEN write");
                    exit(1);
                }
                fclose(df);
                dumped = 1;
            }
            send_token(fd, &out);
            gss_release_buffer(&min, &out);
        }
        if (maj == GSS_S_CONTINUE_NEEDED) {
            recv_token(fd, &in);
        } else if (maj != GSS_S_COMPLETE) {
            die_gss("init_sec_context", maj, min);
        }
    } while (maj == GSS_S_CONTINUE_NEEDED);

    {
        OM_uint32 lifetime = 0, flags = 0;
        maj = gss_inquire_context(&min, ctx, NULL, NULL, &lifetime, NULL, &flags, NULL, NULL);
        if (maj != GSS_S_COMPLETE) {
            die_gss("inquire_context", maj, min);
        }
        fprintf(stderr, "mit-gss inquire flags=%u lifetime=%u\n", flags, lifetime);
    }

    int conf = 0;
    if (want_iov) {
        gss_iov_buffer_desc iov[5];
        int n = 0;
        char assoc[] = "rpc-hdr";
        size_t msglen = strlen(msg);
        void *payload = malloc(msglen ? msglen : 1);
        if (!payload) {
            perror("malloc");
            exit(1);
        }
        memcpy(payload, msg, msglen);
        iov[n].type = GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
        iov[n].buffer.value = NULL;
        iov[n].buffer.length = 0;
        n++;
        if (want_sign) {
            iov[n].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
            iov[n].buffer.value = assoc;
            iov[n].buffer.length = sizeof assoc - 1;
            n++;
        }
        iov[n].type = GSS_IOV_BUFFER_TYPE_DATA;
        iov[n].buffer.value = payload;
        iov[n].buffer.length = msglen;
        n++;
        iov[n].type = GSS_IOV_BUFFER_TYPE_PADDING | GSS_IOV_BUFFER_FLAG_ALLOCATE;
        iov[n].buffer.value = NULL;
        iov[n].buffer.length = 0;
        n++;
        iov[n].type = GSS_IOV_BUFFER_TYPE_TRAILER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
        iov[n].buffer.value = NULL;
        iov[n].buffer.length = 0;
        n++;
        maj = gss_wrap_iov(&min, ctx, 1, GSS_C_QOP_DEFAULT, &conf, iov, n);
        if (maj != GSS_S_COMPLETE) {
            die_gss("wrap_iov", maj, min);
        }
        size_t total = 0;
        int i;
        for (i = 0; i < n; i++) {
            OM_uint32 t = GSS_IOV_BUFFER_TYPE(iov[i].type);
            if (t == GSS_IOV_BUFFER_TYPE_HEADER || t == GSS_IOV_BUFFER_TYPE_DATA
                || t == GSS_IOV_BUFFER_TYPE_PADDING || t == GSS_IOV_BUFFER_TYPE_TRAILER) {
                total += iov[i].buffer.length;
            }
        }
        gss_buffer_desc wrapped = { total, malloc(total ? total : 1) };
        if (!wrapped.value) {
            perror("malloc");
            exit(1);
        }
        unsigned char *p = wrapped.value;
        for (i = 0; i < n; i++) {
            OM_uint32 t = GSS_IOV_BUFFER_TYPE(iov[i].type);
            if (t == GSS_IOV_BUFFER_TYPE_HEADER || t == GSS_IOV_BUFFER_TYPE_DATA
                || t == GSS_IOV_BUFFER_TYPE_PADDING || t == GSS_IOV_BUFFER_TYPE_TRAILER) {
                memcpy(p, iov[i].buffer.value, iov[i].buffer.length);
                p += iov[i].buffer.length;
            }
        }
        send_token(fd, &wrapped);
        free(wrapped.value);
        gss_release_iov_buffer(&min, iov, n);
        free(payload);
        fprintf(stderr, "mit-gss wrap_iov sent %s sign=%d\n", msg, want_sign);
    } else {
        gss_buffer_desc payload = { strlen(msg), (void *)msg };
        gss_buffer_desc wrapped = { 0, NULL };
        maj = gss_wrap(&min, ctx, 1, GSS_C_QOP_DEFAULT, &payload, &conf, &wrapped);
        if (maj != GSS_S_COMPLETE) {
            die_gss("wrap", maj, min);
        }
        send_token(fd, &wrapped);
        gss_release_buffer(&min, &wrapped);
        fprintf(stderr, "mit-gss wrap sent %s\n", msg);
    }
    gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
    gss_release_name(&min, &target);
    close(fd);
    return 0;
}
