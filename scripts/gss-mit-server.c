/* MIT libgssapi_krb5 acceptor: print delegated name from GSS_C_DELEG_FLAG.
 * Out-of-process only; not linked into the Rust product.
 */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void die_gss(const char *what, OM_uint32 maj, OM_uint32 min) {
    OM_uint32 mctx = 0, mj, mn;
    gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
    fprintf(stderr, "%s: maj=%u min=%u\n", what, maj, min);
    do {
        mj = gss_display_status(&mn, maj, GSS_C_GSS_CODE, GSS_C_NO_OID, &mctx, &msg);
        if (msg.length) {
            fprintf(stderr, "  gss: %.*s\n", (int)msg.length, (char *)msg.value);
        }
        gss_release_buffer(&mn, &msg);
    } while (mctx && mj == GSS_S_COMPLETE);
    mctx = 0;
    do {
        mj = gss_display_status(&mn, min, GSS_C_MECH_CODE, GSS_C_NO_OID, &mctx, &msg);
        if (msg.length) {
            fprintf(stderr, "  mech: %.*s\n", (int)msg.length, (char *)msg.value);
        }
        gss_release_buffer(&mn, &msg);
    } while (mctx && mj == GSS_S_COMPLETE);
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

static ssize_t read_full(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r <= 0) {
            return r;
        }
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static void recv_token(int fd, gss_buffer_desc *tok) {
    uint32_t n = 0;
    if (read_full(fd, &n, 4) != 4) {
        perror("read len");
        exit(1);
    }
    n = ntohl(n);
    fprintf(stderr, "mit-gss-server token n=%u\n", n);
    if (n == 0 || n > 1024 * 1024) {
        fprintf(stderr, "mit-gss-server bad token length\n");
        exit(1);
    }
    tok->length = n;
    tok->value = malloc(n);
    if (!tok->value) {
        perror("malloc");
        exit(1);
    }
    if (read_full(fd, tok->value, n) != (ssize_t)n) {
        perror("read tok");
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s keytab ip port\n", argv[0]);
        return 2;
    }
    const char *keytab = argv[1];
    const char *ip = argv[2];
    int port = atoi(argv[3]);
    signal(SIGPIPE, SIG_IGN);
    setenv("KRB5_KTNAME", keytab, 1);

    gss_buffer_desc nbuf = { strlen("host@testhost.kerber.test"),
                             (void *)"host@testhost.kerber.test" };
    gss_name_t aname = GSS_C_NO_NAME;
    gss_cred_id_t acred = GSS_C_NO_CREDENTIAL;
    OM_uint32 amaj, amin;
    amaj = gss_import_name(&amin, &nbuf, GSS_C_NT_HOSTBASED_SERVICE, &aname);
    if (amaj != GSS_S_COMPLETE) {
        die_gss("import_name", amaj, amin);
    }
    amaj = gss_acquire_cred(&amin, aname, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                            GSS_C_ACCEPT, &acred, NULL, NULL);
    if (amaj != GSS_S_COMPLETE) {
        die_gss("acquire_cred", amaj, amin);
    }
    gss_release_name(&amin, &aname);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(ls, 8) != 0) {
        perror("listen");
        return 1;
    }
    fprintf(stderr, "mit-gss-server listening\n");
    for (;;) {
    int fd = accept(ls, NULL, NULL);
    if (fd < 0) {
        perror("accept");
        continue;
    }

    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_cred_id_t deleg = GSS_C_NO_CREDENTIAL;
    gss_name_t src = GSS_C_NO_NAME;
    gss_buffer_desc in = { 0, NULL };
    gss_buffer_desc out = { 0, NULL };
    OM_uint32 maj, min, amin_err, ret_flags = 0;
    do {
        recv_token(fd, &in);
        maj = gss_accept_sec_context(
            &min,
            &ctx,
            acred,
            &in,
            GSS_C_NO_CHANNEL_BINDINGS,
            &src,
            NULL,
            &out,
            &ret_flags,
            NULL,
            &deleg);
        amin_err = min;
        free(in.value);
        in.value = NULL;
        in.length = 0;
        if (out.length) {
            send_token(fd, &out);
            gss_release_buffer(&min, &out);
        }
        if (maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
            fflush(stderr);
            die_gss("accept_sec_context", maj, amin_err);
        }
    } while (maj == GSS_S_CONTINUE_NEEDED);

    if (deleg != GSS_C_NO_CREDENTIAL) {
        gss_name_t dn = GSS_C_NO_NAME;
        maj = gss_inquire_cred(&min, deleg, &dn, NULL, NULL, NULL);
        if (maj == GSS_S_COMPLETE && dn != GSS_C_NO_NAME) {
            gss_buffer_desc nb = { 0, NULL };
            gss_OID t = GSS_C_NO_OID;
            if (gss_display_name(&min, dn, &nb, &t) == GSS_S_COMPLETE) {
                fprintf(stderr, "mit-gss delegated=%.*s\n", (int)nb.length, (char *)nb.value);
                gss_release_buffer(&min, &nb);
            }
            gss_release_name(&min, &dn);
        }
        gss_release_cred(&min, &deleg);
    } else {
        fprintf(stderr, "mit-gss delegated=\n");
    }

    {
        OM_uint32 lifetime = 0, flags = 0;
        maj = gss_inquire_context(&min, ctx, NULL, NULL, &lifetime, NULL, &flags, NULL, NULL);
        if (maj == GSS_S_COMPLETE) {
            fprintf(stderr, "mit-gss inquire flags=%u lifetime=%u\n", flags, lifetime);
        }
    }

    recv_token(fd, &in);
    gss_iov_buffer_desc iov[2];
    iov[0].type = GSS_IOV_BUFFER_TYPE_STREAM;
    iov[0].buffer = in;
    iov[1].type = GSS_IOV_BUFFER_TYPE_DATA | GSS_IOV_BUFFER_FLAG_ALLOCATE;
    iov[1].buffer.value = NULL;
    iov[1].buffer.length = 0;
    int conf = 0;
    maj = gss_unwrap_iov(&min, ctx, &conf, NULL, iov, 2);
    if (maj != GSS_S_COMPLETE) {
        die_gss("unwrap_iov", maj, min);
    }
    fprintf(stderr, "mit-gss unwrap ok %.*s\n",
        (int)iov[1].buffer.length, (char *)iov[1].buffer.value);
    gss_release_iov_buffer(&min, iov, 2);
    free(in.value);
    gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
    if (src != GSS_C_NO_NAME) {
        gss_release_name(&min, &src);
    }
    close(fd);
    }
}
