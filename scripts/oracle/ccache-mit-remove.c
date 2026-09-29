/* MIT krb5_cc_remove_cred oracle for ccache-gate. */
#include <krb5.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context ctx = NULL;
    krb5_ccache cc = NULL;
    krb5_creds mcred;
    const char *msg;

    if (argc != 3) {
        fprintf(stderr, "usage: ccache-mit-remove CCNAME SERVER\n");
        return 2;
    }
    memset(&mcred, 0, sizeof(mcred));
    ret = krb5_init_context(&ctx);
    if (ret) {
        fprintf(stderr, "krb5_init_context failed\n");
        return 1;
    }
    ret = krb5_cc_resolve(ctx, argv[1], &cc);
    if (ret)
        goto fail;
    ret = krb5_parse_name(ctx, argv[2], &mcred.server);
    if (ret)
        goto fail;
    ret = krb5_cc_remove_cred(ctx, cc, 0, &mcred);
    if (ret)
        goto fail;
    krb5_free_principal(ctx, mcred.server);
    krb5_cc_close(ctx, cc);
    krb5_free_context(ctx);
    return 0;

fail:
    msg = krb5_get_error_message(ctx, ret);
    fprintf(stderr, "krb5_cc_remove_cred: %s\n", msg);
    krb5_free_error_message(ctx, msg);
    if (mcred.server)
        krb5_free_principal(ctx, mcred.server);
    if (cc)
        krb5_cc_close(ctx, cc);
    krb5_free_context(ctx);
    return 1;
}
