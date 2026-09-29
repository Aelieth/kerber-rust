/* MIT krb5_change_password with a TGS-obtained kadmin/changepw ticket.
 * Out-of-process only; compiled in the MIT image (gss-mit-*.c).
 * usage: kpasswd-tgs-client <ccache> <realm> <newpw>
 * KPASSWD_TARGNAME_TYPE=<n>: krb5_set_password with target->type = n.
 * KPASSWD_TARGET=name@realm: krb5_set_password with that principal.
 * KPASSWD_AS_PASSWORD=<pw>: AS-REQ kadmin/changepw (INITIAL) instead of TGS.
 */
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    krb5_context ctx;
    krb5_ccache cc;
    krb5_principal princ;
    krb5_creds in, *out = NULL;
    krb5_error_code rc;
    int result_code = -1;
    krb5_data code_string = {0, 0, NULL};
    krb5_data result_string = {0, 0, NULL};
    char *realm;

    if (argc != 4) {
        fprintf(stderr, "usage: %s ccache realm newpw\n", argv[0]);
        return 2;
    }
    realm = argv[2];
    if ((rc = krb5_init_context(&ctx))) {
        fprintf(stderr, "init: %d\n", rc);
        return 1;
    }
    if ((rc = krb5_cc_resolve(ctx, argv[1], &cc))) {
        fprintf(stderr, "cc_resolve: %d\n", rc);
        return 1;
    }
    memset(&in, 0, sizeof(in));
    if ((rc = krb5_cc_get_principal(ctx, cc, &in.client))) {
        fprintf(stderr, "cc_get_principal: %d\n", rc);
        return 1;
    }
    if ((rc = krb5_build_principal(ctx, &princ, (unsigned)strlen(realm), realm,
                                   "kadmin", "changepw", (char *)NULL))) {
        fprintf(stderr, "build_principal: %d\n", rc);
        return 1;
    }
    in.server = princ;
    {
        const char *as_pw = getenv("KPASSWD_AS_PASSWORD");
        if (as_pw != NULL) {
            krb5_get_init_creds_opt *opt = NULL;
            out = calloc(1, sizeof(*out));
            if (out == NULL)
                return 1;
            if ((rc = krb5_get_init_creds_opt_alloc(ctx, &opt))) {
                fprintf(stderr, "opt_alloc: %d\n", rc);
                return 1;
            }
            rc = krb5_get_init_creds_password(ctx, out, in.client, as_pw, NULL,
                                              NULL, 0, "kadmin/changepw", opt);
            krb5_get_init_creds_opt_free(ctx, opt);
            if (rc) {
                const char *m = krb5_get_error_message(ctx, rc);
                fprintf(stderr, "get_init_creds: %s\n", m);
                krb5_free_error_message(ctx, m);
                return 1;
            }
        } else if ((rc = krb5_get_credentials(ctx, 0, cc, &in, &out))) {
            const char *m = krb5_get_error_message(ctx, rc);
            fprintf(stderr, "get_credentials: %s\n", m);
            krb5_free_error_message(ctx, m);
            return 1;
        }
    }
    {
        const char *nt_env = getenv("KPASSWD_TARGNAME_TYPE");
        const char *targ_env = getenv("KPASSWD_TARGET");
        if (nt_env != NULL || targ_env != NULL) {
            krb5_principal target = NULL;
            if (targ_env != NULL) {
                if ((rc = krb5_parse_name(ctx, targ_env, &target))) {
                    fprintf(stderr, "parse_name: %d\n", rc);
                    return 1;
                }
            } else if ((rc = krb5_copy_principal(ctx, in.client, &target))) {
                fprintf(stderr, "copy_principal: %d\n", rc);
                return 1;
            }
            if (nt_env != NULL)
                target->type = atoi(nt_env);
            rc = krb5_set_password(ctx, out, argv[3], target, &result_code,
                                   &code_string, &result_string);
            krb5_free_principal(ctx, target);
        } else {
            rc = krb5_change_password(ctx, out, argv[3], &result_code,
                                      &code_string, &result_string);
        }
    }
    printf("krb5_change_password_rc=%d\n", rc);
    printf("result_code=%d\n", result_code);
    printf("result_code_string=%.*s\n", (int)code_string.length,
           code_string.data ? code_string.data : "");
    printf("result_string=%.*s\n", (int)result_string.length,
           result_string.data ? result_string.data : "");
    krb5_free_data_contents(ctx, &code_string);
    krb5_free_data_contents(ctx, &result_string);
    krb5_free_creds(ctx, out);
    krb5_free_principal(ctx, in.client);
    krb5_free_principal(ctx, princ);
    krb5_cc_close(ctx, cc);
    krb5_free_context(ctx);
    return rc ? 1 : 0;
}
