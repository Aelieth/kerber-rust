/* MIT libkadm5 client authenticating to kadmin/changepw (CHANGEPW_SERVICE).
 * Out-of-process only; compiled in the MIT 1.22.2 image.
 * usage: kadm5-changepw-rpc [--service princ] <client> <password> <realm> <op> [arg]
 * op: listprincs | getprinc <name>
 */
#include <kadm5/admin.h>
#include <com_err.h>
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    krb5_context ctx;
    kadm5_config_params params;
    void *handle = NULL;
    kadm5_ret_t ret;
    char **princs = NULL;
    int count = 0;
    char *client, *pass, *realm, *op;
    char *service = KADM5_CHANGEPW_SERVICE;
    int argi = 1;

    if (argc >= 3 && strcmp(argv[1], "--service") == 0) {
        service = argv[2];
        argi = 3;
    }
    if (argc - argi < 4) {
        fprintf(stderr, "usage: %s [--service princ] client password realm op [arg]\n", argv[0]);
        return 2;
    }
    client = argv[argi];
    pass = argv[argi + 1];
    realm = argv[argi + 2];
    op = argv[argi + 3];

    ret = kadm5_init_krb5_context(&ctx);
    if (ret) {
        printf("init_ctx=%ld\n", (long)ret);
        return 1;
    }
    memset(&params, 0, sizeof(params));
    params.mask = KADM5_CONFIG_REALM | KADM5_CONFIG_ADMIN_SERVER;
    params.realm = realm;
    params.admin_server = "127.0.0.1";

    ret = kadm5_init_with_password(ctx, client, pass, service,
                                   &params, KADM5_STRUCT_VERSION,
                                   KADM5_API_VERSION_2, NULL, &handle);
    printf("init_code=%ld\n", (long)ret);
    if (ret) {
        printf("init_msg=%s\n", error_message(ret));
        krb5_free_context(ctx);
        return 1;
    }

    if (strcmp(op, "listprincs") == 0) {
        ret = kadm5_get_principals(handle, "*", &princs, &count);
        printf("list_code=%ld\n", (long)ret);
        printf("list_msg=%s\n", error_message(ret));
        printf("list_count=%d\n", count);
        if (ret == 0)
            kadm5_free_name_list(handle, princs, count);
    } else if (strcmp(op, "getprinc") == 0 && argc - argi >= 5) {
        krb5_principal p;
        kadm5_principal_ent_rec rec;
        memset(&rec, 0, sizeof(rec));
        ret = krb5_parse_name(ctx, argv[argi + 4], &p);
        if (ret) {
            printf("parse_code=%ld\n", (long)ret);
            kadm5_destroy(handle);
            krb5_free_context(ctx);
            return 1;
        }
        ret = kadm5_get_principal(handle, p, &rec, KADM5_PRINCIPAL);
        printf("get_code=%ld\n", (long)ret);
        printf("get_msg=%s\n", error_message(ret));
        if (ret == 0)
            kadm5_free_principal_ent(handle, &rec);
        krb5_free_principal(ctx, p);
    } else {
        fprintf(stderr, "unknown op\n");
        kadm5_destroy(handle);
        krb5_free_context(ctx);
        return 2;
    }
    kadm5_destroy(handle);
    krb5_free_context(ctx);
    return 0;
}
