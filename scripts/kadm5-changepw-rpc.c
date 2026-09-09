/* MIT libkadm5 client authenticating to kadmin/changepw (CHANGEPW_SERVICE).
 * Out-of-process only; compiled in the MIT 1.22.2 image.
 * usage: kadm5-changepw-rpc [--service princ] <client> <password> <realm> <op> [arg]
 * op: listprincs | getprinc <name> | randkey-keepold <n> | setkey-keepold <n>
 *     | addpol-minlife-unmasked-max <policy>
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
    } else if ((strcmp(op, "randkey-keepold") == 0 || strcmp(op, "setkey-keepold") == 0) &&
               argc - argi >= 5) {
        /* Repeat a keepold key change on the one authenticated handle (self). */
        krb5_principal p;
        int n = atoi(argv[argi + 4]);
        int i;
        ret = krb5_parse_name(ctx, client, &p);
        if (ret) {
            printf("parse_code=%ld\n", (long)ret);
            kadm5_destroy(handle);
            krb5_free_context(ctx);
            return 1;
        }
        for (i = 1; i <= n; i++) {
            if (strcmp(op, "randkey-keepold") == 0) {
                krb5_keyblock *kb = NULL;
                int nk = 0, k;
                ret = kadm5_randkey_principal_3(handle, p, 1, 0, NULL, &kb, &nk);
                for (k = 0; k < nk; k++)
                    krb5_free_keyblock_contents(ctx, &kb[k]);
                free(kb);
            } else {
                kadm5_key_data kd;
                unsigned char raw[32];
                memset(&kd, 0, sizeof(kd));
                memset(raw, (unsigned char)i, sizeof(raw));
                kd.key.magic = KV5M_KEYBLOCK;
                kd.key.enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
                kd.key.length = sizeof(raw);
                kd.key.contents = raw;
                ret = kadm5_setkey_principal_4(handle, p, 1, &kd, 1);
            }
            printf("%s[%d]=%ld\n", op, i, (long)ret);
            if (ret)
                break;
        }
        krb5_free_principal(ctx, p);
    } else if (strcmp(op, "addpol-minlife-unmasked-max") == 0 && argc - argi >= 5) {
        /* pw_max_life is on the wire but not in the mask; MIT ignores it. */
        kadm5_policy_ent_rec ent;
        memset(&ent, 0, sizeof(ent));
        ent.policy = argv[argi + 4];
        ent.pw_min_life = 3600;
        ent.pw_max_life = 1;
        ret = kadm5_create_policy(handle, &ent, KADM5_POLICY | KADM5_PW_MIN_LIFE);
        printf("addpol_code=%ld\n", (long)ret);
    } else if ((strcmp(op, "modify-tl-reserved") == 0 ||
                strcmp(op, "modify-failcount") == 0 ||
                strcmp(op, "modify-policy-clr") == 0 ||
                strcmp(op, "create-failcount-mask") == 0 ||
                strcmp(op, "create-tl-reserved") == 0 ||
                strcmp(op, "create-tl-500") == 0) &&
               argc - argi >= 5) {
        krb5_principal p;
        kadm5_principal_ent_rec rec, after;
        krb5_tl_data tl;
        unsigned char tlbuf[4] = {1, 2, 3, 4};
        long mask;
        memset(&rec, 0, sizeof(rec));
        memset(&after, 0, sizeof(after));
        ret = krb5_parse_name(ctx, argv[argi + 4], &p);
        if (ret) {
            printf("parse_code=%ld\n", (long)ret);
            kadm5_destroy(handle);
            krb5_free_context(ctx);
            return 1;
        }
        if (strcmp(op, "create-failcount-mask") == 0) {
            rec.principal = p;
            ret = kadm5_create_principal(handle, &rec,
                                         KADM5_PRINCIPAL | KADM5_FAIL_AUTH_COUNT,
                                         "password");
            printf("create_code=%ld\n", (long)ret);
            printf("create_msg=%s\n", error_message(ret));
            krb5_free_principal(ctx, p);
            kadm5_destroy(handle);
            krb5_free_context(ctx);
            return 0;
        }
        if (strcmp(op, "create-tl-reserved") == 0 ||
            strcmp(op, "create-tl-500") == 0) {
            memset(&tl, 0, sizeof(tl));
            tl.tl_data_type = (strcmp(op, "create-tl-500") == 0) ? 500 : 3;
            tl.tl_data_length = 4;
            tl.tl_data_contents = tlbuf;
            rec.principal = p;
            rec.tl_data = &tl;
            rec.n_tl_data = 1;
            ret = kadm5_create_principal(handle, &rec,
                                         KADM5_PRINCIPAL | KADM5_TL_DATA,
                                         "password");
            printf("create_code=%ld\n", (long)ret);
            printf("create_msg=%s\n", error_message(ret));
            if (ret == 0 && strcmp(op, "create-tl-500") == 0) {
                kadm5_principal_ent_rec got;
                memset(&got, 0, sizeof(got));
                ret = kadm5_get_principal(handle, p, &got,
                                         KADM5_PRINCIPAL | KADM5_TL_DATA);
                printf("get_code=%ld n_tl=%d", (long)ret, got.n_tl_data);
                if (ret == 0) {
                    krb5_tl_data *t;
                    for (t = got.tl_data; t != NULL; t = t->tl_data_next)
                        printf(" tl_type=%d", (int)t->tl_data_type);
                    printf("\n");
                    kadm5_free_principal_ent(handle, &got);
                } else {
                    printf("\n");
                }
            }
            rec.tl_data = NULL;
            rec.n_tl_data = 0;
            krb5_free_principal(ctx, p);
            kadm5_destroy(handle);
            krb5_free_context(ctx);
            return 0;
        }
        ret = kadm5_get_principal(handle, p, &rec, KADM5_PRINCIPAL | KADM5_MAX_LIFE);
        printf("get_before_code=%ld max_life=%lu\n", (long)ret, (unsigned long)rec.max_life);
        if (ret) {
            krb5_free_principal(ctx, p);
            kadm5_destroy(handle);
            krb5_free_context(ctx);
            return 1;
        }
        rec.max_life += 60;
        if (strcmp(op, "modify-failcount") == 0) {
            rec.fail_auth_count = 1;
            mask = KADM5_MAX_LIFE | KADM5_FAIL_AUTH_COUNT;
        } else if (strcmp(op, "modify-policy-clr") == 0) {
            rec.policy = (char *)"default";
            mask = KADM5_MAX_LIFE | KADM5_POLICY | KADM5_POLICY_CLR;
        } else {
            memset(&tl, 0, sizeof(tl));
            tl.tl_data_type = 3;
            tl.tl_data_length = 4;
            tl.tl_data_contents = tlbuf;
            rec.tl_data = &tl;
            rec.n_tl_data = 1;
            mask = KADM5_MAX_LIFE | KADM5_TL_DATA;
        }
        ret = kadm5_modify_principal(handle, &rec, mask);
        printf("modify_code=%ld\n", (long)ret);
        printf("modify_msg=%s\n", error_message(ret));
        rec.tl_data = NULL;
        rec.n_tl_data = 0;
        rec.policy = NULL;
        kadm5_free_principal_ent(handle, &rec);
        ret = kadm5_get_principal(handle, p, &after, KADM5_PRINCIPAL | KADM5_MAX_LIFE);
        printf("get_after_code=%ld max_life=%lu\n", (long)ret, (unsigned long)after.max_life);
        if (ret == 0)
            kadm5_free_principal_ent(handle, &after);
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
