#include <stdio.h>
#include <string.h>
#include <kadm5/admin.h>
#include <krb5.h>

/* Remote getprinc via MIT's client library. Prints tl type and length only.
 * The "tl" mask is NORMAL_MASK | KADM5_TL_DATA. Landing's "tl" mode
 * was NORMAL_MASK alone (0x41ffff), which does not include 0x040000.
 */
static int read_pw(char *buf, size_t n) {
    FILE *f = fopen("/var/tmp/sc/admin-pw", "r");
    size_t len;
    if (!f) return -1;
    if (!fgets(buf, n, f)) { fclose(f); return -1; }
    fclose(f);
    len = strlen(buf);
    if (len && buf[len - 1] == '\n') buf[len - 1] = '\0';
    return 0;
}

int main(int argc, char **argv) {
    krb5_context ctx;
    krb5_principal princ;
    kadm5_config_params params;
    void *handle = NULL;
    kadm5_principal_ent_rec ent;
    krb5_tl_data *tl;
    long mask;
    kadm5_ret_t rc;
    char pw[256];
    int i;

    if (argc != 3) {
        fprintf(stderr, "usage: sc1-tl principal tl|notl\n");
        return 2;
    }
    if (read_pw(pw, sizeof(pw))) {
        fprintf(stderr, "no admin pw file\n");
        return 2;
    }
    if (krb5_init_context(&ctx)) return 3;
    if (krb5_parse_name(ctx, argv[1], &princ)) return 3;
    memset(&params, 0, sizeof(params));
    rc = kadm5_init_with_password(ctx, "admin/admin@KERBER.TEST", pw,
                                  NULL, &params, KADM5_STRUCT_VERSION,
                                  KADM5_API_VERSION_4, NULL, &handle);
    memset(pw, 0, sizeof(pw));
    if (rc) {
        fprintf(stderr, "init rc %ld\n", (long)rc);
        return 4;
    }
    memset(&ent, 0, sizeof(ent));
    mask = KADM5_PRINCIPAL_NORMAL_MASK;
    if (strcmp(argv[2], "tl") == 0)
        mask |= KADM5_TL_DATA;
    else if (strcmp(argv[2], "notl") != 0) {
        fprintf(stderr, "usage: sc1-tl principal tl|notl\n");
        return 2;
    }
    rc = kadm5_get_principal(handle, princ, &ent, mask);
    if (rc) {
        fprintf(stderr, "getprinc rc %ld\n", (long)rc);
        return 5;
    }
    printf("mask 0x%lx\n", mask);
    printf("n_tl %d\n", (int)ent.n_tl_data);
    for (i = 0, tl = ent.tl_data; tl && i < ent.n_tl_data; i++, tl = tl->tl_data_next)
        printf("tl type %d len %d\n", (int)tl->tl_data_type, (int)tl->tl_data_length);
    kadm5_free_principal_ent(handle, &ent);
    kadm5_destroy(handle);
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    return 0;
}
