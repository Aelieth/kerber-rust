/* Copy one credential into a new FILE ccache. Prints no ticket bytes.
 * args: src-ccache dest-ccache client-principal server-principal
 */
#include <krb5.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    krb5_context ctx;
    krb5_ccache in, out;
    krb5_principal client, server;
    krb5_creds match, creds;
    krb5_error_code rc;

    if (argc != 5) {
        fprintf(stderr, "usage: cc-one SRC DEST CLIENT SERVER\n");
        return 2;
    }
    if (krb5_init_context(&ctx))
        return 3;
    if ((rc = krb5_cc_resolve(ctx, argv[1], &in)))
        return 4;
    if ((rc = krb5_cc_resolve(ctx, argv[2], &out)))
        return 5;
    if ((rc = krb5_parse_name(ctx, argv[3], &client)))
        return 6;
    if ((rc = krb5_parse_name(ctx, argv[4], &server)))
        return 7;
    memset(&match, 0, sizeof match);
    match.client = client;
    match.server = server;
    rc = krb5_cc_retrieve_cred(ctx, in, 0, &match, &creds);
    if (rc) {
        fprintf(stderr, "RETRIEVE %ld\n", (long)rc);
        return 8;
    }
    if ((rc = krb5_cc_initialize(ctx, out, client)))
        return 9;
    if ((rc = krb5_cc_store_cred(ctx, out, &creds)))
        return 10;
    if ((rc = krb5_cc_close(ctx, out)))
        return 11;
    printf("CC_ONE_OK\n");
    return 0;
}
