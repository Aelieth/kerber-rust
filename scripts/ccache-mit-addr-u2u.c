/* Store a MIT FILE cred with authdata + second_ticket after kinit -a. */
#include <krb5.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static krb5_error_code copy_data(const krb5_data *src, krb5_data *dst)
{
    dst->magic = src->magic;
    dst->length = src->length;
    dst->data = malloc(src->length ? src->length : 1);
    if (!dst->data)
        return ENOMEM;
    if (src->length && src->data)
        memcpy(dst->data, src->data, src->length);
    return 0;
}

int main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context ctx = NULL;
    krb5_ccache cc = NULL;
    krb5_cc_cursor cur = NULL;
    krb5_creds cred, extra;
    krb5_authdata ad, *adp[2];
    krb5_boolean have = 0;
    const char *msg;
    unsigned char ad_bytes[] = {0x01, 0x02, 0x03, 0x04};

    if (argc != 2) {
        fprintf(stderr, "usage: ccache-mit-addr-u2u CCNAME\n");
        return 2;
    }
    memset(&cred, 0, sizeof(cred));
    memset(&extra, 0, sizeof(extra));
    ret = krb5_init_context(&ctx);
    if (ret) {
        fprintf(stderr, "krb5_init_context failed\n");
        return 1;
    }
    ret = krb5_cc_resolve(ctx, argv[1], &cc);
    if (ret)
        goto fail;
    ret = krb5_cc_start_seq_get(ctx, cc, &cur);
    if (ret)
        goto fail;
    while ((ret = krb5_cc_next_cred(ctx, cc, &cur, &cred)) == 0) {
        if (cred.server && cred.server->length >= 1 &&
            cred.server->data[0].length == 6 &&
            memcmp(cred.server->data[0].data, "krbtgt", 6) == 0) {
            have = 1;
            break;
        }
        krb5_free_cred_contents(ctx, &cred);
        memset(&cred, 0, sizeof(cred));
    }
    (void)krb5_cc_end_seq_get(ctx, cc, &cur);
    cur = NULL;
    if (!have) {
        fprintf(stderr, "no TGT in cache\n");
        ret = KRB5_CC_NOTFOUND;
        goto fail;
    }
    extra.times = cred.times;
    extra.is_skey = 1;
    extra.ticket_flags = cred.ticket_flags;
    ret = krb5_copy_principal(ctx, cred.client, &extra.client);
    if (ret)
        goto fail;
    ret = krb5_parse_name(ctx, "host/u2u.kerber.test@KERBER.TEST", &extra.server);
    if (ret)
        goto fail;
    ret = krb5_copy_keyblock_contents(ctx, &cred.keyblock, &extra.keyblock);
    if (ret)
        goto fail;
    if (cred.addresses) {
        ret = krb5_copy_addresses(ctx, cred.addresses, &extra.addresses);
        if (ret)
            goto fail;
    }
    ret = copy_data(&cred.ticket, &extra.ticket);
    if (ret)
        goto fail;
    ret = copy_data(&cred.ticket, &extra.second_ticket);
    if (ret)
        goto fail;

    memset(&ad, 0, sizeof(ad));
    ad.ad_type = 1;
    ad.length = (unsigned int)sizeof(ad_bytes);
    ad.contents = ad_bytes;
    adp[0] = &ad;
    adp[1] = NULL;
    extra.authdata = adp;

    ret = krb5_cc_store_cred(ctx, cc, &extra);
    extra.authdata = NULL;
    if (ret)
        goto fail;

    fprintf(stdout, "stored_ok addresses=%s second_ticket=%u authdata=1 is_skey=1\n",
            extra.addresses ? "yes" : "no",
            (unsigned)extra.second_ticket.length);

    free(extra.ticket.data);
    extra.ticket.data = NULL;
    extra.ticket.length = 0;
    free(extra.second_ticket.data);
    extra.second_ticket.data = NULL;
    extra.second_ticket.length = 0;
    krb5_free_keyblock_contents(ctx, &extra.keyblock);
    krb5_free_principal(ctx, extra.client);
    extra.client = NULL;
    krb5_free_principal(ctx, extra.server);
    extra.server = NULL;
    if (extra.addresses)
        krb5_free_addresses(ctx, extra.addresses);
    extra.addresses = NULL;
    krb5_free_cred_contents(ctx, &cred);
    krb5_cc_close(ctx, cc);
    krb5_free_context(ctx);
    return 0;

fail:
    msg = ctx ? krb5_get_error_message(ctx, ret) : "init";
    fprintf(stderr, "ccache-mit-addr-u2u: %s\n", msg);
    if (ctx)
        krb5_free_error_message(ctx, msg);
    if (extra.ticket.data)
        free(extra.ticket.data);
    if (extra.second_ticket.data)
        free(extra.second_ticket.data);
    if (extra.client)
        krb5_free_principal(ctx, extra.client);
    if (extra.server)
        krb5_free_principal(ctx, extra.server);
    if (extra.addresses)
        krb5_free_addresses(ctx, extra.addresses);
    if (extra.keyblock.contents)
        krb5_free_keyblock_contents(ctx, &extra.keyblock);
    krb5_free_cred_contents(ctx, &cred);
    if (cc)
        krb5_cc_close(ctx, cc);
    if (ctx)
        krb5_free_context(ctx);
    return 1;
}
