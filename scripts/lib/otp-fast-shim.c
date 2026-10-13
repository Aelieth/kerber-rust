/* Gate-only LD_PRELOAD observer for MIT krb5 1.22.2 programs (krb5kdc or kinit). It interposes
 * krb5_c_decrypt and krb5_c_encrypt, calls the real function, and appends one line to $KR_SHIM_OUT for a call
 * with key usage 45 (PA-OTP-ENC-REQUEST), 51 (KrbFastReq) or 52 (KrbFastResponse), and for no other usage:
 *   <decrypt|encrypt> usage=N rc=N keyetype=N len=N hex=<plaintext>
 * It changes nothing MIT does. Not linked into the product; no krb5 library is linked here either.
 * Build: cc -shared -fPIC -o otp-fast-shim.so otp-fast-shim.c -ldl */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>

static int watched(krb5_keyusage usage)
{
    return usage == 45 || usage == 51 || usage == 52;
}

static void dump(const char *what, krb5_keyusage usage, krb5_error_code rc, const krb5_keyblock *key,
                 const krb5_data *d)
{
    const char *path = getenv("KR_SHIM_OUT");
    FILE *f;
    unsigned i;

    if (path == NULL || (f = fopen(path, "a")) == NULL)
        return;
    fprintf(f, "%s usage=%d rc=%d keyetype=%d len=%u hex=", what, (int)usage, (int)rc,
            key != NULL ? (int)key->enctype : -1, d != NULL ? d->length : 0);
    for (i = 0; d != NULL && d->data != NULL && i < d->length; i++)
        fprintf(f, "%02x", (unsigned char)d->data[i]);
    fputc('\n', f);
    fclose(f);
}

krb5_error_code krb5_c_decrypt(krb5_context ctx, const krb5_keyblock *key, krb5_keyusage usage,
                               const krb5_data *cipher_state, const krb5_enc_data *input, krb5_data *output)
{
    static krb5_error_code (*real)(krb5_context, const krb5_keyblock *, krb5_keyusage, const krb5_data *,
                                   const krb5_enc_data *, krb5_data *);
    krb5_error_code rc;

    if (real == NULL)
        real = dlsym(RTLD_NEXT, "krb5_c_decrypt");
    rc = real(ctx, key, usage, cipher_state, input, output);
    if (watched(usage))
        dump("decrypt", usage, rc, key, rc == 0 ? output : NULL);
    return rc;
}

krb5_error_code krb5_c_encrypt(krb5_context ctx, const krb5_keyblock *key, krb5_keyusage usage,
                               const krb5_data *cipher_state, const krb5_data *input, krb5_enc_data *output)
{
    static krb5_error_code (*real)(krb5_context, const krb5_keyblock *, krb5_keyusage, const krb5_data *,
                                   const krb5_data *, krb5_enc_data *);
    krb5_error_code rc;

    if (real == NULL)
        real = dlsym(RTLD_NEXT, "krb5_c_encrypt");
    rc = real(ctx, key, usage, cipher_state, input, output);
    if (watched(usage))
        dump("encrypt", usage, rc, key, input);
    return rc;
}
