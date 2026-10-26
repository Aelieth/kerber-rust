//! kadm5 privilege/ACL tests (private-bound; regrouped in place).

use super::*;

#[test]
fn unauthorized_is_auth_even_if_missing_or_lockdown() {
    let (store, _acl, _actor) = setup();
    lockdown_user(&store);
    let limited = Acl::parse("limited@KERBER.TEST i\n").expect("acl");
    let actor = "limited@KERBER.TEST";
    let cases: [(u32, Vec<u8>, u32); 10] = [
        (
            EXTRACT_KEYS,
            extract_args("user@KERBER.TEST", 0),
            KADM5_AUTH_EXTRACT,
        ),
        (
            EXTRACT_KEYS,
            extract_args("no-such@KERBER.TEST", 0),
            KADM5_UNK_PRINC,
        ),
        (
            PURGEKEYS,
            purgekeys_args("user@KERBER.TEST", -1),
            KADM5_AUTH_MODIFY,
        ),
        (
            PURGEKEYS,
            purgekeys_args("no-such@KERBER.TEST", -1),
            KADM5_UNK_PRINC,
        ),
        (
            SETKEY_PRINCIPAL,
            setkey16_args("user@KERBER.TEST", 18, &[0xABu8; 32]),
            KADM5_AUTH_SETKEY,
        ),
        (
            SETKEY_PRINCIPAL,
            setkey16_args("no-such@KERBER.TEST", 18, &[0xABu8; 32]),
            KADM5_UNK_PRINC,
        ),
        (
            CHPASS_PRINCIPAL,
            chpass_args("user@KERBER.TEST", "nope"),
            KADM5_AUTH_CHANGEPW,
        ),
        (
            CHPASS_PRINCIPAL,
            chpass_args("no-such@KERBER.TEST", "nope"),
            KADM5_UNK_PRINC,
        ),
        (
            CHRAND_PRINCIPAL,
            encode_named("user@KERBER.TEST"),
            KADM5_AUTH_CHANGEPW,
        ),
        (
            CHRAND_PRINCIPAL,
            encode_named("no-such@KERBER.TEST"),
            KADM5_UNK_PRINC,
        ),
    ];
    for (proc, args, want) in cases {
        let out = dispatch_kadm5(&store, &limited, actor, proc, &args).unwrap();
        assert_eq!(ret_code(&out), want, "proc {proc}");
    }
}
