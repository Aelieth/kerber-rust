//! MIT `net-server.c` TCP `bufsiz` 1 MiB, `FIELD_TOOLONG` at `msglen > bufsiz-4`.

use krb5_kdc::MAX_TCP_REQUEST;

#[test]
fn tcp_max_request_is_one_mib_minus_four() {
    assert_eq!(MAX_TCP_REQUEST, 1024 * 1024 - 4);
}
