//! MIT `net-server.c:1101-1105,1314-1317` dispatch suffix strings.

use krb5_kdc::{WHILE_DISPATCHING_TCP, WHILE_DISPATCHING_UDP};

#[test]
fn dispatch_suffixes_are_mit_net_server() {
    assert_eq!(WHILE_DISPATCHING_UDP, "while dispatching (udp)");
    assert_eq!(WHILE_DISPATCHING_TCP, "while dispatching (tcp)");
}
