//! `PkinitClient`'s drop wipes the P-256 scalar where the value lies.
//!
//! The scalar is an inline array, with no allocation to follow past the drop, so a test build
//! records the array as the drop left it.

use std::cell::RefCell;

use super::PkinitClient;

thread_local! {
    /// The `key` of each `PkinitClient` dropped on this thread, as its drop left it.
    pub(super) static DROPPED: RefCell<Vec<[u8; 32]>> = const { RefCell::new(Vec::new()) };
}

#[test]
fn a_dropped_pkinit_client_wipes_its_scalar_in_place() {
    DROPPED.with(|d| d.borrow_mut().clear());
    drop(PkinitClient {
        cert: Vec::new(),
        key: [0x5a; 32],
        ca_cert: Vec::new(),
    });
    assert_eq!(DROPPED.with(|d| d.borrow().clone()), [[0; 32]]);
}
