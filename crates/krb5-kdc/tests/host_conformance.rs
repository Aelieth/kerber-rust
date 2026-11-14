use std::sync::Arc;

use krb5_kdc::host::{MemoryRealm, conformance};

#[test]
fn memory_realm_passes_the_host_conformance_rows() {
    for row in conformance::run(&|| Arc::new(MemoryRealm::default())) {
        assert!(row.outcome.is_ok(), "{}: {:?}", row.name, row.outcome);
    }
}
