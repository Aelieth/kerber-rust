use std::sync::Arc;

use krb5_kdc::host::{
    HostChange, KerberosStore, KerberosStoreError, LoadedRealm, MemoryRealm, Operation, conformance,
};

#[test]
fn memory_realm_passes_the_host_conformance_rows() {
    for row in conformance::run(&|| Arc::new(MemoryRealm::default())) {
        assert!(row.outcome.is_ok(), "{}: {:?}", row.name, row.outcome);
    }
}

/// Takes its own changes on their own path and refuses them at `commit_change`.
struct OwnPath(MemoryRealm);

impl KerberosStore for OwnPath {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
        self.0.load()
    }

    fn commit_change(&self, change: HostChange) -> Result<(), KerberosStoreError> {
        if matches!(
            change.intent.operation,
            Operation::Embedded | Operation::Bootstrap
        ) {
            return Err(KerberosStoreError::Refused("an own change".to_owned()));
        }
        self.0.commit_change(change)
    }
}

#[test]
fn a_host_with_its_own_commit_path_passes_them_too() {
    let rows = conformance::run_own(&|| {
        let host = Arc::new(OwnPath(MemoryRealm::default()));
        let own = Arc::clone(&host);
        let own: conformance::OwnCommit = Arc::new(move |c| own.0.commit_change(c));
        (host, own)
    });
    for row in rows {
        assert!(row.outcome.is_ok(), "{}: {:?}", row.name, row.outcome);
    }
}
