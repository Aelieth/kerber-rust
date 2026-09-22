//! Hierarchical transited-realm walk.
//!
//! MIT `lib/krb5/krb/walk_rtree.c` `rtree_hier_realms`, declared at
//! `:69` and defined at `:394`. `rtree_hier_tree` calls it at `:358`.

// `must_use_candidate` applies only once this function is `pub`.
// The KDC copy does not carry `#[must_use]`.
#![allow(clippy::must_use_candidate)]

use crate::MAX_TRANSIT_RAW;

/// MIT `rtree_hier_realms` (`walk_rtree.c:393-451`): client suffixes through
/// the common component suffix, then the server's suffixes below that
/// suffix in reverse. `common == 0` walks every suffix of both realms.
pub fn hierarchical_walk_realms(client: &str, server: &str) -> Vec<String> {
    if client.len() >= MAX_TRANSIT_RAW || server.len() >= MAX_TRANSIT_RAW {
        return Vec::new();
    }
    if client == server {
        return Vec::new();
    }
    let c: Vec<&str> = client.split('.').collect();
    let s: Vec<&str> = server.split('.').collect();
    if c.is_empty() || s.is_empty() {
        return Vec::new();
    }
    let mut common = 0usize;
    while common < c.len() && common < s.len() && c[c.len() - 1 - common] == s[s.len() - 1 - common]
    {
        common += 1;
    }
    let ct: Vec<String> = (0..c.len()).map(|k| c[k..].join(".")).collect();
    let st: Vec<String> = (0..s.len()).map(|k| s[k..].join(".")).collect();
    let c_keep = if common == 0 {
        ct.len()
    } else {
        ct.len() - common + 1
    };
    let s_keep = if common == 0 {
        st.len()
    } else {
        st.len() - common
    };
    let mut out: Vec<String> = ct.into_iter().take(c_keep).collect();
    for hop in st.into_iter().take(s_keep).rev() {
        out.push(hop);
    }
    out
}
