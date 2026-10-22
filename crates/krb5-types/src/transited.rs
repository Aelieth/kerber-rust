use crate::MAX_TRANSIT_RAW;

// MIT `rtree_hier_realms` (`walk_rtree.c:394-452`): client suffixes through
#[must_use]
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
