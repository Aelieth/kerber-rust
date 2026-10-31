use std::collections::BTreeMap;

use crate::{EncTicketPart, MAX_TRANSIT_RAW, err, flag_bit};

// MIT: `rd_req_decoded_opt` (rd_req_dec.c:606-610)
// MIT: `krb5_check_transited_list` (chk_trans.c:309-356)
pub fn check_transited(
    part: &EncTicketPart,
    srealm: &str,
    capaths: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
) -> Result<(), i32> {
    let raw = part.transited.contents.as_ref();
    if part.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED) || raw.first().is_none_or(|b| *b == 0) {
        return Ok(());
    }
    let crealm = String::from_utf8_lossy(part.crealm.as_bytes());
    if crealm == "WELLKNOWN:ANONYMOUS" {
        return Ok(());
    }
    if crealm == srealm {
        return Err(err::NO_TKT_IN_RLM);
    }
    let hops = part
        .transited
        .realms_for(&crealm, srealm)
        .map_err(|_| err::ILL_CR_TKT)?;
    if transit_allowed(capaths, &crealm, srealm, &hops) {
        Ok(())
    } else {
        Err(err::ILL_CR_TKT)
    }
}

// MIT: `check_realm_in_list` (chk_trans.c:293-306)
// MIT: `rtree_capath_tree` (walk_rtree.c:234-291)
// MIT: `rtree_hier_tree` (walk_rtree.c:344-388)
#[must_use]
pub fn transit_allowed(
    capaths: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
    crealm: &str,
    srealm: &str,
    hops: &[String],
) -> bool {
    let path = walk_realm_tree(capaths, crealm, srealm);
    let tgs_realms = &path[..path.len().saturating_sub(1)];
    hops.iter().all(|h| tgs_realms.contains(h))
}

// MIT: `krb5_walk_realm_tree` (walk_rtree.c:96-121)
#[must_use]
pub fn walk_realm_tree(
    capaths: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
    client: &str,
    server: &str,
) -> Vec<String> {
    if client == server {
        return Vec::new();
    }
    if let Some(vals) = capaths.get(client).and_then(|m| m.get(server)) {
        let mut out = vec![client.to_owned()];
        out.extend(vals.iter().filter(|v| *v != ".").cloned());
        out.push(server.to_owned());
        return out;
    }
    hierarchical_walk_realms(client, server)
}

// MIT: `rtree_hier_realms` (walk_rtree.c:394-452)
#[must_use]
fn hierarchical_walk_realms(client: &str, server: &str) -> Vec<String> {
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
