//! W1-B B1: PKINIT / anon second-AS padata order.
//! MIT `preauth2.c:992-1019` `copy_cookie` then the module; `get_in_tkt.c:1365-1372`
//! appends empty 150/149. Live oracle: `MIT_pkinit_second_as_padata`.

use krb5_protocol::insert_module_padata_before_info_pa;
use krb5_types::{PaData, pa};

fn pa_of(ty: i32) -> PaData {
    PaData {
        padata_type: ty,
        padata_value: Vec::new().into(),
    }
}

fn types(list: &[PaData]) -> Vec<i32> {
    list.iter().map(|p| p.padata_type).collect()
}

#[test]
fn b1_pkinit_padata_cookie_then_module_then_info() {
    let mut list = vec![
        pa_of(pa::FX_COOKIE),
        pa_of(pa::AS_FRESHNESS),
        pa_of(pa::REQ_ENC_PA_REP),
    ];
    insert_module_padata_before_info_pa(&mut list, pa_of(pa::PK_AS_REQ));
    assert_eq!(
        types(&list),
        vec![
            pa::FX_COOKIE,
            pa::PK_AS_REQ,
            pa::AS_FRESHNESS,
            pa::REQ_ENC_PA_REP
        ],
        "preauth2.c:992-1019 + get_in_tkt.c:1365-1372 → [133, 16, 150, 149]"
    );
}

#[test]
fn b1_pkinit_padata_module_before_info_without_cookie() {
    let mut list = vec![pa_of(pa::AS_FRESHNESS), pa_of(pa::REQ_ENC_PA_REP)];
    insert_module_padata_before_info_pa(&mut list, pa_of(pa::PK_AS_REQ));
    assert_eq!(
        types(&list),
        vec![pa::PK_AS_REQ, pa::AS_FRESHNESS, pa::REQ_ENC_PA_REP]
    );
}
