#![allow(clippy::all)]

mod domain_claim {
    include!(concat!(env!("OUT_DIR"), "/domain_claim.rs"));
}
mod certificate {
    include!(concat!(env!("OUT_DIR"), "/certificate.rs"));
}
mod cluster_issuer {
    include!(concat!(env!("OUT_DIR"), "/cluster_issuer.rs"));
}
mod ingress_group {
    include!(concat!(env!("OUT_DIR"), "/ingress_group.rs"));
}

pub(crate) use certificate::*;
pub(crate) use cluster_issuer::ClusterIssuer;
pub(crate) use domain_claim::*;
pub(crate) use ingress_group::*;
