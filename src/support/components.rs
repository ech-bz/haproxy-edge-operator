use ech_k8s::Component;
use serde::Serialize;

#[derive(Clone, Copy, Serialize, Component)]
#[component(name = "haproxy")]
pub(crate) struct ProxyComponent;

#[derive(Clone, Copy, Serialize, Component)]
#[component(name = "bundle")]
pub(crate) struct BundleComponent;

#[derive(Clone, Copy, Serialize, Component)]
#[component(name = "dns")]
pub(crate) struct DnsComponent;

#[derive(Clone, Copy, Serialize, Component)]
#[component(name = "edge")]
pub(crate) struct NamespaceComponent {
    pub(crate) node: ResourceId,
}

pub(crate) struct NamespacePrefix(String);

impl NamespacePrefix {
    pub(crate) fn new(value: impl AsRef<str>, component: &NamespaceComponent) -> Self {
        let value = value.as_ref();
        let limit = 63 - component.name("").len();
        Self(if value.len() > limit || value.contains('.') {
            let digest = ResourceId::new(value).to_string();
            let readable = limit - digest.len() - 1;
            format!(
                "{}-{digest}",
                value.replace('.', "-")[..value.len().min(readable)].trim_end_matches('-'),
            )
        } else {
            value.to_string()
        })
    }
}

impl AsRef<str> for NamespacePrefix {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Serialize, Component)]
#[component(name = "domain-cert")]
pub(crate) struct DomainCertificateComponent {
    pub(crate) domain: ResourceId,
}

#[derive(Clone, Copy, Serialize, Component)]
#[component(name = "ip-cert")]
pub(crate) struct IpCertificateComponent {
    pub(crate) ip: ResourceId,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) struct ResourceId([u8; 8]);

impl ResourceId {
    pub(crate) fn new(value: impl AsRef<[u8]>) -> Self {
        use sha2::{Digest, Sha256};
        Self(Sha256::digest(value.as_ref())[..8].try_into().unwrap())
    }
}

impl std::fmt::Display for ResourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

pub(crate) const GROUP: &str = "haproxy.ech.bz/ingress-group";
pub(crate) const GROUP_NS: &str = "haproxy.ech.bz/ingress-namespace";
pub(crate) const OWNER: &str = "haproxy.ech.bz/ingress-uid";
pub(crate) const PUBLIC_IP: &str = "ech.bz/public-ip";

#[derive(Clone, Copy, Serialize, Component)]
#[component(name = "domain")]
pub(crate) struct DomainClaimComponent {
    pub(crate) domain: ResourceId,
}

#[derive(Clone, Copy, Serialize, Component)]
#[component(name = "uns-signer")]
pub(crate) struct UnsSignerComponent;

#[derive(Clone, Copy, Serialize, Component)]
#[component(name = "ech")]
pub(crate) struct EchComponent {
    pub(crate) cover: ResourceId,
}

impl EchComponent {
    pub(crate) fn new(cover: &str) -> Self {
        Self {
            cover: ResourceId::new(cover),
        }
    }

    pub(crate) fn file(&self) -> String {
        format!("{}.ech", self.name("key"))
    }
}

pub(crate) const DOMAIN_BINDING: &str = "haproxy.ech.bz/domain-binding";
