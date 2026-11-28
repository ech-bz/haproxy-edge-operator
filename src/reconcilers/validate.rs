use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        domain::DomainName,
        haproxy::{BackendUrl, HeaderTemplate},
    },
};
use ech_k8s::{CrMeta, K8sClient, NodeState, Reconciler};
use kube::{ResourceExt, api::ListParams};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Serialize)]
pub(crate) struct ValidateReconciler;

#[async_trait::async_trait]
impl Reconciler for ValidateReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        if group.cr_name()?.len() > 63 {
            return Err(OperatorError::Config(
                "group name exceeds the node label limit".into(),
            ));
        }
        let hosts = group.spec.hosts.as_slice();
        if hosts.is_empty() {
            return Err(OperatorError::Config(
                "at least one host block is required".into(),
            ));
        }
        let mut seen_domains = BTreeSet::new();
        for host in hosts {
            if host.domains.is_empty() {
                return Err(OperatorError::Config("host block requires domains".into()));
            }
            for value in &host.domains {
                let domain = DomainName::new(value)?.0;
                if !seen_domains.insert(domain.clone()) {
                    return Err(OperatorError::Config(format!("duplicate domain {domain}")));
                }
            }
        }
        if let Some(cover) = group.ech_cover()? {
            if DomainName::is_uns(&cover) || cover.starts_with("*.") {
                return Err(OperatorError::Config(
                    "ECH cover must be a concrete ICANN domain".into(),
                ));
            }
            if !seen_domains
                .iter()
                .any(|domain| !DomainName::is_uns(domain) && domain != &cover)
            {
                return Err(OperatorError::Config(
                    "ECH requires a protected ICANN domain".into(),
                ));
            }
        }
        for trusted in group
            .spec
            .forwarded_trusted_ips
            .as_deref()
            .unwrap_or_default()
        {
            if trusted.parse::<std::net::IpAddr>().is_err()
                && trusted.parse::<ipnet::IpNet>().is_err()
            {
                return Err(OperatorError::Config(format!(
                    "invalid trusted IP or CIDR {trusted}"
                )));
            }
        }
        for host in hosts {
            let mut paths = BTreeSet::new();
            for route in host.routes.iter().flatten() {
                if !route.path_prefix.starts_with('/')
                    || route.path_prefix.len() > 2048
                    || route
                        .path_prefix
                        .chars()
                        .any(|c| c.is_whitespace() || c.is_control() || c == '?' || c == '#')
                    || !paths.insert(&route.path_prefix)
                {
                    return Err(OperatorError::Config(format!(
                        "invalid or duplicate pathPrefix {}",
                        route.path_prefix
                    )));
                }
                BackendUrl::new(&route.url)?;
                let mut headers = BTreeSet::new();
                for (name, value) in route.headers.iter().flatten() {
                    if name.is_empty()
                        || !name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                        || !headers.insert(name.to_ascii_lowercase())
                    {
                        return Err(OperatorError::Config(format!(
                            "invalid or duplicate request header {name}"
                        )));
                    }
                    HeaderTemplate::new(value)?;
                }
            }
        }
        if group
            .finalizers()
            .iter()
            .any(|value| value == "ech.bz/ingress-cleanup")
        {
            return Err(OperatorError::Config(
                "remove the previous Traefik installation before migrating this group".into(),
            ));
        }
        let name = group.cr_name()?;
        let groups = client
            .all::<IngressGroup>()
            .api()
            .list(&ListParams::default())
            .await?;
        if groups
            .items
            .iter()
            .any(|other| other.name_any() == name && other.namespace() != group.namespace())
        {
            return Err(OperatorError::Config(format!(
                "IngressGroup {name} is ambiguous across namespaces"
            )));
        }
        Ok(NodeState::Ready)
    }
}
