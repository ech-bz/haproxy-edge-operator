use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::haproxy::{backend_url, dns_name, invalid},
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
            return Err(invalid("group name exceeds the node label limit"));
        }
        let mut domains = BTreeSet::new();
        for domain in group.spec.domains.as_deref().unwrap_or_default() {
            if !dns_name(domain.strip_prefix("*.").unwrap_or(domain)) || !domains.insert(domain) {
                return Err(invalid(format!("invalid or duplicate domain {domain}")));
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
                return Err(invalid(format!("invalid trusted IP or CIDR {trusted}")));
            }
        }
        let mut paths = BTreeSet::new();
        for route in group.spec.routes.as_deref().unwrap_or_default() {
            if !route.path_prefix.starts_with('/')
                || route.path_prefix.len() > 2048
                || route
                    .path_prefix
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || c == '?' || c == '#')
                || !paths.insert(&route.path_prefix)
            {
                return Err(invalid(format!(
                    "invalid or duplicate pathPrefix {}",
                    route.path_prefix
                )));
            }
            match (&route.url, &route.service) {
                (Some(url), None) => {
                    backend_url(url)?;
                }
                (None, Some(service)) => {
                    if !dns_name(&service.name)
                        || service.name.contains('.')
                        || service
                            .namespace
                            .as_deref()
                            .is_some_and(|ns| !dns_name(ns) || ns.contains('.'))
                        || !(1..=65535).contains(&service.port)
                    {
                        return Err(invalid("invalid backend service reference"));
                    }
                    if service
                        .scheme
                        .as_deref()
                        .is_some_and(|scheme| !["http", "https", "h2c"].contains(&scheme))
                    {
                        return Err(invalid("unsupported backend scheme"));
                    }
                }
                _ => return Err(invalid("specify exactly one of url or service")),
            }
            let mut headers = BTreeSet::new();
            for (name, value) in route.headers.iter().flatten() {
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                    || value.chars().any(char::is_control)
                    || !headers.insert(name.to_ascii_lowercase())
                {
                    return Err(invalid(format!(
                        "invalid or duplicate request header {name}"
                    )));
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
