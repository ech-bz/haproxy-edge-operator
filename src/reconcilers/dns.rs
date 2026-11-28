use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        components::{BundleComponent, EchComponent},
        dns::{DnsProvider, DnsState},
        haproxy::EchConfig,
    },
};
use ech_k8s::{Component, K8sClient, NodeState, Reconciler};
use k8s_openapi::api::core::v1::Secret;
use serde::Serialize;
use serde_json::json;

#[derive(Clone, Serialize)]
pub(crate) struct DnsReconciler;

#[async_trait::async_trait]
impl Reconciler for DnsReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        let mut states = DnsState::load(client, group).await?;
        if states.is_empty() {
            return Ok(NodeState::Pending);
        }
        let domains = group.ech_domains()?;
        let mut configs = std::collections::BTreeMap::new();
        if !domains.is_empty() {
            let nodes = group.edge_nodes(client).await?;
            let Some(node) = nodes.first() else {
                return Ok(NodeState::Pending);
            };
            let bundle = client
                .namespaced::<Secret>(&node.namespace)
                .api()
                .get(&BundleComponent.name(group.owner()?))
                .await?;
            for cover in domains.values() {
                if !configs.contains_key(cover) {
                    let file = EchComponent::new(cover).file();
                    let pem = bundle
                        .data
                        .as_ref()
                        .and_then(|data| data.get(&file))
                        .ok_or_else(|| {
                            OperatorError::Config(format!("HAProxy bundle has no {file}"))
                        })?;
                    configs.insert(cover.clone(), EchConfig::new(&pem.0)?.0);
                }
            }
        }
        for state in &mut states {
            let mut records = state.records.clone();
            for entries in records.values_mut() {
                entries.retain(|record| record["type"] != "HTTPS");
                if let Some(ech) = domains
                    .get(&state.target.domain)
                    .and_then(|cover| configs.get(cover))
                    .filter(|_| matches!(state.target.provider, DnsProvider::Octodns(_)))
                {
                    entries.push(json!({"type": "HTTPS", "ttl": state.target.ttl, "value": {"svcpriority": 1, "targetname": ".", "svcparams": {"alpn": ["h2", "http/1.1"], "ech": ech}}}));
                }
            }
            state.update_records(records);
            state.initialized = true;
        }
        DnsState::sync(&mut states, client, group).await
    }
}
