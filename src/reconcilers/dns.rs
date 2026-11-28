use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        components::BundleComponent,
        dns::{DnsProvider, DnsState},
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
        let ech = if group.spec.ech.is_some()
            && states
                .iter()
                .any(|state| matches!(state.target.provider, DnsProvider::Octodns(_)))
        {
            let nodes = group.edge_nodes(client).await?;
            let Some(node) = nodes.first() else {
                return Ok(NodeState::Pending);
            };
            let bundle = client
                .namespaced::<Secret>(&node.namespace)
                .api()
                .get(&BundleComponent.name(group.owner()?))
                .await?;
            let name = "ech-current.ech";
            let data = bundle
                .data
                .as_ref()
                .and_then(|data| data.get(name))
                .ok_or_else(|| OperatorError::Config(format!("HAProxy bundle has no {name}")))?;
            let text = std::str::from_utf8(&data.0)
                .map_err(|_| OperatorError::Config(format!("invalid ECH PEM in {name}")))?;
            let ech = text
                .split_once("-----BEGIN ECHCONFIG-----")
                .and_then(|(_, value)| value.split_once("-----END ECHCONFIG-----"))
                .ok_or_else(|| OperatorError::Config(format!("missing ECHCONFIG block in {name}")))?
                .0
                .split_whitespace()
                .collect::<String>();
            if ech.is_empty() {
                return Err(OperatorError::Config(format!(
                    "empty ECHCONFIG block in {name}"
                )));
            }
            Some(ech)
        } else {
            None
        };
        let cover = group.ech_cover()?;
        for state in &mut states {
            let mut records = state.records.clone();
            for entries in records.values_mut() {
                entries.retain(|record| record["type"] != "HTTPS");
                if let Some(ech) = ech.as_ref().filter(|_| {
                    matches!(state.target.provider, DnsProvider::Octodns(_))
                        && Some(&state.target.domain) != cover.as_ref()
                }) {
                    entries.push(json!({"type": "HTTPS", "ttl": state.target.ttl, "value": {"svcpriority": 1, "targetname": ".", "svcparams": {"alpn": ["h2", "http/1.1"], "ech": ech}}}));
                }
            }
            state.update_records(records);
            state.initialized = true;
        }
        DnsState::sync(&mut states, client, group).await
    }
}
