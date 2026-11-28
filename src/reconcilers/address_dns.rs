use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::dns::{DnsState, DnsTarget, Records},
};
use ech_k8s::{K8sClient, NodeState, Reconciler};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;

#[derive(Clone, Serialize)]
pub(crate) struct AddressDnsReconciler {
    pub(crate) state_namespace: String,
}

#[async_trait::async_trait]
impl Reconciler for AddressDnsReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        let targets = DnsTarget::new(client, group, &self.state_namespace).await?;
        if targets.is_empty() {
            return Ok(NodeState::Ready);
        }
        let mut states = DnsState::load(client, group).await?;
        let nodes = group.edge_nodes(client).await?;
        let mut pending = false;
        for target in targets {
            let index = match states
                .iter()
                .position(|state| state.target.matches(&target))
            {
                Some(index) => index,
                None => {
                    states.push(DnsState {
                        target: target.clone(),
                        records: Records::default(),
                        previous: Records::default(),
                        synced: true,
                        initialized: false,
                        draining: false,
                        drain_until: 0,
                        cache_until: 0,
                    });
                    states.len() - 1
                }
            };
            let state = &mut states[index];
            let tls = state.initialized;
            let mut addresses = BTreeSet::new();
            for node in &nodes {
                if node.applied_bundle(client, group, tls).await?.is_some() {
                    addresses.insert(node.ip);
                }
            }
            if addresses.is_empty() {
                state.target = target;
                pending = true;
                continue;
            }
            let mut records = state.records.clone();
            let name = target.record_name();
            for (kind, ipv4) in [("A", true), ("AAAA", false)] {
                let mut values = records.record_values(Some(&name), &[kind]);
                values.extend(
                    addresses
                        .iter()
                        .filter(|ip| ip.is_ipv4() == ipv4)
                        .map(ToString::to_string),
                );
                let entries = records.entry(name.clone()).or_default();
                entries.retain(|record| record["type"] != kind);
                if !values.is_empty() {
                    entries.push(json!({"type": kind, "ttl": target.ttl, "values": values}));
                }
            }
            state.update_records(records);
            state.target = target;
            state.draining = false;
        }
        let outcome = DnsState::sync(&mut states, client, group).await?;
        Ok(if pending { NodeState::Pending } else { outcome })
    }
}
