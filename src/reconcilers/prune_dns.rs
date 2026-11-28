use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        components::{DnsComponent, EchComponent},
        dns::{DnsState, DnsTarget},
        haproxy::EchConfig,
    },
};
use ech_k8s::{Component, CrMeta, K8sClient, NodeState, Reconciler};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Serialize)]
pub(crate) struct PruneDnsReconciler {
    pub(crate) state_namespace: String,
}

impl PruneDnsReconciler {
    async fn prune(
        &self,
        client: &K8sClient,
        group: &IngressGroup,
        deleting: bool,
    ) -> Result<NodeState> {
        let mut states = DnsState::load(client, group).await?;
        if states.is_empty() {
            return Ok(NodeState::Ready);
        }
        let desired = if deleting {
            DnsTarget::new(client, group, &self.state_namespace)
                .await
                .unwrap_or_default()
        } else {
            DnsTarget::new(client, group, &self.state_namespace).await?
        };
        for state in &mut states {
            if let Some(target) = desired.iter().find(|target| state.target.matches(target)) {
                state.target = target.clone();
            }
        }
        if states.iter().any(|state| !state.synced || state.draining)
            && DnsState::sync(&mut states, client, group).await? == NodeState::Pending
        {
            return Ok(NodeState::Pending);
        }
        let addresses: BTreeSet<_> = if deleting {
            BTreeSet::new()
        } else {
            group
                .selected_nodes(client)
                .await?
                .into_iter()
                .filter_map(|node| node.ip().ok().map(|ip| ip.to_string()))
                .collect()
        };
        let domains = group.ech_domains()?;
        let secrets = client.namespaced::<k8s_openapi::api::core::v1::Secret>(&group.cr_ns()?);
        let mut configs = std::collections::BTreeMap::new();
        for cover in group.ech_covers()? {
            let component = EchComponent::new(&cover);
            if desired.iter().any(|target| target.domain == cover)
                && let Some(secret) = secrets
                    .api()
                    .get_opt(&component.name(group.owner()?))
                    .await?
                && let Some(data) = secret.data
                && data
                    .get("public-name")
                    .is_some_and(|value| value.0 == cover.as_bytes())
                && let Some(pem) = data.get("current.ech")
                && let Ok(config) = EchConfig::new(&pem.0)
            {
                configs.insert(cover, config.0);
            }
        }
        for state in &mut states {
            let target = desired
                .iter()
                .find(|target| !deleting && state.target.matches(target));
            let keep = target.map(DnsTarget::record_name);
            let mut records = state.records.clone();
            records.retain(|name, entries| {
                if Some(name) != keep.as_ref() {
                    return false;
                }
                for record in entries
                    .iter_mut()
                    .filter(|record| record["type"] == "A" || record["type"] == "AAAA")
                {
                    if let Some(values) = record["values"].as_array_mut() {
                        values.retain(|value| {
                            value.as_str().is_some_and(|ip| addresses.contains(ip))
                        });
                    }
                }
                entries.retain(|record| match record["type"].as_str() {
                    Some("A" | "AAAA") => record["values"]
                        .as_array()
                        .is_some_and(|values| !values.is_empty()),
                    Some("HTTPS") => domains
                        .get(&state.target.domain)
                        .and_then(|cover| configs.get(cover))
                        .is_some_and(|config| {
                            record["value"]["svcparams"]["ech"].as_str() == Some(config.as_str())
                        }),
                    _ => true,
                });
                entries
                    .iter()
                    .any(|record| record["type"] == "A" || record["type"] == "AAAA")
            });
            if state.update_records(records) {
                state.draining = true;
                state.drain_until = 0;
            }
        }
        if DnsState::sync(&mut states, client, group).await? == NodeState::Pending {
            return Ok(NodeState::Pending);
        }
        states
            .retain(|state| !deleting && desired.iter().any(|target| state.target.matches(target)));
        if states.is_empty() {
            client
                .namespaced::<k8s_openapi::api::core::v1::Secret>(&group.cr_ns()?)
                .api()
                .delete(&DnsComponent.name(group.owner()?), &Default::default())
                .await?;
        } else {
            for state in &mut states {
                state.draining = false;
            }
            DnsState::store(&states, client, group).await?;
        }
        Ok(NodeState::Ready)
    }
}

#[async_trait::async_trait]
impl Reconciler for PruneDnsReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        self.prune(client, group, false).await
    }

    async fn cleanup(&self, client: &K8sClient, group: &IngressGroup) -> Result<()> {
        if self.prune(client, group, true).await? == NodeState::Pending {
            return Err(OperatorError::Config(
                "waiting for DNS withdrawal and cache expiry".into(),
            ));
        }
        Ok(())
    }
}
