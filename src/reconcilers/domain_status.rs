use crate::{
    crds::{DomainClaim, IngressGroup},
    error::{OperatorError, Result},
    support::dns::DnsState,
};
use ech_k8s::{K8sClient, NodeState, Reconciler};
use kube::{
    ResourceExt,
    api::{ListParams, PostParams},
};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct DomainStatusReconciler;

#[async_trait::async_trait]
impl Reconciler for DomainStatusReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        let states = DnsState::load(client, group).await?;
        let claims = client.all::<DomainClaim>();
        for mut claim in claims.api().list(&ListParams::default()).await?.items {
            let Some(previous) = claim.status.as_ref().filter(|_| claim.held_by(group)) else {
                continue;
            };
            let Some(state) = states
                .iter()
                .find(|state| Some(&state.target.claim_uid) == claim.metadata.uid.as_ref())
            else {
                continue;
            };
            let mut status = previous.clone();
            status.observed_generation = claim.metadata.generation;
            status.ready = Some(state.synced && state.initialized && !state.draining);
            status.addresses = Some(
                state
                    .records
                    .record_values(None, &["A", "AAAA"])
                    .into_iter()
                    .collect(),
            );
            if serde_json::to_value(&status)? != serde_json::to_value(previous)? {
                claim.status = Some(status);
                claims
                    .api()
                    .replace_status(&claim.name_any(), &PostParams::default(), &claim)
                    .await?;
            }
        }
        Ok(NodeState::Ready)
    }
}
