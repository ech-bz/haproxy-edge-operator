use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::components::EchComponent,
};
use ech_k8s::{Component, CrMeta, K8sClient, NodeState, Reconciler, ResourcesExt};
use k8s_openapi::api::core::v1::Secret;
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct PruneEchReconciler;

#[async_trait::async_trait]
impl Reconciler for PruneEchReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        if group.spec.ech.is_none() {
            self.cleanup(client, group).await?;
        }
        Ok(NodeState::Ready)
    }

    async fn cleanup(&self, client: &K8sClient, group: &IngressGroup) -> Result<()> {
        client
            .namespaced::<Secret>(&group.cr_ns()?)
            .delete_if_exists(EchComponent.name(group.owner()?))
            .await?;
        Ok(())
    }
}
