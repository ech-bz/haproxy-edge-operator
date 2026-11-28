use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
};
use ech_k8s::{K8sClient, NodeState, Reconciler};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct AppliedReadinessReconciler;

#[async_trait::async_trait]
impl Reconciler for AppliedReadinessReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        let nodes = group.edge_nodes(client).await?;
        if nodes.is_empty() {
            return Ok(NodeState::Pending);
        }
        for node in nodes {
            if node.applied_bundle(client, group, true).await?.is_none() {
                return Ok(NodeState::Pending);
            }
        }
        Ok(NodeState::Ready)
    }
}
