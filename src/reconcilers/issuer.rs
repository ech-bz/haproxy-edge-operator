use crate::{
    crds::{ClusterIssuer, IngressGroup},
    error::{OperatorError, Result},
};
use ech_k8s::{CrMeta, K8sClient, NodeState, Reconciler};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct IssuerReconciler;

#[async_trait::async_trait]
impl Reconciler for IssuerReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        Ok(
            if client
                .all::<ClusterIssuer>()
                .api()
                .get_opt(&group.cr_name()?)
                .await?
                .is_some()
            {
                NodeState::Ready
            } else {
                NodeState::Pending
            },
        )
    }
}
