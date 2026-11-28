use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::components::ProxyComponent,
};
use ech_k8s::{Component, K8sClient, NodeState, Reconciler};
use k8s_openapi::api::apps::v1::DaemonSet;
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct ReadinessReconciler;

#[async_trait::async_trait]
impl Reconciler for ReadinessReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        let mut ready = true;
        for node in group.edge_nodes(client).await? {
            let actual = client
                .namespaced::<DaemonSet>(&node.namespace)
                .api()
                .get(&ProxyComponent.name(group.owner()?))
                .await?;
            ready &= actual.status.as_ref().is_some_and(|status| {
                status.observed_generation == actual.metadata.generation
                    && status.desired_number_scheduled == 1
                    && status.number_ready == 1
                    && status.updated_number_scheduled == Some(1)
            });
        }
        Ok(if ready {
            NodeState::Ready
        } else {
            NodeState::Pending
        })
    }
}
