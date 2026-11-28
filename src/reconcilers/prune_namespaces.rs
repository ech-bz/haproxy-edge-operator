use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
};
use ech_k8s::{K8sClient, NodeState, Reconciler, ResourcesExt};
use k8s_openapi::api::core::v1::Namespace;
use kube::ResourceExt;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Serialize)]
pub(crate) struct PruneNamespacesReconciler;

#[async_trait::async_trait]
impl Reconciler for PruneNamespacesReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        let desired: BTreeSet<_> = group
            .selected_nodes(client)
            .await?
            .into_iter()
            .map(|node| node.namespace)
            .collect();
        for namespace in group.owned_namespaces(client).await? {
            if !desired.contains(&namespace.name_any()) {
                client
                    .all::<Namespace>()
                    .delete_if_exists(namespace.name_any())
                    .await?;
            }
        }
        Ok(NodeState::Ready)
    }

    async fn cleanup(&self, client: &K8sClient, group: &IngressGroup) -> Result<()> {
        let namespaces = group.owned_namespaces(client).await?;
        for namespace in &namespaces {
            client
                .all::<Namespace>()
                .delete_if_exists(namespace.name_any())
                .await?;
        }
        if !namespaces.is_empty() {
            return Err(OperatorError::Config(
                "waiting for edge namespace deletion".into(),
            ));
        }
        Ok(())
    }
}
