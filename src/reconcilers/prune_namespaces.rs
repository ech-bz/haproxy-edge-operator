use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::resources::{owned_namespaces, selected_nodes},
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
        let desired: BTreeSet<_> = selected_nodes(client, group)
            .await?
            .into_iter()
            .map(|node| node.namespace)
            .collect();
        for namespace in owned_namespaces(client, group).await? {
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
        let namespaces = owned_namespaces(client, group).await?;
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
