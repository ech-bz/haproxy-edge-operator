use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        certificates,
        components::{IpCertificateComponent, ResourceId},
        resources::edge_nodes,
    },
};
use ech_k8s::{K8sClient, NodeState, Reconciler};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct IpCertificatesReconciler;

#[async_trait::async_trait]
impl Reconciler for IpCertificatesReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        for node in edge_nodes(client, group).await? {
            certificates::apply(
                client,
                group,
                &node.namespace,
                IpCertificateComponent {
                    ip: ResourceId::new(node.ip.to_string()),
                },
                None,
                Some(vec![node.ip.to_string()]),
            )
            .await?;
        }
        Ok(NodeState::Ready)
    }
}
