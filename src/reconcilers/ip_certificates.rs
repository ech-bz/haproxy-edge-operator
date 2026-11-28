use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        certificates::Certificates,
        components::{IpCertificateComponent, ResourceId},
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
        for node in group.edge_nodes(client).await? {
            Certificates::new(client, group)
                .apply(
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
