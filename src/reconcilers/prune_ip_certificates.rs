use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        certificates::Certificates,
        components::{IpCertificateComponent, ResourceId},
    },
};
use ech_k8s::{Component, K8sClient, NodeState, Reconciler};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Serialize)]
pub(crate) struct PruneIpCertificatesReconciler;

#[async_trait::async_trait]
impl Reconciler for PruneIpCertificatesReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        for node in group.selected_nodes(client).await? {
            let Ok(ip) = node.ip() else {
                continue;
            };
            let namespace = node.namespace;
            if client
                .all::<k8s_openapi::api::core::v1::Namespace>()
                .api()
                .get_opt(&namespace)
                .await?
                .is_none()
            {
                continue;
            }
            let desired = BTreeSet::from([IpCertificateComponent {
                ip: ResourceId::new(ip.to_string()),
            }
            .name(group.owner()?)]);
            Certificates::new(client, group)
                .prune::<IpCertificateComponent>(&namespace, &desired)
                .await?;
        }
        Ok(NodeState::Ready)
    }
}
