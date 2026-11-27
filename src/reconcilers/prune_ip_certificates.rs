use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        certificates,
        components::{IpCertificateComponent, ResourceId},
        resources::{edge_namespace, node_ip, owner, selected_nodes},
    },
};
use ech_k8s::{Component, K8sClient, NodeState, Reconciler};
use kube::ResourceExt;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Serialize)]
pub(crate) struct PruneIpCertificatesReconciler;

#[async_trait::async_trait]
impl Reconciler for PruneIpCertificatesReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        for node in selected_nodes(client, group).await? {
            let Ok(ip) = node_ip(&node) else { continue };
            let namespace = edge_namespace(group, &node.name_any())?;
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
            .name(owner(group)?)]);
            certificates::prune::<IpCertificateComponent>(client, group, &namespace, &desired)
                .await?;
        }
        Ok(NodeState::Ready)
    }
}
