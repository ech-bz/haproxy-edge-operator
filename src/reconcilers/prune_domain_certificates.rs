use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        certificates::Certificates,
        components::{DomainCertificateComponent, ResourceId},
    },
};
use ech_k8s::{Component, CrMeta, K8sClient, NodeState, Reconciler};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct PruneDomainCertificatesReconciler;

#[async_trait::async_trait]
impl Reconciler for PruneDomainCertificatesReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        let owner = group.owner()?;
        let desired = group
            .spec
            .domains
            .iter()
            .flatten()
            .map(|domain| {
                DomainCertificateComponent {
                    domain: ResourceId::new(domain),
                }
                .name(&owner)
            })
            .collect();
        Certificates::new(client, group)
            .prune::<DomainCertificateComponent>(&group.cr_ns()?, &desired)
            .await?;
        Ok(NodeState::Ready)
    }

    async fn cleanup(&self, client: &K8sClient, group: &IngressGroup) -> Result<()> {
        Certificates::new(client, group)
            .prune::<DomainCertificateComponent>(&group.cr_ns()?, &Default::default())
            .await
    }
}
