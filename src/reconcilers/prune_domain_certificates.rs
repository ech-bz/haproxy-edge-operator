use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        certificates,
        components::{DomainCertificateComponent, ResourceId},
        resources::owner,
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
        let owner = owner(group)?;
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
        certificates::prune::<DomainCertificateComponent>(client, group, &group.cr_ns()?, &desired)
            .await?;
        Ok(NodeState::Ready)
    }

    async fn cleanup(&self, client: &K8sClient, group: &IngressGroup) -> Result<()> {
        certificates::prune::<DomainCertificateComponent>(
            client,
            group,
            &group.cr_ns()?,
            &Default::default(),
        )
        .await
    }
}
