use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        certificates::Certificates,
        components::{DomainCertificateComponent, ResourceId},
    },
};
use ech_k8s::{CrMeta, K8sClient, NodeState, Reconciler};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct DomainCertificateReconciler {
    pub(crate) domain: String,
}

#[async_trait::async_trait]
impl Reconciler for DomainCertificateReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        Certificates::new(client, group)
            .apply(
                &group.cr_ns()?,
                DomainCertificateComponent {
                    domain: ResourceId::new(&self.domain),
                },
                Some(vec![self.domain.clone()]),
                None,
            )
            .await?;
        Ok(NodeState::Ready)
    }
}
