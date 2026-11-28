use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::components::EchComponent,
};
use ech_k8s::{Component, CrMeta, K8sClient, NodeState, Reconciler, ResourcesExt};
use k8s_openapi::api::core::v1::Secret;
use kube::{ResourceExt, api::ListParams};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct PruneEchReconciler;

impl PruneEchReconciler {
    async fn prune(&self, client: &K8sClient, group: &IngressGroup, deleting: bool) -> Result<()> {
        let owner = group.owner()?;
        let desired: std::collections::BTreeSet<_> = if deleting {
            Default::default()
        } else {
            group
                .ech_covers()?
                .iter()
                .map(|cover| EchComponent::new(cover).name(&owner))
                .collect()
        };
        let secrets = client.namespaced::<Secret>(&group.cr_ns()?);
        for secret in secrets
            .api()
            .list(&ListParams::default().labels(&group.selector::<EchComponent>()?))
            .await?
            .items
        {
            if !desired.contains(&secret.name_any()) {
                secrets.delete_if_exists(secret.name_any()).await?;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Reconciler for PruneEchReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        self.prune(client, group, false).await?;
        Ok(NodeState::Ready)
    }

    async fn cleanup(&self, client: &K8sClient, group: &IngressGroup) -> Result<()> {
        self.prune(client, group, true).await
    }
}
