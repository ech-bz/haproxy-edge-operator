use crate::{
    crds::{DomainClaim, IngressGroup},
    error::{OperatorError, Result},
    support::{
        components::{DOMAIN_BINDING, DomainClaimComponent, ResourceId},
        domain::DomainName,
    },
};
use ech_k8s::{Component, K8sClient, NodeState, Reconciler};
use k8s_openapi::api::coordination::v1::Lease;
use kube::{
    ResourceExt,
    api::{DeleteParams, ListParams, PostParams, Preconditions},
};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Serialize)]
pub(crate) struct PruneDomainClaimsReconciler {
    pub(crate) state_namespace: String,
}

impl PruneDomainClaimsReconciler {
    async fn prune(&self, client: &K8sClient, group: &IngressGroup, deleting: bool) -> Result<()> {
        let desired = if deleting {
            BTreeSet::new()
        } else {
            group.domains()?
        };
        let claims = client.all::<DomainClaim>();
        let mut retained = BTreeSet::new();
        for mut claim in claims.api().list(&ListParams::default()).await?.items {
            if !claim.held_by(group) {
                continue;
            }
            let domain = DomainName::new(&claim.spec.domain)?.0;
            if desired.contains(&domain) && claim.metadata.deletion_timestamp.is_none() {
                retained.insert(
                    DomainClaimComponent {
                        domain: ResourceId::new(&domain),
                    }
                    .name("claim"),
                );
                continue;
            }
            if let Some(finalizers) = &mut claim.metadata.finalizers {
                finalizers.retain(|value| value != DOMAIN_BINDING);
            }
            match claims
                .api()
                .replace(&claim.name_any(), &PostParams::default(), &claim)
                .await
            {
                Ok(actual) => claim = actual,
                Err(kube::Error::Api(status)) if status.code == 404 => continue,
                Err(error) => return Err(error.into()),
            }
            if let Some(status) = &mut claim.status {
                status.holder = None;
                status.ready = Some(false);
                status.addresses = Some(Vec::new());
            }
            match claims
                .api()
                .replace_status(&claim.name_any(), &PostParams::default(), &claim)
                .await
            {
                Ok(_) => (),
                Err(kube::Error::Api(status)) if status.code == 404 => (),
                Err(error) => return Err(error.into()),
            }
        }
        let leases = client.namespaced::<Lease>(&self.state_namespace);
        for lease in leases
            .api()
            .list(&ListParams::default().labels(&group.selector::<DomainClaimComponent>()?))
            .await?
            .items
        {
            if !retained.contains(&lease.name_any()) {
                leases
                    .api()
                    .delete(
                        &lease.name_any(),
                        &DeleteParams {
                            preconditions: Some(Preconditions {
                                uid: lease.uid(),
                                resource_version: lease.metadata.resource_version.clone(),
                            }),
                            ..Default::default()
                        },
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Reconciler for PruneDomainClaimsReconciler {
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
