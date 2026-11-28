use crate::{
    crds::{DomainClaim, DomainClaimStatus, DomainClaimStatusHolder, IngressGroup},
    error::{OperatorError, Result},
    support::{
        components::{DOMAIN_BINDING, DomainClaimComponent, ResourceId},
        domain::DomainName,
    },
};
use ech_k8s::{Component, CrMeta, K8sClient, NodeState, Reconciler};
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use kube::{
    ResourceExt,
    api::{ListParams, ObjectMeta, PostParams},
};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Serialize)]
pub(crate) struct DomainClaimsReconciler {
    pub(crate) state_namespace: String,
}

#[async_trait::async_trait]
impl Reconciler for DomainClaimsReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        let claims = client.all::<DomainClaim>();
        let mut registry = BTreeMap::<String, Vec<DomainClaim>>::new();
        for claim in claims.api().list(&ListParams::default()).await?.items {
            if let Ok(domain) = DomainName::new(&claim.spec.domain) {
                registry.entry(domain.0).or_default().push(claim);
            }
        }
        let uid = group
            .uid()
            .ok_or_else(|| OperatorError::Config("IngressGroup has no UID".into()))?;
        for domain in group.domains()? {
            let Some(entries) = registry.get_mut(&domain) else {
                return Err(OperatorError::Config(format!(
                    "domain {domain} has no DomainClaim"
                )));
            };
            if entries.len() != 1 {
                return Err(OperatorError::Config(format!(
                    "domain {domain} has multiple DomainClaims"
                )));
            }
            let claim = &mut entries[0];
            if claim.metadata.deletion_timestamp.is_some() {
                return Err(OperatorError::Config(format!(
                    "DomainClaim {} is being deleted",
                    claim.name_any()
                )));
            }
            if let Some(holder) = claim
                .status
                .as_ref()
                .and_then(|status| status.holder.as_ref())
                && holder.uid != uid
            {
                tracing::warn!(
                    "domain {domain} is reserved by {}/{}",
                    holder.namespace,
                    holder.name
                );
                return Ok(NodeState::Pending);
            }
            let component = DomainClaimComponent {
                domain: ResourceId::new(&domain),
            };
            let name = component.name("claim");
            let identity = format!(
                "{}/{}",
                claim
                    .uid()
                    .ok_or_else(|| OperatorError::Config("DomainClaim has no UID".into()))?,
                uid
            );
            let leases = client.namespaced::<Lease>(&self.state_namespace);
            let desired = Lease {
                metadata: ObjectMeta {
                    name: Some(name.clone()),
                    namespace: Some(self.state_namespace.clone()),
                    labels: Some(group.labels(component)?),
                    ..Default::default()
                },
                spec: Some(LeaseSpec {
                    holder_identity: Some(identity.clone()),
                    ..Default::default()
                }),
            };
            let lease = match leases.api().create(&PostParams::default(), &desired).await {
                Ok(lease) => lease,
                Err(kube::Error::Api(status)) if status.code == 409 => {
                    leases.api().get(&name).await?
                }
                Err(error) => return Err(error.into()),
            };
            if lease
                .spec
                .as_ref()
                .and_then(|spec| spec.holder_identity.as_ref())
                != Some(&identity)
            {
                tracing::warn!("domain {domain} has another active binding");
                return Ok(NodeState::Pending);
            }
            if !claim
                .finalizers()
                .iter()
                .any(|value| value == DOMAIN_BINDING)
            {
                claim
                    .metadata
                    .finalizers
                    .get_or_insert_default()
                    .push(DOMAIN_BINDING.into());
                *claim = claims
                    .api()
                    .replace(&claim.name_any(), &PostParams::default(), claim)
                    .await?;
            }
            let mut status = claim.status.clone().unwrap_or_default();
            status.domain = Some(domain);
            status.holder = Some(DomainClaimStatusHolder {
                name: group.cr_name()?,
                namespace: group.cr_ns()?,
                uid: uid.clone(),
            });
            if serde_json::to_value(&claim.status)? != serde_json::to_value(Some(&status))? {
                claim.status = Some(DomainClaimStatus {
                    ready: Some(false),
                    ..status
                });
                claims
                    .api()
                    .replace_status(&claim.name_any(), &PostParams::default(), claim)
                    .await?;
            }
        }
        Ok(NodeState::Ready)
    }
}
