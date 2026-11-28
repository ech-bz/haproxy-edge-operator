use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::components::EchComponent,
};
use ech_k8s::{Component, CrMeta, K8sClient, NodeState, Reconciler};
use k8s_openapi::{ByteString, api::core::v1::Secret};
use kube::api::PostParams;
use serde::Serialize;
use std::{collections::BTreeMap, time::Duration};
use tokio::{process::Command, time::timeout};

#[derive(Clone, Serialize)]
pub(crate) struct EchReconciler;

#[async_trait::async_trait]
impl Reconciler for EchReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        let Some(cover) = group.ech_cover()? else {
            return Ok(NodeState::Ready);
        };
        let secrets = client.namespaced::<Secret>(&group.cr_ns()?);
        let name = EchComponent.name(group.owner()?);
        let current = secrets.api().get_opt(&name).await?;
        if current
            .as_ref()
            .and_then(|secret| secret.data.as_ref())
            .is_some_and(|data| {
                data.get("public-name")
                    .is_some_and(|value| value.0 == cover.as_bytes())
                    && data.contains_key("current.ech")
            })
        {
            return Ok(NodeState::Ready);
        }
        let output = timeout(
            Duration::from_secs(30),
            Command::new("openssl")
                .args(["ech", "-public_name", &cover, "-out", "/dev/stdout"])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| OperatorError::Config("ECH key generation timed out".into()))??;
        if !output.status.success() || output.stdout.is_empty() {
            return Err(OperatorError::Config("ECH key generation failed".into()));
        }
        let mut secret = Secret {
            metadata: group.metadata(&group.cr_ns()?, EchComponent)?,
            data: Some(BTreeMap::from([
                ("public-name".into(), ByteString(cover.into_bytes())),
                ("current.ech".into(), ByteString(output.stdout)),
            ])),
            ..Default::default()
        };
        let result = if let Some(current) = current {
            secret.metadata.resource_version = current.metadata.resource_version;
            secrets
                .api()
                .replace(&name, &PostParams::default(), &secret)
                .await
        } else {
            secrets.api().create(&PostParams::default(), &secret).await
        };
        match result {
            Ok(_) => Ok(NodeState::Ready),
            Err(kube::Error::Api(status)) if status.code == 409 => Ok(NodeState::Pending),
            Err(error) => Err(error.into()),
        }
    }
}
