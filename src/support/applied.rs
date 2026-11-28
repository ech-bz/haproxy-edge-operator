use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        certificates::Certificates,
        components::{BundleComponent, ProxyComponent, ResourceId},
        resources::EdgeNode,
    },
};
use ech_k8s::{Component, K8sClient};
use k8s_openapi::api::core::v1::{Pod, Secret};
use kube::{
    ResourceExt,
    api::{AttachParams, ListParams},
};
use std::{collections::BTreeMap, time::Duration};
use tokio::{io::AsyncReadExt, time::timeout};

impl EdgeNode {
    pub(crate) async fn applied_bundle(
        &self,
        client: &K8sClient,
        group: &IngressGroup,
        tls: bool,
    ) -> Result<Option<BTreeMap<String, Vec<u8>>>> {
        let Some(bundle) = client
            .namespaced::<Secret>(&self.namespace)
            .api()
            .get_opt(&BundleComponent.name(group.owner()?))
            .await?
        else {
            return Ok(None);
        };
        let files: BTreeMap<_, _> = bundle
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|(name, data)| (name, data.0))
            .collect();
        if tls {
            for certificate in Certificates::new(client, group).files(self)? {
                let Some(expected) = certificate.load(client).await? else {
                    return Ok(None);
                };
                if files.get(&certificate.file) != Some(&expected) {
                    return Ok(None);
                }
            }
        }
        let revision = ResourceId::new(serde_json::to_vec(&files)?).to_string();
        let pods = client.namespaced::<Pod>(&self.namespace);
        let active: Vec<_> = pods
            .api()
            .list(&ListParams::default().labels(&group.selector::<ProxyComponent>()?))
            .await?
            .items
            .into_iter()
            .filter(|pod| {
                pod.metadata.deletion_timestamp.is_none()
                    && pod.spec.as_ref().and_then(|spec| spec.node_name.as_deref())
                        == Some(self.name.as_str())
            })
            .collect();
        if active.len() != 1 {
            return Ok(None);
        }
        let mut process = match pods
            .api()
            .exec(
                &active[0].name_any(),
                ["/usr/local/bin/haproxy-edge-operator", "ready"],
                &AttachParams::default()
                    .container(ProxyComponent::NAME)
                    .stdout(true)
                    .stderr(false),
            )
            .await
        {
            Ok(process) => process,
            Err(kube::Error::Api(status)) if [400, 404, 409, 500].contains(&status.code) => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let result = timeout(Duration::from_secs(10), async {
            let mut applied = String::new();
            process
                .stdout()
                .unwrap()
                .take(256)
                .read_to_string(&mut applied)
                .await?;
            let status = process.take_status().unwrap().await;
            Ok::<_, OperatorError>(
                status.is_some_and(|status| status.status.as_deref() == Some("Success"))
                    && applied.trim() == revision,
            )
        })
        .await;
        match result {
            Ok(Ok(true)) => {
                process.join().await.map_err(|_| {
                    OperatorError::Config("HAProxy readiness command failed".into())
                })?;
                Ok(Some(files))
            }
            _ => {
                process.abort();
                Ok(None)
            }
        }
    }
}
