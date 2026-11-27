use crate::{
    crds::*,
    error::Result,
    support::resources::{labels, metadata, owner, selector},
};
use ech_k8s::{Component, CrMeta, K8sClient, ResourcesExt};
use k8s_openapi::api::core::v1::Secret;
use kube::{ResourceExt, api::ListParams};
use std::collections::BTreeSet;

pub(crate) async fn apply(
    client: &K8sClient,
    group: &IngressGroup,
    namespace: &str,
    component: impl Component,
    dns_names: Option<Vec<String>>,
    ip_addresses: Option<Vec<String>>,
) -> Result<()> {
    let name = component.name(owner(group)?);
    client
        .namespaced::<Certificate>(namespace)
        .apply(
            &name,
            &Certificate {
                metadata: metadata(group, namespace, component)?,
                spec: CertificateSpec {
                    secret_name: name.clone(),
                    dns_names,
                    ip_addresses,
                    issuer_ref: CertificateIssuerRef {
                        name: group.cr_name()?,
                        kind: Some("ClusterIssuer".into()),
                        group: Some("cert-manager.io".into()),
                    },
                    secret_template: Some(CertificateSecretTemplate {
                        labels: Some(labels(group, component)?),
                        annotations: None,
                    }),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await?;
    Ok(())
}

pub(crate) async fn prune<C: Component>(
    client: &K8sClient,
    group: &IngressGroup,
    namespace: &str,
    desired: &BTreeSet<String>,
) -> Result<()> {
    let params = ListParams::default().labels(&selector::<C>(group)?);
    let certificates = client.namespaced::<Certificate>(namespace);
    for certificate in certificates.api().list(&params).await?.items {
        if !desired.contains(&certificate.name_any()) {
            certificates
                .delete_if_exists(certificate.name_any())
                .await?;
        }
    }
    let secrets = client.namespaced::<Secret>(namespace);
    for secret in secrets.api().list(&params).await?.items {
        if !desired.contains(&secret.name_any()) {
            secrets.delete_if_exists(secret.name_any()).await?;
        }
    }
    Ok(())
}
