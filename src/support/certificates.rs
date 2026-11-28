use crate::{
    crds::*,
    error::{OperatorError, Result},
    support::{
        components::{DomainCertificateComponent, IpCertificateComponent, ResourceId},
        resources::EdgeNode,
    },
};
use ech_k8s::{Component, CrMeta, K8sClient, ResourcesExt};
use k8s_openapi::api::core::v1::Secret;
use kube::{ResourceExt, api::ListParams};
use std::collections::BTreeSet;

pub(crate) struct CertificateFile {
    namespace: String,
    name: String,
    pub(crate) file: String,
    pub(crate) domain: Option<String>,
}

impl CertificateFile {
    pub(crate) async fn load(&self, client: &K8sClient) -> Result<Option<Vec<u8>>> {
        let Some(data) = client
            .namespaced::<Secret>(&self.namespace)
            .api()
            .get_opt(&self.name)
            .await?
            .and_then(|secret| secret.data)
        else {
            return Ok(None);
        };
        let (Some(cert), Some(key)) = (data.get("tls.crt"), data.get("tls.key")) else {
            return Ok(None);
        };
        for (value, kind) in [(&cert.0, "certificate"), (&key.0, "key")] {
            std::str::from_utf8(value).map_err(|_| {
                OperatorError::Config(format!(
                    "{}/{}: invalid {kind} encoding",
                    self.namespace, self.name
                ))
            })?;
        }
        Ok(Some(
            [cert.0.as_slice(), b"\n", key.0.as_slice(), b"\n"].concat(),
        ))
    }
}

pub(crate) struct Certificates<'a> {
    client: &'a K8sClient,
    group: &'a IngressGroup,
}

impl<'a> Certificates<'a> {
    pub(crate) fn new(client: &'a K8sClient, group: &'a IngressGroup) -> Self {
        Self { client, group }
    }

    pub(crate) fn files(&self, node: &EdgeNode) -> Result<Vec<CertificateFile>> {
        let owner = self.group.owner()?;
        let mut files = vec![CertificateFile {
            namespace: node.namespace.clone(),
            name: IpCertificateComponent {
                ip: ResourceId::new(node.ip.to_string()),
            }
            .name(&owner),
            file: "default.pem".into(),
            domain: None,
        }];
        let namespace = self.group.cr_ns()?;
        files.extend(
            self.group
                .spec
                .domains
                .iter()
                .flatten()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|domain| CertificateFile {
                    namespace: namespace.clone(),
                    name: DomainCertificateComponent {
                        domain: ResourceId::new(&domain),
                    }
                    .name(&owner),
                    file: format!("domain-{}.pem", ResourceId::new(&domain)),
                    domain: Some(domain),
                }),
        );
        Ok(files)
    }

    pub(crate) async fn apply(
        &self,
        namespace: &str,
        component: impl Component,
        dns_names: Option<Vec<String>>,
        ip_addresses: Option<Vec<String>>,
    ) -> Result<()> {
        let name = component.name(self.group.owner()?);
        self.client
            .namespaced::<Certificate>(namespace)
            .apply(
                &name,
                &Certificate {
                    metadata: self.group.metadata(namespace, component)?,
                    spec: CertificateSpec {
                        secret_name: name.clone(),
                        dns_names,
                        ip_addresses,
                        issuer_ref: CertificateIssuerRef {
                            name: self.group.cr_name()?,
                            kind: Some("ClusterIssuer".into()),
                            group: Some("cert-manager.io".into()),
                        },
                        secret_template: Some(CertificateSecretTemplate {
                            labels: Some(self.group.labels(component)?),
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
        &self,
        namespace: &str,
        desired: &BTreeSet<String>,
    ) -> Result<()> {
        let params = ListParams::default().labels(&self.group.selector::<C>()?);
        let certificates = self.client.namespaced::<Certificate>(namespace);
        for certificate in certificates.api().list(&params).await?.items {
            if !desired.contains(&certificate.name_any()) {
                certificates
                    .delete_if_exists(certificate.name_any())
                    .await?;
            }
        }
        let secrets = self.client.namespaced::<Secret>(namespace);
        for secret in secrets.api().list(&params).await?.items {
            if !desired.contains(&secret.name_any()) {
                secrets.delete_if_exists(secret.name_any()).await?;
            }
        }
        Ok(())
    }
}
