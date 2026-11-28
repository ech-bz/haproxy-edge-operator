use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{components::*, domain::DomainName},
};
use ech_k8s::{Component, CrMeta, K8sClient};
use k8s_openapi::api::{
    core::v1::{Namespace, Node},
    networking::v1::Ingress,
};
use kube::{
    Resource, ResourceExt,
    api::{ListParams, ObjectMeta},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

pub(crate) struct EdgeNode {
    pub(crate) name: String,
    pub(crate) namespace: String,
    pub(crate) ip: IpAddr,
}

pub(crate) struct SelectedNode {
    pub(crate) node: Node,
    pub(crate) namespace: String,
}

pub(crate) trait Http01Ingress {
    fn ingress_group(&self) -> Option<&str>;
}

impl Http01Ingress for Ingress {
    fn ingress_group(&self) -> Option<&str> {
        self.spec
            .as_ref()
            .and_then(|spec| spec.ingress_class_name.as_deref())
            .or_else(|| {
                self.annotations()
                    .get("kubernetes.io/ingress.class")
                    .map(String::as_str)
            })
            .and_then(|class| class.strip_prefix("haproxy-"))
    }
}

impl SelectedNode {
    pub(crate) fn ip(&self) -> Result<IpAddr> {
        let node = &self.node;
        let name = node.name_any();
        let address = node
            .annotations()
            .get(PUBLIC_IP)
            .or_else(|| node.labels().get(PUBLIC_IP))
            .ok_or_else(|| OperatorError::Config(format!("node {name} has no {PUBLIC_IP}")))?;
        address.parse().map_err(|_| {
            OperatorError::Config(format!("node {name} has invalid public IP {address}"))
        })
    }
}

impl IngressGroup {
    pub(crate) fn owner(&self) -> Result<String> {
        Ok(ResourceId::new(
            self.uid()
                .ok_or_else(|| OperatorError::Config("IngressGroup has no UID".into()))?,
        )
        .to_string())
    }

    pub(crate) fn labels(&self, component: impl Component) -> Result<BTreeMap<String, String>> {
        let mut labels = component.labels(self.owner()?);
        labels.extend([
            (GROUP.into(), self.cr_name()?),
            (GROUP_NS.into(), self.cr_ns()?),
            (
                OWNER.into(),
                self.uid()
                    .ok_or_else(|| OperatorError::Config("IngressGroup has no UID".into()))?,
            ),
        ]);
        Ok(labels)
    }

    pub(crate) fn selector<C: Component>(&self) -> Result<String> {
        Ok(format!(
            "{},{OWNER}={}",
            C::selector(self.owner()?),
            self.uid().unwrap_or_default()
        ))
    }

    pub(crate) fn metadata(
        &self,
        namespace: &str,
        component: impl Component,
    ) -> Result<ObjectMeta> {
        Ok(ObjectMeta {
            name: Some(component.name(self.owner()?)),
            namespace: Some(namespace.into()),
            labels: Some(self.labels(component)?),
            owner_references: (namespace == self.cr_ns()?)
                .then(|| vec![self.controller_owner_ref(&()).expect("persisted group")]),
            ..Default::default()
        })
    }

    pub(crate) async fn selected_nodes(&self, client: &K8sClient) -> Result<Vec<SelectedNode>> {
        let name = self.cr_name()?;
        Ok(client
            .all::<Node>()
            .api()
            .list(&ListParams::default().labels(&format!("{GROUP}={name}")))
            .await?
            .items
            .into_iter()
            .map(|node| {
                let component = NamespaceComponent {
                    node: ResourceId::new(node.name_any()),
                };
                let namespace = component.name(NamespacePrefix::new(&name, &component));
                SelectedNode { node, namespace }
            })
            .collect())
    }

    pub(crate) async fn edge_nodes(&self, client: &K8sClient) -> Result<Vec<EdgeNode>> {
        self.selected_nodes(client)
            .await?
            .into_iter()
            .map(|selected| {
                let ip = selected.ip()?;
                Ok(EdgeNode {
                    name: selected.node.name_any(),
                    namespace: selected.namespace,
                    ip,
                })
            })
            .collect()
    }

    pub(crate) async fn owned_namespaces(&self, client: &K8sClient) -> Result<Vec<Namespace>> {
        Ok(client
            .all::<Namespace>()
            .api()
            .list(&ListParams::default().labels(&self.selector::<NamespaceComponent>()?))
            .await?
            .items)
    }

    pub(crate) fn domains(&self) -> Result<BTreeSet<String>> {
        self.spec
            .domains
            .iter()
            .flatten()
            .map(String::as_str)
            .chain(self.spec.ech.as_deref())
            .map(|domain| DomainName::new(domain).map(|name| name.0))
            .collect()
    }

    pub(crate) fn icann_domains(&self) -> Result<BTreeSet<String>> {
        Ok(self
            .domains()?
            .into_iter()
            .filter(|domain| !DomainName::is_uns(domain))
            .collect())
    }
}
