use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::components::*,
};
use ech_k8s::{Component, CrMeta, K8sClient};
use k8s_openapi::api::core::v1::{Namespace, Node};
use kube::{
    Resource, ResourceExt,
    api::{ListParams, ObjectMeta},
};
use std::{collections::BTreeMap, net::IpAddr};

pub(crate) struct EdgeNode {
    pub(crate) name: String,
    pub(crate) namespace: String,
    pub(crate) ip: IpAddr,
}

pub(crate) struct SelectedNode {
    pub(crate) node: Node,
    pub(crate) namespace: String,
}

pub(crate) fn owner(group: &IngressGroup) -> Result<String> {
    Ok(hash(group.uid().ok_or_else(|| {
        OperatorError::Config("IngressGroup has no UID".into())
    })?))
}

pub(crate) fn labels(
    group: &IngressGroup,
    component: impl Component,
) -> Result<BTreeMap<String, String>> {
    let mut labels = component.labels(owner(group)?);
    labels.extend([
        (GROUP.into(), group.cr_name()?),
        (GROUP_NS.into(), group.cr_ns()?),
        (
            OWNER.into(),
            group
                .uid()
                .ok_or_else(|| OperatorError::Config("IngressGroup has no UID".into()))?,
        ),
    ]);
    Ok(labels)
}

pub(crate) fn selector<C: Component>(group: &IngressGroup) -> Result<String> {
    Ok(format!(
        "{},{OWNER}={}",
        C::selector(owner(group)?),
        group.uid().unwrap_or_default()
    ))
}

pub(crate) fn metadata(
    group: &IngressGroup,
    namespace: &str,
    component: impl Component,
) -> Result<ObjectMeta> {
    Ok(ObjectMeta {
        name: Some(component.name(owner(group)?)),
        namespace: Some(namespace.into()),
        labels: Some(labels(group, component)?),
        owner_references: (namespace == group.cr_ns()?)
            .then(|| vec![group.controller_owner_ref(&()).expect("persisted group")]),
        ..Default::default()
    })
}

pub(crate) fn node_ip(node: &Node) -> Result<IpAddr> {
    let name = node.name_any();
    let address = node
        .annotations()
        .get(PUBLIC_IP)
        .or_else(|| node.labels().get(PUBLIC_IP))
        .ok_or_else(|| OperatorError::Config(format!("node {name} has no {PUBLIC_IP}")))?;
    address
        .parse()
        .map_err(|_| OperatorError::Config(format!("node {name} has invalid public IP {address}")))
}

pub(crate) async fn selected_nodes(
    client: &K8sClient,
    group: &IngressGroup,
) -> Result<Vec<SelectedNode>> {
    let name = group.cr_name()?;
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

pub(crate) async fn edge_nodes(client: &K8sClient, group: &IngressGroup) -> Result<Vec<EdgeNode>> {
    selected_nodes(client, group)
        .await?
        .into_iter()
        .map(|selected| {
            Ok(EdgeNode {
                name: selected.node.name_any(),
                namespace: selected.namespace,
                ip: node_ip(&selected.node)?,
            })
        })
        .collect()
}

pub(crate) async fn owned_namespaces(
    client: &K8sClient,
    group: &IngressGroup,
) -> Result<Vec<Namespace>> {
    Ok(client
        .all::<Namespace>()
        .api()
        .list(&ListParams::default().labels(&selector::<NamespaceComponent>(group)?))
        .await?
        .items)
}
