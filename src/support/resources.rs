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

pub(crate) fn edge_namespace(group: &IngressGroup, node: &str) -> Result<String> {
    Ok(NamespaceComponent {
        node: ResourceId::new(node),
    }
    .name(owner(group)?))
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

pub(crate) async fn selected_nodes(client: &K8sClient, group: &IngressGroup) -> Result<Vec<Node>> {
    Ok(client
        .all::<Node>()
        .api()
        .list(&ListParams::default().labels(&format!("{GROUP}={}", group.cr_name()?)))
        .await?
        .items)
}

pub(crate) async fn edge_nodes(client: &K8sClient, group: &IngressGroup) -> Result<Vec<EdgeNode>> {
    selected_nodes(client, group)
        .await?
        .into_iter()
        .map(|node| {
            let node_name = node.name_any();
            let ip = node_ip(&node)?;
            Ok(EdgeNode {
                namespace: edge_namespace(group, &node_name)?,
                name: node_name,
                ip,
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
