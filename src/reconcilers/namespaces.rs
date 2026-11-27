use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        components::{NamespaceComponent, OWNER, ResourceId},
        resources::{edge_nodes, labels},
    },
};
use ech_k8s::{K8sClient, NodeState, Reconciler};
use k8s_openapi::api::core::v1::Namespace;
use kube::{
    ResourceExt,
    api::{ObjectMeta, PostParams},
};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct NamespacesReconciler;

#[async_trait::async_trait]
impl Reconciler for NamespacesReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        for node in edge_nodes(client, group).await? {
            let name = node.namespace;
            let labels = labels(
                group,
                NamespaceComponent {
                    node: ResourceId::new(node.name),
                },
            )?;
            let api = client.all::<Namespace>();
            match api.api().get_opt(&name).await? {
                Some(namespace) if namespace.labels().get(OWNER) != labels.get(OWNER) => {
                    return Err(OperatorError::Config(format!(
                        "namespace {name} belongs to another owner"
                    )));
                }
                Some(_) => {}
                None => {
                    api.api()
                        .create(
                            &PostParams::default(),
                            &Namespace {
                                metadata: ObjectMeta {
                                    name: Some(name),
                                    labels: Some(labels),
                                    ..Default::default()
                                },
                                ..Default::default()
                            },
                        )
                        .await?;
                }
            }
        }
        Ok(NodeState::Ready)
    }
}
