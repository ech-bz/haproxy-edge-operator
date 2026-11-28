use crate::{
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::components::{NamespaceComponent, OWNER, ResourceId},
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
        for node in group.selected_nodes(client).await? {
            let name = node.namespace;
            let labels = group.labels(NamespaceComponent {
                node: ResourceId::new(node.node.name_any()),
            })?;
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
