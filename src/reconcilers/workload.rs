use crate::{
    config::OperatorSettings,
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        components::{BundleComponent, ProxyComponent},
        resources::{edge_nodes, labels, metadata, owner},
    },
};
use ech_k8s::{Component, K8sClient, NodeState, Reconciler, ResourcesExt};
use k8s_openapi::{
    api::{
        apps::v1::{DaemonSet, DaemonSetSpec, DaemonSetUpdateStrategy},
        core::v1::*,
    },
    apimachinery::pkg::{api::resource::Quantity, apis::meta::v1::LabelSelector},
};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Serialize)]
pub(crate) struct WorkloadReconciler {
    pub(crate) operator: OperatorSettings,
}

#[async_trait::async_trait]
impl Reconciler for WorkloadReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        for node in edge_nodes(client, group).await? {
            let command = |mode: &str| {
                Some(vec![
                    "/usr/local/bin/haproxy-edge-operator".into(),
                    mode.into(),
                ])
            };
            let desired = DaemonSet {
                metadata: metadata(group, &node.namespace, ProxyComponent)?,
                spec: Some(DaemonSetSpec {
                    selector: LabelSelector {
                        match_labels: Some(labels(group, ProxyComponent)?),
                        ..Default::default()
                    },
                    update_strategy: Some(DaemonSetUpdateStrategy {
                        type_: Some("RollingUpdate".into()),
                        ..Default::default()
                    }),
                    template: PodTemplateSpec {
                        metadata: Some(kube::api::ObjectMeta {
                            labels: Some(labels(group, ProxyComponent)?),
                            ..Default::default()
                        }),
                        spec: Some(PodSpec {
                            affinity: Some(Affinity {
                                node_affinity: Some(NodeAffinity {
                                    required_during_scheduling_ignored_during_execution: Some(
                                        NodeSelector {
                                            node_selector_terms: vec![NodeSelectorTerm {
                                                match_fields: Some(vec![NodeSelectorRequirement {
                                                    key: "metadata.name".into(),
                                                    operator: "In".into(),
                                                    values: Some(vec![node.name.clone()]),
                                                }]),
                                                ..Default::default()
                                            }],
                                        },
                                    ),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }),
                            host_network: Some(true),
                            dns_policy: Some("ClusterFirstWithHostNet".into()),
                            automount_service_account_token: Some(false),
                            termination_grace_period_seconds: Some(30),
                            security_context: Some(PodSecurityContext {
                                run_as_user: Some(0),
                                run_as_group: Some(65532),
                                run_as_non_root: Some(false),
                                fs_group: Some(65532),
                                ..Default::default()
                            }),
                            tolerations: Some(vec![Toleration {
                                key: Some("ech.bz/ingress-only".into()),
                                operator: Some("Equal".into()),
                                value: Some("true".into()),
                                effect: Some("NoSchedule".into()),
                                ..Default::default()
                            }]),
                            volumes: Some(vec![
                                Volume {
                                    name: "bundle".into(),
                                    secret: Some(SecretVolumeSource {
                                        secret_name: Some(BundleComponent.name(owner(group)?)),
                                        default_mode: Some(0o440),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                },
                                Volume {
                                    name: "runtime".into(),
                                    empty_dir: Some(EmptyDirVolumeSource::default()),
                                    ..Default::default()
                                },
                            ]),
                            containers: vec![Container {
                                name: ProxyComponent::NAME.into(),
                                image: Some(self.operator.worker_image.clone()),
                                image_pull_policy: Some("IfNotPresent".into()),
                                command: command("agent"),
                                readiness_probe: Some(Probe {
                                    exec: Some(ExecAction {
                                        command: command("ready"),
                                    }),
                                    period_seconds: Some(2),
                                    timeout_seconds: Some(3),
                                    failure_threshold: Some(1),
                                    ..Default::default()
                                }),
                                resources: Some(ResourceRequirements {
                                    requests: Some(BTreeMap::from([
                                        ("cpu".into(), Quantity("50m".into())),
                                        ("memory".into(), Quantity("64Mi".into())),
                                    ])),
                                    ..Default::default()
                                }),
                                security_context: Some(SecurityContext {
                                    read_only_root_filesystem: Some(true),
                                    allow_privilege_escalation: Some(false),
                                    capabilities: Some(Capabilities {
                                        drop: Some(vec!["ALL".into()]),
                                        add: Some(vec!["NET_BIND_SERVICE".into()]),
                                    }),
                                    ..Default::default()
                                }),
                                volume_mounts: Some(vec![
                                    VolumeMount {
                                        name: "bundle".into(),
                                        mount_path: "/etc/edge".into(),
                                        read_only: Some(true),
                                        ..Default::default()
                                    },
                                    VolumeMount {
                                        name: "runtime".into(),
                                        mount_path: "/run/edge".into(),
                                        ..Default::default()
                                    },
                                ]),
                                ..Default::default()
                            }],
                            ..Default::default()
                        }),
                    },
                    ..Default::default()
                }),
                ..Default::default()
            };
            client
                .namespaced::<DaemonSet>(&node.namespace)
                .apply(ProxyComponent.name(owner(group)?), &desired)
                .await?;
        }
        Ok(NodeState::Ready)
    }
}
