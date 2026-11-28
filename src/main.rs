mod agent;
mod config;
mod crds;
mod error;
mod reconcilers;
mod support;
mod workflow;

use agent::Agent;
use crds::{Certificate, ClusterIssuer};
use ech_k8s::{Operator, OperatorSpec, RuntimeSettings};
use error::{OperatorError, Result};
use k8s_openapi::api::{
    apps::v1::DaemonSet,
    core::v1::{ConfigMap, Namespace, Node, Secret},
    networking::v1::Ingress,
};
use kube::{
    ResourceExt,
    runtime::{reflector::ObjectRef, watcher},
};
use std::{collections::HashMap, fs, sync::Mutex, time::Duration};
use support::{
    components::{GROUP, OWNER},
    resources::Http01Ingress,
    watches::WatchContext,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_target(false)
        .compact()
        .init();
    match std::env::args().nth(1).as_deref().unwrap_or("operator") {
        "agent" => Agent::new().run().await,
        "ready" => {
            let agent = Agent::new();
            let (desired, _) = agent.bundle()?;
            let path = agent.state.join("applied");
            let applied = fs::read_to_string(&path).map_err(|error| {
                OperatorError::Config(format!(
                    "HAProxy configuration has not been applied ({}): {error}",
                    path.display()
                ))
            })?;
            if applied != desired {
                return Err(OperatorError::Config(
                    "HAProxy bundle has not been applied".into(),
                ));
            }
            agent.running().await
        }
        "operator" => {
            let operator: config::OperatorSettings = envy::prefixed("OPERATOR_").from_env()?;
            let leader: ech_k8s::LeaderSettings = envy::prefixed("OPERATOR_LEADER_").from_env()?;
            if leader.lease_grace_seconds == 0
                || leader.lease_grace_seconds >= leader.lease_duration_seconds
            {
                return Err(OperatorError::Config(
                    "lease grace must be positive and shorter than duration".into(),
                ));
            }
            let interval = Duration::from_secs(operator.reconcile_interval_seconds.max(1));
            Operator::run_with_controller(
                OperatorSpec {
                    runtime: RuntimeSettings {
                        health_port: operator.health_port,
                        reconcile_interval: interval,
                        error_backoff: Duration::from_secs(operator.error_backoff_seconds.max(1)),
                    },
                    leader,
                    field_manager: "haproxy-edge-operator",
                    workflow: workflow::EdgeWorkflow { operator },
                },
                move |controller, client| {
                    let nodes = controller.store();
                    let issuers = controller.store();
                    let solvers = controller.store();
                    let secrets = WatchContext {
                        groups: controller.store(),
                    };
                    let config_maps = secrets.clone();
                    let previous = Mutex::new(HashMap::<String, String>::new());
                    let owned = watcher::Config::default().labels(OWNER);
                    controller
                        .watches(
                            client.all::<Node>().into_inner(),
                            watcher::Config::default(),
                            move |node: Node| {
                                let group = node.labels().get(GROUP).cloned().unwrap_or_default();
                                let old = previous
                                    .lock()
                                    .unwrap()
                                    .insert(node.name_any(), group.clone());
                                nodes
                                    .state()
                                    .into_iter()
                                    .filter(|cr| {
                                        cr.name_any() == group
                                            || old.as_deref() == Some(cr.name_any().as_str())
                                    })
                                    .map(|cr| ObjectRef::from_obj(&*cr))
                                    .collect::<Vec<_>>()
                            },
                        )
                        .watches(
                            client.all::<ClusterIssuer>().into_inner(),
                            watcher::Config::default(),
                            move |issuer: ClusterIssuer| {
                                issuers
                                    .state()
                                    .into_iter()
                                    .filter(|cr| cr.name_any() == issuer.name_any())
                                    .map(|cr| ObjectRef::from_obj(&*cr))
                                    .collect::<Vec<_>>()
                            },
                        )
                        .watches(
                            client.all::<Ingress>().into_inner(),
                            watcher::Config::default()
                                .labels("acme.cert-manager.io/http01-solver=true"),
                            move |ingress: Ingress| {
                                let group = ingress.ingress_group();
                                solvers
                                    .state()
                                    .into_iter()
                                    .filter(|cr| group == Some(cr.name_any().as_str()))
                                    .map(|cr| ObjectRef::from_obj(&*cr))
                                    .collect::<Vec<_>>()
                            },
                        )
                        .watches(
                            client.all::<Secret>().into_inner(),
                            watcher::Config::default(),
                            move |secret: Secret| secrets.referenced(secret),
                        )
                        .watches(
                            client.all::<ConfigMap>().into_inner(),
                            watcher::Config::default(),
                            move |config_map: ConfigMap| config_maps.referenced(config_map),
                        )
                        .watches(
                            client.all::<Certificate>().into_inner(),
                            owned.clone(),
                            WatchContext::managed,
                        )
                        .watches(
                            client.all::<DaemonSet>().into_inner(),
                            owned.clone(),
                            WatchContext::managed,
                        )
                        .watches(
                            client.all::<Namespace>().into_inner(),
                            owned,
                            WatchContext::managed,
                        )
                        .reconcile_all_on(futures::stream::unfold((), move |_| async move {
                            tokio::time::sleep(interval).await;
                            Some(((), ()))
                        }))
                },
            )
            .await
        }
        value => Err(OperatorError::Config(format!("unknown command {value}"))),
    }
}
