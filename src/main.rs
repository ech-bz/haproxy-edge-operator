mod agent;
mod config;
mod crds;
mod error;
mod reconcilers;
mod support;
mod workflow;

use agent::{Settings, bundle, listeners, master, running, switch};
use crds::{Certificate, ClusterIssuer};
use ech_k8s::{Operator, OperatorSpec, RuntimeSettings};
use error::{OperatorError, Result};
use k8s_openapi::api::{
    apps::v1::DaemonSet,
    core::v1::{Namespace, Node, Secret, Service},
    networking::v1::Ingress,
};
use kube::{
    ResourceExt,
    runtime::{reflector::ObjectRef, watcher},
};
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    sync::Mutex,
    time::Duration,
};
use support::{
    components::{GROUP, OWNER},
    watches::managed,
};
use tokio::{
    process::{Child, Command},
    signal::unix::{SignalKind, signal},
    time::{sleep, timeout},
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
        "agent" => {
            let settings = Settings::load();
            fs::create_dir_all(&settings.state)?;
            let mut terminate = signal(SignalKind::terminate())?;
            let mut interrupt = signal(SignalKind::interrupt())?;
            let mut child: Option<Child> = None;
            let mut applied = String::new();
            loop {
                if let Some(child) = child.as_mut()
                    && let Some(status) = child.try_wait()?
                {
                    return Err(OperatorError::Config(format!("HAProxy exited: {status}")));
                }
                match bundle(&settings.bundle) {
                    Ok((revision, files)) if revision != applied => {
                        let result: Result<()> = async {
                            let child = &mut child;
                            let revision = revision.as_str();
                            let generation = settings.state.join(format!("generation-{revision}"));
                            fs::create_dir_all(&generation)?;
                            fs::set_permissions(&generation, fs::Permissions::from_mode(0o700))?;
                            for (name, contents) in files {
                                let contents = if name == "haproxy.cfg" || name == "crt-list" {
                                    String::from_utf8(contents)
                                        .map_err(|_| {
                                            OperatorError::Config(
                                                "invalid configuration encoding".into(),
                                            )
                                        })?
                                        .replace("@BUNDLE@", &generation.to_string_lossy())
                                        .into_bytes()
                                } else {
                                    contents
                                };
                                fs::write(generation.join(name), contents)?;
                            }
                            let output = Command::new(&settings.haproxy)
                                .arg("-c")
                                .arg("-f")
                                .arg(generation.join("haproxy.cfg"))
                                .output()
                                .await
                                .map_err(|error| {
                                    OperatorError::Config(format!(
                                        "cannot run {}: {error}",
                                        settings.haproxy
                                    ))
                                })?;
                            if !output.status.success() {
                                return Err(OperatorError::Config(format!(
                                    "HAProxy rejected bundle: {}",
                                    String::from_utf8_lossy(&output.stderr)
                                )));
                            }
                            let previous = fs::read_link(settings.state.join("current")).ok();
                            let previous_listeners = if child.is_some() {
                                listeners(&fs::read_to_string(
                                    settings.state.join("current/haproxy.cfg"),
                                )?)?
                            } else {
                                BTreeSet::new()
                            };
                            for address in
                                listeners(&fs::read_to_string(generation.join("haproxy.cfg"))?)?
                            {
                                drop(TcpListener::bind((address.ip(), 0)).map_err(|error| {
                                    OperatorError::Config(format!(
                                        "cannot bind local IP {}: {error}",
                                        address.ip()
                                    ))
                                })?);
                                if !previous_listeners.contains(&address) {
                                    drop(TcpListener::bind(address).map_err(|error| {
                                        OperatorError::Config(format!(
                                            "cannot bind listener {address}: {error}"
                                        ))
                                    })?);
                                }
                            }
                            switch(&settings.state, &generation)?;
                            let result = async {
                                if child.is_some() {
                                    let response = master(&settings.state, "reload").await?;
                                    if response.lines().any(|line| line == "Success=1") {
                                        Ok(())
                                    } else {
                                        Err(OperatorError::Config(format!(
                                            "HAProxy reload failed: {response}"
                                        )))
                                    }
                                } else {
                                    *child = Some(
                                        Command::new(&settings.haproxy)
                                            .args(["-W", "-db", "-S"])
                                            .arg(settings.state.join("master.sock"))
                                            .arg("-f")
                                            .arg(settings.state.join("current/haproxy.cfg"))
                                            .kill_on_drop(true)
                                            .spawn()?,
                                    );
                                    timeout(Duration::from_secs(10), async {
                                        while running(&settings.state).await.is_err() {
                                            if child.as_mut().unwrap().try_wait()?.is_some() {
                                                return Err(OperatorError::Config(
                                                    "HAProxy exited during startup".into(),
                                                ));
                                            }
                                            sleep(Duration::from_millis(50)).await;
                                        }
                                        Ok(())
                                    })
                                    .await
                                    .map_err(|_| {
                                        OperatorError::Config("HAProxy startup timed out".into())
                                    })?
                                }
                            }
                            .await;
                            if let Err(error) = result {
                                if let Some(previous) = previous {
                                    switch(&settings.state, &previous)?;
                                    let recovery = master(&settings.state, "reload").await?;
                                    if !recovery.lines().any(|line| line == "Success=1") {
                                        return Err(OperatorError::Config(format!(
                                            "HAProxy rollback failed after {error}: {recovery}"
                                        )));
                                    }
                                }
                                return Err(error);
                            }
                            fs::write(settings.state.join("applied"), revision)?;
                            for entry in fs::read_dir(&settings.state)? {
                                let entry = entry?;
                                if entry.file_type()?.is_dir()
                                    && entry
                                        .file_name()
                                        .to_string_lossy()
                                        .starts_with("generation-")
                                    && entry.path() != generation
                                    && Some(entry.path()).as_ref() != previous.as_ref()
                                {
                                    fs::remove_dir_all(entry.path())?;
                                }
                            }
                            tracing::info!(%revision, "HAProxy configuration applied");
                            Ok(())
                        }
                        .await;
                        match result {
                            Ok(()) => applied = revision,
                            Err(error) => {
                                tracing::warn!(%error, "keeping last working HAProxy configuration")
                            }
                        }
                    }
                    Err(error) => tracing::warn!(%error, "waiting for HAProxy bundle"),
                    _ => {}
                }
                tokio::select! {
                    _ = terminate.recv() => break,
                    _ = interrupt.recv() => break,
                    _ = sleep(Duration::from_secs(2)) => {}
                }
            }
            if let Some(mut child) = child {
                if let Some(pid) = child.id() {
                    unsafe {
                        libc::kill(pid as libc::pid_t, libc::SIGUSR1);
                    }
                }
                if timeout(Duration::from_secs(25), child.wait())
                    .await
                    .is_err()
                {
                    child.kill().await?;
                }
            }
            Ok(())
        }
        "ready" => {
            let settings = Settings::load();
            let (desired, _) = bundle(&settings.bundle)?;
            let path = settings.state.join("applied");
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
            running(&settings.state).await
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
                    let services = controller.store();
                    let issuers = controller.store();
                    let solvers = controller.store();
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
                            client.all::<Service>().into_inner(),
                            watcher::Config::default(),
                            move |service: Service| {
                                services
                                    .state()
                                    .into_iter()
                                    .filter(|cr| {
                                        service
                                            .labels()
                                            .get("acme.cert-manager.io/http01-solver")
                                            .is_some_and(|value| value == "true")
                                            || cr.spec.routes.iter().flatten().any(|route| {
                                                route.service_name == service.name_any()
                                                    && route
                                                        .service_namespace
                                                        .clone()
                                                        .or_else(|| cr.namespace())
                                                        == service.namespace()
                                            })
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
                                let class = ingress
                                    .spec
                                    .as_ref()
                                    .and_then(|spec| spec.ingress_class_name.as_ref())
                                    .or_else(|| {
                                        ingress.annotations().get("kubernetes.io/ingress.class")
                                    });
                                solvers
                                    .state()
                                    .into_iter()
                                    .filter(|cr| {
                                        class == Some(&format!("haproxy-{}", cr.name_any()))
                                    })
                                    .map(|cr| ObjectRef::from_obj(&*cr))
                                    .collect::<Vec<_>>()
                            },
                        )
                        .watches(client.all::<Secret>().into_inner(), owned.clone(), managed)
                        .watches(
                            client.all::<Certificate>().into_inner(),
                            owned.clone(),
                            managed,
                        )
                        .watches(
                            client.all::<DaemonSet>().into_inner(),
                            owned.clone(),
                            managed,
                        )
                        .watches(client.all::<Namespace>().into_inner(), owned, managed)
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
