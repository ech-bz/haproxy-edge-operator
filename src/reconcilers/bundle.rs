use crate::{
    config::OperatorSettings,
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        components::*,
        haproxy::{dns_name, invalid},
        resources::{edge_nodes, metadata, owner},
    },
};
use ech_k8s::{Component, CrMeta, K8sClient, NodeState, Reconciler, ResourcesExt};
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::{ByteString, api::core::v1::Secret};
use serde::Serialize;
use std::{collections::BTreeMap, fmt::Write};

#[derive(Clone, Serialize)]
pub(crate) struct BundleReconciler {
    pub(crate) operator: OperatorSettings,
}

#[async_trait::async_trait]
impl Reconciler for BundleReconciler {
    type Crd = IngressGroup;
    type Error = OperatorError;

    async fn reconcile(&self, client: &K8sClient, group: &IngressGroup) -> Result<NodeState> {
        let mut pending = false;
        let quote = |value: &str| {
            format!(
                "\"{}\"",
                value
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('$', "\\$")
            )
        };
        let literal = |value: &str| quote(&value.replace('%', "%%"));
        'nodes: for node in edge_nodes(client, group).await? {
            let mut certificates = vec![(
                node.namespace.clone(),
                IpCertificateComponent {
                    ip: ResourceId::new(node.ip.to_string()),
                }
                .name(owner(group)?),
                "default.pem".to_string(),
                None,
            )];
            for domain in group.spec.domains.iter().flatten() {
                certificates.push((
                    group.cr_ns()?,
                    DomainCertificateComponent {
                        domain: ResourceId::new(domain),
                    }
                    .name(owner(group)?),
                    format!("domain-{}.pem", hash(domain)),
                    Some(domain),
                ));
            }
            let mut data = BTreeMap::new();
            let mut list = String::new();
            for (namespace, name, file, domain) in certificates {
                let Some(secret) = client
                    .namespaced::<Secret>(&namespace)
                    .api()
                    .get_opt(&name)
                    .await?
                else {
                    pending = true;
                    continue 'nodes;
                };
                let Some(source) = secret.data else {
                    pending = true;
                    continue 'nodes;
                };
                let (Some(cert), Some(key)) = (source.get("tls.crt"), source.get("tls.key")) else {
                    pending = true;
                    continue 'nodes;
                };
                let cert = std::str::from_utf8(&cert.0).map_err(|_| {
                    OperatorError::Config(format!(
                        "{namespace}/{name}: invalid certificate encoding"
                    ))
                })?;
                let key = std::str::from_utf8(&key.0).map_err(|_| {
                    OperatorError::Config(format!("{namespace}/{name}: invalid key encoding"))
                })?;
                data.insert(
                    file.clone(),
                    ByteString(format!("{cert}\n{key}\n").into_bytes()),
                );
                if let Some(domain) = domain {
                    writeln!(list, "@BUNDLE@/{file} {domain}").unwrap();
                } else {
                    writeln!(list, "@BUNDLE@/{file}").unwrap();
                }
            }
            if !dns_name(&self.operator.cluster_domain) {
                return Err(invalid("invalid cluster domain"));
            }
            let ip = match node.ip {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            };
            let mut config = format!(
                r"global
  log stdout format raw local0
  maxconn 10000

defaults
  mode http
  log global
  timeout connect 5s
  timeout client 60s
  timeout server 60s
  timeout tunnel 1h

resolvers kubernetes
  parse-resolv-conf
  hold valid 10s

frontend http
  bind {ip}:80
  http-request deny deny_status 404

frontend https
  bind {ip}:443 ssl crt-list @BUNDLE@/crt-list alpn h2,http/1.1
"
            );
            let trusted = group
                .spec
                .forwarded_trusted_ips
                .as_deref()
                .unwrap_or_default();
            if !trusted.is_empty() {
                writeln!(config, "  acl trusted src {}", trusted.join(" ")).unwrap();
            }
            let condition = if trusted.is_empty() {
                ""
            } else {
                " unless trusted"
            };
            for name in [
                "X-Forwarded-For",
                "X-Forwarded-Host",
                "X-Forwarded-Port",
                "X-Forwarded-Proto",
                "X-Forwarded-Server",
                "X-Forwarded-Prefix",
                "X-Real-IP",
            ] {
                writeln!(config, "  http-request del-header {name}{condition}").unwrap();
            }
            for (name, value) in [
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Port", "443"),
                ("X-Forwarded-Host", "%[req.hdr(Host)]"),
                ("X-Real-IP", "%[src]"),
            ] {
                writeln!(
                    config,
                    "  http-request set-header {name} {value} unless {{ req.hdr({name}) -m found }}"
                )
                .unwrap();
            }
            config.push_str(r#"  http-request set-header X-Forwarded-For "%[req.hdr(X-Forwarded-For)], %[src]" if { req.hdr(X-Forwarded-For) -m found }
  http-request set-header X-Forwarded-For %[src] unless { req.hdr(X-Forwarded-For) -m found }
"#);
            let mut routes: Vec<_> = group.spec.routes.iter().flatten().collect();
            routes.sort_by(|a, b| {
                b.path_prefix
                    .len()
                    .cmp(&a.path_prefix.len())
                    .then(a.path_prefix.cmp(&b.path_prefix))
            });
            for (index, route) in routes.iter().enumerate() {
                writeln!(
                    config,
                    "  use_backend route_{index} if {{ path_beg -- {} }}",
                    quote(&route.path_prefix)
                )
                .unwrap();
            }
            config.push_str(
                    "  default_backend unmatched\n\nbackend unmatched\n  http-request deny deny_status 404\n",
                );
            for (index, route) in routes.iter().enumerate() {
                let namespace = route.service_namespace.clone().unwrap_or(group.cr_ns()?);
                let service = client
                    .namespaced::<Service>(&namespace)
                    .api()
                    .get(&route.service_name)
                    .await?;
                let port = service
                    .spec
                    .as_ref()
                    .and_then(|spec| spec.ports.as_ref())
                    .and_then(|ports| {
                        ports.iter().find(|port| {
                            port.port as i64 == route.service_port
                                && port.protocol.as_deref().unwrap_or("TCP") == "TCP"
                        })
                    })
                    .ok_or_else(|| {
                        invalid(format!(
                            "Service {namespace}/{} has no TCP port {}",
                            route.service_name, route.service_port
                        ))
                    })?;
                let scheme = route.service_scheme.as_deref().unwrap_or_else(|| {
                    if route.service_port == 443
                        || port
                            .name
                            .as_deref()
                            .is_some_and(|name| name.starts_with("https"))
                    {
                        "https"
                    } else {
                        "http"
                    }
                });
                writeln!(config, "\nbackend route_{index}").unwrap();
                if route.strip_prefix.unwrap_or(false) {
                    writeln!(
                        config,
                        "  http-request set-header X-Forwarded-Prefix {}",
                        literal(&route.path_prefix)
                    )
                    .unwrap();
                    writeln!(
                        config,
                        "  http-request replace-path {} /\\1",
                        quote(&format!("^{}/?(.*)$", regex::escape(&route.path_prefix)))
                    )
                    .unwrap();
                }
                for (name, value) in route.headers.iter().flatten() {
                    if value.is_empty() {
                        writeln!(config, "  http-request del-header {name}").unwrap();
                    } else {
                        writeln!(
                            config,
                            "  http-request set-header {name} {}",
                            literal(value)
                        )
                        .unwrap();
                    }
                }
                let host = format!(
                    "{}.{namespace}.svc.{}",
                    route.service_name, self.operator.cluster_domain
                );
                write!(
                    config,
                    "  server upstream {host}:{} resolvers kubernetes init-addr last,libc,none",
                    route.service_port
                )
                .unwrap();
                match scheme {
                        "https" => write!(config, " ssl verify required ca-file /etc/ssl/certs/ca-certificates.crt sni str({host}) verifyhost {host} alpn h2,http/1.1").unwrap(),
                        "h2c" => config.push_str(" proto h2"),
                        _ => {}
                    }
                config.push('\n');
            }
            data.insert("haproxy.cfg".into(), ByteString(config.into_bytes()));
            data.insert("crt-list".into(), ByteString(list.into_bytes()));
            client
                .namespaced::<Secret>(&node.namespace)
                .apply(
                    BundleComponent.name(owner(group)?),
                    &Secret {
                        metadata: metadata(group, &node.namespace, BundleComponent)?,
                        data: Some(data),
                        type_: Some("Opaque".into()),
                        ..Default::default()
                    },
                )
                .await?;
        }
        Ok(if pending {
            NodeState::Pending
        } else {
            NodeState::Ready
        })
    }
}
