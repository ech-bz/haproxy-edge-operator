use crate::{
    config::OperatorSettings,
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        components::*,
        haproxy::{HeaderPart, HeaderTemplate, backend_url, dns_name, invalid},
        resources::{edge_nodes, metadata, owner},
    },
};
use ech_k8s::{Component, CrMeta, K8sClient, NodeState, Reconciler, ResourcesExt};
use k8s_openapi::api::{core::v1::ConfigMap, networking::v1::Ingress};
use k8s_openapi::{ByteString, api::core::v1::Secret};
use kube::{ResourceExt, api::ListParams};
use serde::Serialize;
use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt::Write,
};

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
        let mut sources = BTreeMap::new();
        let nodes = edge_nodes(client, group).await?;
        let mut solvers = client
            .all::<Ingress>()
            .api()
            .list(&ListParams::default().labels("acme.cert-manager.io/http01-solver=true"))
            .await?
            .items;
        let class = format!("haproxy-{}", group.cr_name()?);
        solvers.retain(|ingress| {
            ingress.metadata.deletion_timestamp.is_none()
                && ingress
                    .spec
                    .as_ref()
                    .and_then(|spec| spec.ingress_class_name.as_ref())
                    .or_else(|| ingress.annotations().get("kubernetes.io/ingress.class"))
                    == Some(&class)
                && ingress.namespace().is_some_and(|namespace| {
                    group.namespace().as_ref() == Some(&namespace)
                        || nodes.iter().any(|node| node.namespace == namespace)
                })
        });
        solvers.sort_by_key(|ingress| (ingress.namespace(), ingress.name_any()));
        for node in nodes {
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
            let mut complete = true;
            for (namespace, name, file, domain) in certificates {
                let Some(secret) = client
                    .namespaced::<Secret>(&namespace)
                    .api()
                    .get_opt(&name)
                    .await?
                else {
                    complete = false;
                    break;
                };
                let Some(source) = secret.data else {
                    complete = false;
                    break;
                };
                let (Some(cert), Some(key)) = (source.get("tls.crt"), source.get("tls.key")) else {
                    complete = false;
                    break;
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
            if !complete {
                pending = true;
                data = client
                    .namespaced::<Secret>(&node.namespace)
                    .api()
                    .get_opt(&BundleComponent.name(owner(group)?))
                    .await?
                    .and_then(|secret| secret.data)
                    .unwrap_or_default();
                data.retain(|name, _| name.ends_with(".pem") || name == "crt-list");
                list = data
                    .get("crt-list")
                    .map(|value| std::str::from_utf8(&value.0))
                    .transpose()
                    .map_err(|_| invalid("invalid previous certificate list"))?
                    .unwrap_or_default()
                    .to_string();
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
"
            );
            let mut backends = String::new();
            let mut index = 0;
            for ingress in &solvers {
                for rule in ingress
                    .spec
                    .iter()
                    .flat_map(|spec| spec.rules.iter().flatten())
                {
                    let host = rule.host.as_deref().unwrap_or_default();
                    if !host.is_empty() && !dns_name(host) {
                        return Err(invalid("invalid HTTP-01 solver host"));
                    }
                    for path in rule.http.iter().flat_map(|http| &http.paths) {
                        let Some(token) = path
                            .path
                            .as_deref()
                            .and_then(|path| path.strip_prefix("/.well-known/acme-challenge/"))
                            .filter(|token| {
                                !token.is_empty()
                                    && token.bytes().all(|byte| {
                                        byte.is_ascii_alphanumeric() || b"-_".contains(&byte)
                                    })
                            })
                        else {
                            continue;
                        };
                        let Some(service) = &path.backend.service else {
                            continue;
                        };
                        if !dns_name(&service.name) || service.name.contains('.') {
                            return Err(invalid("invalid HTTP-01 solver service"));
                        }
                        let Some(port) = service
                            .port
                            .as_ref()
                            .and_then(|port| port.number)
                            .filter(|port| (1..=65535).contains(port))
                        else {
                            return Err(invalid("HTTP-01 solver requires a numeric service port"));
                        };
                        write!(
                            config,
                            "  use_backend acme_{index} if {{ path -m str -- {} }}",
                            quote(&format!("/.well-known/acme-challenge/{token}")),
                        )
                        .unwrap();
                        if !host.is_empty() {
                            write!(config, " {{ req.hdr(host),field(1,:) -i {} }}", quote(host))
                                .unwrap();
                        }
                        config.push('\n');
                        writeln!(backends,
                            "\nbackend acme_{index}\n  server solver {}.{}.svc.{}:{port} resolvers kubernetes init-addr last,libc,none",
                            service.name, ingress.namespace().unwrap(), self.operator.cluster_domain,
                        ).unwrap();
                        index += 1;
                    }
                }
            }
            config.push_str("  default_backend unmatched\n");
            config.push_str(&backends);
            config.push_str("\nbackend unmatched\n  http-request deny deny_status 404\n");
            if !list.is_empty() {
                writeln!(config,
                    "\nfrontend https\n  bind {ip}:443 ssl crt-list @BUNDLE@/crt-list alpn h2,http/1.1",
                ).unwrap();
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
                config.push_str("  default_backend unmatched\n");
                for (index, route) in routes.iter().enumerate() {
                    let url = backend_url(&route.url)?;
                    let scheme = url.scheme_str().unwrap();
                    let host = url.host().unwrap();
                    let port = url
                        .port_u16()
                        .unwrap_or(if scheme == "https" { 443 } else { 80 });
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
                    writeln!(
                        config,
                        "  http-request set-header Host {}",
                        literal(url.authority().unwrap().as_str())
                    )
                    .unwrap();
                    let path = url.path().trim_end_matches('/');
                    if !path.is_empty() {
                        writeln!(
                            config,
                            "  http-request set-path {}",
                            quote(&format!("{}%[path]", path.replace('%', "%%")))
                        )
                        .unwrap();
                    }
                    for (name, template) in route.headers.iter().flatten() {
                        let mut value = String::new();
                        for part in HeaderTemplate::new(template)?.parts {
                            match part {
                                HeaderPart::Literal(text) => {
                                    value.push_str(&text.replace('%', "%%"))
                                }
                                HeaderPart::RemoteHost => value.push_str("%[src]"),
                                HeaderPart::Source { kind, name, key } => {
                                    let source = match sources.entry((kind, name, key)) {
                                        Entry::Occupied(entry) => entry.into_mut(),
                                        Entry::Vacant(entry) => {
                                            let namespace = group.cr_ns()?;
                                            let text = if kind == "Secret" {
                                                let secret = client
                                                    .namespaced::<Secret>(&namespace)
                                                    .api()
                                                    .get(name)
                                                    .await?;
                                                let data = secret
                                                    .data
                                                    .as_ref()
                                                    .and_then(|data| data.get(key))
                                                    .ok_or_else(|| {
                                                        invalid(format!("Secret {namespace}/{name} has no key {key}"))
                                                    })?;
                                                String::from_utf8(data.0.clone()).map_err(|_| {
                                                    invalid(format!("Secret {namespace}/{name} key {key} is not UTF-8"))
                                                })?
                                            } else {
                                                let config_map = client
                                                    .namespaced::<ConfigMap>(&namespace)
                                                    .api()
                                                    .get(name)
                                                    .await?;
                                                config_map
                                                    .data
                                                    .and_then(|mut data| data.remove(key))
                                                    .ok_or_else(|| {
                                                        invalid(format!("ConfigMap {namespace}/{name} has no key {key}"))
                                                    })?
                                            };
                                            if text.chars().any(char::is_control) {
                                                return Err(invalid(format!(
                                                    "control character in {kind} {namespace}/{name} key {key}"
                                                )));
                                            }
                                            entry.insert(text)
                                        }
                                    };
                                    value.push_str(&source.replace('%', "%%"));
                                }
                            }
                        }
                        if value.is_empty() {
                            writeln!(config, "  http-request del-header {name}").unwrap();
                        } else {
                            writeln!(config, "  http-request set-header {name} {}", quote(&value))
                                .unwrap();
                        }
                    }
                    write!(config, "  server upstream {host}:{port}").unwrap();
                    let name = host.trim_matches(['[', ']']);
                    let ip = name.parse::<std::net::IpAddr>().is_ok();
                    if !ip {
                        config.push_str(" resolvers kubernetes init-addr last,libc,none");
                    }
                    match scheme {
                        "https" => {
                            write!(config, " ssl verify required ca-file /etc/ssl/certs/ca-certificates.crt verifyhost {name} alpn h2,http/1.1").unwrap();
                            if !ip {
                                write!(config, " sni str({host})").unwrap();
                            }
                        }
                        "h2c" => config.push_str(" proto h2"),
                        _ => {}
                    }
                    config.push('\n');
                }
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
