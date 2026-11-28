use crate::{
    config::OperatorSettings,
    crds::IngressGroup,
    error::{OperatorError, Result},
    support::{
        certificates::Certificates,
        components::*,
        domain::DomainName,
        haproxy::{BackendUrl, HeaderPart, HeaderTemplate},
        resources::Http01Ingress,
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
        let mut ech_keys = None;
        let covers = group.ech_covers()?;
        let mut host_acls = String::new();
        let mut has_exact = false;
        let mut conditions = Vec::new();
        let mut routes = Vec::new();
        for (index, host) in group.spec.hosts.iter().enumerate() {
            let mut exact = Vec::new();
            let mut wildcard = Vec::new();
            for domain in &host.domains {
                let domain = DomainName::new(domain)?.0;
                if let Some(suffix) = domain.strip_prefix("*.") {
                    wildcard.push(quote(&format!("^[^.]+\\.{}\\.?$", regex::escape(suffix))));
                } else {
                    exact.push(quote(&domain));
                    exact.push(quote(&format!("{domain}.")));
                }
            }
            let mut alternatives = Vec::new();
            if !exact.is_empty() {
                has_exact = true;
                let names = exact.join(" ");
                writeln!(
                    host_acls,
                    "  acl host_{index}_exact req.hdr(host),field(1,:) -i -- {names}"
                )
                .unwrap();
                writeln!(
                    host_acls,
                    "  acl exact_host req.hdr(host),field(1,:) -i -- {names}"
                )
                .unwrap();
                alternatives.push(format!("host_{index}_exact"));
            }
            if !wildcard.is_empty() {
                writeln!(
                    host_acls,
                    "  acl host_{index}_wildcard req.hdr(host),field(1,:) -m reg -i -- {}",
                    wildcard.join(" ")
                )
                .unwrap();
                alternatives.push(format!("host_{index}_wildcard !exact_host"));
            }
            conditions.push(alternatives);
            let mut selected: Vec<_> = host.routes.iter().flatten().collect();
            selected.sort_by(|a, b| {
                b.path_prefix
                    .len()
                    .cmp(&a.path_prefix.len())
                    .then(a.path_prefix.cmp(&b.path_prefix))
            });
            routes.extend(selected.into_iter().map(|route| (index, route)));
        }
        if !has_exact && !host_acls.is_empty() {
            host_acls.push_str("  acl exact_host always_false\n");
        }
        let routing = |tls: bool| {
            let mut rules = host_acls.clone();
            for (index, (host, route)) in routes.iter().enumerate() {
                let backend = if tls || route.redirect.is_some() {
                    format!("route_{index}")
                } else {
                    "unmatched".into()
                };
                let condition = conditions[*host]
                    .iter()
                    .map(|condition| {
                        format!(
                            "{condition} {{ path_beg -- {} }}",
                            quote(&route.path_prefix)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" or ");
                writeln!(rules, "  use_backend {backend} if {condition}").unwrap();
            }
            rules.push_str("  default_backend unmatched\n");
            rules
        };
        let nodes = group.edge_nodes(client).await?;
        let mut solvers = client
            .all::<Ingress>()
            .api()
            .list(&ListParams::default().labels("acme.cert-manager.io/http01-solver=true"))
            .await?
            .items;
        let name = group.cr_name()?;
        solvers.retain(|ingress| {
            ingress.metadata.deletion_timestamp.is_none()
                && ingress.ingress_group() == Some(name.as_str())
                && ingress.namespace().is_some_and(|namespace| {
                    group.namespace().as_ref() == Some(&namespace)
                        || nodes.iter().any(|node| node.namespace == namespace)
                })
        });
        solvers.sort_by_key(|ingress| (ingress.namespace(), ingress.name_any()));
        for node in nodes {
            let mut data = BTreeMap::new();
            let mut list = String::new();
            let mut complete = true;
            for certificate in Certificates::new(client, group).files(&node)? {
                let Some(pem) = certificate.load(client).await? else {
                    complete = false;
                    break;
                };
                let file = certificate.file;
                data.insert(file.clone(), ByteString(pem));
                let domain = certificate.domain;
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
                    .get_opt(&BundleComponent.name(group.owner()?))
                    .await?
                    .and_then(|secret| secret.data)
                    .unwrap_or_default();
                data.retain(|name, _| name.ends_with(".pem") || name == "crt-list");
                list = data
                    .get("crt-list")
                    .map(|value| std::str::from_utf8(&value.0))
                    .transpose()
                    .map_err(|_| OperatorError::Config("invalid previous certificate list".into()))?
                    .unwrap_or_default()
                    .to_string();
            }
            if !DomainName::is_valid(&self.operator.cluster_domain) {
                return Err(OperatorError::Config("invalid cluster domain".into()));
            }
            let ip = match node.ip {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            };
            let experimental = if !covers.is_empty() {
                "  expose-experimental-directives\n"
            } else {
                ""
            };
            let mut config = format!(
                r"global
{experimental}  user root
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
                    if !host.is_empty() && !DomainName::is_valid(host) {
                        return Err(OperatorError::Config("invalid HTTP-01 solver host".into()));
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
                        if !DomainName::is_valid(&service.name) || service.name.contains('.') {
                            return Err(OperatorError::Config(
                                "invalid HTTP-01 solver service".into(),
                            ));
                        }
                        let Some(port) = service
                            .port
                            .as_ref()
                            .and_then(|port| port.number)
                            .filter(|port| (1..=65535).contains(port))
                        else {
                            return Err(OperatorError::Config(
                                "HTTP-01 solver requires a numeric service port".into(),
                            ));
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
            config.push_str(&routing(false));
            config.push_str(&backends);
            for (index, (_, route)) in routes.iter().enumerate() {
                if let Some(redirect) = &route.redirect {
                    BackendUrl::new(&redirect.url)?;
                    writeln!(
                        config,
                        "\nbackend route_{index}\n  http-request redirect prefix {} code {}",
                        literal(redirect.url.trim_end_matches('/')),
                        redirect.code.unwrap_or(308)
                    )
                    .unwrap();
                }
            }
            config.push_str("\nbackend unmatched\n  http-request deny deny_status 404\n");
            if !list.is_empty() {
                let ech = if !covers.is_empty() {
                    if ech_keys.is_none() {
                        let namespace = group.cr_ns()?;
                        let mut keys = BTreeMap::new();
                        for cover in &covers {
                            let component = EchComponent::new(cover);
                            let name = component.name(group.owner()?);
                            let secret = client
                                .namespaced::<Secret>(&namespace)
                                .api()
                                .get(&name)
                                .await?;
                            let key = secret
                                .data
                                .and_then(|mut data| data.remove("current.ech"))
                                .ok_or_else(|| {
                                    OperatorError::Config(format!(
                                        "Secret {namespace}/{name} has no current.ech key"
                                    ))
                                })?;
                            keys.insert(component.file(), key);
                        }
                        ech_keys = Some(keys);
                    }
                    data.extend(ech_keys.as_ref().unwrap().clone());
                    " ech @BUNDLE@"
                } else {
                    ""
                };
                writeln!(config,
                    "\nfrontend https\n  bind {ip}:443 ssl crt-list @BUNDLE@/crt-list alpn h2,http/1.1{ech}",
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
                config.push_str(&routing(true));
                for (index, (_, route)) in routes.iter().enumerate() {
                    let Some(url) = &route.url else {
                        continue;
                    };
                    let BackendUrl(url) = BackendUrl::new(url)?;
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
                                                        OperatorError::Config(format!("Secret {namespace}/{name} has no key {key}"))
                                                    })?;
                                                String::from_utf8(data.0.clone()).map_err(|_| {
                                                    OperatorError::Config(format!("Secret {namespace}/{name} key {key} is not UTF-8"))
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
                                                        OperatorError::Config(format!("ConfigMap {namespace}/{name} has no key {key}"))
                                                    })?
                                            };
                                            if text.chars().any(char::is_control) {
                                                return Err(OperatorError::Config(format!(
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
                            write!(config, " ssl verify required ca-file /etc/ssl/certs/ca-certificates.crt verifyhost {name} alpn h2,http/1.1 no-sni-auto").unwrap();
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
                    BundleComponent.name(group.owner()?),
                    &Secret {
                        metadata: group.metadata(&node.namespace, BundleComponent)?,
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
