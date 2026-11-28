use crate::{
    crds::{DomainClaim, IngressGroup},
    error::{OperatorError, Result},
    support::{components::DnsComponent, domain::DomainName},
};
use ech_k8s::{Component, CrMeta, K8sClient, NodeState, ResourcesExt};
use k8s_openapi::{ByteString, api::core::v1::Secret};
use kube::{ResourceExt, api::ListParams};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

#[derive(Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub(crate) struct Records(BTreeMap<String, Vec<Value>>);

impl std::ops::Deref for Records {
    type Target = BTreeMap<String, Vec<Value>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Records {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Records {
    pub(crate) fn record_values(&self, name: Option<&str>, kinds: &[&str]) -> BTreeSet<String> {
        self.0
            .iter()
            .filter(|(key, _)| name.is_none_or(|name| name == key.as_str()))
            .flat_map(|(_, entries)| entries)
            .filter(|record| {
                record["type"]
                    .as_str()
                    .is_some_and(|kind| kinds.contains(&kind))
            })
            .flat_map(|record| record["values"].as_array().into_iter().flatten())
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "backend", content = "config")]
pub(crate) enum DnsProvider {
    Octodns(Value),
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct DnsTarget {
    pub(crate) zone: String,
    pub(crate) domain: String,
    pub(crate) secret_name: String,
    pub(crate) secret_namespace: String,
    pub(crate) claim_uid: String,
    pub(crate) provider: DnsProvider,
    pub(crate) ttl: i64,
    pub(crate) state_namespace: String,
}

impl DnsTarget {
    pub(crate) fn record_name(&self) -> String {
        if self.domain == self.zone {
            String::new()
        } else {
            self.domain
                .strip_suffix(&format!(".{}", self.zone))
                .unwrap()
                .to_string()
        }
    }

    pub(crate) async fn new(
        client: &K8sClient,
        group: &IngressGroup,
        state_namespace: &str,
    ) -> Result<Vec<Self>> {
        let requested = group.domains()?;
        let mut targets = Vec::new();
        for claim in client
            .all::<DomainClaim>()
            .api()
            .list(&ListParams::default())
            .await?
            .items
        {
            if claim.metadata.deletion_timestamp.is_some() || !claim.held_by(group) {
                continue;
            }
            let domain = DomainName::new(&claim.spec.domain)?.0;
            if !requested.contains(&domain) {
                continue;
            }
            let credentials = &claim.spec.credentials_secret_ref;
            let secret = client
                .namespaced::<Secret>(&credentials.namespace)
                .api()
                .get(&credentials.name)
                .await?;
            let data = secret.data.unwrap_or_default();
            let (zone, provider) = {
                let provider: Value = serde_json::from_slice(
                    &data
                        .get("provider.json")
                        .ok_or_else(|| {
                            OperatorError::Config(format!(
                                "Secret {}/{} has no provider.json",
                                credentials.namespace, credentials.name
                            ))
                        })?
                        .0,
                )
                .map_err(|_| OperatorError::Config("invalid octoDNS provider.json".into()))?;
                if provider.get("class").and_then(Value::as_str).is_none() {
                    return Err(OperatorError::Config(
                        "octoDNS provider.json requires class".into(),
                    ));
                }
                let mut zones: BTreeMap<String, String> = serde_json::from_value(
                    Octodns(&provider)
                        .request(json!({"domains": [&domain]}))
                        .await?,
                )
                .map_err(|_| {
                    OperatorError::Config("invalid octoDNS zone discovery result".into())
                })?;
                let zone = zones.remove(&domain).ok_or_else(|| {
                    OperatorError::Config(
                        "DNS zone discovery did not cover the requested domain".into(),
                    )
                })?;
                if !DomainName::is_valid(&zone)
                    || (domain != zone && !domain.ends_with(&format!(".{zone}")))
                {
                    return Err(OperatorError::Config("invalid discovered DNS zone".into()));
                }
                (zone, DnsProvider::Octodns(provider))
            };
            targets.push(Self {
                zone,
                domain,
                secret_name: credentials.name.clone(),
                secret_namespace: credentials.namespace.clone(),
                claim_uid: claim
                    .uid()
                    .ok_or_else(|| OperatorError::Config("DomainClaim has no UID".into()))?,
                provider,
                ttl: claim.spec.ttl.unwrap_or(300),
                state_namespace: state_namespace.into(),
            });
        }
        targets.sort_by(|a, b| a.domain.cmp(&b.domain));
        Ok(targets)
    }

    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.claim_uid == other.claim_uid
            && self.secret_namespace == other.secret_namespace
            && self.zone == other.zone
            && self.secret_name == other.secret_name
            && match (&self.provider, &other.provider) {
                (DnsProvider::Octodns(a), DnsProvider::Octodns(b)) => a["class"] == b["class"],
            }
    }
}

#[derive(Deserialize, Serialize)]
pub(crate) struct DnsState {
    pub(crate) target: DnsTarget,
    pub(crate) records: Records,
    pub(crate) previous: Records,
    pub(crate) synced: bool,
    pub(crate) initialized: bool,
    pub(crate) draining: bool,
    pub(crate) drain_until: u64,
    pub(crate) cache_until: u64,
}

impl DnsState {
    pub(crate) fn update_records(&mut self, records: Records) -> bool {
        if self.records == records {
            return false;
        }
        self.records = records;
        self.synced = false;
        true
    }

    pub(crate) async fn load(client: &K8sClient, group: &IngressGroup) -> Result<Vec<Self>> {
        let Some(secret) = client
            .namespaced::<Secret>(&group.cr_ns()?)
            .api()
            .get_opt(&DnsComponent.name(group.owner()?))
            .await?
        else {
            return Ok(Vec::new());
        };
        let data = secret
            .data
            .as_ref()
            .and_then(|data| data.get("state.json"))
            .ok_or_else(|| OperatorError::Config("DNS state Secret has no state.json".into()))?;
        serde_json::from_slice(&data.0)
            .map_err(|_| OperatorError::Config("invalid DNS state".into()))
    }

    pub(crate) async fn store(
        states: &[Self],
        client: &K8sClient,
        group: &IngressGroup,
    ) -> Result<()> {
        let secrets = client.namespaced::<Secret>(&group.cr_ns()?);
        let name = DnsComponent.name(group.owner()?);
        let data = BTreeMap::from([("state.json".into(), ByteString(serde_json::to_vec(states)?))]);
        if secrets
            .api()
            .get_opt(&name)
            .await?
            .is_some_and(|secret| secret.data.as_ref() == Some(&data))
        {
            return Ok(());
        }
        secrets
            .apply(
                &name,
                &Secret {
                    metadata: group.metadata(&group.cr_ns()?, DnsComponent)?,
                    data: Some(data),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn sync(
        states: &mut [Self],
        client: &K8sClient,
        group: &IngressGroup,
    ) -> Result<NodeState> {
        Self::store(states, client, group).await?;
        let mut pending = false;
        for index in 0..states.len() {
            let state = &mut states[index];
            if state.records.is_empty()
                && state.previous.is_empty()
                && state.synced
                && !state.draining
            {
                continue;
            }
            let (outcome, effective_ttl) = match &state.target.provider {
                DnsProvider::Octodns(provider) => {
                    let ttl = Octodns(provider).request(json!({"zone": state.target.zone, "owner": state.target.claim_uid, "records": state.records, "previous": state.previous})).await?.as_u64().ok_or_else(|| OperatorError::Config("invalid octoDNS TTL response".into()))?;
                    (NodeState::Ready, ttl)
                }
            };
            if outcome == NodeState::Pending {
                pending = true;
                continue;
            }
            let state = &mut states[index];
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| OperatorError::Config("system clock is before UNIX epoch".into()))?
                .as_secs();
            if !state.synced {
                let previous_ttl = state
                    .previous
                    .values()
                    .flatten()
                    .filter_map(|record| record["ttl"].as_u64())
                    .max()
                    .unwrap_or(state.target.ttl as u64);
                state.cache_until = state.cache_until.max(now + previous_ttl.max(effective_ttl));
                if state.draining {
                    state.drain_until = state.cache_until;
                }
                state.previous = state.records.clone();
                state.synced = true;
                Self::store(states, client, group).await?;
            }
            pending |= states[index].draining && now < states[index].drain_until;
        }
        Ok(if pending {
            NodeState::Pending
        } else {
            NodeState::Ready
        })
    }
}

struct Octodns<'a>(&'a Value);

impl Octodns<'_> {
    async fn request(&self, mut request: Value) -> Result<Value> {
        request["provider"] = self.0.clone();
        let payload = serde_json::to_vec(&request)?;
        let mut child = Command::new(
            std::env::var_os("EDGE_OCTODNS_PYTHON")
                .unwrap_or_else(|| "/opt/octodns/bin/python3".into()),
        )
        .args(["-I", "-c", include_str!("../../octodns/sync.py")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
        let output = timeout(Duration::from_secs(120), async {
            child.stdin.take().unwrap().write_all(&payload).await?;
            child.wait_with_output().await
        })
        .await
        .map_err(|_| OperatorError::Config("octoDNS request timed out".into()))??;
        if !output.status.success() {
            return Err(OperatorError::Config(format!(
                "DNS request failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|_| OperatorError::Config("invalid octoDNS response".into()))
    }
}
