use crate::{
    crds::{DomainClaim, IngressGroup},
    error::{OperatorError, Result},
    support::{
        components::{DnsComponent, ResourceId, UnsSignerComponent},
        domain::DomainName,
    },
};
use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    eips::eip2718::Encodable2718,
    primitives::{B256, Bytes, TxKind, U256, address, keccak256},
    signers::{SignerSync, local::PrivateKeySigner},
    sol,
    sol_types::SolCall,
};
use ech_k8s::{Component, CrMeta, K8sClient, NodeState, ResourcesExt};
use k8s_openapi::{ByteString, api::core::v1::Secret};
use kube::{
    ResourceExt,
    api::{ListParams, ObjectMeta, PostParams},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

sol! {
    function get(string key, uint256 tokenId) external view returns (string);
    function set(string key, string value, uint256 tokenId) external;
    function isApprovedOrOwner(address spender, uint256 tokenId) external view returns (bool);
}

const UNS_RPC: &str = "https://mainnet.base.org";
const UNS_CHAIN_ID: u64 = 8453;
const UNS_REGISTRY: alloy::primitives::Address =
    address!("f6c1b83977de3deffc476f5048a0a84d3375d498");

struct Rpc {
    client: reqwest::Client,
}

impl Rpc {
    async fn contract<C: SolCall>(&self, call: C, name: &str) -> Result<C::Return> {
        let data = format!("0x{}", hex::encode(call.abi_encode()));
        let result = self
            .call(
                "eth_call",
                json!([{"to": UNS_REGISTRY.to_string(), "data": data}, "latest"]),
            )
            .await?;
        let bytes: Bytes = result
            .as_str()
            .unwrap_or_default()
            .parse()
            .map_err(|_| OperatorError::Config(format!("invalid UNS {name} response")))?;
        C::abi_decode_returns(&bytes)
            .map_err(|_| OperatorError::Config(format!("invalid UNS {name} result")))
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let result: Value = self
            .client
            .post(UNS_RPC)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .map_err(|_| OperatorError::Config(format!("UNS {method}: request failed")))?
            .error_for_status()
            .map_err(|_| OperatorError::Config(format!("UNS {method}: HTTP failure")))?
            .json()
            .await
            .map_err(|_| OperatorError::Config(format!("UNS {method}: invalid response")))?;
        if result.get("error").is_some() || result.get("result").is_none() {
            return Err(OperatorError::Config(format!("UNS {method}: RPC failure")));
        }
        Ok(result["result"].clone())
    }
}

#[derive(Default, Deserialize, Serialize)]
struct Journal {
    transaction: Option<Transaction>,
}

#[derive(Deserialize, Serialize)]
struct Transaction {
    raw: String,
    hash: String,
    domain: String,
    registry: String,
    value: String,
}

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
    Uns(String),
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
            let (zone, provider) = if DomainName::is_uns(&domain) {
                if domain.contains('*') {
                    return Err(OperatorError::Config(
                        "UNS requires concrete domain names".into(),
                    ));
                }
                let key = data.get("uns-private-key").ok_or_else(|| {
                    OperatorError::Config(format!(
                        "Secret {}/{} has no uns-private-key",
                        credentials.namespace, credentials.name
                    ))
                })?;
                let key = std::str::from_utf8(&key.0)
                    .map_err(|_| OperatorError::Config("invalid UNS private key encoding".into()))?
                    .trim()
                    .to_string();
                key.parse::<PrivateKeySigner>()
                    .map_err(|_| OperatorError::Config("invalid UNS private key".into()))?;
                (
                    domain.rsplit('.').next().unwrap_or_default().into(),
                    DnsProvider::Uns(key),
                )
            } else {
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
                (DnsProvider::Uns(_), DnsProvider::Uns(_)) => true,
                _ => false,
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
                DnsProvider::Uns(private_key) => {
                    let outcome: NodeState = async {
                    let namespace = state.target.state_namespace.as_str();
                    let zone = state.target.zone.as_str();
                    let records = &state.records;
                    let previous = &state.previous;
                    let quantity = |value: &Value| -> Result<u128> {
                        value
                            .as_str()
                            .and_then(|value| value.strip_prefix("0x"))
                            .and_then(|value| u128::from_str_radix(value, 16).ok())
                            .ok_or_else(|| OperatorError::Config("invalid UNS RPC quantity".into()))
                    };
                    let signer: PrivateKeySigner = private_key.parse()
                        .map_err(|_| OperatorError::Config("invalid UNS private key".into()))?;
                    let rpc = Rpc {
                        client: reqwest::Client::builder()
                            .timeout(Duration::from_secs(15))
                            .build()
                            .map_err(|_| OperatorError::Config("cannot create UNS RPC client".into()))?,
                    };
                    if quantity(&rpc.call("eth_chainId", json!([])).await?)? != u128::from(UNS_CHAIN_ID) {
                        return Err(OperatorError::Config("UNS RPC chain ID mismatch".into()));
                    }
                    let secrets = client.namespaced::<Secret>(namespace);
                    let journal_name =
                        UnsSignerComponent.name(ResourceId::new(format!("{}:{}", UNS_CHAIN_ID, signer.address())).to_string());
                    let mut secret = match secrets.api().get_opt(&journal_name).await? {
                        Some(secret) => secret,
                        None => {
                            let desired = Secret {
                                metadata: ObjectMeta {
                                    name: Some(journal_name.clone()),
                                    namespace: Some(namespace.into()),
                                    labels: Some(UnsSignerComponent.labels(ResourceId::new(signer.address()).to_string())),
                                    ..Default::default()
                                },
                                ..Default::default()
                            };
                            match secrets.api().create(&PostParams::default(), &desired).await {
                                Ok(secret) => secret,
                                Err(kube::Error::Api(status)) if status.code == 409 => {
                                    return Ok(NodeState::Pending);
                                }
                                Err(error) => return Err(error.into()),
                            }
                        }
                    };
                    let mut journal: Journal = secret
                        .data
                        .as_ref()
                        .and_then(|data| data.get("state.json"))
                        .map(|data| serde_json::from_slice(&data.0))
                        .transpose()?
                        .unwrap_or_default();
                    if let Some(transaction) = &journal.transaction {
                        let receipt = rpc
                            .call("eth_getTransactionReceipt", json!([transaction.hash]))
                            .await?;
                        if receipt.is_null() {
                            if rpc
                                .call("eth_getTransactionByHash", json!([transaction.hash]))
                                .await?
                                .is_null()
                                && rpc
                                    .call("eth_sendRawTransaction", json!([transaction.raw]))
                                    .await
                                    .is_err()
                                && rpc
                                    .call("eth_getTransactionByHash", json!([transaction.hash]))
                                    .await?
                                    .is_null()
                            {
                                return Err(OperatorError::Config(format!(
                                    "UNS transaction {} is saved; submission will be retried",
                                    transaction.hash
                                )));
                            }
                            return Ok(NodeState::Pending);
                        }
                        let block = quantity(&receipt["blockNumber"])?;
                        let head = quantity(&rpc.call("eth_blockNumber", json!([])).await?)?;
                        if head.saturating_sub(block) + 1 < u128::from(2_u64) {
                            return Ok(NodeState::Pending);
                        }
                        let success = quantity(&receipt["status"])? == 1;
                        let tx_hash = transaction.hash.clone();
                        journal.transaction = None;
                        secret.data = Some(BTreeMap::from([(
                            "state.json".into(),
                            ByteString(serde_json::to_vec(&journal)?),
                        )]));
                        match secrets
                            .api()
                            .replace(&journal_name, &PostParams::default(), &secret)
                            .await
                        {
                            Ok(_) => (),
                            Err(kube::Error::Api(status)) if status.code == 409 => {
                                return Ok(NodeState::Pending);
                            }
                            Err(error) => return Err(error.into()),
                        }
                        if !success {
                            return Err(OperatorError::Config(format!("UNS transaction {tx_hash} reverted")));
                        }
                        return Ok(NodeState::Pending);
                    }
                    let names: BTreeSet<_> = records.keys().chain(previous.keys()).collect();
                    for name in names {
                        let domain = if name.is_empty() {
                            zone.to_string()
                        } else {
                            format!("{name}.{zone}")
                        };
                        let mut node = B256::ZERO;
                        for label in domain.rsplit('.') {
                            node =
                                keccak256([node.as_slice(), keccak256(label.as_bytes()).as_slice()].concat());
                        }
                        let token_id = U256::from_be_bytes(node.0);
                        let desired = records.record_values(Some(name), &["A"]);
                        let value = serde_json::to_string(&desired)?;
                        let current = rpc.contract(getCall {
                            key: "dns.A".into(),
                            tokenId: token_id,
                        }, "dns.A").await?;
                        let current_ips: Option<BTreeSet<String>> = if current.is_empty() {
                            Some(BTreeSet::new())
                        } else {
                            serde_json::from_str(&current).ok()
                        };
                        if current_ips.as_ref() == Some(&desired) {
                            continue;
                        }
                        if desired.is_empty() {
                            let owned = previous.record_values(Some(name), &["A"]);
                            if current_ips.as_ref() != Some(&owned) {
                                return Err(OperatorError::Config(format!(
                                    "UNS dns.A for {domain} changed outside this operator; refusing cleanup"
                                )));
                            }
                        }
                        if !rpc.contract(isApprovedOrOwnerCall {
                            spender: signer.address(),
                            tokenId: token_id,
                        }, "ownership").await?
                        {
                            return Err(OperatorError::Config(format!(
                                "UNS signer is not authorized for {domain}"
                            )));
                        }
                        let input = setCall {
                            key: "dns.A".into(),
                            value: value.clone(),
                            tokenId: token_id,
                        }
                        .abi_encode();
                        let nonce = u64::try_from(quantity(
                            &rpc.call(
                                "eth_getTransactionCount",
                                json!([signer.address().to_string(), "pending"]),
                            )
                            .await?,
                        )?)
                        .map_err(|_| OperatorError::Config("invalid UNS nonce".into()))?;
                        let block = rpc
                            .call("eth_getBlockByNumber", json!(["latest", false]))
                            .await?;
                        let priority = quantity(&rpc.call("eth_maxPriorityFeePerGas", json!([])).await?)?;
                        let fee = quantity(&block["baseFeePerGas"])?
                            .checked_mul(2)
                            .and_then(|fee| fee.checked_add(priority))
                            .ok_or_else(|| OperatorError::Config("UNS fee overflow".into()))?;
                        let gas = quantity(&rpc.call("eth_estimateGas", json!([{"from": signer.address().to_string(), "to": UNS_REGISTRY.to_string(), "data": format!("0x{}", hex::encode(&input))}])).await?)?;
                        let transaction = TxEip1559 {
                            chain_id: UNS_CHAIN_ID,
                            nonce,
                            gas_limit: u64::try_from(
                                gas.checked_mul(125)
                                    .ok_or_else(|| OperatorError::Config("UNS gas overflow".into()))?
                                    / 100,
                            )
                            .map_err(|_| OperatorError::Config("invalid UNS gas limit".into()))?,
                            max_fee_per_gas: fee,
                            max_priority_fee_per_gas: priority,
                            to: TxKind::Call(UNS_REGISTRY),
                            input: input.into(),
                            ..Default::default()
                        };
                        let signature = signer
                            .sign_hash_sync(&transaction.signature_hash())
                            .map_err(|_| OperatorError::Config("UNS transaction signing failed".into()))?;
                        let envelope: TxEnvelope = transaction.into_signed(signature).into();
                        let raw = envelope.encoded_2718();
                        journal.transaction = Some(Transaction {
                            raw: format!("0x{}", hex::encode(&raw)),
                            hash: keccak256(&raw).to_string(),
                            domain,
                            registry: UNS_REGISTRY.to_string(),
                            value,
                        });
                        secret.data = Some(BTreeMap::from([(
                            "state.json".into(),
                            ByteString(serde_json::to_vec(&journal)?),
                        )]));
                        match secrets
                            .api()
                            .replace(&journal_name, &PostParams::default(), &secret)
                            .await
                        {
                            Ok(_) => return Ok(NodeState::Pending),
                            Err(kube::Error::Api(status)) if status.code == 409 => {
                                return Ok(NodeState::Pending);
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    Ok(NodeState::Ready)
                }.await?;
                    (outcome, state.target.ttl as u64)
                }
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
