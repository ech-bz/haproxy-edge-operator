use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct OperatorSettings {
    pub(crate) health_port: u16,
    pub(crate) reconcile_interval_seconds: u64,
    pub(crate) error_backoff_seconds: u64,
    pub(crate) worker_image: String,
    pub(crate) cluster_domain: String,
}
