use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum OperatorError {
    #[error("{0}")]
    Config(String),
    #[error(transparent)]
    Kube(#[from] kube::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Envy(#[from] envy::Error),
    #[error(transparent)]
    Leader(#[from] kube_lease_manager::LeaseManagerError),
    #[error(transparent)]
    Metadata(#[from] ech_k8s::CrMetaError),
}

impl From<String> for OperatorError {
    fn from(value: String) -> Self {
        Self::Config(value)
    }
}

pub(crate) type Result<T> = std::result::Result<T, OperatorError>;
