use crate::{
    crds::{DomainClaim, IngressGroup},
    error::{OperatorError, Result},
};

pub(crate) struct DomainName(pub(crate) String);

impl DomainName {
    pub(crate) fn is_valid(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 253
            && value.split('.').all(|part| {
                !part.is_empty()
                    && part.len() <= 63
                    && !part.starts_with('-')
                    && !part.ends_with('-')
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
    }

    pub(crate) fn new(value: &str) -> Result<Self> {
        let (prefix, value) = value
            .strip_prefix("*.")
            .map_or(("", value), |value| ("*.", value));
        let value = idna::domain_to_ascii_cow(value.as_bytes(), idna::AsciiDenyList::URL)
            .map_err(|_| OperatorError::Config("invalid internationalized domain name".into()))?;
        let value = value.strip_suffix('.').unwrap_or(&value);
        if !Self::is_valid(value) {
            return Err(OperatorError::Config("invalid domain name".into()));
        }
        Ok(Self(format!("{prefix}{value}")))
    }
}

impl DomainClaim {
    pub(crate) fn held_by(&self, group: &IngressGroup) -> bool {
        self.status
            .as_ref()
            .and_then(|status| status.holder.as_ref())
            .is_some_and(|holder| Some(&holder.uid) == group.metadata.uid.as_ref())
    }
}
