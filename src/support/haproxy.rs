use crate::error::OperatorError;

pub(crate) fn backend_url(value: &str) -> Result<http::Uri, OperatorError> {
    let url: http::Uri = value.parse().map_err(|_| invalid("invalid backend URL"))?;
    let authority = url
        .authority()
        .ok_or_else(|| invalid("backend URL has no host"))?;
    let host = authority.host();
    if host.is_empty()
        || !matches!(url.scheme_str(), Some("http" | "https"))
        || authority.as_str().contains('@')
        || url.query().is_some()
        || value.contains('#')
        || (authority.as_str().len() != host.len()
            && !authority.port_u16().is_some_and(|port| port > 0))
    {
        return Err(invalid(
            "backend URL requires http or https, a host and numeric port, and no credentials, query or fragment",
        ));
    }
    Ok(url)
}

pub(crate) fn invalid(message: impl Into<String>) -> OperatorError {
    OperatorError::Config(message.into())
}

pub(crate) fn dns_name(value: &str) -> bool {
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
