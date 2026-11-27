use crate::error::OperatorError;

pub(crate) enum HeaderPart<'a> {
    Literal(&'a str),
    RemoteHost,
    Source {
        kind: &'static str,
        name: &'a str,
        key: &'a str,
    },
}

pub(crate) struct HeaderTemplate<'a> {
    pub(crate) parts: Vec<HeaderPart<'a>>,
}

impl<'a> HeaderTemplate<'a> {
    pub(crate) fn new(value: &'a str) -> Result<Self, OperatorError> {
        if value.chars().any(char::is_control) {
            return Err(invalid("control character in header template"));
        }
        let mut parts = Vec::new();
        let mut rest = value;
        while !rest.is_empty() {
            if let Some(tail) = rest.strip_prefix("{{") {
                parts.push(HeaderPart::Literal("{"));
                rest = tail;
            } else if let Some(tail) = rest.strip_prefix("}}") {
                parts.push(HeaderPart::Literal("}"));
                rest = tail;
            } else if let Some(tail) = rest.strip_prefix('{') {
                let (variable, tail) = tail
                    .split_once('}')
                    .ok_or_else(|| invalid("unclosed header variable"))?;
                if variable == "remote_host" {
                    parts.push(HeaderPart::RemoteHost);
                } else {
                    let (kind, source) = if let Some(source) = variable.strip_prefix("secret[") {
                        ("Secret", source)
                    } else if let Some(source) = variable.strip_prefix("cm[") {
                        ("ConfigMap", source)
                    } else {
                        return Err(invalid(format!("unknown header variable {variable}")));
                    };
                    let (name, key) = source
                        .strip_suffix(']')
                        .and_then(|source| source.split_once("]["))
                        .ok_or_else(|| invalid("header source requires [name][key]"))?;
                    if name.is_empty()
                        || key.is_empty()
                        || name.contains(['[', ']', '{', '}'])
                        || key.contains(['[', ']', '{', '}'])
                    {
                        return Err(invalid("header source requires [name][key]"));
                    }
                    parts.push(HeaderPart::Source { kind, name, key });
                }
                rest = tail;
            } else if rest.starts_with('}') {
                return Err(invalid("unmatched closing brace in header template"));
            } else {
                let end = rest.find(['{', '}']).unwrap_or(rest.len());
                parts.push(HeaderPart::Literal(&rest[..end]));
                rest = &rest[end..];
            }
        }
        Ok(Self { parts })
    }
}

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
