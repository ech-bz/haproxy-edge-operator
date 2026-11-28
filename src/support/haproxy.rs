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
            return Err(OperatorError::Config(
                "control character in header template".into(),
            ));
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
                    .ok_or_else(|| OperatorError::Config("unclosed header variable".into()))?;
                if variable == "remote_host" {
                    parts.push(HeaderPart::RemoteHost);
                } else {
                    let (kind, source) = if let Some(source) = variable.strip_prefix("secret[") {
                        ("Secret", source)
                    } else if let Some(source) = variable.strip_prefix("cm[") {
                        ("ConfigMap", source)
                    } else {
                        return Err(OperatorError::Config(format!(
                            "unknown header variable {variable}"
                        )));
                    };
                    let (name, key) = source
                        .strip_suffix(']')
                        .and_then(|source| source.split_once("]["))
                        .ok_or_else(|| {
                            OperatorError::Config("header source requires [name][key]".into())
                        })?;
                    if name.is_empty()
                        || key.is_empty()
                        || name.contains(['[', ']', '{', '}'])
                        || key.contains(['[', ']', '{', '}'])
                    {
                        return Err(OperatorError::Config(
                            "header source requires [name][key]".into(),
                        ));
                    }
                    parts.push(HeaderPart::Source { kind, name, key });
                }
                rest = tail;
            } else if rest.starts_with('}') {
                return Err(OperatorError::Config(
                    "unmatched closing brace in header template".into(),
                ));
            } else {
                let end = rest.find(['{', '}']).unwrap_or(rest.len());
                parts.push(HeaderPart::Literal(&rest[..end]));
                rest = &rest[end..];
            }
        }
        Ok(Self { parts })
    }
}

pub(crate) struct BackendUrl(pub(crate) http::Uri);

impl BackendUrl {
    pub(crate) fn new(value: &str) -> Result<Self, OperatorError> {
        let url: http::Uri = value
            .parse()
            .map_err(|_| OperatorError::Config("invalid backend URL".into()))?;
        let authority = url
            .authority()
            .ok_or_else(|| OperatorError::Config("backend URL has no host".into()))?;
        let host = authority.host();
        if host.is_empty()
            || !matches!(url.scheme_str(), Some("http" | "https" | "h2c"))
            || authority.as_str().contains('@')
            || url.query().is_some()
            || value.contains('#')
            || (authority.as_str().len() != host.len()
                && !authority.port_u16().is_some_and(|port| port > 0))
        {
            return Err(OperatorError::Config("backend URL requires http, https or h2c, a host and numeric port, and no credentials, query or fragment".into()));
        }
        Ok(Self(url))
    }
}

pub(crate) struct EchConfig(pub(crate) String);

impl EchConfig {
    pub(crate) fn new(pem: &[u8]) -> Result<Self, OperatorError> {
        let text = std::str::from_utf8(pem)
            .map_err(|_| OperatorError::Config("invalid ECH PEM".into()))?;
        let config = text
            .split_once("-----BEGIN ECHCONFIG-----")
            .and_then(|(_, value)| value.split_once("-----END ECHCONFIG-----"))
            .ok_or_else(|| OperatorError::Config("missing ECHCONFIG block".into()))?
            .0
            .split_whitespace()
            .collect::<String>();
        if config.is_empty() {
            return Err(OperatorError::Config("empty ECHCONFIG block".into()));
        }
        Ok(Self(config))
    }
}
