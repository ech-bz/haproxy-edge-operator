use crate::{
    crds::{DomainClaim, IngressGroup, IngressGroupHosts},
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

    pub(crate) fn is_uns(domain: &str) -> bool {
        domain.rsplit_once('.').is_some_and(|(_, tld)| {
            [
                "amped",
                "anyone",
                "ask",
                "ath",
                "bald",
                "basenji",
                "bay",
                "bch",
                "benji",
                "bitscrunch",
                "boomer",
                "bunni",
                "caw",
                "chip",
                "chomp",
                "depin",
                "digibyte",
                "enigma",
                "ethermail",
                "goblin",
                "gotchi",
                "her",
                "horizen",
                "learn",
                "lunar",
                "mooncat",
                "mumu",
                "mycircle",
                "npc",
                "ohm",
                "onchain",
                "pendle",
                "podcast",
                "pokt",
                "privacy",
                "propykeys",
                "quantum",
                "rad",
                "smobler",
                "south",
                "spend",
                "u",
                "udtest",
                "verge",
                "xec",
                "xyo",
                "zano",
            ]
            .contains(&tld)
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

impl IngressGroupHosts {
    pub(crate) fn ech_cover(&self) -> Result<Option<String>> {
        self.ech
            .as_deref()
            .map(DomainName::new)
            .transpose()
            .map(|cover| cover.map(|name| name.0))
    }
}

impl IngressGroup {
    pub(crate) fn ech_covers(&self) -> Result<std::collections::BTreeSet<String>> {
        self.spec
            .hosts
            .iter()
            .filter_map(|host| host.ech_cover().transpose())
            .collect()
    }

    pub(crate) fn ech_domains(&self) -> Result<std::collections::BTreeMap<String, String>> {
        let covers = self.ech_covers()?;
        let mut domains = std::collections::BTreeMap::new();
        for host in &self.spec.hosts {
            if let Some(cover) = host.ech_cover()? {
                for domain in &host.domains {
                    let domain = DomainName::new(domain)?.0;
                    if !DomainName::is_uns(&domain) && !covers.contains(&domain) {
                        domains.insert(domain, cover.clone());
                    }
                }
            }
        }
        Ok(domains)
    }
}
