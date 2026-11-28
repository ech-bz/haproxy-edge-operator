use crate::{
    config::OperatorSettings,
    crds::IngressGroup,
    error::OperatorError,
    reconcilers::{
        address_dns::AddressDnsReconciler, applied_readiness::AppliedReadinessReconciler,
        bundle::BundleReconciler, dns::DnsReconciler,
        domain_certificate::DomainCertificateReconciler, domain_claims::DomainClaimsReconciler,
        domain_status::DomainStatusReconciler, ech::EchReconciler,
        ip_certificates::IpCertificatesReconciler, issuer::IssuerReconciler,
        namespaces::NamespacesReconciler, prune_dns::PruneDnsReconciler,
        prune_domain_certificates::PruneDomainCertificatesReconciler,
        prune_domain_claims::PruneDomainClaimsReconciler, prune_ech::PruneEchReconciler,
        prune_ip_certificates::PruneIpCertificatesReconciler,
        prune_namespaces::PruneNamespacesReconciler, readiness::ReadinessReconciler,
        validate::ValidateReconciler, workload::WorkloadReconciler,
    },
};
use ech_k8s::{Graph, GraphError, NodeKey, Workflow};

pub(crate) struct EdgeWorkflow {
    pub(crate) operator: OperatorSettings,
    pub(crate) state_namespace: String,
}

impl Workflow for EdgeWorkflow {
    type Crd = IngressGroup;
    type Error = OperatorError;

    fn build_graph(
        &self,
        group: &IngressGroup,
    ) -> Result<Graph<Self::Crd, Self::Error>, GraphError> {
        let mut graph = Graph::new();
        let prune_dns = PruneDnsReconciler {
            state_namespace: self.state_namespace.clone(),
        };
        let prune_claims = PruneDomainClaimsReconciler {
            state_namespace: self.state_namespace.clone(),
        };
        if group.metadata.deletion_timestamp.is_some() {
            graph.add(prune_claims.clone(), [])?;
            graph.add(PruneNamespacesReconciler, [prune_claims.into()])?;
            graph.add(
                PruneDomainCertificatesReconciler,
                [PruneNamespacesReconciler.into()],
            )?;
            graph.add(
                PruneEchReconciler,
                [PruneDomainCertificatesReconciler.into()],
            )?;
            graph.add(prune_dns, [PruneEchReconciler.into()])?;
            return Ok(graph);
        }
        graph.add(ValidateReconciler, [])?;
        let Ok(certificates_domains) = group.icann_domains() else {
            return Ok(graph);
        };
        graph.add(prune_dns.clone(), [ValidateReconciler.into()])?;
        graph.add(PruneEchReconciler, [prune_dns.into()])?;
        graph.add(
            PruneDomainCertificatesReconciler,
            [PruneEchReconciler.into()],
        )?;
        graph.add(
            prune_claims.clone(),
            [PruneDomainCertificatesReconciler.into()],
        )?;
        let claims = DomainClaimsReconciler {
            state_namespace: self.state_namespace.clone(),
        };
        graph.add(claims.clone(), [prune_claims.into()])?;
        graph.add(NamespacesReconciler, [claims.into()])?;
        graph.add(PruneNamespacesReconciler, [NamespacesReconciler.into()])?;
        graph.add(
            PruneIpCertificatesReconciler,
            [PruneNamespacesReconciler.into()],
        )?;
        graph.add(IssuerReconciler, [PruneIpCertificatesReconciler.into()])?;
        let mut certificates = vec![NodeKey::from(IpCertificatesReconciler)];
        for domain in certificates_domains {
            let certificate = DomainCertificateReconciler { domain };
            graph.add(certificate.clone(), [IssuerReconciler.into()])?;
            certificates.push(certificate.into());
        }
        graph.add(IpCertificatesReconciler, [IssuerReconciler.into()])?;
        let bundle = BundleReconciler {
            operator: self.operator.clone(),
        };
        let Ok(covers) = group.ech_covers() else {
            return Ok(graph);
        };
        for cover in covers {
            let ech = EchReconciler { cover };
            graph.add(ech.clone(), [IssuerReconciler.into()])?;
            certificates.push(ech.into());
        }
        graph.add(bundle.clone(), certificates)?;
        let workload = WorkloadReconciler {
            operator: self.operator.clone(),
        };
        graph.add(workload.clone(), [PruneIpCertificatesReconciler.into()])?;
        graph.add(
            ReadinessReconciler,
            [workload.clone().into(), bundle.into()],
        )?;
        let addresses = AddressDnsReconciler {
            state_namespace: self.state_namespace.clone(),
        };
        graph.add(addresses.clone(), [workload.into()])?;
        graph.add(AppliedReadinessReconciler, [ReadinessReconciler.into()])?;
        graph.add(
            DnsReconciler,
            [AppliedReadinessReconciler.into(), addresses.into()],
        )?;
        graph.add(DomainStatusReconciler, [DnsReconciler.into()])?;
        Ok(graph)
    }
}
