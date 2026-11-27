use crate::{
    config::OperatorSettings,
    crds::IngressGroup,
    error::OperatorError,
    reconcilers::{
        bundle::BundleReconciler, domain_certificate::DomainCertificateReconciler,
        ip_certificates::IpCertificatesReconciler, issuer::IssuerReconciler,
        namespaces::NamespacesReconciler,
        prune_domain_certificates::PruneDomainCertificatesReconciler,
        prune_ip_certificates::PruneIpCertificatesReconciler,
        prune_namespaces::PruneNamespacesReconciler, readiness::ReadinessReconciler,
        validate::ValidateReconciler, workload::WorkloadReconciler,
    },
};
use ech_k8s::{Graph, GraphError, NodeKey, Workflow};

pub(crate) struct EdgeWorkflow {
    pub(crate) operator: OperatorSettings,
}

impl Workflow for EdgeWorkflow {
    type Crd = IngressGroup;
    type Error = OperatorError;

    fn build_graph(
        &self,
        group: &IngressGroup,
    ) -> Result<Graph<Self::Crd, Self::Error>, GraphError> {
        let mut graph = Graph::new();
        graph.add(PruneNamespacesReconciler, [])?;
        graph.add(
            PruneDomainCertificatesReconciler,
            [PruneNamespacesReconciler.into()],
        )?;
        graph.add(
            PruneIpCertificatesReconciler,
            [PruneDomainCertificatesReconciler.into()],
        )?;
        graph.add(ValidateReconciler, [PruneIpCertificatesReconciler.into()])?;
        graph.add(NamespacesReconciler, [ValidateReconciler.into()])?;
        graph.add(IssuerReconciler, [ValidateReconciler.into()])?;

        let mut certificates = vec![NodeKey::from(IpCertificatesReconciler)];
        for domain in group
            .spec
            .domains
            .iter()
            .flatten()
            .collect::<std::collections::BTreeSet<_>>()
        {
            let certificate = DomainCertificateReconciler {
                domain: domain.clone(),
            };
            graph.add(certificate.clone(), [IssuerReconciler.into()])?;
            certificates.push(certificate.into());
        }
        graph.add(
            IpCertificatesReconciler,
            [IssuerReconciler.into(), NamespacesReconciler.into()],
        )?;
        let bundle = BundleReconciler {
            operator: self.operator.clone(),
        };
        graph.add(bundle.clone(), certificates)?;
        let workload = WorkloadReconciler {
            operator: self.operator.clone(),
        };
        graph.add(workload.clone(), [NamespacesReconciler.into()])?;
        graph.add(ReadinessReconciler, [workload.into(), bundle.into()])?;
        Ok(graph)
    }
}
