use crate::{
    crds::IngressGroup,
    support::{
        components::{GROUP, GROUP_NS},
        haproxy::{HeaderPart, HeaderTemplate},
    },
};
use kube::{
    ResourceExt,
    runtime::reflector::{ObjectRef, Store},
};
use std::collections::HashSet;

#[derive(Clone)]
pub(crate) struct WatchContext {
    pub(crate) groups: Store<IngressGroup>,
}

impl WatchContext {
    pub(crate) fn referenced<T: ResourceExt + k8s_openapi::Resource>(
        &self,
        resource: T,
    ) -> Vec<ObjectRef<IngressGroup>> {
        let namespace = resource.namespace();
        let name = resource.name_any();
        let mut roots: HashSet<_> = self
            .groups
            .state()
            .into_iter()
            .filter(|group| {
                group.namespace() == namespace
                    && group
                        .spec
                        .routes
                        .iter()
                        .flatten()
                        .flat_map(|route| route.headers.iter().flat_map(|headers| headers.values()))
                        .any(|value| {
                            HeaderTemplate::new(value).is_ok_and(|template| {
                                template.parts.iter().any(|part| {
                                matches!(part, HeaderPart::Source { kind, name: source_name, .. }
                                    if *kind == T::KIND && *source_name == name)
                            })
                            })
                        })
            })
            .map(|group| ObjectRef::from_obj(&*group))
            .collect();
        roots.extend(Self::managed(resource));
        roots.into_iter().collect()
    }

    pub(crate) fn managed<T: ResourceExt>(resource: T) -> Vec<ObjectRef<IngressGroup>> {
        match (
            resource.labels().get(GROUP),
            resource.labels().get(GROUP_NS),
        ) {
            (Some(name), Some(namespace)) => vec![ObjectRef::new(name).within(namespace)],
            _ => Vec::new(),
        }
    }
}
