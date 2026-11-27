use crate::{
    crds::IngressGroup,
    support::components::{GROUP, GROUP_NS},
};
use kube::{ResourceExt, runtime::reflector::ObjectRef};

pub(crate) fn managed<T: ResourceExt>(resource: T) -> Vec<ObjectRef<IngressGroup>> {
    match (
        resource.labels().get(GROUP),
        resource.labels().get(GROUP_NS),
    ) {
        (Some(name), Some(namespace)) => vec![ObjectRef::new(name).within(namespace)],
        _ => Vec::new(),
    }
}
