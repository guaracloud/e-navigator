use e_navigator_signals::{
    CgroupResourceContext, ProcessResourceContext, ResourceContext, ResourceMetricAttribute,
    SignalEnvelope,
};

pub(super) fn resource_context(
    signal: &SignalEnvelope,
    process: Option<&ProcessResourceContext>,
    cgroup: Option<&CgroupResourceContext>,
) -> ResourceContext {
    let container = process
        .and_then(|process| process.container.clone())
        .or_else(|| cgroup.and_then(|cgroup| cgroup.container.clone()));
    let kubernetes = process
        .and_then(|process| process.kubernetes.clone())
        .or_else(|| cgroup.and_then(|cgroup| cgroup.kubernetes.clone()));
    ResourceContext {
        host_name: signal.host.clone(),
        container,
        kubernetes,
    }
}

pub(super) fn metric_attributes<'a, const N: usize>(
    attributes: [(&'a str, &'a str); N],
) -> Vec<ResourceMetricAttribute> {
    attributes
        .into_iter()
        .map(|(key, value)| ResourceMetricAttribute {
            key: key.to_string(),
            value: value.to_string(),
        })
        .collect()
}
