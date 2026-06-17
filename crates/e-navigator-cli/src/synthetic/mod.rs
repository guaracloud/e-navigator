mod dns;
mod exec;
mod network;
mod profiling;
mod request;
mod resource;
mod source;
mod trace;

pub(crate) use source::SyntheticExecSource;

use e_navigator_signals::{ContainerContext, KubernetesContext, NetworkProcessIdentity};
use std::collections::BTreeMap;

const SOURCE_NAME: &str = "source.synthetic_exec";

fn source_name() -> &'static str {
    SOURCE_NAME
}

fn process_identity() -> NetworkProcessIdentity {
    NetworkProcessIdentity {
        pid: std::process::id(),
        ppid: None,
        uid: None,
        command: "synthetic-api".to_string(),
        executable: Some("/app/synthetic-api".to_string()),
        cgroup_id: None,
    }
}

fn synthetic_attribution() -> (ContainerContext, KubernetesContext) {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/name".to_string(),
        "e-navigator-smoke".to_string(),
    );

    (
        ContainerContext {
            container_id: "synthetic-container".to_string(),
            runtime: Some("synthetic".to_string()),
        },
        KubernetesContext {
            namespace: "e-navigator-system".to_string(),
            pod_name: "e-navigator-synthetic".to_string(),
            pod_uid: Some("synthetic-pod-uid".to_string()),
            container_name: Some("e-navigator".to_string()),
            node_name: crate::registry::node_name().or_else(|| Some("synthetic-node".to_string())),
            labels,
        },
    )
}
