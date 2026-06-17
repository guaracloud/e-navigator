use crate::time::now_unix_nanos;
use e_navigator_signals::{
    ContainerContext, ExecEvent, KubernetesContext, ProcessExitEvent, SignalEnvelope,
};

pub(super) fn exec_signal(
    host: Option<String>,
    container: ContainerContext,
    kubernetes: KubernetesContext,
) -> SignalEnvelope {
    SignalEnvelope::exec(
        super::source_name(),
        host,
        ExecEvent {
            pid: std::process::id(),
            ppid: None,
            uid: None,
            command: "sh".to_string(),
            executable: Some("/bin/sh".to_string()),
            arguments: vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo synthetic".to_string(),
            ],
            cgroup_id: None,
            timestamp_unix_nanos: now_unix_nanos(),
            container: Some(container),
            kubernetes: Some(kubernetes),
        },
    )
}

pub(super) fn process_exit_signal(
    host: Option<String>,
    container: ContainerContext,
    kubernetes: KubernetesContext,
) -> SignalEnvelope {
    SignalEnvelope::process_exit(
        super::source_name(),
        host,
        ProcessExitEvent {
            pid: std::process::id(),
            ppid: None,
            uid: None,
            command: "sh".to_string(),
            cgroup_id: None,
            exit_code: Some(0),
            runtime_nanos: Some(1_000_000),
            timestamp_unix_nanos: now_unix_nanos(),
            container: Some(container),
            kubernetes: Some(kubernetes),
        },
    )
}
