use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Source};
use e_navigator_signals::SignalEnvelope;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::{
    config::HostResourceConfig, model::HostResourceSnapshot, snapshot::sample_host_resources,
};

const HOST_RESOURCE_WARNING_LOG_LIMIT: usize = 8;

#[derive(Debug, Clone)]
pub struct HostResourceSource {
    config: HostResourceConfig,
    host: Option<String>,
}

impl HostResourceSource {
    pub fn new(config: HostResourceConfig) -> Self {
        Self { config, host: None }
    }

    pub fn with_host(config: HostResourceConfig, host: Option<String>) -> Self {
        Self { config, host }
    }

    pub fn config(&self) -> &HostResourceConfig {
        &self.config
    }

    pub fn sample_once(&self) -> HostResourceSnapshot {
        sample_host_resources(&self.config, self.host.clone())
    }
}

#[async_trait]
impl Source<SignalEnvelope> for HostResourceSource {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("source.host_resource", ModuleKind::Source)
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
        let source = *self;
        loop {
            let config = source.config.clone();
            let host = source.host.clone();
            let snapshot =
                tokio::task::spawn_blocking(move || sample_host_resources(&config, host))
                    .await
                    .map_err(|err| CoreError::ModuleFailed {
                        module: "source.host_resource".to_string(),
                        message: err.to_string(),
                    })?;

            log_snapshot_warnings(&snapshot.warnings);

            for signal in snapshot.signals {
                tx.send(signal)
                    .await
                    .map_err(|_| CoreError::PipelineClosed)?;
            }

            if source.config.sample_interval_millis == 0 {
                return Ok(());
            }

            tokio::time::sleep(Duration::from_millis(source.config.sample_interval_millis)).await;
        }
    }
}

fn log_snapshot_warnings(warnings: &[String]) {
    let Some(plan) = snapshot_warning_log_plan(warnings) else {
        return;
    };

    warn!(
        warning_count = plan.warning_count,
        "host resource observation warnings occurred"
    );

    for warning in plan.details {
        debug!(warning, "host resource observation warning");
    }

    if plan.omitted > 0 {
        debug!(
            omitted = plan.omitted,
            "host resource observation warnings omitted"
        );
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SnapshotWarningLogPlan<'a> {
    warning_count: usize,
    details: Vec<&'a str>,
    omitted: usize,
}

fn snapshot_warning_log_plan(warnings: &[String]) -> Option<SnapshotWarningLogPlan<'_>> {
    if warnings.is_empty() {
        return None;
    }

    Some(SnapshotWarningLogPlan {
        warning_count: warnings.len(),
        details: warnings
            .iter()
            .take(HOST_RESOURCE_WARNING_LOG_LIMIT)
            .map(String::as_str)
            .collect(),
        omitted: warnings
            .len()
            .saturating_sub(HOST_RESOURCE_WARNING_LOG_LIMIT),
    })
}

#[cfg(test)]
mod tests {
    use e_navigator_core::Source;
    use e_navigator_signals::SignalPayload;

    use super::{HOST_RESOURCE_WARNING_LOG_LIMIT, HostResourceSource, snapshot_warning_log_plan};
    use crate::HostResourceConfig;

    #[test]
    fn host_resource_source_exposes_config_and_metadata() {
        let source = HostResourceSource::new(HostResourceConfig {
            max_processes: 2,
            ..HostResourceConfig::default()
        });

        assert_eq!(source.metadata().name, "source.host_resource");
        assert_eq!(source.config().max_processes, 2);
    }

    #[test]
    fn warning_aggregation_preserves_one_aggregate_and_bounded_details() {
        let warnings = (0..10)
            .map(|index| format!("warning {index}"))
            .collect::<Vec<_>>();

        let plan = snapshot_warning_log_plan(&warnings).expect("warnings logged");

        assert_eq!(plan.warning_count, 10);
        assert_eq!(plan.details.len(), HOST_RESOURCE_WARNING_LOG_LIMIT);
        assert_eq!(plan.omitted, 2);
    }

    #[tokio::test]
    async fn host_resource_source_exits_after_one_pass_when_interval_is_zero() {
        let root = temp_path("one-shot");
        let _ = std::fs::remove_dir_all(&root);
        let proc_root = root.join("proc");
        let cgroup_root = root.join("cgroup");
        std::fs::create_dir_all(&proc_root).expect("proc");
        std::fs::create_dir_all(&cgroup_root).expect("cgroup");
        std::fs::write(
            proc_root.join("stat"),
            "cpu  100 0 50 500 10 0 0 2 0 0\nprocs_running 3\nprocs_blocked 1\n",
        )
        .expect("stat");
        std::fs::write(proc_root.join("loadavg"), "0.25 0.50 0.75 2/200 12345\n").expect("loadavg");
        std::fs::write(proc_root.join("meminfo"), "MemTotal: 8192 kB\n").expect("meminfo");
        std::fs::write(proc_root.join("diskstats"), "").expect("diskstats");

        let source = HostResourceSource::new(HostResourceConfig {
            procfs_root: proc_root,
            cgroup_root,
            sample_interval_millis: 0,
            max_processes: 0,
            max_cgroups: 0,
            ..HostResourceConfig::default()
        });
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);

        Box::new(source).run(tx).await.expect("source exits");

        let mut signals = Vec::new();
        while let Ok(signal) = rx.try_recv() {
            signals.push(signal);
        }
        assert_eq!(signals.len(), 3);
        assert!(matches!(
            signals[0].payload,
            SignalPayload::NodeCpuObservation(_)
        ));

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "e-navigator-host-source-{label}-{}",
            std::process::id()
        ))
    }
}
