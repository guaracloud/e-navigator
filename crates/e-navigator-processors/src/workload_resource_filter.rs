use async_trait::async_trait;
use e_navigator_core::{
    CaptureFilterConfig, CaptureFilterPolicy, CoreResult, ModuleKind, ModuleMetadata, Processor,
};
use e_navigator_signals::{KubernetesContext, SignalEnvelope, SignalPayload};

/// Applies the workload capture policy to host resource samples after
/// container and Kubernetes attribution has run. Node-level resource signals
/// remain available even when workload capture is fail-closed.
#[derive(Debug)]
pub struct WorkloadResourceFilterProcessor {
    policy: CaptureFilterPolicy,
}

impl WorkloadResourceFilterProcessor {
    pub fn new(config: &CaptureFilterConfig) -> Self {
        Self {
            policy: CaptureFilterPolicy::from_config(config),
        }
    }

    fn captures(&self, kubernetes: Option<&KubernetesContext>, process_name: Option<&str>) -> bool {
        if !self.policy.is_enabled() {
            return true;
        }
        let Some(kubernetes) = kubernetes else {
            return self.policy.unknown_decision().captures();
        };
        self.policy
            .evaluate_workload(
                &kubernetes.namespace,
                &kubernetes.labels,
                process_name,
                kubernetes.container_name.as_deref(),
            )
            .captures()
    }
}

#[async_trait]
impl Processor<SignalEnvelope> for WorkloadResourceFilterProcessor {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("processor.workload_resource_filter", ModuleKind::Processor)
    }

    async fn process(&self, signal: SignalEnvelope) -> CoreResult<Option<SignalEnvelope>> {
        let captures = match &signal.payload {
            SignalPayload::ProcessResourceObservation(observation) => self.captures(
                observation.process.kubernetes.as_ref(),
                Some(&observation.process.command),
            ),
            SignalPayload::CgroupCpuObservation(observation) => {
                self.captures(observation.cgroup.kubernetes.as_ref(), None)
            }
            SignalPayload::CgroupMemoryObservation(observation) => {
                self.captures(observation.cgroup.kubernetes.as_ref(), None)
            }
            SignalPayload::CgroupPidsObservation(observation) => {
                self.captures(observation.cgroup.kubernetes.as_ref(), None)
            }
            SignalPayload::CgroupFileDescriptorObservation(observation) => {
                self.captures(observation.cgroup.kubernetes.as_ref(), None)
            }
            _ => true,
        };
        Ok(captures.then_some(signal))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use e_navigator_core::{CaptureFilterConfig, CapturePosture, Processor};
    use e_navigator_signals::{
        CgroupMemoryObservation, CgroupResourceContext, KubernetesContext, MetricAggregationWindow,
        NodeLoadObservation, ProcessResourceContext, ProcessResourceObservation, SignalEnvelope,
    };

    use super::WorkloadResourceFilterProcessor;

    fn config() -> CaptureFilterConfig {
        CaptureFilterConfig {
            enabled: true,
            default_posture: CapturePosture::Deny,
            unknown_cgroup: CapturePosture::Deny,
            namespace_include: vec!["proj-*".to_string()],
            label_in: BTreeMap::from([("guara.cloud/tier".to_string(), vec!["pro".to_string()])]),
            label_not_exists: vec!["guara.cloud/catalog-slug".to_string()],
            process_exclude: vec!["*_exporter".to_string()],
            ..CaptureFilterConfig::default()
        }
    }

    fn kubernetes(labels: BTreeMap<String, String>) -> KubernetesContext {
        KubernetesContext {
            namespace: "proj-api".to_string(),
            pod_name: "api-123".to_string(),
            pod_uid: Some("pod-uid".to_string()),
            container_name: Some("api".to_string()),
            node_name: Some("node-a".to_string()),
            labels,
        }
    }

    fn process_signal(command: &str, kubernetes: Option<KubernetesContext>) -> SignalEnvelope {
        SignalEnvelope::process_resource_observation(
            "source.host_resource",
            Some("node-a".to_string()),
            ProcessResourceObservation {
                metric_name: "process.resource".to_string(),
                unit: "1".to_string(),
                timestamp_unix_nanos: 2,
                window: MetricAggregationWindow {
                    start_unix_nanos: 1,
                    end_unix_nanos: 2,
                },
                process: ProcessResourceContext {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: command.to_string(),
                    executable: None,
                    container: None,
                    kubernetes,
                },
                cpu_time_nanos: Some(1),
                memory_rss_bytes: None,
                virtual_memory_bytes: None,
                open_fds: None,
                socket_count: None,
                thread_count: None,
            },
        )
    }

    fn allowed_labels() -> BTreeMap<String, String> {
        BTreeMap::from([("guara.cloud/tier".to_string(), "pro".to_string())])
    }

    #[tokio::test]
    async fn filters_host_process_resources_with_the_capture_policy() {
        let processor = WorkloadResourceFilterProcessor::new(&config());

        assert!(
            processor
                .process(process_signal("api", Some(kubernetes(allowed_labels()))))
                .await
                .expect("allowed sample processes")
                .is_some()
        );
        assert!(
            processor
                .process(process_signal("api", None))
                .await
                .expect("unknown sample processes")
                .is_none()
        );
        assert!(
            processor
                .process(process_signal(
                    "api",
                    Some(kubernetes(BTreeMap::from([(
                        "guara.cloud/tier".to_string(),
                        "free".to_string(),
                    )])))
                ))
                .await
                .expect("unpaid sample processes")
                .is_none()
        );
        let mut catalog_labels = allowed_labels();
        catalog_labels.insert(
            "guara.cloud/catalog-slug".to_string(),
            "managed".to_string(),
        );
        assert!(
            processor
                .process(process_signal("api", Some(kubernetes(catalog_labels))))
                .await
                .expect("catalog sample processes")
                .is_none()
        );
        assert!(
            processor
                .process(process_signal(
                    "node_exporter",
                    Some(kubernetes(allowed_labels()))
                ))
                .await
                .expect("excluded process sample processes")
                .is_none()
        );
    }

    #[tokio::test]
    async fn filters_cgroup_resources_but_preserves_node_resources() {
        let processor = WorkloadResourceFilterProcessor::new(&config());
        let cgroup = SignalEnvelope::cgroup_memory_observation(
            "source.host_resource",
            Some("node-a".to_string()),
            CgroupMemoryObservation {
                metric_name: "container.memory".to_string(),
                unit: "By".to_string(),
                timestamp_unix_nanos: 2,
                window: MetricAggregationWindow {
                    start_unix_nanos: 1,
                    end_unix_nanos: 2,
                },
                cgroup: CgroupResourceContext {
                    cgroup_path: "/kubepods/container".to_string(),
                    container: None,
                    kubernetes: Some(kubernetes(allowed_labels())),
                },
                current_bytes: Some(1),
                peak_bytes: None,
                max_bytes: None,
            },
        );
        assert!(
            processor
                .process(cgroup)
                .await
                .expect("cgroup sample processes")
                .is_some()
        );

        let node = SignalEnvelope::node_load_observation(
            "source.host_resource",
            Some("node-a".to_string()),
            NodeLoadObservation {
                metric_name: "system.load".to_string(),
                unit: "1".to_string(),
                timestamp_unix_nanos: 2,
                window: MetricAggregationWindow {
                    start_unix_nanos: 1,
                    end_unix_nanos: 2,
                },
                load1: 1.0,
                load5: 1.0,
                load15: 1.0,
                runnable_tasks: Some(1),
                total_tasks: Some(2),
            },
        );
        assert!(
            processor
                .process(node)
                .await
                .expect("node sample processes")
                .is_some()
        );
    }
}
