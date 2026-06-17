use async_trait::async_trait;
use e_navigator_core::{AttributionConfig, CoreResult, ModuleKind, ModuleMetadata, Processor};
use e_navigator_signals::{ContainerContext, KubernetesContext, SignalEnvelope, SignalPayload};
#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use super::kubernetes::KubernetesMetadataProvider;
use super::{
    cgroup::parse_container_from_cgroup,
    cgroup_id::CgroupIdAttributionCache,
    kubernetes::{KubernetesAttribution, KubernetesMetadataCache},
    pid::PidAttributionCache,
};

#[derive(Debug)]
pub struct ContainerAttributionProcessor {
    config: AttributionConfig,
    kubernetes: KubernetesAttribution,
    pid_cache: PidAttributionCache,
    cgroup_id_cache: CgroupIdAttributionCache,
}

impl Default for ContainerAttributionProcessor {
    fn default() -> Self {
        Self::new(AttributionConfig::default())
    }
}

impl ContainerAttributionProcessor {
    pub fn new(config: AttributionConfig) -> Self {
        Self {
            kubernetes: KubernetesAttribution::new(config.kubernetes.clone()),
            config,
            pid_cache: PidAttributionCache::default(),
            cgroup_id_cache: CgroupIdAttributionCache::default(),
        }
    }

    pub fn with_cache(
        config: AttributionConfig,
        kubernetes_cache: KubernetesMetadataCache,
    ) -> Self {
        Self {
            kubernetes: KubernetesAttribution::with_cache(
                config.kubernetes.clone(),
                kubernetes_cache,
            ),
            config,
            pid_cache: PidAttributionCache::default(),
            cgroup_id_cache: CgroupIdAttributionCache::default(),
        }
    }

    #[cfg(test)]
    pub(super) fn with_cache_and_provider(
        config: AttributionConfig,
        kubernetes_cache: KubernetesMetadataCache,
        kubernetes_provider: impl KubernetesMetadataProvider + 'static,
    ) -> Self {
        Self {
            kubernetes: KubernetesAttribution::with_cache_and_provider(
                config.kubernetes.clone(),
                kubernetes_cache,
                Arc::new(kubernetes_provider),
            ),
            config,
            pid_cache: PidAttributionCache::default(),
            cgroup_id_cache: CgroupIdAttributionCache::default(),
        }
    }
}

#[async_trait]
impl Processor<SignalEnvelope> for ContainerAttributionProcessor {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("processor.container_attribution", ModuleKind::Processor)
    }

    async fn process(&self, mut signal: SignalEnvelope) -> CoreResult<Option<SignalEnvelope>> {
        match &mut signal.payload {
            SignalPayload::Exec(event) => {
                if event.container.is_none() {
                    event.container = self.container_for_pid_or_cgroup(event.pid, event.cgroup_id);
                }
                if event.kubernetes.is_none() {
                    event.kubernetes = event.container.as_ref().and_then(|container| {
                        self.kubernetes_context_for_container(&container.container_id)
                    });
                }
            }
            SignalPayload::ProcessExit(event) => {
                if event.container.is_none() {
                    event.container = self.container_for_pid_or_cgroup(event.pid, event.cgroup_id);
                }
                if event.kubernetes.is_none() {
                    event.kubernetes = event.container.as_ref().and_then(|container| {
                        self.kubernetes_context_for_container(&container.container_id)
                    });
                }
                self.pid_cache.evict_pid(event.pid);
            }
            SignalPayload::ProcessLifecycleDuration(event) => {
                if event.kubernetes.is_none() {
                    event.kubernetes = event.container.as_ref().and_then(|container| {
                        self.kubernetes_context_for_container(&container.container_id)
                    });
                }
            }
            SignalPayload::NetworkConnectionOpen(event) => {
                self.enrich_context(
                    event.process.pid,
                    event.process.cgroup_id,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::NetworkConnectionClose(event) => {
                self.enrich_context(
                    event.process.pid,
                    event.process.cgroup_id,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::NetworkConnectionFailure(event) => {
                self.enrich_context(
                    event.process.pid,
                    event.process.cgroup_id,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::DnsQuery(event) => {
                self.enrich_context(
                    event.process.pid,
                    event.process.cgroup_id,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::DnsResponse(event) => {
                self.enrich_context(
                    event.process.pid,
                    event.process.cgroup_id,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::ProtocolRequestObservation(event) => {
                self.enrich_existing_container_context(&mut event.container, &mut event.kubernetes);
            }
            SignalPayload::ExtractedTraceContextObservation(event) => {
                self.enrich_existing_container_context(&mut event.container, &mut event.kubernetes);
            }
            SignalPayload::RequestSpanObservation(event) => {
                self.enrich_existing_container_context(&mut event.container, &mut event.kubernetes);
            }
            SignalPayload::RequestCorrelationWarning(event) => {
                self.enrich_existing_container_context(&mut event.container, &mut event.kubernetes);
            }
            SignalPayload::ProfileSampleObservation(event) => {
                self.enrich_profile_context(
                    event.process.as_ref().map(|process| process.pid),
                    event.process.as_ref().and_then(|process| process.cgroup_id),
                    &mut event.container,
                    &mut event.kubernetes,
                )
                .await;
            }
            SignalPayload::ProfilingStackTraceObservation(event) => {
                self.enrich_profile_context(
                    event.process.as_ref().map(|process| process.pid),
                    event.process.as_ref().and_then(|process| process.cgroup_id),
                    &mut event.container,
                    &mut event.kubernetes,
                )
                .await;
            }
            SignalPayload::ProfilingSessionObservation(event) => {
                self.enrich_profile_context(
                    event.process.as_ref().map(|process| process.pid),
                    event.process.as_ref().and_then(|process| process.cgroup_id),
                    &mut event.container,
                    &mut event.kubernetes,
                )
                .await;
            }
            SignalPayload::ProfilingWarningObservation(event) => {
                self.enrich_profile_context(
                    event.process.as_ref().map(|process| process.pid),
                    event.process.as_ref().and_then(|process| process.cgroup_id),
                    &mut event.container,
                    &mut event.kubernetes,
                )
                .await;
            }
            SignalPayload::ProcessResourceObservation(event) => {
                self.enrich_context(
                    event.process.pid,
                    None,
                    &mut event.process.container,
                    &mut event.process.kubernetes,
                );
            }
            SignalPayload::CgroupCpuObservation(event) => {
                self.enrich_cgroup_context(&mut event.cgroup);
            }
            SignalPayload::CgroupMemoryObservation(event) => {
                self.enrich_cgroup_context(&mut event.cgroup);
            }
            SignalPayload::CgroupPidsObservation(event) => {
                self.enrich_cgroup_context(&mut event.cgroup);
            }
            SignalPayload::CgroupFileDescriptorObservation(event) => {
                self.enrich_cgroup_context(&mut event.cgroup);
            }
            SignalPayload::ServiceInteractionSpanObservation(event) => {
                self.enrich_dependency_endpoint(&mut event.source);
                self.enrich_dependency_endpoint(&mut event.destination);
            }
            SignalPayload::TraceServicePathObservation(event) => {
                self.enrich_dependency_endpoint(&mut event.source);
                self.enrich_dependency_endpoint(&mut event.destination);
            }
            SignalPayload::DependencyEdge(event) => {
                self.enrich_dependency_endpoint(&mut event.source);
                self.enrich_dependency_endpoint(&mut event.destination);
            }
            SignalPayload::RuntimeSecurityFinding(_) => {}
            _ => {}
        }

        Ok(Some(signal))
    }
}

impl ContainerAttributionProcessor {
    fn enrich_context(
        &self,
        pid: u32,
        cgroup_id: Option<u64>,
        container: &mut Option<ContainerContext>,
        kubernetes: &mut Option<KubernetesContext>,
    ) {
        if container.is_none() {
            *container = self.container_for_pid_or_cgroup(pid, cgroup_id);
        }
        if kubernetes.is_none() {
            *kubernetes = container.as_ref().and_then(|container| {
                self.kubernetes_context_for_container(&container.container_id)
            });
        }
    }

    fn enrich_existing_container_context(
        &self,
        container: &mut Option<ContainerContext>,
        kubernetes: &mut Option<KubernetesContext>,
    ) {
        if kubernetes.is_none() {
            *kubernetes = container.as_ref().and_then(|container| {
                self.kubernetes_context_for_container(&container.container_id)
            });
        }
    }

    fn enrich_dependency_endpoint(&self, endpoint: &mut e_navigator_signals::DependencyEndpoint) {
        if endpoint.workload.is_none() {
            endpoint.workload = endpoint.container.as_ref().and_then(|container| {
                self.kubernetes_context_for_container(&container.container_id)
            });
        }
    }

    async fn enrich_profile_context(
        &self,
        pid: Option<u32>,
        cgroup_id: Option<u64>,
        container: &mut Option<ContainerContext>,
        kubernetes: &mut Option<KubernetesContext>,
    ) {
        if let Some(pid) = pid {
            if container.is_none() {
                *container = self.container_for_pid_or_cgroup_async(pid, cgroup_id).await;
            }
            if kubernetes.is_none() {
                *kubernetes = container.as_ref().and_then(|container| {
                    self.kubernetes_context_for_container(&container.container_id)
                });
            }
        } else {
            self.enrich_existing_container_context(container, kubernetes);
        }
    }

    fn enrich_cgroup_context(&self, cgroup: &mut e_navigator_signals::CgroupResourceContext) {
        if cgroup.container.is_none() {
            cgroup.container = parse_container_from_cgroup(&cgroup.cgroup_path);
        }
        self.cgroup_id_cache
            .cache_cgroup_context(&self.config.cgroup_root, cgroup);
        if cgroup.kubernetes.is_none() {
            cgroup.kubernetes = cgroup.container.as_ref().and_then(|container| {
                self.kubernetes_context_for_container(&container.container_id)
            });
        }
    }

    fn container_for_pid_or_cgroup(
        &self,
        pid: u32,
        cgroup_id: Option<u64>,
    ) -> Option<ContainerContext> {
        self.pid_cache
            .container_for_pid(&self.config.procfs_root, pid)
            .or_else(|| {
                cgroup_id.and_then(|cgroup_id| {
                    self.cgroup_id_cache
                        .container_for_cgroup_id(&self.config.cgroup_root, cgroup_id)
                })
            })
    }

    async fn container_for_pid_or_cgroup_async(
        &self,
        pid: u32,
        cgroup_id: Option<u64>,
    ) -> Option<ContainerContext> {
        match self
            .pid_cache
            .container_for_pid_async(&self.config.procfs_root, pid)
            .await
        {
            Some(container) => Some(container),
            None => cgroup_id.and_then(|cgroup_id| {
                self.cgroup_id_cache
                    .container_for_cgroup_id(&self.config.cgroup_root, cgroup_id)
            }),
        }
    }

    fn kubernetes_context_for_container(&self, container_id: &str) -> Option<KubernetesContext> {
        self.kubernetes.context_for_container(container_id)
    }
}
