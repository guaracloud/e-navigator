use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata};
use e_navigator_signals::{
    ExecEvent, MatchedNetworkConnection, MatchedProcess, NetworkConnectionOpenEvent,
    RuntimeSecurityFinding, RuntimeSecuritySeverity, SignalEnvelope, SignalPayload,
};
use std::{collections::BTreeSet, net::IpAddr};
use tokio::sync::mpsc;

#[derive(Debug, Default)]
pub struct RuntimeSecurityGenerator {
    kubernetes_api_endpoints: BTreeSet<KubernetesApiEndpoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct KubernetesApiEndpoint {
    address: IpAddr,
    port: u16,
}

impl RuntimeSecurityGenerator {
    pub fn with_kubernetes_api_addresses(addresses: impl IntoIterator<Item = String>) -> Self {
        Self::with_kubernetes_api_endpoints(addresses.into_iter().map(|address| (address, 443)))
    }

    pub fn with_kubernetes_api_endpoints(
        endpoints: impl IntoIterator<Item = (String, u16)>,
    ) -> Self {
        Self {
            kubernetes_api_endpoints: endpoints
                .into_iter()
                .filter_map(|(address, port)| {
                    normalize_ip(&address).map(|address| KubernetesApiEndpoint { address, port })
                })
                .collect(),
        }
    }
}

#[async_trait]
impl Generator<SignalEnvelope> for RuntimeSecurityGenerator {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("generator.runtime_security", ModuleKind::Generator)
    }

    fn accepts(&self, signal: &SignalEnvelope) -> bool {
        matches!(
            &signal.payload,
            SignalPayload::Exec(_) | SignalPayload::NetworkConnectionOpen(_)
        )
    }

    fn observe_immediate(
        &self,
        signal: &SignalEnvelope,
    ) -> Option<CoreResult<Vec<SignalEnvelope>>> {
        Some(Ok(self.outputs_for_signal(signal)))
    }

    async fn observe(
        &self,
        signal: &SignalEnvelope,
        tx: &mpsc::Sender<SignalEnvelope>,
    ) -> CoreResult<()> {
        for finding in self.outputs_for_signal(signal) {
            tx.send(finding)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }

        Ok(())
    }
}

impl RuntimeSecurityGenerator {
    fn outputs_for_signal(&self, signal: &SignalEnvelope) -> Vec<SignalEnvelope> {
        let finding = match &signal.payload {
            SignalPayload::Exec(event) => finding_for_exec(event),
            SignalPayload::NetworkConnectionOpen(event) => self.finding_for_network_open(event),
            _ => None,
        };

        let Some(finding) = finding else {
            return Vec::new();
        };

        vec![SignalEnvelope::runtime_security_finding(
            "generator.runtime_security",
            signal.host.clone(),
            finding,
        )]
    }
}

fn finding_for_exec(event: &ExecEvent) -> Option<RuntimeSecurityFinding> {
    let basename = process_basename(event);
    let matched_process = MatchedProcess {
        pid: event.pid,
        command: event.command.clone(),
        executable: event.executable.clone(),
        arguments: event.arguments.clone(),
    };

    if event.container.is_some() && is_shell(basename) {
        return Some(RuntimeSecurityFinding {
            rule_id: "runtime.shell_in_container".to_string(),
            severity: RuntimeSecuritySeverity::Medium,
            matched_process,
            matched_connection: None,
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        });
    }

    if is_network_tool(basename) {
        return Some(RuntimeSecurityFinding {
            rule_id: "runtime.network_tool_exec".to_string(),
            severity: RuntimeSecuritySeverity::Medium,
            matched_process,
            matched_connection: None,
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        });
    }

    None
}

impl RuntimeSecurityGenerator {
    fn finding_for_network_open(
        &self,
        event: &NetworkConnectionOpenEvent,
    ) -> Option<RuntimeSecurityFinding> {
        if self.matches_kubernetes_api_endpoint(event) && !is_control_plane_workload(event) {
            return Some(network_finding(
                "network.kubernetes_api_from_workload",
                RuntimeSecuritySeverity::High,
                event,
            ));
        }

        if event.container.is_some() && is_external_address(&event.remote_address) {
            return Some(network_finding(
                "network.unexpected_external_connection",
                RuntimeSecuritySeverity::Medium,
                event,
            ));
        }

        None
    }

    fn matches_kubernetes_api_endpoint(&self, event: &NetworkConnectionOpenEvent) -> bool {
        let Some(address) = normalize_ip(&event.remote_address) else {
            return false;
        };

        self.kubernetes_api_endpoints
            .contains(&KubernetesApiEndpoint {
                address,
                port: event.remote_port,
            })
    }
}

fn network_finding(
    rule_id: &str,
    severity: RuntimeSecuritySeverity,
    event: &NetworkConnectionOpenEvent,
) -> RuntimeSecurityFinding {
    RuntimeSecurityFinding {
        rule_id: rule_id.to_string(),
        severity,
        matched_process: MatchedProcess {
            pid: event.process.pid,
            command: event.process.command.clone(),
            executable: event.process.executable.clone(),
            arguments: Vec::new(),
        },
        matched_connection: Some(MatchedNetworkConnection {
            protocol: event.protocol,
            remote_address: event.remote_address.clone(),
            remote_port: event.remote_port,
            local_address: event.local_address.clone(),
            local_port: event.local_port,
            fd: event.fd,
        }),
        container: event.container.clone(),
        kubernetes: event.kubernetes.clone(),
    }
}

fn is_external_address(address: &str) -> bool {
    let Some(address) = normalize_ip(address) else {
        return false;
    };

    match address {
        IpAddr::V4(address) => {
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_unspecified())
        }
        IpAddr::V6(address) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || ((address.segments()[0] & 0xfe00) == 0xfc00)
                || ((address.segments()[0] & 0xffc0) == 0xfe80))
        }
    }
}

fn normalize_ip(address: &str) -> Option<IpAddr> {
    let address = address.parse::<IpAddr>().ok()?;

    Some(match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        IpAddr::V4(_) => address,
    })
}

fn is_control_plane_workload(event: &NetworkConnectionOpenEvent) -> bool {
    let Some(context) = &event.kubernetes else {
        return false;
    };

    if context.namespace == "kube-system" {
        return true;
    }

    context.labels.iter().any(|(key, value)| {
        matches!(
            key.as_str(),
            "component" | "k8s-app" | "app.kubernetes.io/component"
        ) && matches!(
            value.as_str(),
            "kube-apiserver" | "kube-controller-manager" | "kube-scheduler" | "control-plane"
        )
    })
}

fn process_basename(event: &ExecEvent) -> &str {
    event
        .executable
        .as_deref()
        .or_else(|| event.arguments.first().map(String::as_str))
        .unwrap_or(&event.command)
        .rsplit('/')
        .next()
        .unwrap_or(&event.command)
}

fn is_shell(value: &str) -> bool {
    matches!(value, "sh" | "bash" | "dash" | "ash" | "zsh" | "ksh")
}

fn is_network_tool(value: &str) -> bool {
    matches!(value, "curl" | "wget" | "nc" | "ncat" | "netcat" | "socat")
}

#[cfg(test)]
mod tests {
    use e_navigator_core::Generator;
    use e_navigator_signals::{
        ContainerContext, ExecEvent, KubernetesContext, NetworkAddressFamily,
        NetworkConnectionOpenEvent, NetworkProcessIdentity, NetworkProtocol,
        RuntimeSecuritySeverity, SignalEnvelope, SignalPayload,
    };
    use std::collections::BTreeMap;
    use tokio::sync::mpsc;

    use super::*;

    #[tokio::test]
    async fn emits_shell_in_container_finding() {
        let findings = observe(exec_signal(
            "sh",
            Some("/bin/sh"),
            vec!["sh"],
            Some(ContainerContext {
                container_id: "container-a".to_string(),
                runtime: Some("containerd".to_string()),
            }),
        ))
        .await;

        assert_eq!(findings.len(), 1);
        let SignalPayload::RuntimeSecurityFinding(finding) = &findings[0].payload else {
            panic!("expected runtime security finding");
        };
        assert_eq!(finding.rule_id, "runtime.shell_in_container");
        assert_eq!(finding.severity, RuntimeSecuritySeverity::Medium);
        assert_eq!(finding.matched_process.command, "sh");
    }

    #[tokio::test]
    async fn emits_network_tool_finding_for_exact_basename() {
        let first = observe(exec_signal(
            "curl",
            Some("/usr/bin/curl"),
            vec!["curl"],
            None,
        ))
        .await;
        let second = observe(exec_signal(
            "mycurl",
            Some("/usr/bin/mycurl"),
            vec!["mycurl"],
            None,
        ))
        .await;

        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
        let SignalPayload::RuntimeSecurityFinding(finding) = &first[0].payload else {
            panic!("expected runtime security finding");
        };
        assert_eq!(finding.rule_id, "runtime.network_tool_exec");
        assert_eq!(finding.matched_process.command, "curl");
    }

    #[tokio::test]
    async fn benign_processes_and_host_shells_do_not_emit() {
        assert!(
            observe(exec_signal(
                "true",
                Some("/usr/bin/true"),
                vec!["true"],
                None
            ))
            .await
            .is_empty()
        );
        assert!(
            observe(exec_signal("bash", Some("/bin/bash"), vec!["bash"], None))
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn generator_output_is_deterministic() {
        let signal = exec_signal("nc", Some("/usr/bin/nc"), vec!["nc", "-z"], None);

        let first = observe(signal.clone()).await;
        let second = observe(signal).await;

        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn emits_external_outbound_connection_finding_for_container() {
        let findings = observe(network_open_signal(
            "203.0.113.10",
            443,
            kubernetes_context(),
        ))
        .await;

        assert_eq!(findings.len(), 1);
        let SignalPayload::RuntimeSecurityFinding(finding) = &findings[0].payload else {
            panic!("expected runtime security finding");
        };
        assert_eq!(finding.rule_id, "network.unexpected_external_connection");
        assert_eq!(finding.severity, RuntimeSecuritySeverity::Medium);
        assert_eq!(
            finding
                .matched_connection
                .as_ref()
                .expect("matched connection")
                .remote_address,
            "203.0.113.10"
        );
    }

    #[tokio::test]
    async fn emits_kubernetes_api_connection_finding_for_non_control_plane_workload() {
        let generator = RuntimeSecurityGenerator::with_kubernetes_api_endpoints([(
            "10.96.0.1".to_string(),
            443,
        )]);
        let signal = network_open_signal("10.96.0.1", 443, kubernetes_context());

        let findings = observe_with(&generator, signal).await;

        assert_eq!(findings.len(), 1);
        let SignalPayload::RuntimeSecurityFinding(finding) = &findings[0].payload else {
            panic!("expected runtime security finding");
        };
        assert_eq!(finding.rule_id, "network.kubernetes_api_from_workload");
        assert_eq!(finding.severity, RuntimeSecuritySeverity::High);
    }

    #[tokio::test]
    async fn suppresses_kubernetes_api_finding_for_unconfigured_port() {
        let generator = RuntimeSecurityGenerator::with_kubernetes_api_endpoints([(
            "10.96.0.1".to_string(),
            443,
        )]);

        assert!(
            observe_with(
                &generator,
                network_open_signal("10.96.0.1", 6443, kubernetes_context())
            )
            .await
            .is_empty()
        );
    }

    #[tokio::test]
    async fn handles_ipv4_mapped_ipv6_external_classification() {
        assert!(
            observe(network_open_signal(
                "::ffff:10.0.0.20",
                5432,
                kubernetes_context()
            ))
            .await
            .is_empty()
        );

        let findings = observe(network_open_signal(
            "::ffff:203.0.113.10",
            443,
            kubernetes_context(),
        ))
        .await;

        assert_eq!(findings.len(), 1);
        let SignalPayload::RuntimeSecurityFinding(finding) = &findings[0].payload else {
            panic!("expected runtime security finding");
        };
        assert_eq!(finding.rule_id, "network.unexpected_external_connection");
    }

    #[tokio::test]
    async fn suppresses_network_findings_for_internal_or_control_plane_connections() {
        assert!(
            observe(network_open_signal("10.0.0.20", 5432, kubernetes_context()))
                .await
                .is_empty()
        );

        let mut context = kubernetes_context();
        context
            .labels
            .insert("component".to_string(), "kube-apiserver".to_string());
        let generator = RuntimeSecurityGenerator::with_kubernetes_api_endpoints([(
            "10.96.0.1".to_string(),
            443,
        )]);

        assert!(
            observe_with(&generator, network_open_signal("10.96.0.1", 443, context))
                .await
                .is_empty()
        );
    }

    async fn observe(signal: SignalEnvelope) -> Vec<SignalEnvelope> {
        let generator = RuntimeSecurityGenerator::default();
        observe_with(&generator, signal).await
    }

    async fn observe_with(
        generator: &RuntimeSecurityGenerator,
        signal: SignalEnvelope,
    ) -> Vec<SignalEnvelope> {
        let (tx, mut rx) = mpsc::channel(4);
        generator
            .observe(&signal, &tx)
            .await
            .expect("generator succeeds");
        drop(tx);

        let mut findings = Vec::new();
        while let Some(finding) = rx.recv().await {
            findings.push(finding);
        }
        findings
    }

    fn exec_signal(
        command: &str,
        executable: Option<&str>,
        arguments: Vec<&str>,
        container: Option<ContainerContext>,
    ) -> SignalEnvelope {
        SignalEnvelope::exec(
            "source.test",
            Some("node-a".to_string()),
            ExecEvent {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: command.to_string(),
                executable: executable.map(ToString::to_string),
                arguments: arguments.into_iter().map(ToString::to_string).collect(),
                cgroup_id: None,
                timestamp_unix_nanos: 123,
                container,
                kubernetes: None,
            },
        )
    }

    fn network_open_signal(
        remote_address: &str,
        remote_port: u16,
        kubernetes: KubernetesContext,
    ) -> SignalEnvelope {
        SignalEnvelope::network_connection_open(
            "source.test",
            Some("node-a".to_string()),
            NetworkConnectionOpenEvent {
                process: NetworkProcessIdentity {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: "api".to_string(),
                    executable: Some("/app/api".to_string()),
                    cgroup_id: None,
                },
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.0.0.5".to_string()),
                local_port: Some(43512),
                remote_address: remote_address.to_string(),
                remote_port,
                fd: Some(7),
                timestamp_unix_nanos: 123,
                container: Some(ContainerContext {
                    container_id: "container-a".to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: Some(kubernetes),
            },
        )
    }

    fn kubernetes_context() -> KubernetesContext {
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "api".to_string());

        KubernetesContext {
            namespace: "default".to_string(),
            pod_name: "api-123".to_string(),
            pod_uid: Some("pod-uid".to_string()),
            container_name: Some("api".to_string()),
            node_name: Some("node-a".to_string()),
            labels,
        }
    }
}
