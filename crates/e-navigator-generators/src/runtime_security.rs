use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata};
use e_navigator_signals::{
    ExecEvent, MatchedProcess, RuntimeSecurityFinding, RuntimeSecuritySeverity, SignalEnvelope,
    SignalPayload,
};
use tokio::sync::mpsc;

#[derive(Debug, Default)]
pub struct RuntimeSecurityGenerator;

#[async_trait]
impl Generator<SignalEnvelope> for RuntimeSecurityGenerator {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("generator.runtime_security", ModuleKind::Generator)
    }

    async fn observe(
        &self,
        signal: &SignalEnvelope,
        tx: &mpsc::Sender<SignalEnvelope>,
    ) -> CoreResult<()> {
        let SignalPayload::Exec(event) = &signal.payload else {
            return Ok(());
        };

        let Some(finding) = finding_for_exec(event) else {
            return Ok(());
        };

        tx.send(SignalEnvelope::runtime_security_finding(
            "generator.runtime_security",
            signal.host.clone(),
            finding,
        ))
        .await
        .map_err(|_| CoreError::PipelineClosed)
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
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        });
    }

    if is_network_tool(basename) {
        return Some(RuntimeSecurityFinding {
            rule_id: "runtime.network_tool_exec".to_string(),
            severity: RuntimeSecuritySeverity::Medium,
            matched_process,
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        });
    }

    None
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
        ContainerContext, ExecEvent, RuntimeSecuritySeverity, SignalEnvelope, SignalPayload,
    };
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

    async fn observe(signal: SignalEnvelope) -> Vec<SignalEnvelope> {
        let generator = RuntimeSecurityGenerator;
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
}
