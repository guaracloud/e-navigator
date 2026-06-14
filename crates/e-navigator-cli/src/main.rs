use async_trait::async_trait;
use clap::{Parser, ValueEnum};
use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, RuntimeConfig, Source};
use e_navigator_generators::RuntimeSecurityGenerator;
use e_navigator_processors::ContainerAttributionProcessor;
use e_navigator_runner::{ModuleRegistry, Runner};
use e_navigator_signals::{
    ContainerContext, ExecEvent, KubernetesContext, ProcessExitEvent, SignalEnvelope,
};
use e_navigator_sinks::JsonStdoutSink;
use e_navigator_sources_ebpf_aya::AyaExecSource;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "e-navigator")]
#[command(about = "E-Navigator node agent")]
struct Args {
    #[arg(long, value_enum, default_value_t = SourceMode::AyaExec)]
    source: SourceMode,

    #[arg(long, env = "E_NAVIGATOR_CONFIG")]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SourceMode {
    AyaExec,
    Synthetic,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = load_config(args.config.as_deref())?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(config.log_level.clone())),
        )
        .init();

    let registry = build_registry(&config, args.source, node_name());

    Runner::new(config, registry)?.run().await?;
    Ok(())
}

fn load_config(path: Option<&std::path::Path>) -> anyhow::Result<RuntimeConfig> {
    match path {
        Some(path) => {
            let contents = std::fs::read_to_string(path)?;
            let config = toml::from_str::<RuntimeConfig>(&contents)?;
            config.validate().map_err(CoreError::InvalidConfig)?;
            Ok(config)
        }
        None => Ok(RuntimeConfig::default()),
    }
}

fn build_registry(
    config: &RuntimeConfig,
    source: SourceMode,
    host: Option<String>,
) -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();

    match source {
        SourceMode::AyaExec if config.module_enabled("source.aya_exec") => {
            registry = registry.with_source(Box::new(AyaExecSource::new(
                host,
                config.argv_capture.clone(),
            )));
        }
        SourceMode::Synthetic if config.module_enabled("source.synthetic_exec") => {
            registry = registry.with_source(Box::new(SyntheticExecSource { host }));
        }
        _ => {}
    }

    if config.module_enabled("processor.container_attribution") {
        registry = registry.with_processor(Box::new(ContainerAttributionProcessor::new(
            config.attribution.clone(),
        )));
    }

    if config.module_enabled("generator.runtime_security") {
        registry = registry.with_generator(Box::new(RuntimeSecurityGenerator::default()));
    }

    if config.module_enabled("sink.json_stdout") {
        registry = registry.with_sink(Box::new(JsonStdoutSink));
    }

    registry
}

fn node_name() -> Option<String> {
    std::env::var("NODE_NAME")
        .ok()
        .filter(|value| !value.is_empty())
}

struct SyntheticExecSource {
    host: Option<String>,
}

#[async_trait]
impl Source<SignalEnvelope> for SyntheticExecSource {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("source.synthetic_exec", ModuleKind::Source)
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
        let (container, kubernetes) = synthetic_attribution();
        let signal = SignalEnvelope::exec(
            "source.synthetic_exec",
            self.host.clone(),
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
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );

        tx.send(signal)
            .await
            .map_err(|_| CoreError::PipelineClosed)?;

        let exit = SignalEnvelope::process_exit(
            "source.synthetic_exec",
            self.host,
            ProcessExitEvent {
                pid: std::process::id(),
                ppid: None,
                uid: None,
                command: "sh".to_string(),
                exit_code: Some(0),
                runtime_nanos: Some(1_000_000),
                timestamp_unix_nanos: now_unix_nanos(),
                container: Some(container),
                kubernetes: Some(kubernetes),
            },
        );

        tx.send(exit).await.map_err(|_| CoreError::PipelineClosed)
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
            node_name: node_name().or_else(|| Some("synthetic-node".to_string())),
            labels,
        },
    )
}

fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::Source;
    use e_navigator_signals::SignalPayload;
    use tokio::sync::mpsc;

    #[test]
    fn config_controls_static_module_registration() {
        let mut config = RuntimeConfig::default();
        for module in &mut config.modules {
            if module.name == "processor.container_attribution" {
                module.enabled = false;
            }
        }

        let registry = build_registry(&config, SourceMode::Synthetic, Some("node-a".to_string()));

        assert_eq!(registry.sources.len(), 1);
        assert_eq!(registry.processors.len(), 0);
        assert_eq!(registry.sinks.len(), 1);
    }

    #[test]
    fn parses_toml_runtime_config() {
        let config = toml::from_str::<RuntimeConfig>(
            r#"
            log_level = "debug"
            queue_capacity = 64

            [[modules]]
            name = "source.synthetic_exec"
            enabled = true

            [[modules]]
            name = "sink.json_stdout"
            enabled = true
            "#,
        )
        .expect("config parses");

        assert_eq!(config.log_level, "debug");
        assert_eq!(config.queue_capacity, 64);
        assert!(config.module_enabled("source.synthetic_exec"));
        assert!(!config.module_enabled("processor.container_attribution"));
    }

    #[tokio::test]
    async fn synthetic_source_emits_attributed_exec_and_exit_fixtures() {
        let (tx, mut rx) = mpsc::channel(4);
        Box::new(SyntheticExecSource {
            host: Some("node-a".to_string()),
        })
        .run(tx)
        .await
        .expect("synthetic source succeeds");

        let mut signals = Vec::new();
        while let Some(signal) = rx.recv().await {
            signals.push(signal);
        }

        assert_eq!(signals.len(), 2);
        let SignalPayload::Exec(exec) = &signals[0].payload else {
            panic!("expected exec fixture");
        };
        assert!(exec.container.is_some());
        assert!(exec.kubernetes.is_some());

        let SignalPayload::ProcessExit(exit) = &signals[1].payload else {
            panic!("expected process exit fixture");
        };
        assert!(exit.container.is_some());
        assert!(exit.kubernetes.is_some());
    }
}
