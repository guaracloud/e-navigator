use async_trait::async_trait;
use clap::{Parser, ValueEnum};
use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, RuntimeConfig, Source};
use e_navigator_processors::ContainerAttributionProcessor;
use e_navigator_runner::{ModuleRegistry, Runner};
use e_navigator_signals::{ExecEvent, SignalEnvelope};
use e_navigator_sinks::JsonStdoutSink;
use e_navigator_sources_ebpf_aya::AyaExecSource;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "e-navigator")]
#[command(about = "E-Navigator node agent")]
struct Args {
    #[arg(long, value_enum, default_value_t = SourceMode::AyaExec)]
    source: SourceMode,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SourceMode {
    AyaExec,
    Synthetic,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = RuntimeConfig::default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(config.log_level.clone()))
        .init();

    let registry = match args.source {
        SourceMode::AyaExec => {
            ModuleRegistry::new().with_source(Box::new(AyaExecSource::new(None)))
        }
        SourceMode::Synthetic => ModuleRegistry::new().with_source(Box::new(SyntheticExecSource)),
    }
    .with_processor(Box::new(ContainerAttributionProcessor))
    .with_sink(Box::new(JsonStdoutSink));

    Runner::new(config, registry)?.run().await?;
    Ok(())
}

struct SyntheticExecSource;

#[async_trait]
impl Source<SignalEnvelope> for SyntheticExecSource {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("source.synthetic_exec", ModuleKind::Source)
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
        let signal = SignalEnvelope::exec(
            "source.synthetic_exec",
            None,
            ExecEvent {
                pid: std::process::id(),
                ppid: None,
                uid: None,
                command: "e-navigator".to_string(),
                executable: None,
                arguments: vec!["synthetic".to_string()],
                cgroup_id: None,
                timestamp_unix_nanos: 1,
                container: None,
                kubernetes: None,
            },
        );

        tx.send(signal).await.map_err(|_| CoreError::PipelineClosed)
    }
}
