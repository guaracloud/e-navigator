# E-Navigator Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the phase 1 E-Navigator foundation: layered Rust workspace, statically registered signal pipeline, local Linux runner, Aya process exec source, JSON stdout sink, Kubernetes DaemonSet packaging, docs, ADRs, and CI.

**Architecture:** E-Navigator is a statically registered signal pipeline engine. The runtime shape is `Sources -> Processors -> Generators -> Sinks`, with Aya/eBPF specifics isolated behind source crates and all deployment modes using the same runner library.

**Tech Stack:** Rust 2024 edition, Cargo workspace, Tokio, Serde, thiserror, tracing, clap, Aya, aya-template conventions, Kubernetes manifests, GitHub Actions.

---

## References

- Approved design: `docs/superpowers/specs/2026-06-13-e-navigator-foundation-design.md`
- Vision: `documentation/vision.md`
- Aya development prerequisites: https://aya-rs.dev/book/start/development.html
- Aya tracepoint guidance: https://aya-rs.dev/book/programs/tracepoints.html
- Aya template layout and build-script pattern: https://github.com/aya-rs/aya-template

## File Structure

Create or modify these files during implementation:

- `Cargo.toml`: workspace members, shared package metadata, shared dependencies, release profile.
- `rust-toolchain.toml`: stable and nightly toolchain expectations for userspace and eBPF development.
- `rustfmt.toml`: formatting baseline.
- `.github/workflows/ci.yml`: non-privileged CI checks.
- `crates/e-navigator-core/Cargo.toml`: core contracts crate manifest.
- `crates/e-navigator-core/src/lib.rs`: public core exports.
- `crates/e-navigator-core/src/config.rs`: runtime config model.
- `crates/e-navigator-core/src/error.rs`: shared error model.
- `crates/e-navigator-core/src/module.rs`: module identity and static registration primitives.
- `crates/e-navigator-core/src/pipeline.rs`: `Source`, `Processor`, `Generator`, and `Sink` traits.
- `crates/e-navigator-signals/Cargo.toml`: signal schema crate manifest.
- `crates/e-navigator-signals/src/lib.rs`: public signal exports.
- `crates/e-navigator-signals/src/envelope.rs`: versioned `SignalEnvelope`.
- `crates/e-navigator-signals/src/exec.rs`: `ExecEvent` payload.
- `crates/e-navigator-runner/Cargo.toml`: runner crate manifest.
- `crates/e-navigator-runner/src/lib.rs`: public runner exports.
- `crates/e-navigator-runner/src/registry.rs`: static module registry.
- `crates/e-navigator-runner/src/runtime.rs`: pipeline orchestration.
- `crates/e-navigator-processors/Cargo.toml`: processor crate manifest.
- `crates/e-navigator-processors/src/lib.rs`: processor exports.
- `crates/e-navigator-processors/src/container_attribution.rs`: best-effort attribution processor.
- `crates/e-navigator-sinks/Cargo.toml`: sink crate manifest.
- `crates/e-navigator-sinks/src/lib.rs`: sink exports.
- `crates/e-navigator-sinks/src/json_stdout.rs`: newline-delimited JSON sink.
- `crates/e-navigator-sources-ebpf-aya/Cargo.toml`: Aya source crate manifest.
- `crates/e-navigator-sources-ebpf-aya/build.rs`: eBPF object build integration.
- `crates/e-navigator-sources-ebpf-aya/src/lib.rs`: Aya source exports.
- `crates/e-navigator-sources-ebpf-aya/src/exec.rs`: userspace exec source.
- `crates/e-navigator-ebpf-programs/Cargo.toml`: no-std eBPF program manifest.
- `crates/e-navigator-ebpf-programs/src/main.rs`: process exec tracepoint program.
- `crates/e-navigator-cli/Cargo.toml`: CLI crate manifest.
- `crates/e-navigator-cli/src/main.rs`: local and Kubernetes process entrypoint.
- `deploy/kubernetes/namespace.yaml`: sample namespace.
- `deploy/kubernetes/rbac.yaml`: metadata access service account and RBAC.
- `deploy/kubernetes/configmap.yaml`: phase 1 runtime config.
- `deploy/kubernetes/daemonset.yaml`: one node-local agent pod per node.
- `docs/adr/0001-aya-first.md`: Aya-first decision.
- `docs/adr/0002-static-pipeline-registration.md`: static registration decision.
- `docs/adr/0003-kubernetes-privilege-model.md`: initial privilege model.
- `docs/development/local-linux.md`: local development and smoke test.
- `docs/development/kubernetes.md`: Kubernetes smoke test.
- `README.md`: short project overview and commands.

## Implementation Tasks

### Task 1: Workspace And Toolchain Baseline

**Files:**
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `rustfmt.toml`
- Create: `README.md`

- [ ] **Step 1: Write the workspace manifest**

Create `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
  "crates/e-navigator-core",
  "crates/e-navigator-signals",
  "crates/e-navigator-runner",
  "crates/e-navigator-processors",
  "crates/e-navigator-sinks",
  "crates/e-navigator-sources-ebpf-aya",
  "crates/e-navigator-cli",
]
default-members = [
  "crates/e-navigator-core",
  "crates/e-navigator-signals",
  "crates/e-navigator-runner",
  "crates/e-navigator-processors",
  "crates/e-navigator-sinks",
  "crates/e-navigator-sources-ebpf-aya",
  "crates/e-navigator-cli",
]

[workspace.package]
edition = "2024"
license = "Apache-2.0"
version = "0.1.0"
repository = "https://github.com/victorbona/e-navigator"

[workspace.dependencies]
anyhow = "1"
async-trait = "0.1"
aya = { git = "https://github.com/aya-rs/aya", default-features = false }
aya-build = { git = "https://github.com/aya-rs/aya", default-features = false }
aya-ebpf = { git = "https://github.com/aya-rs/aya", default-features = false }
aya-log = { git = "https://github.com/aya-rs/aya", default-features = false }
aya-log-ebpf = { git = "https://github.com/aya-rs/aya", default-features = false }
bytes = "1"
clap = { version = "4", features = ["derive", "env"] }
libc = "0.2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tokio = { version = "1", features = ["io-util", "macros", "rt-multi-thread", "signal", "sync", "time"] }
tokio-stream = "0.1"
toml = "0.9"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt", "json"] }
which = "8"

[profile.release.package.e-navigator-ebpf-programs]
debug = 2
codegen-units = 1
strip = false
```

- [ ] **Step 2: Write toolchain metadata**

Create `rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["clippy", "rustfmt"]
targets = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
```

- [ ] **Step 3: Write formatting baseline**

Create `rustfmt.toml`:

```toml
edition = "2024"
newline_style = "Unix"
use_field_init_shorthand = true
use_try_shorthand = true
```

- [ ] **Step 4: Write initial README**

Create `README.md`:

````markdown
# E-Navigator

E-Navigator is a Rust and eBPF observability, security, profiling, and diagnostics platform for Linux and Kubernetes workloads.

Phase 1 builds the foundation:

- A layered Rust workspace.
- A statically registered signal pipeline.
- A local Linux runner.
- Kubernetes DaemonSet packaging.
- An Aya process exec source.
- JSON stdout output.

## Development

Run non-privileged checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

Aya/eBPF development also requires the nightly Rust toolchain with `rust-src`, `bpf-linker`, and `bpftool`.

See:

- `docs/development/local-linux.md`
- `docs/development/kubernetes.md`
````

- [ ] **Step 5: Run the first workspace check**

Run:

```bash
cargo metadata --format-version 1
```

Expected: fails because workspace member crates do not exist yet.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml rust-toolchain.toml rustfmt.toml README.md
git commit -m "chore: add rust workspace baseline"
```

### Task 2: Core Contracts Crate

**Files:**
- Create: `crates/e-navigator-core/Cargo.toml`
- Create: `crates/e-navigator-core/src/lib.rs`
- Create: `crates/e-navigator-core/src/config.rs`
- Create: `crates/e-navigator-core/src/error.rs`
- Create: `crates/e-navigator-core/src/module.rs`
- Create: `crates/e-navigator-core/src/pipeline.rs`

- [ ] **Step 1: Write the manifest**

Create `crates/e-navigator-core/Cargo.toml`:

```toml
[package]
name = "e-navigator-core"
edition.workspace = true
license.workspace = true
version.workspace = true

[dependencies]
async-trait = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
```

- [ ] **Step 2: Write the library exports**

Create `crates/e-navigator-core/src/lib.rs`:

```rust
pub mod config;
pub mod error;
pub mod module;
pub mod pipeline;

pub use config::{ModuleConfig, RuntimeConfig};
pub use error::{CoreError, CoreResult};
pub use module::{ModuleKind, ModuleMetadata};
pub use pipeline::{Generator, Processor, Signal, Sink, Source};
```

- [ ] **Step 3: Write config types**

Create `crates/e-navigator-core/src/config.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub log_level: String,
    pub queue_capacity: usize,
    pub modules: Vec<ModuleConfig>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            queue_capacity: 1024,
            modules: vec![
                ModuleConfig::enabled("source.aya_exec"),
                ModuleConfig::enabled("processor.container_attribution"),
                ModuleConfig::enabled("sink.json_stdout"),
            ],
        }
    }
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.queue_capacity == 0 {
            return Err("queue_capacity must be greater than zero".to_string());
        }

        if self.modules.iter().filter(|module| module.enabled).count() == 0 {
            return Err("at least one module must be enabled".to_string());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub name: String,
    pub enabled: bool,
}

impl ModuleConfig {
    pub fn enabled(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(RuntimeConfig::default().validate().is_ok());
    }

    #[test]
    fn zero_queue_capacity_is_invalid() {
        let config = RuntimeConfig {
            queue_capacity: 0,
            ..RuntimeConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err("queue_capacity must be greater than zero".to_string())
        );
    }
}
```

- [ ] **Step 4: Write shared errors**

Create `crates/e-navigator-core/src/error.rs`:

```rust
use thiserror::Error;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("module failed: {module}: {message}")]
    ModuleFailed { module: String, message: String },

    #[error("pipeline closed")]
    PipelineClosed,
}
```

- [ ] **Step 5: Write module metadata**

Create `crates/e-navigator-core/src/module.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Source,
    Processor,
    Generator,
    Sink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleMetadata {
    pub name: &'static str,
    pub kind: ModuleKind,
}

impl ModuleMetadata {
    pub const fn new(name: &'static str, kind: ModuleKind) -> Self {
        Self { name, kind }
    }
}
```

- [ ] **Step 6: Write pipeline traits**

Create `crates/e-navigator-core/src/pipeline.rs`:

```rust
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::{CoreResult, ModuleMetadata};

pub trait Signal: Send + Sync + Clone + 'static {
    fn kind(&self) -> &'static str;
}

#[async_trait]
pub trait Source<S: Signal>: Send + 'static {
    fn metadata(&self) -> ModuleMetadata;

    async fn run(self: Box<Self>, tx: mpsc::Sender<S>) -> CoreResult<()>;
}

#[async_trait]
pub trait Processor<S: Signal>: Send + Sync + 'static {
    fn metadata(&self) -> ModuleMetadata;

    async fn process(&self, signal: S) -> CoreResult<Option<S>>;
}

#[async_trait]
pub trait Generator<S: Signal>: Send + Sync + 'static {
    fn metadata(&self) -> ModuleMetadata;

    async fn observe(&self, signal: &S, tx: &mpsc::Sender<S>) -> CoreResult<()>;
}

#[async_trait]
pub trait Sink<S: Signal>: Send + Sync + 'static {
    fn metadata(&self) -> ModuleMetadata;

    async fn write(&self, signal: &S) -> CoreResult<()>;
}
```

- [ ] **Step 7: Run tests for the crate**

Run:

```bash
cargo test -p e-navigator-core
```

Expected: tests pass.

- [ ] **Step 8: Commit**

```bash
git add crates/e-navigator-core
git commit -m "feat: add core pipeline contracts"
```

### Task 3: Signal Schema Crate

**Files:**
- Create: `crates/e-navigator-signals/Cargo.toml`
- Create: `crates/e-navigator-signals/src/lib.rs`
- Create: `crates/e-navigator-signals/src/envelope.rs`
- Create: `crates/e-navigator-signals/src/exec.rs`

- [ ] **Step 1: Write the manifest**

Create `crates/e-navigator-signals/Cargo.toml`:

```toml
[package]
name = "e-navigator-signals"
edition.workspace = true
license.workspace = true
version.workspace = true

[dependencies]
e-navigator-core = { path = "../e-navigator-core" }
serde = { workspace = true }
serde_json = { workspace = true }
```

- [ ] **Step 2: Write signal exports**

Create `crates/e-navigator-signals/src/lib.rs`:

```rust
pub mod envelope;
pub mod exec;

pub use envelope::{SignalEnvelope, SignalPayload};
pub use exec::{ContainerContext, ExecEvent, KubernetesContext};
```

- [ ] **Step 3: Write exec event schema**

Create `crates/e-navigator-signals/src/exec.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub command: String,
    pub executable: Option<String>,
    pub arguments: Vec<String>,
    pub cgroup_id: Option<u64>,
    pub timestamp_unix_nanos: u64,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerContext {
    pub container_id: String,
    pub runtime: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesContext {
    pub namespace: String,
    pub pod_name: String,
    pub container_name: Option<String>,
    pub node_name: Option<String>,
}
```

- [ ] **Step 4: Write signal envelope**

Create `crates/e-navigator-signals/src/envelope.rs`:

```rust
use e_navigator_core::Signal;
use serde::{Deserialize, Serialize};

use crate::ExecEvent;

pub const SIGNAL_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum SignalPayload {
    Exec(ExecEvent),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalEnvelope {
    pub schema_version: u16,
    pub source: String,
    pub host: Option<String>,
    pub payload: SignalPayload,
}

impl SignalEnvelope {
    pub fn exec(source: impl Into<String>, host: Option<String>, event: ExecEvent) -> Self {
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            source: source.into(),
            host,
            payload: SignalPayload::Exec(event),
        }
    }
}

impl Signal for SignalEnvelope {
    fn kind(&self) -> &'static str {
        match self.payload {
            SignalPayload::Exec(_) => "exec",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_exec_signal_with_version() {
        let signal = SignalEnvelope::exec(
            "source.test",
            Some("node-a".to_string()),
            ExecEvent {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: "bash".to_string(),
                executable: Some("/usr/bin/bash".to_string()),
                arguments: vec!["bash".to_string()],
                cgroup_id: Some(7),
                timestamp_unix_nanos: 123,
                container: None,
                kubernetes: None,
            },
        );

        let json = serde_json::to_string(&signal).expect("signal serializes");
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"kind\":\"exec\""));
        assert!(json.contains("\"command\":\"bash\""));
    }
}
```

- [ ] **Step 5: Run tests**

Run:

```bash
cargo test -p e-navigator-signals
```

Expected: tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/e-navigator-signals
git commit -m "feat: add versioned signal schemas"
```

### Task 4: Runner Registry And Pipeline Runtime

**Files:**
- Create: `crates/e-navigator-runner/Cargo.toml`
- Create: `crates/e-navigator-runner/src/lib.rs`
- Create: `crates/e-navigator-runner/src/registry.rs`
- Create: `crates/e-navigator-runner/src/runtime.rs`

- [ ] **Step 1: Write the manifest**

Create `crates/e-navigator-runner/Cargo.toml`:

```toml
[package]
name = "e-navigator-runner"
edition.workspace = true
license.workspace = true
version.workspace = true

[dependencies]
async-trait = { workspace = true }
e-navigator-core = { path = "../e-navigator-core" }
e-navigator-signals = { path = "../e-navigator-signals" }
tokio = { workspace = true }
tracing = { workspace = true }
```

- [ ] **Step 2: Write exports**

Create `crates/e-navigator-runner/src/lib.rs`:

```rust
pub mod registry;
pub mod runtime;

pub use registry::ModuleRegistry;
pub use runtime::Runner;
```

- [ ] **Step 3: Write module registry**

Create `crates/e-navigator-runner/src/registry.rs`:

```rust
use e_navigator_core::{Generator, Processor, Sink, Source};
use e_navigator_signals::SignalEnvelope;

#[derive(Default)]
pub struct ModuleRegistry {
    pub sources: Vec<Box<dyn Source<SignalEnvelope>>>,
    pub processors: Vec<Box<dyn Processor<SignalEnvelope>>>,
    pub generators: Vec<Box<dyn Generator<SignalEnvelope>>>,
    pub sinks: Vec<Box<dyn Sink<SignalEnvelope>>>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_source(mut self, source: Box<dyn Source<SignalEnvelope>>) -> Self {
        self.sources.push(source);
        self
    }

    pub fn with_processor(mut self, processor: Box<dyn Processor<SignalEnvelope>>) -> Self {
        self.processors.push(processor);
        self
    }

    pub fn with_generator(mut self, generator: Box<dyn Generator<SignalEnvelope>>) -> Self {
        self.generators.push(generator);
        self
    }

    pub fn with_sink(mut self, sink: Box<dyn Sink<SignalEnvelope>>) -> Self {
        self.sinks.push(sink);
        self
    }

    pub fn module_count(&self) -> usize {
        self.sources.len() + self.processors.len() + self.generators.len() + self.sinks.len()
    }

    pub fn has_source_and_sink(&self) -> bool {
        !self.sources.is_empty() && !self.sinks.is_empty()
    }
}
```

- [ ] **Step 4: Write runtime orchestration**

Create `crates/e-navigator-runner/src/runtime.rs`:

```rust
use e_navigator_core::{CoreError, CoreResult, RuntimeConfig};
use e_navigator_signals::SignalEnvelope;
use tokio::sync::mpsc;
use tracing::debug;

use crate::ModuleRegistry;

pub struct Runner {
    config: RuntimeConfig,
    registry: ModuleRegistry,
}

impl Runner {
    pub fn new(config: RuntimeConfig, registry: ModuleRegistry) -> CoreResult<Self> {
        config.validate().map_err(CoreError::InvalidConfig)?;

        if registry.module_count() == 0 {
            return Err(CoreError::InvalidConfig(
                "at least one registered module is required".to_string(),
            ));
        }

        if !registry.has_source_and_sink() {
            return Err(CoreError::InvalidConfig(
                "at least one source and one sink are required".to_string(),
            ));
        }

        Ok(Self { config, registry })
    }

    pub async fn run(mut self) -> CoreResult<()> {
        let (tx, mut rx) = mpsc::channel::<SignalEnvelope>(self.config.queue_capacity);
        let (source_result_tx, mut source_result_rx) = mpsc::channel::<CoreResult<()>>(self.registry.sources.len());

        for source in self.registry.sources.drain(..) {
            let source_tx = tx.clone();
            let result_tx = source_result_tx.clone();
            let name = source.metadata().name.to_string();
            tokio::spawn(async move {
                let result = source.run(source_tx).await.map_err(|err| CoreError::ModuleFailed {
                    module: name,
                    message: err.to_string(),
                });
                let _ = result_tx.send(result).await;
            });
        }
        drop(tx);
        drop(source_result_tx);
        let mut source_results_open = true;

        loop {
            tokio::select! {
                source_result = source_result_rx.recv(), if source_results_open => {
                    match source_result {
                        Some(Ok(())) => debug!("source exited cleanly"),
                        Some(Err(err)) => return Err(err),
                        None => source_results_open = false,
                    }
                }
                signal = rx.recv() => {
                    match signal {
                        Some(signal) => self.handle_signal(signal).await?,
                        None => return Ok(()),
                    }
                }
            }
        }
    }

    async fn handle_signal(&self, mut signal: SignalEnvelope) -> CoreResult<()> {
        let mut dropped = false;

        for processor in &self.registry.processors {
            match processor.process(signal).await? {
                Some(processed) => signal = processed,
                None => {
                    dropped = true;
                    break;
                }
            }
        }

        if dropped {
            debug!("signal dropped by processor");
            return Ok(());
        }

        for generator in &self.registry.generators {
            let (derived_tx, mut derived_rx) = mpsc::channel(16);
            generator.observe(&signal, &derived_tx).await?;
            drop(derived_tx);
            while let Some(derived) = derived_rx.recv().await {
                for sink in &self.registry.sinks {
                    sink.write(&derived).await?;
                }
            }
        }

        for sink in &self.registry.sinks {
            sink.write(&signal).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use e_navigator_core::{CoreResult, ModuleKind, ModuleMetadata, Sink, Source};
    use e_navigator_signals::{ExecEvent, SignalEnvelope};
    use tokio::sync::{mpsc, Mutex};

    use super::*;
    use std::sync::Arc;

    struct OneSignalSource;

    #[async_trait]
    impl Source<SignalEnvelope> for OneSignalSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.test", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            let signal = SignalEnvelope::exec(
                "source.test",
                None,
                ExecEvent {
                    pid: 1,
                    ppid: None,
                    uid: None,
                    command: "true".to_string(),
                    executable: Some("/usr/bin/true".to_string()),
                    arguments: vec![],
                    cgroup_id: None,
                    timestamp_unix_nanos: 1,
                    container: None,
                    kubernetes: None,
                },
            );
            tx.send(signal).await.map_err(|_| CoreError::PipelineClosed)
        }
    }

    struct MemorySink {
        seen: Arc<Mutex<Vec<SignalEnvelope>>>,
    }

    #[async_trait]
    impl Sink<SignalEnvelope> for MemorySink {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("sink.memory", ModuleKind::Sink)
        }

        async fn write(&self, signal: &SignalEnvelope) -> CoreResult<()> {
            self.seen.lock().await.push(signal.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn runner_routes_source_signal_to_sink() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let registry = ModuleRegistry::new()
            .with_source(Box::new(OneSignalSource))
            .with_sink(Box::new(MemorySink { seen: seen.clone() }));
        let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

        runner.run().await.expect("runner exits after source closes");

        assert_eq!(seen.lock().await.len(), 1);
    }
}
```

- [ ] **Step 5: Run tests**

Run:

```bash
cargo test -p e-navigator-runner
```

Expected: tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/e-navigator-runner
git commit -m "feat: add pipeline runner"
```

### Task 5: JSON Stdout Sink

**Files:**
- Create: `crates/e-navigator-sinks/Cargo.toml`
- Create: `crates/e-navigator-sinks/src/lib.rs`
- Create: `crates/e-navigator-sinks/src/json_stdout.rs`

- [ ] **Step 1: Write the manifest**

Create `crates/e-navigator-sinks/Cargo.toml`:

```toml
[package]
name = "e-navigator-sinks"
edition.workspace = true
license.workspace = true
version.workspace = true

[dependencies]
async-trait = { workspace = true }
e-navigator-core = { path = "../e-navigator-core" }
e-navigator-signals = { path = "../e-navigator-signals" }
serde_json = { workspace = true }
tokio = { workspace = true }
```

- [ ] **Step 2: Write exports**

Create `crates/e-navigator-sinks/src/lib.rs`:

```rust
pub mod json_stdout;

pub use json_stdout::JsonStdoutSink;
```

- [ ] **Step 3: Write JSON stdout sink**

Create `crates/e-navigator-sinks/src/json_stdout.rs`:

```rust
use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Sink};
use e_navigator_signals::SignalEnvelope;
use tokio::io::{self, AsyncWriteExt};

#[derive(Debug, Default)]
pub struct JsonStdoutSink;

#[async_trait]
impl Sink<SignalEnvelope> for JsonStdoutSink {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("sink.json_stdout", ModuleKind::Sink)
    }

    async fn write(&self, signal: &SignalEnvelope) -> CoreResult<()> {
        let mut line = serde_json::to_vec(signal).map_err(|err| CoreError::ModuleFailed {
            module: "sink.json_stdout".to_string(),
            message: err.to_string(),
        })?;
        line.push(b'\n');
        io::stdout()
            .write_all(&line)
            .await
            .map_err(|err| CoreError::ModuleFailed {
                module: "sink.json_stdout".to_string(),
                message: err.to_string(),
            })
    }
}
```

- [ ] **Step 4: Run tests and build**

Run:

```bash
cargo test -p e-navigator-sinks
cargo build -p e-navigator-sinks
```

Expected: both commands pass.

- [ ] **Step 5: Commit**

```bash
git add crates/e-navigator-sinks
git commit -m "feat: add json stdout sink"
```

### Task 6: Container Attribution Processor Stub

**Files:**
- Create: `crates/e-navigator-processors/Cargo.toml`
- Create: `crates/e-navigator-processors/src/lib.rs`
- Create: `crates/e-navigator-processors/src/container_attribution.rs`

- [ ] **Step 1: Write the manifest**

Create `crates/e-navigator-processors/Cargo.toml`:

```toml
[package]
name = "e-navigator-processors"
edition.workspace = true
license.workspace = true
version.workspace = true

[dependencies]
async-trait = { workspace = true }
e-navigator-core = { path = "../e-navigator-core" }
e-navigator-signals = { path = "../e-navigator-signals" }
```

- [ ] **Step 2: Write exports**

Create `crates/e-navigator-processors/src/lib.rs`:

```rust
pub mod container_attribution;

pub use container_attribution::ContainerAttributionProcessor;
```

- [ ] **Step 3: Write attribution processor**

Create `crates/e-navigator-processors/src/container_attribution.rs`:

```rust
use async_trait::async_trait;
use e_navigator_core::{CoreResult, ModuleKind, ModuleMetadata, Processor};
use e_navigator_signals::{SignalEnvelope, SignalPayload};

#[derive(Debug, Default)]
pub struct ContainerAttributionProcessor;

#[async_trait]
impl Processor<SignalEnvelope> for ContainerAttributionProcessor {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("processor.container_attribution", ModuleKind::Processor)
    }

    async fn process(&self, mut signal: SignalEnvelope) -> CoreResult<Option<SignalEnvelope>> {
        match &mut signal.payload {
            SignalPayload::Exec(event) => {
                if event.cgroup_id.is_none() {
                    event.container = None;
                    event.kubernetes = None;
                }
            }
        }

        Ok(Some(signal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_signals::ExecEvent;

    #[tokio::test]
    async fn processor_preserves_exec_event() {
        let processor = ContainerAttributionProcessor;
        let signal = SignalEnvelope::exec(
            "source.test",
            None,
            ExecEvent {
                pid: 7,
                ppid: Some(1),
                uid: Some(1000),
                command: "sh".to_string(),
                executable: Some("/bin/sh".to_string()),
                arguments: vec!["sh".to_string()],
                cgroup_id: None,
                timestamp_unix_nanos: 99,
                container: None,
                kubernetes: None,
            },
        );

        let processed = processor
            .process(signal)
            .await
            .expect("processor succeeds")
            .expect("signal remains");

        assert!(matches!(processed.payload, e_navigator_signals::SignalPayload::Exec(_)));
    }
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
cargo test -p e-navigator-processors
```

Expected: tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/e-navigator-processors
git commit -m "feat: add container attribution processor"
```

### Task 7: CLI Entrypoint With Synthetic Source

**Files:**
- Create: `crates/e-navigator-cli/Cargo.toml`
- Create: `crates/e-navigator-cli/src/main.rs`
- Modify: `Cargo.toml`

- [ ] **Step 1: Write the CLI manifest**

Create `crates/e-navigator-cli/Cargo.toml`:

```toml
[package]
name = "e-navigator-cli"
edition.workspace = true
license.workspace = true
version.workspace = true

[[bin]]
name = "e-navigator"
path = "src/main.rs"

[dependencies]
async-trait = { workspace = true }
clap = { workspace = true }
e-navigator-core = { path = "../e-navigator-core" }
e-navigator-processors = { path = "../e-navigator-processors" }
e-navigator-runner = { path = "../e-navigator-runner" }
e-navigator-signals = { path = "../e-navigator-signals" }
e-navigator-sinks = { path = "../e-navigator-sinks" }
tokio = { workspace = true }
toml = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
```

- [ ] **Step 2: Write the CLI with a synthetic source**

Create `crates/e-navigator-cli/src/main.rs`:

```rust
use async_trait::async_trait;
use clap::{Parser, ValueEnum};
use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, RuntimeConfig, Source};
use e_navigator_processors::ContainerAttributionProcessor;
use e_navigator_runner::{ModuleRegistry, Runner};
use e_navigator_signals::{ExecEvent, SignalEnvelope};
use e_navigator_sinks::JsonStdoutSink;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "e-navigator")]
#[command(about = "E-Navigator node agent")]
struct Args {
    #[arg(long, value_enum, default_value_t = SourceMode::Synthetic)]
    source: SourceMode,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SourceMode {
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
```

- [ ] **Step 3: Add `anyhow` to the CLI manifest**

Modify `crates/e-navigator-cli/Cargo.toml` by adding this dependency under `[dependencies]`:

```toml
anyhow = { workspace = true }
```

- [ ] **Step 4: Run the CLI**

Run:

```bash
cargo run -p e-navigator-cli -- --source synthetic
```

Expected: stdout contains one JSON line with `"source":"source.synthetic_exec"` and `"kind":"exec"`.

- [ ] **Step 5: Run checks**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: all commands pass.

- [ ] **Step 6: Commit**

```bash
git add crates/e-navigator-cli Cargo.toml
git commit -m "feat: add local runner cli"
```

### Task 8: Aya Exec Source And eBPF Program

**Files:**
- Create: `crates/e-navigator-ebpf-programs/Cargo.toml`
- Create: `crates/e-navigator-ebpf-programs/src/main.rs`
- Create: `crates/e-navigator-sources-ebpf-aya/Cargo.toml`
- Create: `crates/e-navigator-sources-ebpf-aya/build.rs`
- Create: `crates/e-navigator-sources-ebpf-aya/src/lib.rs`
- Create: `crates/e-navigator-sources-ebpf-aya/src/exec.rs`
- Modify: `Cargo.toml`
- Modify: `crates/e-navigator-cli/Cargo.toml`
- Modify: `crates/e-navigator-cli/src/main.rs`

- [ ] **Step 1: Add the eBPF program member to the workspace**

Modify root `Cargo.toml` by adding `crates/e-navigator-ebpf-programs` to `members`, but not to `default-members`:

```toml
"crates/e-navigator-ebpf-programs",
```

Expected: the eBPF crate is buildable by the Aya build step but does not run in default non-privileged workspace checks.

- [ ] **Step 2: Write the eBPF program manifest**

Create `crates/e-navigator-ebpf-programs/Cargo.toml`:

```toml
[package]
name = "e-navigator-ebpf-programs"
edition.workspace = true
license.workspace = true
version.workspace = true
publish = false

[dependencies]
aya-ebpf = { workspace = true }
aya-log-ebpf = { workspace = true }

[[bin]]
name = "e-navigator-ebpf-programs"
path = "src/main.rs"
```

- [ ] **Step 3: Write the eBPF tracepoint program**

Create `crates/e-navigator-ebpf-programs/src/main.rs`:

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub command: [u8; 16],
}

#[map]
static EXEC_EVENTS: PerfEventArray<RawExecEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn tracepoint_execve(ctx: TracePointContext) -> u32 {
    match try_tracepoint_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let event = RawExecEvent {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        command: bpf_get_current_comm().map_err(|err| err as i64)?,
    };

    EXEC_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
```

- [ ] **Step 4: Write the Aya source manifest**

Create `crates/e-navigator-sources-ebpf-aya/Cargo.toml`:

```toml
[package]
name = "e-navigator-sources-ebpf-aya"
edition.workspace = true
license.workspace = true
version.workspace = true

[dependencies]
async-trait = { workspace = true }
aya = { workspace = true }
bytes = { workspace = true }
e-navigator-core = { path = "../e-navigator-core" }
e-navigator-signals = { path = "../e-navigator-signals" }
libc = { workspace = true }
tokio = { workspace = true, features = ["io-util"] }
tracing = { workspace = true }

[build-dependencies]
anyhow = { workspace = true }
aya-build = { workspace = true }
```

- [ ] **Step 5: Write the eBPF build script**

Create `crates/e-navigator-sources-ebpf-aya/build.rs`:

```rust
fn main() -> anyhow::Result<()> {
    aya_build::build_ebpf([("../e-navigator-ebpf-programs", "e-navigator-ebpf-programs")])?;
    Ok(())
}
```

- [ ] **Step 6: Write source exports**

Create `crates/e-navigator-sources-ebpf-aya/src/lib.rs`:

```rust
pub mod exec;

pub use exec::AyaExecSource;
```

- [ ] **Step 7: Write the userspace Aya exec source**

Create `crates/e-navigator-sources-ebpf-aya/src/exec.rs`:

```rust
use async_trait::async_trait;
use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::TracePoint,
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Source};
use e_navigator_signals::{ExecEvent, SignalEnvelope};
use tokio::sync::mpsc;
use tracing::{debug, warn};

#[repr(C)]
#[derive(Clone, Copy)]
struct RawExecEvent {
    pid: u32,
    uid: u32,
    command: [u8; 16],
}

#[derive(Debug, Default)]
pub struct AyaExecSource {
    host: Option<String>,
}

impl AyaExecSource {
    pub fn new(host: Option<String>) -> Self {
        Self { host }
    }
}

#[async_trait]
impl Source<SignalEnvelope> for AyaExecSource {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("source.aya_exec", ModuleKind::Source)
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
        bump_memlock_rlimit();

        let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/e-navigator-ebpf-programs"
        )))
        .map_err(|err| CoreError::ModuleFailed {
            module: "source.aya_exec".to_string(),
            message: err.to_string(),
        })?;

        let program: &mut TracePoint = ebpf
            .program_mut("tracepoint_execve")
            .ok_or_else(|| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: "missing tracepoint_execve program".to_string(),
            })?
            .try_into()
            .map_err(|err: aya::programs::ProgramError| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })?;
        program.load().map_err(|err| CoreError::ModuleFailed {
            module: "source.aya_exec".to_string(),
            message: err.to_string(),
        })?;
        program
            .attach("syscalls", "sys_enter_execve")
            .map_err(|err| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })?;

        let mut perf_array = AsyncPerfEventArray::try_from(
            ebpf.take_map("EXEC_EVENTS")
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: "missing EXEC_EVENTS map".to_string(),
                })?,
        )
        .map_err(|err| CoreError::ModuleFailed {
            module: "source.aya_exec".to_string(),
            message: err.to_string(),
        })?;

        for cpu_id in online_cpus().map_err(|(_, err)| CoreError::ModuleFailed {
            module: "source.aya_exec".to_string(),
            message: err.to_string(),
        })? {
            let mut buffer = perf_array.open(cpu_id, None).map_err(|err| {
                CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                }
            })?;
            let cpu_tx = tx.clone();
            let host = self.host.clone();

            tokio::spawn(async move {
                let mut buffers = (0..16)
                    .map(|_| BytesMut::with_capacity(core::mem::size_of::<RawExecEvent>()))
                    .collect::<Vec<_>>();

                loop {
                    match buffer.read_events(&mut buffers).await {
                        Ok(events) => {
                            for index in 0..events.read {
                                if let Some(signal) = raw_to_signal(&buffers[index], host.clone()) {
                                    if cpu_tx.send(signal).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                        Err(err) => warn!(error = %err, "failed to read exec perf events"),
                    }
                }
            });
        }

        debug!("aya exec source attached");
        tokio::signal::ctrl_c()
            .await
            .map_err(|err| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })
    }
}

fn raw_to_signal(bytes: &[u8], host: Option<String>) -> Option<SignalEnvelope> {
    if bytes.len() < core::mem::size_of::<RawExecEvent>() {
        return None;
    }

    let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawExecEvent>()) };
    let command = command_to_string(&raw.command);

    Some(SignalEnvelope::exec(
        "source.aya_exec",
        host,
        ExecEvent {
            pid: raw.pid,
            ppid: None,
            uid: Some(raw.uid),
            command,
            executable: None,
            arguments: vec![],
            cgroup_id: None,
            timestamp_unix_nanos: 0,
            container: None,
            kubernetes: None,
        },
    ))
}

fn command_to_string(command: &[u8; 16]) -> String {
    let end = command
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(command.len());
    String::from_utf8_lossy(&command[..end]).to_string()
}

fn bump_memlock_rlimit() {
    let rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };
    if ret != 0 {
        debug!("failed to raise RLIMIT_MEMLOCK");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_bytes_convert_to_string() {
        let mut command = [0_u8; 16];
        command[..4].copy_from_slice(b"bash");
        assert_eq!(command_to_string(&command), "bash");
    }
}
```

- [ ] **Step 8: Wire Aya source into CLI**

Modify `crates/e-navigator-cli/Cargo.toml` by adding:

```toml
e-navigator-sources-ebpf-aya = { path = "../e-navigator-sources-ebpf-aya" }
```

Modify `crates/e-navigator-cli/src/main.rs`:

```rust
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
        SourceMode::AyaExec => ModuleRegistry::new().with_source(Box::new(AyaExecSource::new(None))),
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
```

- [ ] **Step 9: Run non-privileged checks**

Run:

```bash
cargo fmt --all -- --check
cargo test -p e-navigator-sources-ebpf-aya
cargo test --workspace --exclude e-navigator-ebpf-programs
```

Expected: tests pass.

- [ ] **Step 10: Run privileged local smoke test on Linux**

Run on a Linux host with Aya prerequisites installed:

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo run -p e-navigator-cli --release -- --source aya-exec
```

In another shell, run:

```bash
/bin/true
```

Expected: the runner prints a JSON exec signal with `"source":"source.aya_exec"` and a command value such as `"true"`, `"bash"`, or the invoking shell.

- [ ] **Step 11: Commit**

```bash
git add Cargo.toml crates/e-navigator-ebpf-programs crates/e-navigator-sources-ebpf-aya crates/e-navigator-cli
git commit -m "feat: add aya exec source"
```

### Task 9: Kubernetes Packaging

**Files:**
- Create: `deploy/kubernetes/namespace.yaml`
- Create: `deploy/kubernetes/rbac.yaml`
- Create: `deploy/kubernetes/configmap.yaml`
- Create: `deploy/kubernetes/daemonset.yaml`

- [ ] **Step 1: Write namespace manifest**

Create `deploy/kubernetes/namespace.yaml`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: e-navigator-system
  labels:
    app.kubernetes.io/name: e-navigator
```

- [ ] **Step 2: Write RBAC manifest**

Create `deploy/kubernetes/rbac.yaml`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: e-navigator
  namespace: e-navigator-system
  labels:
    app.kubernetes.io/name: e-navigator
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: e-navigator
  labels:
    app.kubernetes.io/name: e-navigator
rules:
  - apiGroups: [""]
    resources: ["nodes", "pods", "namespaces"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: e-navigator
  labels:
    app.kubernetes.io/name: e-navigator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: e-navigator
subjects:
  - kind: ServiceAccount
    name: e-navigator
    namespace: e-navigator-system
```

- [ ] **Step 3: Write ConfigMap**

Create `deploy/kubernetes/configmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: e-navigator-config
  namespace: e-navigator-system
  labels:
    app.kubernetes.io/name: e-navigator
data:
  e-navigator.toml: |
    log_level = "info"
    queue_capacity = 1024

    [[modules]]
    name = "source.aya_exec"
    enabled = true

    [[modules]]
    name = "processor.container_attribution"
    enabled = true

    [[modules]]
    name = "sink.json_stdout"
    enabled = true
```

- [ ] **Step 4: Write DaemonSet**

Create `deploy/kubernetes/daemonset.yaml`:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: e-navigator
  namespace: e-navigator-system
  labels:
    app.kubernetes.io/name: e-navigator
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: e-navigator
  template:
    metadata:
      labels:
        app.kubernetes.io/name: e-navigator
    spec:
      serviceAccountName: e-navigator
      hostPID: true
      containers:
        - name: e-navigator
          image: ghcr.io/victorbona/e-navigator:dev
          imagePullPolicy: IfNotPresent
          args:
            - "--source"
            - "aya-exec"
          env:
            - name: RUST_LOG
              value: "info"
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          securityContext:
            privileged: true
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: true
          volumeMounts:
            - name: config
              mountPath: /etc/e-navigator
              readOnly: true
            - name: sys-kernel-debug
              mountPath: /sys/kernel/debug
            - name: sys-kernel-tracing
              mountPath: /sys/kernel/tracing
      volumes:
        - name: config
          configMap:
            name: e-navigator-config
        - name: sys-kernel-debug
          hostPath:
            path: /sys/kernel/debug
            type: DirectoryOrCreate
        - name: sys-kernel-tracing
          hostPath:
            path: /sys/kernel/tracing
            type: DirectoryOrCreate
```

- [ ] **Step 5: Validate manifests client-side**

Run:

```bash
kubectl apply --dry-run=client -f deploy/kubernetes/namespace.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/rbac.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/configmap.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/daemonset.yaml
```

Expected: each command reports the resource as configured or created in dry-run mode.

- [ ] **Step 6: Commit**

```bash
git add deploy/kubernetes
git commit -m "feat: add kubernetes daemonset packaging"
```

### Task 10: ADRs And Developer Documentation

**Files:**
- Create: `docs/adr/0001-aya-first.md`
- Create: `docs/adr/0002-static-pipeline-registration.md`
- Create: `docs/adr/0003-kubernetes-privilege-model.md`
- Create: `docs/development/local-linux.md`
- Create: `docs/development/kubernetes.md`

- [ ] **Step 1: Write Aya ADR**

Create `docs/adr/0001-aya-first.md`:

```markdown
# ADR 0001: Use Aya As The First eBPF Stack

## Status

Accepted

## Context

E-Navigator is a Rust-first observability and diagnostics platform. The first phase needs a process exec eBPF source while preserving a long-term path for many probes.

## Decision

Use Aya as the first eBPF stack for userspace loading and kernel-side Rust eBPF programs.

## Consequences

- The project stays Rust-native across userspace and eBPF code.
- eBPF implementation details stay behind source boundaries.
- A future `libbpf-rs` backend remains possible if a specific probe or kernel compatibility requirement justifies it.
```

- [ ] **Step 2: Write static registration ADR**

Create `docs/adr/0002-static-pipeline-registration.md`:

```markdown
# ADR 0002: Use Static Pipeline Registration

## Status

Accepted

## Context

E-Navigator needs to make it easy to add sources, processors, generators, and sinks while keeping the node agent predictable and reviewable.

## Decision

All phase 1 modules are compiled into the binary and registered statically in code.

## Consequences

- Deployment is a single node-agent binary.
- Runtime-loaded external plugins are outside phase 1.
- New capabilities are added by implementing a pipeline trait, registering the module, adding config, and adding tests.
```

- [ ] **Step 3: Write Kubernetes privilege ADR**

Create `docs/adr/0003-kubernetes-privilege-model.md`:

```markdown
# ADR 0003: Start With A Conservative Kubernetes Privilege Model

## Status

Accepted

## Context

The phase 1 DaemonSet must load and attach eBPF programs on Kubernetes nodes. Exact privilege requirements vary by kernel, distribution, container runtime, and cluster policy.

## Decision

Start with a privileged DaemonSet for the first working Kubernetes smoke test. Document this as an initial compatibility choice, not the final security posture.

## Consequences

- The first Kubernetes deployment has the highest chance of working across development clusters.
- Privilege reduction becomes an explicit hardening task after the first eBPF attach path is proven.
- The DaemonSet still uses a dedicated namespace, ServiceAccount, and scoped read-only Kubernetes metadata RBAC.
```

- [ ] **Step 4: Write local Linux development guide**

Create `docs/development/local-linux.md`:

````markdown
# Local Linux Development

## Non-Privileged Checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --exclude e-navigator-ebpf-programs
cargo build --workspace --exclude e-navigator-ebpf-programs
```

## Aya Prerequisites

Install the Rust nightly toolchain with `rust-src`, `bpf-linker`, and `bpftool`:

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

Install `bpftool` from the Linux distribution package manager.

## Synthetic Runner

```bash
cargo run -p e-navigator-cli -- --source synthetic
```

Expected result: one newline-delimited JSON exec signal is printed to stdout.

## Privileged Aya Exec Smoke Test

```bash
cargo run -p e-navigator-cli --release -- --source aya-exec
```

In another shell:

```bash
/bin/true
```

Expected result: the runner prints JSON exec signals from `source.aya_exec`.
````

- [ ] **Step 5: Write Kubernetes guide**

Create `docs/development/kubernetes.md`:

````markdown
# Kubernetes Development

## Deployment Model

E-Navigator runs as one DaemonSet pod per node. Each pod runs one `e-navigator` process with statically registered internal modules.

## Apply Manifests

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

## Check Rollout

```bash
kubectl -n e-navigator-system rollout status daemonset/e-navigator
kubectl -n e-navigator-system get pods -o wide
```

Expected result: one ready `e-navigator` pod per schedulable node.

## Generate Exec Events

```bash
kubectl run e-navigator-exec-smoke --rm -it --restart=Never --image=busybox:1.36 -- sh -c 'echo smoke'
```

## Read Agent Logs

```bash
kubectl -n e-navigator-system logs -l app.kubernetes.io/name=e-navigator --tail=100
```

Expected result: JSON exec signals are visible in the DaemonSet logs.
````

- [ ] **Step 6: Commit**

```bash
git add docs/adr docs/development
git commit -m "docs: add foundation decisions and runbooks"
```

### Task 11: CI Baseline

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  rust:
    name: Rust checks
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy,rustfmt

      - name: Install eBPF build prerequisites
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm
          rustup toolchain install nightly --component rust-src
          cargo install bpf-linker

      - name: Cache Cargo
        uses: Swatinem/rust-cache@v2

      - name: Format
        run: cargo fmt --all -- --check

      - name: Clippy
        run: cargo clippy --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings

      - name: Test
        run: cargo test --workspace --exclude e-navigator-ebpf-programs

      - name: Build
        run: cargo build --workspace --exclude e-navigator-ebpf-programs

  manifests:
    name: Kubernetes manifest checks
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install kubectl
        uses: azure/setup-kubectl@v4

      - name: Validate manifests
        run: |
          kubectl apply --dry-run=client -f deploy/kubernetes/namespace.yaml
          kubectl apply --dry-run=client -f deploy/kubernetes/rbac.yaml
          kubectl apply --dry-run=client -f deploy/kubernetes/configmap.yaml
          kubectl apply --dry-run=client -f deploy/kubernetes/daemonset.yaml
```

- [ ] **Step 2: Run CI-equivalent local checks**

Run:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --workspace --exclude e-navigator-ebpf-programs
cargo build --workspace --exclude e-navigator-ebpf-programs
kubectl apply --dry-run=client -f deploy/kubernetes/namespace.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/rbac.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/configmap.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/daemonset.yaml
```

Expected: all commands pass.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add foundation checks"
```

### Task 12: Final Foundation Verification

**Files:**
- Modify: `README.md`
- Modify: any files required to fix verification failures.

- [ ] **Step 1: Run full non-privileged verification**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --workspace --exclude e-navigator-ebpf-programs
cargo build --workspace --exclude e-navigator-ebpf-programs
cargo run -p e-navigator-cli -- --source synthetic
git diff --check
git status --short
```

Expected:

- Format check passes.
- Clippy passes.
- Tests pass.
- Build passes.
- Synthetic runner prints one JSON exec signal.
- `git diff --check` prints no whitespace errors.
- `git status --short` shows only intentional uncommitted files.

- [ ] **Step 2: Run privileged verification where available**

On a Linux host with required eBPF tooling:

```bash
cargo run -p e-navigator-cli --release -- --source aya-exec
```

In another shell:

```bash
/bin/true
```

Expected: logs include JSON exec signals from `source.aya_exec`.

- [ ] **Step 3: Run Kubernetes verification where available**

In a development cluster with an image containing the built `e-navigator` binary:

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml
kubectl -n e-navigator-system rollout status daemonset/e-navigator
kubectl run e-navigator-exec-smoke --rm -it --restart=Never --image=busybox:1.36 -- sh -c 'echo smoke'
kubectl -n e-navigator-system logs -l app.kubernetes.io/name=e-navigator --tail=100
```

Expected:

- DaemonSet rolls out successfully.
- One pod runs per schedulable node.
- DaemonSet logs contain exec signals.

- [ ] **Step 4: Update README command summary**

Modify `README.md` to include the final commands that passed locally:

````markdown
## Verification

Non-privileged checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --workspace --exclude e-navigator-ebpf-programs
cargo build --workspace --exclude e-navigator-ebpf-programs
cargo run -p e-navigator-cli -- --source synthetic
```

Privileged eBPF smoke test on Linux:

```bash
cargo run -p e-navigator-cli --release -- --source aya-exec
```
````

- [ ] **Step 5: Commit final verification docs**

```bash
git add README.md
git commit -m "docs: add foundation verification commands"
```

## Self-Review Checklist

- Spec coverage: Tasks 1, 10, and 11 cover developer foundation, ADRs, docs, and CI. Tasks 2 through 7 cover core contracts, signal schemas, pipeline runtime, sink, processor, and local runner. Task 8 covers Aya process exec. Task 9 covers Kubernetes packaging. Task 12 covers final verification.
- Scope control: The plan does not include OTLP, UI, storage, network mapping, DNS, tracing, profiling, cost attribution, capacity planning, or runtime-loaded plugins.
- Type consistency: The plan consistently uses `SignalEnvelope`, `ExecEvent`, `Source`, `Processor`, `Generator`, `Sink`, `ModuleRegistry`, `Runner`, `AyaExecSource`, `ContainerAttributionProcessor`, and `JsonStdoutSink`.
- Privileged boundaries: Non-privileged checks exclude `e-navigator-ebpf-programs`; privileged eBPF and Kubernetes tests are separate documented verification steps.
