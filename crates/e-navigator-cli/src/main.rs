#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]

mod args;
mod config;
mod registry;
mod synthetic;
mod time;

use args::Args;
use clap::Parser;
use e_navigator_runner::Runner;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = config::load_config(args.config.as_deref())?;
    if args.validate_config {
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(config.log_level.clone())),
        )
        .init();

    // Start the shared, node-wide capture-filter controller before any source
    // loads its eBPF object, so the membership map is populated as sources come
    // up. A no-op when the filter is disabled.
    e_navigator_sources_ebpf_aya::capture_filter::init_shared(
        &config.capture_filter,
        &config.attribution.kubernetes,
        config.attribution.cgroup_root.clone(),
        registry::node_name(),
    );

    let registry = registry::build_registry(&config, args.source, registry::node_name())?;

    Runner::new(config, registry)?.run().await?;
    Ok(())
}
