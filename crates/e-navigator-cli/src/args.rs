use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "e-navigator", version)]
#[command(about = "E-Navigator node agent")]
pub(crate) struct Args {
    #[arg(long, value_enum, default_value_t = SourceMode::AyaExec)]
    pub(crate) source: SourceMode,

    #[arg(long, env = "E_NAVIGATOR_CONFIG")]
    pub(crate) config: Option<PathBuf>,

    #[arg(long)]
    pub(crate) validate_config: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum SourceMode {
    AyaExec,
    AyaCpuProfile,
    Synthetic,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_args_match_existing_cli_behavior() {
        let args = Args::parse_from(["e-navigator"]);

        assert_eq!(args.source, SourceMode::AyaExec);
        assert_eq!(args.config, None);
        assert!(!args.validate_config);
    }

    #[test]
    fn parses_every_supported_source_mode() {
        for (raw, expected) in [
            ("aya-exec", SourceMode::AyaExec),
            ("aya-cpu-profile", SourceMode::AyaCpuProfile),
            ("synthetic", SourceMode::Synthetic),
        ] {
            let args = Args::parse_from(["e-navigator", "--source", raw]);

            assert_eq!(args.source, expected);
        }
    }

    #[test]
    fn parses_config_and_validate_config_flags() {
        let args = Args::parse_from([
            "e-navigator",
            "--config",
            "fixtures/e-navigator.toml",
            "--validate-config",
        ]);

        assert_eq!(
            args.config,
            Some(PathBuf::from("fixtures/e-navigator.toml"))
        );
        assert!(args.validate_config);
    }
}
