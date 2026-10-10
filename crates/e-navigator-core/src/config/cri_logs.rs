use super::{ConfigError, ConfigResult, bounds::validate_inclusive, filesystem_paths};
use serde::{Deserialize, Serialize};
use std::path::{Component, PathBuf};

/// Opt-in CRI file collection. Checkpoints acknowledge pipeline admission only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CriLogsConfig {
    pub enabled: bool,
    /// Explicit permission to put bounded application payloads in native signals.
    pub include_body: bool,
    pub root: PathBuf,
    pub checkpoint_dir: PathBuf,
    pub initial_read: LogInitialRead,
    pub poll_interval_millis: u64,
    pub assembly_timeout_millis: u64,
    pub retained_file_millis: u64,
    pub max_files: usize,
    pub max_discovery_entries: usize,
    pub max_record_bytes: usize,
    pub max_read_bytes_per_file: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogInitialRead {
    #[default]
    Beginning,
    End,
}

impl Default for CriLogsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            include_body: false,
            root: "/var/log/pods".into(),
            checkpoint_dir: "/var/lib/e-navigator/cri-logs".into(),
            initial_read: LogInitialRead::Beginning,
            poll_interval_millis: 1000,
            assembly_timeout_millis: 5000,
            retained_file_millis: 300_000,
            max_files: 128,
            max_discovery_entries: 4096,
            max_record_bytes: 16_384,
            max_read_bytes_per_file: 65_536,
        }
    }
}

impl CriLogsConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        for (name, path) in [
            ("cri_logs.root", &self.root),
            ("cri_logs.checkpoint_dir", &self.checkpoint_dir),
        ] {
            filesystem_paths::validate_len(name, path)?;
            if !path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
                || path == std::path::Path::new("/")
                || path
                    .to_str()
                    .is_none_or(|p| p.bytes().any(|b| b.is_ascii_control()))
            {
                return Err(ConfigError::invalid_value(
                    name,
                    "must be an absolute, non-root path without traversal or control characters",
                ));
            }
        }
        if self.root.starts_with(&self.checkpoint_dir)
            || self.checkpoint_dir.starts_with(&self.root)
        {
            return Err(ConfigError::invalid_value(
                "cri_logs.checkpoint_dir",
                "log and checkpoint roots must not overlap",
            ));
        }
        validate_inclusive(
            "cri_logs.poll_interval_millis",
            self.poll_interval_millis,
            1,
            60_000,
        )?;
        validate_inclusive(
            "cri_logs.assembly_timeout_millis",
            self.assembly_timeout_millis,
            self.poll_interval_millis,
            3_600_000,
        )?;
        validate_inclusive(
            "cri_logs.retained_file_millis",
            self.retained_file_millis,
            self.assembly_timeout_millis,
            86_400_000,
        )?;
        validate_inclusive("cri_logs.max_files", self.max_files, 1, 1024)?;
        validate_inclusive(
            "cri_logs.max_discovery_entries",
            self.max_discovery_entries,
            self.max_files,
            65_536,
        )?;
        validate_inclusive(
            "cri_logs.max_record_bytes",
            self.max_record_bytes,
            128,
            65_536,
        )?;
        if self.max_files.saturating_mul(self.max_record_bytes) > 8 * 1024 * 1024 {
            return Err(ConfigError::invalid_value(
                "cri_logs.max_files",
                "max_files * max_record_bytes must not exceed 8 MiB",
            ));
        }
        validate_inclusive(
            "cri_logs.max_read_bytes_per_file",
            self.max_read_bytes_per_file,
            self.max_record_bytes,
            1_048_576,
        )
    }
}
