use e_navigator_core::{CoreError, RuntimeConfig};
use std::path::Path;

pub(crate) fn load_config(path: Option<&Path>) -> anyhow::Result<RuntimeConfig> {
    match path {
        Some(path) => {
            let contents = std::fs::read_to_string(path)?;
            let config = toml::from_str::<RuntimeConfig>(&contents)?;
            config.validate_typed().map_err(CoreError::InvalidConfig)?;
            Ok(config)
        }
        None => Ok(RuntimeConfig::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn load_config_returns_default_without_path() {
        let config = load_config(None).expect("default config loads");

        assert_eq!(config, RuntimeConfig::default());
    }

    #[test]
    fn load_config_succeeds_for_valid_toml() {
        let path = temp_config_path("valid");
        fs::write(
            &path,
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
        .expect("write valid config");

        let config = load_config(Some(&path)).expect("config loads");
        let _ = fs::remove_file(path);

        assert_eq!(config.log_level, "debug");
        assert_eq!(config.queue_capacity, 64);
        assert!(config.module_enabled("source.synthetic_exec"));
        assert!(!config.module_enabled("processor.container_attribution"));
    }

    #[test]
    fn load_config_reports_invalid_toml() {
        let path = temp_config_path("invalid-toml");
        fs::write(&path, "queue_capacity = ").expect("write invalid config");

        let err = load_config(Some(&path)).expect_err("invalid toml is rejected");
        let _ = fs::remove_file(path);

        assert!(err.to_string().contains("TOML parse error"));
    }

    #[test]
    fn load_config_reports_invalid_runtime_config() {
        let path = temp_config_path("invalid-runtime");
        fs::write(
            &path,
            r#"
            queue_capacity = 0

            [[modules]]
            name = "source.synthetic_exec"
            enabled = true
            "#,
        )
        .expect("write invalid runtime config");

        let err = load_config(Some(&path)).expect_err("invalid runtime config is rejected");
        let _ = fs::remove_file(path);

        assert!(
            err.to_string()
                .contains("queue_capacity must be greater than zero")
        );
    }

    #[test]
    fn kubernetes_configmap_embedded_runtime_config_validates() {
        let manifest = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("deploy/kubernetes/configmap.yaml"),
        )
        .expect("configmap manifest is readable");
        assert!(manifest.contains("[cpu_profile_source]"));
        assert!(manifest.contains("name = \"source.aya_cpu_profile\""));
        let toml = extract_embedded_configmap_toml(&manifest);
        let config = toml::from_str::<RuntimeConfig>(&toml).expect("configmap toml parses");

        config.validate().expect("configmap config validates");
        assert!(config.module_enabled("source.aya_exec"));
        assert!(!config.module_enabled("source.aya_cpu_profile"));
        assert!(!config.cpu_profile_source.enabled);
        assert_eq!(
            config.cpu_profile_source.module_name,
            "source.aya_cpu_profile"
        );
        assert_eq!(
            config.cpu_profile_source.backpressure,
            e_navigator_core::CpuProfileBackpressure::DropNewest
        );
        assert!(config.module_enabled("generator.profiling"));
        assert!(
            config.profiling.window_nanos
                <= e_navigator_core::ProfilingConfig::MAX_WINDOW_NANOS_LIMIT
        );
    }

    #[test]
    fn config_fixtures_load_through_cli_config_path() {
        for fixture in [
            "default.toml",
            "minimal.toml",
            "profiling-enabled.toml",
            "guara-compat-enabled.toml",
        ] {
            let path = fixture_path(fixture);
            let config = load_config(Some(&path)).unwrap_or_else(|err| {
                panic!("fixture {fixture} should load through CLI config path: {err}")
            });

            assert!(config.validate().is_ok(), "fixture {fixture} validates");
        }
    }

    #[test]
    fn profiling_enabled_fixture_enables_only_the_opt_in_cpu_profile_source() {
        let config = load_config(Some(&fixture_path("profiling-enabled.toml")))
            .expect("profiling fixture loads");

        assert!(config.cpu_profile_source.enabled);
        assert!(config.module_enabled("source.aya_cpu_profile"));
        assert_eq!(
            config.cpu_profile_source.module_name,
            "source.aya_cpu_profile"
        );
    }

    #[test]
    fn guara_compat_fixture_keeps_cpu_profiling_disabled() {
        let config = load_config(Some(&fixture_path("guara-compat-enabled.toml")))
            .expect("guara compat fixture loads");

        assert!(config.module_enabled("generator.guara_compat"));
        assert!(!config.cpu_profile_source.enabled);
        assert!(!config.module_enabled("source.aya_cpu_profile"));
    }

    #[test]
    fn invalid_config_fixtures_are_rejected_through_cli_config_path() {
        for (fixture, expected) in [
            ("invalid-unknown-module.toml", "unknown module"),
            (
                "invalid-cpu-profile-without-module.toml",
                "cpu_profile_source.enabled requires enabled source.aya_cpu_profile module",
            ),
        ] {
            let path = fixture_path(fixture);
            let err = match load_config(Some(&path)) {
                Ok(_) => panic!("fixture {fixture} should be rejected"),
                Err(err) => err,
            };

            assert!(
                err.to_string().contains(expected),
                "fixture {fixture} error {err:?} should contain {expected:?}"
            );
        }
    }

    fn temp_config_path(label: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "e-navigator-cli-{label}-{}-{}.toml",
            std::process::id(),
            crate::time::now_unix_nanos()
        ));
        path
    }

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    fn extract_embedded_configmap_toml(manifest: &str) -> String {
        let mut output = String::new();
        let mut in_config = false;
        for line in manifest.lines() {
            if line == "  e-navigator.toml: |" {
                in_config = true;
                continue;
            }
            if in_config {
                let Some(stripped) = line.strip_prefix("    ") else {
                    break;
                };
                output.push_str(stripped);
                output.push('\n');
            }
        }
        assert!(!output.trim().is_empty(), "configmap toml block exists");
        output
    }
}
