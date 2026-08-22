//! Conservative OpenTelemetry zero-code agent detection from bounded procfs evidence.

use std::{
    collections::{HashMap, VecDeque},
    io::Read,
    path::{Path, PathBuf},
};

use e_navigator_signals::NetworkProcessIdentity;

const MAX_PROCFS_FILE_BYTES: u64 = 64 * 1024;
const MAX_CACHED_PROCESSES: usize = 4096;
const DOTNET_OTEL_PROFILER_ID: &str = "{918728DD-259F-4A6A-AC2B-B85E1B658318}";

#[derive(Debug)]
pub(crate) struct OtelSdkDetector {
    procfs_root: PathBuf,
    cache: HashMap<ProcessCacheKey, bool>,
    insertion_order: VecDeque<ProcessCacheKey>,
}

impl OtelSdkDetector {
    pub(crate) fn new(procfs_root: PathBuf) -> Self {
        Self {
            procfs_root,
            cache: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    pub(crate) fn has_supported_zero_code_trace_agent(
        &mut self,
        process: &NetworkProcessIdentity,
    ) -> bool {
        let process_root = self.procfs_root.join(process.pid.to_string());
        let start_time_ticks = read_process_start_time(&process_root.join("stat"));
        let cache_key = start_time_ticks.map(|start_time_ticks| ProcessCacheKey {
            pid: process.pid,
            start_time_ticks,
            command: process.command.clone(),
            executable: process.executable.clone(),
            cgroup_id: process.cgroup_id,
        });
        if let Some(cached) = cache_key
            .as_ref()
            .and_then(|cache_key| self.cache.get(cache_key))
        {
            return *cached;
        }

        let Some(environment) = read_bounded(&process_root.join("environ")) else {
            return false;
        };
        let command_line = read_bounded(&process_root.join("cmdline")).unwrap_or_default();
        let detected = supported_agent_exports_traces(&environment, &command_line);
        if let Some(cache_key) = cache_key {
            self.insert_cache(cache_key, detected);
        }
        detected
    }

    fn insert_cache(&mut self, key: ProcessCacheKey, detected: bool) {
        if self.cache.contains_key(&key) {
            return;
        }
        while self.cache.len() >= MAX_CACHED_PROCESSES {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.cache.remove(&oldest);
        }
        self.insertion_order.push_back(key.clone());
        self.cache.insert(key, detected);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProcessCacheKey {
    pid: u32,
    start_time_ticks: u64,
    command: String,
    executable: Option<String>,
    cgroup_id: Option<u64>,
}

fn supported_agent_exports_traces(environment: &[u8], command_line: &[u8]) -> bool {
    if traces_are_disabled(environment, command_line) {
        return false;
    }
    java_agent_present(environment, command_line)
        || node_agent_present(environment, command_line)
        || dotnet_agent_present(environment)
        || python_agent_present(environment, command_line)
}

fn traces_are_disabled(environment: &[u8], command_line: &[u8]) -> bool {
    environment_value(environment, "OTEL_SDK_DISABLED").is_some_and(is_true)
        || environment_value(environment, "OTEL_TRACES_EXPORTER")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("none"))
        || environment_value(environment, "OTEL_TRACES_SAMPLER")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("always_off"))
        || environment_value(environment, "OTEL_DOTNET_AUTO_TRACES_ENABLED").is_some_and(is_false)
        || ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"]
            .into_iter()
            .filter_map(|key| environment_value(environment, key))
            .any(|value| {
                value.contains("-Dotel.sdk.disabled=true")
                    || value.contains("-Dotel.traces.exporter=none")
                    || value.contains("-Dotel.traces.sampler=always_off")
            })
        || command_line_arguments(command_line).any(|argument| {
            matches!(
                argument,
                "-Dotel.sdk.disabled=true"
                    | "-Dotel.traces.exporter=none"
                    | "-Dotel.traces.sampler=always_off"
            )
        })
}

fn java_agent_present(environment: &[u8], command_line: &[u8]) -> bool {
    ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"]
        .into_iter()
        .filter_map(|key| environment_value(environment, key))
        .any(contains_java_agent)
        || command_line_arguments(command_line).any(contains_java_agent)
}

fn contains_java_agent(value: &str) -> bool {
    value.contains("-javaagent:") && value.contains("opentelemetry-javaagent")
}

fn node_agent_present(environment: &[u8], command_line: &[u8]) -> bool {
    const REGISTER_MODULE: &str = "@opentelemetry/auto-instrumentations-node/register";
    environment_value(environment, "NODE_OPTIONS")
        .is_some_and(|value| value.contains(REGISTER_MODULE))
        || command_line_arguments(command_line).any(|argument| argument.contains(REGISTER_MODULE))
}

fn dotnet_agent_present(environment: &[u8]) -> bool {
    let profiling_enabled = ["CORECLR_ENABLE_PROFILING", "COR_ENABLE_PROFILING"]
        .into_iter()
        .filter_map(|key| environment_value(environment, key))
        .any(|value| value.trim() == "1");
    let profiler_matches = ["CORECLR_PROFILER", "COR_PROFILER"]
        .into_iter()
        .filter_map(|key| environment_value(environment, key))
        .any(|value| value.trim().eq_ignore_ascii_case(DOTNET_OTEL_PROFILER_ID));
    let profiler_path_matches = [
        "CORECLR_PROFILER_PATH",
        "CORECLR_PROFILER_PATH_32",
        "CORECLR_PROFILER_PATH_64",
        "COR_PROFILER_PATH",
        "COR_PROFILER_PATH_32",
        "COR_PROFILER_PATH_64",
    ]
    .into_iter()
    .filter_map(|key| environment_value(environment, key))
    .any(|value| value.contains("OpenTelemetry.AutoInstrumentation.Native"));
    let startup_hook_matches = environment_value(environment, "DOTNET_STARTUP_HOOKS")
        .is_some_and(|value| value.contains("OpenTelemetry.AutoInstrumentation.StartupHook"));

    startup_hook_matches || (profiling_enabled && (profiler_matches || profiler_path_matches))
}

fn python_agent_present(environment: &[u8], command_line: &[u8]) -> bool {
    environment_value(environment, "PYTHONPATH")
        .is_some_and(|value| value.contains("opentelemetry/instrumentation/auto_instrumentation"))
        || command_line_arguments(command_line)
            .take(2)
            .any(|argument| executable_basename(argument) == "opentelemetry-instrument")
}

fn environment_value<'a>(environment: &'a [u8], key: &str) -> Option<&'a str> {
    environment
        .split(|byte| *byte == 0)
        .filter_map(|entry| {
            let separator = entry.iter().position(|byte| *byte == b'=')?;
            Some((&entry[..separator], &entry[separator + 1..]))
        })
        .find_map(|(candidate, value)| {
            (candidate == key.as_bytes())
                .then(|| std::str::from_utf8(value).ok())
                .flatten()
        })
}

fn command_line_arguments(command_line: &[u8]) -> impl Iterator<Item = &str> {
    command_line
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .filter_map(|argument| std::str::from_utf8(argument).ok())
}

fn executable_basename(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}

fn is_true(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("true") || value.trim() == "1"
}

fn is_false(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("false") || value.trim() == "0"
}

fn read_process_start_time(path: &Path) -> Option<u64> {
    let stat = read_bounded(path)?;
    let closing_parenthesis = stat.iter().rposition(|byte| *byte == b')')?;
    let fields = std::str::from_utf8(stat.get(closing_parenthesis + 1..)?).ok()?;
    fields.split_ascii_whitespace().nth(19)?.parse().ok()
}

fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_PROCFS_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_PROCFS_FILE_BYTES).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use e_navigator_signals::NetworkProcessIdentity;

    use super::{OtelSdkDetector, supported_agent_exports_traces};

    #[test]
    fn recognizes_supported_zero_code_agents() {
        for (environment, command_line) in [
            (
                b"JAVA_TOOL_OPTIONS=-javaagent:/otel/opentelemetry-javaagent.jar\0".as_slice(),
                b"java\0-jar\0app.jar\0".as_slice(),
            ),
            (
                b"NODE_OPTIONS=--require @opentelemetry/auto-instrumentations-node/register\0"
                    .as_slice(),
                b"node\0app.js\0".as_slice(),
            ),
            (
                b"CORECLR_ENABLE_PROFILING=1\0CORECLR_PROFILER={918728DD-259F-4A6A-AC2B-B85E1B658318}\0"
                    .as_slice(),
                b"dotnet\0app.dll\0".as_slice(),
            ),
            (
                b"PYTHONPATH=/otel/opentelemetry/instrumentation/auto_instrumentation\0"
                    .as_slice(),
                b"python\0app.py\0".as_slice(),
            ),
        ] {
            assert!(supported_agent_exports_traces(environment, command_line));
        }
    }

    #[test]
    fn generic_otel_configuration_and_disabled_traces_do_not_suppress() {
        assert!(!supported_agent_exports_traces(
            b"OTEL_SERVICE_NAME=checkout\0OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318\0",
            b"/app/server\0",
        ));
        assert!(!supported_agent_exports_traces(
            b"NODE_OPTIONS=--require @opentelemetry/auto-instrumentations-node/register\0OTEL_SDK_DISABLED=true\0",
            b"node\0app.js\0",
        ));
        assert!(!supported_agent_exports_traces(
            b"JAVA_TOOL_OPTIONS=-javaagent:/otel/opentelemetry-javaagent.jar\0OTEL_TRACES_EXPORTER=none\0",
            b"java\0-jar\0app.jar\0",
        ));
        assert!(!supported_agent_exports_traces(
            b"JAVA_TOOL_OPTIONS=-javaagent:/otel/opentelemetry-javaagent.jar -Dotel.traces.exporter=none\0",
            b"java\0-jar\0app.jar\0",
        ));
    }

    #[test]
    fn procfs_cache_is_process_identity_bound_and_read_failures_are_not_cached() {
        let procfs_root = std::env::temp_dir().join(format!(
            "e-navigator-otel-detector-cache-test-{}",
            std::process::id()
        ));
        let process_root = procfs_root.join("73");
        let _ = std::fs::remove_dir_all(&procfs_root);
        assert!(std::fs::create_dir_all(&process_root).is_ok());
        assert!(std::fs::write(process_root.join("stat"), process_stat(100)).is_ok());
        let process = NetworkProcessIdentity {
            pid: 73,
            ppid: Some(1),
            uid: Some(1000),
            command: "node".to_string(),
            executable: Some("/usr/bin/node".to_string()),
            cgroup_id: Some(44),
        };
        let mut detector = OtelSdkDetector::new(procfs_root.clone());

        assert!(!detector.has_supported_zero_code_trace_agent(&process));
        assert!(
            std::fs::write(
                process_root.join("environ"),
                b"NODE_OPTIONS=--require @opentelemetry/auto-instrumentations-node/register\0",
            )
            .is_ok()
        );
        assert!(std::fs::write(process_root.join("cmdline"), b"node\0app.js\0").is_ok());
        assert!(detector.has_supported_zero_code_trace_agent(&process));

        assert!(std::fs::write(process_root.join("environ"), b"OTEL_SERVICE_NAME=api\0").is_ok());
        assert!(detector.has_supported_zero_code_trace_agent(&process));
        assert!(std::fs::write(process_root.join("stat"), process_stat(101)).is_ok());
        assert!(!detector.has_supported_zero_code_trace_agent(&process));

        let _ = std::fs::remove_dir_all(procfs_root);
    }

    fn process_stat(start_time_ticks: u64) -> String {
        format!("73 (node worker) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 {start_time_ticks}\n")
    }
}
