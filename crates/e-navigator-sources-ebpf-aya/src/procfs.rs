use e_navigator_signals::ContainerContext;
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};
use tracing::{debug, warn};

const MAX_CGROUP_BYTES: u64 = 4096;
const ESRCH: i32 = 3;

pub(crate) fn container_from_pid_cgroup(procfs_root: &Path, pid: u32) -> Option<ContainerContext> {
    let path = procfs_root.join(pid.to_string()).join("cgroup");
    match read_bounded_to_string(&path, MAX_CGROUP_BYTES) {
        Ok(contents) => parse_container_from_cgroup(&contents),
        Err(err) => {
            if is_disappeared_process_error(&err) {
                debug!(
                    pid,
                    path = %path.display(),
                    "source-time process cgroup disappeared before attribution"
                );
            } else {
                warn!(
                    pid,
                    path = %path.display(),
                    error = %err,
                    "unable to read source-time process cgroup"
                );
            }
            None
        }
    }
}

fn is_disappeared_process_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(ESRCH)
}

fn read_bounded_to_string(path: &Path, max_bytes: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = String::new();
    file.by_ref().take(max_bytes).read_to_string(&mut buffer)?;
    Ok(buffer)
}

fn parse_container_from_cgroup(contents: &str) -> Option<ContainerContext> {
    let container_id = find_container_id(contents)?;
    let runtime = infer_runtime(contents);
    Some(ContainerContext {
        container_id,
        runtime,
    })
}

fn find_container_id(contents: &str) -> Option<String> {
    let bytes = contents.as_bytes();
    let mut index = 0;

    while index + 64 <= bytes.len() {
        if bytes[index..index + 64]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
        {
            return Some(contents[index..index + 64].to_string());
        }
        index += 1;
    }

    None
}

fn infer_runtime(contents: &str) -> Option<String> {
    if contents.contains("cri-containerd") || contents.contains("containerd") {
        Some("containerd".to_string())
    } else if contents.contains("crio") || contents.contains("cri-o") {
        Some("cri-o".to_string())
    } else if contents.contains("docker") {
        Some("docker".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTAINER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn extracts_container_from_live_procfs_cgroup_file() {
        let temp = test_temp_dir("source-time-cgroup");
        let cgroup = temp.join("123/cgroup");
        std::fs::create_dir_all(cgroup.parent().expect("parent")).expect("mkdir");
        std::fs::write(
            &cgroup,
            format!("0::/kubepods.slice/cri-containerd-{CONTAINER_ID}.scope\n"),
        )
        .expect("write cgroup");

        let container = container_from_pid_cgroup(&temp, 123).expect("container");

        assert_eq!(container.container_id, CONTAINER_ID);
        assert_eq!(container.runtime.as_deref(), Some("containerd"));

        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn missing_procfs_cgroup_is_not_attributed() {
        let temp = test_temp_dir("missing-source-time-cgroup");

        assert!(container_from_pid_cgroup(&temp, 404).is_none());

        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn esrch_procfs_race_is_treated_as_disappeared_process() {
        let err = io::Error::from_raw_os_error(ESRCH);

        assert!(is_disappeared_process_error(&err));
    }

    fn test_temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("e-navigator-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}
