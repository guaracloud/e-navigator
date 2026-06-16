use e_navigator_signals::ContainerContext;
use std::{fs::File, io::Read, path::Path};

pub(super) fn parse_container_from_cgroup(contents: &str) -> Option<ContainerContext> {
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

pub(super) fn read_bounded_to_string(path: &Path, max_bytes: u64) -> Result<String, String> {
    let mut file = File::open(path).map_err(|err| err.to_string())?;
    let mut buffer = String::new();
    file.by_ref()
        .take(max_bytes)
        .read_to_string(&mut buffer)
        .map_err(|err| err.to_string())?;
    Ok(buffer)
}
