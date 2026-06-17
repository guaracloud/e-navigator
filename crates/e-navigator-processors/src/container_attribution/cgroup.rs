use e_navigator_signals::ContainerContext;
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

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

pub(super) fn read_bounded_to_string(path: &Path, max_bytes: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = String::new();
    file.by_ref().take(max_bytes).read_to_string(&mut buffer)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const CONTAINER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn arbitrary_cgroup_like_strings_never_panic(contents in ".{0,512}") {
            let _ = parse_container_from_cgroup(&contents);
        }

        #[test]
        fn malformed_ids_do_not_produce_container_context(
            prefix in "[^0-9A-Fa-f]{0,64}",
            suffix in "[^0-9A-Fa-f]{0,64}",
            bad_char in "[g-zG-Z]"
        ) {
            let short = format!("{prefix}0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde{suffix}");
            prop_assert!(parse_container_from_cgroup(&short).is_none());

            let malformed = format!("{prefix}0123456789abcdef0123456789abcdef0123456789abcdef0123456789abc{bad_char}{suffix}");
            prop_assert!(parse_container_from_cgroup(&malformed).is_none());
        }
    }

    #[test]
    fn recognized_runtime_cgroup_paths_extract_container_id_deterministically() {
        for (contents, runtime) in [
            (format!("0::/docker/{CONTAINER_ID}.scope\n"), Some("docker")),
            (
                format!("0::/kubepods.slice/cri-containerd-{CONTAINER_ID}.scope\n"),
                Some("containerd"),
            ),
            (
                format!("0::/kubepods.slice/crio-{CONTAINER_ID}.scope\n"),
                Some("cri-o"),
            ),
        ] {
            let first = parse_container_from_cgroup(&contents).expect("container context");
            let second = parse_container_from_cgroup(&contents).expect("container context");

            assert_eq!(first, second);
            assert_eq!(first.container_id, CONTAINER_ID);
            assert_eq!(first.runtime.as_deref(), runtime);
        }
    }
}
