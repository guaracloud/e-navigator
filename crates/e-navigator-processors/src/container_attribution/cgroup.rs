use e_navigator_core::capture_filter::parse_container_id_from_cgroup_path;
use e_navigator_signals::ContainerContext;
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

pub(super) fn parse_container_from_cgroup(contents: &str) -> Option<ContainerContext> {
    if !has_container_cgroup_marker(contents) {
        return None;
    }
    let container_id = parse_container_id_from_cgroup_path(contents)?;
    let runtime = infer_runtime(contents);
    Some(ContainerContext {
        container_id,
        runtime,
    })
}

fn has_container_cgroup_marker(contents: &str) -> bool {
    contents.contains("kubepods")
        || contents.contains("cri-containerd")
        || contents.contains("containerd")
        || contents.contains("crio")
        || contents.contains("cri-o")
        || contents.contains("docker")
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

    #[test]
    fn kubepods_cgroup_paths_with_bare_container_ids_are_supported() {
        let context =
            parse_container_from_cgroup(&format!("0::/kubepods/burstable/podabc/{CONTAINER_ID}\n"))
                .expect("kubepods path is container evidence");

        assert_eq!(context.container_id, CONTAINER_ID);
        assert_eq!(context.runtime, None);
    }

    #[test]
    fn unrecognized_cgroup_paths_do_not_guess_container_ids() {
        let context =
            parse_container_from_cgroup(&format!("0::/user.slice/session-{CONTAINER_ID}.scope\n"));

        assert!(context.is_none());
    }

    #[test]
    fn recognized_runtime_cgroup_paths_reject_longer_hexadecimal_ids() {
        let contents = format!("0::/docker/f{CONTAINER_ID}.scope\n");

        assert!(parse_container_from_cgroup(&contents).is_none());
    }

    #[test]
    fn bounded_cgroup_file_reads_stop_at_configured_limit() {
        let dir = std::env::temp_dir().join(format!(
            "e-navigator-bounded-cgroup-read-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("fixture dir");
        let path = dir.join("cgroup");
        std::fs::write(&path, "0123456789abcdef").expect("fixture cgroup file");

        let contents = read_bounded_to_string(&path, 6).expect("bounded read");

        assert_eq!(contents, "012345");
        std::fs::remove_dir_all(dir).expect("fixture cleanup");
    }
}
