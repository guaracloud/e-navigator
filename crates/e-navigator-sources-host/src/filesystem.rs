use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

pub(crate) fn read_bounded_to_string(path: &Path, max_bytes: u64) -> Result<String, String> {
    let mut file = File::open(path).map_err(|err| err.to_string())?;
    let mut buffer = String::new();
    file.by_ref()
        .take(max_bytes)
        .read_to_string(&mut buffer)
        .map_err(|err| err.to_string())?;
    Ok(buffer)
}

pub(crate) fn count_dir_entries(path: &Path, max_entries: usize) -> Result<u64, String> {
    Ok(fs::read_dir(path)
        .map_err(|err| err.to_string())?
        .take(max_entries)
        .filter_map(Result::ok)
        .count() as u64)
}

pub(crate) fn count_socket_fds(path: &Path, max_entries: usize) -> Result<u64, String> {
    let mut count = 0;
    for entry in fs::read_dir(path)
        .map_err(|err| err.to_string())?
        .take(max_entries)
    {
        let Ok(entry) = entry else {
            continue;
        };
        if fs::read_link(entry.path())
            .map(|target| target.to_string_lossy().starts_with("socket:"))
            .unwrap_or(false)
        {
            count += 1;
        }
    }
    Ok(count)
}

pub(crate) fn bounded_numeric_dirs(
    root: &Path,
    limit: usize,
    label: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<(u32, PathBuf)>, String> {
    let mut entries = Vec::new();
    let mut truncated = false;
    for entry in fs::read_dir(root).map_err(|err| err.to_string())? {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        if entries.len() >= limit {
            truncated = true;
            break;
        }
        entries.push((pid, entry.path()));
    }
    if truncated {
        warnings.push(format!(
            "{}: {label} scan truncated at {limit} entries",
            root.display()
        ));
    }
    Ok(entries)
}

pub(crate) fn bounded_child_dirs(
    entries: fs::ReadDir,
    limit: usize,
    path: &Path,
    warnings: &mut Vec<String>,
) -> Vec<PathBuf> {
    let mut children = Vec::new();
    let mut truncated = false;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        if !entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
            continue;
        }
        if children.len() >= limit {
            truncated = true;
            break;
        }
        children.push(entry.path());
    }
    if truncated {
        warnings.push(format!(
            "{}: child cgroup scan truncated at {limit} entries",
            path.display()
        ));
    }
    children
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        bounded_child_dirs, bounded_numeric_dirs, count_dir_entries, count_socket_fds,
        read_bounded_to_string,
    };

    #[test]
    fn bounded_file_reads_respect_max_file_bytes() {
        let root = temp_path("file-cap");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(root.join("value"), "abcdef").expect("value");

        let contents = read_bounded_to_string(&root.join("value"), 3).expect("bounded read");

        assert_eq!(contents, "abc");
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn bounded_numeric_pid_directory_traversal_honors_limit() {
        let root = temp_path("pid-cap");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("100")).expect("pid");
        std::fs::create_dir_all(root.join("101")).expect("pid");
        std::fs::create_dir_all(root.join("not-a-pid")).expect("non pid");
        let mut warnings = Vec::new();

        let entries = bounded_numeric_dirs(&root, 1, "process", &mut warnings).expect("scan");

        assert_eq!(entries.len(), 1);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("process scan truncated"))
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn bounded_child_directory_traversal_honors_limit() {
        let root = temp_path("child-cap");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("a")).expect("child");
        std::fs::create_dir_all(root.join("b")).expect("child");
        std::fs::write(root.join("file"), "").expect("file");
        let mut warnings = Vec::new();

        let children = bounded_child_dirs(
            std::fs::read_dir(&root).expect("read dir"),
            1,
            &root,
            &mut warnings,
        );

        assert_eq!(children.len(), 1);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("child cgroup scan truncated"))
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn file_descriptor_counting_respects_limits() {
        let root = temp_path("fd-cap");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(root.join("0"), "").expect("fd");
        std::fs::write(root.join("1"), "").expect("fd");

        let count = count_dir_entries(&root, 1).expect("count");

        assert_eq!(count, 1);
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn socket_file_descriptor_counting_respects_limits() {
        use std::os::unix::fs::symlink;

        let root = temp_path("socket-fd-cap");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        symlink("socket:[1]", root.join("0")).expect("socket fd");
        symlink("socket:[2]", root.join("1")).expect("socket fd");

        let count = count_socket_fds(&root, 1).expect("count");

        assert_eq!(count, 1);
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "e-navigator-host-source-{label}-{}",
            std::process::id()
        ))
    }
}
