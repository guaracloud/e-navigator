use std::{
    collections::BinaryHeap,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BoundedCount {
    pub count: u64,
    pub truncated: bool,
}

pub(crate) fn count_dir_entries(path: &Path, max_entries: usize) -> Result<BoundedCount, String> {
    let mut count = 0u64;
    let mut truncated = false;
    for entry in fs::read_dir(path).map_err(|err| err.to_string())? {
        let Ok(_) = entry else {
            continue;
        };
        if count as usize >= max_entries {
            truncated = true;
            break;
        }
        count = count.saturating_add(1);
    }
    Ok(BoundedCount { count, truncated })
}

pub(crate) fn count_socket_fds(path: &Path, max_entries: usize) -> Result<BoundedCount, String> {
    let mut count = 0;
    let mut visited = 0usize;
    let mut truncated = false;
    for entry in fs::read_dir(path).map_err(|err| err.to_string())? {
        let Ok(entry) = entry else {
            continue;
        };
        if visited >= max_entries {
            truncated = true;
            break;
        }
        visited = visited.saturating_add(1);
        if fs::read_link(entry.path())
            .map(|target| target.to_string_lossy().starts_with("socket:"))
            .unwrap_or(false)
        {
            count += 1;
        }
    }
    Ok(BoundedCount { count, truncated })
}

pub(crate) fn bounded_numeric_dirs(
    root: &Path,
    limit: usize,
    label: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<(u32, PathBuf)>, String> {
    let mut entries = BoundedSelection::new(limit);
    for entry in fs::read_dir(root).map_err(|err| err.to_string())? {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        entries.push((pid, entry.path()));
    }
    let truncated = entries.was_truncated();
    let mut entries = entries.into_sorted_vec();
    entries.sort_by_key(|(pid, _)| *pid);
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
    let mut children = BoundedSelection::new(limit);
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        if !entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
            continue;
        }
        children.push(entry.path());
    }
    let truncated = children.was_truncated();
    let children = children.into_sorted_vec();
    if truncated {
        warnings.push(format!(
            "{}: child cgroup scan truncated at {limit} entries",
            path.display()
        ));
    }
    children
}

struct BoundedSelection<T> {
    limit: usize,
    eligible: usize,
    retained: BinaryHeap<T>,
}

impl<T: Ord> BoundedSelection<T> {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            eligible: 0,
            retained: BinaryHeap::new(),
        }
    }

    fn push(&mut self, value: T) {
        self.eligible = self.eligible.saturating_add(1);
        if self.limit == 0 {
            return;
        }
        if self.retained.len() < self.limit {
            self.retained.push(value);
            return;
        }
        let Some(largest_retained) = self.retained.peek() else {
            return;
        };
        if value < *largest_retained {
            let _ = self.retained.pop();
            self.retained.push(value);
        }
    }

    fn was_truncated(&self) -> bool {
        self.eligible > self.limit
    }

    fn into_sorted_vec(self) -> Vec<T> {
        self.retained.into_sorted_vec()
    }

    #[cfg(test)]
    fn retained_len(&self) -> usize {
        self.retained.len()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        BoundedSelection, bounded_child_dirs, bounded_numeric_dirs, count_dir_entries,
        count_socket_fds, read_bounded_to_string,
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
    fn bounded_numeric_pid_directory_traversal_selects_lowest_pids_under_limit() {
        let root = temp_path("pid-cap");
        let _ = std::fs::remove_dir_all(&root);
        for pid in ["900", "300", "100", "700", "200", "500"] {
            std::fs::create_dir_all(root.join(pid)).expect("pid");
        }
        std::fs::create_dir_all(root.join("not-a-pid")).expect("non pid");
        let mut warnings = Vec::new();

        let entries = bounded_numeric_dirs(&root, 2, "process", &mut warnings).expect("scan");

        assert_eq!(
            entries.iter().map(|(pid, _)| *pid).collect::<Vec<_>>(),
            vec![100, 200]
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("process scan truncated"))
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn bounded_child_directory_traversal_selects_lexical_paths_under_limit() {
        let root = temp_path("child-cap");
        let _ = std::fs::remove_dir_all(&root);
        for child in ["zeta", "alpha", "beta"] {
            std::fs::create_dir_all(root.join(child)).expect("child");
        }
        std::fs::write(root.join("file"), "").expect("file");
        let mut warnings = Vec::new();

        let children = bounded_child_dirs(
            std::fs::read_dir(&root).expect("read dir"),
            2,
            &root,
            &mut warnings,
        );

        assert_eq!(
            children
                .iter()
                .map(|path| path
                    .file_name()
                    .expect("name")
                    .to_string_lossy()
                    .to_string())
                .collect::<Vec<_>>(),
            vec!["alpha".to_string(), "beta".to_string()]
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("child cgroup scan truncated"))
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn bounded_selection_retains_only_the_lowest_candidates() {
        let mut selection = BoundedSelection::new(3);

        for value in [90, 10, 80, 20, 70, 30, 60, 40, 50] {
            selection.push(value);
            assert!(selection.retained_len() <= 3);
        }

        assert!(selection.was_truncated());
        assert_eq!(selection.into_sorted_vec(), vec![10, 20, 30]);
    }

    #[test]
    fn file_descriptor_counting_respects_limits() {
        let root = temp_path("fd-cap");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(root.join("0"), "").expect("fd");
        std::fs::write(root.join("1"), "").expect("fd");

        let count = count_dir_entries(&root, 1).expect("count");

        assert_eq!(count.count, 1);
        assert!(count.truncated);
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

        assert_eq!(count.count, 1);
        assert!(count.truncated);
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "e-navigator-host-source-{label}-{}",
            std::process::id()
        ))
    }
}
