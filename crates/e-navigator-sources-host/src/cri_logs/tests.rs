#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "fixture assertions"
)]
use super::*;
use std::{
    fs,
    io::Write,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture {
    root: std::path::PathBuf,
    config: CriLogsConfig,
    log: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "e-navigator-cri-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let log = root.join("pods/default_app_uid/web/0.log");
        fs::create_dir_all(log.parent().unwrap()).unwrap();
        fs::write(&log, b"").unwrap();
        let config = CriLogsConfig {
            root: root.join("pods"),
            checkpoint_dir: root.join("state"),
            include_body: true,
            ..Default::default()
        };
        Self { root, config, log }
    }
    fn collector(&self) -> Collector {
        Collector::new(self.config.clone()).unwrap()
    }
    fn append(&self, bytes: &[u8]) {
        fs::OpenOptions::new()
            .append(true)
            .open(&self.log)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn bodies(items: &[Collected]) -> Vec<&str> {
    items
        .iter()
        .filter_map(|i| match i {
            Collected::Log(l) => l.body.as_deref(),
            _ => None,
        })
        .collect()
}
fn warned(items: &[Collected], outcome: Outcome) -> bool {
    items
        .iter()
        .any(|i| matches!(i, Collected::Warning(o, _) if *o == outcome))
}
fn record(body: &str) -> String {
    format!("2026-10-10T12:00:00.000000001Z stdout F {body}\n")
}

#[test]
fn partial_streams_utf8_and_invalid_input_are_explicit() {
    let f = Fixture::new();
    f.append(include_bytes!("fixtures/mixed.cri"));
    let items = f.collector().poll(1000).unwrap();
    assert_eq!(bodies(&items), ["err", "hello", "\u{fffd}"]);
    assert!(
        items
            .iter()
            .any(|i| matches!(i, Collected::Log(l) if l.invalid_utf8))
    );
    assert!(warned(&items, Outcome::UnsupportedFormat));
}
#[test]
fn utf8_split_across_partial_records_is_reassembled_before_decoding() {
    let f = Fixture::new();
    f.append(include_bytes!("fixtures/partial-utf8.cri"));
    let items = f.collector().poll(1000).unwrap();
    assert_eq!(bodies(&items), ["€"]);
    assert!(
        items
            .iter()
            .all(|i| !matches!(i, Collected::Log(l) if l.invalid_utf8))
    );
}
#[test]
fn crash_rewinds_partial_records_but_not_admitted_complete_records() {
    let f = Fixture::new();
    f.append(record("first").as_bytes());
    f.append(b"2026-10-10T12:00:00Z stdout P partial\n");
    let mut c = f.collector();
    assert_eq!(bodies(&c.poll(1000).unwrap()), ["first"]);
    c.commit().unwrap();
    drop(c);
    f.append(b"2026-10-10T12:00:01Z stdout F final\n");
    let mut c = f.collector();
    assert_eq!(bodies(&c.poll(2000).unwrap()), ["partialfinal"]);
    c.commit().unwrap();
    drop(c);
    assert!(bodies(&f.collector().poll(3000).unwrap()).is_empty());
    let checkpoint = fs::read_to_string(f.config.checkpoint_dir.join("checkpoints.json")).unwrap();
    assert!(!checkpoint.contains("partial"));
    assert!(!checkpoint.contains("first"));
}
#[test]
fn crash_before_commit_replays_and_orphan_temp_does_not_replace_checkpoint() {
    let f = Fixture::new();
    f.append(record("first").as_bytes());
    {
        let mut c = f.collector();
        c.poll(1000).unwrap();
    }
    let mut c = f.collector();
    assert_eq!(bodies(&c.poll(2000).unwrap()), ["first"]);
    c.commit().unwrap();
    drop(c);
    fs::write(f.config.checkpoint_dir.join("checkpoints.tmp"), b"broken").unwrap();
    assert!(bodies(&f.collector().poll(3000).unwrap()).is_empty());
}
#[test]
fn rename_rotation_and_exit_final_records_are_drained_without_a_live_container() {
    let f = Fixture::new();
    let mut c = f.collector();
    c.poll(1000).unwrap();
    let mut old = fs::OpenOptions::new().append(true).open(&f.log).unwrap();
    fs::rename(&f.log, f.log.with_extension("log.20261010")).unwrap();
    old.write_all(record("exit-final").as_bytes()).unwrap();
    fs::write(&f.log, record("replacement")).unwrap();
    assert_eq!(
        bodies(&c.poll(2000).unwrap())
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        ["exit-final", "replacement"].into_iter().collect()
    );
    c.commit().unwrap();
    drop(c);
    assert!(bodies(&f.collector().poll(3000).unwrap()).is_empty());
}
#[test]
fn unlinked_open_file_is_drained_and_copy_truncate_is_detected_after_regrowth() {
    let f = Fixture::new();
    f.append(record("original").as_bytes());
    let mut c = f.collector();
    c.poll(1000).unwrap();
    fs::write(&f.log, record("different-and-longer-than-original")).unwrap();
    let items = c.poll(2000).unwrap();
    assert_eq!(bodies(&items), ["different-and-longer-than-original"]);
    assert!(warned(&items, Outcome::FileReset));
    let mut old = fs::OpenOptions::new().append(true).open(&f.log).unwrap();
    fs::remove_file(&f.log).unwrap();
    old.write_all(record("after-unlink").as_bytes()).unwrap();
    assert_eq!(bodies(&c.poll(3000).unwrap()), ["after-unlink"]);
}
#[test]
fn initial_end_only_skips_preexisting_files_and_saved_offsets_override_policy() {
    let mut f = Fixture::new();
    f.config.initial_read = LogInitialRead::End;
    f.append(record("old").as_bytes());
    let mut c = f.collector();
    assert!(bodies(&c.poll(1000).unwrap()).is_empty());
    c.commit().unwrap();
    drop(c);
    f.append(record("new").as_bytes());
    assert_eq!(bodies(&f.collector().poll(2000).unwrap()), ["new"]);
}
#[test]
fn bounds_timeout_and_privacy_are_observable() {
    let mut f = Fixture::new();
    f.config.max_record_bytes = 128;
    f.config.include_body = false;
    f.append(b"2026-10-10T12:00:00Z stdout P private\n");
    let mut c = f.collector();
    assert!(bodies(&c.poll(1000).unwrap()).is_empty());
    let items = c.poll(6000).unwrap();
    assert!(items.iter().any(
        |i| matches!(i, Collected::Log(l) if l.incomplete && l.body.is_none() && l.body_bytes == 7)
    ));
    f.append(record(&"x".repeat(200)).as_bytes());
    assert!(warned(&c.poll(7000).unwrap(), Outcome::RecordTooLarge));
}
#[test]
fn exit_final_physical_fragment_survives_crash_then_flushes_incomplete() {
    let f = Fixture::new();
    f.append(b"2026-10-10T12:00:00Z stderr F last");
    let mut c = f.collector();
    c.poll(1000).unwrap();
    c.commit().unwrap();
    drop(c);
    let mut c = f.collector();
    c.poll(2000).unwrap();
    let items = c.poll(7000).unwrap();
    assert_eq!(bodies(&items), ["last"]);
    assert!(
        items
            .iter()
            .any(|i| matches!(i, Collected::Log(l) if l.incomplete))
    );
}
#[test]
fn container_churn_keeps_instances_distinct_and_state_bounded() {
    let mut f = Fixture::new();
    f.config.max_files = 1;
    f.append(record("zero").as_bytes());
    let mut c = f.collector();
    c.poll(1000).unwrap();
    fs::write(f.log.with_file_name("1.log"), record("one")).unwrap();
    assert!(warned(&c.poll(2000).unwrap(), Outcome::FileLimit));
    fs::remove_file(&f.log).unwrap();
    let items = c.poll(400_000).unwrap();
    assert_eq!(bodies(&items), ["one"]);
    assert!(
        items
            .iter()
            .any(|i| matches!(i, Collected::Log(l) if l.restart_count == 1 && l.pod_uid == "uid"))
    );
    assert_eq!(c.files.len(), 1);
    c.commit().unwrap();
    assert_eq!(c.saved.len(), 1);
}
#[test]
fn corrupt_checkpoint_is_visible_and_recovery_does_not_trust_temp() {
    let f = Fixture::new();
    {
        let _c = f.collector();
    }
    fs::write(f.config.checkpoint_dir.join("checkpoints.json"), b"corrupt").unwrap();
    f.append(record("replay").as_bytes());
    let items = f.collector().poll(1000).unwrap();
    assert!(warned(&items, Outcome::CheckpointRejected));
    assert_eq!(bodies(&items), ["replay"]);
}
#[test]
fn symlinks_and_duplicate_collectors_are_rejected() {
    let f = Fixture::new();
    let c = f.collector();
    assert!(Collector::new(f.config.clone()).is_err());
    drop(c);
    let outside = f.root.join("outside");
    fs::write(&outside, record("secret")).unwrap();
    fs::remove_file(&f.log).unwrap();
    std::os::unix::fs::symlink(&outside, &f.log).unwrap();
    let items = f.collector().poll(1000).unwrap();
    assert!(bodies(&items).is_empty());
    assert!(warned(&items, Outcome::UnsafePath));
}
#[test]
fn timestamp_validation_checks_calendar_and_precision() {
    for s in ["2024-02-29T23:59:59Z", "2026-10-10T00:00:00.123456789Z"] {
        assert!(valid_timestamp(s));
    }
    for s in [
        "2026-02-29T00:00:00Z",
        "2026-10-10T24:00:00Z",
        "2026-10-10T00:00:00.Z",
        "2026-10-10T00:00:00+00:00",
        "2026-10-10T00:00:00.1234567890Z",
    ] {
        assert!(!valid_timestamp(s));
    }
}

#[test]
fn new_container_after_initial_end_still_recovers_exit_final_records() {
    let mut f = Fixture::new();
    f.config.initial_read = LogInitialRead::End;
    let mut c = f.collector();
    c.poll(1000).unwrap();
    c.commit().unwrap();
    fs::write(f.log.with_file_name("1.log"), record("exit-final")).unwrap();
    assert_eq!(bodies(&c.poll(2000).unwrap()), ["exit-final"]);
}
#[test]
fn malformed_gap_cannot_make_a_partial_record_look_complete() {
    let f = Fixture::new();
    f.append(
        b"2026-10-10T12:00:00Z stdout P before\ninvalid\n2026-10-10T12:00:01Z stdout F after\n",
    );
    let items = f.collector().poll(1000).unwrap();
    assert_eq!(bodies(&items), ["before", "after"]);
    assert!(items.iter().any(
        |i| matches!(i, Collected::Log(l) if l.body.as_deref() == Some("before") && l.incomplete)
    ));
}
#[test]
fn missing_container_directory_during_discovery_does_not_stop_collection() {
    let f = Fixture::new();
    let mut c = f.collector();
    c.poll(1000).unwrap();
    let mut old = fs::OpenOptions::new().append(true).open(&f.log).unwrap();
    fs::remove_dir_all(f.log.parent().unwrap()).unwrap();
    old.write_all(record("exit").as_bytes()).unwrap();
    assert_eq!(bodies(&c.poll(2000).unwrap()), ["exit"]);
}

#[test]
fn invalid_utf8_expansion_stays_inside_the_configured_body_bound() {
    let mut f = Fixture::new();
    f.config.max_record_bytes = 256;
    let mut bytes = b"2026-10-10T12:00:00Z stdout F ".to_vec();
    bytes.extend_from_slice(&[0xff; 200]);
    bytes.push(b'\n');
    f.append(&bytes);
    let items = f.collector().poll(1000).unwrap();
    assert!(items.iter().any(|i| matches!(i, Collected::Log(l) if l.body.as_ref().is_some_and(|b| b.len() <= 256) && l.invalid_utf8 && l.truncated)));
}
#[test]
fn incremental_discovery_never_expires_a_still_present_file() {
    let mut f = Fixture::new();
    f.config.max_files = 1;
    f.config.max_discovery_entries = 1;
    f.config.poll_interval_millis = 1000;
    f.config.assembly_timeout_millis = 1000;
    f.config.retained_file_millis = 1000;
    f.append(record("once").as_bytes());
    let mut c = f.collector();
    let mut collected = Vec::new();
    for now in (1000..=15000).step_by(1000) {
        collected.extend(c.poll(now).unwrap());
        c.commit().unwrap();
    }
    assert_eq!(bodies(&collected), ["once"]);
    assert!(!warned(&collected, Outcome::RetentionExpired));
}
#[test]
fn mutation_between_read_and_commit_never_saves_an_offset_in_replaced_content() {
    let f = Fixture::new();
    f.append(record("before").as_bytes());
    let mut c = f.collector();
    c.poll(1000).unwrap();
    fs::write(&f.log, record("after-longer")).unwrap();
    assert!(c.commit().is_err());
    drop(c);
    assert_eq!(bodies(&f.collector().poll(2000).unwrap()), ["after-longer"]);
}

#[test]
fn recovered_checkpoint_survives_an_initial_scan_longer_than_retention() {
    let mut f = Fixture::new();
    f.config.max_files = 1;
    f.config.max_discovery_entries = 1;
    f.config.poll_interval_millis = 1000;
    f.config.assembly_timeout_millis = 1000;
    f.config.retained_file_millis = 1000;
    f.append(record("once").as_bytes());
    let mut c = f.collector();
    for now in (1000..=6000).step_by(1000) {
        c.poll(now).unwrap();
        c.commit().unwrap();
    }
    drop(c);
    let mut c = f.collector();
    let mut items = Vec::new();
    for now in (7000..=12000).step_by(1000) {
        items.extend(c.poll(now).unwrap());
        c.commit().unwrap();
    }
    assert!(bodies(&items).is_empty());
}
#[test]
fn checkpoint_with_nonzero_offset_and_empty_anchors_is_rejected() {
    let f = Fixture::new();
    f.append(record("must-replay").as_bytes());
    let mut c = f.collector();
    c.poll(1000).unwrap();
    c.commit().unwrap();
    drop(c);
    let path = f.config.checkpoint_dir.join("checkpoints.json");
    let mut snapshot: Checkpoints = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    snapshot.entries[0].prefix.len = 0;
    snapshot.entries[0].tail.len = 0;
    snapshot.entries[0].tail.start = snapshot.entries[0].offset;
    fs::write(path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let items = f.collector().poll(2000).unwrap();
    assert!(warned(&items, Outcome::CheckpointRejected));
    assert_eq!(bodies(&items), ["must-replay"]);
}
#[tokio::test]
async fn source_checkpoints_admission_and_replays_after_a_closed_channel() {
    let mut f = Fixture::new();
    f.config.poll_interval_millis = 10;
    f.append(record("first").as_bytes());
    let source = CriLogSource::new(f.config.clone(), Some("node-a".into()));
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let task = tokio::spawn(Box::new(source).run(tx));
    let signal = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(signal.payload, e_navigator_signals::SignalPayload::ApplicationLogObservation(ref log) if log.body.as_deref() == Some("first"))
    );
    let path = f.config.checkpoint_dir.join("checkpoints.json");
    tokio::time::timeout(Duration::from_secs(2), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let snapshot: Checkpoints = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(snapshot.entries[0].offset, record("first").len() as u64);
    drop(rx);
    f.append(record("second").as_bytes());
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap(),
        Err(CoreError::PipelineClosed)
    ));
    assert_eq!(
        bodies(&f.collector().poll(now_millis()).unwrap()),
        ["second"]
    );
}
