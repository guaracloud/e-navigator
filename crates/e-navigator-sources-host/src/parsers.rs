use e_navigator_signals::{
    MetricAggregationWindow, NodeCpuObservation, NodeDiskIoObservation, NodeLoadObservation,
    NodeMemoryObservation, ProcessResourceContext, ProcessResourceObservation,
};

const DISK_SECTOR_BYTES: u64 = 512;

pub fn parse_cpu_stat(
    contents: &str,
    clock_ticks_per_second: u64,
    start_unix_nanos: u64,
    end_unix_nanos: u64,
) -> Result<NodeCpuObservation, String> {
    let mut cpu_fields = None;
    let mut runnable_tasks = None;
    let mut blocked_tasks = None;

    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("cpu ") {
            cpu_fields = Some(rest);
        } else if let Some(value) = line.strip_prefix("procs_running ") {
            runnable_tasks = parse_u64(value).ok();
        } else if let Some(value) = line.strip_prefix("procs_blocked ") {
            blocked_tasks = parse_u64(value).ok();
        }
    }

    let mut fields = cpu_fields
        .ok_or_else(|| "missing aggregate cpu line".to_string())?
        .split_whitespace();
    let mut next_field = || {
        fields
            .next()
            .ok_or_else(|| "aggregate cpu line has too few fields".to_string())
    };
    let fields = [
        next_field()?,
        next_field()?,
        next_field()?,
        next_field()?,
        next_field()?,
        next_field()?,
        next_field()?,
        next_field()?,
    ];
    let user_ticks = parse_u64(fields[0])?.saturating_add(parse_u64(fields[1])?);

    Ok(NodeCpuObservation {
        metric_name: "system.cpu.time".to_string(),
        unit: "ns".to_string(),
        timestamp_unix_nanos: end_unix_nanos,
        window: MetricAggregationWindow {
            start_unix_nanos,
            end_unix_nanos,
        },
        user_nanos: ticks_to_nanos(user_ticks, clock_ticks_per_second),
        system_nanos: ticks_to_nanos(parse_u64(fields[2])?, clock_ticks_per_second),
        idle_nanos: ticks_to_nanos(parse_u64(fields[3])?, clock_ticks_per_second),
        iowait_nanos: ticks_to_nanos(parse_u64(fields[4])?, clock_ticks_per_second),
        steal_nanos: ticks_to_nanos(parse_u64(fields[7])?, clock_ticks_per_second),
        runnable_tasks,
        blocked_tasks,
    })
}

pub fn parse_loadavg(
    contents: &str,
    start_unix_nanos: u64,
    end_unix_nanos: u64,
) -> Result<NodeLoadObservation, String> {
    let mut fields = contents.split_whitespace();
    let load1 = fields
        .next()
        .ok_or_else(|| "loadavg has too few fields".to_string())?;
    let load5 = fields
        .next()
        .ok_or_else(|| "loadavg has too few fields".to_string())?;
    let load15 = fields
        .next()
        .ok_or_else(|| "loadavg has too few fields".to_string())?;
    let tasks = fields
        .next()
        .ok_or_else(|| "loadavg has too few fields".to_string())?;
    let (runnable_tasks, total_tasks) = tasks
        .split_once('/')
        .map(|(running, total)| (parse_u64(running).ok(), parse_u64(total).ok()))
        .unwrap_or((None, None));

    Ok(NodeLoadObservation {
        metric_name: "system.cpu.load_average.1m".to_string(),
        unit: "1".to_string(),
        timestamp_unix_nanos: end_unix_nanos,
        window: MetricAggregationWindow {
            start_unix_nanos,
            end_unix_nanos,
        },
        load1: parse_f64(load1)?,
        load5: parse_f64(load5)?,
        load15: parse_f64(load15)?,
        runnable_tasks,
        total_tasks,
    })
}

pub fn parse_meminfo(
    contents: &str,
    start_unix_nanos: u64,
    end_unix_nanos: u64,
) -> Result<NodeMemoryObservation, String> {
    let mem_total = meminfo_kib(contents, "MemTotal")?;

    Ok(NodeMemoryObservation {
        metric_name: "system.memory.usage".to_string(),
        unit: "By".to_string(),
        timestamp_unix_nanos: end_unix_nanos,
        window: MetricAggregationWindow {
            start_unix_nanos,
            end_unix_nanos,
        },
        mem_total_bytes: kib_to_bytes(mem_total),
        mem_available_bytes: meminfo_kib(contents, "MemAvailable").ok().map(kib_to_bytes),
        mem_free_bytes: meminfo_kib(contents, "MemFree").ok().map(kib_to_bytes),
        swap_total_bytes: meminfo_kib(contents, "SwapTotal").ok().map(kib_to_bytes),
        swap_free_bytes: meminfo_kib(contents, "SwapFree").ok().map(kib_to_bytes),
    })
}

pub fn parse_diskstats(
    contents: &str,
    start_unix_nanos: u64,
    end_unix_nanos: u64,
) -> Result<Vec<NodeDiskIoObservation>, String> {
    let mut observations = Vec::new();
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let Some(device) = fields.nth(2) else {
            continue;
        };
        let Some(reads_completed) = fields.next() else {
            continue;
        };
        let Some(sectors_read) = fields.nth(1) else {
            continue;
        };
        let Some(writes_completed) = fields.nth(1) else {
            continue;
        };
        let Some(sectors_written) = fields.nth(1) else {
            continue;
        };
        observations.push(NodeDiskIoObservation {
            metric_name: "system.disk.io".to_string(),
            unit: "By".to_string(),
            timestamp_unix_nanos: end_unix_nanos,
            window: MetricAggregationWindow {
                start_unix_nanos,
                end_unix_nanos,
            },
            device: device.to_string(),
            reads_completed: parse_u64(reads_completed)?,
            writes_completed: parse_u64(writes_completed)?,
            read_bytes: parse_u64(sectors_read)?.saturating_mul(DISK_SECTOR_BYTES),
            written_bytes: parse_u64(sectors_written)?.saturating_mul(DISK_SECTOR_BYTES),
        });
    }
    Ok(observations)
}

#[allow(clippy::too_many_arguments)]
pub fn parse_process_stat(
    pid: u32,
    stat: &str,
    status: Option<&str>,
    clock_ticks_per_second: u64,
    page_size_bytes: u64,
    fd_count: u64,
    socket_count: u64,
    start_unix_nanos: u64,
    end_unix_nanos: u64,
) -> Result<ProcessResourceObservation, String> {
    let close = stat
        .rfind(')')
        .ok_or_else(|| "process stat missing command terminator".to_string())?;
    let open = stat[..close]
        .find('(')
        .ok_or_else(|| "process stat missing command opener".to_string())?;
    let rest = stat
        .get(close + ')'.len_utf8()..)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or_else(|| "process stat missing fields".to_string())?;
    let mut fields = rest.split_whitespace();
    let Some(_state) = fields.next() else {
        return Err("process stat has too few fields".to_string());
    };
    let Some(ppid) = fields.next() else {
        return Err("process stat has too few fields".to_string());
    };
    let Some(utime) = fields.nth(9) else {
        return Err("process stat has too few fields".to_string());
    };
    let Some(stime) = fields.next() else {
        return Err("process stat has too few fields".to_string());
    };
    let Some(threads) = fields.nth(4) else {
        return Err("process stat has too few fields".to_string());
    };
    let Some(vsize) = fields.nth(2) else {
        return Err("process stat has too few fields".to_string());
    };
    let Some(rss_pages) = fields.next() else {
        return Err("process stat has too few fields".to_string());
    };
    let command = status
        .and_then(status_name)
        .or_else(|| {
            stat.get(open + '('.len_utf8()..close)
                .map(ToOwned::to_owned)
        })
        .ok_or_else(|| "process stat command has invalid bounds".to_string())?;
    let uid = status.and_then(status_uid);
    let threads = status
        .and_then(status_threads)
        .or_else(|| parse_u64(threads).ok());
    let utime = parse_u64(utime)?;
    let stime = parse_u64(stime)?;
    let vsize = parse_u64(vsize).ok();
    let rss_pages = parse_i64(rss_pages).unwrap_or(0).max(0) as u64;

    Ok(ProcessResourceObservation {
        metric_name: "process.resource".to_string(),
        unit: "1".to_string(),
        timestamp_unix_nanos: end_unix_nanos,
        window: MetricAggregationWindow {
            start_unix_nanos,
            end_unix_nanos,
        },
        process: ProcessResourceContext {
            pid,
            ppid: parse_u64(ppid)
                .ok()
                .and_then(|value| u32::try_from(value).ok()),
            uid,
            command,
            executable: None,
            container: None,
            kubernetes: None,
        },
        cpu_time_nanos: Some(ticks_to_nanos(
            utime.saturating_add(stime),
            clock_ticks_per_second,
        )),
        memory_rss_bytes: Some(rss_pages.saturating_mul(page_size_bytes)),
        virtual_memory_bytes: vsize,
        open_fds: Some(fd_count),
        socket_count: Some(socket_count),
        thread_count: threads,
    })
}

fn meminfo_kib(contents: &str, key: &str) -> Result<u64, String> {
    for line in contents.lines() {
        if let Some(rest) = line
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix(':'))
        {
            let value = rest
                .split_whitespace()
                .next()
                .ok_or_else(|| format!("{key} missing value"))?;
            return parse_u64(value);
        }
    }
    Err(format!("missing {key}"))
}

fn status_name(contents: &str) -> Option<String> {
    status_value(contents, "Name").map(ToOwned::to_owned)
}

fn status_uid(contents: &str) -> Option<u32> {
    status_value(contents, "Uid")
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u32>().ok())
}

fn status_threads(contents: &str) -> Option<u64> {
    status_value(contents, "Threads").and_then(|value| value.parse::<u64>().ok())
}

fn status_value<'a>(contents: &'a str, key: &str) -> Option<&'a str> {
    contents.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix(':'))
            .map(str::trim)
    })
}

fn parse_u64(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|err| format!("invalid unsigned integer {value:?}: {err}"))
}

fn parse_i64(value: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|err| format!("invalid signed integer {value:?}: {err}"))
}

fn parse_f64(value: &str) -> Result<f64, String> {
    value
        .parse::<f64>()
        .map_err(|err| format!("invalid float {value:?}: {err}"))
}

fn ticks_to_nanos(ticks: u64, clock_ticks_per_second: u64) -> u64 {
    ticks
        .saturating_mul(1_000_000_000)
        .checked_div(clock_ticks_per_second.max(1))
        .unwrap_or(0)
}

fn kib_to_bytes(kib: u64) -> u64 {
    kib.saturating_mul(1024)
}

#[cfg(test)]
mod tests {
    use super::{
        parse_cpu_stat, parse_diskstats, parse_loadavg, parse_meminfo, parse_process_stat,
    };

    #[test]
    fn parses_proc_stat_cpu_and_saturation_without_unbounded_labels() {
        let cpu = parse_cpu_stat(
            "cpu  100 0 50 500 10 0 0 2 0 0\nprocs_running 3\nprocs_blocked 1\n",
            100,
            1_000,
            2_000,
        )
        .expect("cpu stat parses");

        assert_eq!(cpu.metric_name, "system.cpu.time");
        assert_eq!(cpu.unit, "ns");
        assert_eq!(cpu.user_nanos, 1_000_000_000);
        assert_eq!(cpu.system_nanos, 500_000_000);
        assert_eq!(cpu.idle_nanos, 5_000_000_000);
        assert_eq!(cpu.iowait_nanos, 100_000_000);
        assert_eq!(cpu.steal_nanos, 20_000_000);
        assert_eq!(cpu.runnable_tasks, Some(3));
        assert_eq!(cpu.blocked_tasks, Some(1));
    }

    #[test]
    fn cpu_user_and_nice_ticks_saturate_instead_of_overflowing() {
        let cpu = parse_cpu_stat("cpu  18446744073709551615 1 0 0 0 0 0 0\n", 1, 1_000, 2_000)
            .expect("extreme cpu ticks parse without overflow");

        assert_eq!(cpu.user_nanos, u64::MAX);
    }

    #[test]
    fn parses_load_and_memory_fixtures() {
        let load =
            parse_loadavg("0.25 0.50 0.75 2/200 12345\n", 1_000, 2_000).expect("load parses");
        assert_eq!(load.metric_name, "system.cpu.load_average.1m");
        assert_eq!(load.load1, 0.25);
        assert_eq!(load.runnable_tasks, Some(2));
        assert_eq!(load.total_tasks, Some(200));

        let memory = parse_meminfo(
            "MemTotal:        8192 kB\nMemFree:         2048 kB\nMemAvailable:    4096 kB\nSwapTotal:       1024 kB\nSwapFree:         512 kB\n",
            1_000,
            2_000,
        )
        .expect("meminfo parses");
        assert_eq!(memory.metric_name, "system.memory.usage");
        assert_eq!(memory.mem_total_bytes, 8_388_608);
        assert_eq!(memory.mem_available_bytes, Some(4_194_304));
        assert_eq!(memory.swap_free_bytes, Some(524_288));
    }

    #[test]
    fn parses_diskstats_with_block_byte_units() {
        let disks = parse_diskstats(
            "259 0 nvme0n1 10 0 8 0 20 0 16 0 0 0 0 0 0 0 0\n",
            1_000,
            2_000,
        )
        .expect("diskstats parses");

        assert_eq!(disks.len(), 1);
        assert_eq!(disks[0].device, "nvme0n1");
        assert_eq!(disks[0].read_bytes, 4_096);
        assert_eq!(disks[0].written_bytes, 8_192);
    }

    #[test]
    fn parses_process_resource_stat_without_command_cardinality_in_keys() {
        let process = parse_process_stat(
            42,
            "42 (api worker) S 1 1 1 0 -1 0 0 0 0 0 12 6 0 0 20 0 4 0 100 8192 8\n",
            Some("Name:\tapi\nUid:\t1000\t1000\t1000\t1000\nThreads:\t4\n"),
            100,
            4096,
            2,
            1,
            1_000,
            2_000,
        )
        .expect("process stat parses");

        assert_eq!(process.process.pid, 42);
        assert_eq!(process.process.command, "api");
        assert_eq!(process.process.ppid, Some(1));
        assert_eq!(process.process.uid, Some(1000));
        assert_eq!(process.cpu_time_nanos, Some(180_000_000));
        assert_eq!(process.memory_rss_bytes, Some(32_768));
        assert_eq!(process.open_fds, Some(2));
        assert_eq!(process.socket_count, Some(1));
        assert_eq!(process.thread_count, Some(4));
    }

    #[test]
    fn parse_process_stat_keeps_parentheses_and_spaces_without_status_name() {
        let process = parse_process_stat(
            42,
            "42 (api (blue) worker) S 1 1 1 0 -1 0 0 0 0 0 12 6 0 0 20 0 7 0 100 8192 -5\n",
            None,
            100,
            4096,
            0,
            0,
            1_000,
            2_000,
        )
        .expect("process stat parses");

        assert_eq!(process.process.command, "api (blue) worker");
        assert_eq!(process.thread_count, Some(7));
        assert_eq!(process.memory_rss_bytes, Some(0));
    }

    #[test]
    fn adversarial_procfs_parsers_reject_malformed_inputs_without_panics() {
        assert!(parse_cpu_stat("", 100, 1_000, 2_000).is_err());
        assert!(parse_cpu_stat("cpu 1 2 3\n", 100, 1_000, 2_000).is_err());
        assert!(parse_loadavg("not-a-float 0.1 0.2 1/2 3\n", 1_000, 2_000).is_err());
        assert!(parse_meminfo("MemFree: 1 kB\n", 1_000, 2_000).is_err());
        assert!(
            parse_process_stat(42, "42 api S 1 1 1", None, 100, 4096, 0, 0, 1_000, 2_000,).is_err()
        );
    }

    #[test]
    fn process_stat_rejects_fuzzed_non_char_boundary_command_without_panic() {
        let data = [
            167, 32, 9, 255, 10, 10, 255, 9, 10, 41, 9, 255, 10, 38, 9, 255, 10, 10, 255, 9, 255,
            10, 38, 9, 255, 10, 10, 255, 38, 9, 255, 49, 10, 33, 10, 1, 10, 1, 38, 255, 10, 38, 9,
            255, 10, 10, 255, 9, 255, 10, 38, 9, 255, 10, 10, 255, 38, 9, 255, 10, 38, 9, 255, 10,
            10, 255, 38, 9, 255, 49, 10, 33, 10, 1, 10, 1, 38, 255, 10, 38,
        ];
        let contents = String::from_utf8_lossy(&data);

        assert!(
            parse_process_stat(
                42,
                &contents,
                Some(&contents),
                100,
                4096,
                0,
                0,
                1_000,
                2_000,
            )
            .is_err()
        );
    }

    #[test]
    fn diskstats_byte_conversion_saturates_on_extreme_sector_counts() {
        let disks = parse_diskstats(
            "259 0 nvme0n1 1 0 18446744073709551615 0 1 0 18446744073709551615 0\n",
            1_000,
            2_000,
        )
        .expect("diskstats parses with saturating byte conversion");

        assert_eq!(disks[0].read_bytes, u64::MAX);
        assert_eq!(disks[0].written_bytes, u64::MAX);
    }

    #[test]
    fn malformed_missing_and_partial_files_are_non_fatal_warnings() {
        assert!(parse_cpu_stat("intr 1\n", 100, 1_000, 2_000).is_err());
        assert!(parse_meminfo("MemFree: 1 kB\n", 1_000, 2_000).is_err());
        assert!(parse_loadavg("0.1 0.2\n", 1_000, 2_000).is_err());
        assert!(
            parse_diskstats("not enough\n", 1_000, 2_000)
                .expect("partial line skipped")
                .is_empty()
        );
    }
}
