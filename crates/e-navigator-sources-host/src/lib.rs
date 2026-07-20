#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]
//! Bounded host resource collection from procfs, sysfs, and cgroups.

mod cgroup;
mod config;
mod filesystem;
mod model;
mod node;
mod parsers;
mod platform;
mod process;
mod snapshot;
mod source;

pub use config::HostResourceConfig;
pub use model::{CgroupSample, HostResourceSnapshot};
pub use parsers::{
    parse_cpu_stat, parse_diskstats, parse_loadavg, parse_meminfo, parse_process_stat,
};
pub use source::HostResourceSource;
