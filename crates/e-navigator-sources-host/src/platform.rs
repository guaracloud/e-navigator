use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn now_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub(crate) fn clock_ticks_per_second() -> u64 {
    sysconf_positive(libc::_SC_CLK_TCK).unwrap_or(100)
}

pub(crate) fn page_size_bytes() -> u64 {
    sysconf_positive(libc::_SC_PAGESIZE).unwrap_or(4096)
}

fn sysconf_positive(name: libc::c_int) -> Option<u64> {
    let value = unsafe { libc::sysconf(name) };
    (value > 0).then_some(value as u64)
}
