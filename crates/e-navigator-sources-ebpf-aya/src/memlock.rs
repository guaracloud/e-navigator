use tracing::debug;

pub(crate) fn bump_memlock_rlimit() {
    let rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `rlimit` is fully initialized and lives for the duration of the
    // call. `setrlimit` only reads the pointed-to value.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };
    if ret != 0 {
        debug!("failed to raise RLIMIT_MEMLOCK");
    }
}
