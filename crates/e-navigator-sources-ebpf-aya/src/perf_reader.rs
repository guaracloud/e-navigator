//! Readiness-driven waiting for synchronous Aya perf-event buffers.
//!
//! Aya's perf buffers expose file descriptors but deliberately do not bind to
//! an async runtime. Each CPU reader remains a blocking worker, uses `poll` to
//! sleep until the kernel marks its buffer readable, and then keeps the proven
//! 25 ms coalescing window before draining. Idle readers therefore consume no
//! periodic scheduling work, while active readers retain bounded batching and
//! latency. A 250 ms timeout bounds shutdown observation and lets sources with
//! cross-CPU ordering advance their idle-reader watermarks.

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::AsFd,
    io::Errno,
};
use std::time::Duration;
use tracing::warn;

const ACTIVE_COALESCE_DELAY: Duration = Duration::from_millis(25);
const SHUTDOWN_CHECK_TIMEOUT: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 250_000_000,
};
const POLL_ERROR_BACKOFF: Duration = Duration::from_secs(1);

/// Returns `Some(true)` for readable data, `Some(false)` for a clean timeout,
/// and `None` after a polling error has been logged and backoff applied.
pub(crate) fn wait_for_events<T: AsFd>(
    buffer: &T,
    source: &'static str,
    cpu_id: u32,
) -> Option<bool> {
    wait_for_readiness(buffer, source, Some(cpu_id))
}

/// Waits for a shared ring buffer with the same bounded coalescing delay as
/// the perf readers. Ring-buffer notifications only coalesce on their own
/// while the consumer lags; at low and moderate event rates the consumer
/// always keeps up, so every event otherwise costs a full poll wakeup,
/// drain, and downstream channel wake. Sleeping once per readiness batches
/// those events with no loss: producers keep reserving ring space while the
/// reader sleeps, and event timestamps are kernel-assigned.
pub(crate) fn wait_for_ring_events<T: AsFd>(buffer: &T, source: &'static str) -> Option<bool> {
    wait_for_readiness(buffer, source, None)
}

fn wait_for_readiness<T: AsFd>(
    buffer: &T,
    source: &'static str,
    cpu_id: Option<u32>,
) -> Option<bool> {
    let mut descriptors = [PollFd::new(buffer, PollFlags::IN)];
    loop {
        match poll(&mut descriptors, Some(&SHUTDOWN_CHECK_TIMEOUT)) {
            Ok(0) => return Some(false),
            Ok(_) => {
                let events = descriptors[0].revents();
                if events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
                    warn!(source, ?cpu_id, ?events, "event reader readiness failed");
                    std::thread::sleep(POLL_ERROR_BACKOFF);
                    return None;
                }
                if events.contains(PollFlags::IN) {
                    std::thread::sleep(ACTIVE_COALESCE_DELAY);
                    return Some(true);
                }
                return Some(false);
            }
            Err(Errno::INTR) => continue,
            Err(err) => {
                warn!(source, ?cpu_id, error = %err, "event reader poll failed");
                std::thread::sleep(POLL_ERROR_BACKOFF);
                return None;
            }
        }
    }
}
