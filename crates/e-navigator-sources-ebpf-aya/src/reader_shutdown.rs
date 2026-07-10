use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Shared stop flag for blocking reader tasks.
///
/// Only the handle created by [`ReaderShutdown::new`] stops readers on drop.
/// Cloned observer handles can be dropped independently without terminating
/// every reader attached to the same source.
#[derive(Debug)]
pub(crate) struct ReaderShutdown {
    stopped: Arc<AtomicBool>,
    stop_on_drop: bool,
}

impl ReaderShutdown {
    pub(crate) fn new() -> Self {
        Self {
            stopped: Arc::new(AtomicBool::new(false)),
            stop_on_drop: true,
        }
    }

    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
}

impl Clone for ReaderShutdown {
    fn clone(&self) -> Self {
        Self {
            stopped: Arc::clone(&self.stopped),
            stop_on_drop: false,
        }
    }
}

impl Drop for ReaderShutdown {
    fn drop(&mut self) {
        if self.stop_on_drop {
            self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReaderShutdown;

    #[test]
    fn dropping_observer_clone_does_not_stop_readers() {
        let owner = ReaderShutdown::new();
        let observer = owner.clone();

        drop(observer);

        assert!(!owner.is_stopped());
    }

    #[test]
    fn dropping_owner_stops_remaining_observers() {
        let owner = ReaderShutdown::new();
        let observer = owner.clone();

        drop(owner);

        assert!(observer.is_stopped());
    }
}
