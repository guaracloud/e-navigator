//! Fail-closed checks shared by TLS handle and goroutine capture paths.

#[inline(always)]
pub(crate) const fn capture_identity_matches(
    captured_process: u64,
    current_process: u64,
    captured_connection: u64,
    current_connection: u64,
) -> bool {
    captured_process != 0
        && captured_process == current_process
        && captured_connection != 0
        && captured_connection == current_connection
}

#[inline(always)]
pub(crate) const fn connection_is_current(
    process_generation: u64,
    connection_started: u64,
) -> bool {
    process_generation != 0 && connection_started >= process_generation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_same_process_and_socket_generation_can_complete_io() {
        assert!(capture_identity_matches(10, 10, 20, 20));
        // exec, PID reuse, or generation-map eviction invalidates old work.
        assert!(!capture_identity_matches(10, 11, 20, 20));
        // Closing and reusing an fd must not redirect an in-flight TLS call.
        assert!(!capture_identity_matches(10, 10, 20, 21));
        for missing in [(0, 10, 20, 20), (10, 0, 20, 20), (10, 10, 0, 20)] {
            assert!(!capture_identity_matches(
                missing.0, missing.1, missing.2, missing.3
            ));
        }
    }

    #[test]
    fn connections_from_before_the_process_generation_are_rejected() {
        assert!(connection_is_current(10, 20));
        assert!(connection_is_current(10, 10));
        assert!(!connection_is_current(20, 10));
        assert!(!connection_is_current(0, 10));
    }
}
