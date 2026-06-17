pub(crate) fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_nanos_is_monotonic_enough_for_fixture_ordering() {
        let first = now_unix_nanos();
        let second = now_unix_nanos();

        assert!(second >= first);
    }
}
