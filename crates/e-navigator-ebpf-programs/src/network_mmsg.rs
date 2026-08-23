//! Verifier-bounded native `mmsghdr` traversal shared with host-side tests.

/// Linux caps native `sendmmsg(2)` and `recvmmsg(2)` vectors at `UIO_MAXIOV`.
pub(crate) const NETWORK_MMSG_MAX_MESSAGES: u32 = 1_024;
// Linux LP64 `struct mmsghdr`: 56-byte `msghdr`, then `msg_len`, rounded to a
// 64-byte array stride.
pub(crate) const NETWORK_MMSG_HEADER_BYTES: usize = 64;
pub(crate) const NETWORK_MMSG_LENGTH_OFFSET: usize = 56;

#[inline(always)]
pub(crate) fn completed_messages(retval: i64, vlen: u32) -> Option<u32> {
    let retval = u32::try_from(retval).ok()?;
    (retval != 0 && retval <= vlen && retval <= NETWORK_MMSG_MAX_MESSAGES).then_some(retval)
}

#[inline(always)]
pub(crate) fn message_length_offset(index: u64, completed: u32) -> Option<usize> {
    if index >= u64::from(completed) || completed > NETWORK_MMSG_MAX_MESSAGES {
        return None;
    }
    (index as usize)
        .checked_mul(NETWORK_MMSG_HEADER_BYTES)?
        .checked_add(NETWORK_MMSG_LENGTH_OFFSET)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_linux_native_message_vector_limit() {
        assert_eq!(NETWORK_MMSG_MAX_MESSAGES, 1_024);
        assert_eq!(completed_messages(1_024, 1_024), Some(1_024));
        assert_eq!(message_length_offset(1_023, 1_024), Some(65_528));
    }

    #[test]
    fn computes_each_native_lp64_length_slot_without_overlap() {
        for index in 0..NETWORK_MMSG_MAX_MESSAGES {
            assert_eq!(
                message_length_offset(u64::from(index), NETWORK_MMSG_MAX_MESSAGES),
                Some(index as usize * NETWORK_MMSG_HEADER_BYTES + NETWORK_MMSG_LENGTH_OFFSET)
            );
        }
    }

    #[test]
    fn rejects_invalid_or_out_of_range_batch_results() {
        assert_eq!(completed_messages(-1, 32), None);
        assert_eq!(completed_messages(0, 32), None);
        assert_eq!(completed_messages(1, 0), None);
        assert_eq!(completed_messages(33, 32), None);
        assert_eq!(completed_messages(1_025, 1_025), None);
        assert_eq!(completed_messages(i64::from(u32::MAX) + 1, 1_024), None);
        assert_eq!(message_length_offset(32, 32), None);
        assert_eq!(message_length_offset(0, 1_025), None);
        assert_eq!(message_length_offset(u64::MAX, 1_024), None);
    }
}
