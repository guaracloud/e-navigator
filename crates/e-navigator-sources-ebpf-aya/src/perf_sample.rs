use std::borrow::Cow;

pub(crate) fn perf_sample_bytes<'a>(head: &'a [u8], tail: &'a [u8]) -> Cow<'a, [u8]> {
    if tail.is_empty() {
        Cow::Borrowed(head)
    } else {
        let mut bytes = Vec::with_capacity(head.len() + tail.len());
        bytes.extend_from_slice(head);
        bytes.extend_from_slice(tail);
        Cow::Owned(bytes)
    }
}

/// Largest fixed-size perf sample carried between the reader and decoder
/// threads. The protocol and TLS sources both emit `RawProtocolDataEvent`
/// (368 bytes); the bound is rounded up with headroom.
pub(crate) const MAX_INLINE_SAMPLE_BYTES: usize = 384;

/// An owned copy of a perf sample stored inline in a fixed-size buffer,
/// so handing a sample from a reader thread to the decoder needs no
/// per-event heap allocation. Reader threads run per-CPU, so the removed
/// allocations also remove global-allocator contention on the hot path.
#[derive(Clone, Copy)]
pub(crate) struct InlineSample {
    len: u16,
    buf: [u8; MAX_INLINE_SAMPLE_BYTES],
}

impl InlineSample {
    /// Copies a (possibly ring-wrapped) perf sample into an inline
    /// buffer. Returns `None` when the sample is larger than the buffer,
    /// so an oversized sample is dropped with accounting rather than
    /// silently truncated.
    pub(crate) fn from_perf(head: &[u8], tail: &[u8]) -> Option<Self> {
        let total = head.len().checked_add(tail.len())?;
        if total > MAX_INLINE_SAMPLE_BYTES {
            return None;
        }
        let mut buf = [0u8; MAX_INLINE_SAMPLE_BYTES];
        buf[..head.len()].copy_from_slice(head);
        buf[head.len()..total].copy_from_slice(tail);
        Some(Self {
            len: total as u16,
            buf,
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

/// Benchmark helper that reproduces the old per-event allocation for
/// comparison with the inline sample path.
#[cfg(feature = "fuzzing")]
pub fn bench_perf_sample_into_owned(head: &[u8], tail: &[u8]) -> usize {
    perf_sample_bytes(head, tail).into_owned().len()
}

/// Benchmark helper: the allocation-free inline copy path.
#[cfg(feature = "fuzzing")]
pub fn bench_inline_sample(head: &[u8], tail: &[u8]) -> usize {
    InlineSample::from_perf(head, tail).map_or(0, |sample| sample.as_bytes().len())
}

#[cfg(test)]
mod tests {
    use super::{InlineSample, MAX_INLINE_SAMPLE_BYTES, perf_sample_bytes};
    use std::borrow::Cow;

    #[test]
    fn borrows_contiguous_samples() {
        let sample = [1, 2, 3];

        assert!(matches!(perf_sample_bytes(&sample, &[]), Cow::Borrowed(_)));
        assert_eq!(perf_sample_bytes(&sample, &[]).as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn joins_wrapped_samples() {
        let head = [1, 2];
        let tail = [3, 4];

        assert!(matches!(perf_sample_bytes(&head, &tail), Cow::Owned(_)));
        assert_eq!(perf_sample_bytes(&head, &tail).as_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn inline_sample_joins_wrapped_bytes_and_rejects_oversize() {
        let sample = InlineSample::from_perf(&[1, 2], &[3, 4]).expect("sample fits");

        assert_eq!(sample.as_bytes(), &[1, 2, 3, 4]);
        assert!(InlineSample::from_perf(&vec![0; MAX_INLINE_SAMPLE_BYTES + 1], &[]).is_none());
    }
}
