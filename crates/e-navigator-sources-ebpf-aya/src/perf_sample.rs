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

#[cfg(test)]
mod tests {
    use super::perf_sample_bytes;
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
}
