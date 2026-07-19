pub(crate) const CAPTURE_FILTER_DISABLED: u32 = 0;
pub(crate) const CAPTURE_FILTER_UNKNOWN_CAPTURE: u32 = 1;

#[inline(always)]
pub(crate) const fn capture_allowed(control: u32, explicit_verdict: Option<u8>) -> bool {
    if control == CAPTURE_FILTER_DISABLED {
        return true;
    }
    match explicit_verdict {
        Some(verdict) => verdict != 0,
        None => control == CAPTURE_FILTER_UNKNOWN_CAPTURE,
    }
}

#[inline(always)]
pub(crate) const fn listener_metadata_allowed(control: u32, explicit_verdict: Option<u8>) -> bool {
    if control == CAPTURE_FILTER_DISABLED {
        return true;
    }
    match explicit_verdict {
        Some(verdict) => verdict != 0,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CAPTURE_FILTER_DISABLED, CAPTURE_FILTER_UNKNOWN_CAPTURE, capture_allowed,
        listener_metadata_allowed,
    };

    const CAPTURE_FILTER_UNKNOWN_DROP: u32 = 2;

    #[test]
    fn payload_capture_preserves_configured_unknown_posture() {
        assert!(capture_allowed(CAPTURE_FILTER_DISABLED, None));
        assert!(capture_allowed(CAPTURE_FILTER_UNKNOWN_CAPTURE, None));
        assert!(!capture_allowed(CAPTURE_FILTER_UNKNOWN_DROP, None));
        assert!(capture_allowed(CAPTURE_FILTER_UNKNOWN_DROP, Some(1)));
        assert!(!capture_allowed(CAPTURE_FILTER_UNKNOWN_CAPTURE, Some(0)));
    }

    #[test]
    fn unknown_listener_metadata_does_not_weaken_payload_default_deny() {
        assert!(listener_metadata_allowed(CAPTURE_FILTER_UNKNOWN_DROP, None));
        assert!(!capture_allowed(CAPTURE_FILTER_UNKNOWN_DROP, None));
        assert!(!listener_metadata_allowed(
            CAPTURE_FILTER_UNKNOWN_DROP,
            Some(0)
        ));
        assert!(listener_metadata_allowed(
            CAPTURE_FILTER_UNKNOWN_DROP,
            Some(1)
        ));
    }
}
