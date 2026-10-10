use e_navigator_context_propagation::context_is_fresh;

#[test]
fn context_lifetime_rejects_missing_future_and_expired_state() {
    assert!(context_is_fresh(10, 10, 5));
    assert!(context_is_fresh(10, 14, 5));
    assert!(!context_is_fresh(10, 15, 5));
    assert!(!context_is_fresh(0, 1, 5));
    assert!(!context_is_fresh(11, 10, 5));
    assert!(!context_is_fresh(10, 10, 0));
    assert!(!context_is_fresh(1, u64::MAX, 5));
}
