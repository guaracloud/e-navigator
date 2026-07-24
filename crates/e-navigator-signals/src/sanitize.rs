use std::collections::BTreeMap;

/// Shared deny-list fragments identifying secret-bearing attribute keys.
///
/// This is the single vocabulary behind every sensitive-key predicate in the
/// workspace. Signal-family predicates may extend it with family-specific
/// fragments, but they must not shrink it: a key that matches any fragment
/// here is dropped before export on every path. `api-key` subsumes the
/// `x-api-key` header spelling because matching is substring-based.
pub const SENSITIVE_ATTRIBUTE_KEY_PARTS: [&str; 12] = [
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "api_key",
    "api-key",
    "apikey",
    "credential",
    "private_key",
    "jwt",
];

/// Whether `key` matches the shared secret-bearing attribute deny list.
///
/// Matching is an allocation-free, case-insensitive substring test because
/// this runs for every attribute of every envelope on the capture hot path.
pub fn is_sensitive_attribute_key(key: &str) -> bool {
    SENSITIVE_ATTRIBUTE_KEY_PARTS
        .iter()
        .any(|sensitive| contains_ascii_case_insensitive(key, sensitive))
}

/// Case-insensitive ASCII substring test without allocating a lowercased
/// copy of `value`. This runs on capture hot paths for every attribute key
/// checked against the sensitive-key deny list, so it must not allocate.
pub fn contains_ascii_case_insensitive(value: &str, needle: &str) -> bool {
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

pub(crate) fn truncate_utf8_in_place(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }

    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

pub(crate) fn sanitize_kubernetes_labels(
    labels: &mut BTreeMap<String, String>,
    max_labels: usize,
    max_key_bytes: usize,
    max_value_bytes: usize,
) {
    if labels.len() <= max_labels
        && labels
            .keys()
            .all(|key| !key.is_empty() && key.len() <= max_key_bytes)
    {
        for value in labels.values_mut() {
            truncate_utf8_in_place(value, max_value_bytes);
        }
        return;
    }

    *labels = std::mem::take(labels)
        .into_iter()
        .filter(|(key, _)| !key.is_empty())
        .map(|(mut key, mut value)| {
            truncate_utf8_in_place(&mut key, max_key_bytes);
            truncate_utf8_in_place(&mut value, max_value_bytes);
            (key, value)
        })
        .take(max_labels)
        .collect();
}

#[cfg(test)]
mod tests {
    use super::{is_sensitive_attribute_key, sanitize_kubernetes_labels, truncate_utf8_in_place};
    use std::collections::BTreeMap;

    #[test]
    fn shared_sensitive_key_list_matches_all_family_spellings() {
        for key in [
            "passwd",
            "db.password",
            "http.request.header.X-API-Key",
            "http.request.header.x-api-key",
            "session_jwt",
            "tls.private_key.path",
            "service.credential",
            "API_KEY",
        ] {
            assert!(is_sensitive_attribute_key(key), "{key}");
        }
        for key in ["http.route", "db.system", "net.peer.name", ""] {
            assert!(!is_sensitive_attribute_key(key), "{key}");
        }
    }

    #[test]
    fn bounded_string_keeps_its_allocation() {
        let mut value = String::with_capacity(64);
        value.push_str("already bounded");
        let pointer = value.as_ptr();
        let capacity = value.capacity();

        truncate_utf8_in_place(&mut value, 32);

        assert_eq!(value, "already bounded");
        assert_eq!(value.as_ptr(), pointer);
        assert_eq!(value.capacity(), capacity);
    }

    #[test]
    fn truncation_preserves_utf8_and_allocation() {
        let mut value = String::from("1234éé");
        let pointer = value.as_ptr();
        let capacity = value.capacity();

        truncate_utf8_in_place(&mut value, 5);

        assert_eq!(value, "1234");
        assert_eq!(value.as_ptr(), pointer);
        assert_eq!(value.capacity(), capacity);
    }

    #[test]
    fn label_sanitization_reuses_owned_strings() {
        let key = "label-key".to_string();
        let value = "label-value".to_string();
        let key_pointer = key.as_ptr();
        let value_pointer = value.as_ptr();
        let mut labels = BTreeMap::from([(key, value)]);

        sanitize_kubernetes_labels(&mut labels, 16, 128, 256);

        let (key, value) = labels.first_key_value().expect("label remains");
        assert_eq!(key.as_ptr(), key_pointer);
        assert_eq!(value.as_ptr(), value_pointer);
    }

    #[test]
    fn label_sanitization_fallback_preserves_filter_limit_and_collision_semantics() {
        let mut labels = BTreeMap::from([
            (String::new(), "discarded".to_string()),
            ("aa".to_string(), "first".to_string()),
            ("ab".to_string(), "second".to_string()),
            ("z".to_string(), "outside-limit".to_string()),
        ]);

        sanitize_kubernetes_labels(&mut labels, 2, 1, 3);

        assert_eq!(
            labels,
            BTreeMap::from([("a".to_string(), "sec".to_string())])
        );
    }
}
