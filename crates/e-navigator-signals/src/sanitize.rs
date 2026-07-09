use std::collections::BTreeMap;

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
    use super::{sanitize_kubernetes_labels, truncate_utf8_in_place};
    use std::collections::BTreeMap;

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
}
