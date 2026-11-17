//! Bounded wire timestamps; calendar and offset validation belong to the parser.

pub(crate) fn parse_rfc3339(value: &str) -> Option<jiff::Timestamp> {
    let bytes = value.as_bytes();
    if !(20..=128).contains(&bytes.len())
        || !bytes.is_ascii()
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't' | b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes.get(17..19) == Some(b"60")
        || [0..4, 5..7, 8..10, 11..13, 14..16, 17..19]
            .iter()
            .any(|part| !bytes[part.clone()].iter().all(u8::is_ascii_digit))
    {
        return None;
    }
    // Jiff also accepts richer ISO/Temporal forms. Keep the native wire domain
    // explicit, and let Jiff validate the actual calendar and UTC offset.
    let mut suffix = &bytes[19..];
    if suffix.first() == Some(&b'.') {
        let digits = suffix[1..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if !(1..=9).contains(&digits) {
            return None;
        }
        suffix = &suffix[1 + digits..];
    }
    if suffix != b"Z"
        && suffix != b"z"
        && !(suffix.len() == 6
            && matches!(suffix[0], b'+' | b'-')
            && suffix[3] == b':'
            && suffix[1..3].iter().all(u8::is_ascii_digit)
            && suffix[4..6].iter().all(u8::is_ascii_digit)
            && (suffix[1] - b'0') * 10 + suffix[2] - b'0' <= 23
            && (suffix[4] - b'0') * 10 + suffix[5] - b'0' <= 59)
    {
        return None;
    }
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::parse_rfc3339;

    #[test]
    fn valid_fractional_and_offset_forms_represent_the_same_instant() {
        let base = parse_rfc3339("2026-11-17T03:00:00.123456789Z").unwrap();
        for value in [
            "2026-11-17T11:00:00.123456789+08:00",
            "2026-11-17t03:00:00.123456789z",
            "2026-11-17 03:00:00.123456789-00:00",
        ] {
            assert_eq!(parse_rfc3339(value), Some(base));
        }
        assert!(parse_rfc3339("2026-11-17T03:00:00.123456788Z").unwrap() < base);
    }

    #[test]
    fn unsupported_leaps_and_extra_precision_are_not_normalized_or_truncated() {
        for value in ["2016-12-31T23:59:60Z", "2026-11-17T03:00:00.1234567890Z"] {
            assert!(
                parse_rfc3339(value).is_none(),
                "unsupported timestamp was accepted: {value}"
            );
        }
    }

    #[test]
    fn malformed_calendar_offsets_annotations_and_unbounded_text_are_rejected() {
        for value in [
            "2026-02-29T03:00:00Z",
            "2026-11-17T03:00:00",
            "2026-11-17T03:00Z",
            "2026-11-17T03:00:00+0800",
            "2026-11-17T03:00:00+24:00",
            "2026-11-17T03:00:00+00:60",
            "2026-11-17T24:00:00Z",
            "2026-11-17T03:60:00Z",
            "2026-11-17T03:00:61Z",
            "2026-11-17T03:00:00Z[UTC]",
            "2026-11-17T03:00:00Z\n",
            "2026-11-17T03:00:00éZ",
        ] {
            assert!(
                parse_rfc3339(value).is_none(),
                "unsupported timestamp was accepted: {value}"
            );
        }
        assert!(parse_rfc3339(&format!("2026-11-17T03:00:00.{}Z", "1".repeat(128))).is_none());
    }
}
