/// Convert a string to PascalCase.
///
/// - "receiverSig" → "ReceiverSig"
/// - "HTLC" → "HTLC" (all-caps preserved)
/// - "non_interactive_swap" → "NonInteractiveSwap"
pub fn to_pascal_case(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    // Already all-caps (e.g., "HTLC") — preserve as-is
    if s.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return s.to_string();
    }
    // Split on underscores or camelCase boundaries
    let words = split_words(s);
    words
        .iter()
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => {
                    let mut s = c.to_uppercase().to_string();
                    s.extend(chars.map(|c| c.to_ascii_lowercase()));
                    s
                }
            }
        })
        .collect()
}

/// Convert a string to camelCase.
///
/// - "ReceiverSig" → "receiverSig"
/// - "HTLC" → "htlc"
/// - "non_interactive_swap" → "nonInteractiveSwap"
pub fn to_camel_case(s: &str) -> String {
    let pascal = to_pascal_case(s);
    if pascal.is_empty() {
        return pascal;
    }
    // If original is all-caps, lowercase the whole thing
    if s.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return pascal.to_lowercase();
    }
    let mut chars = pascal.chars();
    let first = chars.next().unwrap().to_ascii_lowercase();
    format!("{}{}", first, chars.collect::<String>())
}

/// Convert a placeholder path to an exported Go field name without losing
/// the distinction between path separators and source underscores.
pub fn to_go_field_name(s: &str) -> String {
    if !s.contains('.') {
        return to_pascal_case(s);
    }

    let mut result = String::new();
    for (index, ch) in s.chars().enumerate() {
        match ch {
            '.' => result.push_str("_D"),
            '_' => result.push_str("_U"),
            ch if index == 0 => result.push(ch.to_ascii_uppercase()),
            ch => result.push(ch),
        }
    }
    result
}

/// Convert a string to snake_case.
///
/// - "receiverSig" → "receiver_sig"
/// - "HTLC" → "htlc"
/// - "NonInteractiveSwap" → "non_interactive_swap"
pub fn to_snake_case(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    // All-caps → lowercase
    if s.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return s.to_lowercase();
    }
    let words = split_words(s);
    words
        .iter()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join("_")
}

/// Split a string into words on underscore boundaries and camelCase boundaries.
fn split_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();

    for ch in s.chars() {
        if ch == '_' {
            if !current.is_empty() {
                words.push(current.clone());
                current.clear();
            }
        } else if ch.is_ascii_uppercase() && !current.is_empty() {
            // Check if we're in the middle of an all-caps run (e.g., "HTLC")
            let prev_is_upper = current
                .chars()
                .last()
                .is_some_and(|c| c.is_ascii_uppercase());
            if prev_is_upper {
                // Continue the caps run
                current.push(ch);
            } else {
                words.push(current.clone());
                current.clear();
                current.push(ch);
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_pascal_case() {
        assert_eq!(to_pascal_case("receiverSig"), "ReceiverSig");
        assert_eq!(to_pascal_case("HTLC"), "HTLC");
        assert_eq!(to_pascal_case("non_interactive_swap"), "NonInteractiveSwap");
        assert_eq!(to_pascal_case("htlc"), "Htlc");
        assert_eq!(to_pascal_case("sender"), "Sender");
    }

    #[test]
    fn test_to_go_field_name_preserves_dotted_paths() {
        assert_eq!(to_go_field_name("value.a_b"), "Value_Da_Ub");
        assert_eq!(to_go_field_name("value.a.b"), "Value_Da_Db");
        assert_eq!(to_go_field_name("values.0"), "Values_D0");
    }

    #[test]
    fn test_to_camel_case() {
        assert_eq!(to_camel_case("ReceiverSig"), "receiverSig");
        assert_eq!(to_camel_case("HTLC"), "htlc");
        assert_eq!(to_camel_case("non_interactive_swap"), "nonInteractiveSwap");
    }

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("receiverSig"), "receiver_sig");
        assert_eq!(to_snake_case("HTLC"), "htlc");
        assert_eq!(to_snake_case("NonInteractiveSwap"), "non_interactive_swap");
    }
}
