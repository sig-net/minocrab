//! Compact names → Rust names, and back.
//!
//! The mapping has to be a BIJECTION on the names it accepts, because
//! `#[interface]` derives the Compact entry-point name back from the Rust
//! method name by the inverse rule (M9's `snake_case → lowerCamelCase`).
//! Where the round trip does not close — `respondV2`, say — the generator
//! emits an explicit `#[entry_point(name = "…")]` rather than a name that
//! would hash to the wrong entry point.

/// `signBidirectional` → `sign_bidirectional`, `bigR` → `big_r`.
///
/// A `_` goes before every uppercase letter that follows a lowercase
/// letter or a digit; runs of uppercase stay together (`bigR` has none, but
/// `toEVM` would give `to_evm`).
pub fn snake_case(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len() + 4);
    for (i, &ch) in chars.iter().enumerate() {
        if ch.is_ascii_uppercase() {
            let after_lower = i > 0 && (chars[i - 1].is_lowercase() || chars[i - 1].is_ascii_digit());
            let before_lower = chars.get(i + 1).is_some_and(|c| c.is_lowercase());
            let after_upper = i > 0 && chars[i - 1].is_ascii_uppercase();
            if after_lower || (after_upper && before_lower) {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// `sign_bidirectional` → `signBidirectional`. The rule `#[interface]` and
/// `#[derive(CircuitArg)]` already share (minocrab-macros' own
/// `lower_camel_case`), restated here so the generator can check its own
/// output round-trips.
pub fn lower_camel_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper_next = false;
    for ch in name.chars() {
        if ch == '_' {
            upper_next = true;
        } else if upper_next {
            out.extend(ch.to_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// `sign_bidirectional` → `SIGN_BIDIRECTIONAL`, the `EntryPoint` const's
/// name — `#[interface]`'s own rule.
pub fn screaming_snake_case(name: &str) -> String {
    name.to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_corpus_names_round_trip() {
        for name in [
            "signBidirectional",
            "respond",
            "respondBidirectional",
            "deposit",
            "depositEmit",
            "depositBig",
            "confirmRequest",
            "notify",
            "bigR",
            "recoveryId",
            "requestId",
            "version",
            "payload",
            "x",
        ] {
            assert_eq!(lower_camel_case(&snake_case(name)), name, "round trip of {name}");
        }
    }

    #[test]
    fn snake_case_splits_where_expected() {
        assert_eq!(snake_case("signBidirectional"), "sign_bidirectional");
        assert_eq!(snake_case("bigR"), "big_r");
        assert_eq!(snake_case("toEVMAddress"), "to_evm_address");
        assert_eq!(snake_case("deposit"), "deposit");
    }

    /// A name whose round trip does not close is exactly when the
    /// generator must write `#[entry_point(name = …)]`: a Compact circuit
    /// spelled in snake_case, or one with an acronym run.
    #[test]
    fn a_name_that_does_not_round_trip_is_detectable() {
        assert_ne!(lower_camel_case(&snake_case("sign_bidirectional")), "sign_bidirectional");
        assert_ne!(lower_camel_case(&snake_case("toEVMAddress")), "toEVMAddress");
    }
}
