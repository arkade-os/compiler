//! Error codes: an id and an explanation for the errors an author most often meets, set as the
//! diagnostic `code` and printed by `arkadec --explain`, as lints are.

macro_rules! errors {
    ($($variant:ident: $id:literal, $summary:literal;)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ErrorCode {
            $($variant),*
        }

        impl ErrorCode {
            pub const ALL: &'static [ErrorCode] = &[$(ErrorCode::$variant),*];

            /// The id the diagnostic `code` and `--explain` use.
            pub fn id(self) -> &'static str {
                match self {
                    $(ErrorCode::$variant => $id),*
                }
            }

            pub fn summary(self) -> &'static str {
                match self {
                    $(ErrorCode::$variant => $summary),*
                }
            }

            /// What the error means and how to fix it, in Markdown.
            pub fn explanation(self) -> &'static str {
                match self {
                    $(ErrorCode::$variant => include_str!(concat!("docs/", $id, ".md"))),*
                }
            }
        }
    };
}

errors! {
    UnknownName: "unknown-name", "a name no binding in scope declares";
    UnknownFunction: "unknown-function", "a call to no builtin and no function of the contract";
}

impl std::str::FromStr for ErrorCode {
    type Err = String;

    fn from_str(id: &str) -> Result<Self, String> {
        ErrorCode::ALL
            .iter()
            .copied()
            .find(|code| code.id() == id)
            .ok_or_else(|| format!("unknown error code '{id}'"))
    }
}

/// The candidate closest to `name`, when one is within a third of the name's length in edits,
/// so names under three characters get none.
pub(crate) fn closest<'a>(
    name: &str,
    candidates: impl IntoIterator<Item = &'a str>,
) -> Option<&'a str> {
    let limit = name.chars().count() / 3;
    candidates
        .into_iter()
        .filter(|candidate| *candidate != name)
        .map(|candidate| (distance(name, candidate), candidate))
        .filter(|(distance, _)| *distance <= limit)
        .min()
        .map(|(_, candidate)| candidate)
}

/// Edits (insert, delete, replace, swap two neighbours) that turn `a` into `b`.
fn distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut rows = vec![(0..=b.len()).collect::<Vec<_>>()];
    for i in 1..=a.len() {
        let mut row = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            row[j] = (rows[i - 1][j] + 1)
                .min(row[j - 1] + 1)
                .min(rows[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                row[j] = row[j].min(rows[i - 2][j - 2] + 1);
            }
        }
        rows.push(row);
    }
    rows[a.len()][b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggests_only_close_names() {
        assert_eq!(closest("ownr", ["owner", "exit"]), Some("owner"));
        assert_eq!(closest("sha265", ["sha256", "sha1"]), Some("sha256"));
        assert_eq!(closest("x", ["y"]), None);
        assert_eq!(closest("amount", ["owner", "exit"]), None);
        assert_eq!(closest("owner", ["owner"]), None);
    }

    #[test]
    fn every_code_has_a_unique_id_and_an_explanation() {
        for (index, code) in ErrorCode::ALL.iter().enumerate() {
            assert!(ErrorCode::ALL[..index].iter().all(|c| c.id() != code.id()));
            assert_eq!(code.id().parse::<ErrorCode>(), Ok(*code));
            assert!(!code.explanation().trim().is_empty(), "{}", code.id());
        }
    }
}
