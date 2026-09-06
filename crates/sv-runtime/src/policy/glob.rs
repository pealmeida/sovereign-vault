//! Path-aware glob matching for policy selectors. No regular expressions.
//!
//! `*` matches one or more characters inside a single segment. `**` matches
//! zero or more characters, including across `/` and `.` separators, but it
//! does not collapse adjacent separators: `a/**/c` does NOT match `a/c`.

/// Returns whether `value` matches `pattern`.
pub fn matches(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    let pl = p.len();
    let vl = v.len();
    let mut dp = vec![vec![false; vl + 1]; pl + 1];

    for i in (0..=pl).rev() {
        for j in (0..=vl).rev() {
            if i == pl {
                dp[i][j] = j == vl;
                continue;
            }
            match p[i] {
                '*' if i + 1 < pl && p[i + 1] == '*' => {
                    let k = i + 2;
                    for t in j..=vl {
                        if dp[k][t] {
                            dp[i][j] = true;
                            break;
                        }
                    }
                }
                // One or more characters, stopping at the first separator.
                '*' if j < vl && !is_sep(v[j]) => {
                    let mut t = j + 1;
                    while t <= vl && !is_sep(v[t - 1]) {
                        if dp[i + 1][t] {
                            dp[i][j] = true;
                            break;
                        }
                        t += 1;
                    }
                }
                c if j < vl && c == v[j] => dp[i][j] = dp[i + 1][j + 1],
                _ => {}
            }
        }
    }

    dp[0][0]
}

fn is_sep(c: char) -> bool {
    c == '/' || c == '.'
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn literal_matches_exactly() {
        assert!(matches("abc", "abc"));
        assert!(!matches("abc", "abcd"));
        assert!(!matches("abc", "abx"));
    }

    #[test]
    fn empty_pattern_matches_only_empty() {
        assert!(matches("", ""));
        assert!(!matches("", "x"));
        assert!(!matches("x", ""));
    }

    #[test]
    fn star_matches_within_segment() {
        assert!(matches("a/*/c", "a/b/c"));
    }

    #[test]
    fn star_does_not_cross_slash() {
        assert!(!matches("a/*/c", "a/b/x/c"));
        assert!(!matches("a/*", "a/b/c"));
    }

    #[test]
    fn star_does_not_cross_dot() {
        assert!(matches("pii.*", "pii.email"));
        assert!(!matches("pii.*", "pii.email.domain"));
    }

    #[test]
    fn doublestar_crosses_separators() {
        assert!(matches("a/**/c", "a/b/x/c"));
        assert!(matches("pii.**", "pii.email.domain"));
    }

    #[test]
    fn doublestar_matches_zero_segments() {
        // Chosen behavior: `**` does not collapse adjacent separators, so
        // `a/**/c` requires at least one segment between the two slashes.
        assert!(!matches("a/**/c", "a/c"));
    }

    #[test]
    fn regex_syntax_is_literal() {
        assert!(matches("^pii", "^pii"));
        assert!(!matches("^pii", "pii"));
        assert!(matches("pii.+", "pii.+"));
        assert!(!matches("pii.+", "piiXYZ"));
        assert!(matches("[a-z]+", "[a-z]+"));
        assert!(!matches("[a-z]+", "abc"));
        assert!(matches("a|b", "a|b"));
        assert!(!matches("a|b", "a"));
    }

    #[test]
    fn pathological_pattern_terminates() {
        let value = "x".repeat(200);
        assert!(!matches("**a**b**c**d**e", &value));
    }

    /// `*` is one-or-more, not zero-or-more, so a selector cannot match an
    /// empty segment it did not intend to.
    #[test]
    fn star_requires_at_least_one_character() {
        assert!(!matches("pii.*", "pii."));
        assert!(!matches("a/*/c", "a//c"));
    }

    /// A model glob does not span the version dot, because `.` is a separator.
    #[test]
    fn star_stops_at_a_version_dot() {
        assert!(matches("glm-*", "glm-5"));
        assert!(!matches("glm-*", "glm-5.2"));
    }

    /// A tool namespace glob matches one level, not the whole subtree.
    #[test]
    fn tool_namespace_glob_matches_one_level() {
        assert!(matches("admin.*", "admin.delete"));
        assert!(!matches("admin.*", "admin.users.delete"));
        assert!(matches("issues.*", "issues.search"));
    }

    /// A bare `**` covers any non-empty value, which is what makes it usable as
    /// a catch-all in a deny rule.
    #[test]
    fn bare_doublestar_is_a_catch_all() {
        assert!(matches("**", "anything/at.all"));
        assert!(matches("**", "x"));
    }
}
