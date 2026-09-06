//! Hand-reviewed secret-format rules (per ADR-0017 §3).
//!
//! Each rule describes one well-published credential shape as reviewed data:
//! a literal prefix, a length constraint, and a character alphabet. The
//! matcher in [`crate::detect`] applies these mechanically with a hand-rolled
//! byte scanner; no rule here is executed as a regular expression, keeping the
//! crate free of a regex engine per ADR-0010.

use crate::types::Confidence;

/// Rule id of the PEM private-key header, which has its own matcher branch.
pub(crate) const PEM_RULE_ID: &str = "private_key_pem";

/// A hand-reviewed rule describing one credential format.
pub struct SecretRule {
    /// Stable identifier, e.g. `aws_access_key_id`. Appears in `FindingKind::Secret`.
    pub id: &'static str,
    /// Human-readable name for reports.
    pub name: &'static str,
    /// Literal prefix the token starts with, when it has one.
    pub prefix: Option<&'static str>,
    /// Exact total token length in bytes, when the format is fixed-length.
    pub exact_len: Option<usize>,
    /// Inclusive (min, max) total token length, when the format is variable.
    pub len_range: Option<(usize, usize)>,
    /// Which characters may appear in the body of the token.
    pub alphabet: Alphabet,
    /// Confidence to assign when this rule matches.
    pub confidence: Confidence,
}

/// The character class a rule's token body is drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    /// A-Z a-z 0-9
    Alnum,
    /// A-Z a-z 0-9 plus `-` and `_`
    AlnumDashUnderscore,
    /// A-Z 0-9 only
    UpperAlnum,
    /// Lowercase hexadecimal: 0-9 a-f
    HexLower,
    /// A-Z a-z 0-9 plus `+` `/` `=`
    Base64,
}

impl Alphabet {
    /// Whether the byte `b` is a member of this alphabet.
    pub(crate) fn contains(self, b: u8) -> bool {
        match self {
            Alphabet::Alnum => b.is_ascii_alphanumeric(),
            Alphabet::AlnumDashUnderscore => b.is_ascii_alphanumeric() || b == b'-' || b == b'_',
            Alphabet::UpperAlnum => b.is_ascii_uppercase() || b.is_ascii_digit(),
            Alphabet::HexLower => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
            Alphabet::Base64 => b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='),
        }
    }
}

/// The reviewed secret-format rules, in a stable order.
///
/// Order is deterministic. Matching itself is order-independent because
/// overlapping spans are resolved by confidence, span length, then rule id
/// (see [`crate::detect`]).
pub const RULES: &[SecretRule] = &[
    // AWS access key ID.
    SecretRule {
        id: "aws_access_key_id",
        name: "AWS access key ID",
        prefix: Some("AKIA"),
        exact_len: Some(20),
        len_range: None,
        alphabet: Alphabet::UpperAlnum,
        confidence: Confidence::High,
    },
    // GitHub personal access token.
    SecretRule {
        id: "github_pat",
        name: "GitHub personal access token",
        prefix: Some("ghp_"),
        exact_len: Some(40),
        len_range: None,
        alphabet: Alphabet::AlnumDashUnderscore,
        confidence: Confidence::High,
    },
    // GitHub OAuth access token.
    SecretRule {
        id: "github_oauth",
        name: "GitHub OAuth access token",
        prefix: Some("gho_"),
        exact_len: Some(40),
        len_range: None,
        alphabet: Alphabet::AlnumDashUnderscore,
        confidence: Confidence::High,
    },
    // GitHub fine-grained personal access token.
    SecretRule {
        id: "github_fine_grained_pat",
        name: "GitHub fine-grained personal access token",
        prefix: Some("github_pat_"),
        exact_len: None,
        len_range: Some((82, 100)),
        alphabet: Alphabet::AlnumDashUnderscore,
        confidence: Confidence::High,
    },
    // Slack bot token.
    SecretRule {
        id: "slack_bot_token",
        name: "Slack bot token",
        prefix: Some("xoxb-"),
        exact_len: None,
        len_range: Some((24, 80)),
        alphabet: Alphabet::AlnumDashUnderscore,
        confidence: Confidence::High,
    },
    // Slack user token.
    SecretRule {
        id: "slack_user_token",
        name: "Slack user token",
        prefix: Some("xoxp-"),
        exact_len: None,
        len_range: Some((24, 80)),
        alphabet: Alphabet::AlnumDashUnderscore,
        confidence: Confidence::High,
    },
    // Stripe live secret key.
    SecretRule {
        id: "stripe_secret_key",
        name: "Stripe live secret key",
        prefix: Some("sk_live_"),
        exact_len: None,
        len_range: Some((20, 60)),
        alphabet: Alphabet::Alnum,
        confidence: Confidence::High,
    },
    // Stripe test secret key.
    SecretRule {
        id: "stripe_test_key",
        name: "Stripe test secret key",
        prefix: Some("sk_test_"),
        exact_len: None,
        len_range: Some((20, 60)),
        alphabet: Alphabet::Alnum,
        confidence: Confidence::Medium,
    },
    // OpenAI API key.
    SecretRule {
        id: "openai_api_key",
        name: "OpenAI API key",
        prefix: Some("sk-"),
        exact_len: None,
        len_range: Some((20, 120)),
        alphabet: Alphabet::AlnumDashUnderscore,
        confidence: Confidence::Medium,
    },
    // Anthropic API key.
    SecretRule {
        id: "anthropic_api_key",
        name: "Anthropic API key",
        prefix: Some("sk-ant-"),
        exact_len: None,
        len_range: Some((30, 120)),
        alphabet: Alphabet::AlnumDashUnderscore,
        confidence: Confidence::High,
    },
    // Google API key.
    SecretRule {
        id: "google_api_key",
        name: "Google API key",
        prefix: Some("AIza"),
        exact_len: Some(39),
        len_range: None,
        alphabet: Alphabet::AlnumDashUnderscore,
        confidence: Confidence::High,
    },
    // npm access token.
    SecretRule {
        id: "npm_token",
        name: "npm access token",
        prefix: Some("npm_"),
        exact_len: Some(40),
        len_range: None,
        alphabet: Alphabet::Alnum,
        confidence: Confidence::High,
    },
    // PEM private-key header line. Has its own matcher branch: the alphabet
    // and length fields below are unused for this rule.
    SecretRule {
        id: PEM_RULE_ID,
        name: "PEM private-key header",
        prefix: Some("-----BEGIN"),
        exact_len: None,
        len_range: None,
        alphabet: Alphabet::Alnum,
        confidence: Confidence::High,
    },
];

/// Names that, appearing to the left of a candidate on the same line, indicate
/// the value is a credential.
pub const SECRET_KEYWORDS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "secret_key",
    "token",
    "password",
    "passwd",
    "pwd",
    "credential",
    "private_key",
    "access_key",
    "auth",
    "bearer",
];
