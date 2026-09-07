//! Issuer mapping and rotation-state tracking for the 13 reviewed secret
//! rules.
//!
//! Each rule id in `crates/sv-scan/src/rules.rs` maps to an issuer with a real
//! revocation path. The mapping is reviewed data, not inferred logic.
//!
//! # Rotation state
//!
//! Rotation state is tracked independently of vault state. Moving a file into
//! the vault does not change exposure or rotation state. The UI must keep the
//! rotation advisory visible until the user explicitly marks the credential
//! rotated.
//!
//! None of the 13 issuers can be verified offline. `ProviderConfirmed` is only
//! reachable where an issuer exposes a management API that lists credential
//! identifiers (not values). A generic authentication failure must never be
//! labelled as revoked.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A rotation action known for a credential issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerRule {
    /// Rule id from `sv_scan::RULES`, e.g. `github_pat`.
    pub rule_id: &'static str,
    /// Human-readable issuer name.
    pub name: &'static str,
    /// URL or console path where the credential can be revoked.
    pub revoke_url: &'static str,
    /// Guidance to show alongside the link.
    pub guidance: &'static str,
}

/// Issuers for the 13 reviewed secret rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Issuer {
    /// GitHub personal access token.
    GithubPat,
    /// GitHub OAuth access token.
    GithubOauth,
    /// GitHub fine-grained personal access token.
    GithubFineGrainedPat,
    /// AWS access key ID.
    AwsAccessKeyId,
    /// Stripe live secret key.
    StripeSecretKey,
    /// Stripe test secret key.
    StripeTestKey,
    /// OpenAI API key.
    OpenAiApiKey,
    /// Anthropic API key.
    AnthropicApiKey,
    /// Slack bot token.
    SlackBotToken,
    /// Slack user token.
    SlackUserToken,
    /// Google API key.
    GoogleApiKey,
    /// npm access token.
    NpmToken,
    /// PEM private key; the only issuer with no single answer.
    PrivateKeyPem,
}

impl Issuer {
    /// Stable rule id, matching `sv_scan::RULES`.
    pub fn id(self) -> &'static str {
        self.rule().rule_id
    }

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        self.rule().name
    }

    /// Revocation URL or console path.
    pub fn revoke_url(self) -> &'static str {
        self.rule().revoke_url
    }

    /// Guidance text.
    pub fn guidance(self) -> &'static str {
        self.rule().guidance
    }

    /// The reviewed rule entry.
    pub const fn rule(self) -> IssuerRule {
        match self {
            Issuer::GithubPat => IssuerRule {
                rule_id: "github_pat",
                name: "GitHub personal access token",
                revoke_url: "https://github.com/settings/tokens",
                guidance: "GitHub auto-revokes many leaked tokens on detection. Still, revoke the token manually and verify it is gone.",
            },
            Issuer::GithubOauth => IssuerRule {
                rule_id: "github_oauth",
                name: "GitHub OAuth access token",
                revoke_url: "https://github.com/settings/tokens",
                guidance: "Revoke the token in GitHub settings. Check authorized applications and audit logs for unexpected use.",
            },
            Issuer::GithubFineGrainedPat => IssuerRule {
                rule_id: "github_fine_grained_pat",
                name: "GitHub fine-grained personal access token",
                revoke_url: "https://github.com/settings/tokens",
                guidance: "Fine-grained tokens have scoped repository access. Revoke and replace with a new token scoped to the minimum required.",
            },
            Issuer::AwsAccessKeyId => IssuerRule {
                rule_id: "aws_access_key_id",
                name: "AWS access key ID",
                revoke_url: "https://console.aws.amazon.com/iam/home#/security_credentials",
                guidance: "Deactivate the key pair in IAM before deleting it. Review CloudTrail for unexpected use.",
            },
            Issuer::StripeSecretKey => IssuerRule {
                rule_id: "stripe_secret_key",
                name: "Stripe live secret key",
                revoke_url: "https://dashboard.stripe.com/apikeys",
                guidance: "Roll the key in the Stripe dashboard. Check the events log for unexpected charges or refunds.",
            },
            Issuer::StripeTestKey => IssuerRule {
                rule_id: "stripe_test_key",
                name: "Stripe test secret key",
                revoke_url: "https://dashboard.stripe.com/apikeys",
                guidance: "Test keys move no money, but they still authenticate to Stripe. Rotate and check for unexpected test traffic.",
            },
            Issuer::OpenAiApiKey => IssuerRule {
                rule_id: "openai_api_key",
                name: "OpenAI API key",
                revoke_url: "https://platform.openai.com/api-keys",
                guidance: "Revoke the key in the OpenAI platform. Check usage for unexpected spend.",
            },
            Issuer::AnthropicApiKey => IssuerRule {
                rule_id: "anthropic_api_key",
                name: "Anthropic API key",
                revoke_url: "https://console.anthropic.com/settings/keys",
                guidance: "Revoke the key in the Anthropic console. Check usage for unexpected requests.",
            },
            Issuer::SlackBotToken => IssuerRule {
                rule_id: "slack_bot_token",
                name: "Slack bot token",
                revoke_url: "https://api.slack.com/apps",
                guidance: "Revoke the bot token in the Slack app OAuth settings and reinstall the app to mint a new one.",
            },
            Issuer::SlackUserToken => IssuerRule {
                rule_id: "slack_user_token",
                name: "Slack user token",
                revoke_url: "https://api.slack.com/apps",
                guidance: "Revoke the user token in the Slack app OAuth settings. Reinstall the app if it is distributed.",
            },
            Issuer::GoogleApiKey => IssuerRule {
                rule_id: "google_api_key",
                name: "Google API key",
                revoke_url: "https://console.cloud.google.com/apis/credentials",
                guidance: "Delete the key in the Google Cloud console and consider additional IP or referrer restrictions on the replacement.",
            },
            Issuer::NpmToken => IssuerRule {
                rule_id: "npm_token",
                name: "npm access token",
                revoke_url: "https://www.npmjs.com/settings/~/tokens",
                guidance: "Revoke the token on npmjs.com and check for unexpected publishes.",
            },
            Issuer::PrivateKeyPem => IssuerRule {
                rule_id: "private_key_pem",
                name: "PEM private key",
                revoke_url: "",
                guidance: "There is no single revocation path for a PEM private key. Remove the old key from every trust store and reissue certificates or reconfigure services that accepted it.",
            },
        }
    }
}

/// All issuer mappings, in the same order as `sv_scan::RULES` where possible.
pub const RULE_ISSUERS: &[Issuer] = &[
    Issuer::AwsAccessKeyId,
    Issuer::GithubPat,
    Issuer::GithubOauth,
    Issuer::GithubFineGrainedPat,
    Issuer::SlackBotToken,
    Issuer::SlackUserToken,
    Issuer::StripeSecretKey,
    Issuer::StripeTestKey,
    Issuer::OpenAiApiKey,
    Issuer::AnthropicApiKey,
    Issuer::GoogleApiKey,
    Issuer::NpmToken,
    Issuer::PrivateKeyPem,
];

/// Look up the issuer for a rule id.
pub fn lookup(rule_id: &str) -> Option<Issuer> {
    RULE_ISSUERS.iter().find(|i| i.id() == rule_id).copied()
}

/// Three-valued rotation state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationState {
    /// No attestation or confirmation exists.
    Unknown,
    /// The user said they rotated the credential. This is evidence, not proof.
    UserAttested {
        /// When the user attested.
        at: DateTime<Utc>,
    },
    /// An issuer management API, authenticated with separate management
    /// credentials, confirmed the old credential identifier is gone.
    ///
    /// Never inferred from a generic authentication failure; that could be a
    /// network fault or a scope change.
    ProviderConfirmed {
        /// When the confirmation was obtained.
        at: DateTime<Utc>,
        /// Short description of the evidence (API call, credential id, etc.).
        evidence: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_thirteen_rules_have_issuers() {
        let rule_ids: Vec<&str> = sv_scan::RULES.iter().map(|r| r.id).collect();
        let mapped: Vec<&str> = RULE_ISSUERS.iter().map(|i| i.id()).collect();
        assert_eq!(
            rule_ids.len(),
            mapped.len(),
            "rule count ({}) differs from issuer count ({})",
            rule_ids.len(),
            mapped.len()
        );
        for id in rule_ids {
            assert!(lookup(id).is_some(), "rule {id} has no issuer mapping");
        }
    }

    #[test]
    fn lookup_round_trips_rule_ids() {
        for issuer in RULE_ISSUERS {
            let found = lookup(issuer.id()).unwrap_or_else(|| panic!("{}", issuer.id()));
            assert_eq!(found, *issuer);
        }
    }

    #[test]
    fn private_key_pem_has_empty_revoke_url_and_guidance() {
        let r = Issuer::PrivateKeyPem.rule();
        assert!(r.revoke_url.is_empty());
        assert!(!r.guidance.is_empty());
    }
}
