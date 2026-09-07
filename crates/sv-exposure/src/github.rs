//! GitHub API integration for exposure intelligence.
//!
//! This module is gated behind the `github` feature because it is the only code
//! in `sv-exposure` that makes outbound network calls.
//!
//! # Security boundary
//!
//! The user's GitHub **connector token** is read from `gh` CLI configuration or
//! the `GITHUB_TOKEN` environment variable and is transmitted to GitHub's API to
//! authenticate. That is deliberate and expected: the token is a separately
//! authorized connector credential, not a discovered secret.
//!
//! Conversely, **no discovered credential is ever sent to GitHub or anywhere
//! else**. There is no code path that puts a matched secret value into a URL,
//! query parameter, header, or request body. In particular, this crate never
//! queries `/search/code` or any other endpoint that would transmit a secret.
//! The only safe outbound query is one that asks GitHub what GitHub already
//! found.
//!
//! The alert response body **contains the plaintext secret**, so it is handled
//! as inbound secret material: it is parsed in memory, only metadata and a
//! transient keyed fingerprint are extracted, and the rest is dropped before
//! leaving the parser. The raw body is never logged, never written to disk, and
//! never placed in an error message.
//!
//! # Correlation discipline
//!
//! Metadata alone (secret type, state, timestamps) cannot tie an alert to a
//! specific finding — two OpenAI keys in the same repo share all three. Before
//! an alert affects a finding, the returned secret value is correlated using a
//! caller-provided ephemeral 32-byte key:
//!
//! 1. The parser computes a keyed fingerprint of the GitHub-supplied secret and
//!    stores it on the alert.
//! 2. The caller computes the same keyed fingerprint over the finding's own
//!    matched value.
//! 3. The two fingerprints are compared in memory; the key and the values are
//!    discarded immediately afterwards.
//!
//! The fingerprint never leaves the process, is never persisted, and is useless
//! without the key.
//!
//! A no-alert result means exactly "no alerts returned within the authorized
//! query scope at time T". It does **not** mean the repository is clean. Alerts
//! are paginated completely and the states queried (`open`, `resolved`) are
//! recorded so a partial page cannot be mistaken for a clean verdict.

use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

/// Errors that can occur when calling the GitHub API.
#[derive(Debug, thiserror::Error)]
pub enum GitHubError {
    /// The GitHub token could not be found.
    #[error("no GitHub token available: check gh auth or set GITHUB_TOKEN")]
    MissingToken,
    /// The repository owner/name pair could not be parsed.
    #[error("invalid repository identifier")]
    InvalidRepo,
    /// The HTTP request failed.
    #[error("GitHub request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    /// The response was not valid JSON.
    ///
    /// The raw response body is deliberately not included, because it may contain
    /// plaintext secrets.
    #[error("GitHub response could not be parsed")]
    ParseFailed,
}

/// Parsed repository identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoId {
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub name: String,
}

impl RepoId {
    /// Parse from a string like `owner/name`.
    pub fn parse(value: &str) -> Option<RepoId> {
        let mut parts = value.splitn(2, '/');
        let owner = parts.next()?.trim().to_string();
        let name = parts.next()?.trim().to_string();
        if owner.is_empty() || name.is_empty() || owner.contains('/') || name.contains('/') {
            return None;
        }
        Some(RepoId { owner, name })
    }
}

/// Visibility of a repository as observed at a single point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoVisibility {
    /// The repository is public now.
    Public,
    /// The repository is private now.
    Private,
    /// Could not determine visibility.
    Unknown,
}

/// A secret-scanning alert, with the raw `secret` value dropped during parsing.
///
/// A keyed fingerprint of the secret is retained only so the alert can be
/// correlated with a specific finding in memory. The fingerprint is not
/// serialized and is useless without the ephemeral key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretScanningAlert {
    /// Alert number.
    pub number: u64,
    /// Secret type slug reported by GitHub, e.g. `github_pat`.
    pub secret_type: String,
    /// Alert state as reported by GitHub.
    pub state: String,
    /// When GitHub created the alert.
    pub created_at: Option<DateTime<Utc>>,
    /// URL to the alert in the GitHub web UI.
    pub html_url: String,
    /// Resolution reason, if the alert is resolved.
    pub resolution: Option<String>,
    /// Transient keyed fingerprint of the secret value. Not serialized.
    #[serde(skip)]
    pub secret_fingerprint: Option<String>,
}

impl SecretScanningAlert {
    /// Check whether this alert correlates with a specific credential value.
    ///
    /// `key` is an ephemeral 32-byte correlation key supplied by the caller.
    /// The key and both values are used only inside this comparison and are not
    /// stored or transmitted.
    pub fn matches_value(&self, value: &str, key: &[u8; 32]) -> bool {
        let Some(alert_fp) = &self.secret_fingerprint else {
            return false;
        };
        let value_fp = transient_fingerprint(value, key);
        // Constant-time: this compares two secret-derived values, and a
        // variable-time compare leaks how many leading hex characters matched.
        // `ct_eq` only compares equal-length slices, so check the length first
        // and fail closed -- both are hex of a SHA-256, so a mismatch here is a
        // bug rather than an attack, but it must not fall through to a
        // short-circuiting compare.
        if alert_fp.len() != value_fp.len() {
            return false;
        }
        bool::from(alert_fp.as_bytes().ct_eq(value_fp.as_bytes()))
    }
}

/// Outcome of fetching secret-scanning alerts.
///
/// An empty `Known` vector is **not** a clean bill of health; it only means
/// the endpoint returned no alerts within the queried states. Failures are
/// represented as `Unknown`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScanningAlerts {
    /// Metadata extracted from successful responses.
    Known {
        /// Repository these alerts belong to.
        repo: RepoId,
        /// Alert states that were queried, e.g. `["open", "resolved"]`.
        states_queried: Vec<String>,
        /// Alerts returned by GitHub. May be empty.
        alerts: Vec<SecretScanningAlert>,
        /// When the last page finished.
        observed_at: DateTime<Utc>,
    },
    /// The integration could not determine GitHub's view. The reason is
    /// displayed; it must never be interpreted as "no alerts".
    Unknown {
        /// Repository the query was for.
        repo: RepoId,
        /// Alert states that were being queried.
        states_queried: Vec<String>,
        /// Human-readable reason the query failed.
        reason: String,
    },
}

/// Repository-level prevention posture. This is **not** a finding property.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositorySecurityPosture {
    /// Repository the posture describes.
    pub repo: RepoId,
    /// Whether secret scanning push protection is enabled.
    pub push_protection: PushProtectionStatus,
    /// When the posture was observed.
    pub observed_at: DateTime<Utc>,
    /// API endpoint or source that produced the observation.
    pub source: String,
}

/// Whether secret scanning push protection is enabled for a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushProtectionStatus {
    /// Enabled.
    Enabled,
    /// Disabled.
    Disabled,
    /// Unknown because the query failed or the response lacked the field.
    Unknown,
}

/// GitHub API client configuration.
#[derive(Debug, Clone)]
pub struct GitHubClient {
    token: String,
    base_url: String,
    client: reqwest::Client,
}

impl GitHubClient {
    /// Build a client using a token read from the environment or `gh` config.
    ///
    /// Reads `GITHUB_TOKEN` first, then tries `gh auth token`.
    pub fn from_env_or_gh() -> Result<Self, GitHubError> {
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            return Self::with_token(token);
        }
        let token = run_gh_auth_token().map_err(|_| GitHubError::MissingToken)?;
        Self::with_token(token)
    }

    /// Build a client with an explicit token.
    pub fn with_token(token: String) -> Result<Self, GitHubError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(GitHubClient {
            token,
            base_url: "https://api.github.com".into(),
            client,
        })
    }

    /// Fetch all secret-scanning alerts for a repository.
    ///
    /// Queries both `open` and `resolved` states and paginates completely. A
    /// non-2xx response on any page degrades the entire query to `Unknown`;
    /// it is **not** interpreted as "no alerts found".
    ///
    /// `correlation_key` is the ephemeral 32-byte key used to compute
    /// transient fingerprints of returned secrets so alerts can later be
    /// correlated with specific findings in memory.
    pub async fn secret_scanning_alerts(
        &self,
        repo: &RepoId,
        correlation_key: &[u8; 32],
    ) -> Result<SecretScanningAlerts, GitHubError> {
        let states = ["open", "resolved"];
        let mut all_alerts: Vec<SecretScanningAlert> = Vec::new();
        let mut states_queried: Vec<String> = Vec::new();

        for state in states {
            match self.fetch_alert_state(repo, state, correlation_key).await? {
                PageOutcome::Done(alerts) => {
                    states_queried.push(state.to_string());
                    all_alerts.extend(alerts);
                }
                PageOutcome::Failed { status } => {
                    return Ok(SecretScanningAlerts::Unknown {
                        repo: repo.clone(),
                        states_queried: states.iter().map(|s| s.to_string()).collect(),
                        reason: format!(
                            "GitHub returned {} while listing {} alerts",
                            status, state
                        ),
                    });
                }
            }
        }

        Ok(SecretScanningAlerts::Known {
            repo: repo.clone(),
            states_queried,
            alerts: all_alerts,
            observed_at: Utc::now(),
        })
    }

    /// Fetch the current visibility of a repository.
    ///
    /// A current visibility response cannot establish visibility history; the
    /// caller must store `RepoVisibility::observed_at` separately and report
    /// history as unknown.
    pub async fn current_visibility(&self, repo: &RepoId) -> Result<RepoVisibility, GitHubError> {
        let url = format!("{}/repos/{}/{}", self.base_url, repo.owner, repo.name);
        let response = self
            .client
            .get(&url)
            .headers(self.base_headers())
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(RepoVisibility::Unknown);
        }

        let bytes = response.bytes().await?;
        parse_visibility(&bytes).map_err(|_| GitHubError::ParseFailed)
    }

    /// Fetch the repository's security posture.
    ///
    /// Push protection is repository posture, not a finding property. It does
    /// not lower or raise the urgency of any existing finding.
    pub async fn repository_posture(
        &self,
        repo: &RepoId,
    ) -> Result<RepositorySecurityPosture, GitHubError> {
        let url = format!("{}/repos/{}/{}", self.base_url, repo.owner, repo.name);
        let response = self
            .client
            .get(&url)
            .headers(self.base_headers())
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            return Ok(RepositorySecurityPosture {
                repo: repo.clone(),
                push_protection: PushProtectionStatus::Unknown,
                observed_at: Utc::now(),
                source: url,
            });
        }

        let bytes = response.bytes().await?;
        let push_protection =
            parse_push_protection(&bytes).map_err(|_| GitHubError::ParseFailed)?;
        Ok(RepositorySecurityPosture {
            repo: repo.clone(),
            push_protection,
            observed_at: Utc::now(),
            source: url,
        })
    }

    async fn fetch_alert_state(
        &self,
        repo: &RepoId,
        state: &str,
        correlation_key: &[u8; 32],
    ) -> Result<PageOutcome, GitHubError> {
        let mut page = 1u32;
        let mut collected: Vec<SecretScanningAlert> = Vec::new();
        loop {
            let url = format!(
                "{}/repos/{}/{}/secret-scanning/alerts?state={}&per_page=100&page={}",
                self.base_url, repo.owner, repo.name, state, page
            );
            let response = self
                .client
                .get(&url)
                .headers(self.base_headers())
                .send()
                .await?;

            let status = response.status();
            if !status.is_success() {
                return Ok(PageOutcome::Failed { status });
            }

            let bytes = response.bytes().await?;
            let alerts =
                parse_alert_page(&bytes, correlation_key).map_err(|_| GitHubError::ParseFailed)?;
            let got = alerts.len();
            collected.extend(alerts);

            // GitHub's per-page limit is 100. If we got fewer, this is the last
            // page. Also stop if a page somehow returns zero results.
            if got < 100 {
                break;
            }
            page += 1;
        }
        Ok(PageOutcome::Done(collected))
    }

    fn base_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", self.token).parse().unwrap(),
        );
        headers.insert(ACCEPT, "application/vnd.github+json".parse().unwrap());
        headers.insert(USER_AGENT, "sovereign-vault-exposure".parse().unwrap());
        headers.insert("X-GitHub-Api-Version", "2022-11-28".parse().unwrap());
        headers
    }
}

enum PageOutcome {
    Done(Vec<SecretScanningAlert>),
    Failed { status: reqwest::StatusCode },
}

/// Run `gh auth token` to obtain a GitHub token.
fn run_gh_auth_token() -> Result<String, std::io::Error> {
    let output = std::process::Command::new("gh")
        .args(["auth", "token"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other("gh auth token failed"));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Compute a transient keyed fingerprint of a secret value.
///
/// The fingerprint is computed locally and never leaves the process. It is
/// useless without the key, which the caller must discard immediately after
/// correlation.
pub fn transient_fingerprint(value: &str, key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

/// Parse a page of secret-scanning alerts, dropping the raw `secret` value.
///
/// For each alert, the plaintext secret is read only to compute a keyed
/// fingerprint; the value itself is then discarded. The raw bytes are never
/// logged or stored. On parse failure we return an error without echoing the
/// body.
fn parse_alert_page(
    bytes: &[u8],
    correlation_key: &[u8; 32],
) -> Result<Vec<SecretScanningAlert>, GitHubError> {
    let raw: Vec<serde_json::Map<String, serde_json::Value>> =
        serde_json::from_slice(bytes).map_err(|_| GitHubError::ParseFailed)?;

    let mut alerts = Vec::with_capacity(raw.len());
    for mut entry in raw {
        // Read the secret value only to compute its keyed fingerprint, then
        // remove it from the entry so it cannot leak into later processing.
        let secret_fingerprint = entry
            .get("secret")
            .and_then(|v| v.as_str())
            .map(|secret| transient_fingerprint(secret, correlation_key));
        entry.remove("secret");

        let number = entry
            .get("number")
            .and_then(|v| v.as_u64())
            .ok_or(GitHubError::ParseFailed)?;
        let secret_type = entry
            .get("secret_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let state = entry
            .get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let created_at = entry
            .get("created_at")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        let html_url = entry
            .get("html_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let resolution = entry
            .get("resolution")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        alerts.push(SecretScanningAlert {
            number,
            secret_type,
            state,
            created_at,
            html_url,
            resolution,
            secret_fingerprint,
        });
    }

    Ok(alerts)
}

/// Parse repository visibility from a repository response.
fn parse_visibility(bytes: &[u8]) -> Result<RepoVisibility, GitHubError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| GitHubError::ParseFailed)?;
    match value.get("visibility").and_then(|v| v.as_str()) {
        Some("public") => Ok(RepoVisibility::Public),
        Some("private") => Ok(RepoVisibility::Private),
        _ => Ok(RepoVisibility::Unknown),
    }
}

/// Parse the push protection flag from a repository response.
fn parse_push_protection(bytes: &[u8]) -> Result<PushProtectionStatus, GitHubError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| GitHubError::ParseFailed)?;
    let enabled = value
        .get("security_and_analysis")
        .and_then(|sa| sa.get("secret_scanning_push_protection"))
        .and_then(|pp| pp.get("status"))
        .and_then(|s| s.as_str())
        .map(|s| s == "enabled");
    match enabled {
        Some(true) => Ok(PushProtectionStatus::Enabled),
        Some(false) => Ok(PushProtectionStatus::Disabled),
        None => Ok(PushProtectionStatus::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn repo_id_parses_owner_name() {
        let repo = RepoId::parse("pealmeida/sovereign-vault").unwrap();
        assert_eq!(repo.owner, "pealmeida");
        assert_eq!(repo.name, "sovereign-vault");
    }

    #[test]
    fn repo_id_rejects_missing_slash() {
        assert!(RepoId::parse("sovereign-vault").is_none());
    }

    #[test]
    fn parse_alert_page_drops_secret_value_but_keeps_keyed_fingerprint() {
        // Fixture contains an obviously fake secret value. The parser must
        // compute a keyed fingerprint and must not expose the raw secret.
        let json = br#"[
            {
                "number": 42,
                "secret_type": "github_pat",
                "secret": "ghp_this_is_a_fake_secret_for_testing_only_1234567890ab",
                "state": "open",
                "created_at": "2026-01-15T10:30:00Z",
                "html_url": "https://github.com/owner/repo/security/secret-scanning/42",
                "resolution": null
            }
        ]"#;
        let alerts = parse_alert_page(json, &KEY).unwrap();
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.number, 42);
        assert_eq!(alert.secret_type, "github_pat");
        assert_eq!(alert.state, "open");
        assert_eq!(
            alert.html_url,
            "https://github.com/owner/repo/security/secret-scanning/42"
        );
        assert_eq!(alert.resolution, None);
        assert!(alert.created_at.is_some());

        // The raw secret is gone from the struct.
        let serialized = serde_json::to_string(alert).unwrap();
        assert!(!serialized.contains("ghp_this_is_a_fake_secret"));

        // Correlation works with the same key and value, and fails with a
        // different value.
        let same_value = "ghp_this_is_a_fake_secret_for_testing_only_1234567890ab";
        let different_value = "ghp_completely_different_fake_secret_for_tests";
        assert!(alert.matches_value(same_value, &KEY));
        assert!(!alert.matches_value(different_value, &KEY));
    }

    #[test]
    fn parse_alert_page_empty_means_no_alerts_not_clean() {
        let json = br#"[]"#;
        let alerts = parse_alert_page(json, &KEY).unwrap();
        assert!(alerts.is_empty());
    }

    #[test]
    fn transient_fingerprint_changes_with_key() {
        let value = "ghp_fake_value_for_fingerprint_test";
        let fp_a = transient_fingerprint(value, &KEY);
        let fp_b = transient_fingerprint(value, &[9u8; 32]);
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn parse_visibility_public() {
        let json = br#"{ "visibility": "public", "name": "repo" }"#;
        assert_eq!(parse_visibility(json).unwrap(), RepoVisibility::Public);
    }

    #[test]
    fn parse_visibility_private() {
        let json = br#"{ "visibility": "private", "name": "repo" }"#;
        assert_eq!(parse_visibility(json).unwrap(), RepoVisibility::Private);
    }

    #[test]
    fn parse_visibility_missing_is_unknown() {
        let json = br#"{ "name": "repo" }"#;
        assert_eq!(parse_visibility(json).unwrap(), RepoVisibility::Unknown);
    }

    #[test]
    fn parse_push_protection_enabled() {
        let json = br#"{
            "security_and_analysis": {
                "secret_scanning_push_protection": { "status": "enabled" }
            }
        }"#;
        assert_eq!(
            parse_push_protection(json).unwrap(),
            PushProtectionStatus::Enabled
        );
    }

    #[test]
    fn parse_push_protection_disabled() {
        let json = br#"{
            "security_and_analysis": {
                "secret_scanning_push_protection": { "status": "disabled" }
            }
        }"#;
        assert_eq!(
            parse_push_protection(json).unwrap(),
            PushProtectionStatus::Disabled
        );
    }

    #[test]
    fn parse_push_protection_missing_field_is_unknown() {
        let json = br#"{ "name": "repo" }"#;
        assert_eq!(
            parse_push_protection(json).unwrap(),
            PushProtectionStatus::Unknown
        );
    }
}
