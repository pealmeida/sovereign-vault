//! Validation rules applied to a parsed policy document.

use std::collections::BTreeSet;

use crate::error::{Result, RuntimeError};
use crate::policy::document::{AccessEffect, LimitsDocument, PolicyDocument};
use crate::types::RuleExposure;

/// A non-fatal finding recorded on a validated policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationWarning {
    /// An allow rule that an earlier deny fully shadows.
    UnreachableAllow {
        /// Identifier of the shadowed rule.
        rule_id: String,
    },
    /// Two rules select different routes for an otherwise identical match.
    AmbiguousRoute {
        /// Identifier of the ambiguous rule.
        rule_id: String,
    },
}

/// Checks every hard validation rule, returning collected warnings on success.
pub fn check(doc: &PolicyDocument) -> Result<Vec<ValidationWarning>> {
    check_unique_ids(doc)?;
    check_routes(doc)?;
    check_references(doc)?;
    check_urls(doc)?;
    check_exposure(doc)?;
    check_limits(&doc.limits)?;
    check_executables(doc)?;
    Ok(check_warnings(doc))
}

fn check_unique_ids(doc: &PolicyDocument) -> Result<()> {
    ensure_unique(doc.rule.iter().map(|r| &r.id))?;
    ensure_unique(doc.reference_class.iter().map(|r| &r.id))?;
    ensure_unique(doc.provider_route.iter().map(|r| &r.id))?;
    ensure_unique(doc.mcp_server.iter().map(|r| &r.id))?;
    ensure_unique(doc.process_profile.iter().map(|r| &r.id))?;
    Ok(())
}

fn ensure_unique<'a>(items: impl Iterator<Item = &'a String>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for id in items {
        if !seen.insert(id.clone()) {
            return Err(RuntimeError::InvalidStructure);
        }
    }
    Ok(())
}

fn check_routes(doc: &PolicyDocument) -> Result<()> {
    let routes: BTreeSet<&str> = doc.provider_route.iter().map(|r| r.id.as_str()).collect();
    for rule in &doc.rule {
        if let Some(route_id) = &rule.effect.route {
            if !routes.contains(route_id.as_str()) {
                return Err(RuntimeError::RouteDenied);
            }
        }
    }
    Ok(())
}

fn check_references(doc: &PolicyDocument) -> Result<()> {
    let mcps: BTreeSet<&str> = doc.mcp_server.iter().map(|m| m.id.as_str()).collect();
    let profiles: BTreeSet<&str> = doc.process_profile.iter().map(|p| p.id.as_str()).collect();
    for rule in &doc.rule {
        if let Some(ids) = &rule.match_.mcp_server_ids {
            for id in ids {
                if !mcps.contains(id.as_str()) {
                    return Err(RuntimeError::InvalidStructure);
                }
            }
        }
        if let Some(ids) = &rule.match_.process_profile_ids {
            for id in ids {
                if !profiles.contains(id.as_str()) {
                    return Err(RuntimeError::InvalidStructure);
                }
            }
        }
    }
    Ok(())
}

fn check_urls(doc: &PolicyDocument) -> Result<()> {
    for route in &doc.provider_route {
        let host = host_of(&route.base_url)?;
        if !route.base_url.starts_with("https://") || host.is_empty() || host.contains('*') {
            return Err(RuntimeError::InvalidStructure);
        }
    }
    Ok(())
}

fn host_of(url: &str) -> Result<&str> {
    let rest = url
        .strip_prefix("https://")
        .ok_or(RuntimeError::InvalidStructure)?;
    let authority = rest.split('/').next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or("");
    Ok(host_port.rsplit(':').next().unwrap_or(""))
}

fn check_exposure(doc: &PolicyDocument) -> Result<()> {
    const FORBIDDEN: &[&str] = &["transit_key", "signing_key", "provider_credential"];
    for rule in &doc.rule {
        // Only `raw` releases plaintext. The transforming variants
        // (`redact`, `pseudonymize`, `omit`) are permitted against restricted
        // kinds because they do not hand over the underlying material.
        if rule.effect.exposure == Some(RuleExposure::Raw) {
            if let Some(kinds) = &rule.match_.resource_kinds {
                if kinds.iter().any(|k| FORBIDDEN.contains(&k.as_str())) {
                    return Err(RuntimeError::InvalidStructure);
                }
            }
        }
    }
    Ok(())
}

fn check_limits(limits: &LimitsDocument) -> Result<()> {
    if limits.request_bytes == 0
        || limits.fragment_bytes == 0
        || limits.response_bytes == 0
        || limits.concurrent_requests_per_principal == 0
        || limits.request_timeout_ms == 0
        || limits.consent_timeout_ms == 0
        || limits.stream_boundary_bytes == 0
    {
        return Err(RuntimeError::InvalidStructure);
    }
    Ok(())
}

fn check_executables(doc: &PolicyDocument) -> Result<()> {
    for profile in &doc.process_profile {
        let exe = &profile.executable;
        // A space is NOT shell indirection here: the executable is spawned
        // directly, never through a shell, and legitimate Windows paths such as
        // `C:/Program Files/Acme/deploy.exe` contain spaces.
        let absolute = exe.starts_with('/') || is_drive_absolute(exe);
        if !absolute || exe.chars().any(|c| "&|;`$><\n\r".contains(c)) {
            return Err(RuntimeError::InvalidStructure);
        }
    }
    Ok(())
}

fn is_drive_absolute(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(
        (chars.next(), chars.next(), chars.next()),
        (Some(c), Some(':'), Some('/' | '\\')) if c.is_ascii_alphabetic()
    )
}

fn check_warnings(doc: &PolicyDocument) -> Vec<ValidationWarning> {
    let mut warnings = Vec::new();
    for (i, rule) in doc.rule.iter().enumerate() {
        if rule.effect.access == AccessEffect::Allow {
            for earlier in doc.rule.iter().take(i) {
                if earlier.effect.access == AccessEffect::Deny && earlier.match_ == rule.match_ {
                    warnings.push(ValidationWarning::UnreachableAllow {
                        rule_id: rule.id.clone(),
                    });
                    break;
                }
            }
        }
    }
    for (i, rule) in doc.rule.iter().enumerate() {
        let route = rule.effect.route.as_ref();
        for earlier in doc.rule.iter().take(i) {
            if rule.match_ == earlier.match_ && route != earlier.effect.route.as_ref() {
                warnings.push(ValidationWarning::AmbiguousRoute {
                    rule_id: rule.id.clone(),
                });
                break;
            }
        }
    }
    warnings
}
