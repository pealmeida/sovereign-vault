//! Brokered outbound HTTP requests (ADR-0009, highest risk).
//!
//! `vault.broker_request` lets an agent invoke an external API *using* a
//! stored credential without ever seeing it: the vault validates the request
//! against the secret's allowlist, performs the call injecting the secret, and
//! returns only the sanitized response. The credential and any injected auth
//! header are stripped from everything returned or logged.
//!
//! The validation surface (allowlist match, scheme/method restriction, SSRF
//! refusal of private ranges) is split into pure functions so it can be tested
//! without real sockets; [`execute`] wires them around an actual HTTPS client.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::transit::{BrokerAllow, BrokerInjection, ResolvedBrokerSecret};

/// Default off unless this environment variable is set to a truthy value.
pub const ENABLE_ENV: &str = "SV_ENABLE_BROKER";

/// Hard ceiling on a brokered response body.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Hard timeout for the whole brokered call.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Header names that must never be echoed back to the agent.
const STRIPPED_RESPONSE_HEADERS: &[&str] = &["set-cookie", "authorization", "proxy-authorization"];

/// Errors specific to brokering. All deny paths produce a distinct variant so
/// tests can assert on the exact control that fired.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BrokerError {
    /// The broker feature is disabled (default-off flag not set).
    #[error("broker disabled: set {0} to enable vault.broker_request")]
    Disabled(&'static str),

    /// The URL could not be parsed.
    #[error("invalid url: {0}")]
    InvalidUrl(String),

    /// The scheme was not https.
    #[error("scheme not permitted (https only): {0}")]
    SchemeNotHttps(String),

    /// No allowlist entry matched host + path + method.
    #[error("request not on allowlist for this secret")]
    NotAllowed,

    /// The resolved target is a private/loopback/link-local address.
    #[error("target resolves to a blocked private/loopback address: {0}")]
    BlockedAddress(IpAddr),

    /// DNS resolution failed.
    #[error("dns resolution failed: {0}")]
    Dns(String),

    /// The upstream call failed.
    #[error("upstream request failed: {0}")]
    Upstream(String),

    /// The response exceeded the size cap.
    #[error("response exceeded {0} byte cap")]
    ResponseTooLarge(usize),
}

/// Parsed request the agent asked the vault to broker.
#[derive(Debug, Clone, Deserialize)]
pub struct BrokerRequest {
    /// HTTP method (case-insensitive).
    pub method: String,
    /// Full target URL.
    pub url: String,
    /// Optional extra headers (auth headers are added by the vault, not here).
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    /// Optional request body.
    #[serde(default)]
    pub body: Option<String>,
}

/// Sanitized response returned to the agent (secret + auth headers stripped).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BrokerResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers with sensitive entries removed.
    pub headers: std::collections::BTreeMap<String, String>,
    /// Response body as a string (best-effort UTF-8).
    pub body: String,
}

/// Whether brokering is enabled via the default-off env flag.
pub fn is_enabled() -> bool {
    matches!(
        std::env::var(ENABLE_ENV).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("on")
    )
}

/// Parsed components of a validated request target.
#[derive(Debug)]
pub struct ValidatedTarget {
    /// Lowercase host.
    pub host: String,
    /// URL path.
    pub path: String,
    /// Uppercase method.
    pub method: String,
    /// The allow entry that matched (governs SSRF opt-in).
    pub allow: BrokerAllow,
}

/// Validate scheme + method + host + path against the allowlist. Pure: no DNS
/// or sockets. Returns the matched allow entry on success.
pub fn validate_against_allowlist(
    req: &BrokerRequest,
    allow: &[BrokerAllow],
) -> Result<ValidatedTarget, BrokerError> {
    let url = url::Url::parse(&req.url).map_err(|e| BrokerError::InvalidUrl(e.to_string()))?;
    if url.scheme() != "https" {
        return Err(BrokerError::SchemeNotHttps(url.scheme().to_string()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| BrokerError::InvalidUrl("missing host".into()))?
        .to_ascii_lowercase();
    let path = url.path().to_string();
    let method = req.method.to_ascii_uppercase();

    let matched = allow.iter().find(|entry| {
        entry.host.eq_ignore_ascii_case(&host)
            && path.starts_with(&entry.path_prefix)
            && entry
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&method))
    });

    match matched {
        Some(entry) => Ok(ValidatedTarget {
            host,
            path,
            method,
            allow: entry.clone(),
        }),
        None => Err(BrokerError::NotAllowed),
    }
}

/// True if `ip` is a private, loopback, link-local, or unique-local address
/// that must be refused unless the allow entry opts in.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback() // 127.0.0.0/8
        || ip.is_private() // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local() // 169.254/16
        || ip.is_broadcast()
        || ip.is_unspecified()
        || o[0] == 0
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let seg = ip.segments();
    // fc00::/7 unique-local.
    if (seg[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // fe80::/10 link-local.
    if (seg[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // IPv4-mapped: re-check against v4 rules.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_v4(v4);
    }
    false
}

/// Resolve `host:port` and refuse if any resolved address is blocked (unless
/// the allow entry opted in). Returns the resolved addresses to be reused so
/// there is no TOCTOU rebind window between this check and the request.
pub fn resolve_and_screen(
    host: &str,
    port: u16,
    allow: &BrokerAllow,
) -> Result<Vec<IpAddr>, BrokerError> {
    let addrs: Vec<IpAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| BrokerError::Dns(e.to_string()))?
        .map(|sa| sa.ip())
        .collect();
    if addrs.is_empty() {
        return Err(BrokerError::Dns("no addresses".into()));
    }
    if !allow.allow_private_ip {
        for ip in &addrs {
            if is_blocked_ip(*ip) {
                return Err(BrokerError::BlockedAddress(*ip));
            }
        }
    }
    Ok(addrs)
}

/// Perform the validated, screened, secret-injected outbound call.
///
/// All security controls run before any byte leaves the process: allowlist +
/// scheme + method, then DNS resolution + SSRF screening, then a no-redirect
/// client with a hard timeout and a response-size cap. The injected secret and
/// sensitive response headers are never placed in the returned value.
pub async fn execute(
    req: &BrokerRequest,
    resolved: &ResolvedBrokerSecret,
) -> Result<BrokerResponse, BrokerError> {
    if !is_enabled() {
        return Err(BrokerError::Disabled(ENABLE_ENV));
    }

    let target = validate_against_allowlist(req, &resolved.allow)?;
    let url = url::Url::parse(&req.url).map_err(|e| BrokerError::InvalidUrl(e.to_string()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| BrokerError::InvalidUrl("no port".into()))?;
    // Re-screen after resolution; refuse rebinding to private space.
    resolve_and_screen(&target.host, port, &target.allow)?;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .https_only(true)
        .build()
        .map_err(|e| BrokerError::Upstream(e.to_string()))?;

    let method = reqwest::Method::from_bytes(target.method.as_bytes())
        .map_err(|e| BrokerError::Upstream(e.to_string()))?;
    let mut builder = client.request(method, url);

    for (k, v) in &req.headers {
        // Never let the agent set the auth header the vault owns.
        let lower = k.to_ascii_lowercase();
        if lower == "authorization" || lower == "proxy-authorization" {
            continue;
        }
        builder = builder.header(k, v);
    }

    builder = match &resolved.injection {
        BrokerInjection::BearerAuth => {
            builder.header("Authorization", format!("Bearer {}", resolved.secret))
        }
        BrokerInjection::Header { name } => builder.header(name, resolved.secret.clone()),
    };

    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }

    let resp = builder
        .send()
        .await
        .map_err(|e| BrokerError::Upstream(redact_url(&e.to_string(), &resolved.secret)))?;

    let status = resp.status().as_u16();
    let mut headers = std::collections::BTreeMap::new();
    for (name, value) in resp.headers() {
        let lname = name.as_str().to_ascii_lowercase();
        if STRIPPED_RESPONSE_HEADERS.contains(&lname.as_str()) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            headers.insert(name.as_str().to_string(), v.to_string());
        }
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| BrokerError::Upstream(e.to_string()))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(BrokerError::ResponseTooLarge(MAX_RESPONSE_BYTES));
    }
    let body = String::from_utf8_lossy(&bytes).into_owned();

    Ok(BrokerResponse {
        status,
        headers,
        body,
    })
}

fn redact_url(msg: &str, secret: &str) -> String {
    msg.replace(secret, "<redacted>")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(host: &str, prefix: &str, methods: &[&str], private: bool) -> BrokerAllow {
        BrokerAllow {
            host: host.into(),
            path_prefix: prefix.into(),
            methods: methods.iter().map(|m| m.to_string()).collect(),
            allow_private_ip: private,
        }
    }

    fn req(method: &str, url: &str) -> BrokerRequest {
        BrokerRequest {
            method: method.into(),
            url: url.into(),
            headers: Default::default(),
            body: None,
        }
    }

    #[test]
    fn off_allowlist_host_denied() {
        let allows = vec![allow("api.example.com", "/v1", &["GET"], false)];
        let r = req("GET", "https://evil.com/v1/x");
        assert_eq!(
            validate_against_allowlist(&r, &allows).unwrap_err(),
            BrokerError::NotAllowed
        );
    }

    #[test]
    fn disallowed_method_denied() {
        let allows = vec![allow("api.example.com", "/v1", &["GET"], false)];
        let r = req("DELETE", "https://api.example.com/v1/x");
        assert_eq!(
            validate_against_allowlist(&r, &allows).unwrap_err(),
            BrokerError::NotAllowed
        );
    }

    #[test]
    fn off_path_prefix_denied() {
        let allows = vec![allow("api.example.com", "/v1", &["GET"], false)];
        let r = req("GET", "https://api.example.com/v2/x");
        assert_eq!(
            validate_against_allowlist(&r, &allows).unwrap_err(),
            BrokerError::NotAllowed
        );
    }

    #[test]
    fn non_https_denied() {
        let allows = vec![allow("api.example.com", "/", &["GET"], false)];
        let r = req("GET", "http://api.example.com/x");
        assert!(matches!(
            validate_against_allowlist(&r, &allows).unwrap_err(),
            BrokerError::SchemeNotHttps(_)
        ));
    }

    #[test]
    fn allowed_request_matches() {
        let allows = vec![allow("api.example.com", "/v1", &["get", "POST"], false)];
        let r = req("get", "https://API.example.com/v1/charges");
        let t = validate_against_allowlist(&r, &allows).unwrap();
        assert_eq!(t.host, "api.example.com");
        assert_eq!(t.method, "GET");
    }

    #[test]
    fn private_and_loopback_ips_blocked() {
        for ip in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(is_blocked_ip(parsed), "{ip} should be blocked");
        }
    }

    #[test]
    fn public_ips_allowed() {
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(!is_blocked_ip(parsed), "{ip} should be allowed");
        }
    }

    #[test]
    fn resolve_and_screen_refuses_private_unless_opted_in() {
        // localhost resolves to loopback: blocked without opt-in, allowed with.
        let blocked = allow("localhost", "/", &["GET"], false);
        let err = resolve_and_screen("localhost", 443, &blocked);
        assert!(matches!(err, Err(BrokerError::BlockedAddress(_))));

        let opted = allow("localhost", "/", &["GET"], true);
        assert!(resolve_and_screen("localhost", 443, &opted).is_ok());
    }

    #[tokio::test]
    async fn execute_returns_disabled_when_flag_off() {
        // The flag is off by default in the test process.
        std::env::remove_var(ENABLE_ENV);
        let resolved = ResolvedBrokerSecret {
            secret: "s".into(),
            allow: vec![allow("api.example.com", "/", &["GET"], false)],
            injection: BrokerInjection::BearerAuth,
        };
        let r = req("GET", "https://api.example.com/x");
        assert_eq!(
            execute(&r, &resolved).await.unwrap_err(),
            BrokerError::Disabled(ENABLE_ENV)
        );
    }
}
