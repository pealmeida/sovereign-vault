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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::transit::{BrokerAllow, BrokerInjection, ResolvedBrokerSecret};

/// Default off unless this environment variable is set to a truthy value.
pub const ENABLE_ENV: &str = "SV_ENABLE_BROKER";

/// Hard ceiling on a brokered response body.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Hard ceiling on a brokered request body.
pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// Maximum number of agent-supplied request headers.
pub const MAX_REQUEST_HEADERS: usize = 32;

/// Maximum aggregate bytes across agent-supplied header names and values.
pub const MAX_REQUEST_HEADER_BYTES: usize = 32 * 1024;

const MAX_REQUEST_HEADER_NAME_BYTES: usize = 128;
const MAX_REQUEST_HEADER_VALUE_BYTES: usize = 8 * 1024;
const MAX_REQUEST_URL_BYTES: usize = 8 * 1024;
const MAX_REQUEST_METHOD_BYTES: usize = 32;

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

    /// The request exceeded a broker resource ceiling.
    #[error("request {0} exceeded {1} byte/item cap")]
    RequestTooLarge(&'static str, usize),

    /// The request included an invalid or broker-controlled header.
    #[error("request header not permitted: {0}")]
    HeaderNotPermitted(String),

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
    validate_request_shape(req)?;
    let url = url::Url::parse(&req.url).map_err(|e| BrokerError::InvalidUrl(e.to_string()))?;
    if url.scheme() != "https" {
        return Err(BrokerError::SchemeNotHttps(url.scheme().to_string()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(BrokerError::InvalidUrl(
            "embedded URL credentials are not permitted".into(),
        ));
    }
    if url.fragment().is_some() {
        return Err(BrokerError::InvalidUrl(
            "URL fragments are not permitted".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| BrokerError::InvalidUrl("missing host".into()))?
        .to_ascii_lowercase();
    let path = url.path().to_string();
    let encoded_path = path.to_ascii_lowercase();
    if ["%2e", "%2f", "%5c"]
        .iter()
        .any(|encoded| encoded_path.contains(encoded))
    {
        return Err(BrokerError::InvalidUrl(
            "encoded path traversal or separators are not permitted".into(),
        ));
    }
    let method = req.method.to_ascii_uppercase();

    let matched = allow.iter().find(|entry| {
        entry.host.eq_ignore_ascii_case(&host)
            && path_prefix_matches(&entry.path_prefix, &path)
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

fn validate_request_shape(req: &BrokerRequest) -> Result<(), BrokerError> {
    if req.url.len() > MAX_REQUEST_URL_BYTES {
        return Err(BrokerError::RequestTooLarge("URL", MAX_REQUEST_URL_BYTES));
    }
    if req.method.is_empty() || req.method.len() > MAX_REQUEST_METHOD_BYTES {
        return Err(BrokerError::RequestTooLarge(
            "method",
            MAX_REQUEST_METHOD_BYTES,
        ));
    }
    reqwest::Method::from_bytes(req.method.as_bytes())
        .map_err(|_| BrokerError::InvalidUrl("invalid HTTP method".into()))?;
    if req.headers.len() > MAX_REQUEST_HEADERS {
        return Err(BrokerError::RequestTooLarge(
            "header count",
            MAX_REQUEST_HEADERS,
        ));
    }

    let mut header_bytes = 0usize;
    for (name, value) in &req.headers {
        if name.len() > MAX_REQUEST_HEADER_NAME_BYTES {
            return Err(BrokerError::RequestTooLarge(
                "header name",
                MAX_REQUEST_HEADER_NAME_BYTES,
            ));
        }
        if value.len() > MAX_REQUEST_HEADER_VALUE_BYTES {
            return Err(BrokerError::RequestTooLarge(
                "header value",
                MAX_REQUEST_HEADER_VALUE_BYTES,
            ));
        }
        header_bytes = header_bytes.checked_add(name.len() + value.len()).ok_or(
            BrokerError::RequestTooLarge("headers", MAX_REQUEST_HEADER_BYTES),
        )?;
        if header_bytes > MAX_REQUEST_HEADER_BYTES {
            return Err(BrokerError::RequestTooLarge(
                "headers",
                MAX_REQUEST_HEADER_BYTES,
            ));
        }

        let parsed = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| BrokerError::HeaderNotPermitted(name.clone()))?;
        reqwest::header::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|_| BrokerError::HeaderNotPermitted(name.clone()))?;
        if is_broker_controlled_header(parsed.as_str()) {
            return Err(BrokerError::HeaderNotPermitted(name.clone()));
        }
    }

    if req
        .body
        .as_ref()
        .is_some_and(|body| body.len() > MAX_REQUEST_BODY_BYTES)
    {
        return Err(BrokerError::RequestTooLarge("body", MAX_REQUEST_BODY_BYTES));
    }
    Ok(())
}

fn is_broker_controlled_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "proxy-connection"
            | "upgrade"
            | "te"
            | "trailer"
    )
}

fn is_transport_controlled_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "proxy-authorization"
            | "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "proxy-connection"
            | "upgrade"
            | "te"
            | "trailer"
    )
}

fn path_prefix_matches(prefix: &str, path: &str) -> bool {
    if !prefix.starts_with('/') {
        return false;
    }
    if prefix == "/" || prefix.ends_with('/') {
        return path.starts_with(prefix);
    }
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
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
        || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64.0.0/10 shared
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // documentation
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // deprecated 6to4 relay
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // benchmarking
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // documentation
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // documentation
        || o[0] >= 224 // multicast and reserved
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
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
    // fec0::/10 deprecated site-local and 2001:db8::/32 documentation.
    if (seg[0] & 0xffc0) == 0xfec0 || (seg[0] == 0x2001 && seg[1] == 0x0db8) {
        return true;
    }
    // IPv4-mapped: re-check against v4 rules.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_v4(v4);
    }
    // DNS64 well-known prefix 64:ff9b::/96 can route an embedded private IPv4.
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        return is_blocked_v4(Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            seg[6] as u8,
            (seg[7] >> 8) as u8,
            seg[7] as u8,
        ));
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
    // Pin the HTTP client to the exact addresses that passed screening. Letting
    // reqwest resolve the hostname again would re-open a DNS-rebinding window.
    let screened: Vec<SocketAddr> = resolve_and_screen(&target.host, port, &target.allow)?
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .https_only(true)
        .resolve_to_addrs(&target.host, &screened)
        .build()
        .map_err(|error| upstream_error(error, &resolved.secret))?;

    let method = reqwest::Method::from_bytes(target.method.as_bytes())
        .map_err(|error| upstream_error(error, &resolved.secret))?;
    let mut builder = client.request(method, url);

    let (owned_header_name, mut owned_header_value) = match &resolved.injection {
        BrokerInjection::BearerAuth => (
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_bytes(
                format!("Bearer {}", resolved.secret).as_bytes(),
            )
            .map_err(|error| upstream_error(error, &resolved.secret))?,
        ),
        BrokerInjection::Header { name } => (
            {
                let parsed = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|error| upstream_error(error, &resolved.secret))?;
                if is_transport_controlled_header(parsed.as_str()) {
                    return Err(BrokerError::HeaderNotPermitted(name.clone()));
                }
                parsed
            },
            reqwest::header::HeaderValue::from_bytes(resolved.secret.as_bytes())
                .map_err(|error| upstream_error(error, &resolved.secret))?,
        ),
    };
    owned_header_value.set_sensitive(true);

    for (k, v) in &req.headers {
        let name = reqwest::header::HeaderName::from_bytes(k.as_bytes())
            .map_err(|_| BrokerError::HeaderNotPermitted(k.clone()))?;
        if name == owned_header_name {
            continue;
        }
        let value = reqwest::header::HeaderValue::from_bytes(v.as_bytes())
            .map_err(|_| BrokerError::HeaderNotPermitted(k.clone()))?;
        builder = builder.header(name, value);
    }

    builder = builder.header(owned_header_name, owned_header_value);

    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }

    let mut resp = builder
        .send()
        .await
        .map_err(|error| upstream_error(error, &resolved.secret))?;

    let status = resp.status().as_u16();
    let mut headers = std::collections::BTreeMap::new();
    for (name, value) in resp.headers() {
        let lname = name.as_str().to_ascii_lowercase();
        if STRIPPED_RESPONSE_HEADERS.contains(&lname.as_str()) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            headers.insert(
                name.as_str().to_string(),
                redact_secret(v, &resolved.secret),
            );
        }
    }

    // Reject early if the server advertises an oversized body...
    if let Some(len) = resp.content_length() {
        if len > MAX_RESPONSE_BYTES as u64 {
            return Err(BrokerError::ResponseTooLarge(MAX_RESPONSE_BYTES));
        }
    }
    // ...and enforce the cap while streaming so a lying or chunked server
    // cannot make us buffer unbounded memory.
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|error| upstream_error(error, &resolved.secret))?
    {
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(BrokerError::ResponseTooLarge(MAX_RESPONSE_BYTES));
        }
        buf.extend_from_slice(&chunk);
    }
    let body = redact_secret(&String::from_utf8_lossy(&buf), &resolved.secret);

    Ok(BrokerResponse {
        status,
        headers,
        body,
    })
}

fn upstream_error(error: impl std::fmt::Display, secret: &str) -> BrokerError {
    BrokerError::Upstream(redact_secret(&error.to_string(), secret))
}

fn redact_secret(value: &str, secret: &str) -> String {
    if secret.is_empty() {
        value.to_string()
    } else {
        value.replace(secret, "<redacted>")
    }
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
    fn path_prefix_matches_a_segment_boundary() {
        let allows = vec![allow("api.example.com", "/v1", &["GET"], false)];
        assert!(validate_against_allowlist(
            &req("GET", "https://api.example.com/v1/items"),
            &allows
        )
        .is_ok());
        assert_eq!(
            validate_against_allowlist(&req("GET", "https://api.example.com/v10/items"), &allows)
                .unwrap_err(),
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
    fn url_credentials_fragments_and_encoded_traversal_are_denied() {
        let allows = vec![allow("api.example.com", "/v1", &["GET"], false)];
        for url in [
            "https://user:pass@api.example.com/v1/items",
            "https://api.example.com/v1/items#secret",
            "https://api.example.com/v1/%2e%2e/admin",
            "https://api.example.com/v1%2fadmin",
        ] {
            assert!(
                validate_against_allowlist(&req("GET", url), &allows).is_err(),
                "{url} must be denied"
            );
        }
    }

    #[test]
    fn request_shape_limits_and_controlled_headers_are_enforced() {
        let mut oversized_body = req("POST", "https://api.example.com/v1");
        oversized_body.body = Some("x".repeat(MAX_REQUEST_BODY_BYTES + 1));
        assert_eq!(
            validate_request_shape(&oversized_body).unwrap_err(),
            BrokerError::RequestTooLarge("body", MAX_REQUEST_BODY_BYTES)
        );

        let mut too_many_headers = req("GET", "https://api.example.com/v1");
        for index in 0..=MAX_REQUEST_HEADERS {
            too_many_headers
                .headers
                .insert(format!("x-header-{index}"), "x".into());
        }
        assert_eq!(
            validate_request_shape(&too_many_headers).unwrap_err(),
            BrokerError::RequestTooLarge("header count", MAX_REQUEST_HEADERS)
        );

        for header in [
            "Authorization",
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
        ] {
            let mut controlled = req("GET", "https://api.example.com/v1");
            controlled.headers.insert(header.into(), "value".into());
            assert_eq!(
                validate_request_shape(&controlled).unwrap_err(),
                BrokerError::HeaderNotPermitted(header.into())
            );
        }

        let mut invalid_value = req("GET", "https://api.example.com/v1");
        invalid_value
            .headers
            .insert("x-value".into(), "line\r\nbreak".into());
        assert!(matches!(
            validate_request_shape(&invalid_value),
            Err(BrokerError::HeaderNotPermitted(_))
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
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "ff02::1",
            "64:ff9b::7f00:1",
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
    fn secret_redaction_covers_errors_headers_and_bodies() {
        let secret = "stored-credential";
        assert_eq!(
            redact_secret(
                "upstream echoed stored-credential twice stored-credential",
                secret
            ),
            "upstream echoed <redacted> twice <redacted>"
        );
        assert_eq!(redact_secret("ordinary", ""), "ordinary");
        assert_eq!(
            upstream_error("failure for stored-credential", secret),
            BrokerError::Upstream("failure for <redacted>".into())
        );
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
