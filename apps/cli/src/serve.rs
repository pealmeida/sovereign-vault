//! Headless `sovereign-vault serve` gateway.
//!
//! Boots the same WebSocket MCP + read-only HTTP surface as the desktop app,
//! but with a fail-closed access policy: requests targeting APPROVAL / OTP /
//! ZKP / ANONYMIZED containers are rejected, since no UI exists for human
//! approval. Intended for unattended Linux servers, container hosts, and CI
//! runners that need read-only access to vault contents.
//!
//! The pairing secret is printed once to stderr at startup. Capture and
//! supply it to local MCP clients; never persist it on disk.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sv_audit::{AuditDecision, AuditEvent, AuditLog};
use sv_core::agents::{ensure_default_agent, list_agents, DEFAULT_AGENT_NAME};
use sv_core::sv_storage::SecurityMode;
use sv_core::{fresh_pairing_secret, BootstrapResult, CustodyMode, VaultHandle};
use sv_mcp::{
    AccessAction, AccessController, AccessRequest, AgentAuthenticator, AuditSink, RateLimiter,
    ResolvedAgent, ResolvedScope,
};
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{oneshot, Mutex};

#[derive(Debug, Clone)]
pub struct ServeArgs {
    pub root: PathBuf,
    pub passphrase: Option<String>,
    pub recovery: Option<Vec<String>>,
    pub ws_bind: SocketAddr,
    pub http_bind: SocketAddr,
    pub rate_limit: Option<(usize, std::time::Duration)>,
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

pub async fn run(args: ServeArgs) -> Result<(), ServeError> {
    let tracing_sub = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .finish();
    let _ = tracing::subscriber::set_global_default(tracing_sub);

    let (handle, audit_hmac, agent_hmac) = open_or_bootstrap(&args).await?;

    let secret = fresh_pairing_secret().map_err(|e| ServeError::Other(e.to_string()))?;
    ensure_default_agent(&args.root, &agent_hmac, &secret)
        .map_err(|e| ServeError::Other(e.to_string()))?;

    let ws_listener = TcpListener::bind(args.ws_bind).await?;
    let http_listener = TcpListener::bind(args.http_bind).await?;

    let sink = Arc::new(HeadlessAuditSink::new(args.root.clone(), audit_hmac));
    let authenticator = Arc::new(HeadlessAuthenticator::new(
        args.root.clone(),
        agent_hmac,
        secret.clone(),
    ));
    let controller = Arc::new(HeadlessAccessController);

    let mut server = sv_mcp::McpServer::new(
        Arc::new(Mutex::new(Some(handle))) as sv_mcp::SharedVault<VaultHandle>,
        secret.clone(),
    )
    .with_audit_sink(sink.clone())
    .with_agent_authenticator(authenticator);
    server = server.with_access_controller(controller);
    if let Some((max, window)) = args.rate_limit {
        server = server.with_rate_limiter(Arc::new(RateLimiter::new(max, window)));
    }
    let server = Arc::new(server);

    let http_secret = secret.clone();
    let http_server = sv_http::HttpServer::new(http_secret);

    let (ws_tx, ws_rx) = oneshot::channel::<()>();
    let (http_tx, http_rx) = oneshot::channel::<()>();

    let ws_task = tokio::spawn({
        let server = server.clone();
        async move {
            if let Err(error) = server.serve_ws_listener(ws_listener, ws_rx).await {
                tracing::error!(?error, "ws server stopped");
            }
        }
    });
    let http_task = tokio::spawn(async move {
        if let Err(error) = http_server.serve_listener(http_listener, http_rx).await {
            tracing::error!(?error, "http server stopped");
        }
    });

    tracing::info!(ws = %args.ws_bind, http = %args.http_bind, "sovereign-vault headless gateway is up");
    eprintln!("[serve] pairing secret (one-time display, capture immediately):");
    eprintln!("[serve] {secret}");
    if let Ok(agents) = list_agents(&args.root, &agent_hmac) {
        for a in agents
            .into_iter()
            .filter(|a| !a.revoked && a.name != DEFAULT_AGENT_NAME)
        {
            eprintln!("[serve]   - {} ({})", a.name, a.agent_id);
        }
    }

    let mut term = signal(SignalKind::terminate())?;
    let mut intr = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = term.recv() => tracing::info!("received SIGTERM"),
        _ = intr.recv() => tracing::info!("received SIGINT"),
    }

    let lock_event = AuditEvent::new(
        sv_audit::AuditAction::VaultLock,
        AuditDecision::Allowed,
        "headless-gateway",
    );
    let _ = sink.record(lock_event);

    let _ = ws_tx.send(());
    let _ = http_tx.send(());
    let _ = ws_task.await;
    let _ = http_task.await;

    tracing::info!("shutdown complete");
    Ok(())
}

async fn open_or_bootstrap(
    args: &ServeArgs,
) -> Result<(VaultHandle, [u8; 32], [u8; 32]), ServeError> {
    let root = &args.root;

    // A vault is "fresh" when its master.salt (or keychain wrapper) is missing.
    // The directory may exist with a stale .vault.lock from a previous failed
    // bootstrap; that's expected and not a barrier to re-bootstrapping.
    let salt_path = root.join("master.salt");
    let fresh = !salt_path.exists();

    if fresh {
        std::fs::create_dir_all(root)?;
        let pp = args.passphrase.as_ref().ok_or_else(|| {
            ServeError::Other("vault root missing; supply --passphrase to bootstrap".into())
        })?;
        let BootstrapResult {
            handle,
            recovery_phrase: _,
        } = VaultHandle::bootstrap(root, CustodyMode::Passphrase, Some(pp))
            .map_err(|e| ServeError::Other(e.to_string()))?;
        tracing::info!(root = %root.display(), "bootstrapped new vault");
        let audit = handle.audit_hmac_key();
        let agent = handle.agent_token_key();
        return Ok((handle, audit, agent));
    }

    // Vault exists: unlock with passphrase or recovery words.
    if let Some(ref words) = args.recovery {
        let phrase = words.join(" ");
        let handle = VaultHandle::unlock_with_recovery(root, &phrase)
            .map_err(|e| ServeError::Other(e.to_string()))?;
        let audit = handle.audit_hmac_key();
        let agent = handle.agent_token_key();
        return Ok((handle, audit, agent));
    }

    let pp = args.passphrase.as_deref();
    let handle = VaultHandle::unlock(root, CustodyMode::Passphrase, pp)
        .map_err(|e| ServeError::Other(e.to_string()))?;
    let audit = handle.audit_hmac_key();
    let agent = handle.agent_token_key();
    Ok((handle, audit, agent))
}

/// Fail-closed access controller: DIRECT container requests pass through, but
/// container modes requiring human mediation and modeless secret-bearing
/// crypto/broker requests are rejected because no UI is available.
struct HeadlessAccessController;

#[async_trait::async_trait]
impl AccessController for HeadlessAccessController {
    async fn authorize(&self, request: AccessRequest) -> Result<(), String> {
        if is_headless_secret_bearing_action(request.action) {
            return Err(
                "headless mode cannot mediate crypto/broker operations; use the desktop app".into(),
            );
        }
        match request.mode {
            Some(mode) if mode_needs_ui(mode) => {
                Err("headless mode cannot mediate this access; use the desktop app".into())
            }
            _ => Ok(()),
        }
    }
}

fn is_headless_secret_bearing_action(action: AccessAction) -> bool {
    matches!(
        action,
        AccessAction::Encrypt
            | AccessAction::Decrypt
            | AccessAction::Sign
            | AccessAction::CreateBrokerSecret
            | AccessAction::ListBrokerSecrets
            | AccessAction::Broker
    )
}

fn mode_needs_ui(mode: SecurityMode) -> bool {
    matches!(
        mode,
        SecurityMode::Approval | SecurityMode::Otp | SecurityMode::Zkp | SecurityMode::Anonymized
    )
}

struct HeadlessAuthenticator {
    root: PathBuf,
    token_key: [u8; 32],
    shared_secret: String,
}

impl HeadlessAuthenticator {
    fn new(root: PathBuf, token_key: [u8; 32], shared_secret: String) -> Self {
        Self {
            root,
            token_key,
            shared_secret,
        }
    }
}

fn parse_access_action(action: &str) -> Option<AccessAction> {
    Some(match action {
        "list" | "list_containers" => AccessAction::ListContainers,
        "list_files" => AccessAction::ListFiles,
        "read" | "read_file" => AccessAction::ReadFile,
        "write" | "write_file" => AccessAction::WriteFile,
        "delete" | "delete_file" => AccessAction::DeleteFile,
        "create_container" => AccessAction::CreateContainer,
        "create_transit_key" => AccessAction::CreateTransitKey,
        "list_transit_keys" => AccessAction::ListTransitKeys,
        "encrypt" => AccessAction::Encrypt,
        "decrypt" => AccessAction::Decrypt,
        "create_signing_key" => AccessAction::CreateSigningKey,
        "list_signing_keys" => AccessAction::ListSigningKeys,
        "sign" => AccessAction::Sign,
        "verify" => AccessAction::Verify,
        "create_broker_secret" => AccessAction::CreateBrokerSecret,
        "list_broker_secrets" => AccessAction::ListBrokerSecrets,
        "broker" | "broker_request" => AccessAction::Broker,
        _ => return None,
    })
}

fn resolve_scopes(scopes: &[sv_core::agents::AgentScope]) -> Vec<ResolvedScope> {
    scopes
        .iter()
        .map(|scope| ResolvedScope {
            container_glob: scope.container_glob.clone(),
            actions: scope
                .actions
                .iter()
                .filter_map(|action| parse_access_action(action))
                .collect(),
            mode_ceiling: scope
                .mode_ceiling
                .as_deref()
                .and_then(|mode| SecurityMode::parse(mode).ok()),
        })
        .collect()
}

impl AgentAuthenticator for HeadlessAuthenticator {
    fn authenticate(&self, agent_id: Option<&str>, token: &str) -> Result<ResolvedAgent, String> {
        let agent_id = match agent_id {
            Some(id) => id.to_string(),
            None => {
                if token != self.shared_secret {
                    return Err("invalid shared secret".into());
                }
                list_agents(&self.root, &self.token_key)
                    .map_err(|e| e.to_string())?
                    .into_iter()
                    .find(|a| a.name == DEFAULT_AGENT_NAME && !a.revoked)
                    .map(|a| a.agent_id)
                    .ok_or_else(|| "no default agent".to_string())?
            }
        };
        let record = sv_core::agents::authenticate(&self.root, &self.token_key, &agent_id, token)
            .map_err(|e| e.to_string())?;
        Ok(ResolvedAgent {
            agent_id: record.agent_id,
            scopes: resolve_scopes(&record.scopes),
        })
    }
}

struct HeadlessAuditSink {
    root: PathBuf,
    hmac_key: [u8; 32],
}

impl HeadlessAuditSink {
    fn new(root: PathBuf, hmac_key: [u8; 32]) -> Self {
        Self { root, hmac_key }
    }
}

impl AuditSink for HeadlessAuditSink {
    fn record(&self, event: AuditEvent) -> Result<(), String> {
        let log = AuditLog::with_hmac_key(&self.root, self.hmac_key).map_err(|e| e.to_string())?;
        log.record(&event).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use sv_core::agents::{create_agent, AgentScope};
    use sv_mcp::AccessTransport;

    fn temp_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "sv-cli-serve-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn request(action: AccessAction, mode: Option<SecurityMode>) -> AccessRequest {
        AccessRequest {
            transport: AccessTransport::McpWs,
            action,
            container: None,
            file_name: None,
            mode,
            byte_size: None,
            agent_id: None,
            otp: None,
            authorization_context: String::new(),
        }
    }

    #[test]
    fn headless_authenticator_retains_persisted_scopes() {
        let root = temp_root("scopes");
        let token_key = [7u8; 32];
        let (agent_id, token) = create_agent(
            &root,
            &token_key,
            "scoped-agent",
            vec![AgentScope {
                container_glob: "notes/**".into(),
                actions: vec!["read".into(), "write_file".into()],
                mode_ceiling: Some("OTP".into()),
            }],
        )
        .unwrap();
        let authenticator = HeadlessAuthenticator::new(root.clone(), token_key, "shared".into());

        let resolved = authenticator.authenticate(Some(&agent_id), &token).unwrap();

        assert_eq!(resolved.agent_id, agent_id);
        assert_eq!(resolved.scopes.len(), 1);
        assert_eq!(resolved.scopes[0].container_glob, "notes/**");
        assert_eq!(
            resolved.scopes[0].actions,
            vec![AccessAction::ReadFile, AccessAction::WriteFile]
        );
        assert_eq!(resolved.scopes[0].mode_ceiling, Some(SecurityMode::Otp));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn headless_controller_denies_modeless_crypto_and_broker_actions() {
        let controller = HeadlessAccessController;

        for action in [
            AccessAction::Encrypt,
            AccessAction::Decrypt,
            AccessAction::Sign,
            AccessAction::CreateBrokerSecret,
            AccessAction::ListBrokerSecrets,
            AccessAction::Broker,
        ] {
            let error = controller
                .authorize(request(action, None))
                .await
                .unwrap_err();
            assert!(error.contains("cannot mediate crypto/broker operations"));
        }
    }

    #[tokio::test]
    async fn headless_controller_allows_direct_reads() {
        HeadlessAccessController
            .authorize(request(AccessAction::ReadFile, Some(SecurityMode::Direct)))
            .await
            .unwrap();
    }
}
