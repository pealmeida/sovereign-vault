//! Headless `sovereign-vault serve` gateway.
//!
//! Boots the same WebSocket MCP + read-only HTTP surface as the desktop app,
//! but with a fail-closed access policy: requests targeting APPROVAL / OTP /
//! ZKP / ANONYMIZED containers are rejected, since no UI exists for human
//! approval. Intended for unattended Linux servers, container hosts, and CI
//! runners that need scoped access to vault contents.
//!
//! Headless servers never mint a shared Default agent or expose a pairing
//! secret. They require one pre-provisioned, non-empty scoped agent credential.

#![forbid(unsafe_code)]

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sv_audit::{AuditDecision, AuditEvent, AuditLog};
use sv_core::agents::authenticate;
use sv_core::sv_storage::SecurityMode;
use sv_core::{BootstrapResult, CustodyMode, VaultHandle};
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
    pub agent_id: String,
    pub agent_token: String,
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

    let ws_listener = TcpListener::bind(args.ws_bind).await?;
    let http_listener = TcpListener::bind(args.http_bind).await?;

    let sink = Arc::new(HeadlessAuditSink::new(args.root.clone(), audit_hmac));
    let authenticator = Arc::new(HeadlessAuthenticator::new(
        args.root.clone(),
        agent_hmac,
        args.agent_id.clone(),
        args.agent_token.clone(),
    )?);
    let controller = Arc::new(HeadlessAccessController);

    let mut server = sv_mcp::McpServer::new(
        Arc::new(Mutex::new(Some(handle))) as sv_mcp::SharedVault<VaultHandle>,
        "headless-scoped-agent-credentials",
    )
    .with_audit_sink(sink.clone())
    .with_agent_authenticator(authenticator);
    server = server.with_access_controller(controller);
    if let Some((max, window)) = args.rate_limit {
        server = server.with_rate_limiter(Arc::new(RateLimiter::new(max, window)));
    }
    let server = Arc::new(server);

    // The headless HTTP surface intentionally has no pairing endpoint: loopback
    // alone is not an authentication boundary between OS users.
    let http_server = sv_http::HttpServer::without_pairing();

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
    tracing::info!(agent_id = %args.agent_id, "headless gateway accepts only the provisioned scoped agent");

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

    let handle = match startup_action(root, args.recovery.is_some())? {
        // Recovery must win even when the vault's on-disk state is incomplete:
        // it is the only safe way to repair or open a vault without its normal
        // custody credential.
        StartupAction::Recovery => {
            let phrase = args
                .recovery
                .as_ref()
                .expect("recovery was checked above")
                .join(" ");
            VaultHandle::unlock_with_recovery(root, &phrase)
                .map_err(|e| ServeError::Other(e.to_string()))?
        }
        StartupAction::Bootstrap => {
            fs::create_dir_all(root)?;
            let pp = args.passphrase.as_deref().ok_or_else(|| {
                ServeError::Other("vault is uninitialized; supply --passphrase to bootstrap".into())
            })?;
            let BootstrapResult {
                handle,
                recovery_phrase: _,
            } = VaultHandle::bootstrap(root, CustodyMode::Passphrase, Some(pp))
                .map_err(|e| ServeError::Other(e.to_string()))?;
            tracing::info!(root = %root.display(), "bootstrapped new vault");
            handle
        }
        StartupAction::Unlock(custody) => {
            VaultHandle::unlock(root, custody, args.passphrase.as_deref())
                .map_err(|e| ServeError::Other(e.to_string()))?
        }
    };

    let audit = handle.audit_hmac_key();
    let agent = handle.agent_token_key();
    Ok((handle, audit, agent))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupAction {
    Recovery,
    Bootstrap,
    Unlock(CustodyMode),
}

/// Choose the only safe startup path from the user input and on-disk vault state.
///
/// `master.salt` is deliberately absent for OS-keychain vaults, so it cannot
/// distinguish a new vault from an initialized one. The manifest and keyring
/// are the durable initialization artefacts checked by `VaultHandle::bootstrap`.
fn startup_action(root: &std::path::Path, has_recovery: bool) -> Result<StartupAction, ServeError> {
    if has_recovery {
        return Ok(StartupAction::Recovery);
    }

    if vault_is_initialized(root)? {
        let custody =
            VaultHandle::detect_custody(root).map_err(|e| ServeError::Other(e.to_string()))?;
        Ok(StartupAction::Unlock(custody))
    } else {
        Ok(StartupAction::Bootstrap)
    }
}

fn vault_is_initialized(root: &std::path::Path) -> Result<bool, ServeError> {
    for artifact in ["manifest.json", "keyring.svault"] {
        match fs::symlink_metadata(root.join(artifact)) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

/// Fail-closed access controller: only explicitly safe modeless operations
/// pass through. Mode-bearing container operations are permitted only for
/// DIRECT containers; all other modes require desktop mediation. Secret-
/// bearing/key-creating operations are rejected because no UI exists.
struct HeadlessAccessController;

#[async_trait::async_trait]
impl AccessController for HeadlessAccessController {
    async fn authorize(&self, request: AccessRequest) -> Result<(), String> {
        if !is_headless_allowed_action(request.action) {
            return Err(
                "headless mode only permits explicitly safe scoped operations; use the desktop app"
                    .into(),
            );
        }
        if is_headless_container_action(request.action)
            && !headless_allows_container_mode(request.mode)
        {
            return Err("headless cannot mediate this mode; use the desktop app".into());
        }

        Ok(())
    }
}

fn is_headless_allowed_action(action: AccessAction) -> bool {
    matches!(
        action,
        AccessAction::ListContainers
            | AccessAction::ListFiles
            | AccessAction::ReadFile
            | AccessAction::WriteFile
            | AccessAction::DeleteFile
            | AccessAction::CreateContainer
            | AccessAction::ListTransitKeys
            | AccessAction::ListSigningKeys
            | AccessAction::Verify
            | AccessAction::DestroyContainer
            | AccessAction::VaultInfo
    )
}

/// Returns whether an action operates on a specific container and therefore
/// must carry a mode. `ListContainers` is intentionally excluded: it is a
/// modeless vault-metadata operation, not access to a container's contents.
fn is_headless_container_action(action: AccessAction) -> bool {
    matches!(
        action,
        AccessAction::ListFiles
            | AccessAction::ReadFile
            | AccessAction::WriteFile
            | AccessAction::DeleteFile
            | AccessAction::CreateContainer
            | AccessAction::DestroyContainer
    )
}

/// Explicitly enumerate every security mode. Do not replace this with a
/// permissive wildcard: adding a mode must fail compilation until headless
/// behavior is deliberately decided, and defaults to denial here.
fn headless_allows_container_mode(mode: Option<SecurityMode>) -> bool {
    match mode {
        Some(SecurityMode::Direct) => true,
        Some(SecurityMode::Approval) => false,
        Some(SecurityMode::Otp) => false,
        Some(SecurityMode::Anonymized) => false,
        Some(SecurityMode::Zkp) => false,
        Some(SecurityMode::Native) => false,
        None => false,
    }
}

struct HeadlessAuthenticator {
    root: PathBuf,
    token_key: [u8; 32],
    agent_id: String,
    agent_token: String,
}

impl HeadlessAuthenticator {
    fn new(
        root: PathBuf,
        token_key: [u8; 32],
        agent_id: String,
        agent_token: String,
    ) -> Result<Self, ServeError> {
        if agent_id.is_empty() || agent_token.is_empty() {
            return Err(ServeError::Other(
                "headless serve requires SV_AGENT_ID and SV_AGENT_TOKEN (or a 0600 SV_AGENT_TOKEN_FILE)".into(),
            ));
        }
        let record = authenticate(&root, &token_key, &agent_id, &agent_token)
            .map_err(|e| ServeError::Other(format!("invalid pre-provisioned agent: {e}")))?;
        if record.scopes.is_empty() {
            return Err(ServeError::Other(
                "headless serve refuses unscoped agents; provision at least one scope".into(),
            ));
        }
        Ok(Self {
            root,
            token_key,
            agent_id,
            agent_token,
        })
    }
}

fn resolve_scopes(scopes: &[sv_core::agents::AgentScope]) -> Result<Vec<ResolvedScope>, String> {
    scopes
        .iter()
        .map(|scope| {
            sv_mcp::AgentScope {
                container_glob: scope.container_glob.clone(),
                actions: scope.actions.clone(),
                mode_ceiling: scope.mode_ceiling.clone(),
            }
            .resolve()
        })
        .collect()
}

impl AgentAuthenticator for HeadlessAuthenticator {
    fn authenticate(&self, agent_id: Option<&str>, token: &str) -> Result<ResolvedAgent, String> {
        use subtle::ConstantTimeEq as _;

        let token_matches: bool = token.as_bytes().ct_eq(self.agent_token.as_bytes()).into();
        if agent_id != Some(self.agent_id.as_str()) || !token_matches {
            return Err("credential is not the configured scoped agent".into());
        }
        let record = authenticate(&self.root, &self.token_key, &self.agent_id, token)
            .map_err(|e| e.to_string())?;
        if record.scopes.is_empty() {
            return Err("headless serve refuses unscoped agents".into());
        }
        Ok(ResolvedAgent {
            agent_id: record.agent_id,
            scopes: resolve_scopes(&record.scopes)?,
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
            import_summary: None,
        }
    }

    fn serve_args(root: PathBuf) -> ServeArgs {
        ServeArgs {
            root,
            passphrase: None,
            recovery: None,
            ws_bind: "127.0.0.1:0".parse().unwrap(),
            http_bind: "127.0.0.1:0".parse().unwrap(),
            rate_limit: None,
            agent_id: "test-agent".into(),
            agent_token: "test-token".into(),
        }
    }

    #[test]
    fn initialized_saltless_vault_selects_os_keychain_unlock_not_bootstrap() {
        let root = temp_root("os-keychain-startup");
        // OS-keychain custody has no master.salt. A manifest/keyring is enough
        // to establish that this is an existing vault without touching a live
        // OS keychain in the unit test.
        fs::write(root.join("manifest.json"), b"existing vault").unwrap();
        fs::write(root.join("keyring.svault"), b"existing keyring").unwrap();

        assert_eq!(
            startup_action(&root, false).unwrap(),
            StartupAction::Unlock(CustodyMode::OsKeychain)
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_startup_is_prioritized_before_fresh_bootstrap() {
        let root = temp_root("recovery-priority");

        assert_eq!(
            startup_action(&root, true).unwrap(),
            StartupAction::Recovery
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn fresh_vault_bootstraps_with_passphrase() {
        let root = temp_root("fresh-bootstrap");
        let mut args = serve_args(root.clone());
        args.passphrase = Some("fresh-bootstrap-passphrase".into());

        let (handle, _, _) = open_or_bootstrap(&args).await.unwrap();
        assert_eq!(handle.custody(), CustodyMode::Passphrase);
        assert!(root.join("manifest.json").exists());
        assert!(root.join("keyring.svault").exists());
        drop(handle);

        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn recovery_startup_opens_existing_vault_before_bootstrap() {
        let root = temp_root("recovery-existing");
        let bootstrap = VaultHandle::bootstrap(
            &root,
            CustodyMode::Passphrase,
            Some("recovery-existing-passphrase"),
        )
        .unwrap();
        let recovery_phrase = bootstrap.recovery_phrase.clone();
        drop(bootstrap);

        let mut args = serve_args(root.clone());
        args.recovery = Some(
            recovery_phrase
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
        );
        let (handle, _, _) = open_or_bootstrap(&args).await.unwrap();
        assert_eq!(handle.custody(), CustodyMode::Recovery);
        drop(handle);

        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn existing_passphrase_vault_starts_with_detected_custody() {
        let root = temp_root("passphrase-startup");
        let passphrase = "existing-passphrase-startup";
        let bootstrap =
            VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some(passphrase)).unwrap();
        drop(bootstrap);

        let mut args = serve_args(root.clone());
        args.passphrase = Some(passphrase.into());
        let (handle, _, _) = open_or_bootstrap(&args).await.unwrap();
        assert_eq!(handle.custody(), CustodyMode::Passphrase);
        drop(handle);

        fs::remove_dir_all(root).unwrap();
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
        let authenticator =
            HeadlessAuthenticator::new(root.clone(), token_key, agent_id.clone(), token.clone())
                .unwrap();

        let resolved = authenticator.authenticate(Some(&agent_id), &token).unwrap();

        assert_eq!(resolved.agent_id, agent_id);
        assert_eq!(resolved.scopes.len(), 1);
        assert_eq!(resolved.scopes[0].container_glob, "notes/**");
        assert_eq!(
            resolved.scopes[0].actions,
            vec![AccessAction::ReadFile, AccessAction::WriteFile]
        );
        assert_eq!(resolved.scopes[0].mode_ceiling, Some(SecurityMode::Otp));
        assert!(authenticator.authenticate(None, &token).is_err());
        assert!(authenticator
            .authenticate(Some("ag_other"), &token)
            .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn headless_controller_denies_key_creation_and_secret_bearing_actions() {
        let controller = HeadlessAccessController;

        for action in [
            AccessAction::CreateTransitKey,
            AccessAction::Encrypt,
            AccessAction::Decrypt,
            AccessAction::CreateSigningKey,
            AccessAction::Sign,
            AccessAction::CreateBrokerSecret,
            AccessAction::ListBrokerSecrets,
            AccessAction::Broker,
        ] {
            let error = controller
                .authorize(request(action, None))
                .await
                .unwrap_err();
            assert!(error.contains("only permits explicitly safe"));
        }
    }

    #[tokio::test]
    async fn headless_controller_allows_direct_container_read_write_and_list() {
        for action in [
            AccessAction::ReadFile,
            AccessAction::WriteFile,
            AccessAction::ListFiles,
        ] {
            HeadlessAccessController
                .authorize(request(action, Some(SecurityMode::Direct)))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn headless_controller_denies_native_container_read_write_delete_and_creation() {
        for action in [
            AccessAction::ReadFile,
            AccessAction::WriteFile,
            AccessAction::DeleteFile,
            AccessAction::CreateContainer,
        ] {
            let error = HeadlessAccessController
                .authorize(request(action, Some(SecurityMode::Native)))
                .await
                .unwrap_err();
            assert!(error.contains("headless cannot mediate this mode"));
        }
    }

    #[tokio::test]
    async fn headless_controller_denies_all_other_container_modes() {
        for mode in [
            SecurityMode::Approval,
            SecurityMode::Otp,
            SecurityMode::Zkp,
            SecurityMode::Anonymized,
        ] {
            for action in [
                AccessAction::ListFiles,
                AccessAction::ReadFile,
                AccessAction::WriteFile,
                AccessAction::DeleteFile,
                AccessAction::CreateContainer,
                AccessAction::DestroyContainer,
            ] {
                let error = HeadlessAccessController
                    .authorize(request(action, Some(mode)))
                    .await
                    .unwrap_err();
                assert!(error.contains("headless cannot mediate this mode"));
            }
        }
    }

    #[tokio::test]
    async fn headless_controller_denies_modeless_container_operations() {
        let error = HeadlessAccessController
            .authorize(request(AccessAction::ReadFile, None))
            .await
            .unwrap_err();
        assert!(error.contains("headless cannot mediate this mode"));
    }

    #[tokio::test]
    async fn headless_controller_denies_agent_export() {
        let error = HeadlessAccessController
            .authorize(request(AccessAction::ExportAgents, None))
            .await
            .unwrap_err();
        assert!(error.contains("only permits explicitly safe"));
    }

    #[test]
    fn headless_authenticator_rejects_unscoped_agent() {
        let root = temp_root("unscoped");
        let token_key = [9u8; 32];
        let (agent_id, token) = create_agent(&root, &token_key, "unscoped", Vec::new()).unwrap();

        let error = HeadlessAuthenticator::new(root.clone(), token_key, agent_id, token)
            .err()
            .unwrap();
        assert!(error.to_string().contains("refuses unscoped agents"));
        fs::remove_dir_all(root).unwrap();
    }
}
