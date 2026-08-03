//! Sovereign Vault headless CLI.

#![forbid(unsafe_code)]

mod agent_commands;
mod mcp_stdio;
mod serve;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use crate::agent_commands::{default_output_path, install_target, render_target, AgentTarget};

#[derive(Parser, Debug)]
#[command(name = "sovereign-vault", version, about = "Sovereign Vault CLI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run a stdio->WebSocket MCP proxy targeting the local Sovereign Vault.
    McpStdio,
    /// Print or install agent command packs and skills.
    Agents(AgentsCli),
    /// Start the headless MCP+HTTP gateway (no UI).
    Serve(ServeCli),
    /// Detect, repair, and report on a vault (manifest auth, agents, audit).
    Migrate(MigrateCli),
}

#[derive(Args, Debug)]
struct AgentsCli {
    #[command(subcommand)]
    command: AgentsCommand,
}

#[derive(Subcommand, Debug)]
enum AgentsCommand {
    /// Print the rendered command pack for one target to stdout.
    Print {
        #[arg(long, value_enum)]
        target: AgentTarget,
    },
    /// Install the rendered command pack into a target-specific default path.
    Install {
        #[arg(long, value_enum)]
        target: AgentTarget,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// List supported install targets and their default output paths.
    ListTargets,
}

#[derive(Args, Debug)]
struct ServeCli {
    /// Vault root directory. Defaults to the OS app-data dir.
    #[arg(long, env = "SV_ROOT")]
    root: Option<PathBuf>,

    /// File containing the vault passphrase (one line, no trailing newline).
    #[arg(long, env = "SV_PASSPHRASE_FILE")]
    passphrase_file: Option<PathBuf>,

    /// Environment variable holding the vault passphrase.
    #[arg(long, env = "SV_PASSPHRASE_ENV")]
    passphrase_env: Option<String>,

    /// Environment variable holding the recovery phrase (space-separated words).
    #[arg(long, env = "SV_RECOVERY_ENV")]
    recovery_env: Option<String>,

    /// WebSocket MCP bind address.
    #[arg(long, default_value = "127.0.0.1:9944")]
    bind: SocketAddr,

    /// HTTP read-only bind address.
    #[arg(long, default_value = "127.0.0.1:9943")]
    http_bind: SocketAddr,

    /// Rate limit as requests per millisecond window (default: 120/60000 =
    /// 120 requests per minute per agent). Set explicitly to 0 only to disable.
    #[arg(long, default_value = "120/60000")]
    rate_limit: String,

    /// ID of the pre-provisioned, scoped agent allowed to use this headless server.
    #[arg(long, env = "SV_AGENT_ID")]
    agent_id: Option<String>,

    /// Read the pre-provisioned agent token from this 0600 file. Alternatively,
    /// set SV_AGENT_TOKEN in the environment. Tokens are never accepted as CLI arguments.
    #[arg(long, env = "SV_AGENT_TOKEN_FILE")]
    agent_token_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct MigrateCli {
    #[command(subcommand)]
    command: MigrateCommand,
    /// Vault root. Defaults to the OS app-data dir.
    #[arg(long, env = "SV_ROOT", global = true)]
    root: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum MigrateCommand {
    /// Print the canonical manifest SHA-256 (the value to pin in CODEOWNERS).
    ManifestDigest,
    /// Apply manifest authentication migration (requires --manifest-digest).
    ManifestAuth {
        /// Manifest SHA-256 digest required to authorize the one-time
        /// legacy-manifest authentication migration. Read it with
        /// `sovereign-vault migrate manifest-digest` first; never accept it
        /// from chat logs.
        #[arg(long)]
        manifest_digest: String,
        /// Passphrase (only used when the vault custody is `Passphrase`).
        #[arg(long, env = "SV_PASSPHRASE")]
        passphrase: Option<String>,
    },
    /// Verify the authenticated audit log hash chain after unlocking the vault.
    AuditChain {
        /// Passphrase for passphrase custody. May also be supplied as SV_PASSPHRASE.
        #[arg(long, env = "SV_PASSPHRASE")]
        passphrase: Option<String>,
        /// Environment variable containing a space-separated recovery phrase.
        #[arg(long, env = "SV_RECOVERY_ENV")]
        recovery_env: Option<String>,
    },
    /// List revoked or expired agents that may need re-issuance.
    Agents,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        None => {
            println!("Sovereign Vault v{}", sv_core::version());
            ExitCode::SUCCESS
        }
        Some(Cmd::McpStdio) => match mcp_stdio::run_mcp_stdio().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sovereign-vault mcp-stdio: {e}");
                ExitCode::from(1)
            }
        },
        Some(Cmd::Agents(agents)) => match run_agents(agents) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sovereign-vault agents: {e}");
                ExitCode::from(1)
            }
        },
        Some(Cmd::Serve(serve)) => match run_serve(serve).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sovereign-vault serve: {e}");
                ExitCode::from(1)
            }
        },
        Some(Cmd::Migrate(migrate)) => match run_migrate(migrate) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sovereign-vault migrate: {e}");
                ExitCode::from(1)
            }
        },
    }
}

fn run_agents(agents: AgentsCli) -> Result<(), String> {
    match agents.command {
        AgentsCommand::Print { target } => {
            print!("{}", render_target(target)?);
            Ok(())
        }
        AgentsCommand::Install { target, dir, force } => {
            let installed = install_target(target, dir, force)?;
            println!("{}", installed.display());
            Ok(())
        }
        AgentsCommand::ListTargets => {
            for target in AgentTarget::ALL {
                let path = default_output_path(*target);
                println!("{target}\t{}", path.display());
            }
            Ok(())
        }
    }
}

async fn run_serve(cli: ServeCli) -> Result<(), String> {
    let root = cli
        .root
        .or_else(|| dirs::data_dir().map(|d| d.join("sovereign-vault")))
        .ok_or_else(|| {
            "cannot determine vault root; set --root or ensure $HOME is set".to_string()
        })?;

    if cli.passphrase_file.is_some() && cli.passphrase_env.is_some() {
        return Err("set either --passphrase-file or --passphrase-env, not both".into());
    }
    let passphrase = if let Some(ref path) = cli.passphrase_file {
        Some(read_owner_only_secret_file(path, "passphrase")?)
    } else if let Some(ref var) = cli.passphrase_env {
        Some(
            std::env::var(var)
                .map_err(|_| format!("passphrase environment variable is not set: {var}"))?,
        )
    } else {
        None
    };

    let recovery = if let Some(ref var) = cli.recovery_env {
        let words: Vec<String> = std::env::var(var)
            .map_err(|_| format!("recovery environment variable is not set: {var}"))?
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();
        if words.is_empty() {
            None
        } else {
            Some(words)
        }
    } else {
        None
    };

    let rate_limit = parse_rate_limit(&cli.rate_limit)?;
    let agent_id = cli.agent_id.filter(|id| !id.is_empty()).ok_or_else(|| {
        "headless serve requires SV_AGENT_ID for a pre-provisioned scoped agent".to_string()
    })?;
    let agent_token = read_headless_agent_token(cli.agent_token_file.as_deref())?;

    serve::run(serve::ServeArgs {
        root,
        passphrase,
        recovery,
        ws_bind: cli.bind,
        http_bind: cli.http_bind,
        rate_limit,
        agent_id,
        agent_token,
    })
    .await
    .map_err(|e| e.to_string())
}

fn read_headless_agent_token(token_file: Option<&std::path::Path>) -> Result<String, String> {
    let environment_token = std::env::var("SV_AGENT_TOKEN")
        .ok()
        .filter(|token| !token.is_empty());
    if environment_token.is_some() && token_file.is_some() {
        return Err("set either SV_AGENT_TOKEN or SV_AGENT_TOKEN_FILE, not both".into());
    }
    if let Some(token) = environment_token {
        return Ok(token);
    }
    let path = token_file.ok_or_else(|| {
        "headless serve requires SV_AGENT_TOKEN or a 0600 SV_AGENT_TOKEN_FILE".to_string()
    })?;
    read_owner_only_secret_file(path, "agent token")
}

/// Read a local daemon credential only from a regular owner-only file.
///
/// Unix validates both the path and the opened descriptor, preventing a
/// symlink or path-replacement attack from changing the credential source.
#[cfg(unix)]
fn read_owner_only_secret_file(path: &std::path::Path, label: &str) -> Result<String, String> {
    use std::io::Read as _;

    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("reading {label} file {}: {e}", path.display()))?;
    if path_metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} file must not be a symbolic link: {}",
            path.display()
        ));
    }
    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("reading {label} file {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("reading {label} file {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "{label} file is not a regular file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino() {
            return Err(format!(
                "{label} file changed while opening it: {}",
                path.display()
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{label} file must be owner-only (0600): {}",
                path.display()
            ));
        }
    }
    let mut secret = String::new();
    file.read_to_string(&mut secret)
        .map_err(|e| format!("reading {label} file {}: {e}", path.display()))?;
    let secret = secret.trim().to_string();
    if secret.is_empty() {
        return Err(format!("{label} file is empty: {}", path.display()));
    }
    Ok(secret)
}

/// This CLI does not implement equivalent Windows ACL validation, so headless
/// credential files are rejected rather than accepting a weaker guarantee.
#[cfg(not(unix))]
fn read_owner_only_secret_file(path: &std::path::Path, label: &str) -> Result<String, String> {
    Err(format!(
        "headless {label}-file hardening is only supported on Unix; use a supported environment credential source instead: {}",
        path.display()
    ))
}

fn parse_rate_limit(raw: &str) -> Result<Option<(usize, std::time::Duration)>, String> {
    if raw == "0" {
        return Ok(None);
    }
    let (n_str, ms_str) = raw
        .split_once('/')
        .ok_or_else(|| "rate-limit must be N/Ms (e.g. 100/60000)".to_string())?;
    let n: usize = n_str
        .parse()
        .map_err(|_| format!("invalid rate-limit count: {n_str}"))?;
    let ms: u64 = ms_str
        .parse()
        .map_err(|_| format!("invalid rate-limit window ms: {ms_str}"))?;
    if n == 0 || ms == 0 {
        return Ok(None);
    }
    Ok(Some((n, std::time::Duration::from_millis(ms))))
}

fn run_migrate(m: MigrateCli) -> Result<(), String> {
    let root = m
        .root
        .clone()
        .or_else(|| dirs::data_dir().map(|d| d.join("sovereign-vault")))
        .ok_or_else(|| "cannot determine vault root; set --root".to_string())?;
    match m.command {
        MigrateCommand::ManifestDigest => {
            let digest =
                sv_core::sv_storage::manifest_migration_digest(&root).map_err(|e| e.to_string())?;
            println!("{digest}");
        }
        MigrateCommand::ManifestAuth {
            manifest_digest,
            passphrase,
        } => {
            let custody = migration_custody(&root)?;
            sv_core::VaultHandle::migrate_manifest_authentication(
                &root,
                custody,
                passphrase.as_deref(),
                &manifest_digest,
            )
            .map_err(|e| e.to_string())?;
            eprintln!("[migrate] manifest authentication migrated");
        }
        MigrateCommand::AuditChain {
            passphrase,
            recovery_env,
        } => {
            let handle = if let Some(recovery_env) = recovery_env {
                let recovery = std::env::var(&recovery_env).map_err(|_| {
                    format!("recovery environment variable is not set: {recovery_env}")
                })?;
                sv_core::VaultHandle::unlock_with_recovery(&root, &recovery)
                    .map_err(|e| e.to_string())?
            } else {
                let custody = migration_custody(&root)?;
                sv_core::VaultHandle::unlock(&root, custody, passphrase.as_deref())
                    .map_err(|e| e.to_string())?
            };
            let log = sv_audit::AuditLog::with_hmac_key(&root, handle.audit_hmac_key())
                .map_err(|e| e.to_string())?;
            let report = log.verify_chain().map_err(|e| e.to_string())?;
            eprintln!(
                "[migrate] audit chain: {} entries, broken_at={:?}",
                report.entries, report.first_broken
            );
            if report.first_broken.is_some() {
                return Err(
                    "audit chain is broken; investigate from a trusted vault backup".into(),
                );
            }
        }
        MigrateCommand::Agents => {
            // Audit log needs HMAC key for token verification; we only read
            // the agents.json file under the vault root. Open without auth
            // for the listing path.
            let entries = std::fs::read_dir(&root)
                .map_err(|e| format!("read_dir {}: {e}", root.display()))?;
            let mut count = 0usize;
            let mut revoked = 0usize;
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if !name.starts_with("ag_") {
                    continue;
                }
                count += 1;
                if name.contains(".revoked") {
                    revoked += 1;
                }
            }
            eprintln!("[migrate] agents directory entries: {count}, revoked: {revoked}");
            eprintln!("[migrate] (use `agents.export_agents` MCP tool for full export)");
        }
    }
    Ok(())
}

/// Select the persisted normal custody mode for migration commands.
///
/// `master.salt` records passphrase custody; its absence records OS-keychain
/// custody, including legacy vaults that have not yet created a keyring.
fn migration_custody(root: &std::path::Path) -> Result<sv_core::CustodyMode, String> {
    sv_core::VaultHandle::detect_custody(root).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sv-cli-main-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn parse_rate_limit_zero_disables() {
        assert!(parse_rate_limit("0").unwrap().is_none());
    }

    #[test]
    fn parse_rate_limit_valid() {
        let (n, d) = parse_rate_limit("100/60000").unwrap().unwrap();
        assert_eq!(n, 100);
        assert_eq!(d, std::time::Duration::from_millis(60_000));
    }

    #[test]
    fn default_headless_rate_limit_is_conservative_per_minute() {
        let (n, window) = parse_rate_limit("120/60000").unwrap().unwrap();
        assert_eq!(n, 120);
        assert_eq!(window, std::time::Duration::from_secs(60));
    }

    #[test]
    fn parse_rate_limit_zero_parts_disables() {
        assert!(parse_rate_limit("0/60000").unwrap().is_none());
        assert!(parse_rate_limit("100/0").unwrap().is_none());
    }

    #[test]
    fn parse_rate_limit_invalid() {
        assert!(parse_rate_limit("abc/60000").is_err());
        assert!(parse_rate_limit("100/xyz").is_err());
        assert!(parse_rate_limit("100").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn daemon_secret_file_must_be_owner_only_and_not_a_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let root = temp_root("secret-file-permissions");
        std::fs::create_dir_all(&root).unwrap();
        let secret = root.join("agent.token");
        std::fs::write(&secret, "credential").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_owner_only_secret_file(&secret, "agent token").is_err());

        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_owner_only_secret_file(&secret, "agent token").unwrap(),
            "credential"
        );

        let link = root.join("agent.token.link");
        symlink(&secret, &link).unwrap();
        assert!(read_owner_only_secret_file(&link, "agent token").is_err());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(not(unix))]
    #[test]
    fn daemon_secret_file_is_rejected_when_owner_only_hardening_is_unavailable() {
        let path = temp_root("unsupported-secret-file").join("agent.token");
        let error = read_owner_only_secret_file(&path, "agent token").unwrap_err();
        assert!(error.contains("hardening is only supported on Unix"));
    }

    #[test]
    fn audit_chain_uses_the_unlocked_vault_hmac_key() {
        let root = temp_root("audit-chain");
        let passphrase = "audit-chain-test-passphrase";
        let bootstrap = sv_core::VaultHandle::bootstrap(
            &root,
            sv_core::CustodyMode::Passphrase,
            Some(passphrase),
        )
        .unwrap();
        let audit_key = bootstrap.handle.audit_hmac_key();
        let log = sv_audit::AuditLog::with_hmac_key(&root, audit_key).unwrap();
        log.record(&sv_audit::AuditEvent::new(
            sv_audit::AuditAction::VaultInfo,
            sv_audit::AuditDecision::Allowed,
            "test",
        ))
        .unwrap();
        drop(log);
        drop(bootstrap);

        run_migrate(MigrateCli {
            command: MigrateCommand::AuditChain {
                passphrase: Some(passphrase.to_string()),
                recovery_env: None,
            },
            root: Some(root.clone()),
        })
        .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migration_custody_detects_passphrase_vaults() {
        let root = temp_root("migration-custody-passphrase");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("master.salt"), [0u8; 16]).unwrap();

        assert_eq!(
            migration_custody(&root).unwrap(),
            sv_core::CustodyMode::Passphrase
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migration_custody_detects_os_keychain_vaults_without_a_salt() {
        let root = temp_root("migration-custody-keychain");
        std::fs::create_dir_all(&root).unwrap();

        assert_eq!(
            migration_custody(&root).unwrap(),
            sv_core::CustodyMode::OsKeychain
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_auth_migrates_a_legacy_passphrase_vault() {
        let root = temp_root("manifest-auth-passphrase");
        std::fs::create_dir_all(&root).unwrap();
        let passphrase = "manifest-auth-test-passphrase";
        let salt = sv_core::sv_crypto::random_salt().unwrap();
        std::fs::write(root.join("master.salt"), salt).unwrap();
        let legacy_key = sv_core::sv_crypto::MasterKey::from_passphrase(passphrase, &salt).unwrap();
        {
            let vault = sv_core::sv_storage::Vault::open_or_init(&root, legacy_key).unwrap();
            vault
                .create_container("documents", sv_core::sv_storage::SecurityMode::Direct, None)
                .unwrap();
        }
        let digest = sv_core::VaultHandle::manifest_migration_digest(&root).unwrap();

        run_migrate(MigrateCli {
            command: MigrateCommand::ManifestAuth {
                manifest_digest: digest,
                passphrase: Some(passphrase.to_string()),
            },
            root: Some(root.clone()),
        })
        .unwrap();

        let unlocked =
            sv_core::VaultHandle::unlock(&root, sv_core::CustodyMode::Passphrase, Some(passphrase))
                .unwrap();
        assert!(root.join("keyring.svault").exists());
        drop(unlocked);
        std::fs::remove_dir_all(root).unwrap();
    }
}
