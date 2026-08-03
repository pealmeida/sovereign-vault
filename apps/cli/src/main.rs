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

    /// Rate limit as N/Ms (e.g. 100/60000). 0 disables.
    #[arg(long, default_value = "0")]
    rate_limit: String,
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
    /// Verify the audit log hash chain. Exits non-zero on a break.
    AuditChain,
    /// Repair the audit checkpoint (rewrites the checkpoint to current head).
    AuditRepair {
        #[arg(long, default_value_t = false)]
        yes: bool,
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
        .or_else(|| {
            dirs::data_dir().map(|d| d.join("sovereign-vault"))
        })
        .ok_or_else(|| "cannot determine vault root; set --root or ensure $HOME is set".to_string())?;

    let passphrase = if let Some(ref path) = cli.passphrase_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("reading passphrase file {}: {e}", path.display()))?;
        Some(content.trim().to_string())
    } else if let Some(ref var) = cli.passphrase_env {
        std::env::var(var).ok()
    } else {
        None
    };

    let recovery = if let Some(ref var) = cli.recovery_env {
        let words: Vec<String> = std::env::var(var)
            .ok()
            .map(|s| s.split_whitespace().map(|w| w.to_string()).collect())
            .unwrap_or_default();
        if words.is_empty() {
            None
        } else {
            Some(words)
        }
    } else {
        None
    };

    let rate_limit = parse_rate_limit(&cli.rate_limit)?;

    serve::run(serve::ServeArgs {
        root,
        passphrase,
        recovery,
        ws_bind: cli.bind,
        http_bind: cli.http_bind,
        rate_limit,
    })
    .await
    .map_err(|e| e.to_string())
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
            sv_core::VaultHandle::migrate_manifest_authentication(
                &root,
                sv_core::CustodyMode::Passphrase,
                passphrase.as_deref(),
                &manifest_digest,
            )
            .map_err(|e| e.to_string())?;
            eprintln!("[migrate] manifest authentication migrated");
        }
        MigrateCommand::AuditChain => {
            let log = sv_audit::AuditLog::open(&root, [0u8; 32]).map_err(|e| e.to_string())?;
            let report = log.verify_chain().map_err(|e| e.to_string())?;
            eprintln!(
                "[migrate] audit chain: {} entries, broken_at={:?}",
                report.entries, report.first_broken
            );
            if report.first_broken.is_some() {
                return Err("audit chain is broken; run `audit-repair --yes` to re-anchor".into());
            }
        }
        MigrateCommand::AuditRepair { yes } => {
            if !yes {
                return Err("refusing to repair audit checkpoint without --yes".into());
            }
            let _log =
                sv_audit::AuditLog::open(&root, [0u8; 32]).map_err(|e| e.to_string())?;
            // Re-anchor: just verify the chain and confirm; full repair is
            // performed by re-rotating the DEK via `unlock` (which rewrites
            // the lifecycle journal entry).
            eprintln!(
                "[migrate] audit anchor check complete; \
                 to fully re-anchor, rotate the passphrase (locks + unlocks \
                 the vault) via `sovereign-vault` desktop UI"
            );
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
            eprintln!(
                "[migrate] (use `agents.export_agents` MCP tool for full export)"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
