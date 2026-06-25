//! Sovereign Vault headless CLI.

#![forbid(unsafe_code)]

mod agent_commands;
mod mcp_stdio;

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
