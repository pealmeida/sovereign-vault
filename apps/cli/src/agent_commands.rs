use std::fmt;
use std::fs;
use std::path::PathBuf;

use clap::ValueEnum;
use serde::Deserialize;

const CATALOG_YAML: &str =
    include_str!("../../../integrations/agents/sovereign-vault.commands.yaml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AgentTarget {
    ClaudeCode,
    OpenCode,
    Hermes,
    Codex,
    Generic,
}

impl AgentTarget {
    pub const ALL: &'static [AgentTarget] = &[
        AgentTarget::ClaudeCode,
        AgentTarget::OpenCode,
        AgentTarget::Hermes,
        AgentTarget::Codex,
        AgentTarget::Generic,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code Command Pack",
            Self::OpenCode => "OpenCode Command Pack",
            Self::Hermes => "Hermes Skill Pack",
            Self::Codex => "Codex Skill Pack",
            Self::Generic => "Generic MCP Command Pack",
        }
    }

    fn target_notes(self) -> &'static [&'static str] {
        match self {
            Self::ClaudeCode => &[
                "Install this file as a project command so `/sovereign-vault ...` dispatches into the MCP server.",
                "The command file assumes the Claude Code session already has the `sovereign-vault` MCP server configured.",
            ],
            Self::OpenCode => &[
                "Install this file under `.opencode/commands/` so OpenCode exposes `/sovereign-vault`.",
                "The command expects an MCP server named `sovereign-vault` to be present in the project or global config.",
            ],
            Self::Hermes => &[
                "Hermes surfaces installed skills as slash commands, so this output is written as a skill-style command document.",
                "Keep the local Sovereign Vault MCP server configured in the Hermes runtime.",
            ],
            Self::Codex => &[
                "Codex does not rely on project-local slash-command files in the same way; install this as a local skill prompt.",
                "The content is written in skill form so Codex can route `/sovereign-vault`-style intent through the MCP surface.",
            ],
            Self::Generic => &[
                "Use this pack as the reference mapping for agents that can consume arbitrary markdown instructions.",
                "If the client cannot install slash commands directly, copy the relevant command entries into its prompt or skill system.",
            ],
        }
    }
}

impl fmt::Display for AgentTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::ClaudeCode => "claude-code",
            Self::OpenCode => "opencode",
            Self::Hermes => "hermes",
            Self::Codex => "codex",
            Self::Generic => "generic",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Deserialize)]
struct Catalog {
    name: String,
    summary: String,
    prerequisites: Vec<String>,
    environment: Vec<CatalogEnv>,
    behaviors: Vec<String>,
    commands: Vec<CatalogCommand>,
    suggestions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CatalogEnv {
    name: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct CatalogCommand {
    syntax: String,
    purpose: String,
    tool: String,
    mapping: String,
    notes: Option<Vec<String>>,
}

pub fn default_output_path(target: AgentTarget) -> PathBuf {
    match target {
        AgentTarget::ClaudeCode => PathBuf::from(".claude/commands/sovereign-vault.md"),
        AgentTarget::OpenCode => PathBuf::from(".opencode/commands/sovereign-vault.md"),
        AgentTarget::Hermes => PathBuf::from(".hermes/skills/sovereign-vault.md"),
        AgentTarget::Codex => PathBuf::from(".codex/skills/sovereign-vault/SKILL.md"),
        AgentTarget::Generic => {
            PathBuf::from("integrations/agents/generated/sovereign-vault-generic.md")
        }
    }
}

pub fn render_target(target: AgentTarget) -> Result<String, String> {
    let catalog: Catalog =
        serde_yaml::from_str(CATALOG_YAML).map_err(|e| format!("parse catalog: {e}"))?;

    let mut out = String::new();
    let heading = match target {
        AgentTarget::Codex => format!("# {}\n\n", catalog.name),
        _ => format!("# /{}\n\n", catalog.name),
    };
    out.push_str(&heading);
    out.push_str(&format!("{}\n\n", target.title()));
    out.push_str(&format!("{}\n\n", catalog.summary));

    out.push_str("## Target notes\n\n");
    for note in target.target_notes() {
        out.push_str(&format!("- {}\n", note));
    }
    out.push('\n');

    out.push_str("## Preconditions\n\n");
    for item in &catalog.prerequisites {
        out.push_str(&format!("- {}\n", item));
    }
    out.push('\n');

    out.push_str("## Environment\n\n");
    for item in &catalog.environment {
        out.push_str(&format!("- `{}`: {}\n", item.name, item.description));
    }
    out.push('\n');

    out.push_str("## Behavior\n\n");
    for item in &catalog.behaviors {
        out.push_str(&format!("- {}\n", item));
    }
    out.push('\n');

    out.push_str("## Supported commands\n\n");
    for command in &catalog.commands {
        out.push_str(&format!("### `{}`\n\n", command.syntax));
        out.push_str(&format!("{}\n\n", command.purpose));
        out.push_str(&format!("- MCP tool: `{}`\n", command.tool));
        out.push_str(&format!("- Mapping: {}\n", command.mapping));
        if let Some(notes) = &command.notes {
            for note in notes {
                out.push_str(&format!("- Note: {}\n", note));
            }
        }
        out.push('\n');
    }

    out.push_str("## Suggested next commands\n\n");
    for suggestion in &catalog.suggestions {
        out.push_str(&format!("- `{}`\n", suggestion));
    }

    Ok(out)
}

pub fn install_target(
    target: AgentTarget,
    dir: Option<PathBuf>,
    force: bool,
) -> Result<PathBuf, String> {
    let rendered = render_target(target)?;
    let path = dir.unwrap_or_else(|| default_output_path(target));
    if path.exists() && !force {
        return Err(format!(
            "refusing to overwrite {}; pass --force to replace it",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    fs::write(&path, rendered).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_pairing_env_and_primary_commands() {
        let rendered = render_target(AgentTarget::ClaudeCode).unwrap();
        assert!(rendered.contains("SV_AGENT_ID"));
        assert!(rendered.contains("SV_PAIRING_TOKEN"));
        assert!(rendered.contains("/sovereign-vault list vaults"));
        assert!(rendered.contains("vault.create_broker_secret"));
    }

    #[test]
    fn default_paths_match_target_conventions() {
        assert_eq!(
            default_output_path(AgentTarget::ClaudeCode),
            PathBuf::from(".claude/commands/sovereign-vault.md")
        );
        assert_eq!(
            default_output_path(AgentTarget::Codex),
            PathBuf::from(".codex/skills/sovereign-vault/SKILL.md")
        );
    }
}
