# Examples

Ready-to-paste integration samples for connecting an MCP client to Sovereign Vault.

Every sample points an MCP client at the **stdio proxy** the vault ships:

```
sovereign-vault mcp-stdio
```

The proxy fetches the per-launch pairing secret over loopback HTTP and pairs the
built-in **Default** agent. The vault must be **unlocked** for clients to
connect (locking the vault stops the MCP/HTTP servers).

## Before you start

1. Build the CLI/desktop app (see the repo [README](../README.md)).
2. Find your binary path:
   - **macOS / Linux:** `</abs/path>/target/release/sovereign-vault`
   - **Windows:** `<abs\path>\target\release\sovereign-vault.exe`
3. In every sample below, replace `/ABSOLUTE/PATH/TO/sovereign-vault` with your
   real repo path (or put the binary on your `PATH` and use the bare name
   `sovereign-vault`).

## Files

| File | Client | Where it goes |
|---|---|---|
| `claude_desktop_config.json` | Claude Desktop | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json` · Windows: `%APPDATA%\Claude\claude_desktop_config.json` |
| `cursor-mcp.json` | Cursor | `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per-project) |
| `continue-config.json` | Continue.dev | merge `mcpServers` into `~/.continue/config.json` |
| `end-to-end.sh` | any | a self-contained shell script that drives the proxy end to end with **fake** secrets |

> The desktop app's **Settings → MCP** page also has one-click "Copy config"
> buttons that emit these same snippets with your real binary path filled in.

## Try it

```bash
# Vault unlocked, from the repo root:
./examples/end-to-end.sh
```

This creates a throwaway DIRECT container, writes a fake `.env`, reads it back,
and confirms an exact round-trip — never touching real credentials.
