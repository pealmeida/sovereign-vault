# Agent command packs

Canonical command definitions for `/sovereign-vault` live in
`sovereign-vault.commands.yaml`.

Render or install a target-specific pack with the CLI:

```bash
sovereign-vault agents list-targets
sovereign-vault agents print --target claude-code
sovereign-vault agents install --target claude-code
sovereign-vault agents install --target codex --force
```

Supported targets:

- `claude-code`
- `opencode`
- `hermes`
- `codex`
- `generic`

The CLI writes each target to its default path unless `--dir` is supplied.
