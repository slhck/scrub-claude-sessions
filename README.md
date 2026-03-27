# scrub-claude-sessions

Scan and redact secrets from Claude Code session logs using [gitleaks](https://github.com/gitleaks/gitleaks).

Claude Code stores conversation data in `~/.claude/` that can contain API keys, tokens, passwords, and other secrets that were part of your sessions. This script detects and redacts them in-place.

## Scanned locations

- `~/.claude/projects/` — session JSONL files (bulk of data)
- `~/.claude/debug/` — debug logs
- `~/.claude/tasks/` — task JSON files
- `~/.claude/history.jsonl` — prompt history

## Requirements

- [gitleaks](https://github.com/gitleaks/gitleaks) (`brew install gitleaks`)
- [uv](https://docs.astral.sh/uv/) (Python dependencies are managed inline via PEP 723), or Python with `tqdm` installed (`pip install tqdm`)

## Usage

```bash
# Scan only (dry run)
./scrub-claude-sessions.py

# Redact secrets in-place
./scrub-claude-sessions.py --redact

# Delete session files older than 14 days
./scrub-claude-sessions.py --delete 14

# Save JSON report to ~/Desktop/
./scrub-claude-sessions.py --report

# Scan only specific targets
./scrub-claude-sessions.py --type projects
./scrub-claude-sessions.py --type debug --type history

# Control parallelism
./scrub-claude-sessions.py -j 8

# Combine: delete old files, then redact remaining
./scrub-claude-sessions.py --delete 30 --redact
```

Valid `--type` values: `projects`, `debug`, `tasks`, `history`. Multiple `--type` flags can be combined. Defaults to all.

## How it works

The script runs gitleaks against each scan target in parallel (using Python multiprocessing), collecting findings into a merged report. Detected secrets are replaced with `[REDACTED-<rule-id>]` markers (e.g. `[REDACTED-generic-api-key]`).

Gitleaks provides 100+ detection rules covering AWS keys, GitHub/GitLab tokens, Slack tokens, JWTs, private keys, generic API keys, credentials in URLs, and more. See the [gitleaks default config](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml) for the full list.

## Limitations

- Secrets using custom or proprietary formats may not be detected
- Some false positives are possible (high-entropy strings, UUIDs)
- Scan time depends on log volume; use `-j` to increase parallelism

## License

Copyright (c) 2026 Werner Robitza.

This project is licensed under the MIT License. See the [LICENSE](LICENSE.md) file for details.
