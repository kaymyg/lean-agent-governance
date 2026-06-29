---
title: Ultra-Lean Agent Governance Framework v4
emoji: 🔒
colorFrom: gray
colorTo: blue
sdk: static
pinned: true
---

# Ultra-Lean Agent Governance Framework (v4)

A production-ready, drop-in governance layer for AI coding agents (Claude Code, Cursor, Aider).  
Copy the files into any repository to establish sandbox enforcement, boundary rules, and CI pipeline checkpoints.

## What's Included

| File | Purpose |
|------|---------|
| `CLAUDE.md` | Input firewall for Claude Code |
| `.cursorrules` | Input firewall for Cursor Agent |
| `.aiderignore` | Vision barrier for Aider |
| `.claude/settings.json` | Execution guard — banned/allowed bash operations |
| `scripts/run-agent.sh` | Docker sandbox — network, memory, and secret isolation |
| `hooks/pre-commit` | Local gatekeeper — diff volume + core architecture protection |
| `.github/workflows/agent-governance.yml` | Remote CI validator — authoritative PR audit |

> **Note:** `hooks/pre-commit` should be copied to `.git/hooks/pre-commit` in your repo and made executable with `chmod +x .git/hooks/pre-commit`.

## Defense Layers

| Layer | Mechanism | What It Stops |
|-------|-----------|---------------|
| **Input Firewall** | `.cursorrules` / `CLAUDE.md` | Prompt injection, architectural drift |
| **Execution Guard** | `.claude/settings.json` + Docker | Fork bombs, disk abuse, subshell escapes |
| **Network Guard** | `--network none` in Docker | `curl\|bash` downloads, data exfiltration |
| **Secret Guard** | Null bind mounts | `.env` / SSH key exposure to model context |
| **Local Gatekeeper** | Pre-commit hook | Bad agent refactors sneaking into commits |
| **Remote Validator** | GitHub Actions | Hook bypass via `--no-verify` |

## Quick Setup

```bash
# 1. Copy all files into your repo root
# 2. Make scripts executable
chmod +x scripts/run-agent.sh
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# 3. Run an agent session inside the sandbox
./scripts/run-agent.sh claude   # or aider
```

## Human Override

The pre-commit hook and CI both support an explicit architect override:

```bash
ALLOW_CORE_CHANGES=true git commit -m "Architect manual override: update core types"
```

---

Published by [@sahek](https://huggingface.co/sahek).
