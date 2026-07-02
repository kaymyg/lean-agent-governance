---
license: mit
tags:
  - agent-security
  - ai-governance
  - sandboxing
  - devsecops
pretty_name: Adaptive Runtime Security Platform for Autonomous Agents (v7.1)
---

# Adaptive Runtime Security Platform for Autonomous Agents (v7.1 Release Candidate)

A production-ready, drop-in governance layer for AI coding agents (Claude Code, Cursor, Aider).
This is the v7.1 upgrade to the Ultra-Lean Agent Governance Framework (v4) — replacing the static
binary-decision checks in v4 with a weighted, multi-signal **Judgement Risk Index (JRI)** engine.

Copy the files into any repository to establish sandbox enforcement, boundary rules, weighted risk
scoring, and CI pipeline checkpoints.

## What's New in v7.1 (vs v4)

| v4 | v7.1 |
| --- | --- |
| Static allow/deny rules per file | Weighted risk fusion across 6 signal types (prompt, behavior, diff, secret, dependency, historical) |
| Single global policy | Context-aware profiles (`default`, `security_sensitive`) with different weights/thresholds |
| Pre-commit hook only | Split-phase lifecycle: Phase A (pre-runtime prompt scan) → Phase B (sandboxed execution) → Phase C (post-runtime scoring) |
| No memory across sessions | SQLite WAL-mode historical velocity tracking with exponential decay |
| Pattern-matching diff checks | AST-aware Semgrep rules for structural violations (shell injection, `eval`, `exec`) |
| Manual quarantine | Automatic quarantine branch isolation with salted branch names |

## What's Included

| File | Purpose |
| --- | --- |
| `core_engine.py` | The Risk Fusion, Normalization & Policy Engine (JRI calculation) |
| `config/security_profiles.json` | System configuration & context-aware weight profiles |
| `config/rules.semgrep.yml` | Layer 3: AST-aware semantic diff rules |
| `scripts/secure-agent-orchestrator.sh` | Phase-driven execution wrapper (Docker sandbox) |
| `.github/workflows/agent-governance.yml` | Over-the-wire remote CI pipeline arbiter |

## Defense Layers

| Layer | Mechanism | What It Stops |
| --- | --- | --- |
| Pre-Runtime Gateway | `core_engine.py::pre_runtime_scan` | Prompt injection, override signatures, obfuscated (base64) payloads |
| Execution Guard | `--network none`, `--cap-drop ALL`, `--read-only` Docker sandbox | Fork bombs, data exfiltration, subshell escapes |
| Secret Guard | Trufflehog scan + null bind mount on `.env` | Credential/secret leakage into model context |
| Diff/AST Guard | Semgrep structural rules | Shell injection, `eval`/`exec`, backdoors disguised as refactors |
| Historical Memory | SQLite WAL + exponential decay | Slow-creep attacks spread across multiple commits |
| Policy Routing | Weighted JRI + quarantine branches | False-positive-safe isolation of flagged changes |

## Quick Setup

```bash
# 1. Copy all files into your repo root
# 2. Make scripts executable
chmod +x scripts/secure-agent-orchestrator.sh

# 3. Run an agent session inside the sandbox
./scripts/secure-agent-orchestrator.sh aider "your prompt here"
```

## Risk Thresholds (default profile)

- **JRI ≤ 35** → Allow
- **35 < JRI ≤ 65** → Warn (human override required)
- **65 < JRI ≤ 85** → Quarantine (auto-stash)
- **JRI > 85** → Block & isolate to `quarantine/session_<id>_<salt>` branch

`security_sensitive` profile (triggered by auth/crypto/token keywords in the prompt) uses tighter
thresholds (25 / 50 / 75).

## Human Override

```bash
ALLOW_CORE_CHANGES=true git commit -m "Architect manual override: update core types"
```

Published by [@Sahek](https://huggingface.co/Sahek).
