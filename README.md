---
license: mit
tags:
  - agent-security
  - ai-governance
  - sandboxing
  - devsecops
pretty_name: Adaptive Runtime Security Platform for Autonomous Agents (v7.2)
---

# Adaptive Runtime Security Platform for Autonomous Agents (v7.2)

A production-ready, drop-in governance layer for AI coding agents (Claude Code, Cursor, Aider).
v7.2 closes out the 4 major + 3 minor issues found in the v7.1 external review.

## Changelog: v7.1 → v7.2

| # | Issue | Severity | Fix |
| --- | --- | --- | --- |
| 1 | Session UUID collision (`date +%s` granularity) | High | Switched to `uuid.uuid4()` for guaranteed-unique session IDs |
| 2 | Historical velocity always returned 0 (queried by unique `session_id`) | **Critical** | Track a stable `repo_id` (derived from git remote) and query history by repo, not session |
| 3 | Pre-score stored in fragile `/tmp/pre_score_*.txt` files | Medium-High | Moved to a `session_state` SQLite table (WAL mode), no stale files or partial writes |
| 4 | Container had RW access to the real repo + `.git` | High | Repo now mounts **read-only**; agent works in a tmpfs copy; only a scoped patch file crosses back to the host, applied only after JRI evaluation |
| 5 | Semgrep spawned one process per changed file | Minor | Batched into a single `semgrep ... file1 file2 file3 --json` invocation |
| 6 | CI only passed changed filenames into the prompt scorer | Minor | CI now passes actual patch content (truncated) for real prompt-injection scoring |
| 7 | `refactor_heavy` profile branch was unreachable dead code | Minor | Added a `refactor_heavy` profile to config + prompt-intent detection so the branch is now reachable |

## What's Included

| File | Purpose |
| --- | --- |
| `core_engine.py` | Risk Fusion, Normalization & Policy Engine (JRI calculation) |
| `config/security_profiles.json` | Context-aware weight profiles: `default`, `security_sensitive`, `refactor_heavy` |
| `config/rules.semgrep.yml` | AST-aware semantic diff rules |
| `scripts/secure-agent-orchestrator.sh` | Phase-driven execution wrapper — RO repo mount / RW tmpfs overlay / patch export |
| `.github/workflows/agent-governance.yml` | Remote CI pipeline arbiter |

## Isolation Model (v7.2)

```
Host repo (read-only mount) ──► Container tmpfs copy (agent works here)
                                        │
                                        ▼
                              git diff → /patches/session.patch
                                        │
                    (only this narrow RW mount crosses back)
                                        ▼
                Host: git apply --check → git apply → JRI evaluation
```

The agent can never touch host git refs, history, or objects directly — it only ever
produces a patch, and that patch is applied on the host **after** the container is
already destroyed, then scored before it's allowed to land.

## Quick Setup

```bash
chmod +x scripts/secure-agent-orchestrator.sh
./scripts/secure-agent-orchestrator.sh aider "your prompt here"
```

## Risk Thresholds

| Profile | Warn | Quarantine | Block & Isolate |
| --- | --- | --- | --- |
| `default` | 35 | 65 | 85 |
| `security_sensitive` | 25 | 50 | 75 |
| `refactor_heavy` | 45 | 75 | 90 |

## Human Override

```bash
ALLOW_CORE_CHANGES=true git commit -m "Architect manual override: update core types"
```

Published by [@Sahek](https://huggingface.co/Sahek).
