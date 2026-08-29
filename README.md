# Adaptive Runtime Security Platform for Autonomous Agents (v8.0)

[![CI](https://github.com/kaymyg/lean-agent-governance/actions/workflows/ci.yml/badge.svg)](https://github.com/kaymyg/lean-agent-governance/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-5%20passing-brightgreen)](tests/)

A production-ready, drop-in governance layer for AI coding agents (Claude Code, Cursor, Aider).

It combines sandbox isolation, runtime telemetry, and weighted risk scoring to **contain**
prompt injection and malicious agent behavior before changes reach the host repository.
This is a defense-in-depth control, not a guarantee against all prompt injection — see
"Scope & Limitations" below.

## Changelog: v7.2 → v8.0

| # | Issue | Severity | Fix |
| --- | --- | --- | --- |
| 1 | `cp -r` into tmpfs was slow/memory-heavy on monorepos (node_modules, build artifacts) | Medium | Sandbox now copies only git-tracked files via `git archive \| tar -x`, skipping ignored directories entirely |
| 2 | No cap on patch size before the host tried to `git apply` it | High | Patch size checked against `max_patch_size_bytes` (default 5MB) *before* any apply attempt; oversized patches are rejected outright |
| 3 | Prompt-injection regex could be bypassed by zero-width characters, bidi overrides, or whitespace fragmentation | Medium (partial mitigation) | Strip zero-width/bidi-override characters and collapse whitespace before pattern matching; messaging updated to accurately describe this as heuristic detection, not semantic analysis |
| 4 | No timeout — a hung agent process could hold the sandbox open indefinitely | High | `timeout` wraps the full container run, killed and treated as a failed session if it exceeds `agent_runtime_timeout_seconds` (default 900s) |
| 5 | `session_history` / `session_state` grew unbounded | Low-Medium | Auto-prune on every engine init, controlled by `history_retention_days` (default 30) |
| 6 | If a patch failed to apply on the host, container-side activity was scored as zero — evidence lost | Medium (partial mitigation) | Orchestrator exports a small telemetry file (modified file count, apply-failure flag) that the engine folds into behavioral scoring even when the patch itself is rejected |

## Scope & Limitations

Be precise about what this does and doesn't do:

- **Does**: sandbox agent execution (network-isolated, read-only host repo, resource-capped, timeout-enforced), detect common prompt-injection payloads and override signatures, cap the blast radius of any single agent session, and score risk across multiple independent signals before anything lands in the real repo.
- **Does not**: perform semantic/LLM-based prompt analysis. Regex + normalization catches known attack patterns (override phrases, base64-encoded payloads, zero-width smuggling) but a sufficiently novel injection technique can still get through the pre-runtime gate. Treat the runtime sandbox and post-runtime scoring as your primary defenses, and pre-runtime prompt scanning as an early tripwire, not a guarantee.

## What's Included

| File | Purpose |
| --- | --- |
| `core_engine.py` | Risk Fusion, Normalization & Policy Engine (JRI calculation) |
| `config/security_profiles.json` | Context-aware weight profiles + system tunables (patch size cap, runtime timeout, retention) |
| `config/rules.semgrep.yml` | AST-aware semantic diff rules |
| `scripts/secure-agent-orchestrator.sh` | Phase-driven execution wrapper — RO repo mount / RW tmpfs overlay / patch export / timeout enforcement |
| `.github/workflows/agent-governance.yml` | Remote CI pipeline arbiter |

> `scripts/run-agent.sh` also exists in this repo but is **deprecated** — it
> predates the isolation model above (RW `.git` mount, no risk-scoring gate,
> no size/timeout limits) and is kept only for migration history. See the
> warning at the top of that file. Use `secure-agent-orchestrator.sh`.

## Isolation Model

```
Host repo (read-only mount) ──► Container tmpfs copy (git-tracked files only)
                                        │
                                timeout-bounded agent run
                                        │
                                        ▼
                      git diff --cached → /patches/session.patch
                      + modified_files.txt + telemetry.json
                                        │
                    (only this narrow RW mount crosses back)
                                        ▼
        Host: patch size check → git apply --check → git apply → JRI evaluation
```

## Quick Setup

```bash
chmod +x scripts/secure-agent-orchestrator.sh
./scripts/secure-agent-orchestrator.sh aider "your prompt here"
```

`core_engine.py` has zero third-party runtime dependencies — it's Python
standard library only (`sqlite3`, `subprocess`, `re`, `hashlib`, etc.).
Running the test suite needs `pytest` (see `requirements-dev.txt`):

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## System Tunables (`config/security_profiles.json`)

| Setting | Default | Purpose |
| --- | --- | --- |
| `max_patch_size_bytes` | 5242880 (5MB) | Reject oversized patches before host `git apply` ever sees them |
| `agent_runtime_timeout_seconds` | 900 | Kill hung containers instead of letting them run indefinitely |
| `history_retention_days` | 30 | Prune old `session_history` / `session_state` rows automatically |

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

---

## Known limitations worth fixing

Being transparent about the current gaps, since this is exactly the kind of
thing a security-governance project should surface rather than bury:

- `core_engine.py` is 379 lines against the project's own 350-line hard cap
  (see `.github/workflows/agent-governance.yml`) — the codebase currently
  fails its own governance rule. It's grandfathered in (CI only fails on
  *growth* past the cap, not pre-existing size), but splitting it into
  smaller modules is a good, concrete first contribution.
- Test coverage is currently limited to the pre-runtime prompt scanner
  (`tests/test_core_engine.py`). The `post` mode — JRI fusion, the
  quarantine/block-and-isolate git branching logic, historical velocity
  decay — has no automated test coverage yet.

## Contributing

Bug reports, new prompt-injection test cases, and PRs are welcome — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for setup and what CI checks.

## Security

Found a way to get a malicious payload past the pre-runtime scanner, or
otherwise defeat the risk scoring? Please see [`SECURITY.md`](SECURITY.md)
for how to report it responsibly rather than opening a public issue.

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

---

Published by [@Sahek](https://huggingface.co/Sahek).
