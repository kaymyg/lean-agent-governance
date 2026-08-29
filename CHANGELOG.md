# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers follow the project's own versioning as used in the README
(e.g. "Changelog: v7.2 → v8.0").

## [8.0.0] - 2026-07-28

First tagged release. Includes the v7.1 → v8.0 history below plus:

### Added
- LICENSE (MIT) — previously only claimed in prose/frontmatter, no license
  file actually existed.
- `requirements-dev.txt` for test dependencies (`core_engine.py` itself has
  zero third-party runtime dependencies).
- CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, issue/PR templates,
  Dependabot.
- CI (`ci.yml`): install and `pytest -q` on every push/PR.

### Fixed
- Stripped Hugging Face Hub YAML frontmatter from README (GitHub renders it
  literally instead of hiding it).
- README install/dependency instructions now match reality (previously
  referenced `pip install pytest` without a requirements file; CI now
  installs from `requirements-dev.txt`).
- `scripts/run-agent.sh` clearly marked deprecated — it predates the
  read-only-host isolation model this project documents (RW `.git` mount, no
  risk-scoring gate, no size/timeout limits, references a nonexistent
  `coder-agent-image:latest`) and was previously undocumented as such.

### Known limitations (tracked, not yet fixed)
- `core_engine.py` is 379 lines against this project's own 350-line
  governance cap (grandfathered in — CI only fails on further growth).
- `post`-mode (JRI fusion, quarantine/block-and-isolate flow) has no
  automated test coverage yet; only pre-runtime prompt scanning is tested.

## [7.2] - 2026-07-02 → [8.0] - 2026-07-25

See the "Changelog: v7.2 → v8.0" table in the README for the full,
itemized list. Summary:
- Sandbox now copies only git-tracked files (`git archive | tar -x`)
  instead of `cp -r`, avoiding slow/memory-heavy copies on monorepos.
- Patch size checked against `max_patch_size_bytes` (5MB default) before
  any `git apply` attempt.
- Prompt-injection detection normalizes zero-width/bidi-override characters
  and collapses whitespace before pattern matching, closing a bypass class;
  messaging updated to describe this accurately as heuristic detection.
- Full sandbox run wrapped in `timeout`, killed and treated as failed if it
  exceeds `agent_runtime_timeout_seconds` (900s default).
- `session_history`/`session_state` now auto-prune based on
  `history_retention_days` (30 default) instead of growing unbounded.
- Orchestrator exports telemetry (modified file count, apply-failure flag)
  so behavioral scoring isn't zeroed out when a patch fails to apply.
- Fixed historical velocity tracking to key on `repo_id`, session UUID
  collisions, read-only repo mount, SQLite pre-score storage, batched
  semgrep execution, and real CI patch content.
- Fixed a base64 case-sensitivity bug where lowercasing before decoding
  made every encoded injection payload decode to garbage and score 0.
- Fixed an orchestrator crash and an exit-code truncation bug (`sys.exit(403)`
  was reported by the OS as 147, since exit statuses wrap mod 256).

## [7.1] - 2026-07-02

### Added
- Weighted JRI (Joint Risk Index) fusion engine across six signals: prompt,
  behavior, diff, secret, dependency, historical.
- Context profiles (`default`, `security_sensitive`, `refactor_heavy`) with
  independent weights and thresholds.
- Semgrep AST layer for structural diff risk.
- Historical decay tracking (exponential half-life on repeated risky
  behavior from the same repo).

## Earlier

Initial reference implementation, `.claude/settings.json`, `.cursorrules`,
`.aiderignore`, the pre-commit hook, and the original CI workflow.
