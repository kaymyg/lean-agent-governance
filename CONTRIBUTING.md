# Contributing to the Adaptive Runtime Security Platform

Thanks for your interest. This project's whole job is catching malicious or
runaway agent behavior before it reaches a real repo, so contributions that
close detection gaps or add regression tests for real bypass techniques are
especially valuable.

## Getting set up

```bash
git clone https://github.com/kaymyg/lean-agent-governance.git
cd lean-agent-governance
pip install -r requirements-dev.txt
python -m pytest -q     # 5 tests
```

`core_engine.py` itself needs nothing beyond the Python standard library —
`requirements-dev.txt` is only for running the test suite.

## Before opening a PR

CI runs `python -m pytest -q` on every push and PR (note the `-m`: it's
what puts the repo root on `sys.path` so `tests/` can import the top-level
modules — bare `pytest` can't). Please run that locally first.

If you're touching the diff-size/file-size governance rules, also be aware
this repo enforces its own line caps on itself via
`.github/workflows/agent-governance.yml` — a file already over the 350-line
hard cap only fails CI if your change makes it *grow*, not for pre-existing
size (see the comment in that workflow for why: the rule used to block the
only kind of PR that could ever fix it).

## What especially matters here

- **New evasion techniques belong as new tests**, in the style of
  `tests/test_core_engine.py`'s existing regression tests (each one names
  the specific bypass it closes — zero-width smuggling, base64 case
  sensitivity, etc.). A prose description of a bypass without a
  reproducing test is much less useful than the test itself.
- **Don't weaken `verify_clean_secrets`, patch size caps, or runtime
  timeouts** without justifying it in the PR — those are the actual
  blast-radius controls, not tuning knobs.
- **`scripts/run-agent.sh` is deprecated.** Don't build on it or reference
  it as current — it predates the read-only-host isolation model and
  doesn't have any of the guarantees `secure-agent-orchestrator.sh` has.
  If anything, it's a candidate for deletion once nothing points to it.

## Good places to start

- Splitting `core_engine.py` (currently 379 lines, over this project's own
  350-line governance cap — see "Known limitations" in the README)
- Test coverage for `post` mode: JRI fusion, quarantine branch creation,
  block-and-isolate flow — currently untested
- A real Semgrep ruleset behind `config/rules.semgrep.yml` — it currently
  has one rule (dynamic shell execution patterns); more AST-level risk
  patterns would meaningfully improve the diff-risk signal
- Removing or clearly archiving `scripts/run-agent.sh` once you've confirmed
  nothing depends on it

For anything larger, please open an issue first to discuss the approach.

## Commit style

Small, focused commits with a clear one-line summary. No strict format
enforced beyond that.
