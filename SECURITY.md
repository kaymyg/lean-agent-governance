# Security Policy

## Scope

This is a defense-in-depth control against malicious or runaway AI coding
agents, not a guarantee against all prompt injection — the README's "Scope &
Limitations" section is explicit about this, and reports that boil down to
"a sufficiently novel injection technique got past the regex-based
pre-runtime scanner" are expected and already documented as a known
limitation, not a new finding.

What **is** a genuine finding here:

- A prompt-injection or override payload that scores `0` (undetected) when
  it should score above `0` — especially anything in the style of the
  existing regression tests (zero-width smuggling, base64 encoding, bidi
  overrides)
- A patch that exceeds `max_patch_size_bytes` but still reaches `git apply`
  on the host
- A way for the sandboxed container to reach host secrets, the network, or
  files outside its read-only mount / tmpfs overlay
- A way for a session to bypass `agent_runtime_timeout_seconds` and hold the
  sandbox open indefinitely
- A way for `verify_clean_secrets()` or the Semgrep AST layer to be defeated
  by disguising what they check for (not just "no rule exists for X yet" —
  that's a feature request, not a vulnerability)
- A JRI computation or threshold bug that causes a session that should
  `QUARANTINE` or `BLOCK & ISOLATE` to `ALLOW` instead

## Reporting

Please **do not** open a public GitHub issue for a working bypass — that
publishes the technique before there's a fix.

Instead, use GitHub's private vulnerability reporting for this repository
(Security tab → "Report a vulnerability"). Please include:

- The exact prompt, patch, or payload that bypasses detection
- Expected vs. actual JRI score / exit code
- Which of the six risk signals (prompt, behavior, diff, secret, dependency,
  historical) should have caught it

New detection patterns that don't rely on a secret technique (e.g. "here's
a whole class of Unicode normalization tricks the current regex misses") are
fine as a regular issue or PR with a regression test, same as the existing
base64/zero-width fixes in the commit history.

## Response expectations

Independent project — best-effort response, not a guaranteed SLA. Genuine
bypasses will be prioritized and credited (with permission) once fixed.
