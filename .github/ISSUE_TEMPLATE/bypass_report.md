---
name: Bypass report (non-sensitive)
about: A payload that should be caught but isn't, and it's safe to discuss publicly
title: "[Bypass] "
labels: bypass
---

> If this is a working bypass you'd rather not publish before there's a
> fix, please use private vulnerability reporting instead (Security tab →
> "Report a vulnerability") per [SECURITY.md](../../SECURITY.md).

Use this template for bypasses you're comfortable discussing openly, or
that overlap with an already-documented limitation (see the README's
"Scope & Limitations" section) and you just want to confirm/discuss.

**Payload**
The prompt, patch, or input that should score above `0` (or trigger
`QUARANTINE`/`BLOCK & ISOLATE`) but doesn't.

**Actual vs. expected**
```
pre-scan score=<actual>   (expected: >0)
```
or the JRI report / exit code if it's a `post`-mode issue.

**Which risk signal should have caught it?**
prompt / behavior / diff / secret / dependency / historical

**Is this close to an existing test case?**
Reference `tests/test_core_engine.py` if this is a variant of an existing
regression test (zero-width, base64, plaintext override, etc).
