## What does this change do?

<!-- Brief description -->

## Checklist

- [ ] `python -m pytest -q` passes (5 tests)
- [ ] New detection/bypass fix includes a regression test in
      `tests/test_core_engine.py`, in the style of the existing ones
- [ ] `verify_clean_secrets`, patch size caps, or runtime timeouts are not
      weakened without justification in this PR
- [ ] If this touches `scripts/`, `scripts/run-agent.sh` (deprecated) is not
      referenced as current — see the warning at the top of that file
- [ ] Updated README if this changes behavior, thresholds, or file layout

## Related issue

<!-- Closes #123, if applicable -->
