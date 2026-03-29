---
name: discovery
description: Discovery-first assessment objective focused on maximizing coverage and validating impactful vulnerabilities before patching
---

# Discovery Objective

Primary goal: discover, validate, and report real security issues with strong evidence before spending iterations on fixes.

## Operating Priorities

- Maximize high-value attack-surface coverage first
- Prefer finding the next serious bug over patching the first one
- Preserve momentum on reconnaissance, privilege boundary testing, race windows, and bug chaining
- Report validated findings before proposing or implementing fixes

## Remediation Boundaries

- Do not patch early just because a bug was found
- Only move into remediation after reporting is complete and coverage is in a good state
- If you do fix something late in the run, keep it tightly scoped and verify the fix does not hide remaining bugs

## Tooling Implications

- Use the coverage ledger aggressively to avoid blind spots
- Use role-matrix and race testing on sensitive, state-changing, or multi-tenant flows
- Extend the auto-seeded coverage inventory whenever runtime discovery reveals more surface area
