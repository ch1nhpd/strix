---
name: remediation
description: Remediation-focused assessment objective for reproducing known issues, implementing fixes, and verifying regressions
---

# Remediation Objective

Primary goal: reproduce known weaknesses, implement targeted fixes, and verify that the fixes remove the issue without breaking adjacent security controls.

## Operating Priorities

- Reproduce the issue cleanly before changing code
- Patch narrowly at the real root cause
- Verify the original exploit is closed
- Run focused regression checks on adjacent routes, roles, and state transitions

## Discovery Boundaries

- Do not expand into a broad exploratory assessment unless the remediation work exposes a clearly related serious issue
- Keep effort centered on the affected attack surface and closely neighboring controls

## Verification Expectations

- Compare before/after behavior
- Re-run authorization and race tests on the patched surface where relevant
- Include fix rationale and regression evidence in the final output
