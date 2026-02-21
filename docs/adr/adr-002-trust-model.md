# ADR-002: Trust Model

Date: 2026-02-21

## Status
Accepted

## Context
ShieldFlow needs to determine what actions a request can perform based on its trust level.

## Decision
We use a 5-level trust hierarchy:
1. **owner** - Full trust, all actions allowed
2. **system** - High trust, most actions allowed
3. **agent** - Medium trust, tool execution allowed with validation
4. **user** - Limited trust, basic actions allowed
5. **none** - No trust, only read-only operations

Each action has a minimum required trust level. Actions with `never_auto: true` always require explicit user confirmation.

## Consequences
- Positive: Clear, simple model
- Positive: Easy to understand and configure
- Negative: May be too coarse-grained for complex scenarios

## Alternatives Considered
- Continuous trust scores: Rejected - too complex to configure
- Role-based access: Deferred - can be added later
