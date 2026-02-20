# Maintainers Guide: Triage + Keeper Operations

Welcome, maintainers. This is the practical playbook for keeping ShieldFlow issues healthy, contributors unblocked, and chaos goblins under control.

## 1) Triage Process

Use this flow for every new issue:

1. **Confirm scope**
   - Is this about ShieldFlow behavior, docs, examples, CI, or SDK usage?
   - If it is a security vulnerability report, redirect to `SECURITY.md` (no public details).

2. **Validate reproducibility**
   - Ask for minimal repro steps if details are incomplete.
   - Add `status/needs-info` when required context is missing.

3. **Apply labels**
   - Keeper auto-applies initial labels, but humans should correct anything off.
   - Ensure one clear `type/*` + one primary `area/*` where possible.

4. **Prioritize and route**
   - Add `priority/high` for urgent security/production-impacting issues.
   - Add `status/blocked` if the issue is waiting on external context/dependency.

5. **Close the loop**
   - Acknowledge next step (investigate, PR welcome, planned, not planned).
   - Keep tone direct, friendly, and specific.

## 2) Label Conventions

Labels are defined in `.github/labels.yml`.

### Type labels (`type/*`)
- `type/bug` — broken behavior
- `type/feature` — feature request / enhancement
- `type/chore` — maintenance / automation work

### Area labels (`area/*`)
- `area/security`
- `area/core`
- `area/sdk`
- `area/docs`
- `area/examples`
- `area/ci`

### Status labels (`status/*`)
- `status/needs-triage` — new items awaiting maintainer pass
- `status/needs-info` — waiting on reporter details
- `status/blocked` — cannot proceed yet
- `status/stale` — inactive, pending auto-close

### Priority labels (`priority/*`)
- `priority/high` — should be pulled forward quickly

## 3) Stale Policy

Keeper stale sweep workflow: `.github/workflows/keeper-stale.yml`

Current policy:
- Mark item stale after **30 days** inactive.
- Close stale item after **7 more days** inactive.
- Exempt when labeled `status/blocked` or `priority/high`.
- Automatically remove stale label if activity resumes.

Maintainer guidance:
- Before major releases, skim stale queue for items that should remain open.
- If an issue has strategic value, remove `status/stale` and add context.
- Don’t use stale closure for active design discussions.

## 4) Weekly Digest Process

Digest workflow: `.github/workflows/keeper-weekly-digest.yml`

Every Monday, Keeper posts (or updates) a "Keeper Weekly Digest" issue with:
- open issue count
- open PR count
- needs-triage count

Maintainer checklist for the digest:
1. Review `status/needs-triage` issues first.
2. Resolve or re-route `status/blocked` items.
3. Pull forward `priority/high` work.
4. Link notable updates in the digest thread for contributor visibility.

## 5) Release Process

### Publishing to PyPI

ShieldFlow is automatically published to PyPI when a version tag is pushed. The workflow is defined in `.github/workflows/ci.yml`.

**Trigger:** Push a tag matching `v*` (e.g., `v1.2.3`)

**Required secrets:**
- `PYPI_API_TOKEN` — Set this in your GitHub repository secrets. Create a token at https://pypi.org/manage/account/token/ with "Upload" scope for the `shieldflow` project.

**Steps to release:**
```bash
# Bump version in pyproject.toml first
git commit -m "release: bump version to v1.2.3"
git tag v1.2.3
git push origin v1.2.3
```

The CI will run tests and security checks, then publish to PyPI on success.

## Keeper Workflow Safety Notes

To avoid automation spam loops:
- Keeper comments use hidden markers and update existing comments/issues when possible.
- Triage workflow listens only to `issues` `opened/edited/reopened` (not label/comment events).
- Weekly digest runs on schedule/manual dispatch, then creates a single canonical digest issue per week.
- Stale handling is schedule/manual only.

If you modify Keeper workflows, sanity-check trigger/event combinations before merging.
