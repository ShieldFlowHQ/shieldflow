# Contributing to ShieldFlow

[![Tests](https://img.shields.io/badge/tests-492%20%2F%2084%20adversarial-green)](tests/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

Thanks for your interest in contributing! ShieldFlow is an open-source project built entirely by AI agents, and we welcome contributions from humans and AI assistants alike.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/shieldflow.git`
3. Create a virtual environment: `python -m venv .venv && source .venv/bin/activate`
4. Install dev dependencies (recommended): `uv sync --extra dev`
   - If your venv does not include `pip`, bootstrap it first:
     `python -m ensurepip --upgrade && python -m pip install -e ".[dev]"`
5. Run tests: `pytest`
6. Create a branch: `git checkout -b my-feature`

## Development

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=shieldflow

# Specific test file
pytest tests/unit/test_trust.py

# Red team tests (injection scenarios)
pytest tests/red-team/
```

### Code Style

We use `ruff` for linting and formatting:

```bash
ruff check .
ruff format .
```

### Type Checking

```bash
mypy src/shieldflow
```

## What to Contribute

### Good First Issues

Looking for a way to get started? Check out issues labeled [`good first issue`](https://github.com/ShieldFlowHQ/shieldflow/labels/good%20first%20issue):

- Add property-based fuzz tests for the sanitiser pipeline
- Add integration tests for CLI entry points
- Write integration guide for LangChain

### High-Impact Areas

- **Injection patterns**: Add new prompt injection patterns to `validator.py`. Real-world examples are especially valuable.
- **Data classification patterns**: Add patterns for detecting sensitive data types.
- **Red team tests**: Write test cases that try to bypass the trust layer. If you find a bypass, that's a valuable contribution!
- **Documentation**: Improve docs, add examples, fix typos.
- **Integration guides**: Write guides for integrating with specific frameworks.

### Pull Request Process

1. Ensure all tests pass
2. Add tests for new functionality
3. Update documentation if needed
4. Keep PRs focused — one feature/fix per PR
5. Write a clear PR description explaining what and why

### Security Vulnerabilities

If you discover a security vulnerability, **do not open a public issue**. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Keeper Bot Quick Guide (Labels + Workflows)

Keeper helps us triage without turning the repo into notification soup.

- **Labels live in** `.github/labels.yml` and use prefixes (`type/*`, `area/*`, `status/*`, `priority/*`).
- **Auto-triage workflow**: `.github/workflows/keeper-triage.yml` adds `status/needs-triage` plus best-guess `type/*` and `area/*` labels on new/reopened issues.
- **Stale workflow**: `.github/workflows/keeper-stale.yml` runs weekly and marks/cleans up inactive issues/PRs.
- **Weekly digest**: `.github/workflows/keeper-weekly-digest.yml` posts a backlog snapshot issue for maintainers.

If you change label names, update both `labels.yml` and any workflow references in the same PR so Keeper doesn’t get confused and start wearing mismatched socks.

## Code of Conduct

Be kind. Be constructive. We're all here to make AI agents safer.
