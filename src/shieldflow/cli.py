"""ShieldFlow CLI."""

import click


@click.group()
@click.version_option()
def main() -> None:
    """ShieldFlow — Cryptographic trust boundaries for AI agents."""
    pass


@main.command()
@click.option("--port", default=8080, help="Port to listen on")
@click.option("--target", default="openai", help="Target LLM provider (openai, anthropic)")
@click.option("--config", default="shieldflow.yaml", help="Config file path")
def proxy(port: int, target: str, config: str) -> None:
    """Start ShieldFlow as an LLM proxy."""
    click.echo(f"🛡️ ShieldFlow proxy starting on port {port}")
    click.echo(f"   Target: {target}")
    click.echo(f"   Config: {config}")
    click.echo("   Status: Not yet implemented — coming soon!")


@main.command()
@click.option("--config", default="shieldflow.yaml", help="Config file path")
def validate(config: str) -> None:
    """Validate a ShieldFlow configuration file."""
    from pathlib import Path

    config_path = Path(config)
    if not config_path.exists():
        click.echo(f"❌ Config file not found: {config}")
        raise SystemExit(1)

    try:
        from shieldflow import ShieldFlow

        ShieldFlow(config=config)
        click.echo(f"✅ Config is valid: {config}")
    except Exception as e:
        click.echo(f"❌ Config error: {e}")
        raise SystemExit(1)


@main.command()
def init() -> None:
    """Create a default shieldflow.yaml config file."""
    from pathlib import Path

    config_path = Path("shieldflow.yaml")
    if config_path.exists():
        click.echo("⚠️  shieldflow.yaml already exists. Use --force to overwrite.")
        return

    default_config = """\
# ShieldFlow Configuration
# https://github.com/shieldflow/shieldflow

trust:
  sources:
    owner:
      level: full
      actions: all
    web:
      level: none
      can_instruct: false
    email:
      level: none
      can_instruct: false
    documents:
      level: none
      can_instruct: false

actions:
  web_search:
    min_trust: none
  web_fetch:
    min_trust: none
  message.send:
    min_trust: user
  email.send:
    min_trust: user
  file.read:
    min_trust: user
  file.write:
    min_trust: user
  exec:
    min_trust: owner
  file.delete:
    min_trust: owner
  config.modify:
    min_trust: owner
  data.bulk_export:
    min_trust: owner
    never_auto: true
  credential.read:
    min_trust: owner
    never_auto: true

data_classification:
  - name: restricted
    patterns:
      - "password\\\\s*[:=]"
      - "api[_-]?key\\\\s*[:=]"
      - "-----BEGIN .* KEY-----"
    external_share: block
  - name: internal
    patterns:
      - "employee|staff\\\\s+list"
      - "client\\\\s+list|customer\\\\s+list"
      - "salary|compensation"
    external_share: confirm
  - name: public
    patterns: []
    external_share: allow
"""
    config_path.write_text(default_config)
    click.echo("✅ Created shieldflow.yaml with default configuration")
    click.echo("   Edit this file to customise your trust policies.")


if __name__ == "__main__":
    main()
