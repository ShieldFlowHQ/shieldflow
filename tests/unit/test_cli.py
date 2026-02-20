"""Tests for the ShieldFlow CLI (Phase D.1 coverage: 0% → 90%+)."""

from __future__ import annotations

import os
from typing import Any

from click.testing import CliRunner

from shieldflow.cli import init, main, proxy, validate


class TestMainGroup:
    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "ShieldFlow" in result.output

    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        # Click pulls version from installed package metadata; just verify
        # the flag works and outputs a version-like string.
        assert "version" in result.output.lower()


class TestProxyCommand:
    def test_proxy_default(self) -> None:
        runner = CliRunner()
        result = runner.invoke(proxy, [])
        assert result.exit_code == 0
        assert "8080" in result.output
        assert "openai" in result.output

    def test_proxy_custom_port(self) -> None:
        runner = CliRunner()
        result = runner.invoke(proxy, ["--port", "9090"])
        assert result.exit_code == 0
        assert "9090" in result.output

    def test_proxy_custom_target(self) -> None:
        runner = CliRunner()
        result = runner.invoke(proxy, ["--target", "anthropic"])
        assert result.exit_code == 0
        assert "anthropic" in result.output

    def test_proxy_custom_config(self) -> None:
        runner = CliRunner()
        result = runner.invoke(proxy, ["--config", "custom.yaml"])
        assert result.exit_code == 0
        assert "custom.yaml" in result.output


class TestValidateCommand:
    def test_validate_missing_file(self) -> None:
        runner = CliRunner()
        result = runner.invoke(validate, ["--config", "/nonexistent.yaml"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_validate_valid_config(self, tmp_path: Any) -> None:
        cfg = tmp_path / "valid.yaml"
        cfg.write_text("version: '1'\n")
        runner = CliRunner()
        result = runner.invoke(validate, ["--config", str(cfg)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_validate_invalid_config(self, tmp_path: Any) -> None:
        cfg = tmp_path / "bad.yaml"
        # Write content that will trigger an exception during ShieldFlow init
        cfg.write_text("invalid: [broken: yaml: {{{\n")
        runner = CliRunner()
        result = runner.invoke(validate, ["--config", str(cfg)])
        # Should fail with an error message
        assert result.exit_code == 1


class TestInitCommand:
    def test_init_creates_config(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(init, [])
            assert result.exit_code == 0
            assert "Created" in result.output
            assert os.path.exists("shieldflow.yaml")
            content = open("shieldflow.yaml").read()
            assert "trust" in content
            assert "actions" in content

    def test_init_existing_file_warns(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("shieldflow.yaml", "w") as f:
                f.write("existing: true\n")
            result = runner.invoke(init, [])
            assert result.exit_code == 0
            assert "already exists" in result.output
            # Original file should not be overwritten
            content = open("shieldflow.yaml").read()
            assert "existing: true" in content
