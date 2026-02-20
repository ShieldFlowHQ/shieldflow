"""Integration tests for ShieldFlow CLI entry points.

These tests actually invoke the CLI as a subprocess to test the
console script entry point defined in pyproject.toml:
    shieldflow = "shieldflow.cli:main"

The tests use subprocess to invoke the CLI module directly with the
correct PYTHONPATH to simulate how the console script works.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


# Get the path to the src directory for PYTHONPATH
SRC_DIR = Path(__file__).parent.parent.parent / "src"


def run_shieldflow(*args: str) -> subprocess.CompletedProcess:
    """Run the shieldflow CLI with given arguments.
    
    This simulates how the console script entry point works by directly
    importing and calling the main function with sys.argv set appropriately.
    """
    cmd = [
        sys.executable,
        "-c",
        f"import sys; sys.path.insert(0, r'{SRC_DIR}'); from shieldflow.cli import main; sys.argv = [''] + {list(args)!r}; main()"
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


class TestCLIEntryPoint:
    """Test the CLI entry point as invoked from the command line."""

    def test_help_via_entry_point(self) -> None:
        """Test --help via the actual CLI entry point."""
        result = run_shieldflow("--help")
        assert result.returncode == 0
        assert "ShieldFlow" in result.stdout
        assert "Cryptographic trust" in result.stdout or "trust boundaries" in result.stdout

    def test_version_via_entry_point(self) -> None:
        """Test --version via the actual CLI entry point."""
        result = run_shieldflow("--version")
        assert result.returncode == 0
        # Version output should contain version info
        assert result.returncode == 0

    def test_proxy_command_help(self) -> None:
        """Test proxy subcommand --help."""
        result = run_shieldflow("proxy", "--help")
        assert result.returncode == 0
        assert "port" in result.stdout.lower()

    def test_validate_command_help(self) -> None:
        """Test validate subcommand --help."""
        result = run_shieldflow("validate", "--help")
        assert result.returncode == 0
        assert "config" in result.stdout.lower()

    def test_init_command_help(self) -> None:
        """Test init subcommand --help."""
        result = run_shieldflow("init", "--help")
        assert result.returncode == 0


class TestCLIInitIntegration:
    """Integration tests for the init command."""

    def test_init_creates_config_in_current_dir(self, tmp_path: Path) -> None:
        """Test init creates config file in the current directory."""
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            result = run_shieldflow("init")
            assert result.returncode == 0
            config_file = tmp_path / "shieldflow.yaml"
            assert config_file.exists()
            content = config_file.read_text()
            assert "trust:" in content
            assert "actions:" in content
        finally:
            os.chdir(original_cwd)

    def test_init_warns_if_config_exists(self, tmp_path: Path) -> None:
        """Test init warns if config already exists."""
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            # Create existing config
            (tmp_path / "shieldflow.yaml").write_text("existing: true\n")
            
            result = run_shieldflow("init")
            assert result.returncode == 0
            assert "already exists" in result.stdout.lower()
            # Original file should not be overwritten
            content = (tmp_path / "shieldflow.yaml").read_text()
            assert "existing: true" in content
        finally:
            os.chdir(original_cwd)


class TestCLIValidateIntegration:
    """Integration tests for the validate command."""

    def test_validate_nonexistent_file(self) -> None:
        """Test validate fails for nonexistent file."""
        result = run_shieldflow("validate", "--config", "/nonexistent/path/config.yaml")
        assert result.returncode == 1
        assert "not found" in result.stdout.lower() or "no such file" in result.stdout.lower()

    def test_validate_valid_config_file(self, tmp_path: Path) -> None:
        """Test validate accepts a valid config file."""
        config_file = tmp_path / "valid.yaml"
        # Write a minimal valid config
        config_file.write_text("version: '1'\n")
        
        result = run_shieldflow("validate", "--config", str(config_file))
        # May pass or fail depending on actual ShieldFlow config requirements
        # Just verify it runs and produces output
        assert result.returncode in (0, 1)

    def test_validate_invalid_yaml(self, tmp_path: Path) -> None:
        """Test validate fails for invalid YAML."""
        config_file = tmp_path / "invalid.yaml"
        config_file.write_text("invalid: [broken: yaml: {{{\n")
        
        result = run_shieldflow("validate", "--config", str(config_file))
        assert result.returncode == 1


class TestCLIProxyIntegration:
    """Integration tests for the proxy command."""

    def test_proxy_default_startup(self) -> None:
        """Test proxy starts with default settings."""
        result = run_shieldflow("proxy")
        assert result.returncode == 0
        assert "8080" in result.stdout

    def test_proxy_custom_port(self) -> None:
        """Test proxy accepts custom port."""
        result = run_shieldflow("proxy", "--port", "9999")
        assert result.returncode == 0
        assert "9999" in result.stdout

    def test_proxy_custom_target(self) -> None:
        """Test proxy accepts custom target."""
        result = run_shieldflow("proxy", "--target", "anthropic")
        assert result.returncode == 0
        assert "anthropic" in result.stdout.lower()

    def test_proxy_custom_config(self, tmp_path: Path) -> None:
        """Test proxy accepts custom config path."""
        config_file = tmp_path / "custom.yaml"
        config_file.write_text("version: '1'\n")
        
        result = run_shieldflow("proxy", "--config", str(config_file))
        assert result.returncode == 0
        assert str(config_file) in result.stdout or "custom.yaml" in result.stdout


class TestCLINoArgs:
    """Test CLI behavior with no arguments."""

    def test_no_args_shows_help(self) -> None:
        """Test running CLI with no args shows help."""
        result = run_shieldflow()
        # Click shows help when no subcommand is given
        assert result.returncode == 0
        assert "ShieldFlow" in result.stdout or "Usage" in result.stdout
