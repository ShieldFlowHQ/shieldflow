"""Unit tests for OpenClaw upstream auto-detection."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from shieldflow.proxy.config import (
    UpstreamConfig,
    detect_upstream_from_openclaw,
    get_default_model,
    get_provider_config,
    load_openclaw_config,
    parse_model_provider,
)


class TestLoadOpenclawConfig:
    """Tests for load_openclaw_config()."""

    def test_load_valid_config(self, tmp_path):
        """Test loading a valid OpenClaw config file."""
        config_data = {
            "agents": {
                "defaults": {
                    "model": {
                        "primary": "minimax/MiniMax-M2.5"
                    }
                }
            }
        }
        config_file = tmp_path / "openclaw.json"
        config_file.write_text(json.dumps(config_data))

        result = load_openclaw_config(str(config_file))
        assert result == config_data

    def test_load_missing_file(self):
        """Test loading from non-existent file returns None."""
        result = load_openclaw_config("/nonexistent/path.json")
        assert result is None

    def test_load_invalid_json(self, tmp_path):
        """Test loading invalid JSON returns None."""
        config_file = tmp_path / "openclaw.json"
        config_file.write_text("{ invalid json }")

        result = load_openclaw_config(str(config_file))
        assert result is None

    def test_load_default_path(self, tmp_path):
        """Test loading from default path ~.openclaw/openclaw.json."""
        config_data = {"agents": {"defaults": {"model": {"primary": "test"}}}}
        
        with patch.object(Path, "home", return_value=tmp_path):
            config_file = tmp_path / ".openclaw" / "openclaw.json"
            config_file.parent.mkdir()
            config_file.write_text(json.dumps(config_data))
            
            result = load_openclaw_config()
            assert result == config_data


class TestGetDefaultModel:
    """Tests for get_default_model()."""

    def test_extract_primary_model(self):
        """Test extracting primary model from config."""
        config = {
            "agents": {
                "defaults": {
                    "model": {
                        "primary": "minimax/MiniMax-M2.5",
                        "fallbacks": ["anthropic/claude-sonnet-4-6"]
                    }
                }
            }
        }
        
        result = get_default_model(config)
        assert result == "minimax/MiniMax-M2.5"

    def test_missing_agents(self):
        """Test returns None when agents key missing."""
        config = {}
        assert get_default_model(config) is None

    def test_missing_defaults(self):
        """Test returns None when defaults key missing."""
        config = {"agents": {}}
        assert get_default_model(config) is None

    def test_missing_model(self):
        """Test returns None when model key missing."""
        config = {"agents": {"defaults": {}}}
        assert get_default_model(config) is None


class TestParseModelProvider:
    """Tests for parse_model_provider()."""

    def test_parse_minimax_model(self):
        """Test parsing minimax model string."""
        result = parse_model_provider("minimax/MiniMax-M2.5")
        assert result == ("minimax", "MiniMax-M2.5")

    def test_parse_anthropic_model(self):
        """Test parsing anthropic model string."""
        result = parse_model_provider("anthropic/claude-sonnet-4-6")
        assert result == ("anthropic", "claude-sonnet-4-6")

    def test_parse_openai_model(self):
        """Test parsing openai model string."""
        result = parse_model_provider("openai/gpt-4o")
        assert result == ("openai", "gpt-4o")

    def test_parse_empty_string(self):
        """Test parsing empty string returns None."""
        assert parse_model_provider("") is None

    def test_parse_no_slash(self):
        """Test parsing string without slash returns None."""
        assert parse_model_provider("gpt-4o") is None


class TestGetProviderConfig:
    """Tests for get_provider_config()."""

    def test_minimax_config(self):
        """Test getting minimax provider config."""
        result = get_provider_config("minimax")
        assert result == {
            "url": "https://api.minimax.io/anthropic",
            "env_key": "MINIMAX_API_KEY",
        }

    def test_anthropic_config(self):
        """Test getting anthropic provider config."""
        result = get_provider_config("anthropic")
        assert result == {
            "url": "https://api.anthropic.com/",
            "env_key": "ANTHROPIC_API_KEY",
        }

    def test_openai_config(self):
        """Test getting openai provider config."""
        result = get_provider_config("openai")
        assert result == {
            "url": "https://api.openai.com",
            "env_key": "OPENAI_API_KEY",
        }

    def test_unknown_provider(self):
        """Test unknown provider returns None."""
        assert get_provider_config("unknown") is None


class TestDetectUpstreamFromOpenclaw:
    """Tests for detect_upstream_from_openclaw()."""

    def test_detect_success(self, tmp_path, monkeypatch):
        """Test successful auto-detection."""
        config_data = {
            "agents": {
                "defaults": {
                    "model": {
                        "primary": "minimax/MiniMax-M2.5"
                    }
                }
            }
        }
        
        # Create temp config file
        config_file = tmp_path / ".openclaw" / "openclaw.json"
        config_file.parent.mkdir()
        config_file.write_text(json.dumps(config_data))
        
        # Mock environment variable for API key
        monkeypatch.setenv("MINIMAX_API_KEY", "test-api-key")
        
        with patch("shieldflow.proxy.config.Path.home", return_value=tmp_path):
            result = detect_upstream_from_openclaw()
            
        assert result is not None
        assert result.url == "https://api.minimax.io/anthropic"
        assert result.api_key == "test-api-key"

    def test_detect_no_config(self, tmp_path):
        """Test detection fails when no config file."""
        # Point to non-existent home
        with patch("shieldflow.proxy.config.Path.home", return_value=tmp_path):
            result = detect_upstream_from_openclaw()
        assert result is None

    def test_detect_no_model(self, tmp_path):
        """Test detection fails when no default model."""
        config_data = {"agents": {"defaults": {}}}
        config_file = tmp_path / ".openclaw" / "openclaw.json"
        config_file.parent.mkdir()
        config_file.write_text(json.dumps(config_data))
        
        with patch("shieldflow.proxy.config.Path.home", return_value=tmp_path):
            result = detect_upstream_from_openclaw()
        assert result is None

    def test_detect_unknown_provider(self, tmp_path):
        """Test detection fails for unknown provider."""
        config_data = {
            "agents": {
                "defaults": {
                    "model": {
                        "primary": "unknown/model-name"
                    }
                }
            }
        }
        config_file = tmp_path / ".openclaw" / "openclaw.json"
        config_file.parent.mkdir()
        config_file.write_text(json.dumps(config_data))
        
        with patch("shieldflow.proxy.config.Path.home", return_value=tmp_path):
            result = detect_upstream_from_openclaw()
        assert result is None

    def test_detect_no_api_key(self, tmp_path):
        """Test detection fails when API key not in env."""
        config_data = {
            "agents": {
                "defaults": {
                    "model": {
                        "primary": "minimax/MiniMax-M2.5"
                    }
                }
            }
        }
        config_file = tmp_path / ".openclaw" / "openclaw.json"
        config_file.parent.mkdir()
        config_file.write_text(json.dumps(config_data))
        
        # Don't set MINIMAX_API_KEY
        with patch("shieldflow.proxy.config.Path.home", return_value=tmp_path):
            result = detect_upstream_from_openclaw()
        assert result is None
