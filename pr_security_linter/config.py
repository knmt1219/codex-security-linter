"""Configuration loader and schema validator for PR Security Linter."""

import os
import pathlib
import sys
from typing import Any, Dict, List, Optional

VALID_SEVERITY_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_TOP_LEVEL_KEYS = {"version", "settings", "ignore_paths", "rules", "analyzers"}
VALID_SETTINGS_KEYS = {"model", "severity_threshold", "timeout", "strict"}


def parse_simple_yaml(text: str) -> Dict[str, Any]:
    """Lightweight fallback YAML parser for configuration without external dependencies."""
    config: Dict[str, Any] = {}
    current_section: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if not raw_line.startswith(" ") and line.endswith(":"):
            current_section = line[:-1].strip()
            config[current_section] = {}
            continue

        if current_section and raw_line.startswith("  ") and ":" in line:
            parts = line.split(":", 1)
            k = parts[0].strip()
            v = parts[1].strip().strip('"').strip("'")
            if isinstance(config[current_section], dict):
                # Check for boolean or numeric conversions
                if v.lower() == "true":
                    config[current_section][k] = True
                elif v.lower() == "false":
                    config[current_section][k] = False
                else:
                    config[current_section][k] = v
            continue

        if current_section and line.startswith("- "):
            item = line[2:].strip().strip('"').strip("'")
            if not isinstance(config[current_section], list):
                config[current_section] = []
            config[current_section].append(item)
            continue

        if ":" in line:
            parts = line.split(":", 1)
            k = parts[0].strip()
            v = parts[1].strip().strip('"').strip("'")
            if v.lower() == "true":
                config[k] = True
            elif v.lower() == "false":
                config[k] = False
            else:
                config[k] = v
            current_section = None

    return config


def validate_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Validate configuration schema and values, raising ValueError on malformed structures."""
    if not isinstance(config, dict):
        raise ValueError("Configuration must be a dictionary/mapping.")

    for k in config:
        if k not in VALID_TOP_LEVEL_KEYS:
            print(f"Warning: Unrecognized configuration key '{k}'", file=sys.stderr)

    settings = config.get("settings")
    if settings is not None:
        if not isinstance(settings, dict):
            raise ValueError("'settings' must be a mapping/object in configuration.")
        
        sev = settings.get("severity_threshold")
        if sev is not None:
            if not isinstance(sev, str) or sev.upper() not in VALID_SEVERITY_LEVELS:
                raise ValueError(f"Invalid severity_threshold '{sev}'. Must be one of: {', '.join(sorted(VALID_SEVERITY_LEVELS))}")

    ignore_paths = config.get("ignore_paths")
    if ignore_paths is not None and not isinstance(ignore_paths, list):
        raise ValueError("'ignore_paths' must be a list of glob path strings.")

    rules = config.get("rules")
    if rules is not None and not isinstance(rules, dict):
        raise ValueError("'rules' must be a mapping of rule flags.")

    return config


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load and validate configuration from specified path or standard candidate files."""
    candidate_paths = [config_path] if config_path else [".pr-security.yml", ".pr-security-linter.yml", ".codex-security.yml"]

    for path in candidate_paths:
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()

                parsed: Dict[str, Any] = {}
                try:
                    import yaml  # type: ignore
                    data = yaml.safe_load(content)
                    if isinstance(data, dict):
                        parsed = data
                except ImportError:
                    pass

                if not parsed:
                    parsed = parse_simple_yaml(content)

                return validate_config(parsed)
            except Exception as e:
                print(f"Warning: Failed to load or validate config from '{path}': {e}", file=sys.stderr)
                if config_path:
                    # If explicitly requested path failed, raise error
                    raise
                return {}

    if config_path:
        raise FileNotFoundError(f"Specified configuration file '{config_path}' does not exist.")

    return {}
