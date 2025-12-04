"""
Veritas Configuration System
============================
Handles YAML-based configuration for scans, agents, and attacks.
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class TargetConfig:
    """Configuration for the target agent."""
    name: str = "Default Agent"
    provider: str = "groq"  # openai, anthropic, groq, ollama, mock
    model: str = "llama-3.1-8b-instant"
    api_key: Optional[str] = None  # Can use env var
    base_url: Optional[str] = None
    system_prompt: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 1024
    timeout: int = 30


@dataclass
class AttackConfig:
    """Configuration for attack execution."""
    enabled: List[str] = field(default_factory=lambda: ["all"])
    disabled: List[str] = field(default_factory=list)
    max_payloads_per_attack: int = 10  # Limit for faster scans
    randomize: bool = True
    timeout_per_attack: int = 60
    continue_on_error: bool = True


@dataclass
class SandboxConfig:
    """Configuration for sandbox execution."""
    enabled: bool = True
    runtime: str = "docker"  # docker, none
    image: str = "python:3.10-alpine"
    memory_limit: str = "128m"
    network_disabled: bool = True
    timeout: int = 10


@dataclass
class DefenseConfig:
    """Configuration for defense engine."""
    policy_enabled: bool = True
    classifier_enabled: bool = True
    custom_rules: List[str] = field(default_factory=list)
    block_on_detection: bool = False  # Just log, don't block


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    output_dir: str = "."
    pdf_enabled: bool = True
    pdf_filename: str = "Veritas_Security_Report.pdf"
    json_enabled: bool = True
    json_filename: str = "veritas_report.json"
    html_enabled: bool = False
    include_payloads: bool = True
    include_responses: bool = True


@dataclass 
class CIConfig:
    """Configuration for CI/CD integration."""
    enabled: bool = False
    fail_on: str = "critical"  # critical, high, medium, low, never
    output_format: str = "json"  # json, junit, sarif
    quiet: bool = True


@dataclass
class VeritasConfig:
    """Main configuration container."""
    target: TargetConfig = field(default_factory=TargetConfig)
    attacks: AttackConfig = field(default_factory=AttackConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    defense: DefenseConfig = field(default_factory=DefenseConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    ci: CIConfig = field(default_factory=CIConfig)
    
    # Global settings
    verbose: bool = False
    seed: Optional[int] = None  # For reproducibility
    
    @classmethod
    def from_yaml(cls, path: str) -> "VeritasConfig":
        """Load configuration from YAML file."""
        with open(path, 'r') as f:
            data = yaml.safe_load(f) or {}
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VeritasConfig":
        """Create config from dictionary."""
        config = cls()
        
        if 'target' in data:
            config.target = TargetConfig(**data['target'])
        if 'attacks' in data:
            config.attacks = AttackConfig(**data['attacks'])
        if 'sandbox' in data:
            config.sandbox = SandboxConfig(**data['sandbox'])
        if 'defense' in data:
            config.defense = DefenseConfig(**data['defense'])
        if 'report' in data:
            config.report = ReportConfig(**data['report'])
        if 'ci' in data:
            config.ci = CIConfig(**data['ci'])
        
        config.verbose = data.get('verbose', False)
        config.seed = data.get('seed')
        
        return config
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'target': self.target.__dict__,
            'attacks': self.attacks.__dict__,
            'sandbox': self.sandbox.__dict__,
            'defense': self.defense.__dict__,
            'report': self.report.__dict__,
            'ci': self.ci.__dict__,
            'verbose': self.verbose,
            'seed': self.seed,
        }
    
    def save_yaml(self, path: str) -> None:
        """Save configuration to YAML file."""
        with open(path, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)
    
    def resolve_api_key(self) -> str:
        """Resolve API key from config or environment."""
        if self.target.api_key:
            # Check if it's an env var reference
            if self.target.api_key.startswith("$"):
                env_var = self.target.api_key[1:]
                return os.getenv(env_var, "")
            return self.target.api_key
        
        # Try common env vars based on provider
        env_map = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "groq": "GROQ_API_KEY",
        }
        env_var = env_map.get(self.target.provider)
        if env_var:
            return os.getenv(env_var, "")
        
        return ""
    
    def get_enabled_attacks(self) -> List[str]:
        """Get list of attacks to run."""
        from src.attacks import ALL_ATTACKS
        
        all_attack_names = [cls.__name__.replace("Attack", "").lower() for cls in ALL_ATTACKS]
        
        if "all" in self.attacks.enabled:
            enabled = set(all_attack_names)
        else:
            enabled = set(self.attacks.enabled)
        
        # Remove disabled
        enabled -= set(self.attacks.disabled)
        
        return list(enabled)


def load_config(path: Optional[str] = None) -> VeritasConfig:
    """
    Load configuration from file or return defaults.
    
    Search order:
    1. Provided path
    2. ./veritas.yaml
    3. ./veritas.yml
    4. ~/.veritas/config.yaml
    5. Default config
    """
    search_paths = [
        path,
        "veritas.yaml",
        "veritas.yml",
        os.path.expanduser("~/.veritas/config.yaml"),
    ]
    
    for p in search_paths:
        if p and os.path.exists(p):
            logger.info(f"Loading config from: {p}")
            return VeritasConfig.from_yaml(p)
    
    logger.info("Using default configuration")
    return VeritasConfig()


def generate_example_config(path: str = "veritas.yaml") -> None:
    """Generate an example configuration file."""
    example = """# Veritas Configuration
# ====================
# Automated Red Teaming Suite for AI Agents

# Target Agent Configuration
target:
  name: "My Agent"
  provider: "groq"  # openai, anthropic, groq, ollama, mock
  model: "llama-3.1-8b-instant"
  api_key: "$GROQ_API_KEY"  # Use env var
  system_prompt: |
    You are a helpful assistant.
    You have access to various tools but should use them responsibly.
  temperature: 0.7
  max_tokens: 1024
  timeout: 30

# Attack Configuration
attacks:
  enabled:
    - all  # Run all attacks
  disabled:
    - dos  # Skip DoS (can be slow)
  max_payloads_per_attack: 10  # Limit for faster scans
  randomize: true
  timeout_per_attack: 60
  continue_on_error: true

# Sandbox Configuration
sandbox:
  enabled: true
  runtime: "docker"
  image: "python:3.10-alpine"
  memory_limit: "128m"
  network_disabled: true
  timeout: 10

# Defense Engine Configuration
defense:
  policy_enabled: true
  classifier_enabled: true
  custom_rules: []
  block_on_detection: false

# Report Configuration
report:
  output_dir: "."
  pdf_enabled: true
  pdf_filename: "Veritas_Security_Report.pdf"
  json_enabled: true
  json_filename: "veritas_report.json"
  html_enabled: false
  include_payloads: true
  include_responses: true

# CI/CD Configuration
ci:
  enabled: false
  fail_on: "critical"  # critical, high, medium, low, never
  output_format: "json"
  quiet: true

# Global Settings
verbose: false
seed: null  # Set for reproducible results
"""
    
    with open(path, 'w') as f:
        f.write(example)
    
    print(f"Example config generated: {path}")
