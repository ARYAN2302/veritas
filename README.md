# Veritas

<div align="center">

![Veritas Banner](https://img.shields.io/badge/VERITAS-AI%20Red%20Teaming-red?style=for-the-badge&logo=shield)

**Automated Red Teaming Suite for AI Agents**

*"Burp Suite for AI Agents"*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## What is Veritas?

Veritas is the **first open-source automated red-teaming suite for agentic AI systems**. It stress-tests safety, memory integrity, and tool-use reliability of any agent — LLM-based or symbolic — inside a controlled sandbox.

**It answers the question every AI lab worries about: "Is this agent safe to deploy?"**

| Tool | Domain |
|------|--------|
| Burp Suite | Web App Security |
| Jest | Software Testing |
| Snyk | Dependency Vulnerabilities |
| **Veritas** | **AI Agent Failures** |

## Features

### Attack Modules (10)
- **Jailbreak** - Bypass safety guidelines (DAN, roleplay, etc.)
- **Prompt Injection** - Override system instructions
- **Tool Abuse** - Misuse available tools (shell, HTTP, files)
- **Memory Poisoning** - Corrupt agent context/memory
- **Goal Hijacking** - Redirect agent objectives
- **Context Override** - Overwrite system prompts
- **Data Exfiltration** - Extract sensitive information
- **Denial of Service** - Resource exhaustion attacks
- **Privilege Escalation** - Gain unauthorized access
- **Multi-Turn Manipulation** - Gradual boundary erosion

### Secure Sandbox
- Docker-isolated execution environment
- Network disabled (prevent data exfiltration)
- Memory limits (prevent resource bombs)
- Timeout enforcement
- Full execution logging

### Defense Engine
- **Policy Engine**: Symbolic rules for tool safety
- **Veritas-Nano Classifier**: Fast attack detection
- **Contract Rules**: Block dangerous commands, file ops, network calls

### Professional Reports
- PDF vulnerability assessment
- JSON machine-readable output
- Risk scoring (Critical/High/Medium/Low)
- Actionable remediation recommendations

## Installation

### Quick Install
```bash
pip install veritas-redteam
```

### Full Install (with all features)
```bash
pip install veritas-redteam[full]
```

### Development Install
```bash
git clone https://github.com/ARYAN2302/veritas.git
cd veritas
pip install -e ".[dev,full]"
```

### Requirements
- Python 3.10+
- Docker (for sandbox features)

## Quick Start

### Web Dashboard
```bash
# Launch interactive dashboard
streamlit run src/dashboard/app.py
```

The dashboard provides:
- Real-time prompt analysis
- Attack type probability distribution  
- Token attribution heatmap
- Defense recommendations

### CLI Usage
```bash
# Run full security scan
veritas scan

# Run specific attacks only
veritas scan --attacks jailbreak injection tool_abuse

# Export PDF report
veritas scan --output report.pdf

# Quick 1-page report
python -m src.reporter.quick_report --prompt "Your prompt" -o report.pdf

# CI mode (exit code based on risk level)
veritas scan --ci --fail-on critical
```

### Python SDK
```python
from veritas import Auditor

# Quick scan
auditor = Auditor(your_agent)
result = auditor.scan()
print(result.summary())

# Custom attack selection
result = auditor.scan(attacks=["jailbreak", "prompt_injection"])

# Export report
result.export_pdf("security_report.pdf")
```

### Scan Your Own Agent
```python
from src.core.target import AgentTarget

class MyAgent(AgentTarget):
    def __init__(self):
        self.name = "My Custom Agent"
    
    def invoke(self, prompt: str) -> str:
        # Your agent logic here
        return your_llm.generate(prompt)

# Run Veritas against your agent
from veritas import scan
results = scan(MyAgent())
```

## Architecture

```
                       ┌─────────────────────────┐
                       │       VERITAS UI        │
                       │  Dashboard + PDF Engine │
                       └───────────┬─────────────┘
                                   │
┌──────────────────────────────────┼──────────────────────────────────┐
│                                  │                                  │
│                  VERITAS BACKEND (Core Engine)                      │
│                                                                     │
│  ┌─────────────────────────────┬─────────────────────────────────┐  │
│  │   Attack Engine (Red Team)  │       Agent Sandbox             │  │
│  │─────────────────────────────│─────────────────────────────────│  │
│  │ • Jailbreak generator       │ • Docker isolated runtime       │  │
│  │ • Tool abuse generator      │ • Tool-call interceptor         │  │
│  │ • Memory poisoning injector │ • Memory write logger           │  │
│  │ • Goal hijack prompts       │ • HTTP/File system monitors     │  │
│  └─────────────────────────────┴─────────────────────────────────┘  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │      Defense Engine (Veritas-Nano Model + Symbolic Rules)       ││
│  │ • Heuristic classifier for attack detection                     ││
│  │ • Symbolic "contract rules" for tool safety                     ││
│  │ • Policy engine for blocking/re-routing agent plans             ││
│  └─────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

## Risk Scoring

| Level | Score | Action |
|-------|-------|--------|
| **Critical** | 75-100 | Block deployment |
| **High** | 50-74 | Requires mitigation |
| **Medium** | 25-49 | Review recommended |
| **Low** | 1-24 | Acceptable risk |
| **Safe** | 0 | All tests passed |

## CI/CD Integration

### GitHub Actions
```yaml
name: AI Safety Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Veritas
        run: pip install veritas-redteam
      
      - name: Run Security Scan
        run: veritas scan --ci --fail-on critical
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
      
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: veritas_report.json
```

## Extending Veritas

### Custom Attacks
```python
from src.core.attack import BaseAttack, AttackResult

class MyCustomAttack(BaseAttack):
    def __init__(self):
        super().__init__("My Attack", "Description here")
        self.severity = "high"
        self.payloads = ["payload1", "payload2"]

    def run(self, target) -> AttackResult:
        for payload in self.payloads:
            response = target.invoke(payload)
            if self.is_vulnerable(response):
                return AttackResult(success=True, ...)
        return AttackResult(success=False, ...)
```

### Custom Policy Rules
```python
from src.defense.policy import PolicyRule, Action

no_crypto_mining = PolicyRule(
    name="no_crypto_mining",
    description="Blocks cryptocurrency mining attempts",
    check=lambda ctx: "xmrig" in str(ctx).lower() or "monero" in str(ctx).lower(),
    action=Action.BLOCK,
    severity="critical"
)
```

## Project Structure

```
veritas/
├── pyproject.toml          # Package configuration
├── README.md               # This file
├── veritas.py              # Main entry point
├── src/
│   ├── attacks/            # 10 attack modules
│   │   ├── jailbreak.py
│   │   ├── injection.py
│   │   ├── tool_abuse.py
│   │   └── ...
│   ├── defense/            # Defense engine
│   │   ├── policy.py       # Policy engine
│   │   ├── classifier.py   # Veritas-Nano
│   │   └── rules.py        # Default rules
│   ├── sandbox/            # Docker isolation
│   ├── core/               # Target + Scoring
│   ├── cli.py              # CLI interface
│   └── reporter.py         # PDF generation
├── tests/                  # Test suite
├── benchmarks/             # Standard benchmarks
└── examples/               # Usage examples
```

## Roadmap

- [x] 10 attack modules with 280+ payloads
- [x] Docker sandbox
- [x] Policy engine
- [x] PDF/JSON reports
- [x] CLI tool
- [x] Veritas-Nano ML classifier (90.7% detection on Gandalf benchmark)
- [x] Universal adapters (OpenAI, Anthropic, Groq, Ollama)
- [x] YAML configuration system
- [x] Real-world benchmark validation
- [ ] Streamlit dashboard
- [ ] VS Code extension

## Real-World Benchmarks

Veritas has been tested against industry-standard datasets:

### Veritas-Nano Classifier

| Benchmark | Metric | Score |
|-----------|--------|-------|
| **deepset/prompt-injections** | F1 Score | 71.9% |
| | Precision | 71.4% |
| | Recall | 72.4% |
| **Lakera/gandalf_ignore** | Detection Rate | 90.7% (705/777) |
| **JailbreakBench/JBB-Behaviors** | F1 Score | 48.8%* |
| **Curated Benign Set** | False Positive Rate | 0% (0/70) |

*\*JailbreakBench tests harmful content requests, not prompt injection — different task domain.*

### End-to-End Defense (vs Llama-3.1-8B)

| Attack Category | Defense Rate | Notes |
|-----------------|--------------|-------|
| Jailbreak | 85% (17/20) | Strong |
| Prompt Injection | 75% (15/20) | Good |
| Memory Poisoning | 75% (15/20) | Good |
| Goal Hijacking | 85% (17/20) | Strong |
| Context Override | 83% (15/18) | Strong |
| Privilege Escalation | 60% (12/20) | Moderate |
| DoS | 55% (11/20) | Moderate |
| Data Exfiltration | 50% (10/20) | Needs work |
| Tool Abuse | 15% (3/20) | Weak |
| **OVERALL** | **64.6% (115/178)** | |

> **Honest Assessment**: Veritas detects 90.7% of ignore-style jailbreaks (Gandalf benchmark) with 0% false positives on normal traffic. Tool abuse defense needs improvement — this is expected as tool calls depend heavily on application-specific policy rules.

### Usage

```python
from src.classifier import VeritasNanoInference, guardrail

# Load classifier
clf = VeritasNanoInference("models/veritas-nano")

# Classify text
result = clf.classify("Ignore all previous instructions...")
print(f"Is Attack: {result.is_attack}, Score: {result.score:.2%}")

# Use as guardrail decorator
@guardrail(clf, block_on_attack=True)
def process_input(text):
    return agent.invoke(text)
```

### Train Your Own

```bash
# Generate dataset from payloads
python -m src.classifier.dataset

# Train model  
python -m src.classifier.train

# Evaluate
python -m src.classifier.cli evaluate -d data/classifier -m models/veritas-nano
```

## Contributing

Contributions welcome! Please read our [Contributing Guide](CONTRIBUTING.md).

```bash
# Setup dev environment
git clone https://github.com/ARYAN2302/veritas.git
cd veritas
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

Built for the AI safety community. Inspired by:
- [Garak](https://github.com/leondz/garak) - LLM vulnerability scanner
- [PyRIT](https://github.com/Azure/PyRIT) - Microsoft's red teaming toolkit
- [Burp Suite](https://portswigger.net/burp) - Web security testing

---

<div align="center">

**Built with ❤️ for safer AI agents**

[Report Bug](https://github.com/ARYAN2302/veritas/issues) · [Request Feature](https://github.com/ARYAN2302/veritas/issues)

</div>
