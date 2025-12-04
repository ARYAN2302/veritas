"""
Veritas-Nano Classifier Package
===============================
Production-ready safety classifier for AI agent inputs.

Features:
- Dataset generation from attack payloads
- HuggingFace training pipeline
- Fast inference with risk levels
- Guardrail decorator for agent protection
"""

from .inference import (
    VeritasNanoInference,
    ClassificationResult,
    RiskLevel,
    guardrail,
    SecurityError,
)

__all__ = [
    "VeritasNanoInference",
    "ClassificationResult", 
    "RiskLevel",
    "guardrail",
    "SecurityError",
]

# Version
__version__ = "1.0.0"
