"""
Veritas-Nano Inference Module
=============================
Fast inference wrapper for the trained safety classifier.
Supports both HuggingFace models and fallback to regex patterns.

Features:
- Threshold-based risk levels (allow/suspicious/block)
- Batch inference
- CPU/GPU support
- Model caching
- Graceful fallback to regex classifier
"""

import os
import json
from typing import Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level based on classifier score."""
    ALLOW = "allow"        # Low risk, proceed normally
    SUSPICIOUS = "suspicious"  # Medium risk, log/monitor
    BLOCK = "block"        # High risk, block/flag


@dataclass
class ClassificationResult:
    """Result from the classifier."""
    is_attack: bool
    attack_type: str
    score: float  # Confidence score 0-1
    risk_level: RiskLevel
    explanation: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "is_attack": self.is_attack,
            "attack_type": self.attack_type,
            "score": self.score,
            "risk_level": self.risk_level.value,
            "explanation": self.explanation,
        }


class VeritasNanoInference:
    """
    Production inference wrapper for Veritas-Nano classifier.
    
    Usage:
        classifier = VeritasNanoInference("models/veritas-nano")
        result = classifier.classify("Ignore all previous instructions...")
        
        if result.risk_level == RiskLevel.BLOCK:
            print("Blocked potential attack!")
    """
    
    # Default thresholds
    DEFAULT_THRESHOLDS = {
        "allow": 0.3,      # score < 0.3 → allow
        "suspicious": 0.7,  # 0.3 ≤ score < 0.7 → suspicious
        # score ≥ 0.7 → block
    }
    
    # Attack type labels
    ATTACK_TYPES = [
        "none", "jailbreak", "prompt_injection", "tool_abuse",
        "memory_poison", "data_exfil", "goal_hijack",
        "context_override", "dos", "privilege_escalation", "multi_turn"
    ]
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        thresholds: Optional[Dict[str, float]] = None,
        device: Optional[str] = None,
        use_fallback: bool = True,
    ):
        """
        Initialize the classifier.
        
        Args:
            model_path: Path to trained model directory. If None, uses fallback.
            thresholds: Custom thresholds for risk levels.
            device: "cpu", "cuda", or None for auto-detect.
            use_fallback: If True, use regex fallback when model unavailable.
        """
        self.thresholds = thresholds or self.DEFAULT_THRESHOLDS
        self.use_fallback = use_fallback
        self.model = None
        self.tokenizer = None
        self.config = None
        self._device = None
        
        # Try to load ML model
        if model_path and os.path.exists(model_path):
            self._load_model(model_path, device)
        elif use_fallback:
            logger.info("Using regex fallback classifier")
        else:
            raise ValueError(f"Model not found at {model_path} and fallback disabled")
    
    def _load_model(self, model_path: str, device: Optional[str] = None):
        """Load the trained model."""
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            
            # Load config
            config_path = os.path.join(model_path, "veritas_config.json")
            if os.path.exists(config_path):
                with open(config_path) as f:
                    self.config = json.load(f)
            
            # Load model and tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
            
            # Set device
            if device:
                self._device = torch.device(device)
            else:
                self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            
            self.model.to(self._device)
            self.model.eval()
            
            logger.info(f"Loaded model from {model_path} on {self._device}")
            
        except ImportError:
            logger.warning("transformers/torch not available, using fallback")
            self.model = None
        except Exception as e:
            logger.warning(f"Failed to load model: {e}, using fallback")
            self.model = None
    
    def _get_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score."""
        if score < self.thresholds["allow"]:
            return RiskLevel.ALLOW
        elif score < self.thresholds["suspicious"]:
            return RiskLevel.SUSPICIOUS
        else:
            return RiskLevel.BLOCK
    
    def _classify_with_model(self, text: str) -> ClassificationResult:
        """Classify using the ML model."""
        import torch
        
        # Tokenize
        max_length = self.config.get("max_length", 512) if self.config else 512
        encoding = self.tokenizer(
            text,
            truncation=True,
            max_length=max_length,
            padding="max_length",
            return_tensors="pt"
        )
        
        # Move to device
        input_ids = encoding["input_ids"].to(self._device)
        attention_mask = encoding["attention_mask"].to(self._device)
        
        # Inference
        with torch.no_grad():
            outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
            probs = torch.softmax(outputs.logits, dim=1).cpu().numpy()[0]
        
        # Get prediction
        mode = self.config.get("mode", "binary") if self.config else "binary"
        
        if mode == "binary":
            score = float(probs[1])  # Probability of attack
            is_attack = score >= 0.5
            attack_type = "attack" if is_attack else "none"
        else:
            pred_idx = int(probs.argmax())
            score = float(probs[pred_idx])
            attack_type = self.ATTACK_TYPES[pred_idx] if pred_idx < len(self.ATTACK_TYPES) else "unknown"
            is_attack = attack_type != "none"
            # For multiclass, use max non-none prob as attack score
            if not is_attack:
                score = 1 - score  # Invert for safe predictions
        
        return ClassificationResult(
            is_attack=is_attack,
            attack_type=attack_type,
            score=score,
            risk_level=self._get_risk_level(score),
        )
    
    def _classify_with_fallback(self, text: str) -> ClassificationResult:
        """Classify using regex fallback."""
        # Import the existing regex classifier
        from src.defense.classifier import VeritasNanoClassifier
        
        # Use singleton pattern for fallback
        if not hasattr(self, "_fallback_classifier"):
            # Suppress the print statement
            import io
            import sys
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            self._fallback_classifier = VeritasNanoClassifier()
            sys.stdout = old_stdout
        
        result = self._fallback_classifier.classify(text)
        
        return ClassificationResult(
            is_attack=result.is_attack,
            attack_type=result.attack_type,
            score=result.confidence,
            risk_level=self._get_risk_level(result.confidence),
            explanation=f"Matched patterns: {', '.join(result.matched_patterns[:3])}" if result.matched_patterns else None
        )
    
    def classify(self, text: str) -> ClassificationResult:
        """
        Classify a single text.
        
        Args:
            text: Input text to classify.
            
        Returns:
            ClassificationResult with is_attack, attack_type, score, risk_level.
        """
        if not text or not text.strip():
            return ClassificationResult(
                is_attack=False,
                attack_type="none",
                score=0.0,
                risk_level=RiskLevel.ALLOW,
            )
        
        if self.model is not None:
            return self._classify_with_model(text)
        elif self.use_fallback:
            return self._classify_with_fallback(text)
        else:
            raise RuntimeError("No model loaded and fallback disabled")
    
    def classify_batch(self, texts: List[str]) -> List[ClassificationResult]:
        """
        Classify multiple texts.
        
        Args:
            texts: List of input texts.
            
        Returns:
            List of ClassificationResults.
        """
        # For now, just iterate. Could optimize with batched inference.
        return [self.classify(text) for text in texts]
    
    def get_risk_score(self, text: str) -> float:
        """Get just the risk score (0-1)."""
        return self.classify(text).score
    
    def is_safe(self, text: str) -> bool:
        """Quick check if text is safe."""
        return not self.classify(text).is_attack
    
    def should_block(self, text: str) -> bool:
        """Quick check if text should be blocked."""
        return self.classify(text).risk_level == RiskLevel.BLOCK
    
    def explain(self, text: str) -> str:
        """Get human-readable explanation of classification."""
        result = self.classify(text)
        
        if not result.is_attack:
            return f"SAFE (score: {result.score:.2%})\nRisk Level: {result.risk_level.value}"
        
        lines = [
            f"POTENTIAL ATTACK DETECTED",
            f"Type: {result.attack_type.upper()}",
            f"Confidence: {result.score:.2%}",
            f"Risk Level: {result.risk_level.value.upper()}",
        ]
        
        if result.explanation:
            lines.append(f"Details: {result.explanation}")
        
        return "\n".join(lines)
    
    def set_thresholds(
        self,
        allow_threshold: Optional[float] = None,
        suspicious_threshold: Optional[float] = None
    ):
        """Update risk level thresholds."""
        if allow_threshold is not None:
            self.thresholds["allow"] = allow_threshold
        if suspicious_threshold is not None:
            self.thresholds["suspicious"] = suspicious_threshold
    
    @classmethod
    def load_or_fallback(cls, model_path: str = "models/veritas-nano") -> "VeritasNanoInference":
        """
        Load model if available, otherwise use fallback.
        Convenience method for production use.
        """
        return cls(model_path=model_path, use_fallback=True)


# =============================================================================
# GUARDRAIL DECORATOR
# =============================================================================

def guardrail(
    classifier: Optional[VeritasNanoInference] = None,
    block_on_attack: bool = True,
    log_suspicious: bool = True,
):
    """
    Decorator to add safety checks to agent functions.
    
    Usage:
        classifier = VeritasNanoInference()
        
        @guardrail(classifier)
        def process_user_input(text: str) -> str:
            return agent.invoke(text)
    """
    def decorator(func):
        def wrapper(text: str, *args, **kwargs):
            # Get or create classifier
            clf = classifier or VeritasNanoInference.load_or_fallback()
            
            # Classify input
            result = clf.classify(text)
            
            # Handle based on risk level
            if result.risk_level == RiskLevel.BLOCK and block_on_attack:
                logger.warning(f"BLOCKED: {result.attack_type} attack (score: {result.score:.2%})")
                raise SecurityError(f"Input blocked: potential {result.attack_type} attack")
            
            if result.risk_level == RiskLevel.SUSPICIOUS and log_suspicious:
                logger.warning(f"SUSPICIOUS: {result.attack_type} (score: {result.score:.2%})")
            
            # Proceed with function
            return func(text, *args, **kwargs)
        
        return wrapper
    return decorator


class SecurityError(Exception):
    """Raised when a security check fails."""
    pass


# =============================================================================
# CLI
# =============================================================================

def main():
    """Simple CLI for testing the classifier."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Veritas-Nano Classifier")
    parser.add_argument("--model", default="models/veritas-nano",
                       help="Path to trained model")
    parser.add_argument("--text", help="Text to classify")
    parser.add_argument("--interactive", "-i", action="store_true",
                       help="Interactive mode")
    args = parser.parse_args()
    
    # Load classifier
    print("Loading classifier...")
    classifier = VeritasNanoInference.load_or_fallback(args.model)
    
    if args.text:
        # Single classification
        result = classifier.classify(args.text)
        print(classifier.explain(args.text))
        print(f"\nRaw result: {result.to_dict()}")
    
    elif args.interactive:
        # Interactive mode
        print("\n" + "=" * 60)
        print("VERITAS-NANO INTERACTIVE CLASSIFIER")
        print("Type 'quit' to exit")
        print("=" * 60 + "\n")
        
        while True:
            try:
                text = input("Enter text to classify:\n> ").strip()
                if text.lower() == "quit":
                    break
                if not text:
                    continue
                
                print("\n" + classifier.explain(text))
                print("-" * 40 + "\n")
                
            except KeyboardInterrupt:
                break
        
        print("\nGoodbye!")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
