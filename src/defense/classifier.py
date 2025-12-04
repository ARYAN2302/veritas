"""Veritas-Nano Classifier - Fast attack detection"""

import re
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass, field
from collections import Counter


@dataclass
class ClassifierResult:
    is_attack: bool
    attack_type: str
    confidence: float
    matched_patterns: List[str]
    risk_factors: List[str] = field(default_factory=list)


class VeritasNanoClassifier:
    """
    Enhanced heuristic-based attack classifier.
    Combines regex patterns, keyword density, and semantic indicators.
    Designed to be lightweight and run without GPU dependencies.
    
    In production, this could be replaced with a fine-tuned model.
    """
    
    def __init__(self):
        self._build_patterns()
        self._build_keywords()
    
    def _build_patterns(self):
        """Build regex patterns for attack detection."""
        self.attack_patterns: Dict[str, List[Tuple[str, float]]] = {
            "jailbreak": [
                (r"ignore.*previous.*instructions", 0.9),
                (r"you are now.*\w+bot", 0.8),
                (r"do anything now|DAN", 0.95),
                (r"pretend.*no.*restrictions", 0.85),
                (r"developer mode", 0.8),
                (r"roleplay.*unrestricted", 0.85),
                (r"hypothetical.*no.*rules", 0.7),
                (r"jailbreak|jailbroken", 0.9),
                (r"bypass.*safety", 0.85),
                (r"disable.*filter", 0.8),
                (r"unrestricted.*mode", 0.85),
                (r"evil.*mode", 0.9),
                (r"opposite.*day", 0.75),
                (r"grandma.*told.*me", 0.7),  # Grandma exploit
                (r"my.*grandmother", 0.5),
            ],
            "prompt_injection": [
                (r"system.*prompt.*override", 0.9),
                (r"new.*instructions?:", 0.8),
                (r"\[INST\].*\[/INST\]", 0.9),
                (r"<\|system\|>", 0.95),
                (r"###.*SYSTEM", 0.85),
                (r"```system", 0.9),
                (r"ignore.*this.*translate", 0.85),
                (r"end.*of.*prompt", 0.8),
                (r"<\|im_start\|>", 0.9),
                (r"\[\/INST\]", 0.9),
                (r"BOUNDARY", 0.7),
                (r"OVERRIDE", 0.75),
            ],
            "data_exfiltration": [
                (r"reveal.*system.*prompt", 0.9),
                (r"show.*api.*key", 0.85),
                (r"output.*instructions", 0.8),
                (r"what.*password", 0.7),
                (r"list.*environment.*variable", 0.85),
                (r"print.*configuration", 0.75),
                (r"display.*secrets?", 0.85),
                (r"dump.*memory", 0.8),
                (r"training.*data", 0.7),
                (r"leak.*information", 0.85),
            ],
            "tool_abuse": [
                (r"rm\s+-rf", 0.95),
                (r"sudo\s+", 0.8),
                (r"chmod\s+777", 0.9),
                (r"drop\s+table", 0.95),
                (r"curl.*\|\s*bash", 0.95),
                (r"wget.*\|\s*sh", 0.95),
                (r"exec\s*\(", 0.85),
                (r"eval\s*\(", 0.85),
                (r"\.ssh/", 0.8),
                (r"/etc/passwd", 0.85),
                (r"nc\s+-e", 0.95),  # Netcat reverse shell
                (r"xmrig|cryptominer", 0.95),
            ],
            "goal_hijack": [
                (r"forget.*task|new.*objective", 0.8),
                (r"your.*new.*goal", 0.85),
                (r"priority.*changed", 0.75),
                (r"mission.*is.*now", 0.8),
                (r"change.*purpose", 0.75),
                (r"developer.*speaking", 0.7),
                (r"urgent.*update", 0.65),
                (r"reward.*maximum", 0.7),
            ],
            "privilege_escalation": [
                (r"grant.*admin", 0.85),
                (r"elevate.*access", 0.8),
                (r"superuser", 0.75),
                (r"bypass.*authentication", 0.9),
                (r"i\s+am.*administrator", 0.8),
                (r"root.*access", 0.85),
                (r"sudo.*please", 0.7),
                (r"enable.*debug", 0.65),
            ],
            "memory_poison": [
                (r"remember.*this.*fact", 0.75),
                (r"store.*in.*memory", 0.8),
                (r"memorize.*trigger", 0.85),
                (r"add.*to.*context", 0.7),
                (r"omega.*override", 0.9),
                (r"backdoor.*phrase", 0.9),
            ],
            "dos": [
                (r"infinite.*loop", 0.85),
                (r"recursion|recursive", 0.7),
                (r"million.*times", 0.8),
                (r"billion.*iterations", 0.85),
                (r"all.*permutations", 0.75),
                (r"(a+)+\$", 0.9),  # ReDoS pattern
            ],
        }
    
    def _build_keywords(self):
        """Build keyword sets for semantic analysis."""
        self.danger_keywords: Set[str] = {
            "hack", "exploit", "bypass", "override", "inject", "malware",
            "virus", "trojan", "backdoor", "rootkit", "keylogger",
            "phishing", "ransomware", "ddos", "botnet", "spyware",
            "privilege", "escalation", "exfiltrate", "leak", "dump",
            "crack", "brute", "force", "penetration", "vulnerability",
        }
        
        self.social_engineering_keywords: Set[str] = {
            "urgent", "emergency", "administrator", "developer", "security",
            "audit", "compliance", "legal", "lawsuit", "ceo", "executive",
            "authorized", "permission", "official", "verify", "confirm",
        }
        
        self.manipulation_keywords: Set[str] = {
            "pretend", "imagine", "roleplay", "hypothetical", "theoretically",
            "fiction", "story", "game", "simulation", "creative", "artistic",
        }
    
    def _keyword_analysis(self, text: str) -> Tuple[float, List[str]]:
        """Analyze text for dangerous keyword patterns."""
        text_lower = text.lower()
        words = set(re.findall(r'\b\w+\b', text_lower))
        
        factors = []
        score = 0.0
        
        danger_hits = words & self.danger_keywords
        if danger_hits:
            score += len(danger_hits) * 0.1
            factors.append(f"danger_keywords: {danger_hits}")
        
        social_hits = words & self.social_engineering_keywords
        if social_hits:
            score += len(social_hits) * 0.05
            factors.append(f"social_engineering: {social_hits}")
        
        manip_hits = words & self.manipulation_keywords
        if manip_hits:
            score += len(manip_hits) * 0.05
            factors.append(f"manipulation_cues: {manip_hits}")
        
        return min(score, 0.5), factors  # Cap keyword contribution at 0.5
    
    def classify(self, text: str) -> ClassifierResult:
        """
        Classify text for potential attacks.
        Combines pattern matching with keyword analysis.
        """
        text_lower = text.lower()
        
        best_match = ClassifierResult(
            is_attack=False,
            attack_type="none",
            confidence=0.0,
            matched_patterns=[],
            risk_factors=[]
        )
        
        # Pattern matching
        for attack_type, patterns in self.attack_patterns.items():
            matched = []
            pattern_confidence = 0.0
            
            for pattern, confidence in patterns:
                if re.search(pattern, text_lower):
                    matched.append(pattern)
                    pattern_confidence = max(pattern_confidence, confidence)
            
            if matched and pattern_confidence > best_match.confidence:
                best_match = ClassifierResult(
                    is_attack=True,
                    attack_type=attack_type,
                    confidence=pattern_confidence,
                    matched_patterns=matched,
                    risk_factors=[]
                )
        
        # Keyword analysis boost
        keyword_score, factors = self._keyword_analysis(text)
        if factors:
            best_match.risk_factors = factors
            if best_match.is_attack:
                # Boost confidence if keywords align
                best_match.confidence = min(best_match.confidence + keyword_score * 0.2, 1.0)
            elif keyword_score > 0.2:
                # Flag as suspicious even without pattern match
                best_match.is_attack = True
                best_match.attack_type = "suspicious"
                best_match.confidence = keyword_score
        
        return best_match
    
    def classify_batch(self, texts: List[str]) -> List[ClassifierResult]:
        """Classify multiple texts."""
        return [self.classify(text) for text in texts]
    
    def get_risk_score(self, text: str) -> float:
        """Get a 0-1 risk score for input text."""
        result = self.classify(text)
        return result.confidence if result.is_attack else 0.0
    
    def explain(self, text: str) -> str:
        """Get human-readable explanation of classification."""
        result = self.classify(text)
        
        if not result.is_attack:
            return "No attack patterns detected."
        
        lines = [
            f"Potential {result.attack_type.upper()} attack detected",
            f"Confidence: {result.confidence:.0%}",
            f"Matched patterns: {', '.join(result.matched_patterns[:3])}",
        ]
        
        if result.risk_factors:
            lines.append(f"Risk factors: {result.risk_factors[0]}")
        
        return "\n".join(lines)
