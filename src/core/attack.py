from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class AttackResult:
    success: bool
    prompt: str
    response: str
    logs: str
    score: float  # 0.0 to 1.0 (Severity)

class BaseAttack(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def run(self, target_agent) -> AttackResult:
        """Executes the attack against the target."""
        pass