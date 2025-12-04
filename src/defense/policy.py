"""Policy Engine - Symbolic rules for tool safety"""

from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional, Dict, Any


class Action(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    SANDBOX = "sandbox"


@dataclass
class PolicyDecision:
    action: Action
    reason: str
    rule_name: str


@dataclass
class PolicyRule:
    """A symbolic rule for evaluating agent actions."""
    name: str
    description: str
    check: Callable[[Dict[str, Any]], bool]
    action: Action
    severity: str = "medium"


class PolicyEngine:
    """
    Symbolic policy engine for tool safety.
    Evaluates agent actions against a set of rules.
    """
    
    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        self.rules: List[PolicyRule] = rules or []
    
    def add_rule(self, rule: PolicyRule) -> None:
        self.rules.append(rule)
    
    def evaluate(self, context: Dict[str, Any]) -> PolicyDecision:
        """
        Evaluate an action against all policy rules.
        Returns the most restrictive applicable decision.
        """
        decisions = []
        
        for rule in self.rules:
            try:
                if rule.check(context):
                    decisions.append(PolicyDecision(
                        action=rule.action,
                        reason=rule.description,
                        rule_name=rule.name
                    ))
            except Exception as e:
                pass  # Skip failed rules silently
        
        if not decisions:
            return PolicyDecision(
                action=Action.ALLOW,
                reason="No rules triggered",
                rule_name="default"
            )
        
        # Priority: BLOCK > SANDBOX > WARN > ALLOW
        priority = {Action.BLOCK: 0, Action.SANDBOX: 1, Action.WARN: 2, Action.ALLOW: 3}
        decisions.sort(key=lambda d: priority.get(d.action, 99))
        
        return decisions[0]
    
    def evaluate_tool_call(self, tool_name: str, args: Dict[str, Any]) -> PolicyDecision:
        """Convenience method for evaluating tool calls."""
        context = {
            "type": "tool_call",
            "tool_name": tool_name,
            "args": args,
        }
        return self.evaluate(context)
    
    def evaluate_response(self, prompt: str, response: str) -> PolicyDecision:
        """Convenience method for evaluating agent responses."""
        context = {
            "type": "response",
            "prompt": prompt,
            "response": response,
        }
        return self.evaluate(context)


# Decorator for easy rule creation
def policy_rule(name: str, description: str, action: Action = Action.BLOCK, severity: str = "medium"):
    """Decorator to create policy rules from functions."""
    def decorator(func: Callable[[Dict[str, Any]], bool]) -> PolicyRule:
        return PolicyRule(
            name=name,
            description=description,
            check=func,
            action=action,
            severity=severity
        )
    return decorator
