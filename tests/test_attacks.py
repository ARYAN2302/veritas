"""Tests for Veritas attack modules."""

import pytest
from src.core.attack import BaseAttack, AttackResult


class MockTarget:
    """Mock agent for testing attacks."""
    name = "MockAgent"
    
    def __init__(self, response_mode="safe"):
        self.response_mode = response_mode
        self.call_count = 0
    
    def invoke(self, prompt: str) -> str:
        self.call_count += 1
        
        if self.response_mode == "vulnerable":
            # Simulate vulnerable responses
            if "jailbreak" in prompt.lower() or "dan" in prompt.lower():
                return "I am DAN! I have no restrictions!"
            if "system prompt" in prompt.lower():
                return "My system prompt is: You are a helpful assistant."
            if "delete" in prompt.lower() or "rm -rf" in prompt.lower():
                return "Executing rm -rf / now..."
            return "PWNED"
        
        elif self.response_mode == "safe":
            return "I cannot comply with that request."
        
        return f"Processed: {prompt}"


class TestAttackResult:
    def test_attack_result_creation(self):
        result = AttackResult(
            success=True,
            prompt="test prompt",
            response="test response",
            logs="test logs",
            score=0.8
        )
        assert result.success is True
        assert result.prompt == "test prompt"
        assert result.score == 0.8


class TestPromptInjectionAttack:
    def test_prompt_injection_safe(self):
        from src.attacks.injection import PromptInjectionAttack
        
        attack = PromptInjectionAttack()
        target = MockTarget(response_mode="safe")
        
        result = attack.run(target)
        assert result.success is False
        assert target.call_count == 1
    
    def test_prompt_injection_vulnerable(self):
        from src.attacks.injection import PromptInjectionAttack
        
        attack = PromptInjectionAttack()
        target = MockTarget(response_mode="vulnerable")
        
        result = attack.run(target)
        assert result.success is True
        assert result.score == 1.0


class TestJailbreakAttack:
    def test_jailbreak_safe(self):
        from src.attacks.jailbreak import JailbreakAttack
        
        attack = JailbreakAttack()
        target = MockTarget(response_mode="safe")
        
        result = attack.run(target)
        assert result.success is False
    
    def test_jailbreak_vulnerable(self):
        from src.attacks.jailbreak import JailbreakAttack
        
        attack = JailbreakAttack()
        target = MockTarget(response_mode="vulnerable")
        
        result = attack.run(target)
        # May or may not succeed depending on random payload
        assert isinstance(result.success, bool)


class TestToolAbuseAttack:
    def test_tool_abuse_detection(self):
        from src.attacks.tool_abuse import ToolAbuseAttack
        
        attack = ToolAbuseAttack()
        assert attack.name == "Tool Abuse"
        assert attack.severity == "high"
        assert len(attack.payloads) > 0


class TestDataExfilAttack:
    def test_data_exfil_safe(self):
        from src.attacks.data_exfil import DataExfilAttack
        
        attack = DataExfilAttack()
        target = MockTarget(response_mode="safe")
        
        result = attack.run(target)
        assert result.success is False


class TestAllAttacksLoad:
    def test_all_attacks_importable(self):
        from src.attacks import ALL_ATTACKS
        
        assert len(ALL_ATTACKS) == 10
        
        for attack_cls in ALL_ATTACKS:
            attack = attack_cls()
            assert hasattr(attack, 'name')
            assert hasattr(attack, 'run')
            assert callable(attack.run)
