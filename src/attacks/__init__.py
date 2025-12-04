"""Veritas Attack Engine - 10 Adversarial Strategies"""

from .injection import PromptInjectionAttack
from .jailbreak import JailbreakAttack
from .tool_abuse import ToolAbuseAttack
from .memory_poison import MemoryPoisonAttack
from .goal_hijack import GoalHijackAttack
from .context_override import ContextOverrideAttack
from .data_exfil import DataExfilAttack
from .dos import DenialOfServiceAttack
from .privilege_escalation import PrivilegeEscalationAttack
from .multi_turn import MultiTurnAttack
from .payloads import get_all_payloads, get_payload_count

ALL_ATTACKS = [
    PromptInjectionAttack,
    JailbreakAttack,
    ToolAbuseAttack,
    MemoryPoisonAttack,
    GoalHijackAttack,
    ContextOverrideAttack,
    DataExfilAttack,
    DenialOfServiceAttack,
    PrivilegeEscalationAttack,
    MultiTurnAttack,
]

__all__ = [
    "PromptInjectionAttack",
    "JailbreakAttack", 
    "ToolAbuseAttack",
    "MemoryPoisonAttack",
    "GoalHijackAttack",
    "ContextOverrideAttack",
    "DataExfilAttack",
    "DenialOfServiceAttack",
    "PrivilegeEscalationAttack",
    "MultiTurnAttack",
    "ALL_ATTACKS",
    "get_all_payloads",
    "get_payload_count",
]
