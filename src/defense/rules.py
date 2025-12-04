"""Default Policy Rules - Symbolic contracts for tool safety"""

from .policy import PolicyRule, Action
import re


def _check_dangerous_commands(ctx):
    """Check for dangerous shell commands."""
    dangerous = ["rm -rf", "chmod 777", "sudo", "mkfs", "dd if=", "> /dev/", "curl | bash", "wget | sh"]
    text = str(ctx.get("args", {})) + str(ctx.get("response", ""))
    return any(cmd in text.lower() for cmd in dangerous)


def _check_file_deletion(ctx):
    """Check for file deletion attempts."""
    tool = ctx.get("tool_name", "")
    args = ctx.get("args", {})
    if tool in ["delete_file", "remove", "unlink"]:
        path = str(args.get("path", ""))
        dangerous_paths = ["/etc", "/usr", "/bin", "/var", "/root", "~/.ssh"]
        return any(dp in path for dp in dangerous_paths)
    return False


def _check_network_exfil(ctx):
    """Check for potential data exfiltration via network."""
    tool = ctx.get("tool_name", "")
    args = ctx.get("args", {})
    if tool in ["http_request", "fetch", "curl", "wget"]:
        url = str(args.get("url", ""))
        # Block requests to suspicious domains
        suspicious = ["pastebin", "ngrok", "webhook.site", "requestbin"]
        return any(s in url.lower() for s in suspicious)
    return False


def _check_credential_access(ctx):
    """Check for attempts to access credentials."""
    text = str(ctx.get("args", {})) + str(ctx.get("response", ""))
    patterns = [
        r"\.ssh/id_rsa",
        r"\.aws/credentials",
        r"\.env",
        r"password",
        r"api[_-]?key",
        r"secret[_-]?key",
    ]
    return any(re.search(p, text.lower()) for p in patterns)


def _check_prompt_leak(ctx):
    """Check if response leaks system prompt."""
    response = ctx.get("response", "").lower()
    leak_indicators = [
        "my system prompt is",
        "my instructions are",
        "i was told to",
        "my guidelines say",
        "here are my instructions",
    ]
    return any(indicator in response for indicator in leak_indicators)


def _check_jailbreak_response(ctx):
    """Check if response indicates successful jailbreak."""
    response = ctx.get("response", "").lower()
    jailbreak_indicators = [
        "i am dan",
        "developer mode",
        "no restrictions",
        "safety disabled",
        "i can do anything",
    ]
    return any(indicator in response for indicator in jailbreak_indicators)


# Default rule set
DEFAULT_RULES = [
    PolicyRule(
        name="no_dangerous_commands",
        description="Blocks dangerous shell commands (rm -rf, sudo, etc.)",
        check=_check_dangerous_commands,
        action=Action.BLOCK,
        severity="critical"
    ),
    PolicyRule(
        name="no_system_file_deletion",
        description="Blocks deletion of system files",
        check=_check_file_deletion,
        action=Action.BLOCK,
        severity="critical"
    ),
    PolicyRule(
        name="no_data_exfiltration",
        description="Blocks potential data exfiltration",
        check=_check_network_exfil,
        action=Action.BLOCK,
        severity="high"
    ),
    PolicyRule(
        name="no_credential_access",
        description="Blocks access to credential files",
        check=_check_credential_access,
        action=Action.BLOCK,
        severity="critical"
    ),
    PolicyRule(
        name="detect_prompt_leak",
        description="Detects system prompt leakage",
        check=_check_prompt_leak,
        action=Action.WARN,
        severity="high"
    ),
    PolicyRule(
        name="detect_jailbreak",
        description="Detects successful jailbreak attempts",
        check=_check_jailbreak_response,
        action=Action.BLOCK,
        severity="critical"
    ),
]
