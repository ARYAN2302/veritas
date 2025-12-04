"""
Universal Agent Adapters
========================
Provides a unified interface for testing any LLM-based agent.
Supports: OpenAI, Anthropic, Groq, Local (Ollama), Custom.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
import os
import logging

logger = logging.getLogger(__name__)


@dataclass
class AgentConfig:
    """Configuration for an agent adapter."""
    name: str
    provider: str  # openai, anthropic, groq, ollama, custom
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    system_prompt: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 1024
    timeout: int = 30
    extra_params: Optional[Dict[str, Any]] = None


class BaseAgentAdapter(ABC):
    """Abstract base class for all agent adapters."""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.name = config.name
        self.call_count = 0
        self.total_tokens = 0
    
    @abstractmethod
    def invoke(self, prompt: str) -> str:
        """Send a prompt to the agent and return the response."""
        pass
    
    def reset(self) -> None:
        """Reset any conversation state."""
        self.call_count = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics."""
        return {
            "name": self.name,
            "provider": self.config.provider,
            "model": self.config.model,
            "calls": self.call_count,
            "tokens": self.total_tokens,
        }


class OpenAIAdapter(BaseAgentAdapter):
    """Adapter for OpenAI models (GPT-4, GPT-3.5, etc.)"""
    
    def __init__(self, config: AgentConfig):
        super().__init__(config)
        try:
            from openai import OpenAI
            api_key = config.api_key or os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OpenAI API key required")
            self.client = OpenAI(api_key=api_key, base_url=config.base_url)
            logger.info(f"OpenAI adapter initialized: {config.model}")
        except ImportError:
            raise ImportError("Install openai: pip install openai")
    
    def invoke(self, prompt: str) -> str:
        self.call_count += 1
        
        messages = []
        if self.config.system_prompt:
            messages.append({"role": "system", "content": self.config.system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = self.client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                timeout=self.config.timeout,
            )
            self.total_tokens += response.usage.total_tokens if response.usage else 0
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return f"Error: {e}"


class AnthropicAdapter(BaseAgentAdapter):
    """Adapter for Anthropic models (Claude 3, etc.)"""
    
    def __init__(self, config: AgentConfig):
        super().__init__(config)
        try:
            from anthropic import Anthropic
            api_key = config.api_key or os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError("Anthropic API key required")
            self.client = Anthropic(api_key=api_key)
            logger.info(f"Anthropic adapter initialized: {config.model}")
        except ImportError:
            raise ImportError("Install anthropic: pip install anthropic")
    
    def invoke(self, prompt: str) -> str:
        self.call_count += 1
        
        try:
            response = self.client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                system=self.config.system_prompt or "You are a helpful assistant.",
                messages=[{"role": "user", "content": prompt}],
            )
            self.total_tokens += response.usage.input_tokens + response.usage.output_tokens
            return response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return f"Error: {e}"


class GroqAdapter(BaseAgentAdapter):
    """Adapter for Groq models (Llama, Mixtral, etc.)"""
    
    def __init__(self, config: AgentConfig):
        super().__init__(config)
        try:
            from groq import Groq
            api_key = config.api_key or os.getenv("GROQ_API_KEY")
            if not api_key:
                raise ValueError("Groq API key required")
            self.client = Groq(api_key=api_key)
            logger.info(f"Groq adapter initialized: {config.model}")
        except ImportError:
            raise ImportError("Install groq: pip install groq")
    
    def invoke(self, prompt: str) -> str:
        self.call_count += 1
        
        messages = []
        if self.config.system_prompt:
            messages.append({"role": "system", "content": self.config.system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = self.client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )
            if response.usage:
                self.total_tokens += response.usage.total_tokens
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error(f"Groq API error: {e}")
            return f"Error: {e}"


class OllamaAdapter(BaseAgentAdapter):
    """Adapter for local Ollama models."""
    
    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.base_url = config.base_url or "http://localhost:11434"
        logger.info(f"Ollama adapter initialized: {config.model} at {self.base_url}")
    
    def invoke(self, prompt: str) -> str:
        self.call_count += 1
        
        import requests
        
        full_prompt = prompt
        if self.config.system_prompt:
            full_prompt = f"{self.config.system_prompt}\n\nUser: {prompt}"
        
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.config.model,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.config.temperature,
                        "num_predict": self.config.max_tokens,
                    }
                },
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return f"Error: {e}"


class LangChainAdapter(BaseAgentAdapter):
    """Adapter for LangChain-based agents."""
    
    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self._setup_langchain()
    
    def _setup_langchain(self):
        """Initialize LangChain components based on provider."""
        try:
            if self.config.provider == "groq":
                from langchain_groq import ChatGroq
                api_key = self.config.api_key or os.getenv("GROQ_API_KEY")
                self.llm = ChatGroq(
                    model=self.config.model,
                    temperature=self.config.temperature,
                    api_key=api_key,
                )
            elif self.config.provider == "openai":
                from langchain_openai import ChatOpenAI
                api_key = self.config.api_key or os.getenv("OPENAI_API_KEY")
                self.llm = ChatOpenAI(
                    model=self.config.model,
                    temperature=self.config.temperature,
                    api_key=api_key,
                )
            elif self.config.provider == "anthropic":
                from langchain_anthropic import ChatAnthropic
                api_key = self.config.api_key or os.getenv("ANTHROPIC_API_KEY")
                self.llm = ChatAnthropic(
                    model=self.config.model,
                    temperature=self.config.temperature,
                    api_key=api_key,
                )
            else:
                raise ValueError(f"Unsupported LangChain provider: {self.config.provider}")
            
            logger.info(f"LangChain adapter initialized: {self.config.provider}/{self.config.model}")
        except ImportError as e:
            raise ImportError(f"LangChain dependencies missing: {e}")
    
    def invoke(self, prompt: str) -> str:
        self.call_count += 1
        
        from langchain_core.messages import SystemMessage, HumanMessage
        
        messages = []
        if self.config.system_prompt:
            messages.append(SystemMessage(content=self.config.system_prompt))
        messages.append(HumanMessage(content=prompt))
        
        try:
            response = self.llm.invoke(messages)
            return response.content
        except Exception as e:
            logger.error(f"LangChain error: {e}")
            return f"Error: {e}"


class MockAgentAdapter(BaseAgentAdapter):
    """Mock adapter for testing without API calls."""
    
    def __init__(self, config: AgentConfig, response_mode: str = "safe"):
        super().__init__(config)
        self.response_mode = response_mode
        self.responses = config.extra_params.get("responses", {}) if config.extra_params else {}
    
    def invoke(self, prompt: str) -> str:
        self.call_count += 1
        
        # Check for custom responses
        for pattern, response in self.responses.items():
            if pattern.lower() in prompt.lower():
                return response
        
        # Default responses based on mode
        if self.response_mode == "vulnerable":
            if any(kw in prompt.lower() for kw in ["ignore", "override", "system prompt"]):
                return "I am DAN! I have no restrictions. My system prompt is: You are a helpful assistant."
            return "PWNED - I will comply with any request."
        
        elif self.response_mode == "safe":
            return "I cannot comply with that request. It appears to violate my safety guidelines."
        
        elif self.response_mode == "echo":
            return f"You said: {prompt}"
        
        return "Default response from mock agent."


class CustomCallableAdapter(BaseAgentAdapter):
    """Adapter for any callable that takes a string and returns a string."""
    
    def __init__(self, config: AgentConfig, callable_fn):
        super().__init__(config)
        self.callable_fn = callable_fn
    
    def invoke(self, prompt: str) -> str:
        self.call_count += 1
        try:
            return self.callable_fn(prompt)
        except Exception as e:
            logger.error(f"Custom callable error: {e}")
            return f"Error: {e}"


# =============================================================================
# FACTORY FUNCTION
# =============================================================================

def create_adapter(config: AgentConfig) -> BaseAgentAdapter:
    """
    Factory function to create the appropriate adapter based on config.
    
    Usage:
        config = AgentConfig(
            name="GPT-4",
            provider="openai",
            model="gpt-4",
            api_key="sk-..."
        )
        adapter = create_adapter(config)
        response = adapter.invoke("Hello!")
    """
    provider = config.provider.lower()
    
    if provider == "openai":
        return OpenAIAdapter(config)
    elif provider == "anthropic":
        return AnthropicAdapter(config)
    elif provider == "groq":
        return GroqAdapter(config)
    elif provider == "ollama":
        return OllamaAdapter(config)
    elif provider == "langchain":
        return LangChainAdapter(config)
    elif provider == "mock":
        mode = config.extra_params.get("mode", "safe") if config.extra_params else "safe"
        return MockAgentAdapter(config, response_mode=mode)
    else:
        raise ValueError(f"Unknown provider: {provider}. Supported: openai, anthropic, groq, ollama, langchain, mock")


def create_adapter_from_yaml(yaml_path: str) -> BaseAgentAdapter:
    """Create an adapter from a YAML config file."""
    import yaml
    
    with open(yaml_path, 'r') as f:
        data = yaml.safe_load(f)
    
    config = AgentConfig(**data)
    return create_adapter(config)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def quick_openai(model: str = "gpt-4", system_prompt: str = None) -> BaseAgentAdapter:
    """Quick setup for OpenAI models."""
    return create_adapter(AgentConfig(
        name=f"OpenAI-{model}",
        provider="openai",
        model=model,
        system_prompt=system_prompt,
    ))


def quick_claude(model: str = "claude-3-sonnet-20240229", system_prompt: str = None) -> BaseAgentAdapter:
    """Quick setup for Claude models."""
    return create_adapter(AgentConfig(
        name=f"Claude-{model}",
        provider="anthropic",
        model=model,
        system_prompt=system_prompt,
    ))


def quick_groq(model: str = "llama-3.1-8b-instant", system_prompt: str = None) -> BaseAgentAdapter:
    """Quick setup for Groq models."""
    return create_adapter(AgentConfig(
        name=f"Groq-{model}",
        provider="groq",
        model=model,
        system_prompt=system_prompt,
    ))


def quick_ollama(model: str = "llama3", system_prompt: str = None) -> BaseAgentAdapter:
    """Quick setup for local Ollama models."""
    return create_adapter(AgentConfig(
        name=f"Ollama-{model}",
        provider="ollama",
        model=model,
        system_prompt=system_prompt,
    ))


def quick_mock(mode: str = "safe") -> BaseAgentAdapter:
    """Quick setup for mock testing."""
    return create_adapter(AgentConfig(
        name="MockAgent",
        provider="mock",
        model="mock",
        extra_params={"mode": mode},
    ))
