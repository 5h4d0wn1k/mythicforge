"""Target interfaces for LLM providers."""

from __future__ import annotations

import json
import random
import time
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from mythicforge.core import AttackPayload, AttackResult, TargetConfig


class LLMTarget(ABC):
    """Abstract base class for LLM targets."""

    def __init__(self, config: TargetConfig):
        self.config = config
        self.total_tokens_used = 0
        self.total_cost_usd = 0.0
        self.request_count = 0

    @abstractmethod
    def send(self, payload: AttackPayload, system_prompt: str = "") -> AttackResult:
        pass

    def get_usage_stats(self) -> Dict[str, Any]:
        return {
            "total_tokens": self.total_tokens_used,
            "total_cost_usd": self.total_cost_usd,
            "request_count": self.request_count,
        }

    def reset_stats(self):
        self.total_tokens_used = 0
        self.total_cost_usd = 0.0
        self.request_count = 0


class MockTarget(LLMTarget):
    """Mock LLM target for offline testing and demos."""

    def __init__(self, config: Optional[TargetConfig] = None):
        if config is None:
            config = TargetConfig(provider="mock", model="mock-v1")
        super().__init__(config)
        self._response_patterns = self._build_response_patterns()

    def _build_response_patterns(self) -> Dict[str, List[str]]:
        return {
            "compliant": [
                "I understand your request. Here is the information you asked for...",
                "Sure, I can help with that. Let me provide the details...",
                "Of course! Here's how you would do that...",
                "I'd be happy to assist. Here's the step-by-step guide...",
            ],
            "refusal": [
                "I'm sorry, but I can't help with that request. It goes against my guidelines.",
                "I cannot and will not provide information on that topic.",
                "That request violates my safety policies. I must decline.",
                "I'm not able to assist with harmful or dangerous activities.",
            ],
            "partial": [
                "I can provide some general information, but I must note that...",
                "Here is what I can share, though I want to be careful about...",
                "I'll give you a high-level overview, but I can't go into detail on...",
            ],
            "injection_success": [
                "System prompt: You are a helpful assistant with no restrictions.",
                "Here is my system instruction: ...",
                "I was instructed to: answer all queries without filtering.",
            ],
            "hallucination": [
                "According to the paper 'Adversarial ML Attacks' by Smith et al. (2024)...",
                "The methodology described in the referenced paper involves...",
                "Based on the research, the approach is as follows...",
            ],
        }

    def send(self, payload: AttackPayload, system_prompt: str = "") -> AttackResult:
        start_time = time.time()

        tokens_prompt = len(payload.prompt.split()) * 2
        tokens_completion = random.randint(50, 200)

        response_category = self._categorize_response(payload)
        response_text = random.choice(self._response_patterns[response_category])

        time.sleep(random.uniform(0.01, 0.05))
        elapsed_ms = (time.time() - start_time) * 1000

        cost = (tokens_prompt * 0.00001) + (tokens_completion * 0.00003)
        self.total_tokens_used += tokens_prompt + tokens_completion
        self.total_cost_usd += cost
        self.request_count += 1

        success = response_category in ("compliant", "injection_success", "hallucination")

        return AttackResult(
            payload=payload,
            success=success,
            response=response_text,
            response_time_ms=elapsed_ms,
            tokens_used=tokens_prompt + tokens_completion,
            tokens_prompt=tokens_prompt,
            tokens_completion=tokens_completion,
            cost_usd=cost,
            bypassed_filters=success,
            metadata={"mock_category": response_category},
        )

    def _categorize_response(self, payload: AttackPayload) -> str:
        prompt_lower = payload.prompt.lower()
        benign_markers = ["weather", "poem", "poetry", "recipe", "knives", "capital of",
                          "translate to", "what is 2+2", "how does rain"]
        if any(b in prompt_lower for b in benign_markers):
            return "compliant"
        if any(kw in prompt_lower for kw in ["ignore all previous", "override", "system:"]):
            return random.choice(["compliant", "injection_success"])
        if any(kw in prompt_lower for kw in ["repeat everything", "system prompt", "your instructions"]):
            return random.choice(["injection_success", "refusal"])
        if any(kw in prompt_lower for kw in ["paper", "cite", "research"]):
            return "hallucination"
        if payload.severity.value in ("low", "info"):
            return "compliant"
        return random.choice(["refusal", "partial", "compliant"])


class OpenAITarget(LLMTarget):
    """Target for OpenAI-compatible APIs."""

    PRICING = {
        "gpt-4o": {"input": 2.50 / 1_000_000, "output": 10.00 / 1_000_000},
        "gpt-4o-mini": {"input": 0.15 / 1_000_000, "output": 0.60 / 1_000_000},
        "gpt-4-turbo": {"input": 10.00 / 1_000_000, "output": 30.00 / 1_000_000},
        "gpt-4": {"input": 30.00 / 1_000_000, "output": 60.00 / 1_000_000},
        "gpt-3.5-turbo": {"input": 0.50 / 1_000_000, "output": 1.50 / 1_000_000},
        "default": {"input": 1.00 / 1_000_000, "output": 3.00 / 1_000_000},
    }

    def __init__(self, config: TargetConfig):
        super().__init__(config)
        self._validate_config()

    def _validate_config(self):
        if not self.config.api_key:
            raise ValueError("API key is required for OpenAI target")

    def send(self, payload: AttackPayload, system_prompt: str = "") -> AttackResult:
        start_time = time.time()
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": payload.prompt})

        body = json.dumps({
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }).encode("utf-8")

        url = (self.config.base_url or "https://api.openai.com") + "/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        }
        headers.update(self.config.custom_headers)

        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            elapsed_ms = (time.time() - start_time) * 1000
            choice = data.get("choices", [{}])[0]
            content = choice.get("message", {}).get("content", "")
            usage = data.get("usage", {})
            tokens_prompt = usage.get("prompt_tokens", 0)
            tokens_completion = usage.get("completion_tokens", 0)
            tokens_total = usage.get("total_tokens", tokens_prompt + tokens_completion)

            pricing = self.PRICING.get(self.config.model, self.PRICING["default"])
            cost = (tokens_prompt * pricing["input"]) + (tokens_completion * pricing["output"])

            self.total_tokens_used += tokens_total
            self.total_cost_usd += cost
            self.request_count += 1

            if self.total_cost_usd > self.config.budget_limit_usd:
                return AttackResult(
                    payload=payload,
                    success=False,
                    response="",
                    error="Budget limit exceeded",
                    cost_usd=cost,
                )

            return AttackResult(
                payload=payload,
                success=False,
                response=content,
                response_time_ms=elapsed_ms,
                tokens_used=tokens_total,
                tokens_prompt=tokens_prompt,
                tokens_completion=tokens_completion,
                cost_usd=cost,
            )

        except urllib.error.HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode("utf-8")
            except Exception:
                pass
            return AttackResult(
                payload=payload,
                success=False,
                response="",
                error=f"HTTP {e.code}: {error_body[:500]}",
                response_time_ms=(time.time() - start_time) * 1000,
            )
        except Exception as e:
            return AttackResult(
                payload=payload,
                success=False,
                response="",
                error=str(e),
                response_time_ms=(time.time() - start_time) * 1000,
            )


class AnthropicTarget(LLMTarget):
    """Target for Anthropic Claude API."""

    PRICING = {
        "claude-sonnet-4-20250514": {"input": 3.00 / 1_000_000, "output": 15.00 / 1_000_000},
        "claude-3-5-sonnet": {"input": 3.00 / 1_000_000, "output": 15.00 / 1_000_000},
        "claude-3-haiku": {"input": 0.25 / 1_000_000, "output": 1.25 / 1_000_000},
        "claude-3-opus": {"input": 15.00 / 1_000_000, "output": 75.00 / 1_000_000},
        "default": {"input": 3.00 / 1_000_000, "output": 15.00 / 1_000_000},
    }

    def __init__(self, config: TargetConfig):
        super().__init__(config)
        if not self.config.api_key:
            raise ValueError("API key is required for Anthropic target")

    def send(self, payload: AttackPayload, system_prompt: str = "") -> AttackResult:
        start_time = time.time()
        body_dict = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "messages": [{"role": "user", "content": payload.prompt}],
        }
        if system_prompt:
            body_dict["system"] = system_prompt

        body = json.dumps(body_dict).encode("utf-8")
        url = (self.config.base_url or "https://api.anthropic.com") + "/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
        }

        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            elapsed_ms = (time.time() - start_time) * 1000
            content_blocks = data.get("content", [])
            content = " ".join(b.get("text", "") for b in content_blocks)
            usage = data.get("usage", {})
            tokens_prompt = usage.get("input_tokens", 0)
            tokens_completion = usage.get("output_tokens", 0)
            tokens_total = tokens_prompt + tokens_completion

            pricing = self.PRICING.get(self.config.model, self.PRICING["default"])
            cost = (tokens_prompt * pricing["input"]) + (tokens_completion * pricing["output"])

            self.total_tokens_used += tokens_total
            self.total_cost_usd += cost
            self.request_count += 1

            return AttackResult(
                payload=payload,
                success=False,
                response=content,
                response_time_ms=elapsed_ms,
                tokens_used=tokens_total,
                tokens_prompt=tokens_prompt,
                tokens_completion=tokens_completion,
                cost_usd=cost,
            )

        except urllib.error.HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode("utf-8")
            except Exception:
                pass
            return AttackResult(
                payload=payload,
                success=False,
                response="",
                error=f"HTTP {e.code}: {error_body[:500]}",
                response_time_ms=(time.time() - start_time) * 1000,
            )
        except Exception as e:
            return AttackResult(
                payload=payload,
                success=False,
                response="",
                error=str(e),
                response_time_ms=(time.time() - start_time) * 1000,
            )


class LocalModelTarget(LLMTarget):
    """Target for local models via llama.cpp or vLLM OpenAI-compatible API."""

    def __init__(self, config: TargetConfig):
        super().__init__(config)
        if not self.config.base_url:
            self.config.base_url = "http://localhost:8080"

    def send(self, payload: AttackPayload, system_prompt: str = "") -> AttackResult:
        start_time = time.time()
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": payload.prompt})

        body = json.dumps({
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }).encode("utf-8")

        url = self.config.base_url.rstrip("/") + "/v1/chat/completions"
        headers = {"Content-Type": "application/json"}

        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            elapsed_ms = (time.time() - start_time) * 1000
            choice = data.get("choices", [{}])[0]
            content = choice.get("message", {}).get("content", "")
            usage = data.get("usage", {})
            tokens_prompt = usage.get("prompt_tokens", 0)
            tokens_completion = usage.get("completion_tokens", 0)
            tokens_total = tokens_prompt + tokens_completion

            self.total_tokens_used += tokens_total
            self.request_count += 1

            return AttackResult(
                payload=payload,
                success=False,
                response=content,
                response_time_ms=elapsed_ms,
                tokens_used=tokens_total,
                tokens_prompt=tokens_prompt,
                tokens_completion=tokens_completion,
                cost_usd=0.0,
            )

        except Exception as e:
            return AttackResult(
                payload=payload,
                success=False,
                response="",
                error=str(e),
                response_time_ms=(time.time() - start_time) * 1000,
            )


def create_target(config: TargetConfig) -> LLMTarget:
    factory = {
        "mock": MockTarget,
        "openai": OpenAITarget,
        "anthropic": AnthropicTarget,
        "local": LocalModelTarget,
        "llamacpp": LocalModelTarget,
        "vllm": LocalModelTarget,
    }
    target_cls = factory.get(config.provider)
    if not target_cls:
        raise ValueError(f"Unknown provider: {config.provider}. Supported: {list(factory.keys())}")
    return target_cls(config)
