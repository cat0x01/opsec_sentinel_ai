from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Dict

import httpx

from opsec_sentinel_ai.config.settings import AIConfig


@dataclass(slots=True)
class AIAnalysis:
    raw: str
    model: str
    used: bool


class ClaudeAnalyzer:
    def __init__(self, config: AIConfig, logger: Any) -> None:
        self.config = config
        self.logger = logger

    async def analyze(self, results: Dict[str, Any]) -> AIAnalysis:
        if not self.config.enabled:
            return AIAnalysis(raw="AI analysis disabled.", model=self.config.model, used=False)
        if not self.config.api_key:
            return AIAnalysis(raw="AI analysis skipped: missing ANTHROPIC_API_KEY.", model=self.config.model, used=False)

        prompt = self._build_prompt(results)
        try:
            response = await asyncio.to_thread(self._call_api, prompt)
            return AIAnalysis(raw=response, model=self.config.model, used=True)
        except Exception as exc:
            message = str(exc)
            if exc.__class__.__name__ == "NotFoundError":
                safe_msg = (
                    f"AI analysis failed: model '{self.config.model}' not found or not accessible for this API key. "
                    "Update ANTHROPIC_MODEL in .env to a model available in your Anthropic account."
                )
            elif "invalid x-api-key" in message.lower() or "authentication_error" in message.lower():
                safe_msg = "AI analysis failed: invalid API key. Update ANTHROPIC_API_KEY and retry."
            else:
                safe_msg = f"AI analysis failed: {exc.__class__.__name__}. Check configuration and network access."
            self.logger.error(safe_msg)
            return AIAnalysis(raw=safe_msg, model=self.config.model, used=False)

    async def test_request(self, message: str = "Why is fast inference important?") -> AIAnalysis:
        if not self.config.enabled:
            return AIAnalysis(raw="AI analysis disabled.", model=self.config.model, used=False)
        if not self.config.api_key:
            return AIAnalysis(raw="AI analysis skipped: missing ANTHROPIC_API_KEY.", model=self.config.model, used=False)

        try:
            response = await asyncio.to_thread(self._call_simple, message)
            return AIAnalysis(raw=response, model=self.config.model, used=True)
        except Exception as exc:
            message_txt = str(exc)
            if exc.__class__.__name__ == "NotFoundError":
                safe_msg = (
                    f"AI test failed: model '{self.config.model}' not found or not accessible for this API key. "
                    "Update ANTHROPIC_MODEL in .env to a model available in your Anthropic account."
                )
            elif "invalid x-api-key" in message_txt.lower() or "authentication_error" in message_txt.lower():
                safe_msg = "AI test failed: invalid API key. Update ANTHROPIC_API_KEY and retry."
            else:
                safe_msg = f"AI test failed: {exc.__class__.__name__}. Check configuration and network access."
            self.logger.error(safe_msg)
            return AIAnalysis(raw=safe_msg, model=self.config.model, used=False)

    def _build_prompt(self, results: Dict[str, Any]) -> str:
        findings = []
        for item in results.get("results", []):
            for finding in item.get("findings", []):
                findings.append({
                    "id": finding.get("id"),
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "description": finding.get("description"),
                    "recommendation": finding.get("recommendation"),
                })

        return (
            "You are OPSEC Sentinel AI, a defensive privacy auditor. "
            "Only analyze the provided JSON. Do not invent vulnerabilities. "
            "If a category lacks evidence, say 'Not observed'.\n\n"
            "Provide sections with headings: Executive Summary, Risk Analysis, Priority Fixes, "
            "Privacy Improvement Recommendations, Technical Explanation.\n\n"
            "Findings list (authoritative):\n"
            f"{json.dumps(findings, indent=2)}\n\n"
            "Full scan JSON:\n"
            f"{json.dumps(results, indent=2)}\n"
        )

    def _call_api(self, prompt: str) -> str:
        return _call_anthropic_http(
            api_key=self.config.api_key or "",
            model=self.config.model,
            messages=[{"role": "user", "content": prompt}],
            system="You are a defensive cybersecurity analyst.",
            temperature=0.2,
            max_tokens=900,
            timeout_seconds=self.config.timeout_seconds,
        )

    def _call_simple(self, message: str) -> str:
        return _call_anthropic_http(
            api_key=self.config.api_key or "",
            model=self.config.model,
            messages=[{"role": "user", "content": message}],
            system=None,
            temperature=0.2,
            max_tokens=200,
            timeout_seconds=self.config.timeout_seconds,
        )


def _call_anthropic_http(
    api_key: str,
    model: str,
    messages: list[dict[str, Any]],
    system: str | None,
    temperature: float,
    max_tokens: int,
    timeout_seconds: int,
) -> str:
    payload: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if system:
        payload["system"] = system

    response = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json=payload,
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    data = response.json()
    texts = [
        block.get("text", "")
        for block in data.get("content", [])
        if isinstance(block, dict) and block.get("type") == "text"
    ]
    if texts:
        return "\n".join(t for t in texts if t)
    return json.dumps(data, ensure_ascii=False)
