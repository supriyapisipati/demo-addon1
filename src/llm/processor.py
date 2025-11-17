from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

import httpx

try:  # pragma: no cover - optional dependency
    from openai import OpenAI
except ImportError:  # pragma: no cover
    OpenAI = None  # type: ignore[misc,assignment]

from src.config.settings import Settings, get_settings
from src.data.prisma_client import ComplianceViolation

logger = logging.getLogger(__name__)


class LLMClientError(RuntimeError):
    """Raised when the LLM provider cannot be reached or returns an error."""


@dataclass
class ProcessedViolation:
    violation_id: str
    summary: str
    risk_label: str
    risk_score: float
    remediation_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw_response: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "violation_id": self.violation_id,
            "summary": self.summary,
            "risk_label": self.risk_label,
            "risk_score": self.risk_score,
            "remediation_steps": self.remediation_steps,
            "references": self.references,
            "raw_response": self.raw_response,
        }


def chunked(sequence: Iterable[ComplianceViolation], size: int) -> Iterable[List[ComplianceViolation]]:
    batch: List[ComplianceViolation] = []
    for item in sequence:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


class LLMProcessor:
    """Coordinates prompt construction, provider calls, and fallbacks."""

    def __init__(self, settings: Optional[Settings] = None, timeout: Optional[float] = None) -> None:
        self.settings = settings or get_settings()
        self.timeout = timeout or float(self.settings.timeout_seconds)
        self.http_client = httpx.Client(timeout=self.timeout)
        self._openai_client = None

    def process_violations(
        self,
        violations: List[ComplianceViolation],
        batch_size: int = 5,
    ) -> List[ProcessedViolation]:
        results: List[ProcessedViolation] = []
        for batch in chunked(violations, batch_size):
            try:
                processed = self._process_batch_with_llm(batch)
                results.extend(processed)
            except LLMClientError as exc:
                logger.warning("LLM provider unavailable (%s). Using heuristic fallback.", exc)
                for violation in batch:
                    results.append(self._fallback_process(violation))
        return results

    def _process_batch_with_llm(
        self, violations: List[ComplianceViolation]
    ) -> List[ProcessedViolation]:
        provider = self._select_provider()
        if provider == "grok":
            response = self._call_grok(violations)
        elif provider == "openai":
            response = self._call_openai(violations)
        else:
            raise LLMClientError("No LLM provider configured")
        return self._parse_llm_response(violations, response)

    def _select_provider(self) -> Optional[str]:
        if self.settings.grok_api_key:
            return "grok"
        if self.settings.openai_api_key:
            return "openai"
        return None

    def _call_grok(self, violations: List[ComplianceViolation]) -> Dict[str, Any]:
        api_key = self.settings.grok_api_key
        if not api_key:
            raise LLMClientError("Grok API key not configured")

        payload = self._build_payload(violations)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        try:
            response = self.http_client.post(
                "https://api.x.ai/v1/chat/completions",
                headers=headers,
                json={
                    "model": "grok-beta",
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a compliance assistant that produces JSON responses.",
                        },
                        {
                            "role": "user",
                            "content": payload,
                        },
                    ],
                    "response_format": {"type": "json_object"},
                },
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:  # pragma: no cover - network failures
            raise LLMClientError(f"Grok API request failed: {exc}")

        data = response.json()
        return data

    def _call_openai(self, violations: List[ComplianceViolation]) -> Dict[str, Any]:
        api_key = self.settings.openai_api_key
        if not api_key:
            raise LLMClientError("OpenAI API key not configured")

        if OpenAI is None:
            raise LLMClientError(
                "openai package not available. Install using `pip install openai`."
            )

        client = self._openai_client
        if client is None:
            client = OpenAI(api_key=api_key)
            self._openai_client = client

        payload = self._build_payload(violations)
        try:
            completion = client.responses.create(  # type: ignore[attr-defined]
                model="gpt-4.1-mini",
                input=[
                    {
                        "role": "system",
                        "content": "You are a compliance assistant that outputs JSON only.",
                    },
                    {
                        "role": "user",
                        "content": payload,
                    },
                ],
                response_format={"type": "json_object"},
            )
        except Exception as exc:  # pragma: no cover - network failures
            raise LLMClientError(f"OpenAI request failed: {exc}")

        try:
            message = completion.output[0].content[0].text  # type: ignore[index]
        except (AttributeError, IndexError, KeyError) as exc:
            raise LLMClientError(f"Unexpected OpenAI response format: {exc}")

        return json.loads(message)

    def _build_payload(self, violations: List[ComplianceViolation]) -> str:
        items = []
        for violation in violations:
            items.append(
                {
                    "id": violation.id,
                    "resource_name": violation.resource_name,
                    "policy_name": violation.policy_name,
                    "severity": violation.severity,
                    "account": violation.account,
                    "region": violation.region,
                    "standard": violation.standard,
                    "description": violation.description,
                    "remediation": violation.remediation,
                }
            )
        instructions = {
            "task": "Explain each policy violation in plain English, rank the risk from 1-10, classify as high/medium/low, and propose step-by-step remediation instructions with commands when applicable. Return JSON array keyed by violation id.",
            "violations": items,
        }
        return json.dumps(instructions)

    def _parse_llm_response(
        self, violations: List[ComplianceViolation], response: Dict[str, Any]
    ) -> List[ProcessedViolation]:
        normalized: Dict[str, Any]
        if "violations" in response:
            normalized = response["violations"]
        else:
            normalized = response

        output: List[ProcessedViolation] = []
        for violation in violations:
            payload = normalized.get(violation.id)
            if not payload:
                logger.debug(
                    "LLM response missing violation %s. Falling back to heuristic.",
                    violation.id,
                )
                output.append(self._fallback_process(violation))
                continue
            summary = payload.get("summary") or payload.get("explanation")
            risk_score = float(payload.get("risk_score", 0))
            risk_label = payload.get("risk_label") or self._label_from_score(risk_score)
            remediation = payload.get("remediation_steps") or payload.get("remediation")
            if isinstance(remediation, str):
                remediation_steps = [step.strip() for step in remediation.split("\n") if step.strip()]
            else:
                remediation_steps = remediation or []

            output.append(
                ProcessedViolation(
                    violation_id=violation.id,
                    summary=summary or self._default_summary(violation),
                    risk_label=risk_label,
                    risk_score=risk_score or self._score_from_severity(violation.severity),
                    remediation_steps=remediation_steps or self._default_remediation_steps(violation),
                    references=payload.get("references", []),
                    raw_response=payload,
                )
            )
        return output

    def _fallback_process(self, violation: ComplianceViolation) -> ProcessedViolation:
        score = self._score_from_severity(violation.severity)
        label = self._label_from_score(score)
        summary = self._default_summary(violation)
        remediation_steps = self._default_remediation_steps(violation)
        return ProcessedViolation(
            violation_id=violation.id,
            summary=summary,
            risk_label=label,
            risk_score=score,
            remediation_steps=remediation_steps,
            references=[],
            raw_response=None,
        )

    @staticmethod
    def _score_from_severity(severity: Optional[str]) -> float:
        mapping = {
            "critical": 9.5,
            "high": 8.5,
            "medium": 6.0,
            "low": 3.0,
        }
        return mapping.get((severity or "").lower(), 5.0)

    @staticmethod
    def _label_from_score(score: float) -> str:
        if score >= 8:
            return "high"
        if score >= 5:
            return "medium"
        return "low"

    @staticmethod
    def _default_summary(violation: ComplianceViolation) -> str:
        parts = [
            f"{violation.policy_name} detected on {violation.resource_name}",
            f"Severity: {violation.severity}",
        ]
        if violation.description:
            parts.append(violation.description)
        return ". ".join(parts)

    @staticmethod
    def _default_remediation_steps(violation: ComplianceViolation) -> List[str]:
        if violation.remediation:
            return [violation.remediation]
        return [
            "Review the affected resource configuration",
            "Update settings to align with the relevant compliance standard",
            "Re-run the Prisma Cloud scan to confirm the violation is resolved",
        ]
