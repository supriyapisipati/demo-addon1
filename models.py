from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from src.llm.processor import ProcessedViolation


@dataclass
class ReportMetadata:
    title: str = "Prisma Cloud Compliance Report"
    generated_at: datetime = field(default_factory=datetime.utcnow)
    standard: Optional[str] = None
    account: Optional[str] = None
    cloud_provider: Optional[str] = None
    total_violations: Optional[int] = None


@dataclass
class ReportContext:
    metadata: ReportMetadata
    violations: List[ProcessedViolation]
    notes: Optional[str] = None

    def severity_breakdown(self) -> dict[str, int]:
        counts = {"high": 0, "medium": 0, "low": 0}
        for violation in self.violations:
            label = violation.risk_label.lower()
            if label not in counts:
                counts[label] = 0
            counts[label] += 1
        return counts

    def average_risk(self) -> float:
        if not self.violations:
            return 0.0
        return sum(v.risk_score for v in self.violations) / len(self.violations)
