"""
Prisma Cloud Compliance Assistant - Standalone Demo
All code in a single file for easy deployment to Streamlit Cloud.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from io import BytesIO
from typing import Any, Dict, Iterable, List, Optional

import httpx
import streamlit as st
from dotenv import load_dotenv
from pydantic import Field, HttpUrl, validator
from pydantic_settings import BaseSettings
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

try:
    from prismacloud.api import pc_api
except ImportError:
    pc_api = None

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

class Settings(BaseSettings):
    prisma_api_url: Optional[HttpUrl] = Field(default=None, env="PRISMA_API_URL")
    prisma_access_key: Optional[str] = Field(default=None, env="PRISMA_ACCESS_KEY")
    prisma_secret_key: Optional[str] = Field(default=None, env="PRISMA_SECRET_KEY")
    prisma_firewall_ip: Optional[str] = Field(default=None, env="PRISMA_FIREWALL_IP")
    prisma_username: Optional[str] = Field(default=None, env="PRISMA_USERNAME")
    prisma_password: Optional[str] = Field(default=None, env="PRISMA_PASSWORD")
    grok_api_key: Optional[str] = Field(default=None, env="GROK_API_KEY")
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    timeout_seconds: int = Field(default=30, env="PRISMA_TIMEOUT_SECONDS")

    class Config:
        env_file = os.getenv("ENV_FILE", ".env")
        case_sensitive = False

    @validator("prisma_access_key", "prisma_secret_key", pre=True)
    def empty_string_to_none(cls, v: Optional[str]) -> Optional[str]:
        if v == "":
            return None
        return v

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

# ============================================================================
# Data Models
# ============================================================================

@dataclass
class ComplianceViolation:
    id: str
    resource_name: str
    policy_name: str
    policy_id: str
    severity: str
    account: Optional[str]
    region: Optional[str]
    standard: Optional[str]
    description: Optional[str]
    remediation: Optional[str]
    raw: Dict[str, Any]

@dataclass
class ProcessedViolation:
    violation_id: str
    summary: str
    risk_label: str
    risk_score: float
    remediation_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw_response: Optional[Dict[str, Any]] = None

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

# ============================================================================
# Sample Test Cases (Embedded)
# ============================================================================

TEST_CASES = {
    "Basic AWS Violations": {
        "description": "Common AWS security misconfigurations (S3, Security Groups, RDS)",
        "data": [
            {
                "id": "violation-001",
                "resource_name": "prod-data-bucket",
                "policy_name": "S3 bucket public access",
                "policy_id": "policy-123",
                "severity": "high",
                "account": "123456789012",
                "region": "us-east-1",
                "standard": "CIS AWS Foundations 1.4",
                "description": "S3 bucket is publicly readable",
                "remediation": "Block public access on the bucket and update bucket policy",
                "details": {"bucketPublic": True, "riskScore": 9.4}
            },
            {
                "id": "violation-002",
                "resource_name": "dev-app-sg",
                "policy_name": "Security group allows 0.0.0.0/0 on SSH",
                "policy_id": "policy-456",
                "severity": "high",
                "account": "123456789012",
                "region": "us-west-2",
                "standard": "CIS AWS Foundations 4.1",
                "description": "Security group exposes SSH to the internet",
                "remediation": "Restrict ingress to trusted IP ranges",
                "details": {"cidr": "0.0.0.0/0", "riskScore": 8.9}
            },
            {
                "id": "violation-003",
                "resource_name": "prod-rds",
                "policy_name": "RDS instance not encrypted",
                "policy_id": "policy-789",
                "severity": "medium",
                "account": "123456789012",
                "region": "us-east-2",
                "standard": "CIS AWS Foundations 1.15",
                "description": "RDS instance storage is not encrypted",
                "remediation": "Enable encryption at rest for RDS",
                "details": {"encryption": False, "riskScore": 7.1}
            }
        ]
    },
    "Critical IAM Issues": {
        "description": "High-risk IAM policy violations and access control problems",
        "data": [
            {
                "id": "iam-001",
                "resource_name": "admin-role-policy",
                "policy_name": "IAM role with overly permissive policy",
                "policy_id": "policy-iam-001",
                "severity": "critical",
                "account": "123456789012",
                "region": "us-east-1",
                "standard": "CIS AWS Foundations 1.22",
                "description": "IAM role allows full administrative access without restrictions",
                "remediation": "Apply principle of least privilege and add resource-based restrictions",
                "details": {"permissions": "*", "riskScore": 9.8}
            },
            {
                "id": "iam-002",
                "resource_name": "lambda-execution-role",
                "policy_name": "Lambda function with public access",
                "policy_id": "policy-iam-002",
                "severity": "high",
                "account": "123456789012",
                "region": "us-west-2",
                "standard": "CIS AWS Foundations 1.16",
                "description": "Lambda execution role grants unnecessary S3 write permissions",
                "remediation": "Restrict Lambda role to specific S3 buckets and actions required",
                "details": {"s3Access": "write", "riskScore": 8.2}
            },
            {
                "id": "iam-003",
                "resource_name": "ec2-instance-profile",
                "policy_name": "EC2 instance profile with root access",
                "policy_id": "policy-iam-003",
                "severity": "critical",
                "account": "123456789012",
                "region": "eu-west-1",
                "standard": "CIS AWS Foundations 1.4",
                "description": "EC2 instance has IAM role with root-level permissions",
                "remediation": "Remove root permissions and grant only necessary service permissions",
                "details": {"rootAccess": True, "riskScore": 9.9}
            }
        ]
    },
    "Compliance Standards Mix": {
        "description": "Violations across multiple compliance frameworks (PCI-DSS, HIPAA, NIST)",
        "data": [
            {
                "id": "pci-001",
                "resource_name": "payment-api-lb",
                "policy_name": "Load balancer without SSL/TLS termination",
                "policy_id": "policy-pci-001",
                "severity": "high",
                "account": "123456789012",
                "region": "us-east-1",
                "standard": "PCI-DSS 4.1",
                "description": "Application load balancer does not enforce HTTPS",
                "remediation": "Configure ALB listener to redirect HTTP to HTTPS and enforce TLS 1.2+",
                "details": {"tlsVersion": "none", "riskScore": 8.7}
            },
            {
                "id": "hipaa-001",
                "resource_name": "patient-data-db",
                "policy_name": "Database without encryption at rest",
                "policy_id": "policy-hipaa-001",
                "severity": "high",
                "account": "123456789012",
                "region": "us-east-1",
                "standard": "HIPAA §164.312(a)(2)(iv)",
                "description": "DynamoDB table storing PHI is not encrypted",
                "remediation": "Enable encryption at rest using AWS KMS customer-managed keys",
                "details": {"encryption": False, "riskScore": 9.1}
            },
            {
                "id": "nist-001",
                "resource_name": "cloudtrail-log-bucket",
                "policy_name": "CloudTrail logs not protected from deletion",
                "policy_id": "policy-nist-001",
                "severity": "medium",
                "account": "123456789012",
                "region": "us-east-1",
                "standard": "NIST 800-53 AU-9",
                "description": "S3 bucket storing CloudTrail logs lacks object lock",
                "remediation": "Enable S3 Object Lock in governance mode and MFA delete",
                "details": {"objectLock": False, "riskScore": 6.5}
            }
        ]
    },
    "Container Security": {
        "description": "Kubernetes and container-related security violations",
        "data": [
            {
                "id": "k8s-001",
                "resource_name": "default-namespace-pod",
                "policy_name": "Pod running with privileged container",
                "policy_id": "policy-k8s-001",
                "severity": "high",
                "account": "123456789012",
                "region": "us-east-1",
                "standard": "CIS Kubernetes 5.2.1",
                "description": "Kubernetes pod running with privileged=true security context",
                "remediation": "Remove privileged flag and use specific capabilities if needed",
                "details": {"privileged": True, "riskScore": 8.8}
            },
            {
                "id": "k8s-002",
                "resource_name": "api-deployment",
                "policy_name": "Container image from untrusted registry",
                "policy_id": "policy-k8s-002",
                "severity": "medium",
                "account": "123456789012",
                "region": "us-west-2",
                "standard": "CIS Kubernetes 5.3.1",
                "description": "Deployment uses container image from public registry without scanning",
                "remediation": "Use only approved container images from trusted registries with vulnerability scanning",
                "details": {"registry": "dockerhub", "riskScore": 6.2}
            },
            {
                "id": "k8s-003",
                "resource_name": "webapp-service",
                "policy_name": "Service account with excessive permissions",
                "policy_id": "policy-k8s-003",
                "severity": "high",
                "account": "123456789012",
                "region": "eu-central-1",
                "standard": "CIS Kubernetes 5.1.5",
                "description": "Service account bound to cluster-admin role",
                "remediation": "Create custom RBAC role with minimal required permissions",
                "details": {"role": "cluster-admin", "riskScore": 9.0}
            }
        ]
    },
    "Multi-Cloud Violations": {
        "description": "Security issues across AWS, Azure, and GCP environments",
        "data": [
            {
                "id": "aws-001",
                "resource_name": "s3-backup-bucket",
                "policy_name": "S3 bucket versioning disabled",
                "policy_id": "policy-aws-001",
                "severity": "medium",
                "account": "123456789012",
                "region": "us-east-1",
                "standard": "CIS AWS Foundations 2.1.1",
                "description": "S3 bucket storing backups does not have versioning enabled",
                "remediation": "Enable S3 versioning and configure lifecycle policies",
                "details": {"versioning": False, "riskScore": 5.8}
            },
            {
                "id": "azure-001",
                "resource_name": "storage-account-prod",
                "policy_name": "Azure Storage account allows public access",
                "policy_id": "policy-azure-001",
                "severity": "high",
                "account": "azure-sub-123",
                "region": "eastus",
                "standard": "CIS Microsoft Azure Foundations 3.1",
                "description": "Storage account configured to allow public blob access",
                "remediation": "Set public access level to 'Private' and use SAS tokens for controlled access",
                "details": {"publicAccess": True, "riskScore": 8.5}
            },
            {
                "id": "gcp-001",
                "resource_name": "compute-instance-prod",
                "policy_name": "GCP VM with public IP and no firewall rules",
                "policy_id": "policy-gcp-001",
                "severity": "high",
                "account": "gcp-project-456",
                "region": "us-central1",
                "standard": "CIS Google Cloud Platform 4.1",
                "description": "Compute instance has external IP without restrictive firewall rules",
                "remediation": "Remove external IP or configure VPC firewall to restrict access",
                "details": {"externalIP": True, "firewallRules": "none", "riskScore": 8.3}
            }
        ]
    }
}

def load_test_case(case_name: str) -> List[ComplianceViolation]:
    """Load a specific test case by name."""
    if case_name not in TEST_CASES:
        return []
    violations = []
    for item in TEST_CASES[case_name]["data"]:
        violations.append(
            ComplianceViolation(
                id=str(item.get("id", "sample")),
                resource_name=item.get("resource_name", "unknown"),
                policy_name=item.get("policy_name", "unknown"),
                policy_id=str(item.get("policy_id", "sample")),
                severity=item.get("severity", "medium"),
                account=item.get("account"),
                region=item.get("region"),
                standard=item.get("standard"),
                description=item.get("description"),
                remediation=item.get("remediation"),
                raw=item,
            )
        )
    return violations

# ============================================================================
# Prisma Client (Simplified)
# ============================================================================

class PrismaClient:
    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self._sdk = None

    def connect(self) -> None:
        if self._sdk is not None:
            return
        if pc_api is None:
            raise RuntimeError("prismacloud-api-python is not installed")
        client = pc_api.PrismaCloudAPI()
        client.api = str(self.settings.prisma_api_url)
        client.api_key = self.settings.prisma_access_key
        client.api_secret = self.settings.prisma_secret_key
        client.login()
        self._sdk = client

    def fetch_violations_for_job(self, job_id: str) -> List[ComplianceViolation]:
        if self._sdk is None:
            self.connect()
        job_detail = self._sdk.compliance_job_status_get(job_id)
        violations_data = job_detail.get("result", [])
        violations = []
        for item in violations_data:
            policy = item.get("policy", {})
            resource = item.get("resource", {})
            violations.append(
                ComplianceViolation(
                    id=str(item.get("id")),
                    resource_name=resource.get("name", "unknown"),
                    policy_name=policy.get("name", "unknown"),
                    policy_id=str(policy.get("policyId")),
                    severity=policy.get("severity", "unknown"),
                    account=resource.get("accountId"),
                    region=resource.get("region"),
                    standard=item.get("standardName"),
                    description=policy.get("description"),
                    remediation=policy.get("remediation"),
                    raw=item,
                )
            )
        return violations

# ============================================================================
# LLM Processor
# ============================================================================

class LLMClientError(RuntimeError):
    pass

def chunked(sequence: Iterable[ComplianceViolation], size: int) -> Iterable[List[ComplianceViolation]]:
    batch = []
    for item in sequence:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch

class LLMProcessor:
    def __init__(self, settings: Optional[Settings] = None, timeout: Optional[float] = None) -> None:
        self.settings = settings or get_settings()
        self.timeout = timeout or float(self.settings.timeout_seconds)
        self.http_client = httpx.Client(timeout=self.timeout)
        self._openai_client = None

    def process_violations(
        self, violations: List[ComplianceViolation], batch_size: int = 5
    ) -> List[ProcessedViolation]:
        results = []
        for batch in chunked(violations, batch_size):
            try:
                processed = self._process_batch_with_llm(batch)
                results.extend(processed)
            except LLMClientError as exc:
                logger.warning("LLM provider unavailable (%s). Using heuristic fallback.", exc)
                for violation in batch:
                    results.append(self._fallback_process(violation))
        return results

    def _process_batch_with_llm(self, violations: List[ComplianceViolation]) -> List[ProcessedViolation]:
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
        try:
            response = self.http_client.post(
                "https://api.x.ai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": "grok-beta",
                    "messages": [
                        {"role": "system", "content": "You are a compliance assistant that produces JSON responses."},
                        {"role": "user", "content": payload},
                    ],
                    "response_format": {"type": "json_object"},
                },
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMClientError(f"Grok API request failed: {exc}")
        return response.json()

    def _call_openai(self, violations: List[ComplianceViolation]) -> Dict[str, Any]:
        api_key = self.settings.openai_api_key
        if not api_key:
            raise LLMClientError("OpenAI API key not configured")
        if OpenAI is None:
            raise LLMClientError("openai package not available")
        if self._openai_client is None:
            self._openai_client = OpenAI(api_key=api_key)
        payload = self._build_payload(violations)
        try:
            completion = self._openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a compliance assistant that outputs JSON only."},
                    {"role": "user", "content": payload},
                ],
                response_format={"type": "json_object"},
            )
            message = completion.choices[0].message.content
            return json.loads(message) if message else {}
        except Exception as exc:
            raise LLMClientError(f"OpenAI request failed: {exc}")

    def _build_payload(self, violations: List[ComplianceViolation]) -> str:
        items = []
        for violation in violations:
            items.append({
                "id": violation.id,
                "resource_name": violation.resource_name,
                "policy_name": violation.policy_name,
                "severity": violation.severity,
                "account": violation.account,
                "region": violation.region,
                "standard": violation.standard,
                "description": violation.description,
                "remediation": violation.remediation,
            })
        instructions = {
            "task": "Explain each policy violation in plain English, rank the risk from 1-10, classify as high/medium/low, and propose step-by-step remediation instructions with commands when applicable. Return JSON array keyed by violation id.",
            "violations": items,
        }
        return json.dumps(instructions)

    def _parse_llm_response(
        self, violations: List[ComplianceViolation], response: Dict[str, Any]
    ) -> List[ProcessedViolation]:
        normalized = response.get("violations", response)
        output = []
        for violation in violations:
            payload = normalized.get(violation.id)
            if not payload:
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
        return ProcessedViolation(
            violation_id=violation.id,
            summary=self._default_summary(violation),
            risk_label=label,
            risk_score=score,
            remediation_steps=self._default_remediation_steps(violation),
            references=[],
            raw_response=None,
        )

    @staticmethod
    def _score_from_severity(severity: Optional[str]) -> float:
        mapping = {"critical": 9.5, "high": 8.5, "medium": 6.0, "low": 3.0}
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

# ============================================================================
# Reporting
# ============================================================================

def render_markdown_report(context: ReportContext) -> str:
    metadata = context.metadata
    severity_counts = context.severity_breakdown()
    lines = [f"# {metadata.title}", ""]
    lines.append(f"Generated: {metadata.generated_at.isoformat()} UTC")
    if metadata.standard:
        lines.append(f"Standard: {metadata.standard}")
    if metadata.account:
        lines.append(f"Account: {metadata.account}")
    if metadata.cloud_provider:
        lines.append(f"Cloud: {metadata.cloud_provider}")
    if metadata.total_violations is not None:
        lines.append(f"Violations: {metadata.total_violations}")
    lines.append(f"Average Risk Score: {context.average_risk():.1f}")
    lines.append("")
    lines.append("## Risk Overview")
    for level, count in severity_counts.items():
        lines.append(f"- {level.title()}: {count}")
    lines.append("")
    if context.notes:
        lines.append("## Notes")
        lines.append(context.notes)
        lines.append("")
    lines.append("## Violations")
    for violation in context.violations:
        lines.append(f"### {violation.violation_id} - {violation.summary}")
        lines.append(f"- Risk: {violation.risk_label.title()} ({violation.risk_score:.1f})")
        if violation.remediation_steps:
            lines.append("- Remediation:")
            for step in violation.remediation_steps:
                lines.append(f"  - {step}")
        if violation.references:
            lines.append("- References:")
            for ref in violation.references:
                lines.append(f"  - {ref}")
        lines.append("")
    return "\n".join(lines).strip()

SUMMARY_STYLE = ParagraphStyle("Summary", parent=getSampleStyleSheet()["BodyText"], fontSize=11, leading=14)
HEADER_STYLE = ParagraphStyle("Header", parent=getSampleStyleSheet()["Heading1"], fontSize=16, leading=20)
SUBHEADER_STYLE = ParagraphStyle("SubHeader", parent=getSampleStyleSheet()["Heading2"], fontSize=13, leading=18)

def build_pdf(context: ReportContext) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=LETTER, leftMargin=1 * inch, rightMargin=1 * inch)
    elements = []
    meta = context.metadata
    elements.append(Paragraph(meta.title, HEADER_STYLE))
    elements.append(Spacer(1, 0.2 * inch))
    details = [
        f"Generated: {meta.generated_at.isoformat()} UTC",
        f"Average Risk Score: {context.average_risk():.1f}",
    ]
    if meta.standard:
        details.append(f"Standard: {meta.standard}")
    if meta.account:
        details.append(f"Account: {meta.account}")
    if meta.cloud_provider:
        details.append(f"Cloud: {meta.cloud_provider}")
    if meta.total_violations is not None:
        details.append(f"Violations: {meta.total_violations}")
    for line in details:
        elements.append(Paragraph(line, SUMMARY_STYLE))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph("Risk Overview", SUBHEADER_STYLE))
    counts = context.severity_breakdown()
    data = [["Risk Level", "Count"]]
    for level, count in counts.items():
        data.append([level.title(), str(count)])
    table = Table(data, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 0.3 * inch))
    if context.notes:
        elements.append(Paragraph("Notes", SUBHEADER_STYLE))
        elements.append(Paragraph(context.notes, SUMMARY_STYLE))
        elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph("Violations", SUBHEADER_STYLE))
    for violation in context.violations:
        elements.append(Paragraph(f"{violation.violation_id} - {violation.summary}", SUMMARY_STYLE))
        elements.append(Paragraph(f"Risk: {violation.risk_label.title()} ({violation.risk_score:.1f})", SUMMARY_STYLE))
        if violation.remediation_steps:
            elements.append(Paragraph("Remediation:", SUMMARY_STYLE))
            for step in violation.remediation_steps:
                elements.append(Paragraph(f"- {step}", SUMMARY_STYLE))
        if violation.references:
            elements.append(Paragraph("References:", SUMMARY_STYLE))
            for ref in violation.references:
                elements.append(Paragraph(f"- {ref}", SUMMARY_STYLE))
        elements.append(Spacer(1, 0.2 * inch))
    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()

# ============================================================================
# Streamlit App
# ============================================================================

st.set_page_config(page_title="Prisma Cloud Compliance Assistant", layout="wide")

@st.cache_resource(show_spinner=False)
def get_clients():
    settings = get_settings()
    prisma_client = PrismaClient(settings=settings)
    llm_processor = LLMProcessor(settings=settings)
    return prisma_client, llm_processor

def main():
    st.title("Prisma Cloud Compliance Assistant")
    prisma_client, llm_processor = get_clients()
    mode = st.sidebar.radio("Data source", ["Test Cases (Demo)", "Live Prisma API"])

    violations = []
    metadata = ReportMetadata()
    selected_case = st.session_state.get("selected_test_case", None)

    if mode == "Test Cases (Demo)":
        st.sidebar.header("📋 Test Cases")
        st.sidebar.write("Click a button below to load a test case:")
        st.sidebar.write("")
        
        # Display test case buttons
        for case_name, case_info in TEST_CASES.items():
            if st.sidebar.button(
                f"🧪 {case_name}",
                key=f"btn_{case_name}",
                use_container_width=True,
                help=case_info["description"]
            ):
                selected_case = case_name
                st.session_state["selected_test_case"] = case_name
                violations = load_test_case(case_name)
                metadata.title = f"Compliance Report - {case_name}"
                st.session_state["current_violations"] = violations
                st.session_state["current_metadata"] = metadata
        
        # Show selected case info
        if selected_case and selected_case in TEST_CASES:
            st.sidebar.success(f"✅ Loaded: **{selected_case}**")
            st.sidebar.caption(TEST_CASES[selected_case]["description"])
            # Load from session state if available
            if "current_violations" in st.session_state:
                violations = st.session_state["current_violations"]
                metadata = st.session_state.get("current_metadata", metadata)
    else:
        st.sidebar.write("Enter the Compliance Job ID to fetch violations.")
        job_id = st.sidebar.text_input("Job ID", placeholder="abcd-1234")
        if job_id and st.sidebar.button("Fetch Violations"):
            with st.spinner("Fetching from Prisma Cloud..."):
                try:
                    violations = prisma_client.fetch_violations_for_job(job_id)
                    metadata.title = f"Compliance Report - Job {job_id}"
                except Exception as exc:
                    st.error(f"Failed to fetch violations: {exc}")

    if not violations:
        st.info("👆 Select 'Test Cases (Demo)' and click a test case button above, or use 'Live Prisma API' to fetch real violations.")
        st.markdown("### Available Test Cases:")
        cols = st.columns(2)
        for idx, (case_name, case_info) in enumerate(TEST_CASES.items()):
            with cols[idx % 2]:
                st.markdown(f"**{case_name}**")
                st.caption(case_info["description"])
                st.caption(f"Violations: {len(case_info['data'])}")
        return

    metadata.total_violations = len(violations)

    # Show test case info banner if in demo mode
    if mode == "Test Cases (Demo)" and selected_case:
        st.info(f"📊 **Test Case:** {selected_case} | {TEST_CASES[selected_case]['description']} | {len(violations)} violations")

    with st.spinner("Processing violations with LLM..."):
        processed = llm_processor.process_violations(violations)

    context = ReportContext(metadata=metadata, violations=processed)

    col1, col2 = st.columns([2, 1])

    with col1:
        st.header("Summary")
        risk = context.severity_breakdown()
        st.metric("Average Risk Score", f"{context.average_risk():.1f}")
        st.write(risk)

        st.header("Violations")
        for item in processed:
            with st.expander(f"{item.violation_id} - {item.risk_label.title()} ({item.risk_score:.1f})"):
                st.write(item.summary)
                st.write("**Remediation Steps**")
                for step in item.remediation_steps:
                    st.write(f"- {step}")
                if item.references:
                    st.write("**References**")
                    for ref in item.references:
                        st.write(f"- {ref}")

    with col2:
        st.header("Exports")
        markdown_report = render_markdown_report(context)
        st.download_button(
            label="Download Markdown",
            data=markdown_report,
            file_name="prisma_compliance_report.md",
        )
        pdf_bytes = build_pdf(context)
        st.download_button(
            label="Download PDF",
            data=pdf_bytes,
            file_name="prisma_compliance_report.pdf",
            mime="application/pdf",
        )

        st.header("Raw Data")
        st.json([violation.raw for violation in violations])

if __name__ == "__main__":
    main()

