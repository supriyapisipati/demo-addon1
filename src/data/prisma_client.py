from __future__ import annotations

import json
import logging
import pathlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:
    from prismacloud.api import pc_api
except ImportError:  # pragma: no cover - handled in tests/mock environments
    pc_api = None  # type: ignore

from src.config.settings import Settings, get_settings, require_prisma_credentials

logger = logging.getLogger(__name__)


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


class PrismaClient:
    """Thin wrapper around the Prisma Cloud SDK."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self._sdk = None

    def connect(self) -> None:
        if self._sdk is not None:
            return
        require_prisma_credentials(self.settings)
        if pc_api is None:
            raise RuntimeError(
                "prismacloud-api-python is not installed. Run `pip install -r requirements.txt`."
            )

        client = pc_api.PrismaCloudAPI()
        client.retry_limit = 3
        client.timeout = self.settings.timeout_seconds
        client.cloud_name = "prismacloud"
        client.disable_ssl_verification = False

        client.api = str(self.settings.prisma_api_url)
        client.api_key = self.settings.prisma_access_key
        client.api_secret = self.settings.prisma_secret_key

        logger.info("Authenticating with Prisma Cloud API at %s", client.api)
        client.login()
        self._sdk = client

    @property
    def sdk(self) -> "pc_api.PrismaCloudAPI":  # type: ignore[name-defined]
        if self._sdk is None:
            self.connect()
        return self._sdk  # type: ignore[return-value]

    def list_compliance_jobs(self) -> List[Dict[str, Any]]:
        logger.debug("Fetching compliance jobs")
        return self.sdk.compliance_jobs_list()

    def get_compliance_job(self, job_id: str) -> Dict[str, Any]:
        logger.debug("Fetching compliance job %s", job_id)
        return self.sdk.compliance_job_status_get(job_id)

    def list_policy_violations(
        self,
        policy_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if policy_id:
            params["policy.id"] = policy_id
        logger.debug("Querying compliance violations with params=%s", params)
        return self.sdk.compliance_policy_violations_list(params=params)

    def get_violation_detail(self, violation_id: str) -> Dict[str, Any]:
        logger.debug("Fetching violation detail %s", violation_id)
        return self.sdk.compliance_policy_violations_read(violation_id)

    def fetch_violations_for_job(self, job_id: str) -> List[ComplianceViolation]:
        logger.info("Fetching violations for job %s", job_id)
        job_detail = self.get_compliance_job(job_id)
        violations_data: List[Dict[str, Any]] = job_detail.get("result", [])
        violations: List[ComplianceViolation] = []
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


class SampleDataLoader:
    """Loads sample compliance data from JSON fixtures for demo mode."""

    def __init__(self, fixtures_dir: Optional[str] = None) -> None:
        base_path = pathlib.Path(fixtures_dir or pathlib.Path(__file__).parent / "fixtures")
        self.fixtures_dir = base_path

    def list_samples(self) -> List[str]:
        return [
            f.stem
            for f in self.fixtures_dir.glob("*.json")
            if f.is_file() and not f.name.startswith(".")
        ]

    def load(self, sample_name: str) -> List[ComplianceViolation]:
        file_path = self.fixtures_dir / f"{sample_name}.json"
        if not file_path.exists():
            raise FileNotFoundError(f"Sample data '{sample_name}' not found at {file_path}")
        with file_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        violations: List[ComplianceViolation] = []
        for item in data:
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
