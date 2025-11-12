from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import List

import streamlit as st

# Ensure project root is on sys.path when executed from different working directories (e.g., Streamlit Cloud)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:  # pragma: no cover - environment dependent
    sys.path.append(str(PROJECT_ROOT))

from src.config.settings import get_settings
from src.data.prisma_client import ComplianceViolation, PrismaClient, SampleDataLoader
from src.llm.processor import LLMProcessor
from src.reporting.markdown import render_markdown_report
from src.reporting.models import ReportContext, ReportMetadata
from src.reporting.pdf import build_pdf

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


st.set_page_config(page_title="Prisma Cloud Compliance Assistant", layout="wide")


SESSION_LIVE_VIOLATIONS = "live_violations"
SESSION_LIVE_METADATA = "live_metadata"


@st.cache_resource(show_spinner=False)
def get_clients():
    settings = get_settings()
    prisma_client = PrismaClient(settings=settings)
    sample_loader = SampleDataLoader()
    llm_processor = LLMProcessor(settings=settings)
    return prisma_client, sample_loader, llm_processor


@st.cache_data(show_spinner=False)
def load_sample(sample_name: str) -> List[ComplianceViolation]:
    _, sample_loader, _ = get_clients()
    return sample_loader.load(sample_name)


@st.cache_data(show_spinner=False)
def fetch_job_violations(job_id: str) -> List[ComplianceViolation]:
    prisma_client, _, _ = get_clients()
    try:
        return prisma_client.fetch_violations_for_job(job_id)
    except Exception as exc:  # pragma: no cover - network failures
        st.error(f"Failed to fetch violations: {exc}")
        raise


def main():
    st.title("Prisma Cloud Compliance Assistant")
    prisma_client, sample_loader, llm_processor = get_clients()
    mode = st.sidebar.radio("Data source", ["Sample data", "Live Prisma API"])

    violations: List[ComplianceViolation] = []
    metadata = ReportMetadata()
    st.session_state.setdefault(SESSION_LIVE_VIOLATIONS, [])
    st.session_state.setdefault(SESSION_LIVE_METADATA, None)

    if mode == "Sample data":
        st.session_state[SESSION_LIVE_VIOLATIONS] = []
        st.session_state[SESSION_LIVE_METADATA] = None
        samples = sample_loader.list_samples()
        if not samples:
            st.warning("No sample fixtures found in src/data/fixtures")
        sample_name = st.sidebar.selectbox("Choose sample", options=samples)
        if sample_name:
            violations = load_sample(sample_name)
            metadata.title = f"Compliance Report - {sample_name}"
    else:
        st.sidebar.write("Enter the Compliance Job ID to fetch violations.")
        job_id = st.sidebar.text_input("Job ID", placeholder="abcd-1234")
        if job_id:
            if st.sidebar.button("Fetch Violations"):
                with st.spinner("Fetching from Prisma Cloud..."):
                    violations = fetch_job_violations(job_id)
                    metadata.title = f"Compliance Report - Job {job_id}"
                    st.session_state[SESSION_LIVE_VIOLATIONS] = violations
                    st.session_state[SESSION_LIVE_METADATA] = metadata
            else:
                stored = st.session_state.get(SESSION_LIVE_VIOLATIONS, [])
                if stored:
                    violations = stored
                    stored_meta = st.session_state.get(SESSION_LIVE_METADATA)
                    if stored_meta:
                        metadata = stored_meta
                    else:
                        metadata.title = f"Compliance Report - Job {job_id}"


    if not violations:
        st.info("Select a sample or fetch a job to generate a report.")
        return

    metadata.total_violations = len(violations)
    if mode == "Live Prisma API":
        st.session_state[SESSION_LIVE_METADATA] = metadata

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
