# demo-addon

Prototype repository for the Prisma Cloud Compliance Assistant demo add-on.

## Prisma Cloud Compliance Assistant

Prototype for transforming Prisma Cloud compliance scan results into human-readable reports with automated prioritization and remediation guidance.

## Setup

1. Create and activate a Python 3.10 virtual environment.
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies.
   ```bash
   pip install -r requirements.txt
   ```
3. Configure environment variables (see `.env.example`).
4. Run the Streamlit prototype.
   ```bash
   streamlit run src/ui/app.py
   ```

## Components

- `src/config`: configuration loading and environment helpers.
- `src/data`: Prisma Cloud SDK integration and sample data loaders.
- `src/llm`: interfaces for Grok/OpenAI processing.
- `src/reporting`: formatting utilities for reports and PDF export.
- `src/ui`: Streamlit frontend for report generation.
- `tests`: unit tests for data and LLM layers.

## Development Roadmap

- [ ] Implement Prisma Cloud API client wrappers.
- [ ] Add LLM batching pipeline.
- [ ] Build Streamlit workflows and PDF export.
- [ ] Integrate sample/demo data.
- [ ] Add automated tests and mock fixtures.

