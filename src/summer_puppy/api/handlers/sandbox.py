"""Security sandbox endpoints — submit samples for analysis and get structured findings."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from summer_puppy.api.middleware.auth_middleware import verify_customer_path
from summer_puppy.api.state import AppState, get_app_state
from summer_puppy.sandbox.analyzer import SandboxAnalyzer, StubSandboxAnalyzer
from summer_puppy.sandbox.findings_to_events import report_to_events
from summer_puppy.sandbox.models import (
    SampleSubmission,
    SandboxSubmitRequest,
    SandboxSubmitResponse,
)

router = APIRouter()


def _get_analyzer(state: AppState) -> SandboxAnalyzer | StubSandboxAnalyzer:
    analyzer = getattr(state, "sandbox_analyzer", None)
    if analyzer is None:
        return StubSandboxAnalyzer()
    return analyzer  # type: ignore[return-value]


@router.post(
    "/{customer_id}/sandbox/submit",
    response_model=SandboxSubmitResponse,
    dependencies=[Depends(verify_customer_path)],
)
async def submit_sample(
    customer_id: str,
    body: SandboxSubmitRequest,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> SandboxSubmitResponse:
    """Submit a security sample for sandbox analysis.

    Analyzes the sample and automatically generates SecurityEvents for significant findings,
    which are injected into the pipeline for triage and remediation.
    """
    submission = SampleSubmission(
        customer_id=customer_id,
        sample_type=body.sample_type,
        content=body.content,
        filename=body.filename,
        metadata=body.metadata,
    )

    analyzer = _get_analyzer(state)
    report = await analyzer.analyze(submission)

    # Convert findings to SecurityEvents and inject into pipeline
    events = report_to_events(report)
    orchestrator = state.orchestrator

    injected = 0
    if orchestrator is not None:
        from summer_puppy.trust.models import TrustPhase, TrustProfile

        trust_profile = state.trust_store.get(
            customer_id,
            TrustProfile(customer_id=customer_id, trust_phase=TrustPhase.SUPERVISED),
        )

        # Store generated events in the registry and kick off pipeline
        for event in events:
            try:
                ctx = await orchestrator.process_event(event, trust_profile)
                state.event_registry[event.event_id] = ctx
                injected += 1
            except Exception:
                pass

    return SandboxSubmitResponse(
        submission_id=submission.submission_id,
        report_id=report.report_id,
        verdict=report.verdict,
        overall_severity=report.overall_severity,
        finding_count=len(report.findings),
        events_generated=injected,
        summary=report.summary,
    )


@router.get(
    "/{customer_id}/sandbox/reports/{report_id}",
    dependencies=[Depends(verify_customer_path)],
)
async def get_report(
    customer_id: str,
    report_id: str,
    state: AppState = Depends(get_app_state),  # noqa: B008
) -> dict[str, object]:
    """Retrieve a cached sandbox analysis report by ID."""
    report = getattr(state, "_sandbox_reports", {}).get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report  # type: ignore[return-value]
