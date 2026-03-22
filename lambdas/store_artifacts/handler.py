"""
store_artifacts/handler.py

Lambda function: Store Artifacts

Fourth step in the incident-response Step Functions workflow.
Consolidates all collected data and the AI analysis into a final set of
artifacts stored in S3 under the ticket-number prefix:

    s3://<bucket>/<ticket_number>/
        ai_recommendation.txt   – human-readable summary for SOC analysts
        ai_recommendation.json  – full structured AI output
        incident_summary.json   – merged incident summary with all data

Returns the S3 paths so subsequent steps can reference them.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET", "")
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# S3 helpers
# ---------------------------------------------------------------------------

def _s3_client() -> Any:
    return boto3.client("s3")


def put_object(bucket: str, key: str, body: bytes, content_type: str = "application/json") -> str:
    """Upload raw bytes to S3.  Returns the S3 key."""
    s3 = _s3_client()
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType=content_type,
    )
    logger.info("Stored s3://%s/%s (%d bytes)", bucket, key, len(body))
    return key


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

VERDICT_EMOJI = {
    "TRUE_POSITIVE": "🚨",
    "FALSE_POSITIVE": "✅",
    "INCONCLUSIVE": "⚠️",
}

VERDICT_LABEL = {
    "TRUE_POSITIVE": "TRUE POSITIVE – CONFIRMED THREAT",
    "FALSE_POSITIVE": "FALSE POSITIVE – BENIGN ACTIVITY",
    "INCONCLUSIVE": "INCONCLUSIVE – MANUAL REVIEW REQUIRED",
}


def build_text_recommendation(incident: dict, analysis: dict) -> str:
    """Build a human-readable plain-text recommendation report."""
    ticket_number = incident.get("ticket_number", "UNKNOWN")
    alert_type = incident.get("alert_type", "Unknown")
    severity = incident.get("severity", "Unknown")
    finding_id = incident.get("finding_id", "")
    account_id = incident.get("account_id", "")
    region = incident.get("region", "")
    resource_type = incident.get("resource_type", "")
    resource_id = incident.get("resource_id", "")
    description = incident.get("description", "No description provided")

    verdict = analysis.get("verdict", "INCONCLUSIVE")
    confidence = analysis.get("confidence", "LOW")
    reasoning = analysis.get("reasoning", "")
    threat_summary = analysis.get("threat_summary", "")
    iocs = analysis.get("indicators_of_compromise", [])
    fp_indicators = analysis.get("false_positive_indicators", [])
    proposed_actions = analysis.get("proposed_actions", analysis.get("recommendations", []))
    mitre = analysis.get("mitre_attack_techniques", [])
    model_id = analysis.get("model_id", "")
    analysis_ts = analysis.get("analysis_timestamp", datetime.now(tz=timezone.utc).isoformat())

    emoji = VERDICT_EMOJI.get(verdict, "⚠️")
    label = VERDICT_LABEL.get(verdict, verdict)

    lines = [
        "=" * 72,
        f"INCIDENT RESPONSE AI RECOMMENDATION",
        "=" * 72,
        "",
        f"Ticket Number  : {ticket_number}",
        f"Alert Type     : {alert_type}",
        f"Severity       : {severity}",
        f"Finding ID     : {finding_id}",
        f"AWS Account    : {account_id}",
        f"Region         : {region}",
        f"Resource Type  : {resource_type}",
        f"Resource ID    : {resource_id}",
        f"Description    : {description}",
        "",
        "-" * 72,
        f"VERDICT: {emoji} {label}",
        f"CONFIDENCE: {confidence}",
        "-" * 72,
        "",
        "THREAT SUMMARY",
        "-" * 40,
        threat_summary,
        "",
        "AI REASONING",
        "-" * 40,
        reasoning,
        "",
    ]

    if iocs:
        lines += [
            "INDICATORS OF COMPROMISE",
            "-" * 40,
        ]
        for ioc in iocs:
            lines.append(f"  • {ioc}")
        lines.append("")

    if fp_indicators:
        lines += [
            "FALSE POSITIVE INDICATORS",
            "-" * 40,
        ]
        for fp in fp_indicators:
            lines.append(f"  • {fp}")
        lines.append("")

    if mitre:
        lines += [
            "MITRE ATT&CK TECHNIQUES",
            "-" * 40,
        ]
        for technique in mitre:
            lines.append(f"  • {technique}")
        lines.append("")

    lines += [
        "⚠️  PROPOSED ACTIONS — AWAITING ANALYST APPROVAL",
        "-" * 40,
        "NOTICE: NO AUTOMATED ACTIONS HAVE BEEN TAKEN.",
        "The following actions are PROPOSALS ONLY. Each must be explicitly reviewed",
        "and authorized by a human analyst before any remediation is executed.",
        "-" * 40,
    ]
    if proposed_actions:
        for i, action in enumerate(proposed_actions, start=1):
            lines.append(f"  {i}. [ ] PROPOSED: {action}")
    else:
        lines.append("  No specific actions proposed.")
    lines.append("")

    lines += [
        "-" * 72,
        f"Analysis performed by  : {model_id}",
        f"Analysis timestamp     : {analysis_ts}",
        "=" * 72,
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Entry point for the store-artifacts Lambda.

    Args:
        event: Step Functions payload with all incident fields plus
               enrichment_result, artifacts_result, and analysis_result.
        context: Lambda context (unused).

    Returns:
        Dict with S3 paths for the stored recommendation and summary files.
    """
    logger.info("store_artifacts invoked for ticket=%s", event.get("ticket_number", "UNKNOWN"))

    if not ARTIFACTS_BUCKET:
        raise ValueError("ARTIFACTS_BUCKET environment variable is not set")

    ticket_number = event.get("ticket_number", "UNKNOWN")
    prefix = f"{ticket_number}/"

    # Extract analysis from the nested Step Functions result structure
    analysis_wrapper = event.get("analysis_result", {})
    analysis = analysis_wrapper.get("analysis", analysis_wrapper)

    incident = {
        "ticket_number": ticket_number,
        "alert_type": event.get("alert_type", ""),
        "severity": event.get("severity", ""),
        "finding_id": event.get("finding_id", ""),
        "account_id": event.get("account_id", ""),
        "region": event.get("region", ""),
        "resource_type": event.get("resource_type", ""),
        "resource_id": event.get("resource_id", ""),
        "description": event.get("description", ""),
        "secops_case_id": event.get("secops_case_id", ""),
    }

    stored_keys: list[str] = []

    # 1. Human-readable recommendation text file
    text_report = build_text_recommendation(incident, analysis)
    key = put_object(
        ARTIFACTS_BUCKET,
        f"{prefix}ai_recommendation.txt",
        text_report.encode("utf-8"),
        content_type="text/plain",
    )
    stored_keys.append(key)

    # 2. Structured JSON recommendation
    json_recommendation = json.dumps(
        {
            "incident": incident,
            "analysis": analysis,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        },
        default=str,
        indent=2,
    ).encode("utf-8")
    key = put_object(
        ARTIFACTS_BUCKET,
        f"{prefix}ai_recommendation.json",
        json_recommendation,
    )
    stored_keys.append(key)

    # 3. Full incident summary (all data merged)
    summary = {
        "incident": incident,
        "enrichment": event.get("enrichment_result", {}),
        "artifacts": event.get("artifacts_result", {}),
        "analysis": analysis,
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    summary_bytes = json.dumps(summary, default=str, indent=2).encode("utf-8")
    key = put_object(
        ARTIFACTS_BUCKET,
        f"{prefix}incident_summary.json",
        summary_bytes,
    )
    stored_keys.append(key)

    verdict = analysis.get("verdict", "INCONCLUSIVE")
    confidence = analysis.get("confidence", "LOW")
    approval_status = analysis.get("approval_status", "PENDING_HUMAN_APPROVAL")

    result = {
        "ticket_number": ticket_number,
        "s3_bucket": ARTIFACTS_BUCKET,
        "s3_prefix": prefix,
        "stored_keys": stored_keys,
        "recommendation_txt_key": f"{prefix}ai_recommendation.txt",
        "recommendation_json_key": f"{prefix}ai_recommendation.json",
        "summary_json_key": f"{prefix}incident_summary.json",
        "verdict": verdict,
        "confidence": confidence,
        "approval_status": approval_status,
        "store_timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }

    logger.info(
        "Artifacts stored: ticket=%s verdict=%s keys=%s",
        ticket_number,
        verdict,
        stored_keys,
    )

    return result
