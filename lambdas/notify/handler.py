"""
notify/handler.py

Lambda function: Notify

Used at two points in the incident-response Step Functions workflow:

Phase 1 — Investigation complete (notify_mode = "investigation", default):
    Stores ``pending_approval.json`` to S3 so the web UI can surface the
    analyst approval form.  Optionally sends a rich Slack notification (Block
    Kit) with the verdict, threat summary, and a link to the investigation
    page.  When invoked via the ``Notify`` waitForTaskToken state the event
    will contain a ``task_token`` which is stored in S3 for use by the
    ``approve_actions`` Lambda.

Phase 2 — Execution complete (notify_mode = "execution_results"):
    Updates S3 with the execution outcome and posts a follow-up Slack message
    summarising the remediation results.

Slack notifications are optional.  Set ``SLACK_WEBHOOK_SECRET_ARN`` to the
ARN of a Secrets Manager secret whose ``SecretString`` is the Slack Incoming
Webhook URL.  If the variable is empty or the secret cannot be retrieved,
Slack notification is silently skipped.

Environment variables:
  ARTIFACTS_BUCKET          – S3 bucket for incident artifacts
  SLACK_WEBHOOK_SECRET_ARN  – Secrets Manager ARN for the Slack webhook URL
  APPROVAL_API_ENDPOINT     – Base URL of the API Gateway (used to build the
                              web UI link included in Slack messages)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET", "")
SLACK_WEBHOOK_SECRET_ARN = os.environ.get("SLACK_WEBHOOK_SECRET_ARN", "")
APPROVAL_API_ENDPOINT = os.environ.get("APPROVAL_API_ENDPOINT", "")

VERDICT_EMOJI = {
    "TRUE_POSITIVE": "🔴",
    "FALSE_POSITIVE": "🟢",
    "INCONCLUSIVE": "🟡",
}

VERDICT_LABEL = {
    "TRUE_POSITIVE": "TRUE POSITIVE – Confirmed Threat",
    "FALSE_POSITIVE": "FALSE POSITIVE – Benign Activity",
    "INCONCLUSIVE": "INCONCLUSIVE – Manual Review Required",
}

SEVERITY_EMOJI = {
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🔵",
}


# ---------------------------------------------------------------------------
# Slack helpers
# ---------------------------------------------------------------------------

def get_slack_webhook_url() -> str | None:
    """Retrieve the Slack webhook URL from Secrets Manager.

    Returns ``None`` (and logs a warning) if the secret ARN is not configured
    or the retrieval fails.
    """
    if not SLACK_WEBHOOK_SECRET_ARN:
        return None

    sm = boto3.client("secretsmanager")
    try:
        response = sm.get_secret_value(SecretId=SLACK_WEBHOOK_SECRET_ARN)
        url = response.get("SecretString", "").strip()
        if not url:
            logger.warning("Slack webhook secret is empty")
            return None
        return url
    except ClientError as exc:
        logger.warning("Could not retrieve Slack webhook URL: %s", exc)
        return None


def post_slack_message(webhook_url: str, payload: dict) -> bool:
    """POST a JSON payload to a Slack Incoming Webhook URL.

    Returns:
        ``True`` on success, ``False`` on any HTTP/network error.
    """
    body = json.dumps(payload).encode("utf-8")
    req = Request(webhook_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=10) as resp:
            _ = resp.read()
            return True
    except HTTPError as exc:
        logger.warning("Slack webhook HTTP error: %s %s", exc.code, exc.reason)
        return False
    except URLError as exc:
        logger.warning("Slack webhook URL error: %s", exc)
        return False


def _investigation_url(ticket_number: str) -> str | None:
    """Build the web UI investigation URL if the API endpoint is configured."""
    base = APPROVAL_API_ENDPOINT.rstrip("/")
    if not base:
        return None
    return f"{base}/investigation.html?ticket={ticket_number}"


def build_investigation_slack_message(event: dict, analysis: dict) -> dict:
    """Build a Slack Block Kit payload for a new investigation awaiting review.

    Args:
        event: The notify Lambda event (contains ticket_number, severity, etc.).
        analysis: Normalised analysis dict (verdict, confidence, threat_summary, …).

    Returns:
        Slack API payload dict with ``blocks`` and a plain-text ``text`` fallback.
    """
    ticket_number = event.get("ticket_number", "UNKNOWN")
    severity = event.get("severity", "")
    alert_type = event.get("alert_type", "")
    account_id = event.get("account_id", "")
    region = event.get("region", "")

    verdict = analysis.get("verdict", "INCONCLUSIVE")
    confidence = analysis.get("confidence", "")
    threat_summary = analysis.get("threat_summary", "No summary available.")
    proposed_actions = analysis.get("proposed_actions", analysis.get("recommendations", []))

    verdict_emoji = VERDICT_EMOJI.get(verdict, "🟡")
    verdict_label = VERDICT_LABEL.get(verdict, verdict)
    severity_icon = SEVERITY_EMOJI.get(severity, "")

    # Truncate threat summary for Slack display
    summary_display = threat_summary[:300] + "…" if len(threat_summary) > 300 else threat_summary

    actions_text = (
        "\n".join(f"• {a}" for a in proposed_actions[:5])
        if proposed_actions
        else "_No specific actions proposed._"
    )
    if len(proposed_actions) > 5:
        actions_text += f"\n_…and {len(proposed_actions) - 5} more — see investigation page_"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 New Incident: {ticket_number} — Analyst Review Required",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Alert Type:*\n{alert_type}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity_icon} {severity}"},
                {"type": "mrkdwn", "text": f"*Verdict:*\n{verdict_emoji} {verdict_label}"},
                {"type": "mrkdwn", "text": f"*Confidence:*\n{confidence}"},
                {"type": "mrkdwn", "text": f"*Account:*\n{account_id}"},
                {"type": "mrkdwn", "text": f"*Region:*\n{region}"},
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Threat Summary:*\n{summary_display}"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Proposed Actions:*\n{actions_text}"},
        },
    ]

    inv_url = _investigation_url(ticket_number)
    if inv_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔍 Review Investigation", "emoji": True},
                        "url": inv_url,
                        "style": "primary",
                    }
                ],
            }
        )
    else:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "ℹ️ Set APPROVAL_API_ENDPOINT to include a direct link to the investigation.",
                    }
                ],
            }
        )

    blocks.append({"type": "divider"})
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        "⚠️ *No automated actions have been taken.* "
                        "All proposed actions require explicit analyst approval before execution."
                    ),
                }
            ],
        }
    )

    return {
        "text": f"🚨 New incident {ticket_number} ({severity}) needs analyst review — verdict: {verdict_label}",
        "blocks": blocks,
    }


def build_execution_slack_message(event: dict, execution: dict) -> dict:
    """Build a Slack Block Kit payload summarising completed remediation actions.

    Args:
        event: The notify Lambda event (contains ticket_number).
        execution: Execution results dict (analyst_id, total_actions, succeeded, failed, results).

    Returns:
        Slack API payload dict.
    """
    ticket_number = event.get("ticket_number", "UNKNOWN")
    analyst_id = execution.get("analyst_id", "unknown")
    total = execution.get("total_actions", 0)
    succeeded = execution.get("succeeded", 0)
    failed = execution.get("failed", 0)
    results = execution.get("results", [])

    status_emoji = "✅" if failed == 0 else "⚠️"
    status_text = f"{succeeded}/{total} actions succeeded" + (f", {failed} failed" if failed else "")

    result_lines = []
    for r in results:
        icon = "✅" if r.get("status") == "succeeded" else ("❌" if r.get("status") == "failed" else "⏭️")
        detail = r.get("details") or r.get("error", "")
        result_lines.append(f"{icon} *{r.get('type', '')}*: {r.get('status', '')} — {detail}")
    results_text = "\n".join(result_lines) if result_lines else "_No actions were executed._"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{status_emoji} Incident {ticket_number} — Remediation Complete",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Authorised by:*\n{analyst_id}"},
                {"type": "mrkdwn", "text": f"*Actions:*\n{status_text}"},
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Execution Results:*\n{results_text}"},
        },
    ]

    return {
        "text": f"{status_emoji} Incident {ticket_number} remediation complete — {status_text}",
        "blocks": blocks,
    }


# ---------------------------------------------------------------------------
# S3 pending approval store
# ---------------------------------------------------------------------------

def _store_pending_approval(ticket_number: str, task_token: str, analysis: dict) -> None:
    """Write ``pending_approval.json`` to S3 for the web UI analyst approval form."""
    if not ARTIFACTS_BUCKET or not task_token or not ticket_number:
        return
    s3 = boto3.client("s3")
    data = {
        "task_token": task_token,
        "ticket_number": ticket_number,
        "verdict": analysis.get("verdict"),
        "confidence": analysis.get("confidence"),
        "proposed_actions": analysis.get("proposed_actions", []),
        "threat_summary": analysis.get("threat_summary", ""),
        "stored_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    try:
        s3.put_object(
            Bucket=ARTIFACTS_BUCKET,
            Key=f"{ticket_number}/pending_approval.json",
            Body=json.dumps(data, indent=2).encode("utf-8"),
            ContentType="application/json",
        )
        logger.info("Stored pending_approval.json for ticket=%s", ticket_number)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not store pending_approval.json for ticket=%s: %s", ticket_number, exc)


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Entry point for the notify Lambda.

    Handles two notify modes set by the ``notify_mode`` event field:

    ``"investigation"`` (default):
        Stores ``pending_approval.json`` to S3 and sends a Slack message
        prompting the analyst to review the investigation.

    ``"execution_results"``:
        Sends a Slack follow-up message with the remediation outcome.

    Args:
        event: Step Functions payload.
        context: Lambda context (unused).

    Returns:
        Dict describing the notification outcome.
    """
    ticket_number = event.get("ticket_number", "UNKNOWN")
    notify_mode = event.get("notify_mode", "investigation")
    logger.info("notify invoked for ticket=%s mode=%s", ticket_number, notify_mode)

    base_result = {
        "ticket_number": ticket_number,
        "notify_mode": notify_mode,
        "notify_timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }

    if notify_mode == "execution_results":
        execution_wrapper = event.get("execution_result", {})
        execution = execution_wrapper.get("execution", execution_wrapper)

        slack_payload = build_execution_slack_message(event, execution)
        slack_status = _send_slack(slack_payload)

        return {
            **base_result,
            "slack_status": slack_status,
        }

    # investigation mode (default)
    analysis_wrapper = event.get("analysis_result", {})
    analysis = analysis_wrapper.get("analysis", analysis_wrapper)
    verdict = analysis.get("verdict", "INCONCLUSIVE")
    confidence = analysis.get("confidence", "LOW")
    approval_status = analysis.get("approval_status", "PENDING_HUMAN_APPROVAL")

    task_token = event.get("task_token", "")
    if task_token:
        _store_pending_approval(ticket_number, task_token, analysis)

    slack_payload = build_investigation_slack_message(event, analysis)
    slack_status = _send_slack(slack_payload)

    return {
        **base_result,
        "verdict": verdict,
        "confidence": confidence,
        "approval_status": approval_status,
        "slack_status": slack_status,
    }


def _send_slack(payload: dict) -> str:
    """Retrieve the Slack webhook URL and post ``payload``.

    Returns a status string: ``"sent"``, ``"skipped"`` (not configured), or
    ``"failed"`` (webhook returned an error).
    """
    webhook_url = get_slack_webhook_url()
    if not webhook_url:
        logger.info("Slack webhook not configured; skipping notification")
        return "skipped"

    success = post_slack_message(webhook_url, payload)
    if success:
        logger.info("Slack notification sent successfully")
        return "sent"
    logger.warning("Slack notification failed")
    return "failed"
