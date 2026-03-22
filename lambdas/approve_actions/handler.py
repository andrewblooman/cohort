"""
approve_actions/handler.py

Lambda function: Approve Actions

Human-in-the-loop callback for the incident-response Step Functions workflow.
Called by the analyst after reviewing the AI's proposed actions in Google SecOps.

This Lambda validates the approval payload and calls sfn.send_task_success to
resume the paused ``NotifySIEM`` state and proceed to ``ExecuteApprovedActions``.

Invocation payload:
    {
        "task_token": "<Step Functions task token from the SIEM comment>",
        "analyst_id": "<analyst email or username>",
        "approval_notes": "<optional — context for the audit trail>",
        "approved_actions": [
            {
                "action_id": "<unique label for this action>",
                "type": "<action type — see SUPPORTED_ACTION_TYPES>",
                "parameters": { ... }
            }
        ]
    }

To REJECT (cancel remediation entirely), send:
    {
        "action": "reject",
        "task_token": "<token>",
        "analyst_id": "<id>",
        "rejection_reason": "<optional reason>"
    }

Supported action types (executed by the execute_actions Lambda):
    isolate_ec2_instance        params: instance_id, region
    stop_ec2_instance           params: instance_id, region
    snapshot_ec2_instance       params: instance_id, region
    deactivate_iam_access_key   params: user_name, access_key_id
    revoke_iam_role_sessions    params: role_name
    archive_guardduty_finding   params: finding_id, detector_id, region
    block_s3_public_access      params: bucket_name
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

AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

SUPPORTED_ACTION_TYPES = {
    "isolate_ec2_instance",
    "stop_ec2_instance",
    "snapshot_ec2_instance",
    "deactivate_iam_access_key",
    "revoke_iam_role_sessions",
    "archive_guardduty_finding",
    "block_s3_public_access",
}


# ---------------------------------------------------------------------------
# AWS client helpers
# ---------------------------------------------------------------------------

def _sfn_client() -> Any:
    return boto3.client("stepfunctions", region_name=AWS_REGION)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_approval(event: dict) -> list[str]:
    """Validate the analyst approval payload.  Returns a list of error messages."""
    errors: list[str] = []

    if not event.get("task_token"):
        errors.append("task_token is required")
    if not event.get("analyst_id"):
        errors.append("analyst_id is required")

    approved_actions = event.get("approved_actions")
    if not isinstance(approved_actions, list):
        errors.append("approved_actions must be a list")
    else:
        for i, action in enumerate(approved_actions):
            if not isinstance(action, dict):
                errors.append(f"approved_actions[{i}] must be an object")
                continue
            if not action.get("type"):
                errors.append(f"approved_actions[{i}].type is required")
            elif action["type"] not in SUPPORTED_ACTION_TYPES:
                errors.append(
                    f"approved_actions[{i}].type '{action['type']}' is not supported. "
                    f"Valid types: {sorted(SUPPORTED_ACTION_TYPES)}"
                )
            if not isinstance(action.get("parameters", {}), dict):
                errors.append(f"approved_actions[{i}].parameters must be an object")

    return errors


# ---------------------------------------------------------------------------
# Step Functions callbacks
# ---------------------------------------------------------------------------

def send_approval(task_token: str, payload: dict) -> None:
    """Resume the paused Step Functions workflow with the analyst's approved actions."""
    sfn = _sfn_client()
    sfn.send_task_success(
        taskToken=task_token,
        output=json.dumps(payload),
    )
    logger.info(
        "send_task_success: analyst=%s approved_actions=%d",
        payload.get("analyst_id"),
        len(payload.get("approved_actions", [])),
    )


def send_rejection(task_token: str, analyst_id: str, reason: str) -> None:
    """Cancel the workflow — analyst declined to authorise any remediation."""
    sfn = _sfn_client()
    sfn.send_task_failure(
        taskToken=task_token,
        error="AnalystRejected",
        cause=reason[:256],
    )
    logger.info("send_task_failure: analyst=%s reason=%s", analyst_id, reason)


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Entry point for the approve-actions Lambda.

    Args:
        event: Analyst approval or rejection payload.
        context: Lambda context (unused).

    Returns:
        Dict with approval status, suitable for API Gateway response.
    """
    analyst_id = event.get("analyst_id", "UNKNOWN")
    logger.info("approve_actions invoked by analyst=%s action=%s", analyst_id, event.get("action", "approve"))

    # ---- Rejection path ----
    if event.get("action") == "reject":
        task_token = event.get("task_token", "")
        if not task_token:
            return {"status": "error", "message": "task_token is required for rejection"}
        if not analyst_id or analyst_id == "UNKNOWN":
            return {"status": "error", "message": "analyst_id is required for rejection"}

        reason = event.get("rejection_reason", "Analyst declined to authorise proposed actions")
        try:
            send_rejection(task_token, analyst_id, reason)
        except ClientError as exc:
            logger.error("Failed to send rejection: %s", exc)
            return {"status": "error", "message": str(exc)}

        return {
            "status": "rejected",
            "analyst_id": analyst_id,
            "reason": reason,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }

    # ---- Approval path ----
    errors = validate_approval(event)
    if errors:
        logger.warning("Invalid approval payload: %s", errors)
        return {"status": "error", "errors": errors}

    task_token = event["task_token"]
    approved_actions = event.get("approved_actions", [])
    approval_notes = event.get("approval_notes", "")
    approval_timestamp = datetime.now(tz=timezone.utc).isoformat()

    approval_payload = {
        "analyst_id": analyst_id,
        "approved_actions": approved_actions,
        "approval_notes": approval_notes,
        "approval_timestamp": approval_timestamp,
    }

    try:
        send_approval(task_token, approval_payload)
    except ClientError as exc:
        logger.error("Failed to resume Step Functions workflow: %s", exc)
        return {"status": "error", "message": str(exc)}

    logger.info(
        "Approval submitted: analyst=%s actions=%d timestamp=%s",
        analyst_id,
        len(approved_actions),
        approval_timestamp,
    )

    return {
        "status": "approved",
        "analyst_id": analyst_id,
        "approved_actions_count": len(approved_actions),
        "approval_timestamp": approval_timestamp,
    }
