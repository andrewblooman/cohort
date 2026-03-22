"""
list_investigations/handler.py

Lambda function: List Investigations

Serves GET /investigations for the Cohort web UI.

Queries the Step Functions state machine for recent executions and
returns a list of investigations with their current status and, when
available, the AI verdict extracted from the execution output.

Environment variables:
  SFN_STATE_MACHINE_ARN  – ARN of the incident-response state machine
  AWS_DEFAULT_REGION     – AWS region (default: us-east-1)

Query string parameters:
  limit   – maximum results to return (default: 20, max: 50)
  status  – filter by SFN execution status: RUNNING | SUCCEEDED | FAILED |
             TIMED_OUT | ABORTED (optional)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SFN_STATE_MACHINE_ARN = os.environ.get("SFN_STATE_MACHINE_ARN", "")
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

_CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
}


def _sfn_client() -> Any:
    return boto3.client("stepfunctions", region_name=AWS_REGION)


def _extract_verdict_from_output(output_str: str) -> tuple[str | None, str | None]:
    """Try to extract verdict and confidence from a completed execution output JSON."""
    if not output_str:
        return None, None
    try:
        output = json.loads(output_str)
        analysis = (
            output.get("analysis_result", {}).get("analysis", {})
            or output.get("analysis", {})
        )
        return analysis.get("verdict"), analysis.get("confidence")
    except (json.JSONDecodeError, AttributeError):
        return None, None


def list_investigations(sfn: Any, limit: int, status_filter: str | None) -> list[dict]:
    """Query SFN for recent executions and return formatted investigation records."""
    if not SFN_STATE_MACHINE_ARN:
        logger.warning("SFN_STATE_MACHINE_ARN not set; returning empty list")
        return []

    kwargs: dict[str, Any] = {
        "stateMachineArn": SFN_STATE_MACHINE_ARN,
        "maxResults": limit,
    }
    if status_filter:
        kwargs["statusFilter"] = status_filter

    try:
        response = sfn.list_executions(**kwargs)
    except ClientError as exc:
        logger.error("list_executions failed: %s", exc)
        raise

    investigations: list[dict] = []
    for summary in response.get("executions", []):
        exec_arn = summary["executionArn"]
        try:
            desc = sfn.describe_execution(executionArn=exec_arn)
        except ClientError as exc:
            logger.warning("describe_execution failed for %s: %s", exec_arn, exc)
            continue

        input_data: dict = {}
        try:
            input_data = json.loads(desc.get("input", "{}"))
        except json.JSONDecodeError:
            pass

        verdict, confidence = _extract_verdict_from_output(desc.get("output", ""))

        start_date = summary.get("startDate")
        stop_date = summary.get("stopDate")

        investigations.append({
            "ticket_number": input_data.get("ticket_number", "UNKNOWN"),
            "alert_type": input_data.get("alert_type", ""),
            "severity": input_data.get("severity", ""),
            "finding_id": input_data.get("finding_id", ""),
            "account_id": input_data.get("account_id", ""),
            "region": input_data.get("region", ""),
            "secops_case_id": input_data.get("secops_case_id", ""),
            "execution_arn": exec_arn,
            "execution_name": summary.get("name", ""),
            "status": summary.get("status", ""),
            "start_date": start_date.isoformat() if start_date else None,
            "stop_date": stop_date.isoformat() if stop_date else None,
            "verdict": verdict,
            "confidence": confidence,
        })

    return investigations


def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Entry point for the list-investigations Lambda.

    Args:
        event: API Gateway v2 HTTP event.
        context: Lambda context (unused).

    Returns:
        API Gateway HTTP response with investigations list.
    """
    params = event.get("queryStringParameters") or {}
    try:
        limit = min(int(params.get("limit", 20)), 50)
    except (ValueError, TypeError):
        limit = 20
    status_filter = params.get("status")

    logger.info("list_investigations: limit=%d status=%s", limit, status_filter)

    try:
        sfn = _sfn_client()
        investigations = list_investigations(sfn, limit, status_filter)
    except ClientError as exc:
        logger.error("Failed to list investigations: %s", exc)
        return {
            "statusCode": 500,
            "headers": _CORS_HEADERS,
            "body": json.dumps({"error": str(exc)}),
        }

    return {
        "statusCode": 200,
        "headers": _CORS_HEADERS,
        "body": json.dumps(
            {"investigations": investigations, "count": len(investigations)},
            default=str,
        ),
    }
