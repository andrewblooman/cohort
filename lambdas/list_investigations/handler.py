"""
list_investigations/handler.py

Lambda function: List Investigations

Serves GET /investigations for the Cohort web UI.

Queries the Step Functions state machine for recent executions and
returns a list of investigations with their current status and, when
available, the AI verdict extracted from the execution output.

Additionally scans the artifacts S3 bucket for ticket prefixes so that
investigations older than the SFN execution history window (90 days) still
appear in the dashboard. S3-discovered tickets are supplemented with metadata
from their incident_summary.json file.

Environment variables:
  SFN_STATE_MACHINE_ARN  – ARN of the incident-response state machine
  ARTIFACTS_BUCKET       – S3 bucket containing incident artifacts (for fallback listing)
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
ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET", "")
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

_CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
}


def _sfn_client() -> Any:
    return boto3.client("stepfunctions", region_name=AWS_REGION)


def _s3_client() -> Any:
    return boto3.client("s3")


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


def _list_s3_ticket_prefixes(s3: Any) -> list[str]:
    """List all ticket-number prefixes in the artifacts S3 bucket.

    Returns a list of ticket numbers (i.e. top-level prefixes without trailing slash).
    Returns an empty list if ARTIFACTS_BUCKET is not set or a S3 error occurs.
    """
    if not ARTIFACTS_BUCKET:
        return []
    try:
        prefixes: list[str] = []
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=ARTIFACTS_BUCKET, Delimiter="/"):
            for cp in page.get("CommonPrefixes", []):
                prefix = cp.get("Prefix", "")
                if prefix.endswith("/"):
                    prefixes.append(prefix[:-1])
        return prefixes
    except ClientError as exc:
        logger.warning("S3 prefix listing failed: %s", exc)
        return []


def _read_s3_incident_summary(s3: Any, ticket_number: str) -> dict:
    """Read incident_summary.json for a ticket from S3. Returns {} on any error."""
    try:
        key = f"{ticket_number}/incident_summary.json"
        obj = s3.get_object(Bucket=ARTIFACTS_BUCKET, Key=key)
        return json.loads(obj["Body"].read())
    except (ClientError, json.JSONDecodeError, KeyError) as exc:
        logger.debug("Could not read summary for %s: %s", ticket_number, exc)
        return {}


def _record_from_s3_summary(ticket_number: str, summary: dict) -> dict:
    """Build an investigation record from an S3 incident_summary.json."""
    incident = summary.get("incident", {})
    analysis = summary.get("analysis", {})
    generated_at = summary.get("generated_at")
    return {
        "ticket_number": ticket_number,
        "alert_type": incident.get("alert_type", ""),
        "severity": incident.get("severity", ""),
        "finding_id": incident.get("finding_id", ""),
        "account_id": incident.get("account_id", ""),
        "region": incident.get("region", ""),
        "secops_case_id": incident.get("secops_case_id", ""),
        "execution_arn": None,
        "execution_name": None,
        "status": "HISTORICAL",
        "start_date": generated_at,
        "stop_date": generated_at,
        "verdict": analysis.get("verdict"),
        "confidence": analysis.get("confidence"),
    }


def list_investigations(sfn: Any, s3: Any, limit: int, status_filter: str | None) -> list[dict]:
    """Query SFN for recent executions and supplement with S3 historical records.

    SFN results come first (richer metadata, live status). Tickets present in S3 but
    absent from the SFN results are appended from their incident_summary.json files
    until the combined list reaches `limit`.
    """
    sfn_tickets: set[str] = set()

    investigations: list[dict] = []

    if SFN_STATE_MACHINE_ARN:
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

            ticket = input_data.get("ticket_number", "UNKNOWN")
            sfn_tickets.add(ticket)

            investigations.append({
                "ticket_number": ticket,
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
    else:
        logger.warning("SFN_STATE_MACHINE_ARN not set; falling back to S3 listing only")

    # When a status filter is active we only want SFN results (S3 records have no live status).
    if not status_filter and len(investigations) < limit:
        remaining = limit - len(investigations)
        s3_prefixes = _list_s3_ticket_prefixes(s3)
        for ticket_number in s3_prefixes:
            if ticket_number in sfn_tickets:
                continue
            summary = _read_s3_incident_summary(s3, ticket_number)
            if not summary:
                continue
            investigations.append(_record_from_s3_summary(ticket_number, summary))
            remaining -= 1
            if remaining == 0:
                break

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
        s3 = _s3_client()
        investigations = list_investigations(sfn, s3, limit, status_filter)
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
