"""
get_investigation/handler.py

Lambda function: Get Investigation

Serves GET /investigations/{ticket_number} for the Cohort web UI.

Reads the incident_summary.json and pending_approval.json artifacts from S3
and looks up the current Step Functions execution status for the ticket.

Environment variables:
  ARTIFACTS_BUCKET       – S3 bucket containing incident artifacts
  SFN_STATE_MACHINE_ARN  – ARN of the incident-response state machine
  AWS_DEFAULT_REGION     – AWS region (default: us-east-1)
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

ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET", "")
SFN_STATE_MACHINE_ARN = os.environ.get("SFN_STATE_MACHINE_ARN", "")
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

_CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
}


def _s3_client() -> Any:
    return boto3.client("s3")


def _sfn_client() -> Any:
    return boto3.client("stepfunctions", region_name=AWS_REGION)


def _read_s3_json(s3: Any, key: str) -> dict | None:
    """Read and parse a JSON object from S3. Returns None if key does not exist."""
    try:
        obj = s3.get_object(Bucket=ARTIFACTS_BUCKET, Key=key)
        return json.loads(obj["Body"].read())
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("NoSuchKey", "404", "NoSuchBucket"):
            return None
        logger.error("S3 error reading %s: %s", key, exc)
        return None
    except json.JSONDecodeError as exc:
        logger.error("JSON decode error for %s: %s", key, exc)
        return None


def _find_execution(sfn: Any, ticket_number: str) -> dict | None:
    """Return the most recent SFN execution whose input contains this ticket_number."""
    if not SFN_STATE_MACHINE_ARN:
        return None
    try:
        response = sfn.list_executions(
            stateMachineArn=SFN_STATE_MACHINE_ARN,
            maxResults=50,
        )
    except ClientError as exc:
        logger.error("list_executions failed: %s", exc)
        return None

    for summary in response.get("executions", []):
        exec_arn = summary["executionArn"]
        try:
            desc = sfn.describe_execution(executionArn=exec_arn)
            input_data = json.loads(desc.get("input", "{}"))
            if input_data.get("ticket_number") == ticket_number:
                start_date = summary.get("startDate")
                stop_date = summary.get("stopDate")
                return {
                    "execution_arn": exec_arn,
                    "execution_name": summary.get("name", ""),
                    "status": summary.get("status", ""),
                    "start_date": start_date.isoformat() if start_date else None,
                    "stop_date": stop_date.isoformat() if stop_date else None,
                }
        except (ClientError, json.JSONDecodeError) as exc:
            logger.warning("Skipping execution %s: %s", exec_arn, exc)
            continue

    return None


def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Entry point for the get-investigation Lambda.

    Args:
        event: API Gateway v2 HTTP event with pathParameters.ticket_number.
        context: Lambda context (unused).

    Returns:
        API Gateway HTTP response with investigation details.
    """
    path_params = event.get("pathParameters") or {}
    ticket_number = path_params.get("ticket_number", "").strip()

    if not ticket_number:
        return {
            "statusCode": 400,
            "headers": _CORS_HEADERS,
            "body": json.dumps({"error": "ticket_number path parameter is required"}),
        }

    logger.info("get_investigation: ticket=%s", ticket_number)

    s3 = _s3_client()
    sfn = _sfn_client()

    incident_summary = _read_s3_json(s3, f"{ticket_number}/incident_summary.json")
    pending_approval = _read_s3_json(s3, f"{ticket_number}/pending_approval.json")
    execution = _find_execution(sfn, ticket_number)

    if incident_summary is None and execution is None:
        return {
            "statusCode": 404,
            "headers": _CORS_HEADERS,
            "body": json.dumps({"error": f"Investigation not found: {ticket_number}"}),
        }

    return {
        "statusCode": 200,
        "headers": _CORS_HEADERS,
        "body": json.dumps(
            {
                "ticket_number": ticket_number,
                "incident_summary": incident_summary,
                "pending_approval": pending_approval,
                "execution": execution,
            },
            default=str,
        ),
    }
