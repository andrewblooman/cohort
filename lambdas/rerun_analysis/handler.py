"""
rerun_analysis/handler.py

Lambda function: Rerun Analysis

Serves POST /investigations/{ticket_number}/rerun for the Cohort web UI.

Finds the most recent Step Functions execution for the given ticket, aborts
it if it is still RUNNING, and starts a fresh execution with the same
original input so the full pipeline (enrich → collect → analyse → store →
notify) runs again from the beginning.

Environment variables:
  SFN_STATE_MACHINE_ARN  – ARN of the incident-response state machine
  AWS_DEFAULT_REGION     – AWS region (default: us-east-1)
"""

from __future__ import annotations

import json
import logging
import os
import uuid
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


def _find_latest_execution(sfn: Any, ticket_number: str) -> tuple[str | None, str | None, str | None]:
    """Return (execution_arn, status, original_input_json) for the most recent execution.

    Returns (None, None, None) if no matching execution is found.
    """
    if not SFN_STATE_MACHINE_ARN:
        return None, None, None

    try:
        response = sfn.list_executions(
            stateMachineArn=SFN_STATE_MACHINE_ARN,
            maxResults=50,
        )
    except ClientError as exc:
        logger.error("list_executions failed: %s", exc)
        raise

    for summary in response.get("executions", []):
        exec_arn = summary["executionArn"]
        try:
            desc = sfn.describe_execution(executionArn=exec_arn)
            input_str = desc.get("input", "{}")
            input_data = json.loads(input_str)
            if input_data.get("ticket_number") == ticket_number:
                return exec_arn, summary.get("status", ""), input_str
        except (ClientError, json.JSONDecodeError) as exc:
            logger.warning("Skipping execution %s: %s", exec_arn, exc)
            continue

    return None, None, None


def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Entry point for the rerun-analysis Lambda.

    Finds the most recent execution for the ticket, aborts it if RUNNING,
    then starts a new execution with the original input.

    Args:
        event: API Gateway v2 HTTP event with pathParameters.ticket_number.
        context: Lambda context (unused).

    Returns:
        API Gateway HTTP response with new execution ARN.
    """
    path_params = event.get("pathParameters") or {}
    ticket_number = path_params.get("ticket_number", "").strip()

    if not ticket_number:
        return {
            "statusCode": 400,
            "headers": _CORS_HEADERS,
            "body": json.dumps({"error": "ticket_number path parameter is required"}),
        }

    if not SFN_STATE_MACHINE_ARN:
        return {
            "statusCode": 500,
            "headers": _CORS_HEADERS,
            "body": json.dumps({"error": "SFN_STATE_MACHINE_ARN is not configured"}),
        }

    logger.info("rerun_analysis: ticket=%s", ticket_number)

    sfn = _sfn_client()

    try:
        exec_arn, exec_status, original_input = _find_latest_execution(sfn, ticket_number)
    except ClientError as exc:
        return {
            "statusCode": 500,
            "headers": _CORS_HEADERS,
            "body": json.dumps({"error": str(exc)}),
        }

    if original_input is None:
        return {
            "statusCode": 404,
            "headers": _CORS_HEADERS,
            "body": json.dumps({"error": f"No execution found for ticket: {ticket_number}"}),
        }

    aborted_arn: str | None = None
    if exec_status == "RUNNING":
        try:
            sfn.stop_execution(
                executionArn=exec_arn,
                cause="Rerun requested by analyst via Cohort web UI",
            )
            aborted_arn = exec_arn
            logger.info("Aborted running execution %s for ticket %s", exec_arn, ticket_number)
        except ClientError as exc:
            logger.warning("Could not abort execution %s: %s", exec_arn, exc)

    new_name = f"{ticket_number[:36]}-rerun-{uuid.uuid4().hex[:8]}"
    try:
        new_exec = sfn.start_execution(
            stateMachineArn=SFN_STATE_MACHINE_ARN,
            name=new_name,
            input=original_input,
        )
    except ClientError as exc:
        logger.error("start_execution failed: %s", exc)
        return {
            "statusCode": 500,
            "headers": _CORS_HEADERS,
            "body": json.dumps({"error": str(exc)}),
        }

    logger.info(
        "Started new execution %s for ticket %s (aborted: %s)",
        new_exec["executionArn"],
        ticket_number,
        aborted_arn,
    )

    return {
        "statusCode": 200,
        "headers": _CORS_HEADERS,
        "body": json.dumps({
            "status": "started",
            "ticket_number": ticket_number,
            "execution_arn": new_exec["executionArn"],
            "execution_name": new_name,
            "aborted_execution": aborted_arn,
        }, default=str),
    }
