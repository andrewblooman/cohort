"""
generate_incident_id/handler.py

Lambda function: Generate Incident ID

First step of the incident-response Step Functions workflow.  Triggered by an
EventBridge rule that matches native GuardDuty findings published to the default
event bus (source ``aws.guardduty``, detail-type ``GuardDuty Finding``).

Responsibilities:
  * Atomically increments a DynamoDB counter to produce a sequential incident
    number in the form ``inc-0001``, ``inc-0002``, … (zero-padded to 4 digits,
    expanding automatically beyond 9999).
  * Normalises the raw GuardDuty finding into the flat workflow payload expected
    by all downstream Lambda functions (EnrichAlert, CollectArtifacts, …).
  * Maps GuardDuty severity floats to HIGH / MEDIUM / LOW labels.
  * Extracts a human-readable ``resource_id`` from the nested finding structure,
    handling the most common GuardDuty resource types.

Environment variables:
  INCIDENT_COUNTER_TABLE  – DynamoDB table name for the atomic incident counter
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

INCIDENT_COUNTER_TABLE = os.environ.get("INCIDENT_COUNTER_TABLE", "")
COUNTER_KEY = "global"


# ---------------------------------------------------------------------------
# DynamoDB counter
# ---------------------------------------------------------------------------

def _get_dynamodb_client():
    return boto3.client("dynamodb")


def generate_ticket_number() -> str:
    """Atomically increment the DynamoDB counter and return a formatted ticket ID.

    Uses the DynamoDB ``ADD`` operator which initialises the attribute to 0
    before adding, so the first call creates the counter item with value 1.

    Returns:
        Ticket number string, e.g. ``"inc-0001"``.

    Raises:
        RuntimeError: If ``INCIDENT_COUNTER_TABLE`` is not configured or the
            DynamoDB call fails.
    """
    if not INCIDENT_COUNTER_TABLE:
        raise RuntimeError("INCIDENT_COUNTER_TABLE environment variable is not set")

    ddb = _get_dynamodb_client()
    try:
        response = ddb.update_item(
            TableName=INCIDENT_COUNTER_TABLE,
            Key={"counter_id": {"S": COUNTER_KEY}},
            UpdateExpression="ADD current_value :inc",
            ExpressionAttributeValues={":inc": {"N": "1"}},
            ReturnValues="UPDATED_NEW",
        )
        value = int(response["Attributes"]["current_value"]["N"])
        return f"inc-{str(value).zfill(4)}"
    except ClientError as exc:
        logger.error("DynamoDB counter increment failed: %s", exc)
        raise RuntimeError(f"Failed to generate incident ID: {exc}") from exc


# ---------------------------------------------------------------------------
# GuardDuty finding normalisation
# ---------------------------------------------------------------------------

_SEVERITY_HIGH = 7.0
_SEVERITY_MEDIUM = 4.0


def map_severity(severity_float: float) -> str:
    """Map a GuardDuty severity float (0.1–10.0) to HIGH / MEDIUM / LOW."""
    if severity_float >= _SEVERITY_HIGH:
        return "HIGH"
    if severity_float >= _SEVERITY_MEDIUM:
        return "MEDIUM"
    return "LOW"


def extract_resource_id(resource: dict) -> str:
    """Extract a human-readable resource identifier from a GuardDuty resource dict.

    Handles the most common GuardDuty resource types:
      * Instance          → EC2 instance ID
      * AccessKey         → IAM access key ID
      * S3Bucket          → bucket name (first bucket in the list)
      * EKSCluster        → cluster name
      * RDSDBInstance     → DB instance identifier
      * Container         → container name
      * Lambda            → function name
      * ECSCluster        → cluster name
      * Fallback          → resourceType string
    """
    resource_type = resource.get("resourceType", "")

    extractors: dict[str, Any] = {
        "Instance": lambda r: (
            r.get("instanceDetails", {}).get("instanceId", "")
        ),
        "AccessKey": lambda r: (
            r.get("accessKeyDetails", {}).get("accessKeyId", "")
        ),
        "S3Bucket": lambda r: (
            (r.get("s3BucketDetails") or [{}])[0].get("name", "")
        ),
        "EKSCluster": lambda r: (
            r.get("eksClusterDetails", {}).get("name", "")
        ),
        "RDSDBInstance": lambda r: (
            r.get("rdsDbInstanceDetails", {}).get("dbInstanceIdentifier", "")
        ),
        "Container": lambda r: (
            r.get("containerDetails", {}).get("name", "")
        ),
        "Lambda": lambda r: (
            r.get("lambdaDetails", {}).get("functionName", "")
        ),
        "ECSCluster": lambda r: (
            r.get("ecsClusterDetails", {}).get("name", "")
        ),
    }

    extractor = extractors.get(resource_type)
    if extractor:
        resource_id = extractor(resource)
        if resource_id:
            return resource_id

    return resource_type or "unknown"


def normalise_finding(finding: dict, account_id: str, event_region: str) -> dict:
    """Normalise a GuardDuty finding dict into the standard workflow payload.

    Args:
        finding: The ``detail`` section of a GuardDuty EventBridge event.
        account_id: AWS account ID from the EventBridge envelope (``$.account``).
        event_region: AWS region from the EventBridge envelope (``$.region``).

    Returns:
        Flat dict with keys: finding_id, alert_type, severity, description,
        account_id, region, resource_type, resource_id.
    """
    resource = finding.get("resource", {})
    resource_type = resource.get("resourceType", "Unknown")
    severity_raw = finding.get("severity", 0)

    try:
        severity_float = float(severity_raw)
    except (TypeError, ValueError):
        severity_float = 0.0

    return {
        "finding_id": finding.get("id", ""),
        "alert_type": finding.get("type", ""),
        "severity": map_severity(severity_float),
        "description": finding.get("description", ""),
        "account_id": finding.get("accountId") or account_id,
        "region": finding.get("region") or event_region,
        "resource_type": resource_type,
        "resource_id": extract_resource_id(resource),
    }


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Generate a sequential incident ID and normalise the GuardDuty finding.

    Args:
        event: Dict with keys ``finding_detail`` (GuardDuty finding), ``account_id``
               and ``event_region`` extracted by the EventBridge input transformer.
        context: Lambda context (unused).

    Returns:
        Normalised workflow payload including the new ``ticket_number``.
    """
    finding = event.get("finding_detail", {})
    account_id = event.get("account_id", "")
    event_region = event.get("event_region", "")

    logger.info(
        "generate_incident_id invoked: finding_type=%s account=%s region=%s",
        finding.get("type", "unknown"),
        account_id,
        event_region,
    )

    ticket_number = generate_ticket_number()
    normalised = normalise_finding(finding, account_id, event_region)

    logger.info("Generated ticket_number=%s for finding_id=%s", ticket_number, normalised.get("finding_id"))

    return {
        "ticket_number": ticket_number,
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        **normalised,
    }
