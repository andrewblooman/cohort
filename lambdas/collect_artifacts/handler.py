"""
collect_artifacts/handler.py

Lambda function: Collect Artifacts

Second step in the incident-response Step Functions workflow.
Downloads and stores raw evidence for the incident into the S3 artifacts bucket,
creating the folder structure:

    s3://<bucket>/<ticket_number>/
        guardduty_finding.json
        cloudtrail_events.json
        vpc_flow_logs.json          (when ENABLE_VPC_FLOW_LOG_COLLECTION=true)
        cloudwatch_logs.json        (when ENABLE_CLOUDTRAIL_COLLECTION=true)

Returns a manifest of all S3 keys written so that subsequent steps can locate
the artifacts without re-querying AWS.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Ensure the repository root is on the path so the shared package is importable.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from shared.cloudwatch_queries import (  # noqa: E402
    find_log_groups,
    run_insights_query,
    wait_for_query_results as _shared_wait_for_query_results,
    parse_insights_results as _shared_parse_insights_results,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET", "")
ENABLE_VPC_FLOW_LOG_COLLECTION = os.environ.get("ENABLE_VPC_FLOW_LOG_COLLECTION", "true").lower() == "true"
ENABLE_CLOUDTRAIL_COLLECTION = os.environ.get("ENABLE_CLOUDTRAIL_COLLECTION", "true").lower() == "true"
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# S3 helpers
# ---------------------------------------------------------------------------

def _s3_client() -> Any:
    return boto3.client("s3")


def put_artifact(bucket: str, key: str, data: Any) -> str:
    """Serialise *data* to JSON and upload to S3.  Returns the S3 key."""
    s3 = _s3_client()
    body = json.dumps(data, default=str, indent=2).encode("utf-8")
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType="application/json",
    )
    logger.info("Uploaded artifact to s3://%s/%s (%d bytes)", bucket, key, len(body))
    return key


# ---------------------------------------------------------------------------
# VPC Flow Logs collection (delegates to shared.cloudwatch_queries)
# ---------------------------------------------------------------------------

def collect_vpc_flow_logs(resource_id: str, region: str, hours_back: int = 24) -> list[dict]:
    """Query CloudWatch Logs Insights for VPC flow logs related to the resource."""
    if not resource_id:
        return []

    log_groups = _find_vpc_flow_log_groups_via_shared(region)
    if not log_groups:
        logger.info("No VPC flow log groups found in region %s", region)
        return []

    query = (
        f"fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, action, bytes, packets "
        f"| filter srcAddr = '{resource_id}' or dstAddr = '{resource_id}' "
        f"| sort @timestamp desc "
        f"| limit 500"
    )

    return run_insights_query(
        query=query,
        log_groups=log_groups,
        region=region,
        hours_back=hours_back,
    )


def _find_vpc_flow_log_groups(logs_client: Any) -> list[str]:
    """Return CloudWatch log group names that look like VPC flow log groups."""
    try:
        paginator = logs_client.get_paginator("describe_log_groups")
        groups: list[str] = []
        for page in paginator.paginate(PaginationConfig={"MaxItems": 50}):
            for group in page.get("logGroups", []):
                name: str = group.get("logGroupName", "")
                if "vpc" in name.lower() or "flow" in name.lower():
                    groups.append(name)
        return groups
    except ClientError as exc:
        logger.warning("Could not list CloudWatch log groups: %s", exc)
        return []


def _find_vpc_flow_log_groups_via_shared(region: str) -> list[str]:
    """Find VPC flow log groups using the shared utility."""
    return find_log_groups(region, "vpc", "flow")


def _wait_for_query_results(logs_client: Any, query_id: str, max_wait: int = 60) -> list[dict]:
    """Poll until the Insights query finishes and return structured results."""
    return _shared_wait_for_query_results(logs_client, query_id, max_wait=max_wait)


def _parse_insights_results(results: list[list[dict]]) -> list[dict]:
    """Convert Insights result rows into plain dicts."""
    return _shared_parse_insights_results(results)


# ---------------------------------------------------------------------------
# CloudTrail log collection via CloudWatch Logs Insights
# (delegates to shared.cloudwatch_queries)
# ---------------------------------------------------------------------------

def collect_cloudtrail_logs(resource_id: str, region: str, hours_back: int = 24) -> list[dict]:
    """Query CloudWatch Logs Insights for CloudTrail events related to the resource."""
    if not resource_id:
        return []

    log_groups = _find_cloudtrail_log_groups_via_shared(region)
    if not log_groups:
        logger.info("No CloudTrail log groups found in region %s", region)
        return []

    query = (
        f"fields @timestamp, eventName, eventSource, userIdentity.arn, sourceIPAddress, errorCode "
        f"| filter requestParameters like '{resource_id}' or responseElements like '{resource_id}' "
        f"| sort @timestamp desc "
        f"| limit 500"
    )

    return run_insights_query(
        query=query,
        log_groups=log_groups,
        region=region,
        hours_back=hours_back,
    )


def _find_cloudtrail_log_groups(logs_client: Any) -> list[str]:
    """Return CloudWatch log group names that look like CloudTrail groups."""
    try:
        paginator = logs_client.get_paginator("describe_log_groups")
        groups: list[str] = []
        for page in paginator.paginate(PaginationConfig={"MaxItems": 50}):
            for group in page.get("logGroups", []):
                name: str = group.get("logGroupName", "")
                if "cloudtrail" in name.lower() or "trail" in name.lower():
                    groups.append(name)
        return groups
    except ClientError as exc:
        logger.warning("Could not list CloudWatch log groups: %s", exc)
        return []


def _find_cloudtrail_log_groups_via_shared(region: str) -> list[str]:
    """Find CloudTrail log groups using the shared utility."""
    return find_log_groups(region, "cloudtrail", "trail")


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Entry point for the collect-artifacts Lambda.

    Args:
        event: Merged payload from Step Functions containing the original
               incident fields plus the enrichment_result from the previous step.
        context: Lambda context (unused).

    Returns:
        Manifest dict with s3_keys, summary counts, and timestamp.
    """
    logger.info("collect_artifacts invoked with event keys: %s", list(event.keys()))

    ticket_number = event.get("ticket_number", "UNKNOWN")
    finding_id = event.get("finding_id", "")
    resource_id = event.get("resource_id", "")
    region = event.get("region", AWS_REGION)
    enrichment = event.get("enrichment_result", {}).get("enrichment", event.get("enrichment_result", {}))

    if not ARTIFACTS_BUCKET:
        raise ValueError("ARTIFACTS_BUCKET environment variable is not set")

    prefix = f"{ticket_number}/"
    s3_keys: list[str] = []

    # 1. Store GuardDuty finding
    finding = enrichment.get("finding", {})
    if finding:
        key = put_artifact(ARTIFACTS_BUCKET, f"{prefix}guardduty_finding.json", finding)
        s3_keys.append(key)

    # 2. Store CloudTrail events from enrichment
    cloudtrail_events = enrichment.get("cloudtrail_events", [])
    if cloudtrail_events:
        key = put_artifact(
            ARTIFACTS_BUCKET,
            f"{prefix}cloudtrail_events_enrichment.json",
            cloudtrail_events,
        )
        s3_keys.append(key)

    # 3. Collect and store VPC flow logs
    vpc_flows: list[dict] = []
    if ENABLE_VPC_FLOW_LOG_COLLECTION and resource_id:
        logger.info("Collecting VPC flow logs for resource_id=%s", resource_id)
        vpc_flows = collect_vpc_flow_logs(resource_id, region)
        key = put_artifact(ARTIFACTS_BUCKET, f"{prefix}vpc_flow_logs.json", vpc_flows)
        s3_keys.append(key)

    # 4. Collect and store CloudTrail logs via CW Logs Insights
    ct_logs: list[dict] = []
    if ENABLE_CLOUDTRAIL_COLLECTION and resource_id:
        logger.info("Collecting CloudTrail logs via Insights for resource_id=%s", resource_id)
        ct_logs = collect_cloudtrail_logs(resource_id, region)
        key = put_artifact(ARTIFACTS_BUCKET, f"{prefix}cloudtrail_logs_insights.json", ct_logs)
        s3_keys.append(key)

    # 5. Store EC2 and IAM metadata
    ec2_metadata = enrichment.get("ec2_metadata", {})
    if ec2_metadata:
        key = put_artifact(ARTIFACTS_BUCKET, f"{prefix}ec2_metadata.json", ec2_metadata)
        s3_keys.append(key)

    iam_context = enrichment.get("iam_context", {})
    if iam_context:
        key = put_artifact(ARTIFACTS_BUCKET, f"{prefix}iam_context.json", iam_context)
        s3_keys.append(key)

    manifest = {
        "ticket_number": ticket_number,
        "finding_id": finding_id,
        "s3_bucket": ARTIFACTS_BUCKET,
        "s3_prefix": prefix,
        "s3_keys": s3_keys,
        "vpc_flow_log_count": len(vpc_flows),
        "cloudtrail_log_count": len(ct_logs),
        "artifacts_timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }

    logger.info(
        "Artifact collection complete: ticket=%s keys_written=%d",
        ticket_number,
        len(s3_keys),
    )

    return manifest
