"""
enrich_alert/handler.py

Lambda function: Enrich Alert

Triggered as the first step of the incident-response Step Functions workflow.
Accepts a GuardDuty-based alert payload forwarded from Google SecOps via
EventBridge and enriches it with:

  * Full GuardDuty finding details
  * CloudTrail events related to the affected resource
  * EC2 instance / network-interface metadata (when applicable)
  * IAM user / role context (when applicable)

The enriched data is returned to the Step Functions workflow so that the
subsequent steps (collect_artifacts, ai_analysis) have full context.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Ensure the repository root is on the path so the shared package is importable.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from shared.cloudtrail_queries import (  # noqa: E402
    extract_source_ip,
    lookup_cloudtrail_events,
    resolve_lookup_attribute,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# AWS client helpers
# ---------------------------------------------------------------------------

def _guardduty_client(region: str) -> Any:
    return boto3.client("guardduty", region_name=region)


def _cloudtrail_client(region: str) -> Any:
    return boto3.client("cloudtrail", region_name=region)


def _ec2_client(region: str) -> Any:
    return boto3.client("ec2", region_name=region)


def _iam_client() -> Any:
    return boto3.client("iam")


# ---------------------------------------------------------------------------
# GuardDuty enrichment
# ---------------------------------------------------------------------------

def get_guardduty_finding(finding_id: str, region: str) -> dict:
    """Retrieve the full GuardDuty finding for the given finding ID."""
    if not finding_id:
        logger.warning("No finding_id provided; skipping GuardDuty lookup")
        return {}

    gd = _guardduty_client(region)
    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            logger.warning("No GuardDuty detectors found in region %s", region)
            return {}

        detector_id = detectors[0]
        response = gd.get_findings(
            DetectorId=detector_id,
            FindingIds=[finding_id],
        )
        findings = response.get("Findings", [])
        return findings[0] if findings else {}
    except ClientError as exc:
        logger.error("GuardDuty GetFindings failed: %s", exc)
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# CloudTrail enrichment (uses shared.cloudtrail_queries helpers)
# ---------------------------------------------------------------------------

def get_cloudtrail_events(
    resource_id: str,
    resource_type: str,
    region: str,
    hours_back: int = 24,
) -> list[dict]:
    """Look up the last <hours_back> hours of CloudTrail events for the resource."""
    if not resource_id:
        return []

    ct = _cloudtrail_client(region)
    end_time = datetime.now(tz=timezone.utc)
    start_time = end_time - timedelta(hours=hours_back)

    lookup_attribute = _resolve_cloudtrail_lookup_attribute(resource_type, resource_id)

    try:
        paginator = ct.get_paginator("lookup_events")
        events: list[dict] = []
        for page in paginator.paginate(
            LookupAttributes=[lookup_attribute],
            StartTime=start_time,
            EndTime=end_time,
            PaginationConfig={"MaxItems": 200},
        ):
            for raw in page.get("Events", []):
                event = {
                    "EventId": raw.get("EventId"),
                    "EventName": raw.get("EventName"),
                    "EventTime": raw.get("EventTime").isoformat() if raw.get("EventTime") else None,
                    "Username": raw.get("Username"),
                    "EventSource": raw.get("EventSource"),
                    "SourceIPAddress": _extract_source_ip(raw),
                    "Resources": raw.get("Resources", []),
                }
                events.append(event)
        return events
    except ClientError as exc:
        logger.error("CloudTrail LookupEvents failed: %s", exc)
        return [{"error": str(exc)}]


def _resolve_cloudtrail_lookup_attribute(resource_type: str, resource_id: str) -> dict:
    """Map a resource type to the correct CloudTrail lookup attribute."""
    return resolve_lookup_attribute(resource_type, resource_id)


def _extract_source_ip(event: dict) -> str | None:
    """Extract the source IP from a CloudTrail event's CloudTrailEvent JSON."""
    return extract_source_ip(event)


# ---------------------------------------------------------------------------
# EC2 enrichment
# ---------------------------------------------------------------------------

def get_ec2_metadata(resource_id: str, resource_type: str, region: str) -> dict:
    """Return EC2 instance or network-interface metadata."""
    type_lower = (resource_type or "").lower()
    if not resource_id:
        return {}

    ec2 = _ec2_client(region)

    if "instance" in type_lower:
        return _describe_instance(ec2, resource_id)
    if "networkinterface" in type_lower or "eni" in type_lower:
        return _describe_network_interface(ec2, resource_id)
    return {}


def _describe_instance(ec2: Any, instance_id: str) -> dict:
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])
        if not reservations:
            return {}
        instance = reservations[0]["Instances"][0]
        return {
            "InstanceId": instance.get("InstanceId"),
            "InstanceType": instance.get("InstanceType"),
            "State": instance.get("State", {}).get("Name"),
            "LaunchTime": instance.get("LaunchTime").isoformat() if instance.get("LaunchTime") else None,
            "PublicIpAddress": instance.get("PublicIpAddress"),
            "PrivateIpAddress": instance.get("PrivateIpAddress"),
            "VpcId": instance.get("VpcId"),
            "SubnetId": instance.get("SubnetId"),
            "Tags": instance.get("Tags", []),
            "SecurityGroups": instance.get("SecurityGroups", []),
            "IamInstanceProfile": instance.get("IamInstanceProfile", {}),
        }
    except ClientError as exc:
        logger.error("EC2 DescribeInstances failed: %s", exc)
        return {"error": str(exc)}


def _describe_network_interface(ec2: Any, eni_id: str) -> dict:
    try:
        resp = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
        interfaces = resp.get("NetworkInterfaces", [])
        if not interfaces:
            return {}
        eni = interfaces[0]
        return {
            "NetworkInterfaceId": eni.get("NetworkInterfaceId"),
            "PrivateIpAddress": eni.get("PrivateIpAddress"),
            "VpcId": eni.get("VpcId"),
            "SubnetId": eni.get("SubnetId"),
            "Description": eni.get("Description"),
            "Attachment": eni.get("Attachment", {}),
        }
    except ClientError as exc:
        logger.error("EC2 DescribeNetworkInterfaces failed: %s", exc)
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# IAM enrichment
# ---------------------------------------------------------------------------

def get_iam_context(resource_id: str, resource_type: str) -> dict:
    """Return basic IAM user or role metadata."""
    if not resource_id:
        return {}
    type_lower = (resource_type or "").lower()
    iam = _iam_client()

    if "user" in type_lower:
        return _describe_iam_user(iam, resource_id)
    if "role" in type_lower or "assumedrole" in type_lower:
        return _describe_iam_role(iam, resource_id)
    return {}


def _describe_iam_user(iam: Any, username: str) -> dict:
    try:
        user = iam.get_user(UserName=username).get("User", {})
        policies = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
        return {
            "UserName": user.get("UserName"),
            "UserId": user.get("UserId"),
            "Arn": user.get("Arn"),
            "CreateDate": user.get("CreateDate").isoformat() if user.get("CreateDate") else None,
            "PasswordLastUsed": user.get("PasswordLastUsed").isoformat() if user.get("PasswordLastUsed") else None,
            "AttachedPolicies": policies,
        }
    except ClientError as exc:
        logger.warning("IAM GetUser failed for %s: %s", username, exc)
        return {"error": str(exc)}


def _describe_iam_role(iam: Any, role_name: str) -> dict:
    try:
        role = iam.get_role(RoleName=role_name).get("Role", {})
        policies = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
        return {
            "RoleName": role.get("RoleName"),
            "RoleId": role.get("RoleId"),
            "Arn": role.get("Arn"),
            "CreateDate": role.get("CreateDate").isoformat() if role.get("CreateDate") else None,
            "AttachedPolicies": policies,
        }
    except ClientError as exc:
        logger.warning("IAM GetRole failed for %s: %s", role_name, exc)
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Entry point for the enrich-alert Lambda.

    Args:
        event: Step Functions input payload containing at minimum:
               ticket_number, finding_id, alert_type, severity,
               resource_type, resource_id, account_id, region.
        context: Lambda context (unused).

    Returns:
        Enrichment dict with keys: finding, cloudtrail, ec2_metadata, iam_context.
    """
    logger.info("enrich_alert invoked with event keys: %s", list(event.keys()))

    ticket_number = event.get("ticket_number", "UNKNOWN")
    finding_id = event.get("finding_id", "")
    resource_type = event.get("resource_type", "")
    resource_id = event.get("resource_id", "")
    region = event.get("region", AWS_REGION)

    logger.info(
        "Processing ticket=%s finding=%s resource_type=%s resource_id=%s region=%s",
        ticket_number,
        finding_id,
        resource_type,
        resource_id,
        region,
    )

    # Parallel enrichment (each call is independent)
    finding = get_guardduty_finding(finding_id, region)
    cloudtrail_events = get_cloudtrail_events(resource_id, resource_type, region)
    ec2_metadata = get_ec2_metadata(resource_id, resource_type, region)
    iam_context = get_iam_context(resource_id, resource_type)

    enrichment = {
        "ticket_number": ticket_number,
        "finding_id": finding_id,
        "finding": finding,
        "cloudtrail_events": cloudtrail_events,
        "ec2_metadata": ec2_metadata,
        "iam_context": iam_context,
        "enrichment_timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }

    logger.info(
        "Enrichment complete: cloudtrail_events=%d ec2_metadata_keys=%s",
        len(cloudtrail_events),
        list(ec2_metadata.keys()),
    )

    return enrichment
