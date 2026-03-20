"""
shared/cloudtrail_queries.py

Reusable helpers for querying AWS CloudTrail events.

Extracted from the enrich_alert Lambda so that any enrichment Lambda
can look up CloudTrail events without duplicating lookup-attribute
resolution and pagination logic.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def lookup_cloudtrail_events(
    resource_id: str,
    resource_type: str,
    region: str,
    hours_back: int = 24,
    max_items: int = 200,
) -> list[dict]:
    """Look up CloudTrail events for a resource over the last *hours_back* hours.

    Args:
        resource_id:   The AWS resource identifier (instance ID, username, etc.).
        resource_type: The resource type hint (e.g. ``"Instance"``, ``"IAMUser"``).
        region:        AWS region for the CloudTrail client.
        hours_back:    How many hours of history to search (default 24).
        max_items:     Maximum events to return (default 200).

    Returns:
        A list of simplified event dicts.  Returns an empty list when
        *resource_id* is empty or the lookup fails.
    """
    if not resource_id:
        return []

    ct = boto3.client("cloudtrail", region_name=region)
    end_time = datetime.now(tz=timezone.utc)
    start_time = end_time - timedelta(hours=hours_back)

    lookup_attribute = resolve_lookup_attribute(resource_type, resource_id)

    try:
        paginator = ct.get_paginator("lookup_events")
        events: list[dict] = []
        for page in paginator.paginate(
            LookupAttributes=[lookup_attribute],
            StartTime=start_time,
            EndTime=end_time,
            PaginationConfig={"MaxItems": max_items},
        ):
            for raw in page.get("Events", []):
                event = {
                    "EventId": raw.get("EventId"),
                    "EventName": raw.get("EventName"),
                    "EventTime": (
                        raw.get("EventTime").isoformat()
                        if raw.get("EventTime")
                        else None
                    ),
                    "Username": raw.get("Username"),
                    "EventSource": raw.get("EventSource"),
                    "SourceIPAddress": extract_source_ip(raw),
                    "Resources": raw.get("Resources", []),
                }
                events.append(event)
        return events
    except ClientError as exc:
        logger.error("CloudTrail LookupEvents failed: %s", exc)
        return [{"error": str(exc)}]


# ---------------------------------------------------------------------------
# Attribute resolution
# ---------------------------------------------------------------------------

def resolve_lookup_attribute(resource_type: str, resource_id: str) -> dict:
    """Map a resource type to the correct CloudTrail lookup attribute.

    Args:
        resource_type: e.g. ``"Instance"``, ``"IAMUser"``, ``"IAMRole"``.
        resource_id:   The resource identifier value.

    Returns:
        A dict with ``AttributeKey`` and ``AttributeValue`` suitable for the
        CloudTrail ``LookupEvents`` API.
    """
    type_lower = (resource_type or "").lower()
    if "instance" in type_lower:
        return {"AttributeKey": "ResourceName", "AttributeValue": resource_id}
    if "role" in type_lower:
        return {"AttributeKey": "ResourceName", "AttributeValue": resource_id}
    if "user" in type_lower:
        return {"AttributeKey": "Username", "AttributeValue": resource_id}
    return {"AttributeKey": "ResourceName", "AttributeValue": resource_id}


# ---------------------------------------------------------------------------
# Event parsing helpers
# ---------------------------------------------------------------------------

def extract_source_ip(event: dict) -> str | None:
    """Extract the source IP from a CloudTrail event's CloudTrailEvent JSON."""
    raw_json = event.get("CloudTrailEvent", "{}")
    try:
        detail = json.loads(raw_json)
        return detail.get("sourceIPAddress")
    except (json.JSONDecodeError, AttributeError):
        return None
