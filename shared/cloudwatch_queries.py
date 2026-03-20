"""
shared/cloudwatch_queries.py

Reusable helpers for querying CloudWatch Logs Insights.

Extracted from the collect_artifacts Lambda so that any enrichment Lambda
can run Insights queries without duplicating the polling and parsing logic.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def run_insights_query(
    query: str,
    log_groups: list[str],
    region: str,
    hours_back: int = 24,
    max_wait: int = 60,
) -> list[dict]:
    """Run a CloudWatch Logs Insights query and return parsed results.

    Args:
        query:      The Insights query string.
        log_groups: CloudWatch log group names to search.
        region:     AWS region for the Logs client.
        hours_back: How many hours of history to search (default 24).
        max_wait:   Maximum seconds to poll for query completion (default 60).

    Returns:
        A list of dicts, one per result row.  Returns an empty list when
        no log groups are provided or the query fails/times out.
    """
    if not log_groups:
        logger.info("No log groups provided; skipping Insights query")
        return []

    logs = boto3.client("logs", region_name=region)
    end_time = datetime.now(tz=timezone.utc)
    start_time = end_time - timedelta(hours=hours_back)

    try:
        response = logs.start_query(
            logGroupNames=log_groups[:10],
            startTime=int(start_time.timestamp()),
            endTime=int(end_time.timestamp()),
            queryString=query,
        )
        query_id = response["queryId"]
        return wait_for_query_results(logs, query_id, max_wait=max_wait)
    except ClientError as exc:
        logger.error("Insights query failed: %s", exc)
        return [{"error": str(exc)}]


def find_log_groups(region: str, *keywords: str, max_items: int = 50) -> list[str]:
    """Return CloudWatch log group names containing any of the given keywords.

    Args:
        region:    AWS region.
        keywords:  One or more substrings to match (case-insensitive).
        max_items: Maximum log groups to scan.

    Returns:
        A list of matching log group names.
    """
    logs = boto3.client("logs", region_name=region)
    try:
        paginator = logs.get_paginator("describe_log_groups")
        groups: list[str] = []
        for page in paginator.paginate(PaginationConfig={"MaxItems": max_items}):
            for group in page.get("logGroups", []):
                name: str = group.get("logGroupName", "")
                if any(kw.lower() in name.lower() for kw in keywords):
                    groups.append(name)
        return groups
    except ClientError as exc:
        logger.warning("Could not list CloudWatch log groups: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def wait_for_query_results(
    logs_client: Any,
    query_id: str,
    max_wait: int = 60,
) -> list[dict]:
    """Poll until the Insights query finishes and return structured results."""
    waited = 0
    poll_interval = 2
    while waited < max_wait:
        response = logs_client.get_query_results(QueryId=query_id)
        status = response.get("status")
        if status in ("Complete", "Failed", "Cancelled"):
            if status != "Complete":
                logger.warning("Insights query %s ended with status %s", query_id, status)
                return []
            return parse_insights_results(response.get("results", []))
        time.sleep(poll_interval)
        waited += poll_interval
    logger.warning("Insights query %s timed out after %d seconds", query_id, max_wait)
    return []


def parse_insights_results(results: list[list[dict]]) -> list[dict]:
    """Convert Insights result rows into plain dicts, excluding ``@ptr`` fields."""
    records = []
    for row in results:
        record = {
            item["field"]: item["value"]
            for item in row
            if not item["field"].startswith("@ptr")
        }
        records.append(record)
    return records
