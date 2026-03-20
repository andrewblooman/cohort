"""
tests/test_shared.py

Unit tests for the shared CloudWatch and CloudTrail query utilities.
"""

from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Ensure the repo root is on the path so that ``shared`` can be imported.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from shared.cloudtrail_queries import (
    extract_source_ip,
    lookup_cloudtrail_events,
    resolve_lookup_attribute,
)
from shared.cloudwatch_queries import (
    find_log_groups,
    parse_insights_results,
    run_insights_query,
    wait_for_query_results,
)


# ---------------------------------------------------------------------------
# CloudTrail – resolve_lookup_attribute
# ---------------------------------------------------------------------------

class TestResolveLookupAttribute:
    def test_instance_type(self):
        attr = resolve_lookup_attribute("Instance", "i-abc")
        assert attr == {"AttributeKey": "ResourceName", "AttributeValue": "i-abc"}

    def test_user_type(self):
        attr = resolve_lookup_attribute("IAMUser", "alice")
        assert attr == {"AttributeKey": "Username", "AttributeValue": "alice"}

    def test_role_type(self):
        attr = resolve_lookup_attribute("IAMRole", "my-role")
        assert attr == {"AttributeKey": "ResourceName", "AttributeValue": "my-role"}

    def test_fallback_for_unknown_type(self):
        attr = resolve_lookup_attribute("S3Bucket", "my-bucket")
        assert attr == {"AttributeKey": "ResourceName", "AttributeValue": "my-bucket"}

    def test_empty_resource_type(self):
        attr = resolve_lookup_attribute("", "some-id")
        assert attr == {"AttributeKey": "ResourceName", "AttributeValue": "some-id"}

    def test_none_resource_type(self):
        attr = resolve_lookup_attribute(None, "some-id")
        assert attr == {"AttributeKey": "ResourceName", "AttributeValue": "some-id"}


# ---------------------------------------------------------------------------
# CloudTrail – extract_source_ip
# ---------------------------------------------------------------------------

class TestExtractSourceIp:
    def test_extracts_ip_from_valid_event(self):
        event = {"CloudTrailEvent": json.dumps({"sourceIPAddress": "1.2.3.4"})}
        assert extract_source_ip(event) == "1.2.3.4"

    def test_returns_none_when_no_ip(self):
        event = {"CloudTrailEvent": json.dumps({"eventName": "DescribeInstances"})}
        assert extract_source_ip(event) is None

    def test_returns_none_for_invalid_json(self):
        event = {"CloudTrailEvent": "not valid json"}
        assert extract_source_ip(event) is None

    def test_returns_none_for_missing_key(self):
        event = {}
        assert extract_source_ip(event) is None


# ---------------------------------------------------------------------------
# CloudTrail – lookup_cloudtrail_events
# ---------------------------------------------------------------------------

class TestLookupCloudtrailEvents:
    def test_returns_empty_when_no_resource_id(self):
        result = lookup_cloudtrail_events("", "Instance", "us-east-1")
        assert result == []

    def test_returns_events(self):
        from datetime import datetime, timezone

        mock_ct = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "Events": [
                    {
                        "EventId": "e-001",
                        "EventName": "RunInstances",
                        "EventTime": datetime(2024, 1, 15, 9, 0, 0, tzinfo=timezone.utc),
                        "Username": "admin",
                        "EventSource": "ec2.amazonaws.com",
                        "CloudTrailEvent": json.dumps({"sourceIPAddress": "10.0.0.1"}),
                        "Resources": [],
                    }
                ]
            }
        ]
        mock_ct.get_paginator.return_value = paginator

        with patch("boto3.client", return_value=mock_ct):
            result = lookup_cloudtrail_events("i-abc", "Instance", "us-east-1")

        assert len(result) == 1
        assert result[0]["EventName"] == "RunInstances"
        assert result[0]["SourceIPAddress"] == "10.0.0.1"

    def test_returns_error_on_client_error(self):
        from botocore.exceptions import ClientError

        mock_ct = MagicMock()
        mock_ct.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
            "LookupEvents",
        )

        with patch("boto3.client", return_value=mock_ct):
            result = lookup_cloudtrail_events("i-abc", "Instance", "us-east-1")

        assert len(result) == 1
        assert "error" in result[0]


# ---------------------------------------------------------------------------
# CloudWatch – parse_insights_results
# ---------------------------------------------------------------------------

class TestParseInsightsResults:
    def test_parses_single_row(self):
        results = [
            [
                {"field": "srcAddr", "value": "10.0.0.1"},
                {"field": "dstAddr", "value": "1.2.3.4"},
            ]
        ]
        parsed = parse_insights_results(results)
        assert len(parsed) == 1
        assert parsed[0] == {"srcAddr": "10.0.0.1", "dstAddr": "1.2.3.4"}

    def test_excludes_ptr_fields(self):
        results = [
            [
                {"field": "srcAddr", "value": "10.0.0.1"},
                {"field": "@ptr", "value": "pointer-data"},
            ]
        ]
        parsed = parse_insights_results(results)
        assert "@ptr" not in parsed[0]

    def test_handles_empty_results(self):
        assert parse_insights_results([]) == []

    def test_handles_multiple_rows(self):
        results = [
            [{"field": "f1", "value": "a"}],
            [{"field": "f1", "value": "b"}],
        ]
        parsed = parse_insights_results(results)
        assert len(parsed) == 2


# ---------------------------------------------------------------------------
# CloudWatch – wait_for_query_results
# ---------------------------------------------------------------------------

class TestWaitForQueryResults:
    def test_returns_results_on_complete(self):
        mock_logs = MagicMock()
        mock_logs.get_query_results.return_value = {
            "status": "Complete",
            "results": [[{"field": "srcAddr", "value": "10.0.0.1"}]],
        }

        with patch("time.sleep"):
            result = wait_for_query_results(mock_logs, "q-001")

        assert result[0]["srcAddr"] == "10.0.0.1"

    def test_returns_empty_on_failed_status(self):
        mock_logs = MagicMock()
        mock_logs.get_query_results.return_value = {"status": "Failed", "results": []}

        with patch("time.sleep"):
            result = wait_for_query_results(mock_logs, "q-fail")

        assert result == []

    def test_returns_empty_on_timeout(self):
        mock_logs = MagicMock()
        mock_logs.get_query_results.return_value = {"status": "Running", "results": []}

        with patch("time.sleep"):
            result = wait_for_query_results(mock_logs, "q-timeout", max_wait=4)

        assert result == []


# ---------------------------------------------------------------------------
# CloudWatch – find_log_groups
# ---------------------------------------------------------------------------

class TestFindLogGroups:
    def test_finds_matching_groups(self):
        mock_logs = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "logGroups": [
                    {"logGroupName": "/aws/vpc/flowlogs"},
                    {"logGroupName": "/aws/lambda/my-func"},
                    {"logGroupName": "/custom/flow-data"},
                ]
            }
        ]
        mock_logs.get_paginator.return_value = paginator

        with patch("boto3.client", return_value=mock_logs):
            groups = find_log_groups("us-east-1", "vpc", "flow")

        assert "/aws/vpc/flowlogs" in groups
        assert "/custom/flow-data" in groups
        assert "/aws/lambda/my-func" not in groups

    def test_returns_empty_when_no_matches(self):
        mock_logs = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"logGroups": [{"logGroupName": "/aws/lambda/my-func"}]}]
        mock_logs.get_paginator.return_value = paginator

        with patch("boto3.client", return_value=mock_logs):
            groups = find_log_groups("us-east-1", "vpc")

        assert groups == []

    def test_returns_empty_on_client_error(self):
        from botocore.exceptions import ClientError

        mock_logs = MagicMock()
        mock_logs.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
            "DescribeLogGroups",
        )

        with patch("boto3.client", return_value=mock_logs):
            groups = find_log_groups("us-east-1", "vpc")

        assert groups == []


# ---------------------------------------------------------------------------
# CloudWatch – run_insights_query
# ---------------------------------------------------------------------------

class TestRunInsightsQuery:
    def test_returns_empty_when_no_log_groups(self):
        result = run_insights_query("fields @timestamp", [], "us-east-1")
        assert result == []

    def test_runs_query_and_returns_results(self):
        mock_logs = MagicMock()
        mock_logs.start_query.return_value = {"queryId": "q-123"}
        mock_logs.get_query_results.return_value = {
            "status": "Complete",
            "results": [[{"field": "srcAddr", "value": "10.0.0.1"}]],
        }

        with patch("boto3.client", return_value=mock_logs), patch("time.sleep"):
            result = run_insights_query(
                "fields @timestamp",
                ["/aws/vpc/flowlogs"],
                "us-east-1",
            )

        assert len(result) == 1
        assert result[0]["srcAddr"] == "10.0.0.1"

    def test_returns_error_on_client_error(self):
        from botocore.exceptions import ClientError

        mock_logs = MagicMock()
        mock_logs.start_query.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
            "StartQuery",
        )

        with patch("boto3.client", return_value=mock_logs):
            result = run_insights_query(
                "fields @timestamp",
                ["/aws/vpc/flowlogs"],
                "us-east-1",
            )

        assert len(result) == 1
        assert "error" in result[0]
