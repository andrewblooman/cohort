"""
tests/test_collect_artifacts.py

Unit tests for the collect_artifacts Lambda handler.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch

import pytest
import importlib.util
import os

def _load_handler(module_name: str, relative_path: str):
    """Load a Lambda handler module from a relative path without polluting sys.modules."""
    abs_path = os.path.join(os.path.dirname(__file__), relative_path)
    spec = importlib.util.spec_from_file_location(module_name, abs_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

collect_handler = _load_handler("collect_artifacts_handler", "../lambdas/collect_artifacts/handler.py")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_EVENT = {
    "ticket_number": "INC-002",
    "finding_id": "abc456",
    "alert_type": "GuardDuty",
    "severity": "MEDIUM",
    "resource_type": "Instance",
    "resource_id": "i-aabbccddeeff",
    "account_id": "123456789012",
    "region": "us-east-1",
    "secops_case_id": "CASE-100",
    "enrichment_result": {
        "enrichment": {
            "finding": {"Id": "abc456", "Type": "Recon:EC2/PortProbeUnprotectedPort"},
            "cloudtrail_events": [
                {"EventName": "RunInstances", "EventTime": "2024-01-15T09:00:00+00:00"}
            ],
            "ec2_metadata": {"InstanceId": "i-aabbccddeeff", "InstanceType": "t3.micro"},
            "iam_context": {},
        }
    },
}


# ---------------------------------------------------------------------------
# put_artifact tests
# ---------------------------------------------------------------------------

class TestPutArtifact:
    def test_uploads_json_to_s3(self):
        mock_s3 = MagicMock()
        data = {"key": "value", "nested": [1, 2, 3]}

        with patch.object(collect_handler, "_s3_client", return_value=mock_s3):
            key = collect_handler.put_artifact("my-bucket", "prefix/file.json", data)

        assert key == "prefix/file.json"
        call_args = mock_s3.put_object.call_args[1]
        assert call_args["Bucket"] == "my-bucket"
        assert call_args["Key"] == "prefix/file.json"
        assert call_args["ContentType"] == "application/json"
        # Verify body is valid JSON
        parsed = json.loads(call_args["Body"].decode("utf-8"))
        assert parsed == data


# ---------------------------------------------------------------------------
# collect_vpc_flow_logs tests
# ---------------------------------------------------------------------------

class TestCollectVpcFlowLogs:
    def test_returns_empty_when_no_resource_id(self):
        result = collect_handler.collect_vpc_flow_logs("", "us-east-1")
        assert result == []

    def test_returns_empty_when_no_log_groups(self):
        mock_logs = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"logGroups": []}]
        mock_logs.get_paginator.return_value = paginator

        with patch("boto3.client", return_value=mock_logs):
            result = collect_handler.collect_vpc_flow_logs("10.0.1.5", "us-east-1")

        assert result == []

    def test_collects_flow_logs_successfully(self):
        mock_logs = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"logGroups": [{"logGroupName": "/aws/vpc/flowlogs"}]}
        ]
        mock_logs.get_paginator.return_value = paginator
        mock_logs.start_query.return_value = {"queryId": "q-001"}
        mock_logs.get_query_results.return_value = {
            "status": "Complete",
            "results": [
                [
                    {"field": "@timestamp", "value": "2024-01-15 10:00:00.000"},
                    {"field": "srcAddr", "value": "10.0.1.5"},
                    {"field": "dstAddr", "value": "1.2.3.4"},
                    {"field": "@ptr", "value": "ptr-value"},
                ]
            ],
        }

        with patch("boto3.client", return_value=mock_logs):
            result = collect_handler.collect_vpc_flow_logs("10.0.1.5", "us-east-1")

        assert len(result) == 1
        assert result[0]["srcAddr"] == "10.0.1.5"
        # @ptr field should be excluded
        assert "@ptr" not in result[0]

    def test_returns_error_on_client_error(self):
        from botocore.exceptions import ClientError

        mock_logs = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"logGroups": [{"logGroupName": "/aws/vpc/flowlogs"}]}
        ]
        mock_logs.get_paginator.return_value = paginator
        mock_logs.start_query.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
            "StartQuery",
        )

        with patch("boto3.client", return_value=mock_logs):
            result = collect_handler.collect_vpc_flow_logs("10.0.1.5", "us-east-1")

        assert len(result) == 1
        assert "error" in result[0]


# ---------------------------------------------------------------------------
# _wait_for_query_results tests
# ---------------------------------------------------------------------------

class TestWaitForQueryResults:
    def test_returns_results_on_complete(self):
        mock_logs = MagicMock()
        mock_logs.get_query_results.return_value = {
            "status": "Complete",
            "results": [
                [{"field": "srcAddr", "value": "10.0.0.1"}]
            ],
        }

        with patch("time.sleep"):
            result = collect_handler._wait_for_query_results(mock_logs, "q-001")

        assert result[0]["srcAddr"] == "10.0.0.1"

    def test_returns_empty_on_failed_status(self):
        mock_logs = MagicMock()
        mock_logs.get_query_results.return_value = {"status": "Failed", "results": []}

        with patch("time.sleep"):
            result = collect_handler._wait_for_query_results(mock_logs, "q-fail")

        assert result == []

    def test_returns_empty_on_timeout(self):
        mock_logs = MagicMock()
        mock_logs.get_query_results.return_value = {"status": "Running", "results": []}

        with patch("time.sleep"):
            result = collect_handler._wait_for_query_results(
                mock_logs, "q-timeout", max_wait=4
            )

        assert result == []


# ---------------------------------------------------------------------------
# lambda_handler integration test
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    def test_stores_all_artifacts(self):
        mock_s3 = MagicMock()
        mock_logs = MagicMock()

        # No VPC flow log groups found
        paginator = MagicMock()
        paginator.paginate.return_value = [{"logGroups": []}]
        mock_logs.get_paginator.return_value = paginator

        with (
            patch.object(collect_handler, "_s3_client", return_value=mock_s3),
            patch.object(collect_handler, "ARTIFACTS_BUCKET", "test-bucket"),
            patch.object(collect_handler, "ENABLE_VPC_FLOW_LOG_COLLECTION", False),
            patch.object(collect_handler, "ENABLE_CLOUDTRAIL_COLLECTION", False),
        ):
            result = collect_handler.lambda_handler(SAMPLE_EVENT, None)

        assert result["ticket_number"] == "INC-002"
        assert result["s3_bucket"] == "test-bucket"
        assert result["s3_prefix"] == "INC-002/"
        assert isinstance(result["s3_keys"], list)
        # Should have uploaded at least the finding and cloudtrail events
        assert len(result["s3_keys"]) >= 2

    def test_raises_when_bucket_not_set(self):
        with patch.object(collect_handler, "ARTIFACTS_BUCKET", ""):
            with pytest.raises(ValueError, match="ARTIFACTS_BUCKET"):
                collect_handler.lambda_handler(SAMPLE_EVENT, None)

    def test_prefix_uses_ticket_number(self):
        mock_s3 = MagicMock()

        with (
            patch.object(collect_handler, "_s3_client", return_value=mock_s3),
            patch.object(collect_handler, "ARTIFACTS_BUCKET", "test-bucket"),
            patch.object(collect_handler, "ENABLE_VPC_FLOW_LOG_COLLECTION", False),
            patch.object(collect_handler, "ENABLE_CLOUDTRAIL_COLLECTION", False),
        ):
            result = collect_handler.lambda_handler(SAMPLE_EVENT, None)

        for key in result["s3_keys"]:
            assert key.startswith("INC-002/"), f"Key '{key}' does not start with ticket prefix"
