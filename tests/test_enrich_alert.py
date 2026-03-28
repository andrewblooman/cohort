"""
tests/test_enrich_alert.py

Unit tests for the enrich_alert Lambda handler.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

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

enrich_handler = _load_handler("enrich_alert_handler", "../lambdas/enrich_alert/handler.py")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_EVENT = {
    "ticket_number": "INC-001",
    "finding_id": "abc123",
    "alert_type": "GuardDuty",
    "severity": "HIGH",
    "resource_type": "Instance",
    "resource_id": "i-0123456789abcdef0",
    "account_id": "123456789012",
    "region": "us-east-1",
    "description": "An EC2 instance is communicating with a known malicious IP.",
}

SAMPLE_FINDING = {
    "Id": "abc123",
    "Type": "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
    "Severity": {"Score": 8.0, "Label": "HIGH"},
    "Title": "EC2 instance is communicating on unusual server port.",
    "Description": "EC2 instance i-0123456789abcdef0 is communicating...",
    "CreatedAt": "2024-01-15T10:00:00Z",
    "UpdatedAt": "2024-01-15T10:05:00Z",
}

SAMPLE_CT_EVENT = {
    "EventId": "event-001",
    "EventName": "DescribeInstances",
    "EventTime": datetime(2024, 1, 15, 9, 0, 0, tzinfo=timezone.utc),
    "Username": "admin",
    "EventSource": "ec2.amazonaws.com",
    "Resources": [{"ResourceType": "AWS::EC2::Instance", "ResourceName": "i-0123456789abcdef0"}],
    "CloudTrailEvent": json.dumps({"sourceIPAddress": "1.2.3.4"}),
}


# ---------------------------------------------------------------------------
# get_guardduty_finding tests
# ---------------------------------------------------------------------------

class TestGetGuarddutyFinding:
    def test_returns_finding_when_found(self):
        mock_gd = MagicMock()
        mock_gd.list_detectors.return_value = {"DetectorIds": ["det-001"]}
        mock_gd.get_findings.return_value = {"Findings": [SAMPLE_FINDING]}

        with patch.object(enrich_handler, "_guardduty_client", return_value=mock_gd):
            result = enrich_handler.get_guardduty_finding("abc123", "us-east-1")

        assert result == SAMPLE_FINDING
        mock_gd.get_findings.assert_called_once_with(
            DetectorId="det-001", FindingIds=["abc123"]
        )

    def test_returns_empty_when_no_finding_id(self):
        result = enrich_handler.get_guardduty_finding("", "us-east-1")
        assert result == {}

    def test_returns_empty_when_no_detectors(self):
        mock_gd = MagicMock()
        mock_gd.list_detectors.return_value = {"DetectorIds": []}

        with patch.object(enrich_handler, "_guardduty_client", return_value=mock_gd):
            result = enrich_handler.get_guardduty_finding("abc123", "us-east-1")

        assert result == {}

    def test_returns_empty_when_findings_list_is_empty(self):
        mock_gd = MagicMock()
        mock_gd.list_detectors.return_value = {"DetectorIds": ["det-001"]}
        mock_gd.get_findings.return_value = {"Findings": []}

        with patch.object(enrich_handler, "_guardduty_client", return_value=mock_gd):
            result = enrich_handler.get_guardduty_finding("abc123", "us-east-1")

        assert result == {}

    def test_returns_error_dict_on_client_error(self):
        from botocore.exceptions import ClientError

        mock_gd = MagicMock()
        mock_gd.list_detectors.return_value = {"DetectorIds": ["det-001"]}
        mock_gd.get_findings.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}}, "GetFindings"
        )

        with patch.object(enrich_handler, "_guardduty_client", return_value=mock_gd):
            result = enrich_handler.get_guardduty_finding("abc123", "us-east-1")

        assert "error" in result


# ---------------------------------------------------------------------------
# get_cloudtrail_events tests
# ---------------------------------------------------------------------------

class TestGetCloudtrailEvents:
    def test_returns_events_for_instance(self):
        mock_ct = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Events": [SAMPLE_CT_EVENT]}]
        mock_ct.get_paginator.return_value = paginator

        with patch.object(enrich_handler, "_cloudtrail_client", return_value=mock_ct):
            result = enrich_handler.get_cloudtrail_events(
                "i-0123456789abcdef0", "Instance", "us-east-1"
            )

        assert len(result) == 1
        assert result[0]["EventName"] == "DescribeInstances"
        assert result[0]["SourceIPAddress"] == "1.2.3.4"

    def test_returns_empty_when_no_resource_id(self):
        result = enrich_handler.get_cloudtrail_events("", "Instance", "us-east-1")
        assert result == []

    def test_returns_error_on_client_error(self):
        from botocore.exceptions import ClientError

        mock_ct = MagicMock()
        mock_ct.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}}, "LookupEvents"
        )

        with patch.object(enrich_handler, "_cloudtrail_client", return_value=mock_ct):
            result = enrich_handler.get_cloudtrail_events(
                "i-0123456789abcdef0", "Instance", "us-east-1"
            )

        assert len(result) == 1
        assert "error" in result[0]


class TestResolveCloudtrailLookupAttribute:
    def test_instance_type(self):
        attr = enrich_handler._resolve_cloudtrail_lookup_attribute("Instance", "i-abc")
        assert attr == {"AttributeKey": "ResourceName", "AttributeValue": "i-abc"}

    def test_user_type(self):
        attr = enrich_handler._resolve_cloudtrail_lookup_attribute("IAMUser", "alice")
        assert attr == {"AttributeKey": "Username", "AttributeValue": "alice"}

    def test_role_type(self):
        attr = enrich_handler._resolve_cloudtrail_lookup_attribute("IAMRole", "my-role")
        assert attr == {"AttributeKey": "ResourceName", "AttributeValue": "my-role"}


# ---------------------------------------------------------------------------
# get_ec2_metadata tests
# ---------------------------------------------------------------------------

class TestGetEc2Metadata:
    def test_describes_instance(self):
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-0123456789abcdef0",
                            "InstanceType": "t3.micro",
                            "State": {"Name": "running"},
                            "LaunchTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
                            "PublicIpAddress": "54.1.2.3",
                            "PrivateIpAddress": "10.0.1.5",
                            "VpcId": "vpc-abc",
                            "SubnetId": "subnet-abc",
                            "Tags": [],
                            "SecurityGroups": [],
                            "IamInstanceProfile": {},
                        }
                    ]
                }
            ]
        }

        with patch.object(enrich_handler, "_ec2_client", return_value=mock_ec2):
            result = enrich_handler.get_ec2_metadata(
                "i-0123456789abcdef0", "Instance", "us-east-1"
            )

        assert result["InstanceId"] == "i-0123456789abcdef0"
        assert result["InstanceType"] == "t3.micro"

    def test_returns_empty_for_unknown_type(self):
        result = enrich_handler.get_ec2_metadata("some-id", "UnknownType", "us-east-1")
        assert result == {}

    def test_returns_empty_when_no_resource_id(self):
        result = enrich_handler.get_ec2_metadata("", "Instance", "us-east-1")
        assert result == {}


# ---------------------------------------------------------------------------
# get_iam_context tests
# ---------------------------------------------------------------------------

class TestGetIamContext:
    def test_describes_user(self):
        mock_iam = MagicMock()
        mock_iam.get_user.return_value = {
            "User": {
                "UserName": "alice",
                "UserId": "AIDXXX",
                "Arn": "arn:aws:iam::123:user/alice",
                "CreateDate": datetime(2020, 1, 1, tzinfo=timezone.utc),
                "PasswordLastUsed": None,
            }
        }
        mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}

        with patch.object(enrich_handler, "_iam_client", return_value=mock_iam):
            result = enrich_handler.get_iam_context("alice", "IAMUser")

        assert result["UserName"] == "alice"

    def test_returns_empty_when_no_resource_id(self):
        result = enrich_handler.get_iam_context("", "IAMUser")
        assert result == {}

    def test_returns_empty_for_unknown_type(self):
        result = enrich_handler.get_iam_context("some-id", "S3Bucket")
        assert result == {}


# ---------------------------------------------------------------------------
# lambda_handler integration test
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    def test_returns_enrichment_dict(self):
        mock_gd = MagicMock()
        mock_gd.list_detectors.return_value = {"DetectorIds": ["det-001"]}
        mock_gd.get_findings.return_value = {"Findings": [SAMPLE_FINDING]}

        mock_ct = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Events": []}]
        mock_ct.get_paginator.return_value = paginator

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        mock_iam = MagicMock()

        with (
            patch.object(enrich_handler, "_guardduty_client", return_value=mock_gd),
            patch.object(enrich_handler, "_cloudtrail_client", return_value=mock_ct),
            patch.object(enrich_handler, "_ec2_client", return_value=mock_ec2),
            patch.object(enrich_handler, "_iam_client", return_value=mock_iam),
        ):
            result = enrich_handler.lambda_handler(SAMPLE_EVENT, None)

        assert result["ticket_number"] == "INC-001"
        assert result["finding_id"] == "abc123"
        assert "finding" in result
        assert "cloudtrail_events" in result
        assert "ec2_metadata" in result
        assert "iam_context" in result
        assert "enrichment_timestamp" in result

    def test_handles_missing_finding_id_gracefully(self):
        event = {**SAMPLE_EVENT, "finding_id": ""}

        mock_ct = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Events": []}]
        mock_ct.get_paginator.return_value = paginator

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        with (
            patch.object(enrich_handler, "_cloudtrail_client", return_value=mock_ct),
            patch.object(enrich_handler, "_ec2_client", return_value=mock_ec2),
            patch.object(enrich_handler, "_iam_client", return_value=MagicMock()),
        ):
            result = enrich_handler.lambda_handler(event, None)

        assert result["finding"] == {}
