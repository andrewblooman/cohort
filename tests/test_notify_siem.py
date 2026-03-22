"""
tests/test_notify_siem.py

Unit tests for the notify_siem Lambda handler.
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

notify_handler = _load_handler("notify_siem_handler", "../lambdas/notify_siem/handler.py")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_ANALYSIS = {
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "reasoning": "The evidence confirms malicious activity.",
    "threat_summary": "Confirmed cryptocurrency mining.",
    "indicators_of_compromise": ["pool.minexmr.com"],
    "false_positive_indicators": [],
    "proposed_actions": ["Isolate instance", "Rotate credentials"],
    "mitre_attack_techniques": ["T1496"],
    "approval_status": "PENDING_HUMAN_APPROVAL",
    "actions_taken": [],
}

SAMPLE_STORE_RESULT = {
    "s3_bucket": "test-artifacts-bucket",
    "s3_prefix": "INC-005/",
    "stored_keys": ["INC-005/ai_recommendation.txt"],
}

SAMPLE_EVENT = {
    "ticket_number": "INC-005",
    "finding_id": "jkl345",
    "secops_case_id": "CASE-400",
    "analysis_result": {"analysis": SAMPLE_ANALYSIS},
    "store_result": {"store": SAMPLE_STORE_RESULT},
}

SAMPLE_GOOGLE_CREDS = {
    "type": "service_account",
    "project_id": "my-project",
    "private_key_id": "key-id",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n",
    "client_email": "sa@my-project.iam.gserviceaccount.com",
    "client_id": "123456789",
    "token_uri": "https://oauth2.googleapis.com/token",
}


# ---------------------------------------------------------------------------
# get_google_credentials tests
# ---------------------------------------------------------------------------

class TestGetGoogleCredentials:
    def test_returns_none_when_secret_arn_not_set(self):
        with patch.object(notify_handler, "GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN", ""):
            result = notify_handler.get_google_credentials()
        assert result is None

    def test_returns_parsed_credentials(self):
        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {
            "SecretString": json.dumps(SAMPLE_GOOGLE_CREDS)
        }

        with (
            patch.object(notify_handler, "GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:creds"),
            patch("boto3.client", return_value=mock_sm),
        ):
            result = notify_handler.get_google_credentials()

        assert result["client_email"] == "sa@my-project.iam.gserviceaccount.com"

    def test_returns_none_on_client_error(self):
        from botocore.exceptions import ClientError

        mock_sm = MagicMock()
        mock_sm.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Secret not found"}},
            "GetSecretValue",
        )

        with (
            patch.object(notify_handler, "GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:creds"),
            patch("boto3.client", return_value=mock_sm),
        ):
            result = notify_handler.get_google_credentials()

        assert result is None

    def test_returns_none_on_invalid_json(self):
        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": "not-valid-json{{{"}

        with (
            patch.object(notify_handler, "GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:creds"),
            patch("boto3.client", return_value=mock_sm),
        ):
            result = notify_handler.get_google_credentials()

        assert result is None


# ---------------------------------------------------------------------------
# build_siem_comment tests
# ---------------------------------------------------------------------------

class TestBuildSiemComment:
    def test_contains_ticket_number(self):
        comment = notify_handler.build_siem_comment(SAMPLE_EVENT, SAMPLE_ANALYSIS, SAMPLE_STORE_RESULT)
        assert "INC-005" in comment

    def test_contains_verdict(self):
        comment = notify_handler.build_siem_comment(SAMPLE_EVENT, SAMPLE_ANALYSIS, SAMPLE_STORE_RESULT)
        assert "TRUE POSITIVE" in comment

    def test_contains_s3_path(self):
        comment = notify_handler.build_siem_comment(SAMPLE_EVENT, SAMPLE_ANALYSIS, SAMPLE_STORE_RESULT)
        assert "test-artifacts-bucket" in comment
        assert "INC-005/" in comment

    def test_contains_proposed_actions(self):
        comment = notify_handler.build_siem_comment(SAMPLE_EVENT, SAMPLE_ANALYSIS, SAMPLE_STORE_RESULT)
        assert "Isolate instance" in comment
        assert "Rotate credentials" in comment

    def test_contains_approval_language(self):
        comment = notify_handler.build_siem_comment(SAMPLE_EVENT, SAMPLE_ANALYSIS, SAMPLE_STORE_RESULT)
        assert "PENDING ANALYST APPROVAL" in comment
        assert "NO AUTOMATED ACTIONS HAVE BEEN TAKEN" in comment

    def test_handles_empty_proposed_actions(self):
        analysis = {**SAMPLE_ANALYSIS, "proposed_actions": []}
        comment = notify_handler.build_siem_comment(SAMPLE_EVENT, analysis, SAMPLE_STORE_RESULT)
        assert "No specific actions proposed" in comment

    def test_includes_task_token_in_comment_when_present(self):
        event = {**SAMPLE_EVENT, "task_token": "AAAAKgAAAAIAAAAAAAAAAQtoken"}
        comment = notify_handler.build_siem_comment(event, SAMPLE_ANALYSIS, SAMPLE_STORE_RESULT)
        assert "AAAAKgAAAAIAAAAAAAAAAQtoken" in comment
        assert "approve_actions" in comment
        assert "7 days" in comment

    def test_no_approval_section_without_task_token(self):
        event = {**SAMPLE_EVENT}  # no task_token
        comment = notify_handler.build_siem_comment(event, SAMPLE_ANALYSIS, SAMPLE_STORE_RESULT)
        assert "approve_actions" not in comment


class TestBuildExecutionComment:
    EXECUTION = {
        "analyst_id": "analyst@company.com",
        "approval_notes": "Confirmed threat",
        "approval_timestamp": "2024-01-15T11:00:00+00:00",
        "execution_timestamp": "2024-01-15T11:05:00+00:00",
        "total_actions": 2,
        "succeeded": 2,
        "failed": 0,
        "results": [
            {"action_id": "ec2-1", "type": "stop_ec2_instance", "status": "succeeded", "details": {"instance_id": "i-abc"}},
            {"action_id": "gd-1", "type": "archive_guardduty_finding", "status": "succeeded", "details": {}},
        ],
    }

    def test_contains_analyst_id(self):
        comment = notify_handler.build_execution_comment(SAMPLE_EVENT, self.EXECUTION)
        assert "analyst@company.com" in comment

    def test_contains_action_results(self):
        comment = notify_handler.build_execution_comment(SAMPLE_EVENT, self.EXECUTION)
        assert "stop_ec2_instance" in comment
        assert "archive_guardduty_finding" in comment
        assert "succeeded" in comment

    def test_shows_partial_failure(self):
        execution = {
            **self.EXECUTION,
            "failed": 1,
            "results": [
                {"action_id": "bad-1", "type": "stop_ec2_instance", "status": "failed", "error": "Instance not found"},
            ],
        }
        comment = notify_handler.build_execution_comment(SAMPLE_EVENT, execution)
        assert "failed" in comment
        assert "Instance not found" in comment


# ---------------------------------------------------------------------------
# post_case_comment tests
# ---------------------------------------------------------------------------

class TestPostCaseComment:
    def test_skips_when_endpoint_not_configured(self):
        with (
            patch.object(notify_handler, "GOOGLE_SECOPS_API_ENDPOINT", ""),
            patch.object(notify_handler, "GOOGLE_SECOPS_CUSTOMER_ID", ""),
        ):
            result = notify_handler.post_case_comment("CASE-400", "comment", "token")

        assert result["skipped"] is True

    def test_posts_successfully(self):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"id": "comment-001"}).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with (
            patch.object(notify_handler, "GOOGLE_SECOPS_API_ENDPOINT", "https://backstory.googleapis.com"),
            patch.object(notify_handler, "GOOGLE_SECOPS_CUSTOMER_ID", "customer-abc"),
            patch.object(notify_handler, "urlopen", return_value=mock_response),
        ):
            result = notify_handler.post_case_comment("CASE-400", "test comment", "access-token")

        assert result["success"] is True


# ---------------------------------------------------------------------------
# lambda_handler integration tests
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    def test_skips_when_no_secops_case_id(self):
        event = {**SAMPLE_EVENT, "secops_case_id": ""}
        result = notify_handler.lambda_handler(event, None)
        assert result["notification_status"] == "skipped"
        assert result["ticket_number"] == "INC-005"
        assert result["verdict"] == "TRUE_POSITIVE"
        assert result["approval_status"] == "PENDING_HUMAN_APPROVAL"

    def test_skips_when_no_endpoint_configured(self):
        with patch.object(notify_handler, "GOOGLE_SECOPS_API_ENDPOINT", ""):
            result = notify_handler.lambda_handler(SAMPLE_EVENT, None)

        assert result["notification_status"] == "skipped"

    def test_skips_when_credentials_unavailable(self):
        with (
            patch.object(notify_handler, "GOOGLE_SECOPS_API_ENDPOINT", "https://backstory.googleapis.com"),
            patch.object(notify_handler, "get_google_credentials", return_value=None),
        ):
            result = notify_handler.lambda_handler(SAMPLE_EVENT, None)

        assert result["notification_status"] == "skipped"

    def test_returns_comment_in_output(self):
        result = notify_handler.lambda_handler({**SAMPLE_EVENT, "secops_case_id": ""}, None)
        assert "comment" in result
        assert "INC-005" in result["comment"]

    def test_extracts_nested_analysis_result(self):
        """analysis_result with nested 'analysis' key should be unwrapped."""
        event = {**SAMPLE_EVENT}
        result = notify_handler.lambda_handler({**event, "secops_case_id": ""}, None)
        assert result["verdict"] == "TRUE_POSITIVE"

    def test_handles_flat_analysis_result(self):
        """analysis_result without nesting should also work."""
        event = {**SAMPLE_EVENT, "analysis_result": SAMPLE_ANALYSIS, "secops_case_id": ""}
        result = notify_handler.lambda_handler(event, None)
        assert result["verdict"] == "TRUE_POSITIVE"

    def test_full_notification_flow(self):
        """End-to-end test with mocked Google API call."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"id": "comment-001"}).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with (
            patch.object(notify_handler, "GOOGLE_SECOPS_API_ENDPOINT", "https://backstory.googleapis.com"),
            patch.object(notify_handler, "GOOGLE_SECOPS_CUSTOMER_ID", "customer-abc"),
            patch.object(notify_handler, "get_google_credentials", return_value=SAMPLE_GOOGLE_CREDS),
            patch.object(notify_handler, "get_access_token", return_value="test-access-token"),
            patch.object(notify_handler, "urlopen", return_value=mock_response),
        ):
            result = notify_handler.lambda_handler(SAMPLE_EVENT, None)

        assert result["notification_status"] == "success"
        assert result["secops_case_id"] == "CASE-400"
        assert result["approval_status"] == "PENDING_HUMAN_APPROVAL"
