"""
tests/test_notify.py

Unit tests for the notify Lambda handler.
"""

from __future__ import annotations

import importlib.util
import json
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch

import pytest


def _load_handler(module_name: str, relative_path: str):
    """Load a Lambda handler module from a relative path without polluting sys.modules."""
    abs_path = os.path.join(os.path.dirname(__file__), relative_path)
    spec = importlib.util.spec_from_file_location(module_name, abs_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


notify_handler = _load_handler("notify_handler", "../lambdas/notify/handler.py")


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_ANALYSIS = {
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "threat_summary": "EC2 instance established outbound connections to Tor exit nodes.",
    "proposed_actions": ["Isolate instance", "Rotate credentials"],
    "approval_status": "PENDING_HUMAN_APPROVAL",
}

SAMPLE_EVENT = {
    "ticket_number": "inc-0005",
    "finding_id": "jkl345",
    "alert_type": "UnauthorizedAccess:EC2/TorIPCaller",
    "severity": "HIGH",
    "account_id": "123456789012",
    "region": "eu-west-1",
    "analysis_result": {"analysis": SAMPLE_ANALYSIS},
    "store_result": {"store": {"s3_bucket": "test-bucket", "s3_prefix": "inc-0005/"}},
    "task_token": "AAAAKgAAAAIAAAAAAAAAAQ==",
    "notify_mode": "investigation",
}

SAMPLE_EXECUTION = {
    "analyst_id": "analyst@company.com",
    "approval_notes": "Confirmed true positive",
    "approval_timestamp": "2024-01-15T11:00:00+00:00",
    "execution_timestamp": "2024-01-15T11:05:00+00:00",
    "total_actions": 2,
    "succeeded": 2,
    "failed": 0,
    "results": [
        {"action_id": "a1", "type": "isolate_ec2_instance", "status": "succeeded", "details": "Security group applied"},
        {"action_id": "a2", "type": "archive_guardduty_finding", "status": "succeeded", "details": "Archived"},
    ],
}


# ---------------------------------------------------------------------------
# TestGetSlackWebhookUrl
# ---------------------------------------------------------------------------

class TestGetSlackWebhookUrl:
    def test_returns_none_when_secret_arn_not_set(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_SECRET_ARN", "")
        reloaded = _load_handler("notify_handler_no_arn", "../lambdas/notify/handler.py")
        assert reloaded.get_slack_webhook_url() is None

    def test_returns_url_from_secret(self):
        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": "https://hooks.slack.com/services/T000/B000/xyz"}
        with patch.object(notify_handler, "SLACK_WEBHOOK_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:slack"):
            with patch("boto3.client", return_value=mock_sm):
                result = notify_handler.get_slack_webhook_url()
        assert result == "https://hooks.slack.com/services/T000/B000/xyz"

    def test_returns_none_on_client_error(self):
        from botocore.exceptions import ClientError

        mock_sm = MagicMock()
        mock_sm.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Not found"}},
            "GetSecretValue",
        )
        with patch("boto3.client", return_value=mock_sm):
            result = notify_handler.get_slack_webhook_url()
        assert result is None

    def test_returns_none_when_secret_is_empty_string(self):
        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": "   "}
        with patch("boto3.client", return_value=mock_sm):
            result = notify_handler.get_slack_webhook_url()
        assert result is None


# ---------------------------------------------------------------------------
# TestBuildInvestigationSlackMessage
# ---------------------------------------------------------------------------

class TestBuildInvestigationSlackMessage:
    def test_contains_ticket_number_in_header(self):
        payload = notify_handler.build_investigation_slack_message(SAMPLE_EVENT, SAMPLE_ANALYSIS)
        header_text = payload["blocks"][0]["text"]["text"]
        assert "inc-0005" in header_text

    def test_contains_verdict_in_fields(self):
        payload = notify_handler.build_investigation_slack_message(SAMPLE_EVENT, SAMPLE_ANALYSIS)
        all_text = json.dumps(payload)
        assert "TRUE POSITIVE" in all_text

    def test_contains_severity_in_fields(self):
        payload = notify_handler.build_investigation_slack_message(SAMPLE_EVENT, SAMPLE_ANALYSIS)
        all_text = json.dumps(payload)
        assert "HIGH" in all_text

    def test_contains_threat_summary(self):
        payload = notify_handler.build_investigation_slack_message(SAMPLE_EVENT, SAMPLE_ANALYSIS)
        all_text = json.dumps(payload)
        assert "Tor exit nodes" in all_text

    def test_contains_proposed_actions(self):
        payload = notify_handler.build_investigation_slack_message(SAMPLE_EVENT, SAMPLE_ANALYSIS)
        all_text = json.dumps(payload)
        assert "Isolate instance" in all_text

    def test_includes_fallback_text(self):
        payload = notify_handler.build_investigation_slack_message(SAMPLE_EVENT, SAMPLE_ANALYSIS)
        assert "inc-0005" in payload["text"]
        assert "TRUE POSITIVE" in payload["text"]

    def test_no_review_button_without_api_endpoint(self, monkeypatch):
        monkeypatch.setenv("APPROVAL_API_ENDPOINT", "")
        reloaded = _load_handler("notify_handler_no_url", "../lambdas/notify/handler.py")
        payload = reloaded.build_investigation_slack_message(SAMPLE_EVENT, SAMPLE_ANALYSIS)
        all_text = json.dumps(payload)
        assert "button" not in all_text

    def test_includes_review_button_with_api_endpoint(self, monkeypatch):
        monkeypatch.setenv("APPROVAL_API_ENDPOINT", "https://api.example.com")
        reloaded = _load_handler("notify_handler_with_url", "../lambdas/notify/handler.py")
        payload = reloaded.build_investigation_slack_message(SAMPLE_EVENT, SAMPLE_ANALYSIS)
        all_text = json.dumps(payload)
        assert "button" in all_text
        assert "inc-0005" in all_text

    def test_truncates_long_threat_summary(self):
        long_summary = "X" * 500
        analysis = {**SAMPLE_ANALYSIS, "threat_summary": long_summary}
        payload = notify_handler.build_investigation_slack_message(SAMPLE_EVENT, analysis)
        # Confirm the summary was truncated — the full 500 Xs should not all appear
        all_text = json.dumps(payload)
        assert "X" * 301 not in all_text  # truncated to 300 chars + ellipsis

    def test_handles_empty_proposed_actions(self):
        analysis = {**SAMPLE_ANALYSIS, "proposed_actions": []}
        payload = notify_handler.build_investigation_slack_message(SAMPLE_EVENT, analysis)
        all_text = json.dumps(payload)
        assert "No specific actions proposed" in all_text

    def test_caps_proposed_actions_display_at_five(self):
        analysis = {**SAMPLE_ANALYSIS, "proposed_actions": [f"Action {i}" for i in range(10)]}
        payload = notify_handler.build_investigation_slack_message(SAMPLE_EVENT, analysis)
        all_text = json.dumps(payload)
        assert "5 more" in all_text


# ---------------------------------------------------------------------------
# TestBuildExecutionSlackMessage
# ---------------------------------------------------------------------------

class TestBuildExecutionSlackMessage:
    def test_contains_ticket_number(self):
        event = {**SAMPLE_EVENT, "notify_mode": "execution_results"}
        payload = notify_handler.build_execution_slack_message(event, SAMPLE_EXECUTION)
        assert "inc-0005" in payload["blocks"][0]["text"]["text"]

    def test_all_succeeded_uses_check_emoji(self):
        event = {**SAMPLE_EVENT, "notify_mode": "execution_results"}
        payload = notify_handler.build_execution_slack_message(event, SAMPLE_EXECUTION)
        assert "✅" in payload["blocks"][0]["text"]["text"]

    def test_partial_failure_uses_warning_emoji(self):
        execution = {**SAMPLE_EXECUTION, "failed": 1, "succeeded": 1}
        event = {**SAMPLE_EVENT, "notify_mode": "execution_results"}
        payload = notify_handler.build_execution_slack_message(event, execution)
        assert "⚠️" in payload["blocks"][0]["text"]["text"]

    def test_contains_analyst_id(self):
        event = {**SAMPLE_EVENT, "notify_mode": "execution_results"}
        payload = notify_handler.build_execution_slack_message(event, SAMPLE_EXECUTION)
        all_text = json.dumps(payload)
        assert "analyst@company.com" in all_text

    def test_contains_action_results(self):
        event = {**SAMPLE_EVENT, "notify_mode": "execution_results"}
        payload = notify_handler.build_execution_slack_message(event, SAMPLE_EXECUTION)
        all_text = json.dumps(payload)
        assert "isolate_ec2_instance" in all_text


# ---------------------------------------------------------------------------
# TestStorePendingApproval
# ---------------------------------------------------------------------------

class TestStorePendingApproval:
    def test_writes_to_s3(self):
        mock_s3 = MagicMock()
        with patch.object(notify_handler, "ARTIFACTS_BUCKET", "test-artifacts-bucket"):
            with patch("boto3.client", return_value=mock_s3):
                notify_handler._store_pending_approval(
                    "inc-0005", "token123", SAMPLE_ANALYSIS
                )
        mock_s3.put_object.assert_called_once()
        call_kwargs = mock_s3.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "test-artifacts-bucket"
        assert call_kwargs["Key"] == "inc-0005/pending_approval.json"

    def test_skips_when_no_task_token(self):
        mock_s3 = MagicMock()
        with patch("boto3.client", return_value=mock_s3):
            notify_handler._store_pending_approval("inc-0005", "", SAMPLE_ANALYSIS)
        mock_s3.put_object.assert_not_called()

    def test_skips_when_no_ticket_number(self):
        mock_s3 = MagicMock()
        with patch("boto3.client", return_value=mock_s3):
            notify_handler._store_pending_approval("", "token123", SAMPLE_ANALYSIS)
        mock_s3.put_object.assert_not_called()

    def test_stores_correct_fields(self):
        mock_s3 = MagicMock()
        with patch.object(notify_handler, "ARTIFACTS_BUCKET", "test-artifacts-bucket"):
            with patch("boto3.client", return_value=mock_s3):
                notify_handler._store_pending_approval(
                    "inc-0005", "token123", SAMPLE_ANALYSIS
                )
        body = json.loads(mock_s3.put_object.call_args[1]["Body"])
        assert body["task_token"] == "token123"
        assert body["ticket_number"] == "inc-0005"
        assert body["verdict"] == "TRUE_POSITIVE"
        assert body["proposed_actions"] == ["Isolate instance", "Rotate credentials"]


# ---------------------------------------------------------------------------
# TestLambdaHandlerInvestigation
# ---------------------------------------------------------------------------

class TestLambdaHandlerInvestigation:
    def test_stores_pending_approval_when_task_token_present(self):
        mock_s3 = MagicMock()
        with patch.object(notify_handler, "ARTIFACTS_BUCKET", "test-artifacts-bucket"):
            with patch("boto3.client", return_value=mock_s3):
                with patch.object(notify_handler, "get_slack_webhook_url", return_value=None):
                    notify_handler.lambda_handler(SAMPLE_EVENT, None)
        mock_s3.put_object.assert_called_once()

    def test_skips_s3_write_when_no_task_token(self):
        event = {**SAMPLE_EVENT, "task_token": ""}
        mock_s3 = MagicMock()
        with patch("boto3.client", return_value=mock_s3):
            with patch.object(notify_handler, "get_slack_webhook_url", return_value=None):
                notify_handler.lambda_handler(event, None)
        mock_s3.put_object.assert_not_called()

    def test_returns_verdict_and_confidence(self):
        with patch("boto3.client", return_value=MagicMock()):
            with patch.object(notify_handler, "get_slack_webhook_url", return_value=None):
                result = notify_handler.lambda_handler(SAMPLE_EVENT, None)
        assert result["verdict"] == "TRUE_POSITIVE"
        assert result["confidence"] == "HIGH"

    def test_slack_status_skipped_when_no_webhook(self):
        with patch("boto3.client", return_value=MagicMock()):
            with patch.object(notify_handler, "get_slack_webhook_url", return_value=None):
                result = notify_handler.lambda_handler(SAMPLE_EVENT, None)
        assert result["slack_status"] == "skipped"

    def test_slack_status_sent_when_webhook_configured(self):
        with patch("boto3.client", return_value=MagicMock()):
            with patch.object(notify_handler, "get_slack_webhook_url", return_value="https://hooks.slack.com/x"):
                with patch.object(notify_handler, "post_slack_message", return_value=True):
                    result = notify_handler.lambda_handler(SAMPLE_EVENT, None)
        assert result["slack_status"] == "sent"

    def test_slack_status_failed_on_webhook_error(self):
        with patch("boto3.client", return_value=MagicMock()):
            with patch.object(notify_handler, "get_slack_webhook_url", return_value="https://hooks.slack.com/x"):
                with patch.object(notify_handler, "post_slack_message", return_value=False):
                    result = notify_handler.lambda_handler(SAMPLE_EVENT, None)
        assert result["slack_status"] == "failed"

    def test_handles_flat_analysis_result(self):
        """Handler should work whether analysis_result contains a nested 'analysis' key or not."""
        event = {**SAMPLE_EVENT, "analysis_result": SAMPLE_ANALYSIS}
        with patch("boto3.client", return_value=MagicMock()):
            with patch.object(notify_handler, "get_slack_webhook_url", return_value=None):
                result = notify_handler.lambda_handler(event, None)
        assert result["verdict"] == "TRUE_POSITIVE"

    def test_returns_ticket_number_in_result(self):
        with patch("boto3.client", return_value=MagicMock()):
            with patch.object(notify_handler, "get_slack_webhook_url", return_value=None):
                result = notify_handler.lambda_handler(SAMPLE_EVENT, None)
        assert result["ticket_number"] == "inc-0005"


# ---------------------------------------------------------------------------
# TestLambdaHandlerExecutionResults
# ---------------------------------------------------------------------------

class TestLambdaHandlerExecutionResults:
    def test_sends_execution_slack_message(self):
        event = {
            "ticket_number": "inc-0005",
            "notify_mode": "execution_results",
            "execution_result": {"execution": SAMPLE_EXECUTION},
        }
        with patch.object(notify_handler, "get_slack_webhook_url", return_value="https://hooks.slack.com/x"):
            with patch.object(notify_handler, "post_slack_message", return_value=True) as mock_post:
                result = notify_handler.lambda_handler(event, None)

        mock_post.assert_called_once()
        payload = mock_post.call_args[0][1]
        assert "inc-0005" in json.dumps(payload)
        assert result["slack_status"] == "sent"

    def test_skips_s3_write_in_execution_mode(self):
        event = {
            "ticket_number": "inc-0005",
            "notify_mode": "execution_results",
            "execution_result": {"execution": SAMPLE_EXECUTION},
        }
        mock_s3 = MagicMock()
        with patch("boto3.client", return_value=mock_s3):
            with patch.object(notify_handler, "get_slack_webhook_url", return_value=None):
                notify_handler.lambda_handler(event, None)
        mock_s3.put_object.assert_not_called()

    def test_handles_flat_execution_result(self):
        event = {
            "ticket_number": "inc-0005",
            "notify_mode": "execution_results",
            "execution_result": SAMPLE_EXECUTION,
        }
        with patch.object(notify_handler, "get_slack_webhook_url", return_value=None):
            result = notify_handler.lambda_handler(event, None)
        assert result["notify_mode"] == "execution_results"
