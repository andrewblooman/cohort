"""
tests/test_approve_actions.py

Unit tests for the approve_actions Lambda handler.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import importlib.util
import os


def _load_handler(module_name: str, relative_path: str):
    abs_path = os.path.join(os.path.dirname(__file__), relative_path)
    spec = importlib.util.spec_from_file_location(module_name, abs_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


approve_handler = _load_handler("approve_actions_handler", "../lambdas/approve_actions/handler.py")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_APPROVAL = {
    "task_token": "AAAAKgAAAAIAAAAAAAAAAQtoken",
    "analyst_id": "analyst@company.com",
    "approval_notes": "Confirmed true positive — isolating instance",
    "approved_actions": [
        {
            "action_id": "ec2-isolate-1",
            "type": "isolate_ec2_instance",
            "parameters": {"instance_id": "i-0abc123", "region": "us-east-1"},
        },
        {
            "action_id": "gd-archive-1",
            "type": "archive_guardduty_finding",
            "parameters": {"finding_id": "def456", "detector_id": "ghi789", "region": "us-east-1"},
        },
    ],
}


# ---------------------------------------------------------------------------
# validate_approval tests
# ---------------------------------------------------------------------------

class TestValidateApproval:
    def test_returns_empty_for_valid_payload(self):
        errors = approve_handler.validate_approval(VALID_APPROVAL)
        assert errors == []

    def test_requires_task_token(self):
        payload = {**VALID_APPROVAL, "task_token": ""}
        errors = approve_handler.validate_approval(payload)
        assert any("task_token" in e for e in errors)

    def test_requires_analyst_id(self):
        payload = {**VALID_APPROVAL, "analyst_id": ""}
        errors = approve_handler.validate_approval(payload)
        assert any("analyst_id" in e for e in errors)

    def test_requires_approved_actions_list(self):
        payload = {**VALID_APPROVAL, "approved_actions": "not a list"}
        errors = approve_handler.validate_approval(payload)
        assert any("list" in e for e in errors)

    def test_requires_action_type(self):
        payload = {
            **VALID_APPROVAL,
            "approved_actions": [{"action_id": "x", "parameters": {}}],
        }
        errors = approve_handler.validate_approval(payload)
        assert any("type" in e for e in errors)

    def test_rejects_unknown_action_type(self):
        payload = {
            **VALID_APPROVAL,
            "approved_actions": [{"action_id": "x", "type": "nuke_everything", "parameters": {}}],
        }
        errors = approve_handler.validate_approval(payload)
        assert any("not supported" in e for e in errors)

    def test_accepts_all_supported_types(self):
        for action_type in approve_handler.SUPPORTED_ACTION_TYPES:
            payload = {
                **VALID_APPROVAL,
                "approved_actions": [{"action_id": "t", "type": action_type, "parameters": {}}],
            }
            errors = approve_handler.validate_approval(payload)
            assert errors == [], f"Unexpected errors for type {action_type}: {errors}"


# ---------------------------------------------------------------------------
# lambda_handler — approval path
# ---------------------------------------------------------------------------

class TestLambdaHandlerApproval:
    def test_calls_send_task_success(self):
        mock_sfn = MagicMock()

        with patch.object(approve_handler, "_sfn_client", return_value=mock_sfn):
            result = approve_handler.lambda_handler(VALID_APPROVAL, None)

        assert result["status"] == "approved"
        assert result["analyst_id"] == "analyst@company.com"
        assert result["approved_actions_count"] == 2
        mock_sfn.send_task_success.assert_called_once()

    def test_send_task_success_payload_contains_approved_actions(self):
        mock_sfn = MagicMock()

        with patch.object(approve_handler, "_sfn_client", return_value=mock_sfn):
            approve_handler.lambda_handler(VALID_APPROVAL, None)

        call_kwargs = mock_sfn.send_task_success.call_args[1]
        assert call_kwargs["taskToken"] == VALID_APPROVAL["task_token"]
        output = json.loads(call_kwargs["output"])
        assert output["analyst_id"] == "analyst@company.com"
        assert len(output["approved_actions"]) == 2

    def test_returns_error_for_missing_task_token(self):
        payload = {**VALID_APPROVAL, "task_token": ""}
        result = approve_handler.lambda_handler(payload, None)
        assert result["status"] == "error"

    def test_returns_error_on_sfn_client_error(self):
        from botocore.exceptions import ClientError

        mock_sfn = MagicMock()
        mock_sfn.send_task_success.side_effect = ClientError(
            {"Error": {"Code": "TaskTimedOut", "Message": "Task token expired"}},
            "SendTaskSuccess",
        )

        with patch.object(approve_handler, "_sfn_client", return_value=mock_sfn):
            result = approve_handler.lambda_handler(VALID_APPROVAL, None)

        assert result["status"] == "error"
        assert "TaskTimedOut" in result["message"]


# ---------------------------------------------------------------------------
# lambda_handler — rejection path
# ---------------------------------------------------------------------------

class TestLambdaHandlerRejection:
    def test_calls_send_task_failure(self):
        mock_sfn = MagicMock()
        payload = {
            "action": "reject",
            "task_token": "AAAAKgAAAAIAAAAAAAAAAQtoken",
            "analyst_id": "analyst@company.com",
            "rejection_reason": "False positive confirmed — no action needed",
        }

        with patch.object(approve_handler, "_sfn_client", return_value=mock_sfn):
            result = approve_handler.lambda_handler(payload, None)

        assert result["status"] == "rejected"
        mock_sfn.send_task_failure.assert_called_once()
        call_kwargs = mock_sfn.send_task_failure.call_args[1]
        assert call_kwargs["error"] == "AnalystRejected"

    def test_rejection_requires_task_token(self):
        payload = {"action": "reject", "analyst_id": "analyst@company.com", "task_token": ""}
        result = approve_handler.lambda_handler(payload, None)
        assert result["status"] == "error"

    def test_rejection_requires_analyst_id(self):
        payload = {"action": "reject", "task_token": "token123", "analyst_id": ""}
        result = approve_handler.lambda_handler(payload, None)
        assert result["status"] == "error"
