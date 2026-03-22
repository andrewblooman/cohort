"""
tests/test_get_investigation.py

Unit tests for the get_investigation Lambda handler.
"""

from __future__ import annotations

import importlib.util
import json
import os
from datetime import datetime, timezone
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError


def _load_handler(module_name: str, relative_path: str):
    abs_path = os.path.join(os.path.dirname(__file__), relative_path)
    spec = importlib.util.spec_from_file_location(module_name, abs_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


handler = _load_handler(
    "get_investigation_handler",
    "../lambdas/get_investigation/handler.py",
)

# Set module-level variables that are read at import time (before conftest fixtures run)
_TEST_SFN_ARN = "arn:aws:states:us-east-1:123456789012:stateMachine:cohort-incident-response"
handler.SFN_STATE_MACHINE_ARN = _TEST_SFN_ARN
handler.ARTIFACTS_BUCKET = "test-artifacts-bucket"

_NOW = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
_TICKET = "TICKET-001"

_INCIDENT_SUMMARY = {
    "incident": {
        "ticket_number": _TICKET,
        "alert_type": "UnauthorizedAccess:EC2/TorIPCaller",
        "severity": "HIGH",
        "finding_id": "finding-abc",
        "account_id": "123456789012",
        "region": "us-east-1",
        "resource_type": "Instance",
        "resource_id": "i-0abc123",
    },
    "analysis": {
        "verdict": "TRUE_POSITIVE",
        "confidence": "HIGH",
        "reasoning": "The IP is a known Tor exit node.",
        "proposed_actions": ["Isolate instance i-0abc123"],
        "approval_status": "PENDING_HUMAN_APPROVAL",
    },
    "artifacts": {"s3_keys": ["TICKET-001/ai_recommendation.txt"]},
    "generated_at": _NOW.isoformat(),
}

_PENDING_APPROVAL = {
    "task_token": "AAAAKgAAAAIAAAAAAAAAAQ==",
    "ticket_number": _TICKET,
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "proposed_actions": ["Isolate instance i-0abc123"],
    "stored_at": _NOW.isoformat(),
}

_EXEC_SUMMARY = {
    "executionArn": "arn:aws:states:us-east-1:123456789012:execution:cohort:exec-001",
    "name": "exec-001",
    "status": "RUNNING",
    "startDate": _NOW,
    "stopDate": None,
}


def _make_s3_mock(has_summary: bool = True, has_pending: bool = True):
    s3 = MagicMock()

    def _get_object(Bucket, Key):
        if Key == f"{_TICKET}/incident_summary.json" and has_summary:
            return {"Body": BytesIO(json.dumps(_INCIDENT_SUMMARY).encode())}
        if Key == f"{_TICKET}/pending_approval.json" and has_pending:
            return {"Body": BytesIO(json.dumps(_PENDING_APPROVAL).encode())}
        raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "Not found"}}, "GetObject")

    s3.get_object.side_effect = _get_object
    return s3


def _make_sfn_mock(ticket_matches: bool = True):
    sfn = MagicMock()
    sfn.list_executions.return_value = {"executions": [_EXEC_SUMMARY]}

    def _describe(executionArn):
        input_data = {"ticket_number": _TICKET if ticket_matches else "OTHER"}
        return {
            "executionArn": executionArn,
            "input": json.dumps(input_data),
            "status": "RUNNING",
        }

    sfn.describe_execution.side_effect = _describe
    return sfn


# ---------------------------------------------------------------------------
# _read_s3_json
# ---------------------------------------------------------------------------

class TestReadS3Json:
    def test_returns_parsed_dict(self):
        s3 = _make_s3_mock(has_summary=True)
        result = handler._read_s3_json(s3, f"{_TICKET}/incident_summary.json")
        assert result["incident"]["ticket_number"] == _TICKET

    def test_returns_none_for_missing_key(self):
        s3 = _make_s3_mock(has_summary=False, has_pending=False)
        result = handler._read_s3_json(s3, f"{_TICKET}/incident_summary.json")
        assert result is None

    def test_returns_none_on_other_s3_error(self):
        s3 = MagicMock()
        s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "GetObject"
        )
        result = handler._read_s3_json(s3, "any/key.json")
        assert result is None


# ---------------------------------------------------------------------------
# _find_execution
# ---------------------------------------------------------------------------

class TestFindExecution:
    def test_returns_matching_execution(self):
        sfn = _make_sfn_mock(ticket_matches=True)
        result = handler._find_execution(sfn, _TICKET)
        assert result is not None
        assert result["status"] == "RUNNING"
        assert result["execution_name"] == "exec-001"

    def test_returns_none_when_no_match(self):
        sfn = _make_sfn_mock(ticket_matches=False)
        result = handler._find_execution(sfn, _TICKET)
        assert result is None

    def test_returns_none_when_sfn_arn_not_set(self):
        sfn = _make_sfn_mock()
        original = handler.SFN_STATE_MACHINE_ARN
        handler.SFN_STATE_MACHINE_ARN = ""
        try:
            result = handler._find_execution(sfn, _TICKET)
            assert result is None
        finally:
            handler.SFN_STATE_MACHINE_ARN = original

    def test_skips_execution_on_describe_error(self):
        sfn = MagicMock()
        sfn.list_executions.return_value = {"executions": [_EXEC_SUMMARY]}
        sfn.describe_execution.side_effect = ClientError(
            {"Error": {"Code": "ExecutionDoesNotExist", "Message": "x"}},
            "DescribeExecution",
        )
        result = handler._find_execution(sfn, _TICKET)
        assert result is None


# ---------------------------------------------------------------------------
# lambda_handler
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    def test_returns_200_with_full_data(self):
        s3 = _make_s3_mock()
        sfn = _make_sfn_mock()
        with patch.object(handler, "_s3_client", return_value=s3), \
             patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["ticket_number"] == _TICKET
        assert body["incident_summary"] is not None
        assert body["pending_approval"]["task_token"] == _PENDING_APPROVAL["task_token"]
        assert body["execution"]["status"] == "RUNNING"

    def test_returns_400_when_ticket_number_missing(self):
        with patch.object(handler, "_s3_client", return_value=MagicMock()), \
             patch.object(handler, "_sfn_client", return_value=MagicMock()):
            result = handler.lambda_handler({"pathParameters": {}}, None)
        assert result["statusCode"] == 400

    def test_returns_400_when_path_params_absent(self):
        with patch.object(handler, "_s3_client", return_value=MagicMock()), \
             patch.object(handler, "_sfn_client", return_value=MagicMock()):
            result = handler.lambda_handler({}, None)
        assert result["statusCode"] == 400

    def test_returns_404_when_not_found_in_s3_or_sfn(self):
        s3 = _make_s3_mock(has_summary=False, has_pending=False)
        sfn = _make_sfn_mock(ticket_matches=False)
        with patch.object(handler, "_s3_client", return_value=s3), \
             patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        assert result["statusCode"] == 404

    def test_returns_200_with_execution_even_when_s3_missing(self):
        s3 = _make_s3_mock(has_summary=False, has_pending=False)
        sfn = _make_sfn_mock(ticket_matches=True)
        with patch.object(handler, "_s3_client", return_value=s3), \
             patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["incident_summary"] is None
        assert body["execution"] is not None

    def test_pending_approval_is_none_when_not_found(self):
        s3 = _make_s3_mock(has_summary=True, has_pending=False)
        sfn = _make_sfn_mock()
        with patch.object(handler, "_s3_client", return_value=s3), \
             patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        body = json.loads(result["body"])
        assert body["pending_approval"] is None

    def test_returns_cors_headers(self):
        s3 = _make_s3_mock()
        sfn = _make_sfn_mock()
        with patch.object(handler, "_s3_client", return_value=s3), \
             patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        assert result["headers"]["Access-Control-Allow-Origin"] == "*"
