"""
tests/test_rerun_analysis.py

Unit tests for the rerun_analysis Lambda handler.
"""

from __future__ import annotations

import importlib.util
import json
import os
from datetime import datetime, timezone
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
    "rerun_analysis_handler",
    "../lambdas/rerun_analysis/handler.py",
)

# Set module-level variables that are read at import time (before conftest fixtures run)
_TEST_SFN_ARN = "arn:aws:states:us-east-1:123456789012:stateMachine:cohort-incident-response"
handler.SFN_STATE_MACHINE_ARN = _TEST_SFN_ARN

_NOW = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
_TICKET = "TICKET-999"

_ORIGINAL_INPUT = json.dumps({
    "ticket_number": _TICKET,
    "alert_type": "UnauthorizedAccess:EC2/TorIPCaller",
    "severity": "HIGH",
    "finding_id": "finding-xyz",
    "account_id": "123456789012",
    "region": "us-east-1",
})

_RUNNING_EXEC = {
    "executionArn": "arn:aws:states:us-east-1:123456789012:execution:cohort:running-exec",
    "name": "running-exec",
    "status": "RUNNING",
    "startDate": _NOW,
}

_SUCCEEDED_EXEC = {
    "executionArn": "arn:aws:states:us-east-1:123456789012:execution:cohort:succeeded-exec",
    "name": "succeeded-exec",
    "status": "SUCCEEDED",
    "startDate": _NOW,
    "stopDate": _NOW,
}

_NEW_EXEC_ARN = "arn:aws:states:us-east-1:123456789012:execution:cohort:new-exec-abc123"


def _make_sfn_mock(existing_exec: dict | None = _RUNNING_EXEC, ticket_matches: bool = True):
    sfn = MagicMock()
    executions = [existing_exec] if existing_exec else []
    sfn.list_executions.return_value = {"executions": executions}

    def _describe(executionArn):
        input_data = json.loads(_ORIGINAL_INPUT) if ticket_matches else {"ticket_number": "OTHER"}
        return {
            "executionArn": executionArn,
            "input": json.dumps(input_data),
            "status": existing_exec["status"] if existing_exec else "UNKNOWN",
        }

    sfn.describe_execution.side_effect = _describe
    sfn.stop_execution.return_value = {}
    sfn.start_execution.return_value = {"executionArn": _NEW_EXEC_ARN, "startDate": _NOW}
    return sfn


# ---------------------------------------------------------------------------
# _find_latest_execution
# ---------------------------------------------------------------------------

class TestFindLatestExecution:
    def test_returns_execution_for_matching_ticket(self):
        sfn = _make_sfn_mock(existing_exec=_RUNNING_EXEC)
        arn, status, input_str = handler._find_latest_execution(sfn, _TICKET)
        assert arn == _RUNNING_EXEC["executionArn"]
        assert status == "RUNNING"
        assert json.loads(input_str)["ticket_number"] == _TICKET

    def test_returns_none_for_unmatched_ticket(self):
        sfn = _make_sfn_mock(ticket_matches=False)
        arn, status, input_str = handler._find_latest_execution(sfn, _TICKET)
        assert arn is None
        assert status is None
        assert input_str is None

    def test_returns_none_when_no_executions(self):
        sfn = _make_sfn_mock(existing_exec=None)
        arn, status, input_str = handler._find_latest_execution(sfn, _TICKET)
        assert arn is None

    def test_returns_none_when_arn_not_set(self):
        sfn = _make_sfn_mock()
        original = handler.SFN_STATE_MACHINE_ARN
        handler.SFN_STATE_MACHINE_ARN = ""
        try:
            arn, status, input_str = handler._find_latest_execution(sfn, _TICKET)
            assert arn is None
        finally:
            handler.SFN_STATE_MACHINE_ARN = original

    def test_skips_execution_on_describe_error(self):
        sfn = _make_sfn_mock()
        sfn.describe_execution.side_effect = ClientError(
            {"Error": {"Code": "ExecutionDoesNotExist", "Message": "x"}},
            "DescribeExecution",
        )
        arn, status, input_str = handler._find_latest_execution(sfn, _TICKET)
        assert arn is None


# ---------------------------------------------------------------------------
# lambda_handler
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    def test_aborts_running_and_starts_new(self):
        sfn = _make_sfn_mock(existing_exec=_RUNNING_EXEC)
        with patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        assert result["statusCode"] == 200
        sfn.stop_execution.assert_called_once()
        sfn.start_execution.assert_called_once()
        body = json.loads(result["body"])
        assert body["status"] == "started"
        assert body["aborted_execution"] == _RUNNING_EXEC["executionArn"]
        assert body["execution_arn"] == _NEW_EXEC_ARN

    def test_starts_new_without_aborting_when_succeeded(self):
        sfn = _make_sfn_mock(existing_exec=_SUCCEEDED_EXEC)
        with patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        assert result["statusCode"] == 200
        sfn.stop_execution.assert_not_called()
        sfn.start_execution.assert_called_once()
        body = json.loads(result["body"])
        assert body["aborted_execution"] is None

    def test_uses_original_input_for_new_execution(self):
        sfn = _make_sfn_mock(existing_exec=_SUCCEEDED_EXEC)
        with patch.object(handler, "_sfn_client", return_value=sfn):
            handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        call_kwargs = sfn.start_execution.call_args[1]
        reused_input = json.loads(call_kwargs["input"])
        assert reused_input["ticket_number"] == _TICKET
        assert reused_input["finding_id"] == "finding-xyz"

    def test_returns_400_when_ticket_number_missing(self):
        sfn = _make_sfn_mock()
        with patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler({"pathParameters": {}}, None)
        assert result["statusCode"] == 400

    def test_returns_400_when_path_params_absent(self):
        sfn = _make_sfn_mock()
        with patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler({}, None)
        assert result["statusCode"] == 400

    def test_returns_404_when_no_execution_found(self):
        sfn = _make_sfn_mock(ticket_matches=False)
        with patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        assert result["statusCode"] == 404

    def test_returns_500_when_state_machine_arn_not_set(self):
        sfn = _make_sfn_mock()
        original = handler.SFN_STATE_MACHINE_ARN
        handler.SFN_STATE_MACHINE_ARN = ""
        try:
            with patch.object(handler, "_sfn_client", return_value=sfn):
                result = handler.lambda_handler(
                    {"pathParameters": {"ticket_number": _TICKET}}, None
                )
            assert result["statusCode"] == 500
        finally:
            handler.SFN_STATE_MACHINE_ARN = original

    def test_returns_500_when_start_execution_fails(self):
        sfn = _make_sfn_mock(existing_exec=_SUCCEEDED_EXEC)
        sfn.start_execution.side_effect = ClientError(
            {"Error": {"Code": "ExecutionAlreadyExists", "Message": "x"}},
            "StartExecution",
        )
        with patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        assert result["statusCode"] == 500

    def test_continues_when_abort_fails(self):
        sfn = _make_sfn_mock(existing_exec=_RUNNING_EXEC)
        sfn.stop_execution.side_effect = ClientError(
            {"Error": {"Code": "ExecutionNotFound", "Message": "x"}},
            "StopExecution",
        )
        with patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        # Should still start the new execution even though abort failed
        assert result["statusCode"] == 200
        sfn.start_execution.assert_called_once()

    def test_returns_cors_headers(self):
        sfn = _make_sfn_mock()
        with patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        assert result["headers"]["Access-Control-Allow-Origin"] == "*"

    def test_execution_name_contains_ticket_and_rerun(self):
        sfn = _make_sfn_mock()
        with patch.object(handler, "_sfn_client", return_value=sfn):
            handler.lambda_handler(
                {"pathParameters": {"ticket_number": _TICKET}}, None
            )
        call_kwargs = sfn.start_execution.call_args[1]
        assert "rerun" in call_kwargs["name"]
