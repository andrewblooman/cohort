"""
tests/test_list_investigations.py

Unit tests for the list_investigations Lambda handler.
"""

from __future__ import annotations

import importlib.util
import json
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


def _load_handler(module_name: str, relative_path: str):
    abs_path = os.path.join(os.path.dirname(__file__), relative_path)
    spec = importlib.util.spec_from_file_location(module_name, abs_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


handler = _load_handler(
    "list_investigations_handler",
    "../lambdas/list_investigations/handler.py",
)

# Set module-level variables that are read at import time (before conftest fixtures run)
_TEST_SFN_ARN = "arn:aws:states:us-east-1:123456789012:stateMachine:cohort-incident-response"
handler.SFN_STATE_MACHINE_ARN = _TEST_SFN_ARN

_NOW = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

_EXEC_SUMMARIES = [
    {
        "executionArn": "arn:aws:states:us-east-1:123456789012:execution:cohort:exec-001",
        "name": "exec-001",
        "status": "RUNNING",
        "startDate": _NOW,
        "stopDate": None,
    },
    {
        "executionArn": "arn:aws:states:us-east-1:123456789012:execution:cohort:exec-002",
        "name": "exec-002",
        "status": "SUCCEEDED",
        "startDate": _NOW,
        "stopDate": _NOW,
    },
]

_EXEC_INPUTS = {
    "exec-001": {
        "ticket_number": "TICKET-001",
        "alert_type": "UnauthorizedAccess:EC2/TorIPCaller",
        "severity": "HIGH",
        "finding_id": "finding-abc",
        "account_id": "123456789012",
        "region": "us-east-1",
        "secops_case_id": "case-001",
    },
    "exec-002": {
        "ticket_number": "TICKET-002",
        "alert_type": "Recon:IAMUser/MaliciousIPCaller",
        "severity": "MEDIUM",
        "finding_id": "finding-def",
        "account_id": "123456789012",
        "region": "eu-west-1",
        "secops_case_id": "case-002",
    },
}

_EXEC_OUTPUTS = {
    "exec-002": json.dumps({
        "analysis_result": {
            "analysis": {
                "verdict": "FALSE_POSITIVE",
                "confidence": "HIGH",
            }
        }
    })
}


def _make_sfn_mock():
    sfn = MagicMock()
    sfn.list_executions.return_value = {"executions": _EXEC_SUMMARIES}

    def _describe(executionArn):
        for s in _EXEC_SUMMARIES:
            if s["executionArn"] == executionArn:
                name = s["name"]
                input_key = name
                input_data = _EXEC_INPUTS.get(input_key, {})
                return {
                    "executionArn": executionArn,
                    "input": json.dumps(input_data),
                    "output": _EXEC_OUTPUTS.get(input_key, ""),
                    "status": s["status"],
                }
        raise Exception(f"Unknown ARN: {executionArn}")

    sfn.describe_execution.side_effect = _describe
    return sfn


# ---------------------------------------------------------------------------
# list_investigations() function
# ---------------------------------------------------------------------------

class TestListInvestigationsFunction:
    def test_returns_all_executions(self):
        sfn = _make_sfn_mock()
        results = handler.list_investigations(sfn, limit=20, status_filter=None)
        assert len(results) == 2

    def test_calls_list_executions_with_machine_arn(self):
        sfn = _make_sfn_mock()
        handler.list_investigations(sfn, limit=20, status_filter=None)
        call_kwargs = sfn.list_executions.call_args[1]
        assert call_kwargs["stateMachineArn"] == _TEST_SFN_ARN

    def test_passes_status_filter(self):
        sfn = _make_sfn_mock()
        sfn.list_executions.return_value = {"executions": [_EXEC_SUMMARIES[0]]}
        handler.list_investigations(sfn, limit=10, status_filter="RUNNING")
        call_kwargs = sfn.list_executions.call_args[1]
        assert call_kwargs["statusFilter"] == "RUNNING"

    def test_ticket_number_extracted_from_input(self):
        sfn = _make_sfn_mock()
        results = handler.list_investigations(sfn, limit=20, status_filter=None)
        tickets = {r["ticket_number"] for r in results}
        assert "TICKET-001" in tickets
        assert "TICKET-002" in tickets

    def test_verdict_extracted_from_succeeded_output(self):
        sfn = _make_sfn_mock()
        results = handler.list_investigations(sfn, limit=20, status_filter=None)
        t2 = next(r for r in results if r["ticket_number"] == "TICKET-002")
        assert t2["verdict"] == "FALSE_POSITIVE"
        assert t2["confidence"] == "HIGH"

    def test_verdict_is_none_for_running_execution(self):
        sfn = _make_sfn_mock()
        results = handler.list_investigations(sfn, limit=20, status_filter=None)
        t1 = next(r for r in results if r["ticket_number"] == "TICKET-001")
        assert t1["verdict"] is None

    def test_skips_execution_on_describe_error(self):
        from botocore.exceptions import ClientError
        sfn = _make_sfn_mock()
        sfn.describe_execution.side_effect = ClientError(
            {"Error": {"Code": "ExecutionDoesNotExist", "Message": "x"}},
            "DescribeExecution",
        )
        results = handler.list_investigations(sfn, limit=20, status_filter=None)
        assert results == []

    def test_returns_empty_when_state_machine_arn_not_set(self):
        sfn = _make_sfn_mock()
        original = handler.SFN_STATE_MACHINE_ARN
        handler.SFN_STATE_MACHINE_ARN = ""
        try:
            results = handler.list_investigations(sfn, limit=20, status_filter=None)
            assert results == []
        finally:
            handler.SFN_STATE_MACHINE_ARN = original

# ---------------------------------------------------------------------------
# lambda_handler
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    def test_returns_200_with_investigations(self):
        sfn = _make_sfn_mock()
        with patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler({}, None)
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["count"] == 2
        assert len(body["investigations"]) == 2

    def test_limit_param_is_applied(self):
        sfn = _make_sfn_mock()
        with patch.object(handler, "_sfn_client", return_value=sfn):
            handler.lambda_handler({"queryStringParameters": {"limit": "5"}}, None)
        call_kwargs = sfn.list_executions.call_args[1]
        assert call_kwargs["maxResults"] == 5

    def test_limit_is_capped_at_50(self):
        sfn = _make_sfn_mock()
        with patch.object(handler, "_sfn_client", return_value=sfn):
            handler.lambda_handler({"queryStringParameters": {"limit": "999"}}, None)
        call_kwargs = sfn.list_executions.call_args[1]
        assert call_kwargs["maxResults"] == 50

    def test_invalid_limit_uses_default(self):
        sfn = _make_sfn_mock()
        with patch.object(handler, "_sfn_client", return_value=sfn):
            handler.lambda_handler({"queryStringParameters": {"limit": "abc"}}, None)
        call_kwargs = sfn.list_executions.call_args[1]
        assert call_kwargs["maxResults"] == 20

    def test_returns_cors_headers(self):
        sfn = _make_sfn_mock()
        with patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler({}, None)
        assert result["headers"]["Access-Control-Allow-Origin"] == "*"

    def test_returns_500_on_sfn_error(self):
        from botocore.exceptions import ClientError
        sfn = MagicMock()
        sfn.list_executions.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "x"}},
            "ListExecutions",
        )
        with patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler({}, None)
        assert result["statusCode"] == 500

    def test_handles_no_query_string_parameters(self):
        sfn = _make_sfn_mock()
        with patch.object(handler, "_sfn_client", return_value=sfn):
            result = handler.lambda_handler({"queryStringParameters": None}, None)
        assert result["statusCode"] == 200
