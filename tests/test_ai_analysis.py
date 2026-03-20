"""
tests/test_ai_analysis.py

Unit tests for the ai_analysis Lambda handler.
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

ai_handler = _load_handler("ai_analysis_handler", "../lambdas/ai_analysis/handler.py")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_EVENT = {
    "ticket_number": "INC-003",
    "finding_id": "def789",
    "alert_type": "GuardDuty",
    "severity": "HIGH",
    "resource_type": "Instance",
    "resource_id": "i-0abcdef123",
    "account_id": "123456789012",
    "region": "us-east-1",
    "description": "Cryptocurrency mining activity detected.",
    "secops_case_id": "CASE-200",
    "enrichment_result": {
        "enrichment": {
            "finding": {
                "Id": "def789",
                "Type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                "Severity": {"Score": 8.0},
            },
            "cloudtrail_events": [],
            "ec2_metadata": {"InstanceId": "i-0abcdef123", "InstanceType": "c5.4xlarge"},
            "iam_context": {},
        }
    },
    "artifacts_result": {
        "artifacts": {
            "s3_keys": ["INC-003/guardduty_finding.json"],
            "vpc_flow_log_count": 10,
            "cloudtrail_log_count": 5,
        }
    },
}

VALID_BEDROCK_RESPONSE = json.dumps({
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "reasoning": "The GuardDuty finding indicates that the EC2 instance is communicating with known bitcoin mining pools. The instance type c5.4xlarge is unusually large for a typical workload. CloudTrail logs show no legitimate deployment of a mining application. The DNS queries to known cryptocurrency mining endpoints confirm malicious activity. This is consistent with a compromised EC2 instance being used for unauthorized cryptocurrency mining. The evidence strongly supports this being a true positive threat.",
    "threat_summary": "EC2 instance is performing unauthorized cryptocurrency mining.",
    "indicators_of_compromise": ["DNS queries to pool.minexmr.com", "High CPU utilization"],
    "false_positive_indicators": [],
    "recommendations": [
        "Isolate the EC2 instance immediately",
        "Rotate any IAM credentials associated with the instance profile",
        "Review how the instance was compromised",
    ],
    "mitre_attack_techniques": ["T1496"],
})


# ---------------------------------------------------------------------------
# invoke_bedrock tests
# ---------------------------------------------------------------------------

class TestInvokeBedrock:
    def test_returns_text_from_model(self):
        mock_client = MagicMock()
        mock_response_body = MagicMock()
        mock_response_body.read.return_value = json.dumps({
            "content": [{"text": "Hello world"}]
        }).encode()
        mock_client.invoke_model.return_value = {"body": mock_response_body}

        with patch.object(ai_handler, "_bedrock_client", return_value=mock_client):
            result = ai_handler.invoke_bedrock("test prompt")

        assert result == "Hello world"

    def test_raises_on_client_error(self):
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
            "InvokeModel",
        )

        with patch.object(ai_handler, "_bedrock_client", return_value=mock_client):
            with pytest.raises(ClientError):
                ai_handler.invoke_bedrock("test prompt")


# ---------------------------------------------------------------------------
# invoke_agentcore tests
# ---------------------------------------------------------------------------

class TestInvokeAgentcore:
    def _make_mock_chunk(self, text: str) -> dict:
        return {"chunk": {"bytes": text.encode("utf-8")}}

    def test_assembles_chunks_into_single_string(self):
        mock_client = MagicMock()
        mock_client.invoke_agent.return_value = {
            "completion": [
                self._make_mock_chunk('{"verdict": "TRUE_POSITIVE"'),
                self._make_mock_chunk(', "confidence": "HIGH"}'),
            ]
        }

        with patch.object(ai_handler, "_agent_runtime_client", return_value=mock_client):
            with patch.object(ai_handler, "AGENTCORE_AGENT_RUNTIME_ARN", "arn:aws:bedrockagentcore:us-east-1:123456789012:agent-runtime/test"):
                result = ai_handler.invoke_agentcore("prompt", session_id="INC-001")

        assert result == '{"verdict": "TRUE_POSITIVE", "confidence": "HIGH"}'

    def test_passes_memory_store_id_when_configured(self):
        mock_client = MagicMock()
        mock_client.invoke_agent.return_value = {"completion": []}

        with patch.object(ai_handler, "_agent_runtime_client", return_value=mock_client):
            with patch.object(ai_handler, "AGENTCORE_AGENT_RUNTIME_ARN", "arn:aws:bedrockagentcore:us-east-1:123456789012:agent-runtime/test"):
                with patch.object(ai_handler, "AGENTCORE_MEMORY_STORE_ID", "mem-abc123"):
                    ai_handler.invoke_agentcore("prompt", session_id="INC-002")

        call_kwargs = mock_client.invoke_agent.call_args[1]
        assert call_kwargs["memoryId"] == "mem-abc123"
        assert call_kwargs["sessionId"] == "INC-002"

    def test_omits_memory_id_when_not_configured(self):
        mock_client = MagicMock()
        mock_client.invoke_agent.return_value = {"completion": []}

        with patch.object(ai_handler, "_agent_runtime_client", return_value=mock_client):
            with patch.object(ai_handler, "AGENTCORE_AGENT_RUNTIME_ARN", "arn:aws:bedrockagentcore:us-east-1:123456789012:agent-runtime/test"):
                with patch.object(ai_handler, "AGENTCORE_MEMORY_STORE_ID", ""):
                    ai_handler.invoke_agentcore("prompt", session_id="INC-003")

        call_kwargs = mock_client.invoke_agent.call_args[1]
        assert "memoryId" not in call_kwargs

    def test_raises_on_client_error(self):
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.invoke_agent.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Agent not found"}},
            "InvokeAgent",
        )

        with patch.object(ai_handler, "_agent_runtime_client", return_value=mock_client):
            with patch.object(ai_handler, "AGENTCORE_AGENT_RUNTIME_ARN", "arn:aws:bedrockagentcore:us-east-1:123456789012:agent-runtime/test"):
                with pytest.raises(ClientError):
                    ai_handler.invoke_agentcore("prompt", session_id="INC-004")

    def test_handles_empty_completion_stream(self):
        mock_client = MagicMock()
        mock_client.invoke_agent.return_value = {"completion": []}

        with patch.object(ai_handler, "_agent_runtime_client", return_value=mock_client):
            with patch.object(ai_handler, "AGENTCORE_AGENT_RUNTIME_ARN", "arn:aws:bedrockagentcore:us-east-1:123456789012:agent-runtime/test"):
                result = ai_handler.invoke_agentcore("prompt", session_id="INC-005")

        assert result == ""


# ---------------------------------------------------------------------------
# build_analysis_prompt tests
# ---------------------------------------------------------------------------

class TestBuildAnalysisPrompt:
    def test_contains_ticket_number(self):
        prompt = ai_handler.build_analysis_prompt(SAMPLE_EVENT)
        assert "INC-003" in prompt

    def test_contains_finding_id(self):
        prompt = ai_handler.build_analysis_prompt(SAMPLE_EVENT)
        assert "def789" in prompt

    def test_contains_verdict_instructions(self):
        prompt = ai_handler.build_analysis_prompt(SAMPLE_EVENT)
        assert "TRUE_POSITIVE" in prompt
        assert "FALSE_POSITIVE" in prompt
        assert "INCONCLUSIVE" in prompt

    def test_contains_resource_info(self):
        prompt = ai_handler.build_analysis_prompt(SAMPLE_EVENT)
        assert "i-0abcdef123" in prompt
        assert "c5.4xlarge" in prompt

    def test_truncates_large_finding(self):
        large_event = {
            **SAMPLE_EVENT,
            "enrichment_result": {
                "enrichment": {
                    "finding": {"data": "x" * 10000},
                    "cloudtrail_events": [],
                    "ec2_metadata": {},
                    "iam_context": {},
                }
            },
        }
        # Should not raise
        prompt = ai_handler.build_analysis_prompt(large_event)
        assert "INC-003" in prompt


# ---------------------------------------------------------------------------
# parse_bedrock_response tests
# ---------------------------------------------------------------------------

class TestParseBedrockResponse:
    def test_parses_valid_json_response(self):
        result = ai_handler.parse_bedrock_response(VALID_BEDROCK_RESPONSE)
        assert result["verdict"] == "TRUE_POSITIVE"
        assert result["confidence"] == "HIGH"
        assert len(result["recommendations"]) == 3

    def test_parses_json_in_code_block(self):
        response = f"Here is my analysis:\n```json\n{VALID_BEDROCK_RESPONSE}\n```"
        result = ai_handler.parse_bedrock_response(response)
        assert result["verdict"] == "TRUE_POSITIVE"

    def test_normalises_lowercase_verdict(self):
        response = json.dumps({
            "verdict": "true_positive",
            "confidence": "high",
            "reasoning": "detailed reasoning here",
            "threat_summary": "summary",
            "indicators_of_compromise": [],
            "false_positive_indicators": [],
            "recommendations": [],
            "mitre_attack_techniques": [],
        })
        result = ai_handler.parse_bedrock_response(response)
        assert result["verdict"] == "TRUE_POSITIVE"
        assert result["confidence"] == "HIGH"

    def test_defaults_invalid_verdict_to_inconclusive(self):
        response = json.dumps({
            "verdict": "MAYBE",
            "confidence": "HIGH",
            "reasoning": "test",
            "threat_summary": "test",
            "indicators_of_compromise": [],
            "false_positive_indicators": [],
            "recommendations": [],
            "mitre_attack_techniques": [],
        })
        result = ai_handler.parse_bedrock_response(response)
        assert result["verdict"] == "INCONCLUSIVE"

    def test_returns_fallback_on_unparseable_response(self):
        result = ai_handler.parse_bedrock_response("This is not JSON at all.")
        assert result["verdict"] == "INCONCLUSIVE"
        assert result["confidence"] == "LOW"

    def test_ensures_list_fields_are_lists(self):
        response = json.dumps({
            "verdict": "FALSE_POSITIVE",
            "confidence": "MEDIUM",
            "reasoning": "Looks benign.",
            "threat_summary": "Summary.",
            "indicators_of_compromise": "none",  # wrong type
            "false_positive_indicators": "none",  # wrong type
            "recommendations": "review logs",  # wrong type
            "mitre_attack_techniques": None,  # null
        })
        result = ai_handler.parse_bedrock_response(response)
        for field in ("indicators_of_compromise", "false_positive_indicators", "recommendations", "mitre_attack_techniques"):
            assert isinstance(result[field], list), f"{field} should be a list"

    def test_handles_false_positive_verdict(self):
        response = json.dumps({
            "verdict": "FALSE_POSITIVE",
            "confidence": "HIGH",
            "reasoning": "This is routine security scanning.",
            "threat_summary": "Benign activity.",
            "indicators_of_compromise": [],
            "false_positive_indicators": ["Known security scanner IP"],
            "recommendations": ["No action required"],
            "mitre_attack_techniques": [],
        })
        result = ai_handler.parse_bedrock_response(response)
        assert result["verdict"] == "FALSE_POSITIVE"
        assert len(result["false_positive_indicators"]) == 1

    def test_handles_inconclusive_verdict(self):
        response = json.dumps({
            "verdict": "INCONCLUSIVE",
            "confidence": "LOW",
            "reasoning": "Insufficient evidence.",
            "threat_summary": "Cannot determine.",
            "indicators_of_compromise": [],
            "false_positive_indicators": [],
            "recommendations": ["Gather more logs"],
            "mitre_attack_techniques": [],
        })
        result = ai_handler.parse_bedrock_response(response)
        assert result["verdict"] == "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# lambda_handler integration test
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    def test_routes_to_agentcore_when_arn_is_set(self):
        """When AGENTCORE_AGENT_RUNTIME_ARN is configured, lambda_handler should
        call invoke_agentcore instead of invoke_bedrock."""
        mock_agent_client = MagicMock()
        mock_agent_client.invoke_agent.return_value = {
            "completion": [{"chunk": {"bytes": VALID_BEDROCK_RESPONSE.encode()}}]
        }

        with patch.object(ai_handler, "AGENTCORE_AGENT_RUNTIME_ARN", "arn:aws:bedrockagentcore:us-east-1:123456789012:agent-runtime/test"):
            with patch.object(ai_handler, "_agent_runtime_client", return_value=mock_agent_client):
                result = ai_handler.lambda_handler(SAMPLE_EVENT, None)

        assert result["verdict"] == "TRUE_POSITIVE"
        assert result["ticket_number"] == "INC-003"
        mock_agent_client.invoke_agent.assert_called_once()
        call_kwargs = mock_agent_client.invoke_agent.call_args[1]
        assert call_kwargs["sessionId"] == "INC-003"

    def test_returns_analysis_with_metadata(self):
        mock_client = MagicMock()
        mock_body = MagicMock()
        mock_body.read.return_value = json.dumps({
            "content": [{"text": VALID_BEDROCK_RESPONSE}]
        }).encode()
        mock_client.invoke_model.return_value = {"body": mock_body}

        with patch.object(ai_handler, "_bedrock_client", return_value=mock_client):
            result = ai_handler.lambda_handler(SAMPLE_EVENT, None)

        assert result["verdict"] == "TRUE_POSITIVE"
        assert result["ticket_number"] == "INC-003"
        assert result["finding_id"] == "def789"
        assert "model_id" in result
        assert "analysis_timestamp" in result

    def test_returns_inconclusive_on_bedrock_error(self):
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            "InvokeModel",
        )

        with patch.object(ai_handler, "_bedrock_client", return_value=mock_client):
            with pytest.raises(ClientError):
                ai_handler.lambda_handler(SAMPLE_EVENT, None)
