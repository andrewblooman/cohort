"""
tests/test_generate_incident_id.py

Unit tests for the generate_incident_id Lambda handler.
"""

from __future__ import annotations

import importlib.util
import os
from unittest.mock import MagicMock, patch

import pytest


def _load_handler(module_name: str, relative_path: str):
    """Load a Lambda handler module from a relative path without polluting sys.modules."""
    abs_path = os.path.join(os.path.dirname(__file__), relative_path)
    spec = importlib.util.spec_from_file_location(module_name, abs_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


handler = _load_handler(
    "generate_incident_id_handler",
    "../lambdas/generate_incident_id/handler.py",
)


# ---------------------------------------------------------------------------
# Sample GuardDuty finding (EventBridge detail section)
# ---------------------------------------------------------------------------

SAMPLE_FINDING = {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "type": "UnauthorizedAccess:EC2/TorIPCaller",
    "severity": 7.8,
    "description": "EC2 instance i-0abc123 established outbound connections via Tor.",
    "accountId": "123456789012",
    "region": "us-east-1",
    "resource": {
        "resourceType": "Instance",
        "instanceDetails": {"instanceId": "i-0abc123"},
    },
}

SAMPLE_EVENT = {
    "finding_detail": SAMPLE_FINDING,
    "account_id": "123456789012",
    "event_region": "us-east-1",
}


# ---------------------------------------------------------------------------
# Helper: mock DynamoDB UpdateItem to return a specific counter value
# ---------------------------------------------------------------------------

def _mock_ddb(counter_value: int):
    mock_client = MagicMock()
    mock_client.update_item.return_value = {
        "Attributes": {"current_value": {"N": str(counter_value)}}
    }
    return mock_client


# ---------------------------------------------------------------------------
# TestGenerateTicketNumber
# ---------------------------------------------------------------------------

class TestGenerateTicketNumber:
    def test_formats_with_zero_padding(self):
        with patch.object(handler, "INCIDENT_COUNTER_TABLE", "test-counter-table"):
            with patch.object(handler, "_get_dynamodb_client", return_value=_mock_ddb(1)):
                result = handler.generate_ticket_number()
        assert result == "inc-0001"

    def test_formats_double_digit(self):
        with patch.object(handler, "INCIDENT_COUNTER_TABLE", "test-counter-table"):
            with patch.object(handler, "_get_dynamodb_client", return_value=_mock_ddb(42)):
                result = handler.generate_ticket_number()
        assert result == "inc-0042"

    def test_formats_four_digit(self):
        with patch.object(handler, "INCIDENT_COUNTER_TABLE", "test-counter-table"):
            with patch.object(handler, "_get_dynamodb_client", return_value=_mock_ddb(9999)):
                result = handler.generate_ticket_number()
        assert result == "inc-9999"

    def test_expands_beyond_four_digits(self):
        """Counter should expand gracefully beyond 9999."""
        with patch.object(handler, "INCIDENT_COUNTER_TABLE", "test-counter-table"):
            with patch.object(handler, "_get_dynamodb_client", return_value=_mock_ddb(10000)):
                result = handler.generate_ticket_number()
        assert result == "inc-10000"

    def test_raises_when_table_not_configured(self, monkeypatch):
        monkeypatch.setenv("INCIDENT_COUNTER_TABLE", "")
        # Reload module to pick up the cleared env var
        reloaded = _load_handler(
            "generate_incident_id_handler_empty",
            "../lambdas/generate_incident_id/handler.py",
        )
        with pytest.raises(RuntimeError, match="INCIDENT_COUNTER_TABLE"):
            reloaded.generate_ticket_number()

    def test_raises_on_dynamodb_error(self):
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.update_item.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Table not found"}},
            "UpdateItem",
        )
        with patch.object(handler, "INCIDENT_COUNTER_TABLE", "test-counter-table"):
            with patch.object(handler, "_get_dynamodb_client", return_value=mock_client):
                with pytest.raises(RuntimeError, match="Failed to generate incident ID"):
                    handler.generate_ticket_number()

    def test_calls_add_expression(self):
        mock_client = _mock_ddb(1)
        with patch.object(handler, "INCIDENT_COUNTER_TABLE", "test-counter-table"):
            with patch.object(handler, "_get_dynamodb_client", return_value=mock_client):
                handler.generate_ticket_number()
        call_kwargs = mock_client.update_item.call_args[1]
        assert "ADD current_value :inc" in call_kwargs["UpdateExpression"]
        assert call_kwargs["ReturnValues"] == "UPDATED_NEW"


# ---------------------------------------------------------------------------
# TestMapSeverity
# ---------------------------------------------------------------------------

class TestMapSeverity:
    def test_high_at_7(self):
        assert handler.map_severity(7.0) == "HIGH"

    def test_high_at_10(self):
        assert handler.map_severity(10.0) == "HIGH"

    def test_high_at_8_point_5(self):
        assert handler.map_severity(8.5) == "HIGH"

    def test_medium_at_4(self):
        assert handler.map_severity(4.0) == "MEDIUM"

    def test_medium_at_6_point_9(self):
        assert handler.map_severity(6.9) == "MEDIUM"

    def test_low_at_3_point_9(self):
        assert handler.map_severity(3.9) == "LOW"

    def test_low_at_0_point_1(self):
        assert handler.map_severity(0.1) == "LOW"

    def test_low_at_zero(self):
        assert handler.map_severity(0) == "LOW"


# ---------------------------------------------------------------------------
# TestExtractResourceId
# ---------------------------------------------------------------------------

class TestExtractResourceId:
    def test_extracts_instance_id(self):
        resource = {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": "i-0abc123"},
        }
        assert handler.extract_resource_id(resource) == "i-0abc123"

    def test_extracts_access_key_id(self):
        resource = {
            "resourceType": "AccessKey",
            "accessKeyDetails": {"accessKeyId": "AKIAIOSFODNN7EXAMPLE"},
        }
        assert handler.extract_resource_id(resource) == "AKIAIOSFODNN7EXAMPLE"

    def test_extracts_s3_bucket_name(self):
        resource = {
            "resourceType": "S3Bucket",
            "s3BucketDetails": [{"name": "my-sensitive-bucket"}],
        }
        assert handler.extract_resource_id(resource) == "my-sensitive-bucket"

    def test_extracts_eks_cluster_name(self):
        resource = {
            "resourceType": "EKSCluster",
            "eksClusterDetails": {"name": "production-cluster"},
        }
        assert handler.extract_resource_id(resource) == "production-cluster"

    def test_extracts_rds_instance_id(self):
        resource = {
            "resourceType": "RDSDBInstance",
            "rdsDbInstanceDetails": {"dbInstanceIdentifier": "prod-mysql"},
        }
        assert handler.extract_resource_id(resource) == "prod-mysql"

    def test_extracts_container_name(self):
        resource = {
            "resourceType": "Container",
            "containerDetails": {"name": "web-app"},
        }
        assert handler.extract_resource_id(resource) == "web-app"

    def test_extracts_lambda_function_name(self):
        resource = {
            "resourceType": "Lambda",
            "lambdaDetails": {"functionName": "my-function"},
        }
        assert handler.extract_resource_id(resource) == "my-function"

    def test_fallback_to_resource_type(self):
        resource = {"resourceType": "UnknownType"}
        assert handler.extract_resource_id(resource) == "UnknownType"

    def test_empty_resource_returns_unknown(self):
        assert handler.extract_resource_id({}) == "unknown"

    def test_empty_instance_details_falls_back_to_resource_type(self):
        resource = {"resourceType": "Instance", "instanceDetails": {}}
        assert handler.extract_resource_id(resource) == "Instance"


# ---------------------------------------------------------------------------
# TestNormaliseFinding
# ---------------------------------------------------------------------------

class TestNormaliseFinding:
    def test_extracts_all_fields(self):
        result = handler.normalise_finding(SAMPLE_FINDING, "123456789012", "us-east-1")
        assert result["finding_id"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert result["alert_type"] == "UnauthorizedAccess:EC2/TorIPCaller"
        assert result["severity"] == "HIGH"
        assert result["description"] == "EC2 instance i-0abc123 established outbound connections via Tor."
        assert result["account_id"] == "123456789012"
        assert result["region"] == "us-east-1"
        assert result["resource_type"] == "Instance"
        assert result["resource_id"] == "i-0abc123"

    def test_uses_finding_account_over_envelope(self):
        finding = {**SAMPLE_FINDING, "accountId": "999988887777"}
        result = handler.normalise_finding(finding, "123456789012", "us-east-1")
        assert result["account_id"] == "999988887777"

    def test_falls_back_to_envelope_account_when_finding_has_none(self):
        finding = {**SAMPLE_FINDING}
        del finding["accountId"]
        result = handler.normalise_finding(finding, "fallback-account", "us-east-1")
        assert result["account_id"] == "fallback-account"

    def test_maps_medium_severity(self):
        finding = {**SAMPLE_FINDING, "severity": 5.0}
        result = handler.normalise_finding(finding, "", "")
        assert result["severity"] == "MEDIUM"

    def test_maps_low_severity(self):
        finding = {**SAMPLE_FINDING, "severity": 2.5}
        result = handler.normalise_finding(finding, "", "")
        assert result["severity"] == "LOW"

    def test_handles_string_severity(self):
        finding = {**SAMPLE_FINDING, "severity": "8.0"}
        result = handler.normalise_finding(finding, "", "")
        assert result["severity"] == "HIGH"

    def test_handles_missing_severity(self):
        finding = {k: v for k, v in SAMPLE_FINDING.items() if k != "severity"}
        result = handler.normalise_finding(finding, "", "")
        assert result["severity"] == "LOW"


# ---------------------------------------------------------------------------
# TestLambdaHandler
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    def test_returns_ticket_number(self):
        with patch.object(handler, "INCIDENT_COUNTER_TABLE", "test-counter-table"):
            with patch.object(handler, "_get_dynamodb_client", return_value=_mock_ddb(1)):
                result = handler.lambda_handler(SAMPLE_EVENT, None)
        assert result["ticket_number"] == "inc-0001"

    def test_returns_normalised_fields(self):
        with patch.object(handler, "INCIDENT_COUNTER_TABLE", "test-counter-table"):
            with patch.object(handler, "_get_dynamodb_client", return_value=_mock_ddb(5)):
                result = handler.lambda_handler(SAMPLE_EVENT, None)
        assert result["finding_id"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert result["alert_type"] == "UnauthorizedAccess:EC2/TorIPCaller"
        assert result["severity"] == "HIGH"
        assert result["resource_type"] == "Instance"
        assert result["resource_id"] == "i-0abc123"
        assert result["account_id"] == "123456789012"
        assert result["region"] == "us-east-1"

    def test_includes_generated_at_timestamp(self):
        with patch.object(handler, "INCIDENT_COUNTER_TABLE", "test-counter-table"):
            with patch.object(handler, "_get_dynamodb_client", return_value=_mock_ddb(1)):
                result = handler.lambda_handler(SAMPLE_EVENT, None)
        assert "generated_at" in result

    def test_sequential_calls_increment_counter(self):
        mock_client = MagicMock()
        call_count = [0]

        def side_effect(**kwargs):
            call_count[0] += 1
            return {"Attributes": {"current_value": {"N": str(call_count[0])}}}

        mock_client.update_item.side_effect = side_effect

        with patch.object(handler, "INCIDENT_COUNTER_TABLE", "test-counter-table"):
            with patch.object(handler, "_get_dynamodb_client", return_value=mock_client):
                r1 = handler.lambda_handler(SAMPLE_EVENT, None)
                r2 = handler.lambda_handler(SAMPLE_EVENT, None)

        assert r1["ticket_number"] == "inc-0001"
        assert r2["ticket_number"] == "inc-0002"

    def test_handles_empty_finding_gracefully(self):
        """Lambda should not crash on minimal/empty finding detail."""
        with patch.object(handler, "INCIDENT_COUNTER_TABLE", "test-counter-table"):
            with patch.object(handler, "_get_dynamodb_client", return_value=_mock_ddb(1)):
                result = handler.lambda_handler(
                    {"finding_detail": {}, "account_id": "123", "event_region": "us-east-1"},
                    None,
                )
        assert "ticket_number" in result
        assert result["severity"] == "LOW"
