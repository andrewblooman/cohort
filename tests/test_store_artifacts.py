"""
tests/test_store_artifacts.py

Unit tests for the store_artifacts Lambda handler.
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

store_handler = _load_handler("store_artifacts_handler", "../lambdas/store_artifacts/handler.py")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_ANALYSIS = {
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "reasoning": "Detailed reasoning here explaining why this is a true positive.",
    "threat_summary": "EC2 instance is performing cryptocurrency mining.",
    "indicators_of_compromise": ["DNS queries to pool.minexmr.com"],
    "false_positive_indicators": [],
    "proposed_actions": ["Isolate the instance", "Rotate credentials"],
    "mitre_attack_techniques": ["T1496"],
    "model_id": "anthropic.claude-3-5-sonnet-20240620-v1:0",
    "analysis_timestamp": "2024-01-15T10:30:00+00:00",
    "approval_status": "PENDING_HUMAN_APPROVAL",
    "actions_taken": [],
}

SAMPLE_EVENT = {
    "ticket_number": "INC-004",
    "finding_id": "ghi012",
    "alert_type": "GuardDuty",
    "severity": "HIGH",
    "resource_type": "Instance",
    "resource_id": "i-test1234",
    "account_id": "123456789012",
    "region": "eu-west-1",
    "description": "Cryptocurrency mining detected.",
    "secops_case_id": "CASE-300",
    "enrichment_result": {
        "enrichment": {
            "finding": {"Id": "ghi012"},
            "cloudtrail_events": [],
        }
    },
    "artifacts_result": {
        "artifacts": {
            "s3_keys": ["INC-004/guardduty_finding.json"],
            "vpc_flow_log_count": 0,
            "cloudtrail_log_count": 0,
        }
    },
    "analysis_result": {"analysis": SAMPLE_ANALYSIS},
}


# ---------------------------------------------------------------------------
# put_object tests
# ---------------------------------------------------------------------------

class TestPutObject:
    def test_uploads_bytes_to_s3(self):
        mock_s3 = MagicMock()
        body = b"Hello, world!"

        with patch.object(store_handler, "_s3_client", return_value=mock_s3):
            key = store_handler.put_object("test-bucket", "prefix/file.txt", body, "text/plain")

        assert key == "prefix/file.txt"
        call_kwargs = mock_s3.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "test-bucket"
        assert call_kwargs["Key"] == "prefix/file.txt"
        assert call_kwargs["Body"] == body
        assert call_kwargs["ContentType"] == "text/plain"


# ---------------------------------------------------------------------------
# build_text_recommendation tests
# ---------------------------------------------------------------------------

class TestBuildTextRecommendation:
    def setup_method(self):
        self.incident = {
            "ticket_number": "INC-004",
            "alert_type": "GuardDuty",
            "severity": "HIGH",
            "finding_id": "ghi012",
            "account_id": "123456789012",
            "region": "eu-west-1",
            "resource_type": "Instance",
            "resource_id": "i-test1234",
            "description": "Cryptocurrency mining detected.",
            "secops_case_id": "CASE-300",
        }

    def test_contains_ticket_number(self):
        report = store_handler.build_text_recommendation(self.incident, SAMPLE_ANALYSIS)
        assert "INC-004" in report

    def test_contains_verdict_label(self):
        report = store_handler.build_text_recommendation(self.incident, SAMPLE_ANALYSIS)
        assert "TRUE POSITIVE" in report

    def test_contains_proposed_actions(self):
        report = store_handler.build_text_recommendation(self.incident, SAMPLE_ANALYSIS)
        assert "Isolate the instance" in report
        assert "Rotate credentials" in report

    def test_proposed_actions_awaiting_approval_label(self):
        report = store_handler.build_text_recommendation(self.incident, SAMPLE_ANALYSIS)
        assert "AWAITING ANALYST APPROVAL" in report
        assert "NO AUTOMATED ACTIONS HAVE BEEN TAKEN" in report

    def test_contains_iocs(self):
        report = store_handler.build_text_recommendation(self.incident, SAMPLE_ANALYSIS)
        expected_ioc = "pool.minexmr.com"
        assert expected_ioc in report

    def test_contains_mitre_techniques(self):
        report = store_handler.build_text_recommendation(self.incident, SAMPLE_ANALYSIS)
        assert "T1496" in report

    def test_false_positive_verdict(self):
        analysis = {
            **SAMPLE_ANALYSIS,
            "verdict": "FALSE_POSITIVE",
            "confidence": "HIGH",
            "threat_summary": "This is routine activity.",
            "indicators_of_compromise": [],
            "false_positive_indicators": ["Known scanner IP 10.0.0.1"],
            "proposed_actions": ["No action required"],
        }
        report = store_handler.build_text_recommendation(self.incident, analysis)
        assert "FALSE POSITIVE" in report
        assert "10.0.0.1" in report

    def test_inconclusive_verdict(self):
        analysis = {
            **SAMPLE_ANALYSIS,
            "verdict": "INCONCLUSIVE",
            "confidence": "LOW",
            "threat_summary": "Insufficient evidence.",
            "indicators_of_compromise": [],
            "false_positive_indicators": [],
            "proposed_actions": ["Gather more evidence"],
        }
        report = store_handler.build_text_recommendation(self.incident, analysis)
        assert "INCONCLUSIVE" in report

    def test_handles_no_proposed_actions(self):
        analysis = {**SAMPLE_ANALYSIS, "proposed_actions": []}
        report = store_handler.build_text_recommendation(self.incident, analysis)
        assert "No specific actions proposed" in report


# ---------------------------------------------------------------------------
# lambda_handler integration test
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    def test_stores_three_artifacts(self):
        mock_s3 = MagicMock()

        with (
            patch.object(store_handler, "_s3_client", return_value=mock_s3),
            patch.object(store_handler, "ARTIFACTS_BUCKET", "test-bucket"),
        ):
            result = store_handler.lambda_handler(SAMPLE_EVENT, None)

        assert result["ticket_number"] == "INC-004"
        assert result["s3_bucket"] == "test-bucket"
        assert result["s3_prefix"] == "INC-004/"
        assert len(result["stored_keys"]) == 3
        assert result["recommendation_txt_key"] == "INC-004/ai_recommendation.txt"
        assert result["recommendation_json_key"] == "INC-004/ai_recommendation.json"
        assert result["summary_json_key"] == "INC-004/incident_summary.json"

    def test_verdict_is_propagated(self):
        mock_s3 = MagicMock()

        with (
            patch.object(store_handler, "_s3_client", return_value=mock_s3),
            patch.object(store_handler, "ARTIFACTS_BUCKET", "test-bucket"),
        ):
            result = store_handler.lambda_handler(SAMPLE_EVENT, None)

        assert result["verdict"] == "TRUE_POSITIVE"
        assert result["confidence"] == "HIGH"
        assert result["approval_status"] == "PENDING_HUMAN_APPROVAL"

    def test_raises_when_bucket_not_set(self):
        with patch.object(store_handler, "ARTIFACTS_BUCKET", ""):
            with pytest.raises(ValueError, match="ARTIFACTS_BUCKET"):
                store_handler.lambda_handler(SAMPLE_EVENT, None)

    def test_s3_keys_use_ticket_prefix(self):
        mock_s3 = MagicMock()

        with (
            patch.object(store_handler, "_s3_client", return_value=mock_s3),
            patch.object(store_handler, "ARTIFACTS_BUCKET", "test-bucket"),
        ):
            result = store_handler.lambda_handler(SAMPLE_EVENT, None)

        for key in result["stored_keys"]:
            assert key.startswith("INC-004/"), f"Key '{key}' does not start with ticket prefix"

    def test_handles_flat_analysis_result(self):
        """When analysis_result is not nested under 'analysis' key it should still work."""
        event = {**SAMPLE_EVENT, "analysis_result": SAMPLE_ANALYSIS}
        mock_s3 = MagicMock()

        with (
            patch.object(store_handler, "_s3_client", return_value=mock_s3),
            patch.object(store_handler, "ARTIFACTS_BUCKET", "test-bucket"),
        ):
            result = store_handler.lambda_handler(event, None)

        assert result["verdict"] == "TRUE_POSITIVE"

    def test_stores_valid_json_files(self):
        """Verify that the JSON artifacts uploaded to S3 contain valid JSON."""
        captured_uploads: list[dict] = []

        def capture_put_object(**kwargs):
            captured_uploads.append(kwargs)

        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = capture_put_object

        with (
            patch.object(store_handler, "_s3_client", return_value=mock_s3),
            patch.object(store_handler, "ARTIFACTS_BUCKET", "test-bucket"),
        ):
            store_handler.lambda_handler(SAMPLE_EVENT, None)

        # Find JSON uploads
        json_uploads = [u for u in captured_uploads if u.get("ContentType") == "application/json"]
        assert len(json_uploads) >= 2

        for upload in json_uploads:
            parsed = json.loads(upload["Body"].decode("utf-8"))
            assert isinstance(parsed, dict)
