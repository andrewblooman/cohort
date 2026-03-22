"""
tests/test_execute_actions.py

Unit tests for the execute_actions Lambda handler.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, call, patch

import pytest
import importlib.util
import os


def _load_handler(module_name: str, relative_path: str):
    abs_path = os.path.join(os.path.dirname(__file__), relative_path)
    spec = importlib.util.spec_from_file_location(module_name, abs_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


exec_handler = _load_handler("execute_actions_handler", "../lambdas/execute_actions/handler.py")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_EVENT = {
    "ticket_number": "INC-010",
    "secops_case_id": "CASE-500",
    "approval_result": {
        "analyst_id": "analyst@company.com",
        "approval_notes": "Confirmed",
        "approval_timestamp": "2024-01-15T11:00:00+00:00",
        "approved_actions": [
            {
                "action_id": "ec2-isolate-1",
                "type": "isolate_ec2_instance",
                "parameters": {"instance_id": "i-0abc123", "region": "us-east-1"},
            }
        ],
    },
}


# ---------------------------------------------------------------------------
# Individual action tests
# ---------------------------------------------------------------------------

class TestIsolateEC2Instance:
    def test_places_instance_in_quarantine_sg(self):
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"VpcId": "vpc-123", "BlockDeviceMappings": []}]}]
        }
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        mock_ec2.create_security_group.return_value = {"GroupId": "sg-quarantine"}

        with patch.object(exec_handler, "_ec2", return_value=mock_ec2):
            result = exec_handler.isolate_ec2_instance(
                {"instance_id": "i-0abc123", "region": "us-east-1"}
            )

        assert result["instance_id"] == "i-0abc123"
        assert result["quarantine_sg_id"] == "sg-quarantine"
        mock_ec2.modify_instance_attribute.assert_called_once_with(
            InstanceId="i-0abc123", Groups=["sg-quarantine"]
        )

    def test_reuses_existing_quarantine_sg(self):
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"VpcId": "vpc-123", "BlockDeviceMappings": []}]}]
        }
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-existing-quarantine"}]
        }

        with patch.object(exec_handler, "_ec2", return_value=mock_ec2):
            result = exec_handler.isolate_ec2_instance(
                {"instance_id": "i-0abc123", "region": "us-east-1"}
            )

        assert result["quarantine_sg_id"] == "sg-existing-quarantine"
        mock_ec2.create_security_group.assert_not_called()


class TestStopEC2Instance:
    def test_stops_instance(self):
        mock_ec2 = MagicMock()
        mock_ec2.stop_instances.return_value = {
            "StoppingInstances": [{"CurrentState": {"Name": "stopping"}}]
        }

        with patch.object(exec_handler, "_ec2", return_value=mock_ec2):
            result = exec_handler.stop_ec2_instance({"instance_id": "i-0abc123"})

        assert result["instance_id"] == "i-0abc123"
        assert result["current_state"] == "stopping"
        mock_ec2.stop_instances.assert_called_once_with(InstanceIds=["i-0abc123"])


class TestSnapshotEC2Instance:
    def test_creates_snapshot_per_volume(self):
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "BlockDeviceMappings": [
                                {"Ebs": {"VolumeId": "vol-111"}},
                                {"Ebs": {"VolumeId": "vol-222"}},
                            ]
                        }
                    ]
                }
            ]
        }
        mock_ec2.create_snapshot.side_effect = [
            {"SnapshotId": "snap-aaa"},
            {"SnapshotId": "snap-bbb"},
        ]

        with patch.object(exec_handler, "_ec2", return_value=mock_ec2):
            result = exec_handler.snapshot_ec2_instance({"instance_id": "i-0abc123"})

        assert result["snapshot_ids"] == ["snap-aaa", "snap-bbb"]
        assert mock_ec2.create_snapshot.call_count == 2


class TestDeactivateIAMAccessKey:
    def test_deactivates_key(self):
        mock_iam = MagicMock()

        with patch.object(exec_handler, "_iam", return_value=mock_iam):
            result = exec_handler.deactivate_iam_access_key(
                {"user_name": "compromised-user", "access_key_id": "AKIAIOSFODNN7EXAMPLE"}
            )

        assert result["new_status"] == "Inactive"
        mock_iam.update_access_key.assert_called_once_with(
            UserName="compromised-user",
            AccessKeyId="AKIAIOSFODNN7EXAMPLE",
            Status="Inactive",
        )


class TestRevokeIAMRoleSessions:
    def test_attaches_deny_policy(self):
        mock_iam = MagicMock()

        with patch.object(exec_handler, "_iam", return_value=mock_iam):
            result = exec_handler.revoke_iam_role_sessions({"role_name": "compromised-role"})

        assert result["role_name"] == "compromised-role"
        assert result["policy_name"] == exec_handler._REVOKE_POLICY_NAME
        call_kwargs = mock_iam.put_role_policy.call_args[1]
        policy = json.loads(call_kwargs["PolicyDocument"])
        assert policy["Statement"][0]["Effect"] == "Deny"
        assert "DateLessThan" in policy["Statement"][0]["Condition"]


class TestArchiveGuardDutyFinding:
    def test_archives_finding(self):
        mock_gd = MagicMock()

        with patch.object(exec_handler, "_guardduty", return_value=mock_gd):
            result = exec_handler.archive_guardduty_finding(
                {"finding_id": "abc123", "detector_id": "det456", "region": "us-east-1"}
            )

        assert result["status"] == "archived"
        mock_gd.archive_findings.assert_called_once_with(
            DetectorId="det456", FindingIds=["abc123"]
        )


class TestBlockS3PublicAccess:
    def test_enables_all_four_settings(self):
        mock_s3 = MagicMock()

        with patch.object(exec_handler, "_s3", return_value=mock_s3):
            result = exec_handler.block_s3_public_access({"bucket_name": "my-bucket"})

        assert result["block_public_access_enabled"] is True
        call_kwargs = mock_s3.put_public_access_block.call_args[1]
        config = call_kwargs["PublicAccessBlockConfiguration"]
        assert all(config.values()), "All four block settings should be True"


# ---------------------------------------------------------------------------
# execute_action router tests
# ---------------------------------------------------------------------------

class TestExecuteAction:
    def test_returns_succeeded_on_success(self):
        action = {
            "action_id": "test-1",
            "type": "stop_ec2_instance",
            "parameters": {"instance_id": "i-0abc123"},
        }
        mock_ec2 = MagicMock()
        mock_ec2.stop_instances.return_value = {
            "StoppingInstances": [{"CurrentState": {"Name": "stopping"}}]
        }

        with patch.object(exec_handler, "_ec2", return_value=mock_ec2):
            result = exec_handler.execute_action(action)

        assert result["status"] == "succeeded"
        assert result["action_id"] == "test-1"

    def test_returns_failed_on_client_error(self):
        from botocore.exceptions import ClientError

        action = {
            "action_id": "test-2",
            "type": "stop_ec2_instance",
            "parameters": {"instance_id": "i-0nonexistent"},
        }
        mock_ec2 = MagicMock()
        mock_ec2.stop_instances.side_effect = ClientError(
            {"Error": {"Code": "InvalidInstanceID.NotFound", "Message": "Instance not found"}},
            "StopInstances",
        )

        with patch.object(exec_handler, "_ec2", return_value=mock_ec2):
            result = exec_handler.execute_action(action)

        assert result["status"] == "failed"
        assert "InvalidInstanceID" in result["error"]

    def test_returns_skipped_for_unknown_type(self):
        action = {"action_id": "test-3", "type": "unknown_action", "parameters": {}}
        result = exec_handler.execute_action(action)
        assert result["status"] == "skipped"
        assert "Unsupported" in result["error"]


# ---------------------------------------------------------------------------
# lambda_handler integration tests
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    def test_executes_all_approved_actions(self):
        event = {
            **SAMPLE_EVENT,
            "approval_result": {
                **SAMPLE_EVENT["approval_result"],
                "approved_actions": [
                    {
                        "action_id": "stop-1",
                        "type": "stop_ec2_instance",
                        "parameters": {"instance_id": "i-0abc123"},
                    },
                    {
                        "action_id": "gd-1",
                        "type": "archive_guardduty_finding",
                        "parameters": {"finding_id": "f1", "detector_id": "d1"},
                    },
                ],
            },
        }
        mock_ec2 = MagicMock()
        mock_ec2.stop_instances.return_value = {
            "StoppingInstances": [{"CurrentState": {"Name": "stopping"}}]
        }
        mock_gd = MagicMock()

        with (
            patch.object(exec_handler, "_ec2", return_value=mock_ec2),
            patch.object(exec_handler, "_guardduty", return_value=mock_gd),
        ):
            result = exec_handler.lambda_handler(event, None)

        assert result["ticket_number"] == "INC-010"
        assert result["total_actions"] == 2
        assert result["succeeded"] == 2
        assert result["failed"] == 0

    def test_counts_failures_separately(self):
        from botocore.exceptions import ClientError

        event = {
            **SAMPLE_EVENT,
            "approval_result": {
                **SAMPLE_EVENT["approval_result"],
                "approved_actions": [
                    {
                        "action_id": "fail-1",
                        "type": "stop_ec2_instance",
                        "parameters": {"instance_id": "i-bad"},
                    }
                ],
            },
        }
        mock_ec2 = MagicMock()
        mock_ec2.stop_instances.side_effect = ClientError(
            {"Error": {"Code": "InvalidInstanceID.NotFound", "Message": "Not found"}},
            "StopInstances",
        )

        with patch.object(exec_handler, "_ec2", return_value=mock_ec2):
            result = exec_handler.lambda_handler(event, None)

        assert result["failed"] == 1
        assert result["succeeded"] == 0

    def test_empty_approved_actions_returns_zero_counts(self):
        event = {
            **SAMPLE_EVENT,
            "approval_result": {**SAMPLE_EVENT["approval_result"], "approved_actions": []},
        }
        result = exec_handler.lambda_handler(event, None)
        assert result["total_actions"] == 0
        assert result["succeeded"] == 0
        assert result["results"] == []

    def test_output_includes_analyst_metadata(self):
        event = {
            **SAMPLE_EVENT,
            "approval_result": {**SAMPLE_EVENT["approval_result"], "approved_actions": []},
        }
        result = exec_handler.lambda_handler(event, None)
        assert result["analyst_id"] == "analyst@company.com"
        assert result["approval_notes"] == "Confirmed"
        assert "execution_timestamp" in result
