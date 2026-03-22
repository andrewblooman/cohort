"""
execute_actions/handler.py

Lambda function: Execute Approved Actions

Phase 2 of the incident-response workflow.  Receives a list of analyst-approved
remediation actions and executes them against AWS services.

This Lambda is the ONLY component in the system that makes mutating AWS API
calls.  It is invoked exclusively by Step Functions after the ``NotifySIEM``
waitForTaskToken state has been resumed by the ``approve_actions`` Lambda — i.e.
only after a human analyst has explicitly authorised the actions.

Supported action types
----------------------
isolate_ec2_instance
    Remove an EC2 instance from all security groups and place it in a dedicated
    quarantine SG that blocks all inbound and outbound traffic.
    params: instance_id (str), region (str, optional)

stop_ec2_instance
    Stop a running EC2 instance.
    params: instance_id (str), region (str, optional)

snapshot_ec2_instance
    Create EBS snapshots for all volumes attached to an instance for forensic
    preservation.
    params: instance_id (str), region (str, optional), description (str, optional)

deactivate_iam_access_key
    Mark an IAM access key as Inactive to prevent further API use.
    params: user_name (str), access_key_id (str)

revoke_iam_role_sessions
    Attach a time-conditioned deny-all inline policy to an IAM role so all
    sessions issued before the revocation timestamp are immediately invalid.
    params: role_name (str)

archive_guardduty_finding
    Archive a GuardDuty finding to mark it as reviewed.
    params: finding_id (str), detector_id (str), region (str, optional)

block_s3_public_access
    Enable all four S3 Block Public Access settings on a bucket.
    params: bucket_name (str)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

# Name of the inline policy attached by revoke_iam_role_sessions
_REVOKE_POLICY_NAME = "CohortRevokedSessions"


# ---------------------------------------------------------------------------
# AWS client helpers
# ---------------------------------------------------------------------------

def _ec2(region: str = "") -> Any:
    return boto3.client("ec2", region_name=region or AWS_REGION)


def _iam() -> Any:
    return boto3.client("iam")


def _guardduty(region: str = "") -> Any:
    return boto3.client("guardduty", region_name=region or AWS_REGION)


def _s3() -> Any:
    return boto3.client("s3")


# ---------------------------------------------------------------------------
# Action implementations
# ---------------------------------------------------------------------------

def _ensure_quarantine_sg(ec2: Any, vpc_id: str, instance_id: str) -> str:
    """Return the ID of a quarantine security group (no ingress/egress rules).

    Creates one if it does not already exist in the given VPC.
    """
    sg_name = f"cohort-quarantine-{vpc_id}"
    existing = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": [sg_name]},
        ]
    )
    if existing["SecurityGroups"]:
        sg_id = existing["SecurityGroups"][0]["GroupId"]
        logger.info("Reusing quarantine SG %s", sg_id)
        return sg_id

    sg = ec2.create_security_group(
        GroupName=sg_name,
        Description=(
            f"Cohort incident response quarantine — no ingress/egress. "
            f"Created for incident involving {instance_id}."
        ),
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]

    # Remove the default allow-all egress rule so there is truly no traffic.
    ec2.revoke_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
            }
        ],
    )
    logger.info("Created quarantine SG %s in VPC %s", sg_id, vpc_id)
    return sg_id


def isolate_ec2_instance(params: dict) -> dict:
    """Remove instance from all security groups; place in quarantine SG."""
    instance_id = params["instance_id"]
    region = params.get("region", AWS_REGION)
    ec2 = _ec2(region)

    resp = ec2.describe_instances(InstanceIds=[instance_id])
    instance = resp["Reservations"][0]["Instances"][0]
    vpc_id = instance.get("VpcId", "")

    quarantine_sg_id = _ensure_quarantine_sg(ec2, vpc_id, instance_id)
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[quarantine_sg_id])

    logger.info("Isolated EC2 %s → quarantine SG %s", instance_id, quarantine_sg_id)
    return {"instance_id": instance_id, "quarantine_sg_id": quarantine_sg_id}


def stop_ec2_instance(params: dict) -> dict:
    """Stop a running EC2 instance."""
    instance_id = params["instance_id"]
    region = params.get("region", AWS_REGION)
    ec2 = _ec2(region)

    resp = ec2.stop_instances(InstanceIds=[instance_id])
    state = resp["StoppingInstances"][0]["CurrentState"]["Name"]
    logger.info("Stopped EC2 %s — current state: %s", instance_id, state)
    return {"instance_id": instance_id, "current_state": state}


def snapshot_ec2_instance(params: dict) -> dict:
    """Create EBS snapshots for every volume attached to an instance."""
    instance_id = params["instance_id"]
    region = params.get("region", AWS_REGION)
    description = params.get("description", f"Cohort forensic snapshot — {instance_id}")
    ec2 = _ec2(region)

    resp = ec2.describe_instances(InstanceIds=[instance_id])
    volumes = [
        bdm["Ebs"]["VolumeId"]
        for bdm in resp["Reservations"][0]["Instances"][0].get("BlockDeviceMappings", [])
        if "Ebs" in bdm
    ]

    snapshot_ids = []
    for volume_id in volumes:
        snap = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"{description} (volume {volume_id})",
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "CohortIncident", "Value": instance_id},
                        {"Key": "ForensicSnapshot", "Value": "true"},
                    ],
                }
            ],
        )
        snapshot_ids.append(snap["SnapshotId"])
        logger.info("Created snapshot %s for volume %s", snap["SnapshotId"], volume_id)

    return {"instance_id": instance_id, "snapshot_ids": snapshot_ids}


def deactivate_iam_access_key(params: dict) -> dict:
    """Mark an IAM access key as Inactive."""
    user_name = params["user_name"]
    access_key_id = params["access_key_id"]
    iam = _iam()

    iam.update_access_key(
        UserName=user_name,
        AccessKeyId=access_key_id,
        Status="Inactive",
    )
    logger.info("Deactivated IAM key %s for user %s", access_key_id, user_name)
    return {"user_name": user_name, "access_key_id": access_key_id, "new_status": "Inactive"}


def revoke_iam_role_sessions(params: dict) -> dict:
    """Revoke all active sessions for an IAM role via a time-conditioned deny policy.

    Follows the AWS-recommended session revocation pattern: attaches an inline
    policy that denies all actions on tokens issued before the current timestamp.
    New sessions created after this call are not affected.
    """
    role_name = params["role_name"]
    iam = _iam()

    revocation_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {"aws:TokenIssueTime": revocation_time}
                },
            }
        ],
    }

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=_REVOKE_POLICY_NAME,
        PolicyDocument=json.dumps(deny_policy),
    )
    logger.info("Revoked sessions for IAM role %s (tokens before %s)", role_name, revocation_time)
    return {
        "role_name": role_name,
        "revocation_time": revocation_time,
        "policy_name": _REVOKE_POLICY_NAME,
    }


def archive_guardduty_finding(params: dict) -> dict:
    """Archive a GuardDuty finding."""
    finding_id = params["finding_id"]
    detector_id = params["detector_id"]
    region = params.get("region", AWS_REGION)
    gd = _guardduty(region)

    gd.archive_findings(DetectorId=detector_id, FindingIds=[finding_id])
    logger.info("Archived GuardDuty finding %s in detector %s", finding_id, detector_id)
    return {"finding_id": finding_id, "detector_id": detector_id, "status": "archived"}


def block_s3_public_access(params: dict) -> dict:
    """Enable all four S3 Block Public Access settings on a bucket."""
    bucket_name = params["bucket_name"]
    s3 = _s3()

    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    logger.info("Blocked all public access on S3 bucket %s", bucket_name)
    return {"bucket_name": bucket_name, "block_public_access_enabled": True}


# ---------------------------------------------------------------------------
# Action router
# ---------------------------------------------------------------------------

ACTION_HANDLERS: dict[str, Any] = {
    "isolate_ec2_instance": isolate_ec2_instance,
    "stop_ec2_instance": stop_ec2_instance,
    "snapshot_ec2_instance": snapshot_ec2_instance,
    "deactivate_iam_access_key": deactivate_iam_access_key,
    "revoke_iam_role_sessions": revoke_iam_role_sessions,
    "archive_guardduty_finding": archive_guardduty_finding,
    "block_s3_public_access": block_s3_public_access,
}


def execute_action(action: dict) -> dict:
    """Dispatch a single action to its handler.  Returns a result dict."""
    action_type = action.get("type", "")
    action_id = action.get("action_id", action_type)
    params = action.get("parameters", {})

    handler = ACTION_HANDLERS.get(action_type)
    if not handler:
        logger.warning("Unknown action type: %s", action_type)
        return {
            "action_id": action_id,
            "type": action_type,
            "status": "skipped",
            "error": f"Unsupported action type: {action_type}",
        }

    try:
        details = handler(params)
        return {"action_id": action_id, "type": action_type, "status": "succeeded", "details": details}
    except (ClientError, KeyError, ValueError) as exc:
        error_msg = str(exc)
        logger.error("Action %s (%s) failed: %s", action_id, action_type, error_msg)
        return {"action_id": action_id, "type": action_type, "status": "failed", "error": error_msg}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Entry point for the execute-actions Lambda.

    Args:
        event: Step Functions payload containing ticket_number, secops_case_id,
               and approval_result (analyst-approved actions).
        context: Lambda context (unused).

    Returns:
        Execution summary with per-action results.
    """
    ticket_number = event.get("ticket_number", "UNKNOWN")
    logger.info("execute_actions invoked for ticket=%s", ticket_number)

    approval_result = event.get("approval_result", {})
    analyst_id = approval_result.get("analyst_id", "unknown")
    approved_actions = approval_result.get("approved_actions", [])
    approval_notes = approval_result.get("approval_notes", "")
    approval_timestamp = approval_result.get("approval_timestamp", "")

    logger.info(
        "Executing %d approved action(s) for ticket=%s approved_by=%s",
        len(approved_actions),
        ticket_number,
        analyst_id,
    )

    results = [execute_action(action) for action in approved_actions]
    succeeded = sum(1 for r in results if r["status"] == "succeeded")
    failed = sum(1 for r in results if r["status"] == "failed")

    execution_timestamp = datetime.now(tz=timezone.utc).isoformat()

    logger.info(
        "Execution complete: ticket=%s succeeded=%d failed=%d",
        ticket_number,
        succeeded,
        failed,
    )

    return {
        "ticket_number": ticket_number,
        "analyst_id": analyst_id,
        "approval_notes": approval_notes,
        "approval_timestamp": approval_timestamp,
        "execution_timestamp": execution_timestamp,
        "total_actions": len(approved_actions),
        "succeeded": succeeded,
        "failed": failed,
        "results": results,
    }
