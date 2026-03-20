"""
playbooks/iam_privilege_escalation.py

Playbook for IAM privilege-escalation incidents.

Covers GuardDuty findings related to unauthorized policy changes,
credential abuse, and privilege-escalation attempts.
"""

from __future__ import annotations

from playbooks.base import Playbook

IAM_PRIVILEGE_ESCALATION = Playbook(
    name="IAM Privilege Escalation",
    description=(
        "Investigates potential IAM privilege-escalation activity, including "
        "unauthorized policy attachments, role assumption from unexpected "
        "principals, and credential misuse."
    ),
    finding_type_patterns=[
        "UnauthorizedAccess:IAMUser",
        "Policy:IAMUser",
        "PrivilegeEscalation",
        "PenTest:IAMUser",
        "Persistence:IAMUser",
        "CredentialAccess:IAMUser",
        "Impact:IAMUser",
    ],
    investigation_steps=[
        "Identify the IAM principal (user, role, or federated identity) involved in the finding.",
        "Review CloudTrail for recent IAM API calls: AttachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy, CreateAccessKey, CreateLoginProfile, UpdateAssumeRolePolicy.",
        "Determine whether any new policies grant overly broad permissions (e.g. iam:*, s3:*, ec2:*).",
        "Check for unusual AssumeRole or GetSessionToken calls, especially cross-account or from unexpected source IPs.",
        "Compare the principal's historical API-call patterns with the current activity to spot anomalies.",
        "Verify whether the changes align with an approved change-management ticket or deployment pipeline.",
        "Inspect access-key age and rotation history for the affected principal.",
    ],
    key_indicators=[
        "New inline or managed policies granting administrative access",
        "AssumeRole calls from unfamiliar accounts or IPs",
        "CreateAccessKey or CreateLoginProfile for existing users",
        "Rapid succession of IAM write calls within a short time window",
        "API calls from geographic locations inconsistent with the user's profile",
        "Use of root account credentials",
    ],
    response_actions=[
        "Disable or delete compromised access keys immediately",
        "Revoke any newly attached policies that grant excessive permissions",
        "Rotate credentials for the affected IAM principal",
        "Enable or review AWS CloudTrail multi-region logging",
        "Apply a deny-all SCP or permission boundary to contain the principal",
        "Notify the security operations team and open an incident ticket",
    ],
    mitre_techniques=[
        "T1078",   # Valid Accounts
        "T1098",   # Account Manipulation
        "T1136",   # Create Account
        "T1484",   # Domain Policy Modification
        "T1548",   # Abuse Elevation Control Mechanism
    ],
    data_sources=[
        "guardduty",
        "cloudtrail",
        "cloudwatch",
        "iam",
    ],
)
