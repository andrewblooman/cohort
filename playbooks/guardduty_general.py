"""
playbooks/guardduty_general.py

Default / fallback playbook for generic GuardDuty findings.

Used when no more specific playbook matches the finding type.
Provides broad investigation guidance applicable to most GuardDuty alerts.
"""

from __future__ import annotations

from playbooks.base import Playbook

GUARDDUTY_GENERAL = Playbook(
    name="GuardDuty General",
    description=(
        "General-purpose playbook for GuardDuty findings that do not match a "
        "more specific scenario.  Provides a broad investigation framework "
        "suitable for network-based, DNS-based, and miscellaneous findings."
    ),
    # Empty patterns – this playbook is the default fallback
    finding_type_patterns=[],
    investigation_steps=[
        "Understand the GuardDuty finding type and what threat behaviour it represents.",
        "Evaluate the affected resource (EC2 instance, IAM entity, S3 bucket, etc.) and its business context.",
        "Review CloudTrail events for the resource to identify suspicious or anomalous API calls.",
        "Examine VPC Flow Logs and DNS query logs for unusual network traffic patterns.",
        "Check whether the activity correlates with known benign patterns such as security scanning, penetration tests, or approved automation.",
        "Assess the severity and confidence of the GuardDuty finding against the collected evidence.",
    ],
    key_indicators=[
        "Connections to known malicious IP addresses or domains",
        "DNS queries to command-and-control or cryptocurrency mining endpoints",
        "Unusual outbound traffic volume or port usage",
        "API calls from unexpected IP addresses or at unusual times",
        "Resource tags or metadata indicating a non-production or test environment",
    ],
    response_actions=[
        "Isolate the affected resource if evidence supports a true positive",
        "Capture forensic evidence (memory dump, disk snapshot) before remediation",
        "Rotate credentials associated with the affected resource",
        "Review and tighten security-group and NACL rules",
        "Notify the security operations team and update the incident ticket",
    ],
    mitre_techniques=[
        "T1071",   # Application Layer Protocol
        "T1105",   # Ingress Tool Transfer
        "T1571",   # Non-Standard Port
    ],
    data_sources=[
        "guardduty",
        "cloudtrail",
        "cloudwatch",
        "vpc_flow_logs",
    ],
)
