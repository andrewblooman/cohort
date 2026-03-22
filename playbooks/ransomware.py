"""
playbooks/ransomware.py

Playbook for ransomware and destructive-activity incidents.

Covers GuardDuty findings related to data exfiltration, data destruction,
malware execution, and crypto-mining (which often accompanies ransomware
campaigns).
"""

from __future__ import annotations

from playbooks.base import Playbook

RANSOMWARE = Playbook(
    name="Ransomware / Destructive Activity",
    description=(
        "Investigates potential ransomware, data-destruction, cryptomining, "
        "and data-exfiltration activity detected by GuardDuty.  Focuses on "
        "rapid containment, evidence preservation, and recovery guidance."
    ),
    finding_type_patterns=[
        "CryptoCurrency",
        "Trojan",
        "Malware",
        "Backdoor",
        "Impact:EC2",
        "Exfiltration",
        "UnauthorizedAccess:EC2",
        "Execution:EC2",
        "AttackSequence:EC2",
        "Execution:Runtime",
        "Impact:Runtime",
        "UnauthorizedAccess:Lambda",
    ],
    investigation_steps=[
        "Identify the affected EC2 instance and its associated IAM instance profile.",
        "Review GuardDuty finding details for indicators of malware execution, C2 communication, or data exfiltration.",
        "Examine CloudTrail for suspicious S3 API calls (GetObject, PutObject, DeleteObject) that may indicate data staging or encryption.",
        "Check for unusual outbound network traffic in VPC Flow Logs, especially to known malicious IPs or on non-standard ports.",
        "Look for evidence of lateral movement: API calls from the instance to other EC2 instances or internal services.",
        "Assess whether the instance's user-data script or launch configuration has been tampered with.",
        "Determine the initial access vector: was the instance exposed to the internet, or was access gained via compromised credentials?",
    ],
    key_indicators=[
        "DNS queries to cryptocurrency mining pools",
        "Connections to known command-and-control infrastructure",
        "High CPU utilization inconsistent with the instance's normal workload",
        "Mass S3 object deletion or encryption activity",
        "Unexpected EBS snapshot creation or cross-account sharing",
        "New or modified cron jobs, systemd services, or startup scripts",
        "Outbound traffic on ports commonly used by ransomware (445, 3389, 4444)",
    ],
    response_actions=[
        "Immediately isolate the affected instance by replacing its security group with a deny-all group",
        "Create an EBS snapshot for forensic analysis before terminating the instance",
        "Revoke and rotate all credentials associated with the instance profile",
        "Check for and revoke any unauthorized cross-account access or resource sharing",
        "Scan other instances in the same VPC for indicators of lateral movement",
        "Restore affected data from known-good backups after confirming containment",
        "Engage the incident-response team and consider notifying law enforcement if data was exfiltrated",
    ],
    mitre_techniques=[
        "T1486",   # Data Encrypted for Impact
        "T1490",   # Inhibit System Recovery
        "T1496",   # Resource Hijacking (cryptomining)
        "T1041",   # Exfiltration Over C2 Channel
        "T1059",   # Command and Scripting Interpreter
        "T1570",   # Lateral Tool Transfer
    ],
    data_sources=[
        "guardduty",
        "cloudtrail",
        "cloudwatch",
        "vpc_flow_logs",
        "ec2",
    ],
)
