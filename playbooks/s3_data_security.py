"""
playbooks/s3_data_security.py

Playbook for S3 data-security incidents.

Covers all GuardDuty S3-related finding categories: anomalous bucket discovery
and enumeration, data exfiltration, destructive or permission-modifying impact
actions, public-access policy misconfigurations, server-access logging disabled,
penetration-testing tool signatures, malicious IP access, and S3 malware
detection findings.
"""

from __future__ import annotations

from playbooks.base import Playbook

S3_DATA_SECURITY = Playbook(
    name="S3 Data Security",
    description=(
        "Investigates GuardDuty findings related to Amazon S3, including "
        "anomalous bucket access and enumeration, data exfiltration, destructive "
        "write/delete/permission-change activity, public-access misconfigurations, "
        "access-logging tampering, penetration-testing tool signatures, and S3 "
        "object malware detections.  Focuses on determining the scope of data "
        "exposure, containing the risk, and hardening bucket policies."
    ),
    finding_type_patterns=[
        "Discovery:S3",
        "Exfiltration:S3",
        "Impact:S3",
        "Policy:S3",
        "PenTest:S3",
        "Stealth:S3",
        "UnauthorizedAccess:S3",
        "Object:S3",
        "AttackSequence:S3",
    ],
    investigation_steps=[
        "Identify the affected S3 bucket(s) and their data classification (PII, confidential, public).",
        "Review CloudTrail data events for S3 (GetObject, PutObject, DeleteObject, PutBucketPolicy, PutBucketAcl) from the time window of the alert.",
        "Determine the IAM principal making the suspicious requests: user, role, federated identity, or public access.",
        "Check whether public access is enabled on the bucket or account: evaluate Block Public Access settings and bucket/object ACLs.",
        "Assess data-exfiltration risk: how much data was read (GetObject requests), to which IPs, and was it downloaded in bulk?",
        "Look for bucket policy or ACL changes that may have granted broader access (PutBucketPolicy, PutBucketAcl calls in CloudTrail).",
        "Verify whether S3 server-access logging or CloudTrail data events were disabled around the time of the finding.",
        "Check for object-level delete activity (DeleteObject, DeleteObjects) that may indicate data destruction or ransomware staging.",
        "Correlate the source IP with GuardDuty threat-intelligence lists (malicious IPs, Tor exit nodes, penetration-testing distributions).",
        "Review Cross-Region or Cross-Account replication settings for unauthorised data-movement paths.",
    ],
    key_indicators=[
        "Bulk GetObject requests from a single IP or principal within a short time window",
        "PutBucketPolicy or PutBucketAcl changes granting s3:GetObject to * (anonymous public access)",
        "Block Public Access disabled at account or bucket level",
        "DeleteObject or DeleteObjects calls on production data buckets",
        "S3 server-access logging or CloudTrail data events disabled (Stealth finding)",
        "API calls from Tor exit nodes, known malicious IPs, or penetration-testing distros (Kali, Parrot, Pentoo)",
        "Object:S3/MaliciousFile detection from S3 Malware Protection scan",
        "AttackSequence finding indicating correlated data-compromise across multiple S3 actions",
    ],
    response_actions=[
        "Enable or re-enable Block Public Access at the account level immediately",
        "Revoke and rotate credentials of the IAM principal responsible for the suspicious activity",
        "Revert any unauthorised bucket policy or ACL changes using a known-good policy version",
        "Enable S3 server-access logging and CloudTrail data events for the affected bucket if disabled",
        "Enable S3 Object Lock or versioning to protect against future deletion or overwrite",
        "Quarantine any malicious objects detected by S3 Malware Protection (move to isolated bucket, apply deny ACL)",
        "Notify the data-owner and DPO if PII or sensitive data was exposed or exfiltrated",
        "Review and tighten bucket policies using AWS IAM Access Analyzer to remove overly permissive grants",
    ],
    mitre_techniques=[
        "T1530",      # Data from Cloud Storage
        "T1619",      # Cloud Storage Object Discovery
        "T1537",      # Transfer Data to Cloud Account
        "T1485",      # Data Destruction
        "T1562.008",  # Impair Defenses – Disable Cloud Logs
        "T1078",      # Valid Accounts
        "T1190",      # Exploit Public-Facing Application
    ],
    data_sources=[
        "guardduty",
        "cloudtrail",
        "s3",
    ],
)
