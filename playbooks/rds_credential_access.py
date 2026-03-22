"""
playbooks/rds_credential_access.py

Playbook for Amazon RDS and Aurora database credential-access incidents.

Covers all GuardDuty RDS Login Activity Monitoring findings, including
anomalous failed logins, successful brute-force attacks, logins from
malicious IPs or Tor nodes, and unusual successful logins.  Targets
Aurora MySQL, Aurora PostgreSQL, RDS MySQL, RDS PostgreSQL, and
Aurora Limitless databases.
"""

from __future__ import annotations

from playbooks.base import Playbook

RDS_CREDENTIAL_ACCESS = Playbook(
    name="RDS Database Credential Access",
    description=(
        "Investigates GuardDuty RDS Login Activity Monitoring findings targeting "
        "Amazon Aurora and RDS databases, including anomalous brute-force login "
        "attempts, successful logins after repeated failures, logins from malicious "
        "IP addresses, and Tor-based database access.  Focuses on determining "
        "whether the database was successfully compromised, assessing data-exposure "
        "risk, and hardening database authentication."
    ),
    finding_type_patterns=[
        "CredentialAccess:RDS",
        "Discovery:RDS",
    ],
    investigation_steps=[
        "Identify the affected RDS or Aurora instance/cluster and its database engine, VPC, and subnet placement.",
        "Review RDS login activity logs in CloudWatch for the volume of failed and successful authentication attempts from the source IP.",
        "Determine whether the brute force succeeded: look for CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce or SuccessfulLogin findings.",
        "Check whether the database is publicly accessible (PubliclyAccessible=true) or exposed via an unprotected security group (0.0.0.0/0 on 3306/5432).",
        "Review the IAM authentication configuration: is IAM database authentication enabled as a more secure alternative to password auth?",
        "Examine database query logs (if enabled via parameter group) for suspicious SELECT/INSERT/DROP/EXPORT activity after a successful login.",
        "Correlate the source IP with GuardDuty threat-intelligence (malicious IP, Tor exit node).",
        "Check for recent RDS parameter group or security group changes in CloudTrail that may have weakened the database's security posture.",
    ],
    key_indicators=[
        "High volume of failed login attempts followed by a successful login (brute force pattern)",
        "RDS instance with PubliclyAccessible=true and no IP-based security group restriction",
        "Login from a known malicious IP or Tor exit node",
        "IAM authentication disabled; password-only authentication in use",
        "Database parameter group with general_log or slow_query_log disabled (evidence tampering)",
        "Recent security group change opening port 3306/5432 to 0.0.0.0/0",
        "Unusual SELECT * or DUMP operations shortly after a successful login",
        "GuardDuty Discovery:RDS finding indicating enumeration of database objects",
    ],
    response_actions=[
        "Immediately rotate the compromised database user password and all application credentials that use it",
        "Restrict the RDS security group to known application/bastion CIDR ranges; remove 0.0.0.0/0 rules",
        "Enable IAM database authentication and disable direct password-based logins where possible",
        "Set PubliclyAccessible=false and place the instance in a private subnet behind a VPC endpoint or bastion",
        "Enable enhanced monitoring and CloudWatch Logs export (audit logs, general logs, slow query logs) for forensic analysis",
        "Rotate the RDS master credentials and all application service-account credentials",
        "Review database query logs for data exfiltration (large SELECT or SELECT INTO OUTFILE activity)",
        "Consider creating a read-only replica for forensic investigation before modifying the primary instance",
    ],
    mitre_techniques=[
        "T1110",      # Brute Force
        "T1110.001",  # Brute Force – Password Guessing
        "T1110.003",  # Brute Force – Password Spraying
        "T1078",      # Valid Accounts (successful login with compromised credentials)
        "T1213",      # Data from Information Repositories
        "T1190",      # Exploit Public-Facing Application (public RDS endpoint)
    ],
    data_sources=[
        "guardduty",
        "cloudtrail",
        "cloudwatch",
        "rds",
    ],
)
