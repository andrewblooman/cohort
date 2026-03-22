"""
playbooks/ec2_credential_access.py

Playbook for EC2 credential-access and credential-dumping incidents.

Covers scenarios where an attacker on a Linux EC2 instance attempts to harvest
credentials by reading /etc/passwd and /etc/shadow, using password-cracking
tools (e.g. John the Ripper, Hashcat), or abusing the EC2 Instance Metadata
Service (IMDS) to steal the attached IAM role's short-lived credentials.
"""

from __future__ import annotations

from playbooks.base import Playbook

EC2_CREDENTIAL_ACCESS = Playbook(
    name="EC2 Credential Access",
    description=(
        "Investigates credential-harvesting activity on Linux EC2 instances, "
        "including reading /etc/passwd and /etc/shadow, use of password-cracking "
        "tools, and abuse of the EC2 Instance Metadata Service (IMDS) to steal "
        "IAM role credentials.  Focuses on identifying the initial foothold, "
        "the scope of credential exposure, and lateral-movement risk."
    ),
    finding_type_patterns=[
        "CredentialAccess:EC2",
        "CredentialAccess:Runtime",
        "InstanceCredentialExfiltration",
    ],
    investigation_steps=[
        "Identify the affected EC2 instance and the IAM instance profile / role attached to it.",
        "Review CloudWatch Logs (OS-level audit logs, /var/log/secure, /var/log/auth.log) for commands reading /etc/passwd or /etc/shadow.",
        "Search for execution of known password-cracking tools: john, hashcat, hydra, medusa, unshadow.",
        "Check CloudTrail for IMDS-sourced API calls: look for requests where the user-agent or source IP matches the instance's private IP or contains 'aws-internal'.",
        "Determine whether the IAM role credentials were used outside the instance's known IP range (CloudTrail sourceIPAddress field).",
        "Examine VPC Flow Logs for outbound connections from the instance to external IPs immediately after the credential-access event (possible exfiltration).",
        "Assess the blast radius: what resources does the stolen IAM role grant access to?",
        "Check whether IMDSv2 (token-required mode) is enforced on the instance; if not, SSRF-to-IMDS is trivially exploitable.",
    ],
    key_indicators=[
        "cat, less, or strings commands targeting /etc/shadow or /etc/passwd in audit logs",
        "Execution of unshadow, john, hashcat, hydra, or medusa binaries",
        "HTTP GET to http://169.254.169.254/latest/meta-data/iam/security-credentials/ in CloudWatch or VPC Flow Logs",
        "CloudTrail events with a source IP that does not match the instance's private IP",
        "IAM role temporary credentials used from an unexpected geographic location or IP",
        "IMDSv1 (no token required) enabled on a public-facing instance",
        "New SSH keys added to ~/.ssh/authorized_keys after the credential-access event",
    ],
    response_actions=[
        "Immediately revoke the instance profile's temporary credentials by attaching a deny-all inline policy to the IAM role",
        "Isolate the instance by replacing its security group with a deny-all group",
        "Force credential rotation: detach and re-create the IAM instance profile with a new role",
        "Enforce IMDSv2 on all EC2 instances using instance metadata options (HttpTokens=required)",
        "Capture a memory dump and EBS snapshot for forensic analysis before termination",
        "Audit all API calls made with the stolen credentials and determine if any resources were accessed or modified",
        "Check for lateral movement: were credentials used to access other EC2 instances, S3 buckets, or RDS databases?",
        "Review and harden OS-level access controls: restrict /etc/shadow to root only, enable auditd rules for sensitive file reads",
    ],
    mitre_techniques=[
        "T1003",      # OS Credential Dumping
        "T1003.008",  # OS Credential Dumping – /etc/passwd and /etc/shadow
        "T1552.005",  # Unsecured Credentials – Cloud Instance Metadata API
        "T1555",      # Credentials from Password Stores
        "T1078",      # Valid Accounts (using stolen credentials)
        "T1190",      # Exploit Public-Facing Application (SSRF to IMDS)
    ],
    data_sources=[
        "guardduty",
        "cloudtrail",
        "cloudwatch",
        "vpc_flow_logs",
        "ec2",
    ],
)
