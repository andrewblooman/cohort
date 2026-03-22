"""
playbooks/ec2_ssh_brute_force.py

Playbook for SSH/RDP brute-force and unauthorized remote-access incidents.

Covers GuardDuty findings where an external actor attempts to gain access
to an EC2 instance by brute-forcing SSH or RDP credentials, or where the
instance is communicating over Tor, indicating covert remote-access activity.
"""

from __future__ import annotations

from playbooks.base import Playbook

EC2_SSH_BRUTE_FORCE = Playbook(
    name="EC2 SSH / RDP Brute Force",
    description=(
        "Investigates brute-force and unauthorized remote-access attempts "
        "against EC2 instances, including SSH and RDP credential stuffing, "
        "Tor-based anonymous access, and successful logins following a series "
        "of failures.  Focuses on determining whether the attack succeeded, "
        "identifying the source, and hardening remote-access exposure."
    ),
    finding_type_patterns=[
        "UnauthorizedAccess:EC2/SSHBruteForce",
        "UnauthorizedAccess:EC2/RDPBruteForce",
        "UnauthorizedAccess:EC2/TorClient",
        "UnauthorizedAccess:EC2/TorRelay",
        "UnauthorizedAccess:Runtime/TorClient",
        "UnauthorizedAccess:Runtime/TorRelay",
    ],
    investigation_steps=[
        "Confirm whether the brute-force originated from a known scanner, penetration test, or a genuine threat actor.",
        "Review VPC Flow Logs for repeated connection attempts on ports 22 (SSH) or 3389 (RDP) from the source IP.",
        "Inspect CloudWatch Logs (/var/log/secure or /var/log/auth.log) for failed and successful authentication events.",
        "Determine whether any login attempt succeeded: look for 'Accepted password' or 'Accepted publickey' log entries.",
        "If a successful login is detected, trace subsequent commands via CloudWatch audit logs or AWS Systems Manager Session Manager logs.",
        "Check whether the instance's security group permits unrestricted inbound SSH/RDP (0.0.0.0/0 on port 22 or 3389).",
        "Correlate the source IP with threat-intelligence feeds and GuardDuty's IP reputation lists.",
        "Assess whether the instance is running any internet-facing services that could serve as a pivot for lateral movement.",
    ],
    key_indicators=[
        "High volume of REJECT entries on port 22 or 3389 from a single source IP in VPC Flow Logs",
        "Multiple failed SSH authentication attempts followed by a successful login",
        "Security group inbound rule allowing 0.0.0.0/0 or ::/0 on port 22 or 3389",
        "Source IP associated with Tor exit nodes or known scanning services",
        "New user accounts or SSH authorized_keys added shortly after a successful login",
        "Outbound connections to Tor relays (GuardDuty TorClient finding)",
        "Unusual commands run interactively after a successful SSH session",
    ],
    response_actions=[
        "Restrict SSH/RDP security-group rules to known CIDR ranges immediately; remove 0.0.0.0/0 rules",
        "If a successful login is confirmed, isolate the instance by replacing its security group with a deny-all group",
        "Disable password-based SSH authentication and enforce key-pair-only login",
        "Rotate or revoke any SSH keys or passwords that may have been compromised",
        "Enable AWS Systems Manager Session Manager as a replacement for direct SSH access",
        "Deploy a bastion host or VPN to gate all remote-access to private instances",
        "Create a CloudWatch alarm or GuardDuty suppression rule for known-safe scanners to reduce noise",
        "Review and terminate any unexpected interactive sessions active on the instance",
    ],
    mitre_techniques=[
        "T1110",      # Brute Force
        "T1110.001",  # Brute Force – Password Guessing
        "T1110.003",  # Brute Force – Password Spraying
        "T1021.004",  # Remote Services – SSH
        "T1021.001",  # Remote Services – Remote Desktop Protocol
        "T1133",      # External Remote Services
        "T1078",      # Valid Accounts (successful login with brute-forced credential)
    ],
    data_sources=[
        "guardduty",
        "cloudwatch",
        "vpc_flow_logs",
        "ec2",
    ],
)
