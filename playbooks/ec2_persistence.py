"""
playbooks/ec2_persistence.py

Playbook for attacker-persistence mechanisms on EC2 instances.

Covers scenarios where an attacker with initial access establishes a
persistent foothold on a Linux EC2 instance via cron job injection,
SSH authorized_keys modification, creation of new local OS accounts,
or tampering with EC2 user-data scripts to survive instance reboots.
"""

from __future__ import annotations

from playbooks.base import Playbook

EC2_PERSISTENCE = Playbook(
    name="EC2 Persistence",
    description=(
        "Investigates attacker-persistence techniques on EC2 instances, "
        "including cron job injection, SSH authorized_keys modification, "
        "creation of new local OS user accounts, and tampering with EC2 "
        "user-data scripts.  Focuses on identifying the persistence mechanism, "
        "removing it, and tracing the initial access that preceded it."
    ),
    finding_type_patterns=[
        "Persistence:EC2",
        "Behavior:EC2/NetworkPortUnusual",
        "Behavior:EC2/TrafficVolumeUnusual",
        "DefenseEvasion:EC2",
        "DefenseEvasion:Runtime",
        "Persistence:Runtime",
    ],
    investigation_steps=[
        "Identify the affected EC2 instance and determine when anomalous behavior began relative to the GuardDuty finding timestamp.",
        "Review CloudWatch Logs (auditd or /var/log/secure) for file-write events to /etc/cron*, /var/spool/cron/, or ~/.ssh/authorized_keys.",
        "Search for new OS user accounts created since the suspected compromise time: audit logs for useradd, adduser, or /etc/passwd modifications.",
        "Retrieve and inspect the current EC2 user-data script via the metadata service or EC2 DescribeInstanceAttribute API; compare against the approved baseline.",
        "Check for unusual listening ports or new systemd / init.d services that may represent a backdoor or reverse-shell listener.",
        "Trace the initial access event that preceded persistence: correlate GuardDuty finding time with SSH login events, web server logs, or CloudTrail API calls.",
        "Determine whether the persistence mechanism survives instance replacement (e.g., baked into a custom AMI or launch template user-data).",
        "Check Auto Scaling launch configurations and EC2 Image Builder pipelines for tampering that would propagate persistence to new instances.",
    ],
    key_indicators=[
        "New or modified cron entries in /etc/cron.d/, /etc/crontab, or user crontabs written by a non-root, unexpected user",
        "SSH authorized_keys file modified to add an unrecognised public key",
        "New local OS user account with UID 0 or membership in the sudo/wheel group",
        "EC2 user-data script containing base64-encoded payloads, curl/wget downloads, or reverse-shell commands",
        "New systemd service or init.d script with an unknown or obfuscated name",
        "Unusual outbound connections from the instance on a non-standard port consistent with a reverse-shell",
        "GuardDuty Behavior findings indicating unexpected network port usage or traffic volume spikes",
    ],
    response_actions=[
        "Isolate the instance immediately by replacing its security group with a deny-all group",
        "Remove the persistence mechanism: purge malicious cron entries, revoke unauthorised SSH keys, delete backdoor accounts",
        "Terminate and replace the instance from a known-good AMI rather than attempting in-place remediation",
        "Audit the launch template and user-data script; remove any injected commands before the next scale-out event",
        "Rotate all credentials associated with the instance profile and any user accounts on the instance",
        "Enable EC2 Instance Connect or SSM Session Manager to eliminate direct SSH exposure going forward",
        "Scan all instances in the same Auto Scaling group or sharing the same AMI for identical persistence artefacts",
        "Review and lock down IAM permissions that allow ModifyInstanceAttribute (to prevent future user-data tampering)",
    ],
    mitre_techniques=[
        "T1098.004",  # Account Manipulation – SSH Authorized Keys
        "T1053.003",  # Scheduled Task/Job – Cron
        "T1136.001",  # Create Account – Local Account
        "T1505",      # Server Software Component
        "T1037",      # Boot or Logon Initialization Scripts
        "T1059.004",  # Command and Scripting Interpreter – Unix Shell
    ],
    data_sources=[
        "guardduty",
        "cloudtrail",
        "cloudwatch",
        "ec2",
    ],
)
