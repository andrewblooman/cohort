"""
playbooks/registry.py

Playbook registry and selection logic.

Maps GuardDuty finding types (and alert descriptions) to the most appropriate
playbook.  When no specific playbook matches, the general GuardDuty playbook
is returned as a safe default.
"""

from __future__ import annotations

from playbooks.base import Playbook
from playbooks.ec2_credential_access import EC2_CREDENTIAL_ACCESS
from playbooks.ec2_persistence import EC2_PERSISTENCE
from playbooks.ec2_ssh_brute_force import EC2_SSH_BRUTE_FORCE
from playbooks.guardduty_general import GUARDDUTY_GENERAL
from playbooks.iam_privilege_escalation import IAM_PRIVILEGE_ESCALATION
from playbooks.kubernetes_container import KUBERNETES_CONTAINER
from playbooks.ransomware import RANSOMWARE
from playbooks.rds_credential_access import RDS_CREDENTIAL_ACCESS
from playbooks.s3_data_security import S3_DATA_SECURITY
from playbooks.web_application_attack import WEB_APPLICATION_ATTACK

# Ordered list – more specific playbooks first, general fallback last.
#
# Ordering principles:
#   1. IAM-specific playbook first – its patterns are scoped to :IAMUser/ and
#      AttackSequence:IAM so they will not shadow EC2/S3/Runtime findings.
#   2. EC2-specific targeted playbooks before RANSOMWARE – RANSOMWARE carries
#      broad patterns (UnauthorizedAccess:EC2, Exfiltration, Backdoor, …) that
#      would otherwise shadow the more precise EC2 credential / SSH / web /
#      persistence playbooks.
#   3. S3_DATA_SECURITY before RANSOMWARE – ensures Exfiltration:S3 and
#      Impact:S3 are captured by the S3 playbook, not the generic Exfiltration
#      or Impact:EC2 patterns in RANSOMWARE.
#   4. KUBERNETES_CONTAINER before RANSOMWARE – Execution:ECS and
#      Execution:Container patterns must resolve before RANSOMWARE's
#      Execution:EC2 can shadow them (different suffix, but safer ordering).
#   5. RANSOMWARE as a broad safety-net for EC2/Lambda/Runtime malware,
#      crypto-mining, trojans, backdoors, and destructive activity.
#   6. GUARDDUTY_GENERAL is the final fallback.
_PLAYBOOKS: list[Playbook] = [
    IAM_PRIVILEGE_ESCALATION,
    EC2_CREDENTIAL_ACCESS,
    EC2_SSH_BRUTE_FORCE,
    WEB_APPLICATION_ATTACK,
    EC2_PERSISTENCE,
    S3_DATA_SECURITY,
    KUBERNETES_CONTAINER,
    RDS_CREDENTIAL_ACCESS,
    RANSOMWARE,
    GUARDDUTY_GENERAL,
]


def get_all_playbooks() -> list[Playbook]:
    """Return every registered playbook (including the fallback)."""
    return list(_PLAYBOOKS)


def select_playbook(
    finding_type: str = "",
    description: str = "",
) -> Playbook:
    """Choose the best playbook for the given finding.

    The selection algorithm checks each playbook's ``finding_type_patterns``
    against the *finding_type* **and** the *description* (case-insensitive
    substring match).  The first playbook with at least one matching pattern
    wins.  If nothing matches, the general GuardDuty playbook is returned.

    Args:
        finding_type: The ``Type`` field from the GuardDuty finding
                      (e.g. ``"UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"``).
        description:  Free-text description from the alert event.

    Returns:
        The most appropriate :class:`Playbook` instance.
    """
    search_text = f"{finding_type} {description}".lower()

    for playbook in _PLAYBOOKS:
        if not playbook.finding_type_patterns:
            # Skip the fallback during the matching loop
            continue
        for pattern in playbook.finding_type_patterns:
            if pattern.lower() in search_text:
                return playbook

    return GUARDDUTY_GENERAL
