"""
playbooks/registry.py

Playbook registry and selection logic.

Maps GuardDuty finding types (and alert descriptions) to the most appropriate
playbook.  When no specific playbook matches, the general GuardDuty playbook
is returned as a safe default.
"""

from __future__ import annotations

from playbooks.base import Playbook
from playbooks.guardduty_general import GUARDDUTY_GENERAL
from playbooks.iam_privilege_escalation import IAM_PRIVILEGE_ESCALATION
from playbooks.ransomware import RANSOMWARE

# Ordered list – more specific playbooks first, general fallback last.
_PLAYBOOKS: list[Playbook] = [
    IAM_PRIVILEGE_ESCALATION,
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
