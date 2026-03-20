"""
playbooks – Modular incident-response playbooks for the Cohort AI agent.

Each playbook provides scenario-specific investigation guidance, key indicators,
and recommended response actions.  The ``select_playbook`` function maps a
GuardDuty finding type to the most appropriate playbook at runtime.

Usage::

    from playbooks import select_playbook

    playbook = select_playbook(
        finding_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        description="Credentials were used from an external IP.",
    )
    prompt_section = playbook.format_prompt_section()
"""

from playbooks.base import Playbook
from playbooks.guardduty_general import GUARDDUTY_GENERAL
from playbooks.iam_privilege_escalation import IAM_PRIVILEGE_ESCALATION
from playbooks.ransomware import RANSOMWARE
from playbooks.registry import get_all_playbooks, select_playbook

__all__ = [
    "Playbook",
    "GUARDDUTY_GENERAL",
    "IAM_PRIVILEGE_ESCALATION",
    "RANSOMWARE",
    "get_all_playbooks",
    "select_playbook",
]
