"""
tests/test_playbooks.py

Unit tests for the playbooks package: base dataclass, individual playbooks,
and the registry/selection logic.
"""

from __future__ import annotations

import os
import sys

import pytest

# Ensure the repo root is on the path so that ``playbooks`` can be imported.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from playbooks.base import Playbook
from playbooks.guardduty_general import GUARDDUTY_GENERAL
from playbooks.iam_privilege_escalation import IAM_PRIVILEGE_ESCALATION
from playbooks.ransomware import RANSOMWARE
from playbooks.registry import get_all_playbooks, select_playbook


# ---------------------------------------------------------------------------
# Base Playbook dataclass
# ---------------------------------------------------------------------------

class TestPlaybookBase:
    def test_playbook_is_immutable(self):
        pb = Playbook(name="Test", description="A test playbook")
        with pytest.raises(AttributeError):
            pb.name = "Changed"  # type: ignore[misc]

    def test_format_prompt_section_contains_name(self):
        pb = Playbook(
            name="My Playbook",
            description="Covers XYZ scenarios.",
            investigation_steps=["Step one"],
            key_indicators=["Indicator A"],
            response_actions=["Action 1"],
            mitre_techniques=["T1234"],
        )
        section = pb.format_prompt_section()
        assert "My Playbook" in section
        assert "Covers XYZ scenarios." in section
        assert "Step one" in section
        assert "Indicator A" in section
        assert "Action 1" in section
        assert "T1234" in section

    def test_format_prompt_section_omits_empty_lists(self):
        pb = Playbook(name="Minimal", description="No extras.")
        section = pb.format_prompt_section()
        assert "Investigation Steps" not in section
        assert "Key Indicators" not in section
        assert "Recommended Response Actions" not in section
        assert "MITRE" not in section

    def test_default_fields_are_empty_lists(self):
        pb = Playbook(name="Empty", description="Empty playbook")
        assert pb.finding_type_patterns == []
        assert pb.investigation_steps == []
        assert pb.key_indicators == []
        assert pb.response_actions == []
        assert pb.mitre_techniques == []
        assert pb.data_sources == []

    def test_format_prompt_section_includes_data_sources(self):
        pb = Playbook(
            name="Sources Playbook",
            description="Has data sources.",
            data_sources=["cloudtrail", "cloudwatch"],
        )
        section = pb.format_prompt_section()
        assert "Required Data Sources" in section
        assert "cloudtrail" in section
        assert "cloudwatch" in section

    def test_format_prompt_section_omits_empty_data_sources(self):
        pb = Playbook(name="No Sources", description="No data sources.")
        section = pb.format_prompt_section()
        assert "Required Data Sources" not in section


# ---------------------------------------------------------------------------
# Individual playbook definitions
# ---------------------------------------------------------------------------

class TestIAMPrivilegeEscalationPlaybook:
    def test_has_name_and_description(self):
        assert IAM_PRIVILEGE_ESCALATION.name == "IAM Privilege Escalation"
        assert len(IAM_PRIVILEGE_ESCALATION.description) > 0

    def test_has_finding_type_patterns(self):
        assert len(IAM_PRIVILEGE_ESCALATION.finding_type_patterns) > 0
        assert "UnauthorizedAccess:IAMUser" in IAM_PRIVILEGE_ESCALATION.finding_type_patterns

    def test_has_investigation_steps(self):
        assert len(IAM_PRIVILEGE_ESCALATION.investigation_steps) > 0

    def test_has_mitre_techniques(self):
        assert "T1078" in IAM_PRIVILEGE_ESCALATION.mitre_techniques

    def test_has_data_sources(self):
        assert len(IAM_PRIVILEGE_ESCALATION.data_sources) > 0
        assert "cloudtrail" in IAM_PRIVILEGE_ESCALATION.data_sources
        assert "iam" in IAM_PRIVILEGE_ESCALATION.data_sources


class TestGuardDutyGeneralPlaybook:
    def test_has_name_and_description(self):
        assert GUARDDUTY_GENERAL.name == "GuardDuty General"
        assert len(GUARDDUTY_GENERAL.description) > 0

    def test_finding_type_patterns_is_empty(self):
        # The general playbook is a fallback – no patterns to match
        assert GUARDDUTY_GENERAL.finding_type_patterns == []

    def test_has_investigation_steps(self):
        assert len(GUARDDUTY_GENERAL.investigation_steps) > 0

    def test_has_data_sources(self):
        assert len(GUARDDUTY_GENERAL.data_sources) > 0
        assert "guardduty" in GUARDDUTY_GENERAL.data_sources
        assert "cloudtrail" in GUARDDUTY_GENERAL.data_sources


class TestRansomwarePlaybook:
    def test_has_name_and_description(self):
        assert RANSOMWARE.name == "Ransomware / Destructive Activity"
        assert len(RANSOMWARE.description) > 0

    def test_has_finding_type_patterns(self):
        assert len(RANSOMWARE.finding_type_patterns) > 0
        assert "CryptoCurrency" in RANSOMWARE.finding_type_patterns

    def test_has_mitre_techniques(self):
        assert "T1486" in RANSOMWARE.mitre_techniques

    def test_has_data_sources(self):
        assert len(RANSOMWARE.data_sources) > 0
        assert "vpc_flow_logs" in RANSOMWARE.data_sources
        assert "ec2" in RANSOMWARE.data_sources


# ---------------------------------------------------------------------------
# Registry / selection logic
# ---------------------------------------------------------------------------

class TestGetAllPlaybooks:
    def test_returns_all_registered_playbooks(self):
        playbooks = get_all_playbooks()
        names = {pb.name for pb in playbooks}
        assert "IAM Privilege Escalation" in names
        assert "Ransomware / Destructive Activity" in names
        assert "GuardDuty General" in names

    def test_returns_copies(self):
        a = get_all_playbooks()
        b = get_all_playbooks()
        assert a is not b  # different list objects


class TestSelectPlaybook:
    # ---- IAM privilege escalation ----
    def test_selects_iam_playbook_for_unauthorized_access_iam_user(self):
        pb = select_playbook(finding_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS")
        assert pb.name == "IAM Privilege Escalation"

    def test_selects_iam_playbook_for_policy_iam_user(self):
        pb = select_playbook(finding_type="Policy:IAMUser/RootCredentialUsage")
        assert pb.name == "IAM Privilege Escalation"

    def test_selects_iam_playbook_for_privilege_escalation_keyword(self):
        pb = select_playbook(finding_type="PrivilegeEscalation:IAMUser/AdministrativePermissions")
        assert pb.name == "IAM Privilege Escalation"

    # ---- Ransomware / destructive ----
    def test_selects_ransomware_playbook_for_cryptocurrency(self):
        pb = select_playbook(finding_type="CryptoCurrency:EC2/BitcoinTool.B!DNS")
        assert pb.name == "Ransomware / Destructive Activity"

    def test_selects_ransomware_playbook_for_trojan(self):
        pb = select_playbook(finding_type="Trojan:EC2/BlackholeTraffic")
        assert pb.name == "Ransomware / Destructive Activity"

    def test_selects_ransomware_playbook_for_malware(self):
        pb = select_playbook(finding_type="Malware:EC2/MaliciousFile")
        assert pb.name == "Ransomware / Destructive Activity"

    def test_selects_ransomware_playbook_for_backdoor(self):
        pb = select_playbook(finding_type="Backdoor:EC2/DenialOfService.Dns")
        assert pb.name == "Ransomware / Destructive Activity"

    def test_selects_ransomware_playbook_via_description(self):
        pb = select_playbook(description="Trojan activity detected on the instance")
        assert pb.name == "Ransomware / Destructive Activity"

    # ---- Fallback to general ----
    def test_falls_back_to_general_for_unknown_type(self):
        pb = select_playbook(finding_type="SomethingNew:Resource/Custom")
        assert pb.name == "GuardDuty General"

    def test_falls_back_to_general_with_empty_input(self):
        pb = select_playbook()
        assert pb.name == "GuardDuty General"

    # ---- Case insensitivity ----
    def test_matching_is_case_insensitive(self):
        pb = select_playbook(finding_type="cryptocurrency:ec2/bitcointool.b!dns")
        assert pb.name == "Ransomware / Destructive Activity"
