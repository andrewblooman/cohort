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
from playbooks.ec2_credential_access import EC2_CREDENTIAL_ACCESS
from playbooks.ec2_persistence import EC2_PERSISTENCE
from playbooks.ec2_ssh_brute_force import EC2_SSH_BRUTE_FORCE
from playbooks.guardduty_general import GUARDDUTY_GENERAL
from playbooks.iam_privilege_escalation import IAM_PRIVILEGE_ESCALATION
from playbooks.kubernetes_container import KUBERNETES_CONTAINER
from playbooks.ransomware import RANSOMWARE
from playbooks.rds_credential_access import RDS_CREDENTIAL_ACCESS
from playbooks.registry import get_all_playbooks, select_playbook
from playbooks.s3_data_security import S3_DATA_SECURITY
from playbooks.web_application_attack import WEB_APPLICATION_ATTACK


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
# New EC2 / web-layer playbook definitions
# ---------------------------------------------------------------------------

class TestEC2CredentialAccessPlaybook:
    def test_has_name_and_description(self):
        assert EC2_CREDENTIAL_ACCESS.name == "EC2 Credential Access"
        assert len(EC2_CREDENTIAL_ACCESS.description) > 0

    def test_has_finding_type_patterns(self):
        assert len(EC2_CREDENTIAL_ACCESS.finding_type_patterns) > 0
        assert "CredentialAccess:EC2" in EC2_CREDENTIAL_ACCESS.finding_type_patterns

    def test_has_investigation_steps(self):
        assert len(EC2_CREDENTIAL_ACCESS.investigation_steps) > 0

    def test_has_mitre_techniques(self):
        assert "T1003.008" in EC2_CREDENTIAL_ACCESS.mitre_techniques
        assert "T1552.005" in EC2_CREDENTIAL_ACCESS.mitre_techniques

    def test_has_data_sources(self):
        assert "cloudwatch" in EC2_CREDENTIAL_ACCESS.data_sources
        assert "cloudtrail" in EC2_CREDENTIAL_ACCESS.data_sources
        assert "ec2" in EC2_CREDENTIAL_ACCESS.data_sources


class TestEC2SSHBruteForcePlaybook:
    def test_has_name_and_description(self):
        assert EC2_SSH_BRUTE_FORCE.name == "EC2 SSH / RDP Brute Force"
        assert len(EC2_SSH_BRUTE_FORCE.description) > 0

    def test_has_finding_type_patterns(self):
        assert len(EC2_SSH_BRUTE_FORCE.finding_type_patterns) > 0
        assert "UnauthorizedAccess:EC2/SSHBruteForce" in EC2_SSH_BRUTE_FORCE.finding_type_patterns
        assert "UnauthorizedAccess:EC2/RDPBruteForce" in EC2_SSH_BRUTE_FORCE.finding_type_patterns

    def test_has_investigation_steps(self):
        assert len(EC2_SSH_BRUTE_FORCE.investigation_steps) > 0

    def test_has_mitre_techniques(self):
        assert "T1110" in EC2_SSH_BRUTE_FORCE.mitre_techniques
        assert "T1021.004" in EC2_SSH_BRUTE_FORCE.mitre_techniques

    def test_has_data_sources(self):
        assert "vpc_flow_logs" in EC2_SSH_BRUTE_FORCE.data_sources
        assert "cloudwatch" in EC2_SSH_BRUTE_FORCE.data_sources
        assert "ec2" in EC2_SSH_BRUTE_FORCE.data_sources


class TestWebApplicationAttackPlaybook:
    def test_has_name_and_description(self):
        assert WEB_APPLICATION_ATTACK.name == "Web Application Attack (ALB / WAF)"
        assert len(WEB_APPLICATION_ATTACK.description) > 0

    def test_has_finding_type_patterns(self):
        assert len(WEB_APPLICATION_ATTACK.finding_type_patterns) > 0
        assert "MetadataDNSRebind" in WEB_APPLICATION_ATTACK.finding_type_patterns
        assert "Recon:EC2" in WEB_APPLICATION_ATTACK.finding_type_patterns

    def test_has_investigation_steps(self):
        assert len(WEB_APPLICATION_ATTACK.investigation_steps) > 0

    def test_has_mitre_techniques(self):
        assert "T1190" in WEB_APPLICATION_ATTACK.mitre_techniques
        assert "T1505.003" in WEB_APPLICATION_ATTACK.mitre_techniques

    def test_has_data_sources(self):
        assert "waf" in WEB_APPLICATION_ATTACK.data_sources
        assert "alb" in WEB_APPLICATION_ATTACK.data_sources
        assert "ec2" in WEB_APPLICATION_ATTACK.data_sources


class TestEC2PersistencePlaybook:
    def test_has_name_and_description(self):
        assert EC2_PERSISTENCE.name == "EC2 Persistence"
        assert len(EC2_PERSISTENCE.description) > 0

    def test_has_finding_type_patterns(self):
        assert len(EC2_PERSISTENCE.finding_type_patterns) > 0
        assert "Persistence:EC2" in EC2_PERSISTENCE.finding_type_patterns

    def test_has_investigation_steps(self):
        assert len(EC2_PERSISTENCE.investigation_steps) > 0

    def test_has_mitre_techniques(self):
        assert "T1098.004" in EC2_PERSISTENCE.mitre_techniques
        assert "T1053.003" in EC2_PERSISTENCE.mitre_techniques

    def test_has_data_sources(self):
        assert "cloudtrail" in EC2_PERSISTENCE.data_sources
        assert "cloudwatch" in EC2_PERSISTENCE.data_sources
        assert "ec2" in EC2_PERSISTENCE.data_sources

    def test_defense_evasion_patterns_present(self):
        assert "DefenseEvasion:EC2" in EC2_PERSISTENCE.finding_type_patterns
        assert "DefenseEvasion:Runtime" in EC2_PERSISTENCE.finding_type_patterns
        assert "Persistence:Runtime" in EC2_PERSISTENCE.finding_type_patterns


class TestS3DataSecurityPlaybook:
    def test_has_name_and_description(self):
        assert S3_DATA_SECURITY.name == "S3 Data Security"
        assert len(S3_DATA_SECURITY.description) > 0

    def test_has_finding_type_patterns(self):
        assert len(S3_DATA_SECURITY.finding_type_patterns) > 0
        assert "Discovery:S3" in S3_DATA_SECURITY.finding_type_patterns
        assert "Exfiltration:S3" in S3_DATA_SECURITY.finding_type_patterns
        assert "Impact:S3" in S3_DATA_SECURITY.finding_type_patterns
        assert "Policy:S3" in S3_DATA_SECURITY.finding_type_patterns
        assert "UnauthorizedAccess:S3" in S3_DATA_SECURITY.finding_type_patterns
        assert "AttackSequence:S3" in S3_DATA_SECURITY.finding_type_patterns

    def test_has_investigation_steps(self):
        assert len(S3_DATA_SECURITY.investigation_steps) > 0

    def test_has_mitre_techniques(self):
        assert "T1530" in S3_DATA_SECURITY.mitre_techniques
        assert "T1619" in S3_DATA_SECURITY.mitre_techniques

    def test_has_data_sources(self):
        assert "cloudtrail" in S3_DATA_SECURITY.data_sources
        assert "s3" in S3_DATA_SECURITY.data_sources


class TestKubernetesContainerPlaybook:
    def test_has_name_and_description(self):
        assert KUBERNETES_CONTAINER.name == "Kubernetes / Container Threat"
        assert len(KUBERNETES_CONTAINER.description) > 0

    def test_has_finding_type_patterns(self):
        assert len(KUBERNETES_CONTAINER.finding_type_patterns) > 0
        assert ":Kubernetes/" in KUBERNETES_CONTAINER.finding_type_patterns
        assert "Execution:Container" in KUBERNETES_CONTAINER.finding_type_patterns
        assert "Execution:ECS" in KUBERNETES_CONTAINER.finding_type_patterns
        assert "PrivilegeEscalation:Runtime" in KUBERNETES_CONTAINER.finding_type_patterns
        assert "AttackSequence:EKS" in KUBERNETES_CONTAINER.finding_type_patterns

    def test_has_investigation_steps(self):
        assert len(KUBERNETES_CONTAINER.investigation_steps) > 0

    def test_has_mitre_techniques(self):
        assert "T1610" in KUBERNETES_CONTAINER.mitre_techniques
        assert "T1611" in KUBERNETES_CONTAINER.mitre_techniques

    def test_has_data_sources(self):
        assert "cloudtrail" in KUBERNETES_CONTAINER.data_sources
        assert "eks" in KUBERNETES_CONTAINER.data_sources


class TestRDSCredentialAccessPlaybook:
    def test_has_name_and_description(self):
        assert RDS_CREDENTIAL_ACCESS.name == "RDS Database Credential Access"
        assert len(RDS_CREDENTIAL_ACCESS.description) > 0

    def test_has_finding_type_patterns(self):
        assert len(RDS_CREDENTIAL_ACCESS.finding_type_patterns) > 0
        assert "CredentialAccess:RDS" in RDS_CREDENTIAL_ACCESS.finding_type_patterns
        assert "Discovery:RDS" in RDS_CREDENTIAL_ACCESS.finding_type_patterns

    def test_has_investigation_steps(self):
        assert len(RDS_CREDENTIAL_ACCESS.investigation_steps) > 0

    def test_has_mitre_techniques(self):
        assert "T1110" in RDS_CREDENTIAL_ACCESS.mitre_techniques

    def test_has_data_sources(self):
        assert "cloudwatch" in RDS_CREDENTIAL_ACCESS.data_sources
        assert "rds" in RDS_CREDENTIAL_ACCESS.data_sources


# ---------------------------------------------------------------------------
# Registry / selection logic
# ---------------------------------------------------------------------------

class TestGetAllPlaybooks:
    def test_returns_all_registered_playbooks(self):
        playbooks = get_all_playbooks()
        names = {pb.name for pb in playbooks}
        assert "IAM Privilege Escalation" in names
        assert "Ransomware / Destructive Activity" in names
        assert "EC2 Credential Access" in names
        assert "EC2 SSH / RDP Brute Force" in names
        assert "Web Application Attack (ALB / WAF)" in names
        assert "EC2 Persistence" in names
        assert "S3 Data Security" in names
        assert "Kubernetes / Container Threat" in names
        assert "RDS Database Credential Access" in names
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

    # ---- EC2 credential access ----
    def test_selects_ec2_credential_access_for_credential_access_ec2(self):
        pb = select_playbook(finding_type="CredentialAccess:EC2/UnusualProcesses")
        assert pb.name == "EC2 Credential Access"

    def test_selects_ec2_credential_access_for_instance_credential_exfiltration(self):
        pb = select_playbook(finding_type="CredentialAccess:EC2/AnomalousBehavior")
        assert pb.name == "EC2 Credential Access"

    def test_selects_ec2_credential_access_via_description(self):
        pb = select_playbook(description="CredentialAccess:EC2 activity detected: possible /etc/shadow dump")
        assert pb.name == "EC2 Credential Access"

    # ---- EC2 SSH brute force ----
    def test_selects_ssh_brute_force_for_ssh_brute_force_finding(self):
        pb = select_playbook(finding_type="UnauthorizedAccess:EC2/SSHBruteForce")
        assert pb.name == "EC2 SSH / RDP Brute Force"

    def test_selects_ssh_brute_force_for_rdp_brute_force_finding(self):
        pb = select_playbook(finding_type="UnauthorizedAccess:EC2/RDPBruteForce")
        assert pb.name == "EC2 SSH / RDP Brute Force"

    def test_selects_ssh_brute_force_for_tor_client(self):
        pb = select_playbook(finding_type="UnauthorizedAccess:EC2/TorClient")
        assert pb.name == "EC2 SSH / RDP Brute Force"

    # ---- Web application attack ----
    def test_selects_web_application_attack_for_metadata_dns_rebind(self):
        pb = select_playbook(finding_type="UnauthorizedAccess:EC2/MetadataDNSRebind")
        assert pb.name == "Web Application Attack (ALB / WAF)"

    def test_selects_web_application_attack_for_port_probe(self):
        pb = select_playbook(finding_type="Recon:EC2/PortProbeUnprotectedPort")
        assert pb.name == "Web Application Attack (ALB / WAF)"

    # ---- EC2 persistence ----
    def test_selects_ec2_persistence_for_persistence_ec2(self):
        pb = select_playbook(finding_type="Persistence:EC2/AnomalousBehavior")
        assert pb.name == "EC2 Persistence"

    def test_selects_ec2_persistence_for_behavior_finding(self):
        pb = select_playbook(finding_type="Behavior:EC2/NetworkPortUnusual")
        assert pb.name == "EC2 Persistence"

    def test_selects_ec2_persistence_for_defense_evasion_ec2(self):
        pb = select_playbook(finding_type="DefenseEvasion:EC2/UnusualDoHActivity")
        assert pb.name == "EC2 Persistence"

    def test_selects_ec2_persistence_for_defense_evasion_runtime(self):
        pb = select_playbook(finding_type="DefenseEvasion:Runtime/ProcessInjection.Proc")
        assert pb.name == "EC2 Persistence"

    def test_selects_ec2_persistence_for_persistence_runtime(self):
        pb = select_playbook(finding_type="Persistence:Runtime/SuspiciousCommand")
        assert pb.name == "EC2 Persistence"

    # ---- S3 data security ----
    def test_selects_s3_data_security_for_discovery_s3(self):
        pb = select_playbook(finding_type="Discovery:S3/AnomalousBehavior")
        assert pb.name == "S3 Data Security"

    def test_selects_s3_data_security_for_exfiltration_s3(self):
        pb = select_playbook(finding_type="Exfiltration:S3/MaliciousIPCaller")
        assert pb.name == "S3 Data Security"

    def test_selects_s3_data_security_for_impact_s3(self):
        pb = select_playbook(finding_type="Impact:S3/AnomalousBehavior.Delete")
        assert pb.name == "S3 Data Security"

    def test_selects_s3_data_security_for_policy_s3(self):
        pb = select_playbook(finding_type="Policy:S3/BucketPublicAccessGranted")
        assert pb.name == "S3 Data Security"

    def test_selects_s3_data_security_for_attack_sequence_s3(self):
        pb = select_playbook(finding_type="AttackSequence:S3/CompromisedData")
        assert pb.name == "S3 Data Security"

    # ---- Kubernetes / container ----
    def test_selects_kubernetes_container_for_kubernetes_finding(self):
        pb = select_playbook(finding_type="CredentialAccess:Kubernetes/MaliciousIPCaller")
        assert pb.name == "Kubernetes / Container Threat"

    def test_selects_kubernetes_container_for_execution_ecs(self):
        pb = select_playbook(finding_type="Execution:ECS/MaliciousFile")
        assert pb.name == "Kubernetes / Container Threat"

    def test_selects_kubernetes_container_for_execution_container(self):
        pb = select_playbook(finding_type="Execution:Container/SuspiciousFile")
        assert pb.name == "Kubernetes / Container Threat"

    def test_selects_kubernetes_container_for_privilege_escalation_runtime(self):
        pb = select_playbook(finding_type="PrivilegeEscalation:Runtime/ElevationToRoot")
        assert pb.name == "Kubernetes / Container Threat"

    def test_selects_kubernetes_container_for_attack_sequence_eks(self):
        pb = select_playbook(finding_type="AttackSequence:EKS/CompromisedCluster")
        assert pb.name == "Kubernetes / Container Threat"

    # ---- RDS credential access ----
    def test_selects_rds_credential_access_for_rds_brute_force(self):
        pb = select_playbook(finding_type="CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce")
        assert pb.name == "RDS Database Credential Access"

    def test_selects_rds_credential_access_for_tor_login(self):
        pb = select_playbook(finding_type="CredentialAccess:RDS/TorIPCaller.SuccessfulLogin")
        assert pb.name == "RDS Database Credential Access"

    def test_selects_rds_credential_access_for_discovery_rds(self):
        pb = select_playbook(finding_type="Discovery:RDS/MaliciousIPCaller")
        assert pb.name == "RDS Database Credential Access"

    # ---- IAM new patterns ----
    def test_selects_iam_for_defense_evasion_iam_user(self):
        pb = select_playbook(finding_type="DefenseEvasion:IAMUser/AnomalousBehavior")
        assert pb.name == "IAM Privilege Escalation"

    def test_selects_iam_for_stealth_iam_user(self):
        pb = select_playbook(finding_type="Stealth:IAMUser/CloudTrailLoggingDisabled")
        assert pb.name == "IAM Privilege Escalation"

    def test_selects_iam_for_discovery_iam_user(self):
        pb = select_playbook(finding_type="Discovery:IAMUser/AnomalousBehavior")
        assert pb.name == "IAM Privilege Escalation"

    def test_selects_iam_for_attack_sequence_iam(self):
        pb = select_playbook(finding_type="AttackSequence:IAM/CompromisedCredentials")
        assert pb.name == "IAM Privilege Escalation"

    # ---- PrivilegeEscalation:IAMUser no longer uses broad pattern ----
    def test_privilege_escalation_iam_user_still_matches_iam(self):
        pb = select_playbook(finding_type="PrivilegeEscalation:IAMUser/AnomalousBehavior")
        assert pb.name == "IAM Privilege Escalation"

    # ---- Ransomware new patterns ----
    def test_selects_ransomware_for_execution_runtime(self):
        pb = select_playbook(finding_type="Execution:Runtime/ReverseShell")
        assert pb.name == "Ransomware / Destructive Activity"

    def test_selects_ransomware_for_impact_runtime(self):
        pb = select_playbook(finding_type="Impact:Runtime/CryptoMinerExecuted")
        assert pb.name == "Ransomware / Destructive Activity"

    def test_selects_ransomware_for_attack_sequence_ec2(self):
        pb = select_playbook(finding_type="AttackSequence:EC2/CompromisedInstanceGroup")
        assert pb.name == "Ransomware / Destructive Activity"

    def test_selects_ransomware_for_unauthorized_access_lambda(self):
        pb = select_playbook(finding_type="UnauthorizedAccess:Lambda/TorClient")
        assert pb.name == "Ransomware / Destructive Activity"

    # ---- Web app new patterns ----
    def test_selects_web_app_for_recon_ec2_portscan(self):
        pb = select_playbook(finding_type="Recon:EC2/Portscan")
        assert pb.name == "Web Application Attack (ALB / WAF)"

    def test_selects_web_app_for_recon_ec2_emr_port(self):
        pb = select_playbook(finding_type="Recon:EC2/PortProbeEMRUnprotectedPort")
        assert pb.name == "Web Application Attack (ALB / WAF)"

    def test_selects_web_app_for_metadata_dns_rebind_runtime(self):
        pb = select_playbook(finding_type="UnauthorizedAccess:Runtime/MetadataDNSRebind")
        assert pb.name == "Web Application Attack (ALB / WAF)"

    # ---- Runtime Tor goes to SSH brute force ----
    def test_selects_ssh_brute_force_for_runtime_tor_client(self):
        pb = select_playbook(finding_type="UnauthorizedAccess:Runtime/TorClient")
        assert pb.name == "EC2 SSH / RDP Brute Force"

    # ---- CredentialAccess:Runtime goes to EC2 credential access ----
    def test_selects_ec2_credential_access_for_runtime_credential_access(self):
        pb = select_playbook(finding_type="CredentialAccess:Runtime/SuspiciousCommand")
        assert pb.name == "EC2 Credential Access"
