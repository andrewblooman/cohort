"""
playbooks/kubernetes_container.py

Playbook for Kubernetes, Amazon EKS, Amazon ECS, and container security incidents.

Covers all GuardDuty findings involving Kubernetes audit logs, EKS runtime
monitoring, ECS runtime detections, container execution findings, and
AttackSequence findings for EKS and ECS clusters.  Also handles
PrivilegeEscalation:Runtime findings which represent container-escape and
host-privilege-escalation techniques detected by GuardDuty Runtime Monitoring.
"""

from __future__ import annotations

from playbooks.base import Playbook

KUBERNETES_CONTAINER = Playbook(
    name="Kubernetes / Container Threat",
    description=(
        "Investigates GuardDuty findings targeting Kubernetes (EKS), ECS, "
        "and containerised workloads, including credential access via Kubernetes "
        "API, privilege escalation and container escape, anomalous workload "
        "deployment, execution inside pods, policy violations, defense evasion, "
        "and runtime-detected privilege escalation (process injection, Docker "
        "socket access, cgroups escape, runc escape).  Covers all "
        ":Kubernetes/, Execution:ECS, Execution:Container, PrivilegeEscalation:Runtime, "
        "and AttackSequence:EKS / AttackSequence:ECS finding types."
    ),
    finding_type_patterns=[
        ":Kubernetes/",
        "Execution:Container",
        "Execution:ECS",
        "PrivilegeEscalation:Runtime",
        "AttackSequence:EKS",
        "AttackSequence:ECS",
    ],
    investigation_steps=[
        "Identify the affected EKS cluster or ECS cluster/task and the Kubernetes namespace or ECS service involved.",
        "Review EKS audit logs in CloudWatch or CloudTrail for the API calls that triggered the finding (e.g. exec, create RoleBinding, deploy workload).",
        "Determine the Kubernetes service account or IAM role that performed the action; check if it has overly broad RBAC permissions.",
        "For Execution findings: identify the container image, registry, and command executed; check for known-malicious or unexpected images.",
        "For PrivilegeEscalation:Runtime findings: determine the container that triggered the event and whether it ran as privileged or with a sensitive host mount.",
        "Check for unauthorised ClusterRoleBinding or RoleBinding creations that may grant admin privileges to a compromised service account.",
        "Examine VPC Flow Logs and container network policies for lateral movement between pods or egress to external C2 infrastructure.",
        "Review node IAM instance profiles: if a pod gained host access, it may have access to the node's IAM credentials via IMDS.",
        "Assess whether the ECS task execution role or task role was abused for privilege escalation beyond container boundaries.",
        "Check AttackSequence findings for correlated events spanning multiple GuardDuty detections across the same cluster.",
    ],
    key_indicators=[
        "kubectl exec or ECS exec into a running container from an unexpected principal or IP",
        "New ClusterRoleBinding granting cluster-admin to an unexpected service account or user",
        "Privileged container or container with hostPID / hostNetwork / hostPath mounted",
        "Execution of unexpected binaries inside a container (GuardDuty Runtime new binary execution)",
        "Docker socket (/var/run/docker.sock) accessed from within a container",
        "cgroups release_agent or runc escape technique detected by Runtime Monitoring",
        "Kubernetes API called from a Tor exit node or known-malicious IP",
        "Anonymous access to the Kubernetes API (system:anonymous principal)",
        "AttackSequence finding correlating multiple stages of a cluster compromise",
        "Container image pulled from an unrecognised or public registry during an incident",
    ],
    response_actions=[
        "Immediately cordon and drain the affected node to prevent new pods from scheduling there",
        "Terminate or stop the suspicious container/task; capture its filesystem and logs before deletion",
        "Revoke the Kubernetes service account token and the IAM task/instance role credentials",
        "Remove any unauthorised ClusterRoleBinding or RoleBinding objects",
        "Enable or tighten Kubernetes Network Policies to restrict pod-to-pod and pod-to-internet traffic",
        "Enforce Pod Security Admission (Restricted policy) to prevent privileged containers",
        "Rotate the EKS cluster authentication credentials and audit all kubeconfig files",
        "Scan all running container images with ECR Malware Protection or an image scanner (Trivy, Snyk)",
        "Review and lock down ECS task execution roles and task roles to least-privilege",
        "Enable GuardDuty Runtime Monitoring on all EKS node groups and ECS tasks if not already active",
    ],
    mitre_techniques=[
        "T1610",      # Deploy Container
        "T1611",      # Escape to Host
        "T1552.007",  # Unsecured Credentials – Container API
        "T1613",      # Container and Resource Discovery
        "T1098.006",  # Account Manipulation – Additional Container Cluster Roles
        "T1059.004",  # Command and Scripting Interpreter – Unix Shell (exec in pod)
        "T1548",      # Abuse Elevation Control Mechanism (privileged container / cgroups escape)
        "T1046",      # Network Service Discovery (lateral movement between pods)
    ],
    data_sources=[
        "guardduty",
        "cloudtrail",
        "cloudwatch",
        "eks",
        "vpc_flow_logs",
    ],
)
