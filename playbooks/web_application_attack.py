"""
playbooks/web_application_attack.py

Playbook for web-application attacks targeting public-facing EC2 workloads
behind an Application Load Balancer (ALB) and AWS WAF.

Covers exploitation of public-facing applications including SQL injection,
command injection, Server-Side Request Forgery (SSRF) targeting the EC2 IMDS,
and web-shell deployment.  Draws on ALB access logs and WAF logs in addition
to standard GuardDuty and CloudTrail sources.
"""

from __future__ import annotations

from playbooks.base import Playbook

WEB_APPLICATION_ATTACK = Playbook(
    name="Web Application Attack (ALB / WAF)",
    description=(
        "Investigates exploitation of public-facing web applications running "
        "behind an AWS Application Load Balancer (ALB) and WAF, including "
        "SQL injection, command injection, SSRF attacks targeting the EC2 "
        "Instance Metadata Service, and web-shell uploads.  Draws on ALB "
        "access logs and WAF logs alongside GuardDuty and CloudTrail.  Also "
        "covers port-scanning and port-probe reconnaissance findings (Recon:EC2)."
    ),
    finding_type_patterns=[
        "MetadataDNSRebind",
        "Recon:EC2",
    ],
    investigation_steps=[
        "Identify the target EC2 instance or Auto Scaling group and the ALB in front of it.",
        "Review WAF logs for blocked and allowed requests matching SQL injection, XSS, or path-traversal rule groups around the time of the alert.",
        "Examine ALB access logs for anomalous URI patterns: directory traversal (../), shell metacharacters, or requests to /etc/passwd, /proc/self, or IMDS URLs.",
        "Check CloudWatch application logs for evidence of command injection or web-shell execution (unexpected child processes spawned by the web server).",
        "Determine whether any SSRF attempt reached http://169.254.169.254/ by searching ALB and VPC Flow Logs for requests to 169.254.169.254.",
        "If a web shell is suspected, search the instance filesystem (via SSM Run Command) for recently modified PHP, JSP, or ASPX files.",
        "Trace any IAM API calls made using credentials obtained through SSRF-to-IMDS (CloudTrail sourceIPAddress = instance private IP).",
        "Assess whether the WAF was in detection (count) mode rather than block mode, allowing attacks through.",
    ],
    key_indicators=[
        "WAF rule matches for SQL injection (SQLi), cross-site scripting (XSS), or remote file inclusion patterns",
        "ALB access log entries with HTTP 200 responses to requests containing shell metacharacters or path traversal sequences",
        "Outbound HTTP/HTTPS request to 169.254.169.254 from the web-server process (SSRF to IMDS)",
        "Web server spawning unexpected child processes (e.g., bash, python, curl) visible in CloudWatch or audit logs",
        "Newly uploaded script files (.php, .jsp, .aspx, .py) in the web root with recent modification timestamps",
        "CloudTrail API calls sourced from the EC2 instance's private IP using IAM role credentials (post-SSRF)",
        "WAF configured in COUNT mode – attacks logged but not blocked",
        "Unusual outbound connections from the web server to attacker-controlled infrastructure",
    ],
    response_actions=[
        "Switch WAF from COUNT to BLOCK mode for all core rule groups immediately",
        "Isolate the compromised EC2 instance by replacing its security group with a deny-all group",
        "Enforce IMDSv2 (HttpTokens=required) on all EC2 instances to prevent SSRF-to-IMDS exploitation",
        "Revoke IAM role credentials if SSRF-to-IMDS exfiltration is confirmed",
        "Remove or quarantine any identified web shells from the instance filesystem",
        "Enable WAF managed rule groups: AWSManagedRulesCommonRuleSet, AWSManagedRulesSQLiRuleSet, and AWSManagedRulesKnownBadInputsRuleSet",
        "Review and restrict ALB target group health-check paths and response codes to reduce reconnaissance surface",
        "Capture an EBS snapshot and ALB/WAF logs archive for forensic evidence before remediation",
    ],
    mitre_techniques=[
        "T1190",      # Exploit Public-Facing Application
        "T1505.003",  # Server Software Component – Web Shell
        "T1059",      # Command and Scripting Interpreter
        "T1552.005",  # Unsecured Credentials – Cloud Instance Metadata API (via SSRF)
        "T1190",      # Exploit Public-Facing Application (SQL injection / command injection)
        "T1071.001",  # Application Layer Protocol – Web Protocols (C2 over HTTP/S)
    ],
    data_sources=[
        "guardduty",
        "waf",
        "alb",
        "cloudwatch",
        "cloudtrail",
        "ec2",
    ],
)
