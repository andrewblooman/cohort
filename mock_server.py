#!/usr/bin/env python3
"""
Cohort UI Mock Server
---------------------
Serves the UI on http://localhost:8080 with realistic fake investigation data.

Usage:
    python mock_server.py

Then open http://localhost:8080 in your browser.
"""

import json
import os
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT = 8080
UI_DIR = os.path.join(os.path.dirname(__file__), "ui")
ASSETS_DIR = os.path.join(os.path.dirname(__file__), "assets")

# ── Mock data ───────────────────────────────────────────────────────────────

INVESTIGATIONS = [
    {
        "ticket_number":  "inc-0042",
        "alert_type":     "UnauthorizedAccess:EC2/TorIPCaller",
        "severity":       "HIGH",
        "verdict":        "TRUE_POSITIVE",
        "status":         "SUCCEEDED",
        "start_date":     "2024-03-20T14:32:11Z",
        "account_id":     "123456789012",
        "region":         "eu-west-1",
    },
    {
        "ticket_number":  "inc-0043",
        "alert_type":     "PrivilegeEscalation:IAMUser/AdministrativePermissions",
        "severity":       "HIGH",
        "verdict":        "INCONCLUSIVE",
        "status":         "RUNNING",
        "start_date":     "2024-03-21T08:17:44Z",
        "account_id":     "123456789012",
        "region":         "us-east-1",
    },
    {
        "ticket_number":  "inc-0044",
        "alert_type":     "Recon:EC2/PortProbeUnprotectedPort",
        "severity":       "MEDIUM",
        "verdict":        "FALSE_POSITIVE",
        "status":         "SUCCEEDED",
        "start_date":     "2024-03-21T11:05:29Z",
        "account_id":     "987654321098",
        "region":         "eu-west-2",
    },
    {
        "ticket_number":  "inc-0045",
        "alert_type":     "Behavior:EC2/NetworkPortUnusual",
        "severity":       "MEDIUM",
        "verdict":        None,
        "status":         "RUNNING",
        "start_date":     "2024-03-22T07:55:02Z",
        "account_id":     "123456789012",
        "region":         "eu-west-1",
    },
    {
        "ticket_number":  "inc-0046",
        "alert_type":     "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "severity":       "HIGH",
        "verdict":        "TRUE_POSITIVE",
        "status":         "SUCCEEDED",
        "start_date":     "2024-03-22T09:12:55Z",
        "account_id":     "123456789012",
        "region":         "ap-southeast-1",
    },
    {
        "ticket_number":  "inc-0047",
        "alert_type":     "Trojan:EC2/BlackholeTraffic",
        "severity":       "HIGH",
        "verdict":        None,
        "status":         "FAILED",
        "start_date":     "2024-03-22T10:44:18Z",
        "account_id":     "555555555555",
        "region":         "eu-west-1",
    },
    {
        "ticket_number":  "inc-0048",
        "alert_type":     "Policy:S3/BucketPublicAccessGranted",
        "severity":       "LOW",
        "verdict":        "FALSE_POSITIVE",
        "status":         "SUCCEEDED",
        "start_date":     "2024-03-22T13:01:37Z",
        "account_id":     "123456789012",
        "region":         "eu-west-1",
    },
]

INVESTIGATION_DETAILS = {
    "inc-0042": {
        "execution": {"status": "SUCCEEDED"},
        "pending_approval": None,
        "incident_summary": {
            "incident": {
                "ticket_number":  "inc-0042",
                "alert_type":     "UnauthorizedAccess:EC2/TorIPCaller",
                "severity":       "HIGH",
                "finding_id":     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "account_id":     "123456789012",
                "region":         "eu-west-1",
                "resource_type":  "Instance",
                "resource_id":    "i-0a1b2c3d4e5f67890",
            },
            "analysis": {
                "verdict":          "TRUE_POSITIVE",
                "confidence":       "HIGH",
                "playbook":         "EC2_CREDENTIAL_ACCESS",
                "model_id":         "us.anthropic.claude-sonnet-4-5-20250514-v1:0",
                "analysis_timestamp": "2024-03-20T14:35:44Z",
                "threat_summary": (
                    "EC2 instance i-0a1b2c3d4e5f67890 in eu-west-1 established outbound connections "
                    "to known Tor exit nodes (185.220.101.47, 185.220.101.52) over a 23-minute window. "
                    "CloudTrail shows the instance IAM role was used to call DescribeInstances and "
                    "GetSecretValue 47 times in the preceding hour, suggesting active credential harvesting "
                    "prior to exfiltration over the anonymised channel."
                ),
                "reasoning": (
                    "ANALYSIS CHAIN OF THOUGHT\n"
                    "==========================\n\n"
                    "1. ALERT CONTEXT\n"
                    "   GuardDuty flagged outbound traffic from i-0a1b2c3d4e5f67890 to Tor exit nodes.\n"
                    "   Finding type: UnauthorizedAccess:EC2/TorIPCaller (severity 8.2/10)\n\n"
                    "2. CLOUDTRAIL REVIEW (last 2h)\n"
                    "   14:09 - AssumeRole: arn:aws:iam::123456789012:role/ec2-app-role\n"
                    "   14:11 - DescribeInstances x12 (unusual for app workload)\n"
                    "   14:14 - GetSecretValue: prod/db-master-password (SUCCESS)\n"
                    "   14:14 - GetSecretValue: prod/api-keys (SUCCESS)\n"
                    "   14:16 - DescribeSecurityGroups x8\n"
                    "   14:18 - ListBuckets (SUCCESS) — no prior S3 usage from this role\n"
                    "   14:32 - GuardDuty finding generated\n\n"
                    "3. VPC FLOW LOG ANALYSIS\n"
                    "   Destination IPs 185.220.101.47:443 and 185.220.101.52:443 confirmed Tor exit nodes\n"
                    "   via threat intel feed. Total outbound bytes: 2.3 MB over 23 minutes.\n"
                    "   No legitimate business justification for Tor connectivity.\n\n"
                    "4. EC2 METADATA\n"
                    "   Instance launched 47 days ago as part of web-tier ASG.\n"
                    "   Last patched: 2024-01-15. CVE-2024-1086 (Linux kernel) unpatched.\n"
                    "   User data script references external package repository — possible supply chain vector.\n\n"
                    "5. VERDICT REASONING\n"
                    "   The combination of: (a) active Tor exfiltration, (b) secret enumeration via\n"
                    "   Secrets Manager, (c) unpatched critical CVE, and (d) lateral recon activity\n"
                    "   provides HIGH confidence this is an active compromise with credential exfiltration.\n"
                    "   This is classified TRUE_POSITIVE."
                ),
                "indicators_of_compromise": [
                    "Outbound connections to Tor exit node 185.220.101.47:443",
                    "Outbound connections to Tor exit node 185.220.101.52:443",
                    "GetSecretValue called on prod/db-master-password at 14:14 UTC",
                    "GetSecretValue called on prod/api-keys at 14:14 UTC",
                    "Unusual ListBuckets call from ec2-app-role (no prior S3 usage)",
                    "Unpatched CVE-2024-1086 on instance i-0a1b2c3d4e5f67890",
                ],
                "false_positive_indicators": [],
                "mitre_attack_techniques": [
                    "T1041 – Exfiltration Over C2 Channel",
                    "T1552.001 – Credentials In Files",
                    "T1555 – Credentials from Password Stores",
                    "T1046 – Network Service Discovery",
                    "T1083 – File and Directory Discovery",
                ],
                "proposed_actions": [
                    "Isolate instance i-0a1b2c3d4e5f67890 by replacing its security group with deny-all",
                    "Rotate all secrets accessed: prod/db-master-password, prod/api-keys",
                    "Revoke temporary credentials for role ec2-app-role issued before 14:32 UTC",
                    "Capture memory dump and disk snapshot of i-0a1b2c3d4e5f67890 for forensics",
                    "Block Tor exit node IP ranges in NACL for eu-west-1 VPC (vpc-0abc12345)",
                    "Notify DBA team of potential DB credential compromise",
                ],
            },
            "artifacts": {
                "s3_bucket": "cohort-artifacts-prod-eu-west-1",
            },
        },
    },

    "inc-0043": {
        "execution": {"status": "RUNNING"},
        "pending_approval": {
            "task_token": "mock-task-token-abc123xyz",
            "ticket_number": "inc-0043",
        },
        "incident_summary": {
            "incident": {
                "ticket_number":  "inc-0043",
                "alert_type":     "PrivilegeEscalation:IAMUser/AdministrativePermissions",
                "severity":       "HIGH",
                "finding_id":     "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                "account_id":     "123456789012",
                "region":         "us-east-1",
                "resource_type":  "IAMUser",
                "resource_id":    "AIDA4SAMPLEUSERID0042",
            },
            "analysis": {
                "verdict":          "INCONCLUSIVE",
                "confidence":       "MEDIUM",
                "playbook":         "IAM_PRIVILEGE_ESCALATION",
                "model_id":         "us.anthropic.claude-sonnet-4-5-20250514-v1:0",
                "analysis_timestamp": "2024-03-21T08:21:09Z",
                "threat_summary": (
                    "IAM user 'deploy-svc-prod' attached the AdministratorAccess policy to its own user "
                    "at 08:11 UTC. The action originated from IP 203.0.113.77, which has no prior history "
                    "with this account. Insufficient CloudTrail coverage in us-east-1 prevents full "
                    "attribution — the finding is INCONCLUSIVE pending manual analyst review."
                ),
                "reasoning": (
                    "ANALYSIS CHAIN OF THOUGHT\n"
                    "==========================\n\n"
                    "1. ALERT CONTEXT\n"
                    "   GuardDuty detected IAMUser/AdministrativePermissions for user deploy-svc-prod.\n"
                    "   Source IP: 203.0.113.77 — first seen in account history.\n\n"
                    "2. CLOUDTRAIL REVIEW\n"
                    "   08:09 - ConsoleLogin SUCCESS from 203.0.113.77 (MFA: false)\n"
                    "   08:11 - AttachUserPolicy: AdministratorAccess attached to deploy-svc-prod\n"
                    "   08:12 - CreateAccessKey for deploy-svc-prod (new key pair created)\n"
                    "   Note: CloudTrail logging has a gap 07:55–08:09 (delivery delay or tampering?)\n\n"
                    "3. IP REPUTATION\n"
                    "   203.0.113.77 — not listed in major threat feeds, but is a residential ISP\n"
                    "   address in Bucharest, Romania. deploy-svc-prod has historically only been\n"
                    "   accessed from 10.0.0.0/8 (internal CI/CD runners).\n\n"
                    "4. LIMITATIONS\n"
                    "   Cannot confirm whether this was an authorised emergency change (no change ticket\n"
                    "   found in enrichment data). HR records not accessible for after-hours check.\n"
                    "   Recommend analyst review before taking isolating action.\n\n"
                    "5. VERDICT\n"
                    "   INCONCLUSIVE — high suspicion but insufficient evidence for automated action."
                ),
                "indicators_of_compromise": [
                    "ConsoleLogin without MFA from external IP 203.0.113.77",
                    "AttachUserPolicy: AdministratorAccess self-assigned at 08:11 UTC",
                    "New access key created immediately after privilege escalation",
                    "Source IP 203.0.113.77 — no prior history in account (residential ISP, Bucharest)",
                ],
                "false_positive_indicators": [
                    "No active threat intel hits on source IP",
                    "deploy-svc-prod is a legitimate service account (used by CI/CD pipeline)",
                    "Could be an emergency access scenario by a remote engineer",
                ],
                "mitre_attack_techniques": [
                    "T1078 – Valid Accounts",
                    "T1098.001 – Additional Cloud Credentials",
                    "T1548.005 – Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access",
                ],
                "proposed_actions": [
                    "Suspend access key AKIASAMPLEKEY0042 created at 08:12 UTC",
                    "Detach AdministratorAccess policy from deploy-svc-prod pending investigation",
                    "Require MFA re-enrolment for deploy-svc-prod",
                    "Contact engineer team lead to verify if this was an authorised emergency change",
                ],
            },
            "artifacts": {
                "s3_bucket": "cohort-artifacts-prod-eu-west-1",
            },
        },
    },

    "inc-0044": {
        "execution": {"status": "SUCCEEDED"},
        "pending_approval": None,
        "incident_summary": {
            "incident": {
                "ticket_number":  "inc-0044",
                "alert_type":     "Recon:EC2/PortProbeUnprotectedPort",
                "severity":       "MEDIUM",
                "finding_id":     "c3d4e5f6-a7b8-9012-cdef-123456789012",
                "account_id":     "987654321098",
                "region":         "eu-west-2",
                "resource_type":  "Instance",
                "resource_id":    "i-0f9e8d7c6b5a43210",
            },
            "analysis": {
                "verdict":          "FALSE_POSITIVE",
                "confidence":       "HIGH",
                "playbook":         "GUARDDUTY_GENERAL",
                "model_id":         "us.anthropic.claude-sonnet-4-5-20250514-v1:0",
                "analysis_timestamp": "2024-03-21T11:09:17Z",
                "threat_summary": (
                    "Port probe activity on instance i-0f9e8d7c6b5a43210 originated from "
                    "the organisation's own authorised security scanning service (Tenable Nessus — "
                    "10.0.100.55). This is scheduled weekly vulnerability assessment activity. "
                    "Classified FALSE_POSITIVE."
                ),
                "reasoning": (
                    "ANALYSIS CHAIN OF THOUGHT\n"
                    "==========================\n\n"
                    "1. ALERT CONTEXT\n"
                    "   GuardDuty flagged port probe activity on instance i-0f9e8d7c6b5a43210.\n"
                    "   Ports probed: 22, 80, 443, 3306, 5432, 8080, 8443\n\n"
                    "2. SOURCE IP ANALYSIS\n"
                    "   Source IP: 10.0.100.55 — internal RFC 1918 address.\n"
                    "   Reverse lookup + EC2 tag check: this is 'vuln-scanner-prod' (Tenable Nessus)\n"
                    "   owned by the Security Engineering team.\n\n"
                    "3. CLOUDTRAIL / SCHEDULE\n"
                    "   No suspicious IAM activity. Scan scheduled every Tuesday 11:00–12:00 UTC.\n"
                    "   Alert time 11:05 — within expected scan window.\n\n"
                    "4. VERDICT\n"
                    "   This is authorised internal vulnerability scanning. FALSE_POSITIVE."
                ),
                "indicators_of_compromise": [],
                "false_positive_indicators": [
                    "Source IP 10.0.100.55 is the organisation's Tenable Nessus scanner",
                    "Scan occurred within the scheduled weekly maintenance window (Tue 11:00–12:00 UTC)",
                    "No lateral movement or data access observed post-scan",
                    "EC2 tag on source instance: team=security-engineering, purpose=vuln-scan",
                ],
                "mitre_attack_techniques": [],
                "proposed_actions": [
                    "Add 10.0.100.55 to GuardDuty trusted IP list to suppress future false positives",
                ],
            },
            "artifacts": {
                "s3_bucket": "cohort-artifacts-prod-eu-west-1",
            },
        },
    },

    "inc-0045": {
        "execution": {"status": "RUNNING"},
        "pending_approval": None,
        "incident_summary": {
            "incident": {
                "ticket_number":  "inc-0045",
                "alert_type":     "Behavior:EC2/NetworkPortUnusual",
                "severity":       "MEDIUM",
                "finding_id":     "d4e5f6a7-b8c9-0123-defa-234567890123",
                "account_id":     "123456789012",
                "region":         "eu-west-1",
                "resource_type":  "Instance",
                "resource_id":    "i-0c1d2e3f4a5b67890",
            },
            "analysis": None,
            "artifacts": {
                "s3_bucket": "cohort-artifacts-prod-eu-west-1",
            },
        },
    },

    "inc-0046": {
        "execution": {"status": "SUCCEEDED"},
        "pending_approval": None,
        "incident_summary": {
            "incident": {
                "ticket_number":  "inc-0046",
                "alert_type":     "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                "severity":       "HIGH",
                "finding_id":     "e5f6a7b8-c9d0-1234-efab-345678901234",
                "account_id":     "123456789012",
                "region":         "ap-southeast-1",
                "resource_type":  "Instance",
                "resource_id":    "i-0d2e3f4a5b6c78901",
            },
            "analysis": {
                "verdict":          "TRUE_POSITIVE",
                "confidence":       "HIGH",
                "playbook":         "EC2_CREDENTIAL_ACCESS",
                "model_id":         "us.anthropic.claude-sonnet-4-5-20250514-v1:0",
                "analysis_timestamp": "2024-03-22T09:18:33Z",
                "threat_summary": (
                    "EC2 instance i-0d2e3f4a5b6c78901 in ap-southeast-1 is making repeated DNS lookups "
                    "to pool.supportxmr.com, xmr.pool.minergate.com, and moneroocean.stream — well-known "
                    "Monero mining pool hostnames. CPU utilisation spiked to 98% from a baseline of 12%. "
                    "The instance hosts a public-facing PHP application with an unpatched RCE vulnerability "
                    "(CVE-2023-4969). Cryptomining malware confirmed TRUE_POSITIVE."
                ),
                "reasoning": (
                    "ANALYSIS CHAIN OF THOUGHT\n"
                    "==========================\n\n"
                    "1. ALERT CONTEXT\n"
                    "   GuardDuty CryptoCurrency:EC2/BitcoinTool.B!DNS triggered on i-0d2e3f4a5b6c78901.\n"
                    "   DNS queries to 3 known XMR mining pool domains in past 4 hours.\n\n"
                    "2. CLOUDWATCH METRICS\n"
                    "   CPU: baseline 12% → spike to 98% at 08:44 UTC (sustained)\n"
                    "   Network out: 3x baseline — miner reporting back to pool\n"
                    "   Disk I/O: minimal — consistent with in-memory miner\n\n"
                    "3. CLOUDTRAIL\n"
                    "   No IAM anomalies. Compromise appears to be at the application layer.\n\n"
                    "4. VULNERABILITY CONTEXT\n"
                    "   Instance runs PHP 8.0.28 (EOL). CVE-2023-4969 (RCE via deserialization)\n"
                    "   is publicly exploited in the wild. Exploit kit 'PhpGhost' specifically\n"
                    "   targets this version for cryptominer deployment.\n\n"
                    "5. VERDICT\n"
                    "   Cryptomining malware confirmed. TRUE_POSITIVE. Instance should be terminated\n"
                    "   and rebuilt from a clean AMI with patched PHP version."
                ),
                "indicators_of_compromise": [
                    "DNS queries to pool.supportxmr.com (Monero mining pool)",
                    "DNS queries to xmr.pool.minergate.com",
                    "DNS queries to moneroocean.stream",
                    "CPU sustained at 98% from 08:44 UTC (baseline: 12%)",
                    "CVE-2023-4969 unpatched — PHP 8.0.28 (EOL)",
                ],
                "false_positive_indicators": [],
                "mitre_attack_techniques": [
                    "T1496 – Resource Hijacking",
                    "T1059 – Command and Scripting Interpreter",
                    "T1190 – Exploit Public-Facing Application",
                ],
                "proposed_actions": [
                    "Terminate instance i-0d2e3f4a5b6c78901 immediately",
                    "Launch replacement from latest hardened AMI with PHP 8.3",
                    "Review load balancer access logs for exploit attempt source IPs and block",
                    "Scan remaining PHP instances in ap-southeast-1 for CVE-2023-4969",
                    "File abuse report with mining pool operators",
                ],
            },
            "artifacts": {
                "s3_bucket": "cohort-artifacts-prod-eu-west-1",
            },
        },
    },

    "inc-0047": {
        "execution": {"status": "FAILED"},
        "pending_approval": None,
        "incident_summary": {
            "incident": {
                "ticket_number":  "inc-0047",
                "alert_type":     "Trojan:EC2/BlackholeTraffic",
                "severity":       "HIGH",
                "finding_id":     "f6a7b8c9-d0e1-2345-fabc-456789012345",
                "account_id":     "555555555555",
                "region":         "eu-west-1",
                "resource_type":  "Instance",
                "resource_id":    "i-0e3f4a5b6c7d89012",
            },
            "analysis": None,
            "artifacts": {
                "s3_bucket": "cohort-artifacts-prod-eu-west-1",
            },
        },
    },

    "inc-0048": {
        "execution": {"status": "SUCCEEDED"},
        "pending_approval": None,
        "incident_summary": {
            "incident": {
                "ticket_number":  "inc-0048",
                "alert_type":     "Policy:S3/BucketPublicAccessGranted",
                "severity":       "LOW",
                "finding_id":     "a7b8c9d0-e1f2-3456-abcd-567890123456",
                "account_id":     "123456789012",
                "region":         "eu-west-1",
                "resource_type":  "S3Bucket",
                "resource_id":    "cohort-static-assets-dev",
            },
            "analysis": {
                "verdict":          "FALSE_POSITIVE",
                "confidence":       "HIGH",
                "playbook":         "S3_DATA_SECURITY",
                "model_id":         "us.anthropic.claude-sonnet-4-5-20250514-v1:0",
                "analysis_timestamp": "2024-03-22T13:07:52Z",
                "threat_summary": (
                    "S3 bucket cohort-static-assets-dev was made public intentionally to serve "
                    "static web assets (CSS, JS, images) for the development environment. Bucket "
                    "contains no sensitive data — only public-facing website assets. The bucket "
                    "policy was applied via an approved Terraform change (PR #487, merged 13:00 UTC). "
                    "FALSE_POSITIVE."
                ),
                "reasoning": (
                    "ANALYSIS CHAIN OF THOUGHT\n"
                    "==========================\n\n"
                    "1. ALERT CONTEXT\n"
                    "   GuardDuty: Policy:S3/BucketPublicAccessGranted on cohort-static-assets-dev.\n"
                    "   Public access was granted at 13:00 UTC via bucket policy change.\n\n"
                    "2. CLOUDTRAIL\n"
                    "   13:00:12 - PutBucketPolicy by arn:aws:iam::123456789012:role/terraform-deploy-role\n"
                    "   Change originated from GitHub Actions runner IP 140.82.114.0/24\n"
                    "   (verified GitHub Actions IP range).\n\n"
                    "3. BUCKET CONTENTS\n"
                    "   Objects present: *.css, *.js, *.png, *.ico, *.woff2 — no PII, credentials,\n"
                    "   or sensitive data detected. Bucket tagged: classification=public, env=dev\n\n"
                    "4. CHANGE MANAGEMENT\n"
                    "   Corresponds to Terraform PR #487 'feat: serve static assets from S3'\n"
                    "   — approved by 2 reviewers, merged by senior engineer at 12:58 UTC.\n\n"
                    "5. VERDICT\n"
                    "   Intentional, approved, change-managed public access. FALSE_POSITIVE."
                ),
                "indicators_of_compromise": [],
                "false_positive_indicators": [
                    "Bucket policy applied by terraform-deploy-role from GitHub Actions (verified IP)",
                    "Change linked to approved PR #487 with 2 reviewer approvals",
                    "Bucket contains only public static assets (CSS/JS/images) — no sensitive data",
                    "Bucket tagged classification=public, env=dev",
                ],
                "mitre_attack_techniques": [],
                "proposed_actions": [
                    "Add bucket cohort-static-assets-dev to GuardDuty suppression list for S3 public access findings",
                ],
            },
            "artifacts": {
                "s3_bucket": "cohort-artifacts-prod-eu-west-1",
            },
        },
    },
}


# ── HTTP handler ─────────────────────────────────────────────────────────────

class MockHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"  {self.command} {self.path}  →  {args[1] if len(args) > 1 else ''}")

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path, content_type):
        with open(path, "rb") as f:
            body = f.read()
        # Inject API base URL into config.js
        if path.endswith("config.js"):
            body = f'window.COHORT_API_BASE = "http://localhost:{PORT}";\n'.encode()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)

        # ── Static files ──────────────────────────────────────────────────
        if path in ("", "/"):
            self.send_response(302)
            self.send_header("Location", "/index.html")
            self.end_headers()
            return

        static_map = {
            "/index.html":        (os.path.join(UI_DIR, "index.html"),        "text/html"),
            "/investigation.html":(os.path.join(UI_DIR, "investigation.html"),"text/html"),
            "/config.js":         (os.path.join(UI_DIR, "config.js"),         "application/javascript"),
            "/repo_image.jpg":    (os.path.join(ASSETS_DIR, "repo_image.jpg"),"image/jpeg"),
        }
        # Also serve the logo at the path the HTML uses: ../assets/repo_image.jpg
        # resolves relative to /investigation.html → /assets/repo_image.jpg
        static_map["/assets/repo_image.jpg"] = (
            os.path.join(ASSETS_DIR, "repo_image.jpg"), "image/jpeg"
        )

        if path in static_map:
            file_path, ct = static_map[path]
            if os.path.exists(file_path):
                self.send_file(file_path, ct)
            else:
                self.send_json({"error": "File not found"}, 404)
            return

        # ── API: GET /investigations ──────────────────────────────────────
        if path == "/investigations":
            status_filter = qs.get("status", [None])[0]
            result = [
                inv for inv in INVESTIGATIONS
                if status_filter is None or inv["status"] == status_filter
            ]
            self.send_json({"investigations": result})
            return

        # ── API: GET /investigations/{ticket} ─────────────────────────────
        if path.startswith("/investigations/") and path.count("/") == 2:
            ticket = path.split("/")[2]
            detail = INVESTIGATION_DETAILS.get(ticket)
            if detail:
                self.send_json(detail)
            else:
                self.send_json({"error": f"Investigation {ticket} not found"}, 404)
            return

        self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b"{}"

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # ── API: POST /approve ────────────────────────────────────────────
        if path == "/approve":
            payload = json.loads(body)
            action = payload.get("action", "approve")
            if action == "reject":
                self.send_json({"status": "ok", "message": "Rejection recorded. No actions executed."})
            else:
                approved = payload.get("approved_actions", [])
                self.send_json({
                    "status": "ok",
                    "message": f"Approved {len(approved)} action(s). Remediation workflow resumed.",
                })
            return

        # ── API: POST /investigations/{ticket}/rerun ──────────────────────
        if path.startswith("/investigations/") and path.endswith("/rerun"):
            ticket = path.split("/")[2]
            self.send_json({
                "status":         "ok",
                "execution_name": f"cohort-{ticket}-rerun-20240322T175301Z",
                "execution_arn":  f"arn:aws:states:eu-west-1:123456789012:execution:cohort-incident-response:{ticket}-rerun",
            })
            return

        self.send_json({"error": "Not found"}, 404)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    server = HTTPServer(("localhost", PORT), MockHandler)
    print(f"""
╔══════════════════════════════════════════════════════╗
║        Cohort UI Mock Server                         ║
╠══════════════════════════════════════════════════════╣
║  Dashboard:      http://localhost:{PORT}                ║
║  Investigation:  http://localhost:{PORT}/investigation.html?ticket=inc-0042  ║
║                                                      ║
║  Press Ctrl+C to stop                                ║
╚══════════════════════════════════════════════════════╝
""")
    print("Mock investigations loaded:")
    for inv in INVESTIGATIONS:
        verdict = inv.get("verdict") or "—"
        print(f"  {inv['ticket_number']:16}  {inv['status']:10}  {inv['severity']:6}  {verdict}")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
