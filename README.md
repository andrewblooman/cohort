# Cohort – AI-Assisted Cloud Incident Response

<p align="center">
  <img src="assets/repo_image.jpg" alt="Illustration of a soldier defending a castle with the AWS cloud inside the walls">
</p>

<p align="center">
  <a href="https://github.com/andrewblooman/Cohort/actions/workflows/deploy.yml">
    <img src="https://github.com/andrewblooman/Cohort/actions/workflows/deploy.yml/badge.svg" alt="Deploy">
  </a>
  <img src="https://img.shields.io/badge/python-3.12-blue?logo=python&logoColor=white" alt="Python 3.12">
  <img src="https://img.shields.io/badge/terraform-%3E%3D1.10-purple?logo=terraform&logoColor=white" alt="Terraform ≥ 1.10">
  <img src="https://img.shields.io/badge/AWS-Step%20Functions-orange?logo=amazonaws&logoColor=white" alt="AWS Step Functions">
  <img src="https://img.shields.io/badge/AI-Amazon%20Bedrock-yellow?logo=amazonaws&logoColor=white" alt="Amazon Bedrock">
  <img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="Apache-2.0">
</p>

A fully AWS-native, AI-assisted cloud incident response system. GuardDuty findings
are automatically picked up from EventBridge, triaged by Amazon Bedrock (Claude),
and routed to an analyst for approval before any remediation action is taken.

---

## Architecture

```
GuardDuty Finding
      │  (published to default EventBridge bus)
      ▼
AWS EventBridge (default bus)
      │  aws.guardduty / GuardDuty Finding
      ▼
Step Functions State Machine
      │
      ├─► Lambda: generate_incident_id
      │       Atomically increments DynamoDB counter
      │       Assigns sequential ID:  inc-0001, inc-0002, …
      │       Normalises the GuardDuty finding payload
      │
      ├─► Lambda: enrich_alert
      │       Fetches full GuardDuty finding details
      │       CloudTrail events (last 24 h)
      │       EC2 / IAM metadata
      │
      ├─► Lambda: collect_artifacts
      │       Uploads raw evidence to S3
      │       s3://<bucket>/<incident-id>/
      │           guardduty_finding.json
      │           cloudtrail_events.json
      │           vpc_flow_logs.json
      │           ec2_metadata.json
      │
      ├─► Lambda: ai_analysis
      │       Selects scenario-specific playbook
      │       Invokes Amazon Bedrock AgentCore (Claude)
      │       Returns structured verdict:
      │           TRUE_POSITIVE | FALSE_POSITIVE | INCONCLUSIVE
      │
      ├─► Lambda: store_artifacts
      │       Saves AI recommendation to S3:
      │           ai_recommendation.txt   (human-readable)
      │           ai_recommendation.json  (structured)
      │           incident_summary.json   (full context)
      │
      └─► Lambda: notify  ── waitForTaskToken ──► [Analyst reviews via Web UI]
              Slack Block Kit notification                   │
              Writes pending_approval.json to S3    approve / reject
                                                            │
                                                    Lambda: approve_actions
                                                            │
                                                    Lambda: execute_actions
                                                            │
                                                    Lambda: notify (execution_results)
                                                            │
                                                    Slack follow-up message
```

---

## Web UI

A zero-dependency static web UI (Bootstrap 5.3 + vanilla JS) provides the
analyst approval workflow. Run it locally without any AWS credentials:

```bash
python mock_server.py   # → http://localhost:8080
```

| Page | Description |
|---|---|
| `/` (Dashboard) | Lists all investigations with status/verdict badges, 30-second auto-refresh |
| `/investigation.html?id=inc-0001` | Incident detail — AI verdict, evidence, analyst approval form |

---

## Repository Layout

```
cohort/
├── lambdas/
│   ├── generate_incident_id/    # Step 1: Assign inc-XXXX ID, normalise GuardDuty finding
│   ├── enrich_alert/            # Step 2: Fetch GuardDuty + CloudTrail + EC2/IAM context
│   ├── collect_artifacts/       # Step 3: Download and store raw log artifacts in S3
│   ├── ai_analysis/             # Step 4: Amazon Bedrock AI analysis with playbook guidance
│   ├── store_artifacts/         # Step 5: Write AI recommendation and full summary to S3
│   ├── notify/                  # Step 6: Slack notification + S3 pending_approval.json
│   ├── approve_actions/         # API: Human-in-the-loop approval callback
│   ├── execute_actions/         # Executes analyst-approved remediation actions
│   ├── list_investigations/     # API: GET /investigations (dashboard data)
│   ├── get_investigation/       # API: GET /investigations/{id} (detail page)
│   └── rerun_analysis/          # API: POST /investigations/{id}/rerun
├── playbooks/                   # Incident response playbook definitions (10 playbooks)
│   ├── base.py                  #   Playbook dataclass (frozen, immutable)
│   ├── registry.py              #   select_playbook() – matches finding type to playbook
│   └── *.py                     #   Scenario-specific playbooks
├── shared/                      # Reusable modules deployed as a Lambda Layer
│   ├── cloudtrail_queries.py    #   CloudTrail event lookup and parsing helpers
│   └── cloudwatch_queries.py    #   CloudWatch Logs Insights query orchestration
├── ui/                          # Static web UI (Bootstrap 5.3, no build step)
│   ├── index.html               #   Investigations dashboard
│   ├── investigation.html       #   Incident detail + analyst approval form
│   └── config.js                #   API Gateway base URL (injected by Terraform)
├── terraform/                   # Terraform IaC
│   └── modules/
│       └── enrichment_lambda/   #   Reusable Lambda module template
├── tests/                       # pytest unit tests (362 tests across 13 files)
├── assets/                      # Project images
├── mock_server.py               # Local development server (no AWS needed)
├── requirements.txt             # Runtime Python dependencies
├── requirements-dev.txt         # Dev/test dependencies (pytest, moto)
└── pytest.ini                   # pytest configuration
```

---

## Playbooks

The AI analysis step uses **scenario-specific playbooks** to guide the LLM's
reasoning. Each playbook defines investigation steps, key indicators, response
actions, MITRE ATT&CK references, and required data sources.

| Playbook | Matches |
|---|---|
| **IAM Privilege Escalation** | `PrivilegeEscalation`, `IAMUser`, policy escalation |
| **EC2 Credential Access** | `credential`, `TorIPCaller`, `CryptoCurrency`, `BitcoinTool` |
| **EC2 SSH Brute Force** | `SSHBruteForce`, `RDPBruteForce`, brute force, port probe |
| **Web Application Attack** | web application, SQL injection, XSS, scanner |
| **EC2 Persistence** | `Backdoor`, persistence, unusual network, blackhole |
| **S3 Data Security** | S3, bucket, public access, data exfiltration |
| **Kubernetes / Container** | Kubernetes, EKS, container, pod |
| **RDS Credential Access** | RDS, database, DB credential |
| **Ransomware** | Ransomware, encryption, ransom |
| **GuardDuty General** | *(fallback — matches any unrecognised finding type)* |

---

## Remediation Actions

The `execute_actions` Lambda supports seven analyst-approved actions:

| Action | Effect |
|---|---|
| `isolate_ec2_instance` | Replaces all security groups with an isolation group (no ingress/egress) |
| `stop_ec2_instance` | Stops the EC2 instance |
| `snapshot_ec2_instance` | Creates EBS snapshots of all attached volumes |
| `deactivate_iam_access_key` | Marks the IAM access key as `Inactive` |
| `revoke_iam_role_sessions` | Updates the role trust policy to deny all sessions before now |
| `archive_guardduty_finding` | Archives the GuardDuty finding |
| `block_s3_public_access` | Enables S3 Block Public Access on the affected bucket |

---

## Amazon Bedrock AgentCore

The `ai_analysis` Lambda supports two invocation modes:

- **AgentCore mode** (preferred) — calls `bedrock-agent-runtime:InvokeAgent`. Set
  `AGENTCORE_AGENT_RUNTIME_ARN` in Terraform. Supports per-incident session context
  and cross-incident memory for past verdicts and false-positive patterns.
- **Direct InvokeModel** (fallback) — used when `AGENTCORE_AGENT_RUNTIME_ARN` is
  empty. Calls `bedrock-runtime:InvokeModel` with the Anthropic Messages API.

---

## API Gateway Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/investigations` | Dashboard — lists all investigations |
| `GET` | `/investigations/{id}` | Detail page — incident data + pending approval |
| `POST` | `/investigations/{id}/rerun` | Re-trigger the full pipeline |
| `POST` | `/approve` | Analyst approval / rejection callback |

---

## CI/CD

The GitHub Actions workflow (`.github/workflows/deploy.yml`) uses **OIDC** — no
long-lived AWS keys are stored in GitHub.

| Trigger | Action |
|---|---|
| Push to `main` | `terraform plan` (safe preview) |
| Manual dispatch | `terraform plan` → `terraform apply` (requires environment approval) |

---

## Prerequisites

| Tool | Version |
|---|---|
| Python | 3.12 |
| Terraform | ≥ 1.10 |
| AWS CLI | ≥ 2.x |
| AWS account | GuardDuty enabled |

---

## Deployment

### 1. Bootstrap Terraform state backend

Create an S3 bucket with Object Lock enabled for Terraform state, then fill in
`terraform/backend.tf`.

### 2. Create the GitHub OIDC IAM role

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:andrewblooman/Cohort:ref:refs/heads/main"
    }
  }
}
```

Add `AWS_OIDC_ROLE_ARN` as a GitHub Actions secret and create a `production`
environment in **Settings → Environments** with at least one required reviewer.

### 3. Configure Terraform variables

Create `terraform/terraform.tfvars` (git-ignored):

```hcl
aws_region   = "us-east-1"
environment  = "prod"
project_name = "cohort"

# Amazon Bedrock model (Claude 3.5 Sonnet by default)
bedrock_model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"

# Slack webhook for analyst notifications (optional)
# Store the webhook URL in Secrets Manager and provide the ARN here
slack_webhook_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret/cohort/slack-webhook"

# Amazon Bedrock AgentCore (optional – leave empty to use direct InvokeModel)
# enable_agentcore = true
```

### 4. Deploy

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

### 5. Store the Slack webhook in Secrets Manager (optional)

```bash
aws secretsmanager create-secret \
  --name cohort/slack-webhook \
  --secret-string "https://hooks.slack.com/services/T.../B.../..."
```

### 6. Run locally (no AWS needed)

```bash
pip install -r requirements-dev.txt
python mock_server.py   # → http://localhost:8080
```

---

## AI Verdict Schema

```json
{
  "verdict": "TRUE_POSITIVE",
  "confidence": "HIGH",
  "reasoning": "Detailed step-by-step analysis…",
  "threat_summary": "One-paragraph summary of the threat",
  "indicators_of_compromise": ["DNS query to pool.minexmr.com"],
  "false_positive_indicators": [],
  "proposed_actions": ["isolate_ec2_instance", "snapshot_ec2_instance"],
  "mitre_attack_techniques": ["T1496 – Resource Hijacking"]
}
```

**Verdict values:**
- `TRUE_POSITIVE` – confirmed malicious activity; remediation actions will be proposed
- `FALSE_POSITIVE` – benign activity; no action required
- `INCONCLUSIVE` – insufficient evidence; manual investigation required

---

## Security Considerations

- S3 artifacts bucket enforces HTTPS-only access and SSE-KMS encryption with versioning
- IAM roles follow least-privilege principles; no wildcard `*` actions on sensitive services
- Slack webhook URL is stored in AWS Secrets Manager, never in code or environment variables
- EventBridge rule only matches native `aws.guardduty` events — no external event ingestion
- S3 bucket public access is fully blocked
- Step Functions `waitForTaskToken` ensures **no automated remediation** without explicit analyst approval
- GitHub Actions OIDC — no long-lived AWS credentials stored in GitHub

---

## License

Apache-2.0 – see [LICENSE](LICENSE).
