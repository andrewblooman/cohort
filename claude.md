# Claude Code – Cohort

## Project Overview

Cohort is an automated, AI-assisted cloud incident response system running on AWS.
It integrates with Google SecOps (Chronicle SIEM) so that a GuardDuty alert
automatically triggers a full triage workflow—collecting evidence, reasoning over
it with Amazon Bedrock (Claude), and posting the verdict back to the SIEM case.

## Architecture

```
GuardDuty Alert → Google SecOps → EventBridge → Step Functions → 5 Lambdas → S3 + SIEM
```

The Step Functions state machine orchestrates five Lambda functions in sequence:

1. **enrich_alert** – Fetches GuardDuty finding details, CloudTrail events, EC2/IAM metadata
2. **collect_artifacts** – Downloads raw evidence to S3 (`s3://<bucket>/<ticket_number>/`)
3. **ai_analysis** – Invokes Bedrock (Claude) with a scenario-specific playbook to produce a verdict
4. **store_artifacts** – Writes AI recommendation (text + JSON) and incident summary to S3
5. **notify_siem** – Posts verdict back to Google SecOps via OAuth2 JWT API

## Repository Structure

```
cohort/
├── lambdas/                    # AWS Lambda function handlers
│   ├── enrich_alert/           #   Step 1: GuardDuty + CloudTrail + EC2/IAM enrichment
│   ├── collect_artifacts/      #   Step 2: Store raw evidence in S3
│   ├── ai_analysis/            #   Step 3: Bedrock AI analysis with playbook guidance
│   ├── store_artifacts/        #   Step 4: Write AI verdict and summary to S3
│   └── notify_siem/            #   Step 5: Post verdict to Google SecOps
├── playbooks/                  # Incident response playbook definitions
│   ├── base.py                 #   Playbook dataclass (frozen, immutable)
│   ├── registry.py             #   select_playbook() – matches finding type to playbook
│   ├── guardduty_general.py    #   Generic fallback playbook
│   ├── iam_privilege_escalation.py  # IAM-focused playbook
│   └── ransomware.py           #   Ransomware/destructive activity playbook
├── shared/                     # Reusable modules deployed as Lambda Layer
│   ├── cloudtrail_queries.py   #   CloudTrail event lookup and parsing helpers
│   └── cloudwatch_queries.py   #   CloudWatch Logs Insights query orchestration
├── terraform/                  # Terraform IaC
│   ├── main.tf                 #   Provider config, backend
│   ├── variables.tf            #   Input variables (15 total)
│   ├── lambda.tf               #   Lambda functions, log groups, packaging
│   ├── lambda_layer.tf         #   Shared code Lambda Layer
│   ├── iam.tf                  #   IAM roles and policies (least-privilege)
│   ├── s3.tf                   #   Artifacts bucket (encrypted, versioned)
│   ├── eventbridge.tf          #   Custom bus, rule, target
│   ├── step_functions.tf       #   State machine definition
│   ├── outputs.tf              #   Exported resource ARNs/names
│   └── modules/
│       └── enrichment_lambda/  #   Reusable Lambda module template
├── tests/                      # pytest unit tests (140 tests)
├── assets/                     # Project images (cohort-guardian.svg)
├── requirements.txt            # Runtime deps (boto3, botocore)
├── requirements-dev.txt        # Dev deps (pytest, pytest-cov, moto)
└── pytest.ini                  # pytest config
```

## Development Commands

```bash
# Install dependencies
pip install -r requirements-dev.txt

# Run all tests
python -m pytest

# Run tests with coverage
python -m pytest --cov

# Run a specific test file
python -m pytest tests/test_ai_analysis.py

# Run a specific test
python -m pytest tests/test_ai_analysis.py::test_returns_text_from_model

# Terraform
cd terraform
terraform init
terraform plan
terraform apply
```

## Key Conventions

- **Python 3.12** – Lambda runtime and development target
- **Lambda handlers** – Each lambda has `handler.py` with `def lambda_handler(event, context)` entry point
- **Playbooks** – Frozen dataclasses (`@dataclass(frozen=True)`) with `format_prompt_section()` for LLM prompt injection. Playbook selection is pattern-based via `select_playbook()` in `registry.py`
- **Shared code** – The `shared/` package is deployed as a Lambda Layer mounted at `/opt/python/`. All lambdas can import from it
- **Testing** – Uses `moto` to mock AWS services (S3, GuardDuty, CloudTrail, CloudWatch, IAM, etc.). Tests live in `tests/` and follow `test_*.py` naming. `conftest.py` provides AWS credential fixtures
- **Terraform** – Infrastructure follows a flat module pattern with a reusable `modules/enrichment_lambda/` template. Default tags applied via provider block
- **IAM** – Follows least-privilege. All permissions scoped in `iam.tf`
- **Error handling** – Lambdas catch `botocore.exceptions.ClientError`. Step Functions retry 3x with exponential backoff
- **AI verdicts** – Three possible values: `TRUE_POSITIVE`, `FALSE_POSITIVE`, `INCONCLUSIVE` with confidence levels `HIGH`, `MEDIUM`, `LOW`

## Important Patterns

### Adding a New Playbook

1. Create a new file in `playbooks/` (e.g., `playbooks/my_playbook.py`)
2. Define a `Playbook` instance with `finding_type_patterns`, `investigation_steps`, `key_indicators`, `response_actions`, `mitre_techniques`, and `data_sources`
3. Import and register in `playbooks/registry.py` (order matters – specific playbooks before the general fallback)
4. Add tests in `tests/test_playbooks.py`

### Adding a New Lambda

1. Create `lambdas/<name>/__init__.py` and `lambdas/<name>/handler.py`
2. Define `def lambda_handler(event, context)` entry point
3. Add Terraform resources in `terraform/lambda.tf` (archive, log group, function)
4. Add IAM permissions in `terraform/iam.tf`
5. Wire into the Step Functions state machine in `terraform/step_functions.tf`
6. Add tests in `tests/test_<name>.py`
