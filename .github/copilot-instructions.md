# Cohort – Copilot Instructions

## What this project does

Cohort is an AI-assisted AWS cloud incident response system. A GuardDuty alert forwarded from Google SecOps (via EventBridge) triggers an AWS Step Functions workflow that runs five Lambda functions in sequence: enrich → collect artifacts → AI analysis → store artifacts → notify SIEM. The AI analysis step uses Amazon Bedrock AgentCore (when configured) or falls back to direct Bedrock `InvokeModel`, and returns a structured `TRUE_POSITIVE | FALSE_POSITIVE | INCONCLUSIVE` verdict back to the Google SecOps case.

## Commands

```bash
# Install dependencies
pip install -r requirements-dev.txt

# Run all tests
python -m pytest

# Run a single test file
python -m pytest tests/test_playbooks.py

# Run a single test by name
python -m pytest tests/test_playbooks.py::TestSelectPlaybook::test_falls_back_to_general_for_unknown_type

# Run with coverage
python -m pytest --cov
```

Python 3.12. No linter is configured.

## Architecture

```
EventBridge → Step Functions → enrich_alert → collect_artifacts → ai_analysis → store_artifacts → notify_siem
```

- **`lambdas/enrich_alert/`** – Fetches the full GuardDuty finding, CloudTrail events, EC2 metadata, and IAM context. Returns an `enrichment` dict to the workflow.
- **`lambdas/collect_artifacts/`** – Downloads raw logs (VPC Flow Logs, CloudTrail Insights) and uploads them to S3 under `s3://<bucket>/<ticket_number>/`.
- **`lambdas/ai_analysis/`** – Selects a playbook, builds a prompt, invokes Bedrock AgentCore (or direct `InvokeModel` as fallback), parses and validates the JSON verdict. Falls back to `INCONCLUSIVE` on any parse failure.
- **`lambdas/store_artifacts/`** – Writes `ai_recommendation.txt`, `ai_recommendation.json`, and `incident_summary.json` to S3.
- **`lambdas/notify_siem/`** – Posts the verdict as a comment to the Google SecOps case via the Chronicle API using credentials from Secrets Manager.
- **`shared/`** – Deployed as a Lambda Layer (`/opt/python/` in production). Contains `cloudtrail_queries.py` and `cloudwatch_queries.py` with reusable boto3 helpers.
- **`playbooks/`** – Scenario-specific guidance injected into the Bedrock prompt at analysis time.

Each Lambda handler adds the repo root to `sys.path` so `shared/` and `playbooks/` are importable during local development and testing without the layer being present.

## Bedrock AgentCore

The `ai_analysis` Lambda supports two invocation modes, selected at runtime by the `AGENTCORE_AGENT_RUNTIME_ARN` environment variable:

- **AgentCore mode** (preferred) – calls `bedrock-agent-runtime:InvokeAgent`. The managed runtime handles session lifecycle, tool use, and memory. Responses arrive as a streaming `EventStream` of chunks that are assembled into a single string before parsing.
- **Direct mode** (fallback) – calls `bedrock-runtime:InvokeModel` with the Anthropic Messages API when `AGENTCORE_AGENT_RUNTIME_ARN` is empty.

**Memory:** When `AGENTCORE_MEMORY_STORE_ID` is set, `invoke_agentcore()` passes it as `memoryId` and uses `ticket_number` as `sessionId`, giving the agent per-incident session context and cross-incident memory for past verdicts and false-positive patterns.

**AgentCore Terraform resources** (`terraform/bedrock_agentcore.tf`, gated on `var.enable_agentcore`):
- `aws_bedrockagentcore_agent_runtime.incident_response` – the managed runtime (`agent_runtime_name`, `role_arn`)
- `aws_bedrockagentcore_memory_store.incident_memory` – cross-session memory store
- `aws_iam_role.agentcore_runtime` – execution role trusted by `bedrockagentcore.amazonaws.com`

**AgentCore mocking in tests:** moto doesn't cover `bedrock-agent-runtime`, so `invoke_agentcore` is tested by patching `_agent_runtime_client` and simulating the `completion` EventStream as a list of `{"chunk": {"bytes": b"..."}}` dicts. The `conftest.py` autouse fixture sets `AGENTCORE_AGENT_RUNTIME_ARN = ""` so existing tests always exercise the direct-mode fallback path.



Playbooks are frozen dataclasses (`playbooks/base.py`). Each defines `finding_type_patterns` (substring list matched case-insensitively against the GuardDuty finding type and description), plus `investigation_steps`, `key_indicators`, `response_actions`, `mitre_techniques`, and `data_sources`.

`playbooks/registry.py` holds an ordered `_PLAYBOOKS` list. `select_playbook()` returns the first match; `GUARDDUTY_GENERAL` (empty `finding_type_patterns`) is always last and acts as the fallback.

**To add a new playbook:**
1. Create `playbooks/<scenario>.py` defining a module-level `Playbook` constant.
2. Import it in `playbooks/registry.py` and insert it into `_PLAYBOOKS` before `GUARDDUTY_GENERAL`.
3. Add tests in `tests/test_playbooks.py` following the existing `TestSelectPlaybook` pattern.

## Lambda conventions

- All handlers use `from __future__ import annotations` and type-hint `lambda_handler(event: dict, context: Any) -> dict`.
- Boto3 clients are created inside helper functions (not at module level) so they can be patched in tests.
- Environment variables are read at module level with `os.environ.get()` and sensible defaults.
- `logger = logging.getLogger()` / `logger.setLevel(logging.INFO)` at module level; every handler logs `ticket_number` on entry.
- `ClientError` from botocore is the primary exception type caught and re-raised after logging.

**To add a new Lambda:**
1. Create `lambdas/<name>/handler.py` and `lambdas/<name>/__init__.py`.
2. Add the `sys.path` preamble block (copy from any existing handler) if it needs `shared/` or `playbooks/`.
3. Add a Terraform resource in `terraform/lambda.tf` using the `enrichment_lambda` module pattern.
4. Add a state in `terraform/step_functions.tf`.
5. Add tests in `tests/test_<name>.py`.

## Testing conventions

- `moto` is used for all AWS service mocking (`@mock_aws` decorator from `moto`).
- Lambda handlers are loaded with `importlib.util` via the `_load_handler()` helper in each test file to avoid `sys.modules` pollution between test files.
- `conftest.py` has an `autouse` fixture that sets all required environment variables (`AWS_DEFAULT_REGION`, `ARTIFACTS_BUCKET`, `BEDROCK_MODEL_ID`, `GOOGLE_SECOPS_*`, `ENABLE_VPC_FLOW_LOG_COLLECTION`, `ENABLE_CLOUDTRAIL_COLLECTION`, `AGENTCORE_AGENT_RUNTIME_ARN=""`).
- Bedrock and AgentCore calls are patched with `unittest.mock.patch` since moto doesn't mock either service.
- Tests are organised into classes (`TestXxx`) with one test per method (`test_*`).

## Key environment variables (Lambda runtime)

| Variable | Description |
|---|---|
| `ARTIFACTS_BUCKET` | S3 bucket for all incident artifacts |
| `BEDROCK_MODEL_ID` | Bedrock model (default: `anthropic.claude-3-5-sonnet-20240620-v1:0`) |
| `GOOGLE_SECOPS_API_ENDPOINT` | Chronicle API base URL |
| `GOOGLE_SECOPS_CUSTOMER_ID` | Chronicle customer ID |
| `GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN` | Secrets Manager ARN for service-account JSON |
| `AGENTCORE_AGENT_RUNTIME_ARN` | AgentCore runtime ARN; empty string enables direct `InvokeModel` fallback |
| `AGENTCORE_MEMORY_STORE_ID` | AgentCore memory store ID; omitted from `InvokeAgent` call when empty |
| `ENABLE_VPC_FLOW_LOG_COLLECTION` | `"true"` / `"false"` |
| `ENABLE_CLOUDTRAIL_COLLECTION` | `"true"` / `"false"` |

## Terraform

All resources are in `terraform/`. The `terraform/modules/enrichment_lambda/` module is a reusable template for deploying a Lambda with the shared layer, IAM role, and CloudWatch log group. Infrastructure is configured via `terraform/terraform.tfvars` (git-ignored).

| File | What it manages |
|---|---|
| `eventbridge.tf` | Custom bus, rule, SFN target |
| `lambda.tf` | All 5 Lambda functions, packaging, log groups, common env locals |
| `lambda_layer.tf` | Shared utilities Lambda Layer |
| `step_functions.tf` | State machine with all 5 states + error-handler Pass states |
| `iam.tf` | Lambda exec role, Step Functions role, EventBridge→SFN role, AgentCore runtime role |
| `s3.tf` | KMS-encrypted artifacts bucket with versioning and lifecycle |
| `bedrock_agentcore.tf` | AgentCore runtime + memory store |

## CI/CD

The workflow is defined in `.github/workflows/deploy.yml`. It uses **OIDC** (no long-lived AWS keys) and targets the flat `terraform/` directory.

**Triggers:**
- `push` to `main` → runs `terraform-plan` only (safe preview on every merge)
- `workflow_dispatch` (manual) → runs `terraform-plan` then `terraform-apply`

**Required GitHub secrets:**

| Secret | Description |
|---|---|
| `AWS_OIDC_ROLE_ARN` | ARN of the IAM role to assume via OIDC (e.g. `arn:aws:iam::123456789012:role/github-deploy`) |

Backend configuration (S3 bucket, key, region) is set directly in `terraform/backend.tf` — fill in the placeholder values before first deploy. These are not secrets so they are committed to the repo.

**AWS OIDC IAM role trust policy** — create this role in AWS before the workflow can authenticate:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:<ORG>/<REPO>:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

> **Important:** the `sub` condition is scoped to `ref:refs/heads/main` — only the `main` branch can assume this role. Other branches, tags, and fork PRs are rejected at the AWS trust policy level.

The GitHub OIDC provider (`token.actions.githubusercontent.com`) must be added to the AWS account before creating the role. The role needs sufficient IAM permissions to create all resources managed in `terraform/`.

**GitHub Environment (required):** Create a `production` environment in repo **Settings → Environments** and add at least one required reviewer. The `terraform-apply` job targets this environment, so every apply will pause for manual approval before AWS credentials are exchanged.

**Terraform version:** `>= 1.10.0` (required for S3 object lock state locking — `use_lockfile = true` in `backend.tf`). The S3 state bucket must be created with Object Lock enabled.
