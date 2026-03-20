"""
ai_analysis/handler.py

Lambda function: AI Analysis

Third step in the incident-response Step Functions workflow.
Uses Amazon Bedrock (Claude) to reason over the collected evidence and produce
a structured verdict:

  - TRUE_POSITIVE   – confirmed malicious activity
  - FALSE_POSITIVE  – benign activity, no threat
  - INCONCLUSIVE    – insufficient evidence to determine

The function builds a rich prompt from the incident context and all collected
enrichment data, invokes the Bedrock model, and parses the structured response.
The full AI reasoning and recommendation are returned to the workflow so they
can be stored and sent back to the SIEM.

A scenario-specific playbook is selected at runtime based on the GuardDuty
finding type, providing the LLM with targeted investigation guidance.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Ensure the repository root is on the path so the playbooks package is importable.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from playbooks.registry import select_playbook  # noqa: E402

logger = logging.getLogger()
logger.setLevel(logging.INFO)

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "anthropic.claude-3-5-sonnet-20240620-v1:0",
)
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

VALID_VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "INCONCLUSIVE"}
VALID_CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}


# ---------------------------------------------------------------------------
# Bedrock helpers
# ---------------------------------------------------------------------------

def _bedrock_client() -> Any:
    return boto3.client("bedrock-runtime", region_name=AWS_REGION)


def invoke_bedrock(prompt: str) -> str:
    """Invoke the configured Bedrock model and return the raw text response."""
    client = _bedrock_client()

    request_body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "temperature": 0.1,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
    }

    try:
        response = client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(request_body),
        )
        response_body = json.loads(response["body"].read())
        return response_body["content"][0]["text"]
    except ClientError as exc:
        logger.error("Bedrock InvokeModel failed: %s", exc)
        raise


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def build_analysis_prompt(event: dict) -> str:
    """Build the analysis prompt from the incident event data."""
    ticket_number = event.get("ticket_number", "UNKNOWN")
    alert_type = event.get("alert_type", "Unknown")
    severity = event.get("severity", "Unknown")
    finding_id = event.get("finding_id", "")
    account_id = event.get("account_id", "")
    region = event.get("region", "")
    resource_type = event.get("resource_type", "")
    resource_id = event.get("resource_id", "")
    description = event.get("description", "No description provided")

    enrichment = event.get("enrichment_result", {})
    if isinstance(enrichment, dict) and "enrichment" in enrichment:
        enrichment = enrichment["enrichment"]

    finding = enrichment.get("finding", {})
    cloudtrail_events = enrichment.get("cloudtrail_events", [])
    ec2_metadata = enrichment.get("ec2_metadata", {})
    iam_context = enrichment.get("iam_context", {})

    artifacts = event.get("artifacts_result", {})
    if isinstance(artifacts, dict) and "artifacts" in artifacts:
        artifacts = artifacts["artifacts"]

    vpc_flows_count = artifacts.get("vpc_flow_log_count", 0)
    ct_logs_count = artifacts.get("cloudtrail_log_count", 0)
    s3_keys = artifacts.get("s3_keys", [])

    # Select scenario-specific playbook
    finding_type = finding.get("Type", "")
    playbook = select_playbook(finding_type=finding_type, description=description)
    playbook_section = playbook.format_prompt_section()

    # Truncate large objects to avoid exceeding context limits
    cloudtrail_sample = cloudtrail_events[:20] if len(cloudtrail_events) > 20 else cloudtrail_events

    prompt = f"""You are a cloud security incident responder with deep expertise in AWS, GuardDuty, CloudTrail, and threat analysis.

You have been presented with a security alert that requires investigation. Your task is to analyse all available evidence and provide a structured verdict.

{playbook_section}

## INCIDENT SUMMARY

- **Ticket Number**: {ticket_number}
- **Alert Type**: {alert_type}
- **Severity**: {severity}
- **Finding ID**: {finding_id}
- **AWS Account**: {account_id}
- **Region**: {region}
- **Resource Type**: {resource_type}
- **Resource ID**: {resource_id}
- **Description**: {description}

## GUARDDUTY FINDING

```json
{json.dumps(finding, default=str, indent=2)[:4000]}
```

## CLOUDTRAIL EVENTS (up to 20 most recent)

```json
{json.dumps(cloudtrail_sample, default=str, indent=2)[:3000]}
```
Total CloudTrail events collected: {len(cloudtrail_events)}

## EC2 METADATA

```json
{json.dumps(ec2_metadata, default=str, indent=2)[:2000]}
```

## IAM CONTEXT

```json
{json.dumps(iam_context, default=str, indent=2)[:2000]}
```

## COLLECTED ARTIFACTS

- VPC flow log records collected: {vpc_flows_count}
- CloudTrail log records (Insights): {ct_logs_count}
- Artifact S3 keys: {json.dumps(s3_keys)}

## INSTRUCTIONS

Carefully analyse all the evidence above. Apply the following reasoning framework:

1. **Understand the alert**: What is GuardDuty detecting? What is the threat type?
2. **Evaluate the context**: Does the resource, account, and region make sense for this alert? Are there any known benign patterns?
3. **Examine CloudTrail**: Do the API calls support or contradict the alert? Are there anomalous patterns (unusual times, unexpected IPs, privilege escalation attempts)?
4. **Assess the resource**: Is the EC2 instance or IAM entity behaving normally? Are there indicators of compromise?
5. **Consider false-positive indicators**: Common false positives include security scanning tools, penetration tests, known automation, or expected administrative activity.
6. **Weigh all evidence**: Provide a balanced assessment.

Provide your response in the following **exact JSON format** (do not include any text outside the JSON):

```json
{{
  "verdict": "<TRUE_POSITIVE | FALSE_POSITIVE | INCONCLUSIVE>",
  "confidence": "<HIGH | MEDIUM | LOW>",
  "reasoning": "<detailed step-by-step reasoning, at least 200 words>",
  "threat_summary": "<one-paragraph summary of the threat or why it is benign>",
  "indicators_of_compromise": ["<list of IoCs if TRUE_POSITIVE, else empty>"],
  "false_positive_indicators": ["<list of FP indicators if FALSE_POSITIVE, else empty>"],
  "recommendations": ["<list of specific recommended actions>"],
  "mitre_attack_techniques": ["<relevant MITRE ATT&CK technique IDs if applicable>"]
}}
```

Remember:
- Use ONLY the verdicts: TRUE_POSITIVE, FALSE_POSITIVE, or INCONCLUSIVE
- Be specific and evidence-based in your reasoning
- If evidence is insufficient for a confident verdict, use INCONCLUSIVE
- Recommendations should be actionable and specific to the evidence"""

    return prompt


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def parse_bedrock_response(raw_response: str) -> dict:
    """Extract and validate the structured JSON from the Bedrock response."""
    # Try to extract JSON from a code block first
    code_block_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_response, re.DOTALL)
    if code_block_match:
        json_str = code_block_match.group(1)
    else:
        # Try to find raw JSON object
        json_match = re.search(r"\{.*\}", raw_response, re.DOTALL)
        if json_match:
            json_str = json_match.group(0)
        else:
            logger.warning("Could not extract JSON from Bedrock response; returning raw text")
            return _fallback_inconclusive(f"Could not parse AI response: {raw_response[:500]}")

    try:
        result = json.loads(json_str)
    except json.JSONDecodeError as exc:
        logger.warning("JSON decode error on Bedrock response: %s", exc)
        return _fallback_inconclusive(f"JSON parse error: {exc}")

    # Validate and normalise verdict
    verdict = result.get("verdict", "INCONCLUSIVE").upper().strip()
    if verdict not in VALID_VERDICTS:
        logger.warning("Unexpected verdict '%s'; defaulting to INCONCLUSIVE", verdict)
        verdict = "INCONCLUSIVE"
    result["verdict"] = verdict

    # Validate confidence
    confidence = result.get("confidence", "LOW").upper().strip()
    if confidence not in VALID_CONFIDENCES:
        confidence = "LOW"
    result["confidence"] = confidence

    # Ensure list fields are lists
    for list_field in ("indicators_of_compromise", "false_positive_indicators", "recommendations", "mitre_attack_techniques"):
        if not isinstance(result.get(list_field), list):
            result[list_field] = []

    return result


def _fallback_inconclusive(reason: str) -> dict:
    """Return a safe INCONCLUSIVE result when parsing fails."""
    return {
        "verdict": "INCONCLUSIVE",
        "confidence": "LOW",
        "reasoning": reason,
        "threat_summary": "AI analysis could not be completed. Manual review required.",
        "indicators_of_compromise": [],
        "false_positive_indicators": [],
        "recommendations": ["Perform manual investigation of the GuardDuty finding"],
        "mitre_attack_techniques": [],
    }


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Entry point for the AI-analysis Lambda.

    Args:
        event: Step Functions payload with incident fields, enrichment_result,
               and artifacts_result from previous steps.
        context: Lambda context (unused).

    Returns:
        Analysis dict with verdict, confidence, reasoning, and recommendations.
    """
    logger.info("ai_analysis invoked for ticket=%s", event.get("ticket_number", "UNKNOWN"))

    prompt = build_analysis_prompt(event)
    logger.info("Built analysis prompt (%d chars)", len(prompt))

    raw_response = invoke_bedrock(prompt)
    logger.info("Received Bedrock response (%d chars)", len(raw_response))

    analysis = parse_bedrock_response(raw_response)

    # Resolve the playbook that was used so it can be recorded in the output.
    enrichment = event.get("enrichment_result", {})
    if isinstance(enrichment, dict) and "enrichment" in enrichment:
        enrichment = enrichment["enrichment"]
    finding_type = enrichment.get("finding", {}).get("Type", "")
    description = event.get("description", "")
    playbook = select_playbook(finding_type=finding_type, description=description)

    analysis["ticket_number"] = event.get("ticket_number", "UNKNOWN")
    analysis["finding_id"] = event.get("finding_id", "")
    analysis["model_id"] = BEDROCK_MODEL_ID
    analysis["playbook"] = playbook.name
    analysis["analysis_timestamp"] = datetime.now(tz=timezone.utc).isoformat()

    logger.info(
        "Analysis complete: ticket=%s verdict=%s confidence=%s playbook=%s",
        analysis["ticket_number"],
        analysis["verdict"],
        analysis["confidence"],
        analysis["playbook"],
    )

    return analysis
