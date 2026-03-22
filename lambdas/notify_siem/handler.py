"""
notify_siem/handler.py

Lambda function: Notify SIEM

Used at two points in the incident-response Step Functions workflow:

Phase 1 — Investigation complete (notify_mode = "investigation", default):
    Posts the AI verdict and proposed actions to Google SecOps as a case comment.
    When invoked via the ``NotifySIEM`` waitForTaskToken state, the event will
    include a ``task_token``; this token is embedded in the comment so the analyst
    can use it to call the ``approve_actions`` Lambda and resume the workflow.

Phase 2 — Execution complete (notify_mode = "execution_results"):
    Posts the execution results (which actions were run, success/failure) back to
    the case after the analyst has approved and actions have been executed.

Google SecOps API integration uses a service-account credentials JSON stored in
AWS Secrets Manager.  The function skips notification gracefully if credentials
or the endpoint are not configured.

Environment variables:
  GOOGLE_SECOPS_API_ENDPOINT            – base URL, e.g. https://backstory.googleapis.com
  GOOGLE_SECOPS_CUSTOMER_ID             – Chronicle customer UUID
  GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN  – Secrets Manager ARN for service-account JSON
  ARTIFACTS_BUCKET                      – name of the S3 bucket (included in notification)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

GOOGLE_SECOPS_API_ENDPOINT = os.environ.get("GOOGLE_SECOPS_API_ENDPOINT", "")
GOOGLE_SECOPS_CUSTOMER_ID = os.environ.get("GOOGLE_SECOPS_CUSTOMER_ID", "")
GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN = os.environ.get("GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN", "")
ARTIFACTS_BUCKET = os.environ.get("ARTIFACTS_BUCKET", "")

VERDICT_LABEL = {
    "TRUE_POSITIVE": "TRUE POSITIVE – CONFIRMED THREAT",
    "FALSE_POSITIVE": "FALSE POSITIVE – BENIGN ACTIVITY",
    "INCONCLUSIVE": "INCONCLUSIVE – MANUAL REVIEW REQUIRED",
}


# ---------------------------------------------------------------------------
# Secrets Manager helper
# ---------------------------------------------------------------------------

def get_google_credentials() -> dict | None:
    """Retrieve Google SecOps service-account credentials from Secrets Manager."""
    if not GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN:
        logger.info("GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN not set; skipping credential retrieval")
        return None

    sm = boto3.client("secretsmanager")
    try:
        response = sm.get_secret_value(SecretId=GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN)
        secret_str = response.get("SecretString", "{}")
        return json.loads(secret_str)
    except ClientError as exc:
        logger.error("Failed to retrieve Google SecOps credentials: %s", exc)
        return None
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse Google SecOps credentials JSON: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Google SecOps OAuth2 token exchange
# ---------------------------------------------------------------------------

def get_access_token(credentials: dict) -> str | None:
    """Exchange a Google service-account key for a short-lived access token.

    Uses the OAuth2 JWT grant flow documented at:
    https://developers.google.com/identity/protocols/oauth2/service-account
    """
    try:
        import base64
        import hashlib
        import hmac
        import struct
        import time

        # Use google-auth if available (packaged with Lambda layer), otherwise
        # fall back to a minimal JWT implementation.
        try:
            from google.oauth2 import service_account
            import google.auth.transport.requests

            scopes = ["https://www.googleapis.com/auth/chronicle-backstory"]
            creds = service_account.Credentials.from_service_account_info(
                credentials, scopes=scopes
            )
            request = google.auth.transport.requests.Request()
            creds.refresh(request)
            return creds.token
        except ImportError:
            logger.warning(
                "google-auth library not available; attempting minimal JWT flow"
            )
            return _minimal_jwt_token(credentials)

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to obtain Google access token: %s", exc)
        return None


def _minimal_jwt_token(credentials: dict) -> str | None:
    """Minimal RS256 JWT implementation for environments without google-auth."""
    import base64
    import json as _json
    import time

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        private_key_pem = credentials.get("private_key", "").encode()
        client_email = credentials.get("client_email", "")
        token_uri = credentials.get("token_uri", "https://oauth2.googleapis.com/token")
        scope = "https://www.googleapis.com/auth/chronicle-backstory"

        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": client_email,
            "scope": scope,
            "aud": token_uri,
            "exp": now + 3600,
            "iat": now,
        }

        def b64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        header_b64 = b64url(_json.dumps(header).encode())
        payload_b64 = b64url(_json.dumps(payload).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()

        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        jwt_token = f"{header_b64}.{payload_b64}.{b64url(signature)}"

        # Exchange JWT for access token
        data = (
            f"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
            f"&assertion={jwt_token}"
        ).encode()
        req = Request(token_uri, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urlopen(req, timeout=10) as resp:
            token_response = _json.loads(resp.read())
            return token_response.get("access_token")
    except Exception as exc:  # noqa: BLE001
        logger.error("Minimal JWT token exchange failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Google SecOps API calls
# ---------------------------------------------------------------------------

def post_case_comment(
    case_id: str,
    comment: str,
    access_token: str,
) -> dict:
    """Add a comment to a Google SecOps (Chronicle SOAR) case."""
    if not GOOGLE_SECOPS_API_ENDPOINT or not GOOGLE_SECOPS_CUSTOMER_ID:
        logger.info("Google SecOps endpoint/customer not configured; skipping comment post")
        return {"skipped": True, "reason": "Google SecOps not configured"}

    url = urljoin(
        GOOGLE_SECOPS_API_ENDPOINT,
        f"/v1/projects/{GOOGLE_SECOPS_CUSTOMER_ID}/locations/us/instances/default/cases/{case_id}/comments",
    )

    payload = {
        "body": comment,
        "creator": {
            "email": "aws-incident-response-bot@automated",
            "fullName": "AWS Incident Response AI Agent",
        },
    }

    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    try:
        req = Request(url, data=body, headers=headers, method="POST")
        with urlopen(req, timeout=30) as resp:
            response_data = json.loads(resp.read())
            logger.info("Posted case comment for case_id=%s", case_id)
            return {"success": True, "response": response_data}
    except HTTPError as exc:
        logger.error("HTTP error posting case comment: %s %s", exc.code, exc.reason)
        return {"success": False, "error": f"HTTP {exc.code}: {exc.reason}"}
    except URLError as exc:
        logger.error("URL error posting case comment: %s", exc)
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Notification message builder
# ---------------------------------------------------------------------------

def _store_pending_approval(ticket_number: str, task_token: str, analysis: dict) -> None:
    """Write pending_approval.json to S3 so the web UI can surface the task token.

    This file is read by the get_investigation Lambda and presented to analysts
    so they can approve or reject proposed actions from the web dashboard.
    """
    if not ARTIFACTS_BUCKET or not task_token or not ticket_number:
        return
    s3 = boto3.client("s3")
    data = {
        "task_token": task_token,
        "ticket_number": ticket_number,
        "verdict": analysis.get("verdict"),
        "confidence": analysis.get("confidence"),
        "proposed_actions": analysis.get("proposed_actions", []),
        "threat_summary": analysis.get("threat_summary", ""),
        "stored_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    try:
        s3.put_object(
            Bucket=ARTIFACTS_BUCKET,
            Key=f"{ticket_number}/pending_approval.json",
            Body=json.dumps(data, indent=2).encode("utf-8"),
            ContentType="application/json",
        )
        logger.info("Stored pending_approval.json for ticket=%s", ticket_number)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not store pending_approval.json for ticket=%s: %s", ticket_number, exc)


def build_siem_comment(event: dict, analysis: dict, store_result: dict) -> str:
    """Build the Phase 1 investigation comment to post to Google SecOps.

    When a ``task_token`` is present in the event (waitForTaskToken invocation),
    it is embedded in the comment so the analyst can use it to call the
    ``approve_actions`` Lambda and resume the Step Functions workflow.
    """
    ticket_number = event.get("ticket_number", "UNKNOWN")
    finding_id = event.get("finding_id", "")
    verdict = analysis.get("verdict", "INCONCLUSIVE")
    confidence = analysis.get("confidence", "LOW")
    label = VERDICT_LABEL.get(verdict, verdict)
    threat_summary = analysis.get("threat_summary", "No summary available.")
    proposed_actions = analysis.get("proposed_actions", analysis.get("recommendations", []))
    s3_bucket = store_result.get("s3_bucket", ARTIFACTS_BUCKET)
    s3_prefix = store_result.get("s3_prefix", f"{ticket_number}/")
    task_token = event.get("task_token", "")

    action_lines = (
        "\n".join(f"  - [ ] {a}" for a in proposed_actions)
        if proposed_actions
        else "  _No specific actions proposed._"
    )

    approval_section = ""
    if task_token:
        approval_section = f"""
### 🔑 Analyst Approval Callback

To **approve** selected actions, invoke the `approve_actions` Lambda (or POST to the
`/approve` API endpoint) with the following payload — replacing `approved_actions`
with the specific structured actions you authorise:

```json
{{
  "task_token": "{task_token}",
  "analyst_id": "<your-email>",
  "approval_notes": "<optional context>",
  "approved_actions": [
    {{
      "action_id": "action-1",
      "type": "<action_type>",
      "parameters": {{ ... }}
    }}
  ]
}}
```

To **reject** (take no action), send `"action": "reject"` with the same token.

> ⏱️ This approval window expires in **7 days**. After expiry the workflow will close without executing any actions.
"""

    comment = f"""## AWS Incident Response AI Analysis Complete

**Ticket**: {ticket_number}  
**Finding ID**: {finding_id}  
**Verdict**: {label}  
**Confidence**: {confidence}  

### Summary
{threat_summary}

---

### ⚠️ Proposed Actions — PENDING ANALYST APPROVAL

> **IMPORTANT: NO AUTOMATED ACTIONS HAVE BEEN TAKEN.**  
> The AI agent is an investigator only. The actions listed below are **proposals** and have **not** been executed.  
> Each action requires explicit review and authorization by a human analyst before any remediation is performed.

{action_lines}

**To authorize remediation:** Review each proposed action above, confirm it is appropriate for this incident, and execute only those actions you approve.
{approval_section}
### Artifacts
All evidence has been stored in S3:  
`s3://{s3_bucket}/{s3_prefix}`

The full AI recommendation is available at:  
`s3://{s3_bucket}/{s3_prefix}ai_recommendation.txt`

---
*Automated analysis by AWS Incident Response AI Agent — investigative role only*  
*Analysis timestamp: {datetime.now(tz=timezone.utc).isoformat()}*
"""
    return comment


def build_execution_comment(event: dict, execution: dict) -> str:
    """Build the Phase 2 comment posted after approved actions have been executed."""
    ticket_number = event.get("ticket_number", "UNKNOWN")
    analyst_id = execution.get("analyst_id", "unknown")
    approval_notes = execution.get("approval_notes", "")
    approval_timestamp = execution.get("approval_timestamp", "")
    execution_timestamp = execution.get("execution_timestamp", "")
    total = execution.get("total_actions", 0)
    succeeded = execution.get("succeeded", 0)
    failed = execution.get("failed", 0)
    results = execution.get("results", [])

    status_emoji = "✅" if failed == 0 else "⚠️"
    result_lines = []
    for r in results:
        icon = "✅" if r["status"] == "succeeded" else ("❌" if r["status"] == "failed" else "⏭️")
        detail = r.get("details") or r.get("error", "")
        result_lines.append(f"  {icon} **{r['type']}** (`{r['action_id']}`): {r['status']} — {detail}")

    result_block = "\n".join(result_lines) if result_lines else "  _No actions were executed._"
    notes_line = f"\n**Analyst notes:** {approval_notes}" if approval_notes else ""

    comment = f"""## {status_emoji} AWS Incident Response — Remediation Executed

**Ticket**: {ticket_number}  
**Authorised by**: {analyst_id}  
**Approval timestamp**: {approval_timestamp}  
**Execution timestamp**: {execution_timestamp}  
**Actions**: {succeeded}/{total} succeeded{f", {failed} failed" if failed else ""}
{notes_line}

### Execution Results

{result_block}

---
*Remediation executed by AWS Incident Response system following explicit analyst approval*
"""
    return comment


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Entry point for the notify-SIEM Lambda.

    Handles two notify modes set by the ``notify_mode`` event field:

    ``"investigation"`` (default):
        Post AI verdict + proposed actions to Google SecOps.  When invoked via
        waitForTaskToken, embeds the ``task_token`` in the comment so the analyst
        can call ``approve_actions`` to resume the workflow.

    ``"execution_results"``:
        Post the execution summary (which actions ran, pass/fail) back to the
        case after the ``execute_actions`` Lambda has finished.

    Args:
        event: Step Functions payload.
        context: Lambda context (unused).

    Returns:
        Dict describing the notification outcome.
    """
    ticket_number = event.get("ticket_number", "UNKNOWN")
    notify_mode = event.get("notify_mode", "investigation")
    logger.info("notify_siem invoked for ticket=%s mode=%s", ticket_number, notify_mode)

    secops_case_id = event.get("secops_case_id", "")

    # ---- Build comment based on mode ----
    if notify_mode == "execution_results":
        execution_wrapper = event.get("execution_result", {})
        execution = execution_wrapper.get("execution", execution_wrapper)
        comment = build_execution_comment(event, execution)
        verdict = "EXECUTED"
        confidence = ""
        approval_status = "ACTIONS_EXECUTED"
    else:
        # investigation mode (default)
        analysis_wrapper = event.get("analysis_result", {})
        analysis = analysis_wrapper.get("analysis", analysis_wrapper)
        store_wrapper = event.get("store_result", {})
        store_result = store_wrapper.get("store", store_wrapper)
        verdict = analysis.get("verdict", "INCONCLUSIVE")
        confidence = analysis.get("confidence", "LOW")
        approval_status = analysis.get("approval_status", "PENDING_HUMAN_APPROVAL")
        comment = build_siem_comment(event, analysis, store_result)
        task_token = event.get("task_token", "")
        if task_token:
            _store_pending_approval(ticket_number, task_token, analysis)

    base_result = {
        "ticket_number": ticket_number,
        "notify_mode": notify_mode,
        "verdict": verdict,
        "confidence": confidence,
        "approval_status": approval_status,
        "notify_timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }

    # Only attempt SIEM notification when a case ID and endpoint are configured
    if not secops_case_id:
        logger.info("No secops_case_id provided; skipping SIEM notification")
        return {**base_result, "notification_status": "skipped", "reason": "No secops_case_id in event", "comment": comment}

    if not GOOGLE_SECOPS_API_ENDPOINT:
        logger.info("GOOGLE_SECOPS_API_ENDPOINT not set; skipping SIEM notification")
        return {**base_result, "notification_status": "skipped", "reason": "GOOGLE_SECOPS_API_ENDPOINT not configured", "comment": comment}

    credentials = get_google_credentials()
    if not credentials:
        logger.warning("Could not obtain Google credentials; skipping SIEM notification")
        return {**base_result, "notification_status": "skipped", "reason": "Google credentials unavailable", "comment": comment}

    access_token = get_access_token(credentials)
    if not access_token:
        return {**base_result, "notification_status": "failed", "reason": "Could not obtain Google access token"}

    notify_result = post_case_comment(secops_case_id, comment, access_token)

    return {
        **base_result,
        "notification_status": "success" if notify_result.get("success") else "failed",
        "secops_case_id": secops_case_id,
        "siem_response": notify_result,
        "comment": comment,
    }
