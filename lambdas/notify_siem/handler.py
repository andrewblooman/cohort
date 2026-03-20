"""
notify_siem/handler.py

Lambda function: Notify SIEM

Fifth and final step in the incident-response Step Functions workflow.
Sends the AI-generated verdict and recommendation back to Google SecOps
(Chronicle) as a case comment / SOAR action so that analysts can see the
automated triage result directly in their SIEM.

Google SecOps API integration uses a service-account credentials JSON
stored in AWS Secrets Manager.  The function will skip notification
gracefully if the credentials or endpoint are not configured.

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

def build_siem_comment(event: dict, analysis: dict, store_result: dict) -> str:
    """Build the comment text to post back to Google SecOps."""
    ticket_number = event.get("ticket_number", "UNKNOWN")
    finding_id = event.get("finding_id", "")
    verdict = analysis.get("verdict", "INCONCLUSIVE")
    confidence = analysis.get("confidence", "LOW")
    label = VERDICT_LABEL.get(verdict, verdict)
    threat_summary = analysis.get("threat_summary", "No summary available.")
    recommendations = analysis.get("recommendations", [])
    s3_bucket = store_result.get("s3_bucket", ARTIFACTS_BUCKET)
    s3_prefix = store_result.get("s3_prefix", f"{ticket_number}/")

    rec_lines = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(recommendations)) if recommendations else "  None"

    comment = f"""## AWS Incident Response AI Analysis Complete

**Ticket**: {ticket_number}  
**Finding ID**: {finding_id}  
**Verdict**: {label}  
**Confidence**: {confidence}  

### Summary
{threat_summary}

### Recommended Actions
{rec_lines}

### Artifacts
All evidence has been stored in S3:  
`s3://{s3_bucket}/{s3_prefix}`

The full AI recommendation is available at:  
`s3://{s3_bucket}/{s3_prefix}ai_recommendation.txt`

---
*Automated analysis by AWS Incident Response AI Agent*  
*Analysis timestamp: {datetime.now(tz=timezone.utc).isoformat()}*
"""
    return comment


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: dict, context: Any) -> dict:  # noqa: ARG001
    """Entry point for the notify-SIEM Lambda.

    Args:
        event: Step Functions payload containing ticket_number, finding_id,
               secops_case_id, analysis_result, and store_result.
        context: Lambda context (unused).

    Returns:
        Dict describing the notification outcome.
    """
    logger.info("notify_siem invoked for ticket=%s", event.get("ticket_number", "UNKNOWN"))

    ticket_number = event.get("ticket_number", "UNKNOWN")
    secops_case_id = event.get("secops_case_id", "")

    # Extract nested analysis / store results from Step Functions output
    analysis_wrapper = event.get("analysis_result", {})
    analysis = analysis_wrapper.get("analysis", analysis_wrapper)

    store_wrapper = event.get("store_result", {})
    store_result = store_wrapper.get("store", store_wrapper)

    verdict = analysis.get("verdict", "INCONCLUSIVE")
    confidence = analysis.get("confidence", "LOW")

    # Build the comment to post to the SIEM
    comment = build_siem_comment(event, analysis, store_result)

    # Only attempt SIEM notification when a case ID and endpoint are configured
    if not secops_case_id:
        logger.info("No secops_case_id provided; skipping SIEM notification")
        return {
            "ticket_number": ticket_number,
            "verdict": verdict,
            "confidence": confidence,
            "notification_status": "skipped",
            "reason": "No secops_case_id in event",
            "comment": comment,
            "notify_timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }

    if not GOOGLE_SECOPS_API_ENDPOINT:
        logger.info("GOOGLE_SECOPS_API_ENDPOINT not set; skipping SIEM notification")
        return {
            "ticket_number": ticket_number,
            "verdict": verdict,
            "confidence": confidence,
            "notification_status": "skipped",
            "reason": "GOOGLE_SECOPS_API_ENDPOINT not configured",
            "comment": comment,
            "notify_timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }

    credentials = get_google_credentials()
    if not credentials:
        logger.warning("Could not obtain Google credentials; skipping SIEM notification")
        return {
            "ticket_number": ticket_number,
            "verdict": verdict,
            "confidence": confidence,
            "notification_status": "skipped",
            "reason": "Google credentials unavailable",
            "comment": comment,
            "notify_timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }

    access_token = get_access_token(credentials)
    if not access_token:
        return {
            "ticket_number": ticket_number,
            "verdict": verdict,
            "confidence": confidence,
            "notification_status": "failed",
            "reason": "Could not obtain Google access token",
            "notify_timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }

    notify_result = post_case_comment(secops_case_id, comment, access_token)

    return {
        "ticket_number": ticket_number,
        "verdict": verdict,
        "confidence": confidence,
        "notification_status": "success" if notify_result.get("success") else "failed",
        "secops_case_id": secops_case_id,
        "siem_response": notify_result,
        "comment": comment,
        "notify_timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }
