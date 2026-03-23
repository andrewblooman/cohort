"""
api_authorizer/handler.py

Lambda REQUEST authorizer for the Cohort API Gateway.

Validates the X-Api-Key header against the value stored in AWS Secrets Manager.
API Gateway caches the result for `authorizer_result_ttl_in_seconds` seconds
(configured in Terraform) so Secrets Manager is not hit on every request.

When `enable_simple_responses` is True (as configured), API Gateway expects the
handler to return a plain boolean:
  - True  → allow the request
  - False → reject with 403

Environment variables:
  API_KEY_SECRET_ARN  ARN of the Secrets Manager secret containing the API key.
  AWS_DEFAULT_REGION  AWS region (set by Lambda runtime; overridden in Terraform).
"""

from __future__ import annotations

import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

API_KEY_SECRET_ARN = os.environ.get("API_KEY_SECRET_ARN", "")
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "eu-west-1")

# Module-level cache so repeated invocations within the same Lambda execution
# environment avoid redundant Secrets Manager calls between cache TTL refreshes.
_cached_api_key: str | None = None


def _secrets_client() -> Any:
    return boto3.client("secretsmanager", region_name=AWS_REGION)


def _get_api_key() -> str:
    """Fetch the API key from Secrets Manager, using the module cache."""
    global _cached_api_key
    if _cached_api_key is not None:
        return _cached_api_key

    if not API_KEY_SECRET_ARN:
        logger.error("API_KEY_SECRET_ARN is not configured")
        return ""

    try:
        response = _secrets_client().get_secret_value(SecretId=API_KEY_SECRET_ARN)
        _cached_api_key = response["SecretString"]
        return _cached_api_key
    except ClientError as exc:
        logger.error("Failed to retrieve API key from Secrets Manager: %s", exc)
        return ""


def lambda_handler(event: dict, context: Any) -> bool:  # noqa: ARG001
    """Validate the X-Api-Key header.

    Args:
        event:   API Gateway authorizer event (payload format version 2.0).
        context: Lambda context (unused).

    Returns:
        True if the supplied key matches the stored secret, False otherwise.
    """
    headers = event.get("headers") or {}
    supplied_key = headers.get("x-api-key") or headers.get("X-Api-Key") or ""

    if not supplied_key:
        logger.warning("Request rejected: X-Api-Key header missing")
        return False

    expected_key = _get_api_key()
    if not expected_key:
        logger.error("Request rejected: could not retrieve expected API key")
        return False

    if supplied_key != expected_key:
        logger.warning("Request rejected: invalid API key")
        return False

    logger.info("Request authorised")
    return True
