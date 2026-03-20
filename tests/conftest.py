"""
conftest.py – pytest configuration for the incident-response project.

Sets environment variables required by all Lambda handlers so tests can be
run without real AWS credentials.
"""

import os

import pytest


@pytest.fixture(autouse=True)
def aws_env_vars(monkeypatch):
    """Set dummy AWS environment variables for all tests."""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")  # noqa: S105
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "test")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "test")
    monkeypatch.setenv("ARTIFACTS_BUCKET", "test-artifacts-bucket")
    monkeypatch.setenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0")
    monkeypatch.setenv("GOOGLE_SECOPS_API_ENDPOINT", "")
    monkeypatch.setenv("GOOGLE_SECOPS_CUSTOMER_ID", "")
    monkeypatch.setenv("GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN", "")
    monkeypatch.setenv("ENABLE_VPC_FLOW_LOG_COLLECTION", "false")
    monkeypatch.setenv("ENABLE_CLOUDTRAIL_COLLECTION", "false")
