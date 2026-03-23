"""
tests/test_api_authorizer.py

Unit tests for the api_authorizer Lambda handler.
"""

from __future__ import annotations

import importlib.util
import os
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError


def _load_handler(module_name: str, relative_path: str):
    abs_path = os.path.join(os.path.dirname(__file__), relative_path)
    spec = importlib.util.spec_from_file_location(module_name, abs_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


auth_handler = _load_handler("api_authorizer_handler", "../lambdas/api_authorizer/handler.py")

SECRET_ARN = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:ir-api-key-abc123"
VALID_KEY = "super-secret-key-abc123"


def _make_event(key: str | None = VALID_KEY) -> dict:
    headers: dict = {}
    if key is not None:
        headers["x-api-key"] = key
    return {"headers": headers, "requestContext": {}}


def _mock_sm(key: str = VALID_KEY):
    client = MagicMock()
    client.get_secret_value.return_value = {"SecretString": key}
    return client


class TestLambdaHandler:
    def setup_method(self):
        # Reset module cache before each test
        auth_handler._cached_api_key = None

    def test_valid_key_returns_true(self):
        with patch.object(auth_handler, "API_KEY_SECRET_ARN", SECRET_ARN):
            with patch.object(auth_handler, "_secrets_client", return_value=_mock_sm()):
                result = auth_handler.lambda_handler(_make_event(VALID_KEY), None)
        assert result is True

    def test_missing_header_returns_false(self):
        event = {"headers": {}}
        with patch.object(auth_handler, "API_KEY_SECRET_ARN", SECRET_ARN):
            with patch.object(auth_handler, "_secrets_client", return_value=_mock_sm()):
                result = auth_handler.lambda_handler(event, None)
        assert result is False

    def test_null_headers_returns_false(self):
        event = {"headers": None}
        with patch.object(auth_handler, "API_KEY_SECRET_ARN", SECRET_ARN):
            with patch.object(auth_handler, "_secrets_client", return_value=_mock_sm()):
                result = auth_handler.lambda_handler(event, None)
        assert result is False

    def test_wrong_key_returns_false(self):
        with patch.object(auth_handler, "API_KEY_SECRET_ARN", SECRET_ARN):
            with patch.object(auth_handler, "_secrets_client", return_value=_mock_sm()):
                result = auth_handler.lambda_handler(_make_event("wrong-key"), None)
        assert result is False

    def test_secrets_manager_error_returns_false(self):
        mock_client = MagicMock()
        mock_client.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Not found"}},
            "GetSecretValue",
        )
        with patch.object(auth_handler, "API_KEY_SECRET_ARN", SECRET_ARN):
            with patch.object(auth_handler, "_secrets_client", return_value=mock_client):
                result = auth_handler.lambda_handler(_make_event(VALID_KEY), None)
        assert result is False

    def test_missing_secret_arn_returns_false(self):
        with patch.object(auth_handler, "API_KEY_SECRET_ARN", ""):
            result = auth_handler.lambda_handler(_make_event(VALID_KEY), None)
        assert result is False

    def test_key_is_cached_across_invocations(self):
        mock_client = _mock_sm()
        with patch.object(auth_handler, "API_KEY_SECRET_ARN", SECRET_ARN):
            with patch.object(auth_handler, "_secrets_client", return_value=mock_client):
                auth_handler.lambda_handler(_make_event(VALID_KEY), None)
                auth_handler.lambda_handler(_make_event(VALID_KEY), None)
                auth_handler.lambda_handler(_make_event(VALID_KEY), None)
        # Secrets Manager should only be called once per Lambda execution environment
        mock_client.get_secret_value.assert_called_once()

    def test_x_api_key_capitalised_header_accepted(self):
        """Header matching is case-insensitive via explicit fallback."""
        event = {"headers": {"X-Api-Key": VALID_KEY}}
        with patch.object(auth_handler, "API_KEY_SECRET_ARN", SECRET_ARN):
            with patch.object(auth_handler, "_secrets_client", return_value=_mock_sm()):
                result = auth_handler.lambda_handler(event, None)
        assert result is True
