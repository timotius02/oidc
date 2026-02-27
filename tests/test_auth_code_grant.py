"""
Tests for OAuth 2.0 Authorization Code Grant flow per RFC 6749.
"""

import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.oauth.errors import OAuthError
from app.oauth.models import AuthorizationCode, OAuthClient
from app.oauth.service import handle_authorization_code_grant
from app.services.auth import hash_password


@pytest.fixture
def mock_db():
    """Create a mock database session."""
    db = MagicMock(spec=Session)
    return db


def test_auth_code_grant_without_redirect_uri_succeeds_if_missing_in_auth_request(
    mock_db,
):
    """
    Verify auth_code grant succeeds without redirect_uri if it was absent in /authorize.
    Per RFC 6749 §4.1.3.
    """
    client = OAuthClient(
        client_id="test_client",
        client_secret=hash_password("test_secret"),
        redirect_uri="http://localhost/callback",
        client_type="confidential",
    )

    # auth_code.redirect_uri is None (was omitted in initial request)
    code_record = AuthorizationCode(
        code="test_code",
        client_id="test_client",
        redirect_uri=None,
        user_id=str(uuid.uuid4()),
        scope="openid",
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )

    mock_query = MagicMock()
    mock_query.filter.return_value.first.side_effect = [client, code_record]
    mock_db.query.return_value = mock_query

    with (
        patch("app.oauth.service.create_access_token", return_value=("access", "jti")),
        patch("app.oauth.service.create_refresh_token", return_value="refresh"),
    ):
        # Call WITHOUT redirect_uri
        response = handle_authorization_code_grant(
            db=mock_db,
            code="test_code",
            client_id="test_client",
            client_secret="test_secret",
            redirect_uri=None,
            code_verifier=None,
            scope=None,
        )

    assert response.status_code == 200


def test_auth_code_grant_fails_without_redirect_uri_if_present_in_auth_request(mock_db):
    """
    Verify auth_code grant FAILS without redirect_uri if it was present in /authorize.
    Per RFC 6749 §4.1.3.
    """
    client = OAuthClient(
        client_id="test_client",
        client_secret=hash_password("test_secret"),
        redirect_uri="http://localhost/callback",
        client_type="confidential",
    )

    # auth_code.redirect_uri is present
    code_record = AuthorizationCode(
        code="test_code",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        user_id=str(uuid.uuid4()),
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )

    mock_query = MagicMock()
    mock_query.filter.return_value.first.side_effect = [client, code_record]
    mock_db.query.return_value = mock_query

    with pytest.raises(OAuthError) as exc:
        handle_authorization_code_grant(
            db=mock_db,
            code="test_code",
            client_id="test_client",
            client_secret="test_secret",
            redirect_uri=None,  # Missing!
            code_verifier=None,
            scope=None,
        )

    assert "Missing required parameter: redirect_uri" in str(exc.value.description)
