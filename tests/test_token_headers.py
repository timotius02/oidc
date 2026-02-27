"""
Tests for OAuth 2.0 Token Response Headers per RFC 6749.
"""

import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.oauth.models import AuthorizationCode, OAuthClient
from app.oauth.service import (
    handle_authorization_code_grant,
    handle_refresh_token_grant,
)
from app.oauth.utils import create_token_response


@pytest.fixture
def mock_db():
    """Create a mock database session."""
    db = MagicMock(spec=Session)
    return db


def test_utility_headers():
    """Verify the create_token_response utility adds correct headers."""
    content = {"access_token": "test_access_token"}
    response = create_token_response(content)

    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.status_code == 200


def test_authorization_code_grant_headers(mock_db):
    """Verify headers in authorization_code grant response."""
    # Setup mocks
    client = OAuthClient(
        client_id="test_client",
        client_secret="test_secret",
        redirect_uri="http://localhost/callback",
        client_type="confidential",
    )

    code_record = AuthorizationCode(
        code="test_code",
        client_id="test_client",
        redirect_uri="http://localhost/callback",
        user_id=str(uuid.uuid4()),
        scope="openid profile",
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )

    mock_query = MagicMock()
    mock_query.filter.return_value.first.side_effect = [client, code_record]
    mock_db.query.return_value = mock_query

    # Mock JWT and token creation to avoid side effects
    with (
        patch(
            "app.oauth.service.create_access_token",
            return_value=("access_token", "jti"),
        ),
        patch("app.oauth.service.create_refresh_token", return_value="refresh_token"),
    ):
        response = handle_authorization_code_grant(
            db=mock_db,
            code="test_code",
            client_id="test_client",
            client_secret="test_secret",
            redirect_uri="http://localhost/callback",
            code_verifier=None,
            scope=None,
        )

    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_refresh_token_grant_headers(mock_db):
    """Verify headers in refresh_token grant response."""
    # Setup mocks
    client = OAuthClient(
        client_id="test_client", client_secret="test_secret", client_type="confidential"
    )

    from app.oauth.models import RefreshToken

    refresh_token_record = RefreshToken(
        token="old_refresh_token",
        client_id="test_client",
        user_id=str(uuid.uuid4()),
        expires_at=datetime.utcnow() + timedelta(days=7),
        is_active="true",
        scope="openid profile",
    )

    mock_query = MagicMock()
    mock_query.filter.return_value.first.side_effect = [client, refresh_token_record]
    mock_db.query.return_value = mock_query

    # Mock validations and token creation
    with (
        patch(
            "app.oauth.service.validate_refresh_token",
            return_value=refresh_token_record,
        ),
        patch(
            "app.oauth.service.create_access_token",
            return_value=("new_access_token", "jti"),
        ),
        patch(
            "app.oauth.service.rotate_refresh_token", return_value="new_refresh_token"
        ),
    ):
        response = handle_refresh_token_grant(
            db=mock_db,
            refresh_token="old_refresh_token",
            client_id="test_client",
            client_secret="test_secret",
            scope=None,
        )

    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
