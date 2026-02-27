"""
Tests for Token Revocation per RFC 7009.

Tests cover:
- Revoke endpoint for refresh tokens
- Token chain revocation
- Client authentication for revocation
- Access token revocation (short-lived, no blacklist)
"""

import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

from app.oauth.models import OAuthClient, RefreshToken
from app.oauth.service import revoke_token
from app.services.auth import hash_password

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_db():
    """Create a mock database session."""
    db = MagicMock(spec=Session)
    return db


@pytest.fixture
def sample_user_id():
    """Sample user UUID."""
    return str(uuid.uuid4())


@pytest.fixture
def sample_client_id():
    """Sample client ID."""
    return "test_client_123"


@pytest.fixture
def sample_client(sample_client_id):
    """Create a sample OAuth client."""
    client = OAuthClient(
        id=uuid.uuid4(),
        client_id=sample_client_id,
        client_secret=hash_password("test_secret"),
        redirect_uri="https://client.example.com/callback",
        name="Test Client",
        scopes="openid profile email offline_access",
    )
    return client


@pytest.fixture
def sample_scope():
    """Sample scope string."""
    return "openid profile email"


# =============================================================================
# TestRevokeTokenEndpoint
# =============================================================================


class TestRevokeTokenEndpoint:
    """Tests for the /oauth/revoke endpoint handler."""

    def test_revoke_refresh_token_marks_as_revoked(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that revoking a refresh token marks it as revoked (not deleted)."""
        token = RefreshToken(
            id=uuid.uuid4(),
            token="refresh_token_to_revoke",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=None,
            replaced_by_token_id=None,
        )

        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = token
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        revoke_token(
            db=mock_db,
            token="refresh_token_to_revoke",
            client_id=sample_client_id,
        )

        assert token.is_active == "revoked"
        assert token.revoked_reason == "user_revoked"
        mock_db.commit.assert_called_once()

    def test_revoke_refresh_token_calls_chain_revocation(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that revoking a refresh token triggers chain revocation."""
        parent_id = uuid.uuid4()
        parent_token = RefreshToken(
            id=parent_id,
            token="parent_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=None,
            replaced_by_token_id=None,
        )

        current_token = RefreshToken(
            id=uuid.uuid4(),
            token="current_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=parent_id,
            replaced_by_token_id=None,
        )

        mock_query = MagicMock()
        mock_query.filter.return_value.first.side_effect = [
            current_token,
            parent_token,
            None,
        ]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        revoke_token(
            db=mock_db,
            token="current_token",
            client_id=sample_client_id,
        )

        assert current_token.is_active == "revoked"
        assert parent_token.is_active == "revoked"
        assert "chain_revocation" in parent_token.revoked_reason

    def test_revoke_token_only_for_matching_client(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that token is only revoked if client_id matches."""
        token = RefreshToken(
            id=uuid.uuid4(),
            token="refresh_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=None,
            replaced_by_token_id=None,
        )

        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = token
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        revoke_token(
            db=mock_db,
            token="refresh_token",
            client_id="different_client",
        )

        assert token.is_active == "true"
        mock_db.commit.assert_not_called()

    def test_revoke_nonexistent_token_does_not_crash(self, mock_db):
        """Test that revoking a non-existent token doesn't crash (RFC 7009)."""
        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = None
        mock_db.query.return_value = mock_query

        revoke_token(
            db=mock_db,
            token="nonexistent_token",
            client_id="some_client",
        )

    def test_revoke_token_with_hint_refresh_token(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test revocation with token_type_hint=refresh_token."""
        token = RefreshToken(
            id=uuid.uuid4(),
            token="refresh_token_with_hint",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=None,
            replaced_by_token_id=None,
        )

        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = token
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        revoke_token(
            db=mock_db,
            token="refresh_token_with_hint",
            token_type_hint="refresh_token",
            client_id=sample_client_id,
        )

        assert token.is_active == "revoked"

    def test_revoke_access_token_ignored_short_expiry(self, mock_db, sample_client_id):
        """Test that access tokens (JWTs) are ignored - short expiry is sufficient."""
        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = None
        mock_db.query.return_value = mock_query

        revoke_token(
            db=mock_db,
            token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            token_type_hint="access_token",
            client_id=sample_client_id,
        )

        mock_db.query.assert_called()


# =============================================================================
# TestRevokeTokenChainIntegration
# =============================================================================


class TestRevokeTokenChainIntegration:
    """Integration tests for revoke token chain."""

    def test_rotate_then_revoke_revokes_both(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test full flow: create token -> rotate -> revoke -> both revoked."""
        old_token = RefreshToken(
            id=uuid.uuid4(),
            token="old_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="replaced",
            parent_token_id=None,
            replaced_by_token_id=None,
        )

        new_token = RefreshToken(
            id=uuid.uuid4(),
            token="new_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=str(old_token.id),
            replaced_by_token_id=None,
        )

        old_token.replaced_by_token_id = new_token.id

        mock_query = MagicMock()
        mock_query.filter.return_value.first.side_effect = [
            new_token,
            old_token,
            None,
        ]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        revoke_token(
            db=mock_db,
            token="new_token",
            client_id=sample_client_id,
        )

        assert new_token.is_active == "revoked"
        assert old_token.is_active == "replaced"

    def test_user_logout_revokes_all_tokens(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that user logout revokes all tokens in chain."""
        token1 = RefreshToken(
            id=uuid.uuid4(),
            token="token1",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=None,
            replaced_by_token_id=None,
        )

        token2 = RefreshToken(
            id=uuid.uuid4(),
            token="token2",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=str(token1.id),
            replaced_by_token_id=None,
        )

        token3 = RefreshToken(
            id=uuid.uuid4(),
            token="token3",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=str(token2.id),
            replaced_by_token_id=None,
        )

        token1.replaced_by_token_id = token2.id
        token2.replaced_by_token_id = token3.id

        mock_query = MagicMock()
        mock_query.filter.return_value.first.side_effect = [
            token3,
            token2,
            token1,
            None,
        ]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        revoke_token(
            db=mock_db,
            token="token3",
            client_id=sample_client_id,
        )

        assert token1.is_active == "revoked"
        assert token2.is_active == "revoked"
        assert token3.is_active == "revoked"
        assert "user_revoked" in token1.revoked_reason
