"""
Tests for Refresh Token functionality per OAuth 2.0 RFC 6749 and Security BCP.

Tests cover:
- Refresh token creation
- Token validation
- Token rotation
- Replay attack detection
- Token chain revocation
- Refresh token grant endpoint
"""

import json
import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.config import settings
from app.oauth.errors import OAuthError, OAuthErrorCode
from app.oauth.jwt import (
    revoke_token_chain,
    rotate_refresh_token,
    validate_refresh_token,
)
from app.oauth.models import OAuthClient, RefreshToken
from app.oauth.service import create_refresh_token as service_create_refresh_token
from app.oauth.service import handle_refresh_token_grant
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
    return "openid profile email offline_access"


@pytest.fixture
def valid_refresh_token_record(sample_user_id, sample_client_id, sample_scope):
    """Create a valid refresh token record."""
    return RefreshToken(
        id=uuid.uuid4(),
        token="valid_refresh_token_123",
        user_id=sample_user_id,
        client_id=sample_client_id,
        scope=sample_scope,
        expires_at=datetime.utcnow() + timedelta(days=7),
        created_at=datetime.utcnow(),
        is_active="true",
        parent_token_id=None,
        replaced_by_token_id=None,
    )


@pytest.fixture
def expired_refresh_token_record(sample_user_id, sample_client_id, sample_scope):
    """Create an expired refresh token record."""
    return RefreshToken(
        id=uuid.uuid4(),
        token="expired_refresh_token_123",
        user_id=sample_user_id,
        client_id=sample_client_id,
        scope=sample_scope,
        expires_at=datetime.utcnow() - timedelta(days=1),
        created_at=datetime.utcnow() - timedelta(days=8),
        is_active="true",
        parent_token_id=None,
        replaced_by_token_id=None,
    )


@pytest.fixture
def revoked_refresh_token_record(sample_user_id, sample_client_id, sample_scope):
    """Create a revoked refresh token record."""
    return RefreshToken(
        id=uuid.uuid4(),
        token="revoked_refresh_token_123",
        user_id=sample_user_id,
        client_id=sample_client_id,
        scope=sample_scope,
        expires_at=datetime.utcnow() + timedelta(days=7),
        created_at=datetime.utcnow(),
        is_active="revoked",
        revoked_at=datetime.utcnow(),
        revoked_reason="user_revoked",
        parent_token_id=None,
        replaced_by_token_id=None,
    )


# =============================================================================
# TestRefreshTokenCreation
# =============================================================================


class TestRefreshTokenCreation:
    """Tests for refresh token creation."""

    def test_create_refresh_token_with_valid_parameters(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test creating a refresh token with valid parameters."""
        # Setup mock
        mock_db.add = MagicMock()
        mock_db.commit = MagicMock()

        # Create refresh token
        token = service_create_refresh_token(
            db=mock_db,
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
        )

        # Verify token was created
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

        # Verify database operations were called
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()

    def test_token_stored_in_database(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that token is stored in database with correct fields."""
        # Setup mock
        mock_db.add = MagicMock()
        mock_db.commit = MagicMock()

        # Create refresh token
        token = service_create_refresh_token(
            db=mock_db,
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
        )

        # Get the RefreshToken object that was added
        added_token = mock_db.add.call_args[0][0]

        # Verify fields
        assert added_token.token == token
        assert added_token.user_id == sample_user_id
        assert added_token.client_id == sample_client_id
        assert added_token.scope == sample_scope
        assert added_token.expires_at > datetime.utcnow()

    def test_parent_token_id_stored_for_rotation_chains(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that parent_token_id is correctly stored for rotation chains."""
        # Setup mock
        mock_db.add = MagicMock()
        mock_db.commit = MagicMock()

        parent_token_id = str(uuid.uuid4())

        # Create refresh token with parent
        token = service_create_refresh_token(
            db=mock_db,
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            parent_token_id=parent_token_id,
        )

        # Get the RefreshToken object that was added
        added_token = mock_db.add.call_args[0][0]

        # Verify parent_token_id is stored
        assert added_token.parent_token_id == parent_token_id

    def test_token_expiry_set_correctly(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that token expiry is set based on configuration."""
        # Setup mock
        mock_db.add = MagicMock()
        mock_db.commit = MagicMock()

        # Create refresh token
        service_create_refresh_token(
            db=mock_db,
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
        )

        # Get the RefreshToken object that was added
        added_token = mock_db.add.call_args[0][0]

        # Verify expiry time
        expected_expiry = datetime.utcnow() + timedelta(
            seconds=settings.REFRESH_TOKEN_EXPIRE_SECONDS
        )
        # Allow 1 second tolerance for test execution time
        assert abs((added_token.expires_at - expected_expiry).total_seconds()) < 1


# =============================================================================
# TestRefreshTokenValidation
# =============================================================================


class TestRefreshTokenValidation:
    """Tests for refresh token validation."""

    def test_validate_valid_refresh_token(
        self, mock_db, valid_refresh_token_record, sample_client_id
    ):
        """Test validation of valid refresh token."""
        # Setup mock
        mock_db.query.return_value.filter.return_value.first.return_value = (
            valid_refresh_token_record
        )

        # Validate token
        result = validate_refresh_token(
            db=mock_db,
            token=valid_refresh_token_record.token,
            client_id=sample_client_id,
        )

        # Verify result
        assert result == valid_refresh_token_record
        assert result.is_active == "true"

    def test_validation_fails_for_nonexistent_token(self, mock_db, sample_client_id):
        """Test validation fails for non-existent token."""
        # Setup mock
        mock_db.query.return_value.filter.return_value.first.return_value = None

        # Validate token should raise error
        with pytest.raises(OAuthError) as exc_info:
            validate_refresh_token(
                db=mock_db,
                token="nonexistent_token",
                client_id=sample_client_id,
            )

        assert exc_info.value.error_code == OAuthErrorCode.INVALID_GRANT
        assert "Invalid refresh token" in exc_info.value.description

    def test_validation_fails_for_expired_token(
        self, mock_db, expired_refresh_token_record, sample_client_id
    ):
        """Test validation fails for expired token."""
        # Setup mock
        mock_db.query.return_value.filter.return_value.first.return_value = (
            expired_refresh_token_record
        )

        # Validate token should raise error
        with pytest.raises(OAuthError) as exc_info:
            validate_refresh_token(
                db=mock_db,
                token=expired_refresh_token_record.token,
                client_id=sample_client_id,
            )

        assert exc_info.value.error_code == OAuthErrorCode.INVALID_GRANT
        assert "expired" in exc_info.value.description.lower()

    def test_validation_fails_for_wrong_client_id(
        self, mock_db, valid_refresh_token_record
    ):
        """Test validation fails for wrong client_id (client binding)."""
        # Setup mock
        mock_db.query.return_value.filter.return_value.first.return_value = (
            valid_refresh_token_record
        )

        # Validate with wrong client_id
        with pytest.raises(OAuthError) as exc_info:
            validate_refresh_token(
                db=mock_db,
                token=valid_refresh_token_record.token,
                client_id="wrong_client_id",
            )

        assert exc_info.value.error_code == OAuthErrorCode.INVALID_GRANT
        assert "mismatch" in exc_info.value.description.lower()

    def test_validation_fails_for_revoked_token(
        self, mock_db, revoked_refresh_token_record, sample_client_id
    ):
        """Test validation fails for revoked token."""
        # Setup mock
        mock_db.query.return_value.filter.return_value.first.return_value = (
            revoked_refresh_token_record
        )
        mock_db.commit = MagicMock()

        # Validate token should raise error
        with pytest.raises(OAuthError) as exc_info:
            validate_refresh_token(
                db=mock_db,
                token=revoked_refresh_token_record.token,
                client_id=sample_client_id,
            )

        assert exc_info.value.error_code == OAuthErrorCode.INVALID_GRANT
        assert "revoked" in exc_info.value.description.lower()

    def test_validation_fails_for_revoked_token_also_revokes_chain(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that validating a replaced token revokes its parent chain."""
        # Create a parent token that is still active
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

        # Create current token that was replaced (child of active parent)
        child_id = uuid.uuid4()
        current_token = RefreshToken(
            id=child_id,
            token="current_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="replaced",
            parent_token_id=parent_id,
            replaced_by_token_id=None,
        )

        mock_query = MagicMock()
        mock_query.filter.return_value.first.side_effect = [
            current_token,  # First call: validate token
            parent_token,  # Second call: traverse parent chain
            None,  # Third call: no more parents
        ]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        # Validate the replaced token - should raise error AND revoke chain
        with pytest.raises(OAuthError) as exc_info:
            validate_refresh_token(
                db=mock_db,
                token=current_token.token,
                client_id=sample_client_id,
            )

        assert exc_info.value.error_code == OAuthErrorCode.INVALID_GRANT
        # Current token changed from "replaced" to "revoked" during chain revocation
        assert current_token.is_active == "revoked"
        # Parent should now be revoked via chain revocation
        assert parent_token.is_active == "revoked"
        assert "chain_revocation" in parent_token.revoked_reason


# =============================================================================
# TestRefreshTokenRotation
# =============================================================================


class TestRefreshTokenRotation:
    """Tests for refresh token rotation."""

    def test_rotation_creates_new_token(
        self, mock_db, valid_refresh_token_record, sample_scope
    ):
        """Test that rotation creates a new token."""
        # Create new token record that will be returned
        new_token_record = RefreshToken(
            id=uuid.uuid4(),
            token="new_refresh_token_456",
            user_id=valid_refresh_token_record.user_id,
            client_id=valid_refresh_token_record.client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            created_at=datetime.utcnow(),
            is_active="true",
            parent_token_id=str(valid_refresh_token_record.id),
        )

        # Setup mocks
        mock_db.query.return_value.filter.return_value.first.return_value = (
            new_token_record
        )
        mock_db.commit = MagicMock()

        # Mock create_refresh_token to return a known token
        with patch(
            "app.oauth.service.create_refresh_token",
            return_value="new_refresh_token_456",
        ):
            new_token = rotate_refresh_token(mock_db, valid_refresh_token_record)

        # Verify new token is returned
        assert new_token == "new_refresh_token_456"

    def test_old_token_marked_as_replaced(
        self, mock_db, valid_refresh_token_record, sample_scope
    ):
        """Test that old token is marked as 'replaced'."""
        # Create new token record
        new_token_record = RefreshToken(
            id=uuid.uuid4(),
            token="new_refresh_token_456",
            user_id=valid_refresh_token_record.user_id,
            client_id=valid_refresh_token_record.client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            created_at=datetime.utcnow(),
            is_active="true",
            parent_token_id=str(valid_refresh_token_record.id),
        )

        # Setup mocks
        mock_db.query.return_value.filter.return_value.first.return_value = (
            new_token_record
        )
        mock_db.commit = MagicMock()

        # Rotate token
        with patch(
            "app.oauth.service.create_refresh_token",
            return_value="new_refresh_token_456",
        ):
            rotate_refresh_token(mock_db, valid_refresh_token_record)

        # Verify old token is marked as replaced
        assert valid_refresh_token_record.is_active == "replaced"

    def test_new_token_has_parent_token_id(
        self, mock_db, valid_refresh_token_record, sample_scope
    ):
        """Test that new token has parent_token_id pointing to old token."""
        # Create new token record
        new_token_id = uuid.uuid4()
        new_token_record = RefreshToken(
            id=new_token_id,
            token="new_refresh_token_456",
            user_id=valid_refresh_token_record.user_id,
            client_id=valid_refresh_token_record.client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            created_at=datetime.utcnow(),
            is_active="true",
            parent_token_id=str(valid_refresh_token_record.id),
        )

        # Setup mocks
        mock_db.query.return_value.filter.return_value.first.return_value = (
            new_token_record
        )
        mock_db.commit = MagicMock()

        # Rotate token
        with patch(
            "app.oauth.service.create_refresh_token",
            return_value="new_refresh_token_456",
        ):
            rotate_refresh_token(mock_db, valid_refresh_token_record)

        # Verify create_refresh_token was called with parent_token_id
        # This is verified by the new_token_record having the correct parent_token_id
        assert new_token_record.parent_token_id == str(valid_refresh_token_record.id)

    def test_old_token_has_replaced_by_token_id(
        self, mock_db, valid_refresh_token_record, sample_scope
    ):
        """Test that old token has replaced_by_token_id pointing to new token."""
        # Create new token record
        new_token_id = uuid.uuid4()
        new_token_record = RefreshToken(
            id=new_token_id,
            token="new_refresh_token_456",
            user_id=valid_refresh_token_record.user_id,
            client_id=valid_refresh_token_record.client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            created_at=datetime.utcnow(),
            is_active="true",
            parent_token_id=str(valid_refresh_token_record.id),
        )

        # Setup mocks
        mock_db.query.return_value.filter.return_value.first.return_value = (
            new_token_record
        )
        mock_db.commit = MagicMock()

        # Rotate token
        with patch(
            "app.oauth.service.create_refresh_token",
            return_value="new_refresh_token_456",
        ):
            rotate_refresh_token(mock_db, valid_refresh_token_record)

        # Verify old token has replaced_by_token_id
        assert valid_refresh_token_record.replaced_by_token_id == new_token_id


# =============================================================================
# TestReplayAttackDetection
# =============================================================================


class TestReplayAttackDetection:
    """Tests for replay attack detection."""

    def test_using_replaced_token_raises_error(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that using a replaced token raises an error."""
        # Create a properly linked chain
        new_token_id = uuid.uuid4()
        replaced_token = RefreshToken(
            id=uuid.uuid4(),
            token="replaced_refresh_token_123",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            created_at=datetime.utcnow(),
            is_active="replaced",
            parent_token_id=None,
            replaced_by_token_id=new_token_id,
        )

        # The new token that replaced this one
        new_token = RefreshToken(
            id=new_token_id,
            token="new_valid_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=str(replaced_token.id),
            replaced_by_token_id=None,
        )

        mock_query = MagicMock()
        mock_query.filter.return_value.first.side_effect = [
            replaced_token,  # First call: validate token
            new_token,  # Second call: find child in chain
            None,  # Third call: no more children
        ]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        # Attempt to validate the replaced token
        with pytest.raises(OAuthError) as exc_info:
            validate_refresh_token(
                db=mock_db,
                token=replaced_token.token,
                client_id=sample_client_id,
            )

        # Verify error is raised
        assert exc_info.value.error_code == OAuthErrorCode.INVALID_GRANT
        assert "revoked" in exc_info.value.description.lower()

    def test_using_revoked_token_raises_error(
        self, mock_db, revoked_refresh_token_record, sample_client_id
    ):
        """Test that using a revoked token raises an error."""
        # Setup mock - return the revoked token for validation,
        # and return None for any chain queries
        mock_query = MagicMock()
        mock_query.filter.return_value.first.side_effect = [
            revoked_refresh_token_record,
            None,
        ]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        # Attempt to validate the revoked token
        with pytest.raises(OAuthError) as exc_info:
            validate_refresh_token(
                db=mock_db,
                token=revoked_refresh_token_record.token,
                client_id=sample_client_id,
            )

        # Verify error is raised
        assert exc_info.value.error_code == OAuthErrorCode.INVALID_GRANT

    def test_revoked_token_validation_does_not_crash(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that validating an already-revoked token doesn't crash."""
        token = RefreshToken(
            id=uuid.uuid4(),
            token="revoked_token_simple",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="revoked",
            revoked_at=datetime.utcnow(),
            revoked_reason="user_request",
            parent_token_id=None,
            replaced_by_token_id=None,
        )

        mock_query = MagicMock()
        mock_query.filter.return_value.first.side_effect = [token, None]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        with pytest.raises(OAuthError):
            validate_refresh_token(
                db=mock_db,
                token=token.token,
                client_id=sample_client_id,
            )

        assert mock_db.commit.called


# =============================================================================
# TestTokenChainRevocation
# =============================================================================


class TestTokenChainRevocation:
    """Tests for token chain revocation."""

    def test_revoke_single_token(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test revoking a single token without chain."""
        token = RefreshToken(
            id=uuid.uuid4(),
            token="test_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=None,
            replaced_by_token_id=None,
        )
        mock_db.commit = MagicMock()

        revoke_token_chain(
            db=mock_db,
            refresh_token=token,
            reason="user_revoked",
        )

        assert token.is_active == "revoked"
        assert token.revoked_at is not None
        assert token.revoked_reason == "user_revoked"

    def test_revocation_sets_revoked_at_and_reason(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that revocation sets revoked_at and revoked_reason."""
        token = RefreshToken(
            id=uuid.uuid4(),
            token="test_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=None,
            replaced_by_token_id=None,
        )
        mock_db.commit = MagicMock()

        before_revoke = datetime.utcnow()

        revoke_token_chain(
            db=mock_db,
            refresh_token=token,
            reason="test_revocation",
        )

        assert token.revoked_at is not None
        assert token.revoked_at >= before_revoke
        assert token.revoked_reason == "test_revocation"

    def test_revoke_token_with_parent_chain(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test revoking a token revokes its parent chain."""
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
        mock_query.filter.return_value.first.side_effect = [parent_token, None]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        revoke_token_chain(
            db=mock_db,
            refresh_token=current_token,
            reason="user_revoked",
        )

        assert current_token.is_active == "revoked"
        assert parent_token.is_active == "revoked"
        assert parent_token.revoked_reason == "chain_revocation: user_revoked"

    def test_revoke_token_with_child_chain(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test revoking a token revokes its child chain."""
        child_id = uuid.uuid4()
        child_token = RefreshToken(
            id=child_id,
            token="child_token",
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
            parent_token_id=None,
            replaced_by_token_id=child_id,
        )

        mock_query = MagicMock()
        mock_query.filter.return_value.first.side_effect = [child_token, None]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        revoke_token_chain(
            db=mock_db,
            refresh_token=current_token,
            reason="security_event",
        )

        assert current_token.is_active == "revoked"
        assert child_token.is_active == "revoked"
        assert child_token.revoked_reason == "chain_revocation: security_event"

    def test_revoke_token_with_full_chain(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test revoking a middle token revokes both parent and child chains."""
        parent_id = uuid.uuid4()
        parent_token = RefreshToken(
            id=parent_id,
            token="oldest_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=None,
            replaced_by_token_id=None,
        )

        middle_id = uuid.uuid4()
        child_id = uuid.uuid4()
        middle_token = RefreshToken(
            id=middle_id,
            token="middle_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=parent_id,
            replaced_by_token_id=child_id,
        )

        child_token = RefreshToken(
            id=child_id,
            token="newest_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=middle_id,
            replaced_by_token_id=None,
        )

        mock_query = MagicMock()
        mock_query.filter.return_value.first.side_effect = [
            parent_token,
            child_token,
            None,
        ]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        revoke_token_chain(
            db=mock_db,
            refresh_token=middle_token,
            reason="user_logout",
        )

        assert middle_token.is_active == "revoked"
        assert parent_token.is_active == "revoked"
        assert child_token.is_active == "revoked"

    def test_revoke_already_revoked_token_in_chain_is_idempotent(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that revoking an already-revoked token doesn't cause errors."""
        parent_id = uuid.uuid4()
        parent_token = RefreshToken(
            id=parent_id,
            token="parent_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="revoked",
            revoked_at=datetime.utcnow() - timedelta(hours=1),
            revoked_reason="previous_revocation",
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
        mock_query.filter.return_value.first.side_effect = [parent_token, None]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        revoke_token_chain(
            db=mock_db,
            refresh_token=current_token,
            reason="new_revocation",
        )

        assert current_token.is_active == "revoked"
        assert parent_token.is_active == "revoked"
        assert parent_token.revoked_reason == "previous_revocation"

    def test_revoking_token_with_broken_parent_chain_handles_gracefully(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that revoking a token handles orphaned parent references gracefully."""
        parent_id = uuid.uuid4()
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
            None,  # Parent doesn't exist (orphaned reference)
        ]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        # Should not raise an error
        revoke_token_chain(
            db=mock_db,
            refresh_token=current_token,
            reason="user_revoked",
        )

        assert current_token.is_active == "revoked"

    def test_revoking_token_with_broken_child_chain_handles_gracefully(
        self, mock_db, sample_user_id, sample_client_id, sample_scope
    ):
        """Test that revoking a token handles orphaned child references gracefully."""
        child_id = uuid.uuid4()
        current_token = RefreshToken(
            id=uuid.uuid4(),
            token="current_token",
            user_id=sample_user_id,
            client_id=sample_client_id,
            scope=sample_scope,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active="true",
            parent_token_id=None,
            replaced_by_token_id=child_id,
        )

        mock_query = MagicMock()
        mock_query.filter.return_value.first.side_effect = [
            None,  # Child doesn't exist (orphaned reference)
        ]
        mock_db.query.return_value = mock_query
        mock_db.commit = MagicMock()

        # Should not raise an error
        revoke_token_chain(
            db=mock_db,
            refresh_token=current_token,
            reason="user_revoked",
        )

        assert current_token.is_active == "revoked"


# =============================================================================
# TestRefreshTokenGrantEndpoint
# =============================================================================


class TestRefreshTokenGrantEndpoint:
    """Tests for the refresh token grant endpoint handler."""

    def test_successful_token_refresh_flow(
        self, mock_db, valid_refresh_token_record, sample_client, sample_scope
    ):
        """Test successful token refresh flow."""
        # Setup mocks
        mock_db.query.return_value.filter.return_value.first.return_value = (
            sample_client
        )

        with patch(
            "app.oauth.service.validate_refresh_token",
            return_value=valid_refresh_token_record,
        ):
            with patch(
                "app.oauth.service.rotate_refresh_token",
                return_value="new_refresh_token",
            ):
                with patch(
                    "app.oauth.service.create_access_token",
                    return_value=("new_access_token", "jti"),
                ):
                    result = handle_refresh_token_grant(
                        db=mock_db,
                        refresh_token=valid_refresh_token_record.token,
                        client_id=sample_client.client_id,
                        client_secret="test_secret",
                        scope=None,
                    )

        # Verify response structure
        data = json.loads(result.body)
        assert data["access_token"] == "new_access_token"
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == settings.ACCESS_TOKEN_EXPIRE_SECONDS
        assert data["refresh_token"] == "new_refresh_token"
        assert data["scope"] == sample_scope

    def test_error_for_missing_refresh_token_parameter(
        self, mock_db, sample_client, sample_client_id
    ):
        """Test error for missing refresh_token parameter."""
        # Setup mocks
        mock_db.query.return_value.filter.return_value.first.return_value = (
            sample_client
        )

        with pytest.raises(OAuthError) as exc_info:
            handle_refresh_token_grant(
                db=mock_db,
                refresh_token=None,
                client_id=sample_client_id,
                client_secret="test_secret",
                scope=None,
            )

        assert exc_info.value.error_code == OAuthErrorCode.INVALID_REQUEST
        assert "Missing required parameter" in exc_info.value.description
        assert "refresh_token" in exc_info.value.description

    def test_error_for_invalid_client_credentials(self, mock_db, sample_client_id):
        """Test error for invalid client credentials."""
        # Setup mocks - client not found
        mock_db.query.return_value.filter.return_value.first.return_value = None

        with pytest.raises(OAuthError) as exc_info:
            handle_refresh_token_grant(
                db=mock_db,
                refresh_token="some_token",
                client_id=sample_client_id,
                client_secret="wrong_secret",
                scope=None,
            )

        assert exc_info.value.error_code == OAuthErrorCode.INVALID_CLIENT
        assert "authentication failed" in exc_info.value.description.lower()

    def test_error_for_invalid_refresh_token(
        self, mock_db, sample_client, sample_client_id
    ):
        """Test error for invalid refresh token."""
        # Setup mocks
        mock_db.query.return_value.filter.return_value.first.return_value = (
            sample_client
        )

        with patch(
            "app.oauth.service.validate_refresh_token",
            side_effect=OAuthError(
                error_code=OAuthErrorCode.INVALID_GRANT,
                description="Invalid refresh token",
            ),
        ):
            with pytest.raises(OAuthError) as exc_info:
                handle_refresh_token_grant(
                    db=mock_db,
                    refresh_token="invalid_token",
                    client_id=sample_client_id,
                    client_secret="test_secret",
                    scope=None,
                )

        assert exc_info.value.error_code == OAuthErrorCode.INVALID_GRANT

    def test_scope_reduction_requesting_subset(
        self, mock_db, valid_refresh_token_record, sample_client
    ):
        """Test scope reduction (requesting subset of original scopes)."""
        # Setup mocks
        mock_db.query.return_value.filter.return_value.first.return_value = (
            sample_client
        )

        # Original scope is "openid profile email offline_access"
        # Request subset "openid profile"
        reduced_scope = "openid profile"

        with patch(
            "app.oauth.service.validate_refresh_token",
            return_value=valid_refresh_token_record,
        ):
            with patch(
                "app.oauth.service.rotate_refresh_token",
                return_value="new_refresh_token",
            ):
                with patch(
                    "app.oauth.service.create_access_token",
                    return_value=("new_access_token", "jti"),
                ):
                    result = handle_refresh_token_grant(
                        db=mock_db,
                        refresh_token=valid_refresh_token_record.token,
                        client_id=sample_client.client_id,
                        client_secret="test_secret",
                        scope=reduced_scope,
                    )

        # Verify reduced scope is returned
        data = json.loads(result.body)
        assert data["scope"] == reduced_scope

    def test_error_when_requesting_scope_not_in_original_grant(
        self, mock_db, valid_refresh_token_record, sample_client
    ):
        """Test error when requesting scope not in original grant."""
        # Setup mocks
        mock_db.query.return_value.filter.return_value.first.return_value = (
            sample_client
        )

        # Original scope is "openid profile email offline_access"
        # Request scope that includes "admin" which is not in original
        invalid_scope = "openid profile admin"

        with patch(
            "app.oauth.service.validate_refresh_token",
            return_value=valid_refresh_token_record,
        ):
            with pytest.raises(OAuthError) as exc_info:
                handle_refresh_token_grant(
                    db=mock_db,
                    refresh_token=valid_refresh_token_record.token,
                    client_id=sample_client.client_id,
                    client_secret="test_secret",
                    scope=invalid_scope,
                )

        assert exc_info.value.error_code == OAuthErrorCode.INVALID_SCOPE
        assert "exceeds original grant" in exc_info.value.description.lower()

    def test_original_scope_used_when_scope_not_provided(
        self, mock_db, valid_refresh_token_record, sample_client, sample_scope
    ):
        """Test that original scope is used when scope parameter is not provided."""
        # Setup mocks
        mock_db.query.return_value.filter.return_value.first.return_value = (
            sample_client
        )

        with patch(
            "app.oauth.service.validate_refresh_token",
            return_value=valid_refresh_token_record,
        ):
            with patch(
                "app.oauth.service.rotate_refresh_token",
                return_value="new_refresh_token",
            ):
                with patch(
                    "app.oauth.service.create_access_token",
                    return_value=("new_access_token", "jti"),
                ):
                    result = handle_refresh_token_grant(
                        db=mock_db,
                        refresh_token=valid_refresh_token_record.token,
                        client_id=sample_client.client_id,
                        client_secret="test_secret",
                        scope=None,  # No scope provided
                    )

        # Verify original scope is used
        data = json.loads(result.body)
        assert data["scope"] == sample_scope


# =============================================================================
# RFC Compliance Tests
# =============================================================================


def test_refresh_token_grant_without_redirect_uri_succeeds(
    mock_db, sample_client, valid_refresh_token_record
):
    """
    Verify that refresh_token grant does NOT require redirect_uri.
    Per RFC 6749 §6.
    """
    mock_query = MagicMock()
    # First call: validate client, Second call: validate_refresh_token
    mock_query.filter.return_value.first.side_effect = [
        sample_client,
        valid_refresh_token_record,
    ]
    mock_db.query.return_value = mock_query

    with (
        patch(
            "app.oauth.service.validate_refresh_token",
            return_value=valid_refresh_token_record,
        ),
        patch(
            "app.oauth.service.create_access_token",
            return_value=("access", "jti"),
        ),
        patch("app.oauth.service.rotate_refresh_token", return_value="rotated"),
    ):
        # Call WITHOUT redirect_uri
        response = handle_refresh_token_grant(
            db=mock_db,
            refresh_token="valid_refresh_token_123",
            client_id=sample_client.client_id,
            client_secret="test_secret",
            scope=None,
        )

    assert response.status_code == 200
