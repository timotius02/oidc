"""
Tests for OAuth 2.0 Authorization Code Grant flow per RFC 6749.
"""

import base64
import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
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


# =============================================================================
# Integration Tests
# =============================================================================


class TestAuthCodeGrantIntegration:
    """Integration tests for the /oauth/token endpoint (Auth Code Grant)."""

    @pytest.fixture(autouse=True)
    def setup_test_client(self):
        SQLALCHEMY_DATABASE_URL = "sqlite://"
        self.engine = create_engine(
            SQLALCHEMY_DATABASE_URL,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.TestingSessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )
        Base.metadata.create_all(bind=self.engine)

        def override_get_db():
            try:
                db = self.TestingSessionLocal()
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)
        yield
        app.dependency_overrides.clear()

    @pytest.fixture
    def db_session(self):
        db = self.TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    def test_token_response_scope_matches_granted(self, db_session):
        """RFC 6749 §5.1: The 'scope' parameter MUST match the granted scope."""
        client_id = "test_client"
        secret = "test_secret"
        db_client = OAuthClient(
            client_id=client_id,
            client_secret=hash_password(secret),
            redirect_uri="http://localhost",
            client_type="confidential",
            name="Test Client",
            scopes="openid profile email",
        )
        db_session.add(db_client)

        granted_scope = "openid profile"
        code = "test_code"
        auth_code = AuthorizationCode(
            code=code,
            user_id=uuid.uuid4(),
            client_id=client_id,
            redirect_uri="http://localhost",
            scope=granted_scope,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        db_session.add(auth_code)
        db_session.commit()

        # Request with a different subset of scopes -
        # the response MUST reflect granted_scope
        response = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "client_secret": secret,
                "redirect_uri": "http://localhost",
                "scope": "openid",
            },
        )

        assert response.status_code == 200
        assert response.json()["scope"] == granted_scope

    def test_public_client_exchange_without_secret(self, db_session):
        """RFC 6749 §2.3: Public clients are NOT required to provide a secret."""
        client_id = "public_client"
        db_client = OAuthClient(
            client_id=client_id,
            client_secret="",
            redirect_uri="http://localhost",
            client_type="public",
            name="Public Client",
            scopes="openid profile",
        )
        db_session.add(db_client)

        code = "public_code"
        auth_code = AuthorizationCode(
            code=code,
            user_id=uuid.uuid4(),
            client_id=client_id,
            redirect_uri="http://localhost",
            scope="openid",
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        db_session.add(auth_code)
        db_session.commit()

        response = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "redirect_uri": "http://localhost",
            },
        )

        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_token_basic_auth_success(self, db_session):
        """RFC 6749 §2.3.1: Verify Basic Authentication support."""
        client_id = "basic_client"
        secret = "basic_secret"
        db_client = OAuthClient(
            client_id=client_id,
            client_secret=hash_password(secret),
            redirect_uri="http://localhost",
            client_type="confidential",
            name="Basic Client",
            scopes="openid",
        )
        db_session.add(db_client)

        code = "basic_code"
        auth_code = AuthorizationCode(
            code=code,
            user_id=uuid.uuid4(),
            client_id=client_id,
            redirect_uri="http://localhost",
            scope="openid",
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        db_session.add(auth_code)
        db_session.commit()

        auth_header = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
        response = self.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost",
            },
            headers={"Authorization": f"Basic {auth_header}"},
        )

        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_token_basic_auth_failure_returns_www_authenticate(self, db_session):
        """RFC 6749 §5.2: MUST return WWW-Authenticate on client auth failure."""
        client_id = "fail_client"
        db_client = OAuthClient(
            client_id=client_id,
            client_secret=hash_password("correct_secret"),
            redirect_uri="http://localhost",
            client_type="confidential",
            name="Fail Client",
            scopes="openid",
        )
        db_session.add(db_client)
        db_session.commit()

        # Basic auth with wrong secret
        auth_str = f"{client_id}:wrong_secret"
        auth_header = base64.b64encode(auth_str.encode()).decode()

        response = self.client.post(
            "/oauth/token",
            data={"grant_type": "authorization_code", "code": "any"},
            headers={"Authorization": f"Basic {auth_header}"},
        )

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"
        assert "WWW-Authenticate" in response.headers
        assert 'Basic realm="oauth"' in response.headers["WWW-Authenticate"]
