"""
Tests for DPoP (Demonstrating Proof of Possession) per RFC 9449.
"""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.middleware.rate_limit import clear_rate_limit_store
from app.models.user import User
from app.oauth.dpop import compute_at_hash, compute_jwk_thumbprint
from app.oauth.models import AuthorizationCode, OAuthClient
from app.oauth.schemas import TokenRequest
from app.oauth.services.token import TokenService
from app.services.auth import hash_password


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter between tests."""
    clear_rate_limit_store()
    yield
    clear_rate_limit_store()


@pytest.fixture
def mock_db():
    """Create a mock database session."""
    db = MagicMock(spec=Session)
    return db


@pytest.fixture
def db_session():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(db_session):
    """Create a TestClient with a overridden get_db dependency."""

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    del app.dependency_overrides[get_db]


class TestDPoPFunctions:
    """Tests for DPoP utility functions."""

    def test_compute_at_hash(self):
        """Test access token hash computation."""
        access_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        at_hash = compute_at_hash(access_token)
        assert isinstance(at_hash, str)
        assert len(at_hash) > 0

    def test_compute_at_hash_deterministic(self):
        """Test that compute_at_hash is deterministic."""
        token = "test_token_value"
        hash1 = compute_at_hash(token)
        hash2 = compute_at_hash(token)
        assert hash1 == hash2

    def test_compute_jwk_thumbprint_ec(self):
        """Test JWK thumbprint computation for EC key."""
        jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
        thumbprint = compute_jwk_thumbprint(jwk)
        assert isinstance(thumbprint, str)
        assert len(thumbprint) > 0

    def test_compute_jwk_thumbprint_rsa(self):
        """Test JWK thumbprint computation for RSA key."""
        jwk = {"kty": "RSA", "n": "abc", "e": "AQAB"}
        thumbprint = compute_jwk_thumbprint(jwk)
        assert isinstance(thumbprint, str)

    def test_compute_jwk_thumbprint_only_required_fields(self):
        """Test JWK thumbprint only includes required fields."""
        jwk = {"kty": "EC", "crv": "P-256"}
        thumbprint = compute_jwk_thumbprint(jwk)
        assert isinstance(thumbprint, str)


class TestDPoPTokenEndpoint:
    """Tests for DPoP at the token endpoint."""

    def test_token_exchange_without_dpop_returns_bearer(self, client, db_session):
        """Test token exchange without DPoP returns bearer token."""
        user = User(
            email="testuser@example.com",
            password_hash=hash_password("password123"),
        )
        db_session.add(user)
        db_session.commit()

        oauth_client = OAuthClient(
            client_id="test-client",
            client_secret=hash_password("client-secret"),
            redirect_uri="http://localhost:3000/callback",
            name="Test Client",
            scopes="openid",
            client_type="confidential",
        )
        db_session.add(oauth_client)
        db_session.commit()

        code = AuthorizationCode(
            code="test-code",
            user_id=user.id,
            client_id=oauth_client.client_id,
            redirect_uri=oauth_client.redirect_uri,
            scope="openid",
            expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=10),
        )
        db_session.add(code)
        db_session.commit()

        import re

        get_response = client.get("/auth/login")
        match = re.search(r'name="csrf_token" value="([^"]+)"', get_response.text)
        csrf_token = match.group(1)

        client.post(
            "/auth/login",
            data={
                "email": "testuser@example.com",
                "password": "password123",
                "next": "/",
                "csrf_token": csrf_token,
            },
        )

        response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "test-code",
                "redirect_uri": "http://localhost:3000/callback",
                "client_id": "test-client",
                "client_secret": "client-secret",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["token_type"] == "bearer"

    def test_token_exchange_with_invalid_dpop_fails(self, client, db_session):
        """Test token exchange with invalid DPoP proof fails."""
        user = User(
            email="testuser@example.com",
            password_hash=hash_password("password123"),
        )
        db_session.add(user)
        db_session.commit()

        oauth_client = OAuthClient(
            client_id="test-client",
            client_secret=hash_password("client-secret"),
            redirect_uri="http://localhost:3000/callback",
            name="Test Client",
            scopes="openid",
            client_type="confidential",
        )
        db_session.add(oauth_client)
        db_session.commit()

        code = AuthorizationCode(
            code="test-code",
            user_id=user.id,
            client_id=oauth_client.client_id,
            redirect_uri=oauth_client.redirect_uri,
            scope="openid",
            expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=10),
        )
        db_session.add(code)
        db_session.commit()

        response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "test-code",
                "redirect_uri": "http://localhost:3000/callback",
                "client_id": "test-client",
                "client_secret": "client-secret",
            },
            headers={"DPoP": "invalid-proof-jwt"},
        )

        assert response.status_code == 400


class TestDPoPRefreshToken:
    """Tests for DPoP with refresh token flow."""

    def test_refresh_token_without_dpop_returns_bearer(self, mock_db):
        """Test refresh token flow returns bearer when no DPoP provided."""
        from app.oauth.models import RefreshToken

        client = OAuthClient(
            client_id="test-client",
            client_secret=hash_password("test-secret"),
            client_type="confidential",
        )

        refresh_token_record = RefreshToken(
            token="old_refresh_token",
            client_id="test-client",
            user_id=str(uuid.uuid4()),
            expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(days=7),
            is_active="true",
            scope="openid",
        )

        mock_query = MagicMock()
        mock_query.filter.return_value.first.return_value = refresh_token_record
        mock_db.query.return_value = mock_query

        with (
            patch(
                "app.oauth.services.token.validate_refresh_token",
                return_value=refresh_token_record,
            ),
            patch(
                "app.oauth.services.token.create_access_token",
                return_value=("access_token", "jti"),
            ),
            patch(
                "app.oauth.services.token.rotate_refresh_token",
                return_value="new_refresh_token",
            ),
        ):
            response = TokenService(mock_db).handle_refresh_token_grant(
                request_data=TokenRequest(
                    grant_type="refresh_token", refresh_token="old_refresh_token"
                ),
                client=client,
            )

        assert response.status_code == 200
        import json

        data = json.loads(response.body)
        assert data["token_type"] == "bearer"


class TestDPoPDiscovery:
    """Tests for DPoP in discovery document."""

    def test_discovery_contains_dpop_signing_alg_values(self, client):
        """Test discovery document includes DPoP algorithms."""
        response = client.get("/.well-known/openid-configuration")
        assert response.status_code == 200
        data = response.json()
        assert "dpop_signing_alg_values_supported" in data
        assert "ES256" in data["dpop_signing_alg_values_supported"]

    def test_discovery_contains_cnf_claim(self, client):
        """Test discovery document includes cnf in claims supported."""
        response = client.get("/.well-known/openid-configuration")
        assert response.status_code == 200
        data = response.json()
        assert "cnf" in data.get("claims_supported", [])


class TestDPoPIntegration:
    """Integration tests for DPoP flow."""

    def test_bearer_token_can_be_used_without_dpop_header(self, client, db_session):
        """Test that bearer tokens work without DPoP headers."""
        user = User(
            email="testuser@example.com",
            password_hash=hash_password("password123"),
        )
        db_session.add(user)
        db_session.commit()

        oauth_client = OAuthClient(
            client_id="test-client",
            client_secret=hash_password("client-secret"),
            redirect_uri="http://localhost:3000/callback",
            name="Test Client",
            scopes="openid profile",
            client_type="confidential",
        )
        db_session.add(oauth_client)
        db_session.commit()

        code = AuthorizationCode(
            code="test-code",
            user_id=user.id,
            client_id=oauth_client.client_id,
            redirect_uri=oauth_client.redirect_uri,
            scope="openid profile",
            expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=10),
        )
        db_session.add(code)
        db_session.commit()

        import re

        get_response = client.get("/auth/login")
        match = re.search(r'name="csrf_token" value="([^"]+)"', get_response.text)

        client.post(
            "/auth/login",
            data={
                "email": "testuser@example.com",
                "password": "password123",
                "next": "/",
                "csrf_token": match.group(1),
            },
        )

        # Get token
        response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": "test-code",
                "redirect_uri": "http://localhost:3000/callback",
                "client_id": "test-client",
                "client_secret": "client-secret",
            },
        )

        assert response.status_code == 200
        data = response.json()
        access_token = data["access_token"]

        # Use token without DPoP (bearer)
        response = client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert response.status_code == 200
