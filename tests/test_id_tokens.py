"""
Tests for OIDC ID Token functionality per OpenID Connect Core §2.
"""

import hashlib
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.oauth.jwt import compute_at_hash, create_id_token
from app.oauth.models import AuthorizationCode, OAuthClient
from app.services.auth import hash_password


class TestAtHash:
    """Tests for at_hash computation per OIDC Core §3.2.2.9."""

    def test_at_hash_correct_length(self):
        """at_hash should be 128 bits (16 bytes) base64url encoded."""
        access_token = "test_access_token_value"
        at_hash = compute_at_hash(access_token)

        # Base64url decode and check length
        import base64

        decoded = base64.urlsafe_b64decode(at_hash + "==")
        assert len(decoded) == 16  # 128 bits = 16 bytes

    def test_at_hash_deterministic(self):
        """Same access token should produce same at_hash."""
        access_token = "deterministic_token"
        at_hash1 = compute_at_hash(access_token)
        at_hash2 = compute_at_hash(access_token)
        assert at_hash1 == at_hash2

    def test_at_hash_different_tokens_different_hash(self):
        """Different access tokens should produce different at_hashes."""
        at_hash1 = compute_at_hash("token1")
        at_hash2 = compute_at_hash("token2")
        assert at_hash1 != at_hash2

    def test_at_hash_matches_oidc_spec(self):
        """
        Verify at_hash computation matches OIDC Core §3.2.2.9:
        SHA256 hash, left-truncate to 128 bits, base64url encode.
        """
        access_token = "test_token"
        expected_hash = hashlib.sha256(access_token.encode()).digest()[:16]
        import base64

        expected_at_hash = base64.urlsafe_b64encode(expected_hash).rstrip(b"=").decode()

        assert compute_at_hash(access_token) == expected_at_hash


class TestCreateIdToken:
    """Tests for ID token creation."""

    @pytest.fixture
    def mock_settings(self):
        with patch("app.oauth.jwt.settings") as mock:
            mock.JWT_ISSUER = "http://localhost:8000"
            mock.ID_TOKEN_EXPIRE_SECONDS = 3600
            yield mock

    def test_id_token_contains_required_claims(self, mock_settings):
        """ID token must contain all required claims per OIDC Core §2."""
        with patch("app.oauth.jwt.PRIVATE_KEY", "test_key"):
            with patch("app.oauth.jwt.jwt") as mock_jwt:
                mock_jwt.encode.return_value = "mock_token"

                token = create_id_token(
                    subject="user123",
                    audience="client123",
                )

                # Check that jwt.encode was called with required claims
                call_args = mock_jwt.encode.call_args[0][0]
                assert "iss" in call_args
                assert call_args["iss"] == "http://localhost:8000"
                assert "sub" in call_args
                assert call_args["sub"] == "user123"
                assert "aud" in call_args
                assert call_args["aud"] == "client123"
                assert "iat" in call_args
                assert "exp" in call_args
                # Check expiry is approximately 1 hour from iat
                expiry_delta = call_args["exp"] - call_args["iat"]
                assert expiry_delta.total_seconds() == pytest.approx(3600, abs=1)

    def test_id_token_with_nonce(self, mock_settings):
        """ID token should include nonce when provided."""
        with patch("app.oauth.jwt.PRIVATE_KEY", "test_key"):
            with patch("app.oauth.jwt.jwt") as mock_jwt:
                mock_jwt.encode.return_value = "mock_token"

                token = create_id_token(
                    subject="user123",
                    audience="client123",
                    nonce="nonce_value",
                )

                call_args = mock_jwt.encode.call_args[0][0]
                assert "nonce" in call_args
                assert call_args["nonce"] == "nonce_value"

    def test_id_token_without_nonce(self, mock_settings):
        """ID token should NOT include nonce when not provided."""
        with patch("app.oauth.jwt.PRIVATE_KEY", "test_key"):
            with patch("app.oauth.jwt.jwt") as mock_jwt:
                mock_jwt.encode.return_value = "mock_token"

                token = create_id_token(
                    subject="user123",
                    audience="client123",
                )

                call_args = mock_jwt.encode.call_args[0][0]
                assert "nonce" not in call_args

    def test_id_token_with_at_hash(self, mock_settings):
        """ID token should include at_hash when access_token provided."""
        with patch("app.oauth.jwt.PRIVATE_KEY", "test_key"):
            with patch("app.oauth.jwt.jwt") as mock_jwt:
                mock_jwt.encode.return_value = "mock_token"

                token = create_id_token(
                    subject="user123",
                    audience="client123",
                    access_token="test_access_token",
                )

                call_args = mock_jwt.encode.call_args[0][0]
                assert "at_hash" in call_args
                assert call_args["at_hash"] == compute_at_hash("test_access_token")


class TestIdTokenIntegration:
    """Integration tests for ID token in token endpoint."""

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

    def test_token_exchange_with_openid_scope_returns_id_token(self, db_session):
        """When scope=openid, token response should include id_token."""
        client_id = "oidc_client"
        secret = "test_secret"
        db_client = OAuthClient(
            client_id=client_id,
            client_secret=hash_password(secret),
            redirect_uri="http://localhost",
            client_type="confidential",
            name="OIDC Client",
            scopes="openid profile email",
        )
        db_session.add(db_client)

        user_id = uuid.uuid4()
        code = "oidc_code"
        auth_code = AuthorizationCode(
            code=code,
            user_id=user_id,
            client_id=client_id,
            redirect_uri="http://localhost",
            scope="openid profile",
            nonce="test_nonce",
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
                "client_secret": secret,
                "redirect_uri": "http://localhost",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "id_token" in data
        assert "access_token" in data

        # Decode and verify id_token claims
        import base64
        import json

        id_token = data["id_token"]
        parts = id_token.split(".")
        # Add padding if needed
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        assert claims["sub"] == str(user_id)
        assert claims["aud"] == client_id
        assert claims["nonce"] == "test_nonce"
        assert "at_hash" in claims

    def test_token_exchange_without_openid_scope_no_id_token(self, db_session):
        """When scope does NOT include openid, no id_token should be returned."""
        client_id = "resource_client"
        secret = "test_secret"
        db_client = OAuthClient(
            client_id=client_id,
            client_secret=hash_password(secret),
            redirect_uri="http://localhost",
            client_type="confidential",
            name="Resource Client",
            scopes="profile",  # No openid
        )
        db_session.add(db_client)

        user_id = uuid.uuid4()
        code = "resource_code"
        auth_code = AuthorizationCode(
            code=code,
            user_id=user_id,
            client_id=client_id,
            redirect_uri="http://localhost",
            scope="profile",
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
                "client_secret": secret,
                "redirect_uri": "http://localhost",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "id_token" not in data
        assert "access_token" in data

    def test_id_token_expiry_is_1_hour(self, db_session):
        """ID token should expire in 1 hour (configurable in config.py)."""
        client_id = "expiry_client"
        secret = "test_secret"
        db_client = OAuthClient(
            client_id=client_id,
            client_secret=hash_password(secret),
            redirect_uri="http://localhost",
            client_type="confidential",
            name="Expiry Client",
            scopes="openid",
        )
        db_session.add(db_client)

        user_id = uuid.uuid4()
        code = "expiry_code"
        auth_code = AuthorizationCode(
            code=code,
            user_id=user_id,
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
                "client_secret": secret,
                "redirect_uri": "http://localhost",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "id_token" in data

        import base64
        import json

        id_token = data["id_token"]
        parts = id_token.split(".")
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))

        # exp - iat should be 3600 (1 hour)
        assert claims["exp"] - claims["iat"] == 3600
