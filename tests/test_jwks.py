"""
Tests for OIDC JWKS Endpoint per OpenID Connect Discovery §3.
"""

import base64
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.oauth.jwt import (
    CURRENT_KEY,
    KEYS,
    create_access_token,
    create_id_token,
    verify_token,
)


class TestJWKSEndpoint:
    """Integration tests for the /.well-known/jwks.json endpoint."""

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

    def test_jwks_returns_200(self):
        """JWKS endpoint returns 200 OK."""
        response = self.client.get("/.well-known/jwks.json")
        assert response.status_code == 200

    def test_jwks_returns_json(self):
        """JWKS endpoint returns JSON content."""
        response = self.client.get("/.well-known/jwks.json")
        assert response.headers["content-type"] == "application/json"

    def test_jwks_contains_keys_array(self):
        """JWKS response contains 'keys' array."""
        response = self.client.get("/.well-known/jwks.json")
        data = response.json()
        assert "keys" in data
        assert isinstance(data["keys"], list)
        assert len(data["keys"]) >= 1

    def test_jwks_key_has_required_fields(self):
        """Each key in JWKS has required JWK fields."""
        response = self.client.get("/.well-known/jwks.json")
        data = response.json()
        required_fields = ["kty", "kid", "use", "alg", "n", "e"]

        for key in data["keys"]:
            for field in required_fields:
                assert field in key, f"Missing required field: {field}"

    def test_jwks_key_kty_is_rsa(self):
        """JWK key type is RSA."""
        response = self.client.get("/.well-known/jwks.json")
        data = response.json()
        assert data["keys"][0]["kty"] == "RSA"

    def test_jwks_key_use_is_sig(self):
        """JWK key use is 'sig' (signature)."""
        response = self.client.get("/.well-known/jwks.json")
        data = response.json()
        assert data["keys"][0]["use"] == "sig"

    def test_jwks_key_alg_is_rs256(self):
        """JWK algorithm is RS256."""
        response = self.client.get("/.well-known/jwks.json")
        data = response.json()
        assert data["keys"][0]["alg"] == "RS256"

    def test_jwks_key_n_is_valid_base64(self):
        """JWK modulus (n) is valid base64url."""
        response = self.client.get("/.well-known/jwks.json")
        data = response.json()
        n = data["keys"][0]["n"]
        # Should not raise
        base64.urlsafe_b64decode(n + "==")

    def test_jwks_key_e_is_valid_base64(self):
        """JWK exponent (e) is valid base64url."""
        response = self.client.get("/.well-known/jwks.json")
        data = response.json()
        e = data["keys"][0]["e"]
        # Should not raise
        base64.urlsafe_b64decode(e + "==")

    def test_jwks_current_key_has_kid(self):
        """Current key has a key ID."""
        response = self.client.get("/.well-known/jwks.json")
        data = response.json()
        kids = [key["kid"] for key in data["keys"]]
        assert "current-key-1" in kids


class TestTokenHeaders:
    """Tests for JWT token headers including kid."""

    def test_access_token_has_kid_header(self):
        """Access token includes kid in header."""
        token, _ = create_access_token("user123", "client123", "openid")
        parts = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert "kid" in header
        assert header["kid"] == "current-key-1"

    def test_access_token_has_alg_header(self):
        """Access token includes alg in header."""
        token, _ = create_access_token("user123", "client123", "openid")
        parts = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["alg"] == "RS256"

    def test_access_token_has_typ_header(self):
        """Access token includes typ header."""
        token, _ = create_access_token("user123", "client123", "openid")
        parts = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["typ"] == "JWT"

    def test_id_token_has_kid_header(self):
        """ID token includes kid in header."""
        token = create_id_token("user123", "client123")
        parts = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert "kid" in header
        assert header["kid"] == "current-key-1"

    def test_id_token_has_alg_header(self):
        """ID token includes alg in header."""
        token = create_id_token("user123", "client123")
        parts = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["alg"] == "RS256"


class TestTokenVerification:
    """Tests for token verification with JWKS keys."""

    def test_verify_token_succeeds_with_current_key(self):
        """Token verification succeeds with current signing key."""
        token, _ = create_access_token("user123", "client123", "openid")
        payload = verify_token(token, "client123")
        assert payload["sub"] == "user123"

    def test_verify_token_extracts_correct_scope(self):
        """Token verification returns correct scope."""
        token, _ = create_access_token("user123", "client123", "openid profile email")
        payload = verify_token(token, "client123")
        assert payload["scope"] == "openid profile email"

    def test_verify_token_fails_with_wrong_audience(self):
        """Token verification fails with wrong audience."""
        token, _ = create_access_token("user123", "client123", "openid")
        with pytest.raises(Exception):
            verify_token(token, "wrong_client")


class TestJWKConversion:
    """Tests for RSAKey.to_jwk() method."""

    def test_to_jwk_returns_dict(self):
        """to_jwk() returns a dictionary."""
        jwk = CURRENT_KEY.to_jwk()
        assert isinstance(jwk, dict)

    def test_to_jwk_has_required_fields(self):
        """to_jwk() returns JWK with all required fields."""
        jwk = CURRENT_KEY.to_jwk()
        required = ["kty", "kid", "use", "alg", "n", "e"]
        for field in required:
            assert field in jwk

    def test_to_jwk_kid_matches(self):
        """to_jwk() returns correct kid."""
        jwk = CURRENT_KEY.to_jwk()
        assert jwk["kid"] == CURRENT_KEY.kid

    def test_multiple_keys_in_jwks(self):
        """When multiple keys exist, JWKS contains all of them."""
        if len(KEYS) > 1:
            response = TestClient(app).get("/.well-known/jwks.json")
            data = response.json()
            assert len(data["keys"]) == 2
            kids = [key["kid"] for key in data["keys"]]
            assert "current-key-1" in kids
            assert "next-key-1" in kids
