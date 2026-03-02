"""
Tests for OpenID Connect Discovery Document per OpenID Connect Discovery §3.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app


class TestDiscoveryEndpoint:
    """Integration tests for the /.well-known/openid-configuration endpoint."""

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

    def test_discovery_returns_200(self):
        """Discovery endpoint returns 200 OK."""
        response = self.client.get("/.well-known/openid-configuration")
        assert response.status_code == 200

    def test_discovery_returns_json(self):
        """Discovery endpoint returns JSON content."""
        response = self.client.get("/.well-known/openid-configuration")
        assert response.headers["content-type"] == "application/json"

    def test_discovery_contains_issuer(self):
        """Discovery document contains issuer field."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "issuer" in data
        assert data["issuer"] == "http://localhost:8000"

    def test_discovery_contains_authorization_endpoint(self):
        """Discovery document contains authorization_endpoint."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "authorization_endpoint" in data
        assert data["authorization_endpoint"] == "http://localhost:8000/oauth/authorize"

    def test_discovery_contains_token_endpoint(self):
        """Discovery document contains token_endpoint."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "token_endpoint" in data
        assert data["token_endpoint"] == "http://localhost:8000/oauth/token"

    def test_discovery_contains_userinfo_endpoint(self):
        """Discovery document contains userinfo_endpoint."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "userinfo_endpoint" in data
        assert data["userinfo_endpoint"] == "http://localhost:8000/oauth/userinfo"

    def test_discovery_contains_jwks_uri(self):
        """Discovery document contains jwks_uri."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "jwks_uri" in data
        assert data["jwks_uri"] == "http://localhost:8000/.well-known/jwks.json"

    def test_discovery_contains_revocation_endpoint(self):
        """Discovery document contains revocation_endpoint."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "revocation_endpoint" in data
        assert data["revocation_endpoint"] == "http://localhost:8000/oauth/revoke"

    def test_discovery_contains_grant_types_supported(self):
        """Discovery document contains grant_types_supported."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "grant_types_supported" in data
        assert "authorization_code" in data["grant_types_supported"]
        assert "refresh_token" in data["grant_types_supported"]

    def test_discovery_contains_response_types_supported(self):
        """Discovery document contains response_types_supported."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "response_types_supported" in data
        assert "code" in data["response_types_supported"]

    def test_discovery_contains_response_modes_supported(self):
        """Discovery document contains response_modes_supported."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "response_modes_supported" in data
        assert "query" in data["response_modes_supported"]

    def test_discovery_contains_token_endpoint_auth_methods(self):
        """Discovery document contains token_endpoint_auth_methods_supported."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "token_endpoint_auth_methods_supported" in data
        assert "client_secret_basic" in data["token_endpoint_auth_methods_supported"]
        assert "client_secret_post" in data["token_endpoint_auth_methods_supported"]

    def test_discovery_contains_subject_types_supported(self):
        """Discovery document contains subject_types_supported."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "subject_types_supported" in data
        assert "public" in data["subject_types_supported"]

    def test_discovery_contains_id_token_signing_alg(self):
        """Discovery document contains id_token_signing_alg_values_supported."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "id_token_signing_alg_values_supported" in data
        assert "RS256" in data["id_token_signing_alg_values_supported"]

    def test_discovery_contains_scopes_supported(self):
        """Discovery document contains scopes_supported."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "scopes_supported" in data
        assert "openid" in data["scopes_supported"]
        assert "profile" in data["scopes_supported"]
        assert "email" in data["scopes_supported"]
        assert "offline_access" in data["scopes_supported"]

    def test_discovery_contains_claims_supported(self):
        """Discovery document contains claims_supported."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "claims_supported" in data
        required_claims = ["sub", "iss", "aud", "exp", "iat"]
        for claim in required_claims:
            assert claim in data["claims_supported"]

    def test_discovery_contains_claim_types_supported(self):
        """Discovery document contains claim_types_supported."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "claim_types_supported" in data
        assert "normal" in data["claim_types_supported"]

    def test_discovery_contains_code_challenge_methods_supported(self):
        """Discovery document contains code_challenge_methods_supported."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "code_challenge_methods_supported" in data
        assert "S256" in data["code_challenge_methods_supported"]

    def test_discovery_contains_ui_locales_supported(self):
        """Discovery document contains ui_locales_supported."""
        response = self.client.get("/.well-known/openid-configuration")
        data = response.json()
        assert "ui_locales_supported" in data
        assert "en" in data["ui_locales_supported"]

    def test_discovery_matches_jwks_uri_consistency(self):
        """JWKS URI in discovery matches actual JWKS endpoint."""
        discovery_response = self.client.get("/.well-known/openid-configuration")
        discovery_data = discovery_response.json()

        jwks_response = self.client.get("/.well-known/jwks.json")

        assert (
            discovery_data["jwks_uri"] == "http://localhost:8000/.well-known/jwks.json"
        )
        assert jwks_response.status_code == 200
