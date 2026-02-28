"""
Tests for OIDC UserInfo Endpoint per OpenID Connect Core §5.3.
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models.user import User
from app.oauth.jwt import create_access_token
from app.services.auth import hash_password


class TestUserInfoEndpoint:
    """Integration tests for the /oauth/userinfo endpoint."""

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

    @pytest.fixture
    def test_user(self, db_session):
        """Create a test user with profile fields."""
        user = User(
            id=uuid.uuid4(),
            email="test@example.com",
            password_hash=hash_password("password"),
            name="Test User",
            given_name="Test",
            family_name="User",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user

    def test_userinfo_requires_bearer_token(self, db_session):
        """UserInfo endpoint requires Bearer token authentication."""
        response = self.client.get("/oauth/userinfo")
        assert response.status_code == 401

    def test_userinfo_requires_valid_token(self, db_session, test_user):
        """UserInfo endpoint rejects invalid tokens."""
        response = self.client.get(
            "/oauth/userinfo",
            headers={"Authorization": "Bearer invalid_token"},
        )
        assert response.status_code == 401

    def test_userinfo_returns_sub_claim(self, db_session, test_user):
        """UserInfo endpoint always returns sub claim."""
        access_token, _ = create_access_token(
            subject=str(test_user.id),
            audience="test_client",
            scope="openid",
        )

        response = self.client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["sub"] == str(test_user.id)

    def test_userinfo_with_email_scope(self, db_session, test_user):
        """UserInfo returns email when email scope is granted."""
        access_token, _ = create_access_token(
            subject=str(test_user.id),
            audience="test_client",
            scope="openid email",
        )

        response = self.client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["email"] == test_user.email
        assert data["sub"] == str(test_user.id)

    def test_userinfo_with_profile_scope(self, db_session, test_user):
        """UserInfo returns profile claims when profile scope is granted."""
        access_token, _ = create_access_token(
            subject=str(test_user.id),
            audience="test_client",
            scope="openid profile",
        )

        response = self.client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["sub"] == str(test_user.id)
        assert data["name"] == test_user.name
        assert data["given_name"] == test_user.given_name
        assert data["family_name"] == test_user.family_name

    def test_userinfo_with_multiple_scopes(self, db_session, test_user):
        """UserInfo returns claims for multiple scopes."""
        access_token, _ = create_access_token(
            subject=str(test_user.id),
            audience="test_client",
            scope="openid profile email",
        )

        response = self.client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["sub"] == str(test_user.id)
        assert data["name"] == test_user.name
        assert data["email"] == test_user.email

    def test_userinfo_without_profile_scope_no_profile_claims(
        self, db_session, test_user
    ):
        """UserInfo does NOT return profile claims without profile scope."""
        access_token, _ = create_access_token(
            subject=str(test_user.id),
            audience="test_client",
            scope="openid email",
        )

        response = self.client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["sub"] == str(test_user.id)
        assert data["email"] == test_user.email
        assert "name" not in data
        assert "given_name" not in data
        assert "family_name" not in data

    def test_userinfo_returns_401_for_nonexistent_user(self, db_session):
        """UserInfo returns 401 if user referenced in token doesn't exist."""
        nonexistent_user_id = uuid.uuid4()
        access_token, _ = create_access_token(
            subject=str(nonexistent_user_id),
            audience="test_client",
            scope="openid",
        )

        response = self.client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 401

    def test_userinfo_user_without_profile_fields(self, db_session):
        """UserInfo handles user with NULL profile fields gracefully."""
        user = User(
            id=uuid.uuid4(),
            email="minimal@example.com",
            password_hash=hash_password("password"),
            name=None,
            given_name=None,
            family_name=None,
        )
        db_session.add(user)
        db_session.commit()

        access_token, _ = create_access_token(
            subject=str(user.id),
            audience="test_client",
            scope="openid profile email",
        )

        response = self.client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["sub"] == str(user.id)
        assert data["email"] == user.email
        assert "name" not in data
        assert "given_name" not in data
        assert "family_name" not in data

    def test_userinfo_requires_openid_scope(self, db_session, test_user):
        """UserInfo endpoint rejects tokens without openid scope."""
        access_token, _ = create_access_token(
            subject=str(test_user.id),
            audience="test_client",
            scope="profile email",  # Missing openid
        )

        response = self.client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        # Per RFC 6750, insufficient_scope returns 403
        assert response.status_code == 403
        assert "UserInfo scope" in response.json()["detail"]
        assert "insufficient_scope" in response.headers["www-authenticate"]
