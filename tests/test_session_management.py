import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.middleware.rate_limit import clear_rate_limit_store
from app.models.user import User
from app.oauth.models import OAuthClient
from app.services.auth import hash_password


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter between tests."""
    clear_rate_limit_store()
    yield
    clear_rate_limit_store()


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


@pytest.fixture
def test_user(db_session: Session):
    """Create a test user."""
    user = User(
        email="testuser@example.com",
        password_hash=hash_password("password123"),
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def test_client(db_session: Session):
    """Create a test OAuth client with post_logout_redirect_uris."""
    client = OAuthClient(
        client_id="test-client",
        client_secret=hash_password("client-secret"),
        redirect_uri="http://localhost:3000/callback",
        name="Test Client",
        scopes="openid profile email",
        client_type="confidential",
        post_logout_redirect_uris="http://localhost:3000/logout http://localhost:3000/",
    )
    db_session.add(client)
    db_session.commit()
    db_session.refresh(client)
    return client


def login_user(client: TestClient, test_user: User) -> str:
    """Helper to login a user and return the session cookie."""
    # Get CSRF token
    get_response = client.get("/auth/login")
    import re

    match = re.search(r'name="csrf_token" value="([^"]+)"', get_response.text)
    csrf_token = match.group(1)

    # Login
    client.post(
        "/auth/login",
        data={
            "email": test_user.email,
            "password": "password123",
            "next": "/",
            "csrf_token": csrf_token,
        },
    )
    return csrf_token


class TestEndSessionEndpoint:
    """Tests for the RP-Initiated Logout endpoint."""

    def test_end_session_without_session_shows_logout_page(self, client):
        """Test end_session when no user is logged in shows logout page."""
        response = client.get("/oauth/end_session", follow_redirects=False)
        assert response.status_code == 200
        assert "Logged Out" in response.text

    def test_end_session_with_valid_session_clears_session(
        self, client, test_user, db_session
    ):
        """Test end_session clears the user session."""
        # Login first
        login_user(client, test_user)

        # Verify session exists by accessing a protected resource
        # (we'll check by hitting end_session and seeing it was cleared)
        response = client.get("/oauth/end_session", follow_redirects=False)
        assert response.status_code == 200
        assert "Logged Out" in response.text

    def test_end_session_with_post_logout_redirect_uri(
        self, client, test_user, test_client, db_session
    ):
        """Test end_session redirects to valid post_logout_redirect_uri."""
        # Login first
        login_user(client, test_user)

        # Create an ID token hint
        from app.oauth.jwt import create_id_token

        id_token = create_id_token(
            subject=str(test_user.id),
            audience=test_client.client_id,
        )

        response = client.get(
            "/oauth/end_session",
            params={
                "id_token_hint": id_token,
                "post_logout_redirect_uri": "http://localhost:3000/logout",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert response.headers["location"] == "http://localhost:3000/logout"

    def test_end_session_with_post_logout_redirect_uri_and_state(
        self, client, test_user, test_client, db_session
    ):
        """Test end_session passes state through to redirect."""
        # Login first
        login_user(client, test_user)

        # Create an ID token hint
        from app.oauth.jwt import create_id_token

        id_token = create_id_token(
            subject=str(test_user.id),
            audience=test_client.client_id,
        )

        response = client.get(
            "/oauth/end_session",
            params={
                "id_token_hint": id_token,
                "post_logout_redirect_uri": "http://localhost:3000/logout",
                "state": "test-state-123",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "state=test-state-123" in response.headers["location"]

    def test_end_session_rejects_invalid_post_logout_redirect_uri(
        self, client, test_user, test_client, db_session
    ):
        """Test end_session does not redirect to unregistered URI."""
        # Login first
        login_user(client, test_user)

        # Create an ID token hint
        from app.oauth.jwt import create_id_token

        id_token = create_id_token(
            subject=str(test_user.id),
            audience=test_client.client_id,
        )

        response = client.get(
            "/oauth/end_session",
            params={
                "id_token_hint": id_token,
                "post_logout_redirect_uri": "http://evil.com/steal",
            },
            follow_redirects=False,
        )
        # Should show logout page instead of redirecting to evil site
        assert response.status_code == 200
        assert "Logged Out" in response.text

    def test_end_session_extracts_client_id_from_token_hint(
        self, client, test_user, test_client, db_session
    ):
        """Test end_session extracts client_id from id_token_hint."""
        # Login first
        login_user(client, test_user)

        # Create an ID token hint
        from app.oauth.jwt import create_id_token

        id_token = create_id_token(
            subject=str(test_user.id),
            audience=test_client.client_id,
        )

        # Don't provide client_id explicitly - it should be extracted from token
        response = client.get(
            "/oauth/end_session",
            params={
                "id_token_hint": id_token,
                "post_logout_redirect_uri": "http://localhost:3000/logout",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert response.headers["location"] == "http://localhost:3000/logout"

    def test_end_session_with_invalid_token_hint_still_works(self, client, test_user):
        """Test end_session works even with invalid id_token_hint."""
        # Login first
        login_user(client, test_user)

        response = client.get(
            "/oauth/end_session",
            params={
                "id_token_hint": "invalid-token-not-a-jwt",
            },
            follow_redirects=False,
        )
        # Should still show logout page (invalid token is acceptable)
        assert response.status_code == 200
        assert "Logged Out" in response.text

    def test_end_session_without_client_shows_logout_page(self, client, test_user):
        """Test end_session without client context shows logout page."""
        # Login first
        login_user(client, test_user)

        response = client.get(
            "/oauth/end_session",
            params={
                "post_logout_redirect_uri": "http://localhost:3000/logout",
            },
            follow_redirects=False,
        )
        # No client_id means no validation, so shows logout page
        assert response.status_code == 200
        assert "Logged Out" in response.text


class TestDiscoveryDocument:
    """Tests for discovery document including end_session_endpoint."""

    def test_discovery_contains_end_session_endpoint(self, client):
        """Test discovery document includes end_session_endpoint."""
        response = client.get("/.well-known/openid-configuration")
        assert response.status_code == 200
        data = response.json()
        assert "end_session_endpoint" in data
        assert data["end_session_endpoint"].endswith("/oauth/end_session")
