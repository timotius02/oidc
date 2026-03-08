import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models.user import User
from app.services.auth import UserService


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
def user_service(db_session: Session):
    return UserService(db_session)


def test_user_service_registration(user_service):
    """Test creating a user via UserService."""
    email = "newuser@example.com"
    password = "securepassword"
    user = user_service.create_user(email, password)

    assert user.email == email
    assert user.password_hash != password
    assert user_service.verify_password(password, user.password_hash)


def test_user_service_authentication(user_service):
    """Test authenticating a user via UserService."""
    email = "authuser@example.com"
    password = "password123"
    user_service.create_user(email, password)

    authenticated_user = user_service.authenticate_user(email, password)
    assert authenticated_user is not None
    assert authenticated_user.email == email

    # Test wrong password
    assert user_service.authenticate_user(email, "wrongpassword") is None

    # Test non-existent user
    assert user_service.authenticate_user("nonexistent@example.com", password) is None


def test_login_page_get(client):
    """Test the login page loads with the new template."""
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert "Welcome Back" in response.text
    assert "<form" in response.text
    assert "Sign In" in response.text


def test_login_flow_success(client, user_service):
    """Test successful login redirect with CSRF."""
    email = "login@example.com"
    password = "password123"
    user_service.create_user(email, password)

    # 1. Get the login page to get the CSRF token
    get_response = client.get("/auth/login")
    assert get_response.status_code == 200

    # Simple way to extract CSRF token from HTML
    import re

    match = re.search(r'name="csrf_token" value="([^"]+)"', get_response.text)
    assert match is not None
    csrf_token = match.group(1)

    # 2. Post with the token
    response = client.post(
        "/auth/login",
        data={
            "email": email,
            "password": password,
            "next": "/custom-next",
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )

    assert response.status_code == 302, response.json()
    assert response.headers["location"] == "/custom-next"


def test_login_flow_csrf_failure(client, user_service):
    """Test login fails without a valid CSRF token."""
    email = "csrf_fail@example.com"
    password = "password123"
    user_service.create_user(email, password)

    response = client.post(
        "/auth/login",
        data={
            "email": email,
            "password": password,
            "next": "/",
            "csrf_token": "invalid_token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert "CSRF token validation failed" in response.json()["detail"]


def test_login_flow_failure(client, user_service):
    """Test login failure re-renders the page with an error and new CSRF."""
    email = "wrong@example.com"
    password = "wrongpassword"
    user_service.create_user(email, "correctpassword")

    # 1. Get CSRF
    get_response = client.get("/auth/login")
    import re

    csrf_token = re.search(
        r'name="csrf_token" value="([^"]+)"', get_response.text
    ).group(1)

    # 2. Post wrong credentials
    response = client.post(
        "/auth/login",
        data={
            "email": email,
            "password": password,
            "next": "/",
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )

    assert response.status_code == 200, response.json()
    assert "Invalid email or password" in response.text
    assert 'name="csrf_token"' in response.text  # New token should be present


def test_register_flow_json(client, db_session):
    """Test registration via JSON endpoint."""
    email = "register_json@example.com"
    password = "password123"

    response = client.post(
        "/auth/register", json={"email": email, "password": password}
    )

    assert response.status_code == 200
    assert response.json()["email"] == email

    # Verify user was created in DB
    user = db_session.query(User).filter(User.email == email).first()
    assert user is not None
