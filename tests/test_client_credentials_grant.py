import base64

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.oauth.models import OAuthClient
from app.services.auth import hash_password


@pytest.fixture
def client_credentials_setup():
    """Setup a fresh in-memory database and test client."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)

    db = TestingSessionLocal()
    yield test_client, db

    db.close()
    app.dependency_overrides.clear()


def test_client_credentials_grant_success(client_credentials_setup):
    """Test successful client_credentials grant for a confidential client."""
    test_client, db = client_credentials_setup

    client_id = "trusted_service"
    client_secret = "very_secret"
    db_client = OAuthClient(
        client_id=client_id,
        client_secret=hash_password(client_secret),
        redirect_uri="https://service.local/cb",
        client_type="confidential",
        name="Trusted Service",
        scopes="read write",
    )
    db.add(db_client)
    db.commit()

    # Request token using Basic Auth
    auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    response = test_client.post(
        "/oauth/token",
        headers={"Authorization": f"Basic {auth_header}"},
        data={"grant_type": "client_credentials", "scope": "read"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["scope"] == "read"
    assert "refresh_token" not in data
    assert "id_token" not in data


def test_client_credentials_grant_public_client_rejected(client_credentials_setup):
    """Test that public clients cannot use client_credentials grant."""
    test_client, db = client_credentials_setup

    client_id = "public_app"
    db_client = OAuthClient(
        client_id=client_id,
        client_secret="",  # Public clients have no secret
        redirect_uri="https://app.local/cb",
        client_type="public",
        name="Public App",
        scopes="",
    )
    db.add(db_client)
    db.commit()

    response = test_client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": client_id},
    )

    # Public clients are rejected with 400 unauthorized_client
    assert response.status_code == 400
    assert response.json()["error"] == "unauthorized_client"


def test_client_credentials_grant_invalid_scope(client_credentials_setup):
    """Test that requesting scopes outside client permissions fails."""
    test_client, db = client_credentials_setup

    client_id = "limited_service"
    client_secret = "secret"
    db_client = OAuthClient(
        client_id=client_id,
        client_secret=hash_password(client_secret),
        redirect_uri="https://service.local/cb",
        client_type="confidential",
        name="Limited Service",
        scopes="read",
    )
    db.add(db_client)
    db.commit()

    auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    response = test_client.post(
        "/oauth/token",
        headers={"Authorization": f"Basic {auth_header}"},
        data={"grant_type": "client_credentials", "scope": "write"},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


def test_client_credentials_grant_default_scope(client_credentials_setup):
    """Test that omitting scope returns all allowed scopes."""
    test_client, db = client_credentials_setup

    client_id = "all_access"
    client_secret = "secret"
    db_client = OAuthClient(
        client_id=client_id,
        client_secret=hash_password(client_secret),
        redirect_uri="https://service.local/cb",
        client_type="confidential",
        name="All Access",
        scopes="read write admin",
    )
    db.add(db_client)
    db.commit()

    auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    response = test_client.post(
        "/oauth/token",
        headers={"Authorization": f"Basic {auth_header}"},
        data={"grant_type": "client_credentials"},
    )

    assert response.status_code == 200
    assert response.json()["scope"] == "read write admin"
