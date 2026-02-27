"""
Script to create a new OAuth client for testing.

This creates a new OAuth client with the required fields for the consent flow.
"""

import secrets

from app.db import SessionLocal
from app.oauth.models import OAuthClient
from app.services.auth import hash_password


def main():
    db = SessionLocal()

    client_id = secrets.token_urlsafe(32)
    client_secret_plain = secrets.token_urlsafe(48)
    client_secret_hashed = hash_password(client_secret_plain)

    # Create client with new fields for consent flow
    client = OAuthClient(
        client_id=client_id,
        client_secret=client_secret_hashed,
        redirect_uri="http://localhost:3000/callback",
        name="Test Application",
        logo_uri=None,  # Optional: URL to client logo
        scopes="openid profile email",  # Space-separated allowed scopes
    )

    db.add(client)
    db.commit()

    print("\n" + "=" * 50)
    print("OAuth Client Created")
    print("=" * 50)
    print(f"CLIENT_ID: {client_id}")
    print(f"CLIENT_SECRET: {client_secret_plain}")
    print(f"REDIRECT_URI: {client.redirect_uri}")
    print(f"NAME: {client.name}")
    print(f"SCOPES: {client.scopes}")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    main()
