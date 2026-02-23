import secrets

from app.db import SessionLocal
from app.oauth.models import OAuthClient


def main():
    db = SessionLocal()

    client_id = secrets.token_urlsafe(32)
    client_secret = secrets.token_urlsafe(48)

    client = OAuthClient(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri="http://localhost:3000/callback",
    )

    db.add(client)
    db.commit()

    print("\n✅ OAuth Client Created")
    print("CLIENT_ID:", client_id)
    print("CLIENT_SECRET:", client_secret)
    print("REDIRECT_URI:", client.redirect_uri)


if __name__ == "__main__":
    main()