from jose import jwt
from datetime import datetime, timedelta
from ..config import settings

with open(settings.PRIVATE_KEY_PATH) as f:
    PRIVATE_KEY = f.read()

with open(settings.PUBLIC_KEY_PATH) as f:
    PUBLIC_KEY = f.read()


def create_access_token(subject: str, audience: str, scope: str) -> str:
    now = datetime.utcnow()

    payload = {
        "iss": settings.JWT_ISSUER,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(seconds=settings.ACCESS_TOKEN_EXPIRE_SECONDS),
        "scope": scope,
    }

    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")


def verify_token(token: str, audience: str):
    return jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=["RS256"],
        audience=audience,
        issuer=settings.JWT_ISSUER,
    )