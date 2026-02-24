import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.oauth.errors import OAuthError, OAuthErrorCode
from app.oauth.models import AuthorizationCode
from app.services.jwt import create_access_token


CODE_EXPIRY_SECONDS = 600


def create_authorization_code(
    db: Session,
    user_id: str,
    client_id: str,
):
    code = secrets.token_urlsafe(32)

    auth_code = AuthorizationCode(
        code=code,
        user_id=user_id,
        client_id=client_id,
        expires_at=datetime.utcnow() + timedelta(seconds=CODE_EXPIRY_SECONDS),
    )

    db.add(auth_code)
    db.commit()

    return code


def exchange_code_for_token(db: Session, code: str):
    auth_code = (
        db.query(AuthorizationCode)
        .filter(AuthorizationCode.code == code)
        .first()
    )

    if not auth_code:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_GRANT,
            description="The authorization code is invalid or has been used"
        )

    if auth_code.expires_at < datetime.utcnow():
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_GRANT,
            description="The authorization code has expired"
        )


    access_token = create_access_token(
        subject=str(auth_code.user_id),
        audience=auth_code.client_id
    )

    db.delete(auth_code)
    db.commit()

    return access_token