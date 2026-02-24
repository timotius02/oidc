import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.oauth.errors import OAuthError, OAuthErrorCode
from app.oauth.models import AuthorizationCode, OAuthClient
from app.services.jwt import create_access_token


CODE_EXPIRY_SECONDS = 600

# Scope descriptions for consent screen
SCOPE_DESCRIPTIONS: Dict[str, str] = {
    "openid": "Authenticate your identity",
    "profile": "Access your profile information (name, picture)",
    "email": "Access your email address",
    "offline_access": "Access your data even when you're offline",
}


def get_scope_descriptions(scopes: List[str]) -> List[Dict[str, str]]:
    """
    Get human-readable descriptions for a list of scopes.

    Args:
        scopes: List of scope strings

    Returns:
        List of dicts with 'name' and 'description' keys
    """
    return [
        {
            "name": scope,
            "description": SCOPE_DESCRIPTIONS.get(scope, f"Access {scope}")
        }
        for scope in scopes
    ]


def validate_client(
    db: Session,
    client_id: str,
    redirect_uri: str,
    requested_scopes: str,
) -> OAuthClient:
    """
    Validate OAuth client and its parameters.

    Args:
        db: Database session
        client_id: Client identifier
        redirect_uri: Redirect URI from authorization request
        requested_scopes: Space-separated requested scopes

    Returns:
        OAuthClient if validation succeeds

    Raises:
        OAuthError if validation fails
    """
    client = db.query(OAuthClient).filter(
        OAuthClient.client_id == client_id
    ).first()

    if not client:
        raise OAuthError(
            error_code=OAuthErrorCode.UNAUTHORIZED_CLIENT,
            description="Unknown client"
        )

    if redirect_uri != client.redirect_uri:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_REQUEST,
            description="Redirect URI mismatch"
        )

    # Validate requested scopes are subset of allowed scopes
    allowed_scopes = set(client.scopes.split())
    requested = set(requested_scopes.split())

    if not requested.issubset(allowed_scopes):
        invalid_scopes = requested - allowed_scopes
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_SCOPE,
            description=f"Requested scopes not allowed: {' '.join(invalid_scopes)}"
        )

    return client


def create_authorization_code(
    db: Session,
    user_id: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    nonce: Optional[str] = None,
) -> str:
    """
    Create an authorization code for the OAuth flow.

    Args:
        db: Database session
        user_id: User's UUID
        client_id: Client identifier
        redirect_uri: Redirect URI for validation at token exchange
        scope: Granted scopes (space-separated)
        nonce: Optional nonce for OIDC id_token

    Returns:
        The generated authorization code string
    """
    code = secrets.token_urlsafe(32)

    auth_code = AuthorizationCode(
        code=code,
        user_id=user_id,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        nonce=nonce,
        expires_at=datetime.utcnow() + timedelta(seconds=CODE_EXPIRY_SECONDS),
    )

    db.add(auth_code)
    db.commit()

    return code


def exchange_code_for_token(
    db: Session,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> str:
    """
    Exchange an authorization code for an access token.

    Args:
        db: Database session
        code: Authorization code
        client_id: Client identifier
        client_secret: Client secret for authentication
        redirect_uri: Must match the redirect_uri from authorization request

    Returns:
        Access token string

    Raises:
        OAuthError if code is invalid, expired, or client authentication fails
    """
    # Validate client credentials
    client = db.query(OAuthClient).filter(
        OAuthClient.client_id == client_id
    ).first()

    if not client or client.client_secret != client_secret:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_CLIENT,
            description="Client authentication failed"
        )

    # Find the authorization code
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

    # Validate client_id matches
    if auth_code.client_id != client_id:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_GRANT,
            description="Client ID mismatch"
        )

    # Validate redirect_uri matches
    if auth_code.redirect_uri != redirect_uri:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_GRANT,
            description="Redirect URI mismatch"
        )

    access_token = create_access_token(
        subject=str(auth_code.user_id),
        audience=auth_code.client_id
    )

    # Delete the code (single use)
    db.delete(auth_code)
    db.commit()

    return access_token