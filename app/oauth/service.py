import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.oauth.errors import OAuthError, OAuthErrorCode
from app.oauth.jwt import (
    create_access_token,
    revoke_token_chain,
    rotate_refresh_token,
    validate_refresh_token,
)
from app.oauth.models import AuthorizationCode, OAuthClient, RefreshToken
from app.oauth.pkce import verify_s256_code_verifier

from ..config import settings

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
        {"name": scope, "description": SCOPE_DESCRIPTIONS.get(scope, f"Access {scope}")}
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
    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()

    if not client:
        raise OAuthError(
            error_code=OAuthErrorCode.UNAUTHORIZED_CLIENT, description="Unknown client"
        )

    if redirect_uri != client.redirect_uri:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_REQUEST,
            description="Redirect URI mismatch",
        )

    # Validate requested scopes are subset of allowed scopes
    allowed_scopes = set(client.scopes.split())
    requested = set(requested_scopes.split())

    if not requested.issubset(allowed_scopes):
        invalid_scopes = requested - allowed_scopes
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_SCOPE,
            description=f"Requested scopes not allowed: {' '.join(invalid_scopes)}",
        )

    return client


def create_authorization_code(
    db: Session,
    user_id: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
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
        code_challenge: PKCE code challenge (required if PKCE is enforced)
        code_challenge_method: PKCE method (e.g., "S256")
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
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=datetime.utcnow() + timedelta(seconds=settings.CODE_EXPIRY_SECONDS),
    )

    db.add(auth_code)
    db.commit()

    return code


def create_refresh_token(
    db: Session,
    user_id: str,
    client_id: str,
    scope: str,
    parent_token_id: Optional[str] = None,
) -> str:
    """
    Create a refresh token for the OAuth flow.

    Args:
        db: Database session
        user_id: User's UUID
        client_id: Client identifier
        scope: Granted scopes (space-separated)
        parent_token_id: Optional parent token ID for chain tracking

    Returns:
        The generated refresh token string
    """

    token = secrets.token_urlsafe(32)

    refresh_token = RefreshToken(
        token=token,
        user_id=user_id,
        client_id=client_id,
        scope=scope,
        expires_at=datetime.utcnow()
        + timedelta(seconds=settings.REFRESH_TOKEN_EXPIRE_SECONDS),
        parent_token_id=parent_token_id,
    )

    db.add(refresh_token)
    db.commit()

    return token


def exchange_code_for_tokens(
    db: Session,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code_verifier: Optional[str] = None,
) -> str:
    """
    Exchange an authorization code for access token and refresh tokens.

    Args:
        db: Database session
        code: Authorization code
        client_id: Client identifier
        client_secret: Client secret for authentication
        redirect_uri: Must match the redirect_uri from authorization request
        code_verifier: PKCE code verifier (required if code_challenge was used)

    Returns:
        Tuple of (access_token, refresh_token)

    Raises:
        OAuthError if code is invalid, expired, or client authentication fails
    """
    # Validate client credentials
    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()

    if not client or client.client_secret != client_secret:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_CLIENT,
            description="Client authentication failed",
        )

    # Find the authorization code
    auth_code = (
        db.query(AuthorizationCode).filter(AuthorizationCode.code == code).first()
    )

    if not auth_code:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_GRANT,
            description="The authorization code is invalid or has been used",
        )

    if auth_code.expires_at < datetime.utcnow():
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_GRANT,
            description="The authorization code has expired",
        )

    # Validate client_id matches
    if auth_code.client_id != client_id:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_GRANT, description="Client ID mismatch"
        )

    # Validate redirect_uri matches
    if auth_code.redirect_uri != redirect_uri:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_GRANT, description="Redirect URI mismatch"
        )

    # Validate PKCE code_verifier per RFC 7636 Section 4.6
    # Note: Authorization endpoint enforces S256-only, so we only need to verify
    if auth_code.code_challenge:
        if not code_verifier:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_REQUEST,
                description="Missing required parameter: code_verifier",
            )

        if not verify_s256_code_verifier(code_verifier, auth_code.code_challenge):
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_GRANT,
                description="PKCE verification failed: code_verifier mismatch",
            )

    # Create access token
    access_token, _ = create_access_token(
        subject=str(auth_code.user_id),
        audience=auth_code.client_id,
        scope=auth_code.scope,
    )

    # Create refresh token
    refresh_token = create_refresh_token(
        db=db,
        user_id=auth_code.user_id,
        client_id=auth_code.client_id,
        scope=auth_code.scope,
    )

    # Delete the code (single use)
    db.delete(auth_code)
    db.commit()

    return access_token, refresh_token


def handle_authorization_code_grant(
    db: Session,
    code: Optional[str],
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code_verifier: Optional[str],
    scope: Optional[str],
):
    """Handle authorization_code grant type."""
    if not code:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_REQUEST,
            description="Missing required parameter: code",
        )

    # Exchange code for tokens
    access_token, refresh_token = exchange_code_for_tokens(
        db=db,
        code=code,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_SECONDS,
        "refresh_token": refresh_token,
        "scope": scope,
    }


def handle_refresh_token_grant(
    db: Session,
    refresh_token: Optional[str],
    client_id: str,
    client_secret: str,
    scope: Optional[str],
):
    """
    Handle refresh_token grant type per RFC 6749 §6.

    Validates the refresh token, rotates it, and issues new tokens.
    """
    if not refresh_token:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_REQUEST,
            description="Missing required parameter: refresh_token",
        )

    # Validate client credentials
    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()

    if not client or client.client_secret != client_secret:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_CLIENT,
            description="Client authentication failed",
        )

    # Validate refresh token
    token_record = validate_refresh_token(
        db=db,
        token=refresh_token,
        client_id=client_id,
    )

    # Handle scope - must be subset of original scope
    if scope:
        original_scopes = set(token_record.scope.split())
        requested_scopes = set(scope.split())
        if not requested_scopes.issubset(original_scopes):
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_SCOPE,
                description="Requested scope exceeds original grant",
            )
        final_scope = scope
    else:
        final_scope = token_record.scope

    # Rotate refresh token
    new_refresh_token = rotate_refresh_token(db, token_record)

    # Create new access token
    access_token, _ = create_access_token(
        subject=str(token_record.user_id),
        audience=client_id,
        scope=final_scope,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_SECONDS,
        "refresh_token": new_refresh_token,
        "scope": final_scope,
    }


def revoke_token(
    db: Session,
    token: str,
    token_type_hint: Optional[str] = None,
    client_id: Optional[str] = None,
):
    """
    Revoke an access or refresh token per RFC 7009.
    For refresh tokens, marks as revoked and revokes entire token chain.
    For access tokens (JWTs), relies on short expiry - no action needed.
    """

    # Try to find the token in refresh tokens
    refresh_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()

    if refresh_token:
        if refresh_token.client_id == client_id:
            revoke_token_chain(db, refresh_token, reason="user_revoked")
        return

    # For access tokens, short expiry (5 min) is sufficient - no blacklist needed
