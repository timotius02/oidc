import base64
from typing import Optional

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.oauth.constants import ClientType
from app.oauth.errors import OAuthError, OAuthErrorCode
from app.oauth.models import OAuthClient
from app.oauth.services.client import get_client_by_id
from app.services.auth import verify_password


def get_client_credentials(
    request: Request,
    client_id_param: Optional[str] = None,
    client_secret_param: Optional[str] = None,
) -> tuple[Optional[str], Optional[str], bool]:
    """
    Extract client credentials from Authorization header or form parameters.
    Per RFC 6749 Section 2.3.1.

    Returns:
        Tuple of (client_id, client_secret, used_basic_auth)
    """
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("basic "):
        try:
            auth_decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            if ":" in auth_decoded:
                cid, csec = auth_decoded.split(":", 1)
                return cid, csec, True
        except Exception:
            pass

    return client_id_param, client_secret_param, False


def authenticate_client(
    db: Session,
    client_id: str,
    client_secret: Optional[str] = None,
) -> OAuthClient:
    """
    Authenticate an OAuth client per RFC 6749 Section 2.3.1.

    Args:
        db: Database session
        client_id: Client identifier
        client_secret: Client secret for authentication

    Returns:
        OAuthClient if authentication succeeds

    Raises:
        OAuthError if authentication fails
    """
    client = get_client_by_id(db, client_id)

    if not client:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_CLIENT,
            description="Client authentication failed",
            status_code=401,
        )

    # Confidential clients MUST provide a valid secret.
    if client.client_type == ClientType.CONFIDENTIAL:
        if not client_secret or not verify_password(
            client_secret, client.client_secret
        ):
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_CLIENT,
                description="Client authentication failed",
                status_code=401,
            )
    elif client_secret:
        # If secret provided for public client, it must be valid.
        if not verify_password(client_secret, client.client_secret):
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_CLIENT,
                description="Client authentication failed",
                status_code=401,
            )

    return client


async def get_authenticated_client(
    request: Request,
    db: Session = Depends(get_db),
) -> OAuthClient:
    """
    FastAPI dependency to authenticate an OAuth client.
    Supports both Basic Auth and form-encoded credentials.
    """
    # Look for client_id/secret in form-data if not in header
    form_data = await request.form()
    client_id_param = form_data.get("client_id")
    client_secret_param = form_data.get("client_secret")

    client_id, client_secret, used_basic = get_client_credentials(
        request, client_id_param, client_secret_param
    )

    if not client_id:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_CLIENT,
            description="Client authentication failed (missing client_id)",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="oauth"'} if used_basic else None,
        )

    try:
        return authenticate_client(db, client_id, client_secret)
    except OAuthError as e:
        # Standardize 401 response and add WWW-Authenticate header
        if e.error_code == OAuthErrorCode.INVALID_CLIENT:
            if e.headers is None:
                e.headers = {}
            e.headers["WWW-Authenticate"] = 'Basic realm="oauth"'
        raise e
