from typing import Optional

from sqlalchemy.orm import Session

from app.oauth.models import OAuthClient


def get_client_by_id(db: Session, client_id: str) -> Optional[OAuthClient]:
    """
    Retrieve an OAuth client by its client_id.

    Args:
        db: Database session
        client_id: The client identifier

    Returns:
        OAuthClient object if found, otherwise None
    """
    return db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()


def get_validated_client(
    db: Session, client_id: Optional[str], redirect_uri: Optional[str] = None
) -> OAuthClient:
    """
    Validate client_id and redirect_uri for the authorization endpoint.

    Per RFC 6749 Section 4.1.2.1, errors related to client_id or redirect_uri
    should be shown to the user via an error page and MUST NOT result in
    a redirect to an untrusted URI.

    Args:
        db: Database session
        client_id: Client identifier
        redirect_uri: Optional redirect URI from the request

    Returns:
        Validated OAuthClient object

    Raises:
        ValueError: If client_id is missing/invalid or redirect_uri mismatch
    """
    if not client_id:
        raise ValueError("Missing required parameter: client_id")

    client = get_client_by_id(db, client_id)
    if not client:
        raise ValueError("The client could not be identified.")

    # Use registered redirect_uri if not provided in request
    target_uri = redirect_uri or client.redirect_uri

    if target_uri != client.redirect_uri:
        raise ValueError("Redirect URI does not match the registered URI.")

    return client
