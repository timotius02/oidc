import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.oauth.client_auth import get_authenticated_client
from app.oauth.constants import GrantType
from app.oauth.errors import (
    OAuthError,
    OAuthErrorCode,
    create_authorization_error_response,
)
from app.oauth.models import OAuthClient
from app.oauth.schemas import AuthorizationRequest, RevocationRequest, TokenRequest
from app.oauth.service import (
    create_authorization_code,
    get_userinfo_claims,
    get_validated_client,
    handle_authorization_code_grant,
    handle_refresh_token_grant,
    prepare_consent_view_data,
    revoke_token,
    validate_authorization_request,
)
from app.oauth.utils import get_current_user
from app.templates_config import templates

router = APIRouter(prefix="/oauth", tags=["oauth"])


def generate_csrf_token(request: Request) -> str:
    """Generate a CSRF token and store it in the session."""
    token = secrets.token_urlsafe(32)
    request.session["csrf_token"] = token
    return token


def validate_csrf_token(request: Request, submitted_token: str) -> bool:
    """Validate the submitted CSRF token against the session token."""
    session_token = request.session.get("csrf_token")
    if not session_token:
        return False
    return secrets.compare_digest(session_token, submitted_token)


def render_consent_html(
    request: Request,
    user,
    client,
    scope_descriptions: list,
    csrf_token: str,
) -> HTMLResponse:
    """
    Render the consent screen using Jinja2 template.

    Args:
        request: The FastAPI request object
        user: The authenticated user object
        client: The OAuthClient object
        scope_descriptions: List of scope descriptions with 'name' and 'description'
        csrf_token: CSRF token for form protection

    Returns:
        HTMLResponse with the rendered consent screen
    """
    return templates.TemplateResponse(
        "consent.html",
        {
            "request": request,
            "client_name": client.name,
            "client_logo_uri": client.logo_uri,
            "user_email": user.email,
            "scopes": scope_descriptions,
            "csrf_token": csrf_token,
        },
    )


@router.get("/authorize")
def authorize(
    request: Request,
    params: AuthorizationRequest = Depends(),
    db: Session = Depends(get_db),
):
    """
    OAuth 2.0 Authorization Endpoint.
    """
    # 1. Restore/Merge params from session if missing (for post-login redirect)
    stored = request.session.get("authorize_params") or {}
    client_id = params.client_id or stored.get("client_id")
    redirect_uri = params.redirect_uri or stored.get("redirect_uri")

    # 2. Hard Validation (Errors here show an error page, no redirect)
    try:
        client = get_validated_client(db, client_id, redirect_uri)
    except ValueError as e:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Invalid Request",
                "error_message": str(e),
            },
            status_code=400,
        )

    # 3. OAuth Validation (Errors here result in a redirect back to client)
    # Use stored values if current ones are missing
    resolved_redirect_uri = redirect_uri or client.redirect_uri
    try:
        effective_scope = validate_authorization_request(
            client=client,
            response_type=params.response_type or stored.get("response_type"),
            scope=params.scope or stored.get("scope"),
            code_challenge=params.code_challenge or stored.get("code_challenge"),
            code_challenge_method=params.code_challenge_method
            or stored.get("code_challenge_method"),
        )
    except OAuthError as e:
        return create_authorization_error_response(
            redirect_uri=resolved_redirect_uri,
            error_code=e.error_code,
            description=e.description,
            state=params.state or stored.get("state"),
        )

    # 4. Persistence
    request.session["authorize_params"] = {
        "client_id": client.client_id,
        "redirect_uri": resolved_redirect_uri,
        "response_type": params.response_type or stored.get("response_type"),
        "scope": effective_scope,
        "state": params.state or stored.get("state"),
        "code_challenge": params.code_challenge or stored.get("code_challenge"),
        "code_challenge_method": params.code_challenge_method
        or stored.get("code_challenge_method"),
        "nonce": params.nonce or stored.get("nonce"),
    }

    # 5. Auth Check
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/auth/login?next=/oauth/authorize")

    return RedirectResponse("/oauth/consent")


@router.get("/consent", response_class=HTMLResponse)
def consent_page(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Display the consent screen for the user to approve or deny authorization.
    """
    params = request.session.get("authorize_params")
    if not params:
        raise HTTPException(400, "Missing authorization request")

    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/auth/login")

    try:
        client, scope_descriptions = prepare_consent_view_data(
            db, params["client_id"], params["scope"]
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    return render_consent_html(
        request, user, client, scope_descriptions, generate_csrf_token(request)
    )


@router.post("/consent/approve")
def approve_consent(
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """
    Handle user approval of authorization request.
    Creates an authorization code and redirects back to the client.
    """
    # Validate CSRF token
    if not validate_csrf_token(request, csrf_token):
        raise HTTPException(403, "Invalid CSRF token")

    params = request.session.get("authorize_params")
    user = get_current_user(request, db)

    if not params or not user:
        raise HTTPException(400, "Session expired or invalid")

    # Clear CSRF token after use
    request.session.pop("csrf_token", None)

    code = create_authorization_code(
        db=db,
        user_id=str(user.id),
        client_id=params["client_id"],
        redirect_uri=params["redirect_uri"],
        scope=params["scope"],
        code_challenge=params.get("code_challenge"),
        code_challenge_method=params.get("code_challenge_method"),
        nonce=params.get("nonce"),
    )

    # Clear session params
    request.session.pop("authorize_params", None)

    # Build redirect URL - state is optional (RECOMMENDED but not REQUIRED per RFC 6749)
    redirect_url = f"{params['redirect_uri']}?code={code}"
    if params.get("state"):
        redirect_url += f"&state={params['state']}"

    return RedirectResponse(redirect_url)


@router.post("/consent/deny")
def deny_consent(
    request: Request,
    csrf_token: str = Form(...),
):
    """
    Handle user denial of authorization request.
    Returns an access_denied error redirect to the client.
    """
    # Validate CSRF token
    if not validate_csrf_token(request, csrf_token):
        raise HTTPException(403, "Invalid CSRF token")

    params = request.session.get("authorize_params")

    if not params:
        raise HTTPException(400, "Missing authorization request")

    # Clear CSRF token and session params
    request.session.pop("csrf_token", None)
    request.session.pop("authorize_params", None)

    return create_authorization_error_response(
        redirect_uri=params["redirect_uri"],
        error_code=OAuthErrorCode.ACCESS_DENIED,
        description="The user denied the authorization request",
        state=params.get("state"),
    )


@router.post("/token")
def token(
    request: Request,
    request_data: TokenRequest = Depends(TokenRequest.as_form),
    client: OAuthClient = Depends(get_authenticated_client),
    db: Session = Depends(get_db),
):
    """
    OAuth 2.0 Token Endpoint.

    Exchanges an authorization code for an access token and refresh token,
    or rotates a refresh token. Validates client credentials, redirect_uri,
    PKCE code_verifier, and refresh token.

    Supports:
    - authorization_code grant (RFC 6749 §4.1)
    - refresh_token grant (RFC 6749 §6)

    """
    if request_data.grant_type == GrantType.AUTHORIZATION_CODE:
        return handle_authorization_code_grant(
            db=db,
            code=request_data.code,
            client=client,
            redirect_uri=request_data.redirect_uri,
            code_verifier=request_data.code_verifier,
            scope=request_data.scope,
        )
    elif request_data.grant_type == GrantType.REFRESH_TOKEN:
        return handle_refresh_token_grant(
            db=db,
            refresh_token=request_data.refresh_token,
            client=client,
            scope=request_data.scope,
        )

    raise OAuthError(
        error_code=OAuthErrorCode.UNSUPPORTED_GRANT_TYPE,
        description=f"Unsupported grant type: {request_data.grant_type}",
    )


@router.post("/revoke")
def revoke(
    request_data: RevocationRequest = Depends(RevocationRequest.as_form),
    client: OAuthClient = Depends(get_authenticated_client),
    db: Session = Depends(get_db),
):
    """
    OAuth 2.0 Token Revocation Endpoint (RFC 7009).

    Allows clients to revoke tokens (refresh or access) when they are no longer needed.
    Validates client credentials & token existence. Per RFC 7009, the endpoint responds
    with HTTP 200 even if the token is invalid or already revoked to prevent token
    enumeration.

    This implementation supports revoking refresh tokens but follows Modern OAuth
    guidance of allowing access tokens to expire naturally without revocation due to
    their short lifespan and stateless nature.
    """
    # Attempt to revoke the token (access or refresh)
    revoke_token(db, request_data.token, request_data.token_type_hint, client.client_id)

    # Per RFC 7009 Section 2.2, respond with HTTP 200 even if the token is invalid
    return {"success": True}


@router.get("/userinfo")
def userinfo(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    OIDC UserInfo Endpoint per OpenID Connect Core §5.3.

    Returns claims about the authenticated user based on granted scopes.
    Protected by access token (Bearer authentication).
    """
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": 'Bearer realm="userinfo"'},
        )

    access_token = auth_header[7:]  # Remove "Bearer " prefix

    try:
        claims = get_userinfo_claims(db, access_token)
    except OAuthError as e:
        # Per RFC 6750, insufficient_scope returns 403, others return 401
        status_code = 403 if e.error_code == OAuthErrorCode.INSUFFICIENT_SCOPE else 401
        auth_header = f'Bearer realm="userinfo", error="{e.error_code.value}"'
        raise HTTPException(
            status_code=status_code,
            detail=e.description,
            headers={"WWW-Authenticate": auth_header},
        )

    return claims
