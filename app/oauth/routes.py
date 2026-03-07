from typing import Annotated

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
from app.oauth.services.authorization import AuthorizationService
from app.oauth.services.client import ClientService
from app.oauth.services.token import TokenService
from app.oauth.services.userinfo import UserInfoService
from app.oauth.utils import get_current_user
from app.security.csrf import generate_csrf_token, verify_csrf
from app.templates_config import templates

router = APIRouter(prefix="/oauth", tags=["oauth"])


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
        request,
        "consent.html",
        {
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
    client_service: ClientService = Depends(ClientService),
    auth_service: AuthorizationService = Depends(AuthorizationService),
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
        client = client_service.get_validated_client(client_id, redirect_uri)
    except ValueError as e:
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "error_title": "Invalid Request",
                "error_message": str(e),
            },
            status_code=400,
        )

    # 3. OAuth Validation (Errors here result in a redirect back to client)
    # Use stored values if current ones are missing
    resolved_redirect_uri = redirect_uri or client.redirect_uri
    try:
        effective_scope = auth_service.validate_authorization_request(
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
    auth_service: AuthorizationService = Depends(AuthorizationService),
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
        client, scope_descriptions = auth_service.prepare_consent_view_data(
            params["client_id"], params["scope"]
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    return render_consent_html(
        request, user, client, scope_descriptions, generate_csrf_token(request)
    )


@router.post("/consent/approve", dependencies=[Depends(verify_csrf)])
def approve_consent(
    request: Request,
    db: Session = Depends(get_db),
    auth_service: AuthorizationService = Depends(AuthorizationService),
):
    """
    Handle user approval of authorization request.
    Creates an authorization code and redirects back to the client.
    """
    # Extract params and user
    params = request.session.get("authorize_params")
    user = get_current_user(request, db)

    if not params or not user:
        raise HTTPException(400, "Session expired or invalid")

    # Clear CSRF token after use
    request.session.pop("csrf_token", None)

    code = auth_service.create_authorization_code(
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


@router.post("/consent/deny", dependencies=[Depends(verify_csrf)])
def deny_consent(
    request: Request,
):
    """
    Handle user denial of authorization request.
    Returns an access_denied error redirect to the client.
    """

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
    request_data: Annotated[TokenRequest, Form()],
    client: OAuthClient = Depends(get_authenticated_client),
    token_service: TokenService = Depends(TokenService),
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
        return token_service.handle_authorization_code_grant(
            request_data=request_data,
            client=client,
        )
    elif request_data.grant_type == GrantType.REFRESH_TOKEN:
        return token_service.handle_refresh_token_grant(
            request_data=request_data,
            client=client,
        )

    raise OAuthError(
        error_code=OAuthErrorCode.UNSUPPORTED_GRANT_TYPE,
        description=f"Unsupported grant type: {request_data.grant_type}",
    )


@router.post("/revoke")
def revoke(
    request_data: Annotated[RevocationRequest, Form()],
    client: OAuthClient = Depends(get_authenticated_client),
    token_service: TokenService = Depends(TokenService),
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
    token_service.revoke_token(
        request_data.token, request_data.token_type_hint, client.client_id
    )

    # Per RFC 7009 Section 2.2, respond with HTTP 200 even if the token is invalid
    return {"success": True}


@router.get("/userinfo")
def userinfo(
    request: Request,
    userinfo_service: UserInfoService = Depends(UserInfoService),
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
        claims = userinfo_service.get_userinfo_claims(access_token)
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
