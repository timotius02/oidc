import secrets
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.oauth.errors import (
    OAuthError,
    OAuthErrorCode,
    create_authorization_error_response,
)
from app.oauth.models import OAuthClient
from app.oauth.service import (
    create_authorization_code,
    get_scope_descriptions,
    handle_authorization_code_grant,
    handle_refresh_token_grant,
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
    client: OAuthClient,
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
    client_id: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    response_type: Optional[str] = None,
    scope: Optional[str] = None,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    nonce: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    OAuth 2.0 Authorization Endpoint.

    Validates the client and authorization parameters, then either:
    - Redirects to login if user is not authenticated
    - Redirects to consent screen if user is authenticated

    Parameters can be provided via query string or retrieved from session
    (stored during a previous request that triggered login redirect).
    """
    # If query params are missing, try to restore from session
    # This handles the post-login redirect case
    if client_id is None or redirect_uri is None or response_type is None:
        stored_params = request.session.get("authorize_params")
        if stored_params:
            # Use stored params for missing values
            client_id = client_id or stored_params.get("client_id")
            redirect_uri = redirect_uri or stored_params.get("redirect_uri")
            response_type = response_type or stored_params.get("response_type")
            scope = scope or stored_params.get("scope")
            state = state or stored_params.get("state")
            code_challenge = code_challenge or stored_params.get("code_challenge")
            code_challenge_method = code_challenge_method or stored_params.get(
                "code_challenge_method"
            )
            nonce = nonce or stored_params.get("nonce")

    # =========================================================================
    # STEP 1: Validate client_id (REQUIRED per RFC 6749 Section 4.1.1)
    # =========================================================================
    # Per RFC 6749 Section 4.1.2.1:
    # "If the request fails due to a missing, invalid, or mismatching
    # redirection URI, or if the client identifier is missing or invalid,
    # the authorization server SHOULD inform the resource owner of the
    # error and MUST NOT automatically redirect the user-agent to the
    # invalid redirection URI."
    if not client_id:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Invalid Request",
                "error_message": "Missing required parameter: client_id",
            },
            status_code=400,
        )

    # =========================================================================
    # STEP 2: Validate client exists
    # =========================================================================
    # This must be done BEFORE using redirect_uri for any error redirects
    # to prevent open redirect attacks
    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()

    if not client:
        # Unknown client - show error page, don't redirect
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Invalid Client",
                "error_message": "The client could not be identified.",
            },
            status_code=400,
        )

    # =========================================================================
    # STEP 3: Validate redirect_uri
    # =========================================================================
    # Per RFC 6749 Section 4.1.1, redirect_uri is OPTIONAL if the client
    # has pre-registered a redirect URI. If not provided, use the registered one.
    if redirect_uri is None:
        redirect_uri = client.redirect_uri

    # Validate redirect_uri matches registered URI
    if redirect_uri != client.redirect_uri:
        # Invalid redirect_uri - show error page, don't redirect
        # This prevents open redirect attacks
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error_title": "Invalid Redirect URI",
                "error_message": ("Redirect URI does not match the registered URI."),
            },
            status_code=400,
        )

    # =========================================================================
    # STEP 4: Validate response_type (REQUIRED per RFC 6749 Section 4.1.1)
    # =========================================================================
    if not response_type:
        return create_authorization_error_response(
            redirect_uri=redirect_uri,
            error_code=OAuthErrorCode.INVALID_REQUEST,
            description="Missing required parameter: response_type",
            state=state,
        )

    if response_type != "code":
        return create_authorization_error_response(
            redirect_uri=redirect_uri,
            error_code=OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE,
            description="The authorization server only supports 'code' response type",
            state=state,
        )

    # =========================================================================
    # STEP 5: Validate PKCE parameters
    # =========================================================================
    # Per RFC 7636 Section 4.2:
    # - code_challenge is REQUIRED when PKCE is mandated by the server
    # - code_challenge_method is OPTIONAL, defaults to "plain" if absent
    #
    # This server enforces S256 only for security (modern best practice).
    # Clients MUST explicitly provide code_challenge_method=S256.
    if not code_challenge:
        return create_authorization_error_response(
            redirect_uri=redirect_uri,
            error_code=OAuthErrorCode.INVALID_REQUEST,
            description="Missing required parameter: code_challenge (PKCE is required)",
            state=state,
        )

    if code_challenge_method != "S256":
        return create_authorization_error_response(
            redirect_uri=redirect_uri,
            error_code=OAuthErrorCode.INVALID_REQUEST,
            description="Missing/invalid code_challenge_method. Only 'S256' supported.",
            state=state,
        )

    # =========================================================================
    # STEP 6: Validate scope (OPTIONAL per RFC 6749 Section 4.1.1)
    # =========================================================================
    # If scope is not provided, use the client's default scopes
    if not scope:
        scope = client.scopes

    # Validate requested scopes are subset of allowed scopes
    allowed_scopes = set(client.scopes.split())
    requested = set(scope.split())

    if not requested.issubset(allowed_scopes):
        invalid_scopes = requested - allowed_scopes
        return create_authorization_error_response(
            redirect_uri=redirect_uri,
            error_code=OAuthErrorCode.INVALID_SCOPE,
            description=f"Requested scopes not allowed: {' '.join(invalid_scopes)}",
            state=state,
        )

    # Store validated params in session for consent flow and post-login redirect
    request.session["authorize_params"] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "nonce": nonce,
    }

    # Check user authentication
    user = get_current_user(request, db)
    if not user:
        login_url = "/auth/login?next=/oauth/authorize"
        return RedirectResponse(login_url)

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

    # Get client info for display
    client = (
        db.query(OAuthClient)
        .filter(OAuthClient.client_id == params["client_id"])
        .first()
    )

    if not client:
        raise HTTPException(400, "Invalid client")

    # Parse scopes for display
    scopes = params["scope"].split()
    scope_descriptions = get_scope_descriptions(scopes)

    # Generate CSRF token for form protection
    csrf_token = generate_csrf_token(request)

    return render_consent_html(request, user, client, scope_descriptions, csrf_token)


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
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    redirect_uri: str = Form(...),
    code_verifier: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    scope: Optional[str] = Form(None),
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
    if grant_type == "authorization_code":
        return handle_authorization_code_grant(
            db=db,
            code=code,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            scope=scope,
        )
    elif grant_type == "refresh_token":
        return handle_refresh_token_grant(
            db=db,
            refresh_token=refresh_token,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
        )
    else:
        raise OAuthError(
            error_code=OAuthErrorCode.UNSUPPORTED_GRANT_TYPE,
            description=f"Unsupported grant type: {grant_type}",
        )
