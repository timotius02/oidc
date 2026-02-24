from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.oauth.errors import OAuthErrorCode, create_authorization_error_response
from app.oauth.service import create_authorization_code, exchange_code_for_token
from app.oauth.utils import get_current_user

router = APIRouter(prefix="/oauth", tags=["oauth"])


@router.get("/authorize")
def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str,
    state: str,
    db: Session = Depends(get_db),
):
    if response_type != "code":
        return create_authorization_error_response(
            redirect_uri=redirect_uri,
            error_code=OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE,
            description="The authorization server only supports 'code' response type",
            state=state
        )
    user = get_current_user(request, db)
    if not user:
        # Redirect to login with "next" parameter back to /authorize
        login_url = f"/auth/login?next={request.url}"
        return RedirectResponse(login_url)

    # Show consent screen (skipped here, could be a template)
    # For now we assume consent is granted automatically

    # Create authorization code tied to this user & client
    code = create_authorization_code(db, user.id, client_id)

    # Redirect back to client
    redirect_with_code = f"{redirect_uri}?code={code}&state={state}"
    return RedirectResponse(redirect_with_code)

@router.get("/consent")
def consent(request: Request):

    params = request.session.get("authorize_params")

    if not params:
        raise HTTPException(400, "Missing authorization request")

    return {
        "client_id": params["client_id"],
        "scope": params["scope"],
    }

@router.post("/consent/approve")
def approve_consent(
    request: Request,
    db: Session = Depends(get_db),
):

    params = request.session.get("authorize_params")

    user_id = request.session.get("user_id")

    if not params or not user_id:
        raise HTTPException(400)

    code = create_authorization_code(
        db=db,
        user_id=user_id,
        client_id=params["client_id"],
        redirect_uri=params["redirect_uri"],
    )

    redirect_url = (
        f"{params['redirect_uri']}?code={code}&state={params['state']}"
    )

    request.session.pop("authorize_params", None)

    return RedirectResponse(redirect_url)


@router.post("/consent/deny")
def deny_consent(request: Request):

    params = request.session.get("authorize_params")

    redirect_url = (
        f"{params['redirect_uri']}?error=access_denied"
    )

    request.session.pop("authorize_params", None)

    return RedirectResponse(redirect_url)


@router.post("/token")
def token(
    code: str,
    db: Session = Depends(get_db),
):
    access_token = exchange_code_for_token(db, code)

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }