import secrets

from fastapi import Form, HTTPException, Request, status


def generate_csrf_token(request: Request) -> str:
    """
    Generate a CSRF token and store it in the session.
    """
    token = secrets.token_urlsafe(32)
    request.session["csrf_token"] = token
    return token


async def verify_csrf(request: Request, csrf_token: str = Form(...)):
    """
    FastAPI dependency to verify the CSRF token from a form field.

    Raises:
        HTTPException: If the token is missing or invalid.
    """
    session_token = request.session.get("csrf_token")
    if not session_token or not secrets.compare_digest(session_token, csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token validation failed"
        )
