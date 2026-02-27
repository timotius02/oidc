from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.models.user import User


def get_current_user(request: Request, db: Session):
    user_id = request.session.get("user_id")
    if not user_id:
        return None

    return db.query(User).filter(User.id == user_id).first()


def create_token_response(content: dict) -> JSONResponse:
    """
    Create a JSON response for token requests with RFC 6749 compliant headers.

    As per RFC 6749 Section 5.1:
    "The authorization server MUST include the HTTP "Cache-Control" response header
    field [RFC2616] with a value of "no-store" in any response containing tokens,
    credentials, or other sensitive information, as well as the "Pragma" response
    header field [RFC2616] with a value of "no-cache"."
    """
    return JSONResponse(
        content=content,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )
