from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.oauth.service import create_authorization_code, exchange_code_for_token

router = APIRouter(prefix="/oauth", tags=["oauth"])

@router.get("/authorize")
def authorize(
    client_id: str,
    redirect_uri: str,
    user_id: str,
    db: Session = Depends(get_db),
):
    code = create_authorization_code(db, user_id, client_id)

    return {
        "redirect_to": f"{redirect_uri}?code={code}"
    }

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