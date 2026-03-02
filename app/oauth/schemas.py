from typing import Optional

from fastapi import Form
from pydantic import BaseModel

from app.oauth.constants import CodeChallengeMethod, GrantType, ResponseType


class AuthorizationRequest(BaseModel):
    client_id: str
    redirect_uri: Optional[str] = None
    response_type: ResponseType
    scope: Optional[str] = None
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[CodeChallengeMethod] = None
    nonce: Optional[str] = None


class TokenRequest(BaseModel):
    grant_type: GrantType
    code: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    redirect_uri: Optional[str] = None
    code_verifier: Optional[str] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None

    @classmethod
    def as_form(
        cls,
        grant_type: str = Form(...),
        code: Optional[str] = Form(None),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
        redirect_uri: Optional[str] = Form(None),
        code_verifier: Optional[str] = Form(None),
        refresh_token: Optional[str] = Form(None),
        scope: Optional[str] = Form(None),
    ):
        return cls(
            grant_type=grant_type,
            code=code,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            refresh_token=refresh_token,
            scope=scope,
        )


class RevocationRequest(BaseModel):
    token: str
    token_type_hint: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None

    @classmethod
    def as_form(
        cls,
        token: str = Form(...),
        token_type_hint: Optional[str] = Form(None),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
    ):
        return cls(
            token=token,
            token_type_hint=token_type_hint,
            client_id=client_id,
            client_secret=client_secret,
        )
