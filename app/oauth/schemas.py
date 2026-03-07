from typing import Optional

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


class RevocationRequest(BaseModel):
    token: str
    token_type_hint: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
