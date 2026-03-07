import secrets
from datetime import UTC, datetime, timedelta
from typing import Dict, List, Optional

from fastapi import Depends
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.oauth.errors import OAuthError, OAuthErrorCode
from app.oauth.models import AuthorizationCode, OAuthClient
from app.oauth.services.client import ClientService

# Scope descriptions for consent screen
SCOPE_DESCRIPTIONS: Dict[str, str] = {
    "openid": "Authenticate your identity",
    "profile": "Access your profile information (name, picture)",
    "email": "Access your email address",
    "offline_access": "Access your data even when you're offline",
}


class AuthorizationService:
    def __init__(self, db: Session = Depends(get_db)):
        self.db = db
        self.client_service = ClientService(db)

    def get_scope_descriptions(self, scopes: List[str]) -> List[Dict[str, str]]:
        """
        Get human-readable descriptions for a list of scopes.

        Args:
            scopes: List of scope strings

        Returns:
            List of dicts with 'name' and 'description' keys
        """
        return [
            {
                "name": scope,
                "description": SCOPE_DESCRIPTIONS.get(scope, f"Access {scope}"),
            }
            for scope in scopes
        ]

    def validate_authorization_request(
        self,
        client: OAuthClient,
        response_type: Optional[str],
        scope: Optional[str],
        code_challenge: Optional[str],
        code_challenge_method: Optional[str],
    ) -> str:
        """
        Validate strictly OAuth-related parameters for authorization.

        Args:
            client: The validated OAuthClient
            response_type: The requested response_type
            scope: The requested scope(s)
            code_challenge: PKCE code challenge
            code_challenge_method: PKCE method

        Returns:
            The resolved scope string (defaults to client scopes if none provided)

        Raises:
            OAuthError: For parameters that should result in a redirect with error
        """
        # 1. Validate response_type
        if not response_type:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_REQUEST,
                description="Response_type is required",
            )

        if response_type != "code":
            raise OAuthError(
                error_code=OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE,
                description="Only 'code' response type is supported",
            )

        # 2. Validate PKCE (Enforced S256)
        if not code_challenge:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_REQUEST,
                description="Code_challenge is required",
            )

        if code_challenge_method != "S256":
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_REQUEST,
                description="Code_challenge_method must be 'S256'",
            )

        # 3. Validate Scope
        effective_scope = scope or client.scopes
        allowed_scopes = set(client.scopes.split())
        requested = set(effective_scope.split())

        if not requested.issubset(allowed_scopes):
            invalid_scopes = requested - allowed_scopes
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_SCOPE,
                description=f"Requested scopes not allowed: {' '.join(invalid_scopes)}",
            )

        return effective_scope

    def prepare_consent_view_data(
        self, client_id: str, scope: str
    ) -> tuple[OAuthClient, List[Dict[str, str]]]:
        """
        Gather client and scope details for the consent screen.

        Returns:
            Tuple of (OAuthClient, list of scope descriptions)
        """
        client = self.client_service.get_client_by_id(client_id)
        if not client:
            raise ValueError("Invalid client")

        scopes = scope.split()
        scope_descriptions = self.get_scope_descriptions(scopes)

        return client, scope_descriptions

    def create_authorization_code(
        self,
        user_id: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> str:
        """
        Create an authorization code for the OAuth flow.

        Args:
            user_id: User's UUID
            client_id: Client identifier
            redirect_uri: Redirect URI for validation at token exchange
            scope: Granted scopes (space-separated)
            code_challenge: PKCE code challenge (required if PKCE is enforced)
            code_challenge_method: PKCE method (e.g., "S256")
            nonce: Optional nonce for OIDC id_token

        Returns:
            The generated authorization code string
        """
        code = secrets.token_urlsafe(32)

        auth_code = AuthorizationCode(
            code=code,
            user_id=user_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=datetime.now(UTC).replace(tzinfo=None)
            + timedelta(seconds=settings.CODE_EXPIRY_SECONDS),
        )

        self.db.add(auth_code)
        self.db.commit()

        return code
