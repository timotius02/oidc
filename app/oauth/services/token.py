import secrets
from datetime import UTC, datetime, timedelta
from typing import Optional

from fastapi import Depends
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.oauth.errors import OAuthError, OAuthErrorCode
from app.oauth.jwt import (
    create_access_token,
    create_id_token,
    revoke_token_chain,
    rotate_refresh_token,
    validate_refresh_token,
)
from app.oauth.models import AuthorizationCode, OAuthClient, RefreshToken
from app.oauth.pkce import verify_s256_code_verifier
from app.oauth.schemas import TokenRequest
from app.oauth.utils import create_token_response


class TokenService:
    def __init__(self, db: Session = Depends(get_db)):
        self.db = db

    def create_refresh_token(
        self,
        user_id: str,
        client_id: str,
        scope: str,
        parent_token_id: Optional[str] = None,
    ) -> str:
        """
        Create a refresh token for the OAuth flow.

        Args:
            user_id: User's UUID
            client_id: Client identifier
            scope: Granted scopes (space-separated)
            parent_token_id: Optional parent token ID for chain tracking

        Returns:
            The generated refresh token string
        """

        token = secrets.token_urlsafe(32)

        refresh_token = RefreshToken(
            token=token,
            user_id=user_id,
            client_id=client_id,
            scope=scope,
            expires_at=datetime.now(UTC).replace(tzinfo=None)
            + timedelta(seconds=settings.REFRESH_TOKEN_EXPIRE_SECONDS),
            parent_token_id=parent_token_id,
        )

        self.db.add(refresh_token)
        self.db.commit()

        return token

    def exchange_code_for_tokens(
        self,
        code: str,
        client: OAuthClient,
        redirect_uri: Optional[str] = None,
        code_verifier: Optional[str] = None,
    ) -> tuple[str, str | None, str, str]:
        """
        Exchange an authorization code for access token and refresh tokens.

        Args:
            code: Authorization code
            client: The OAuthClient object
            redirect_uri: Must match the redirect_uri from authorization request
            code_verifier: PKCE code verifier (required if code_challenge was used)

        Returns:
            Tuple of (access_token, id_token, refresh_token, granted_scope)

        Raises:
            OAuthError if code is invalid, expired, or client authentication fails
        """
        # Find the authorization code
        auth_code = (
            self.db.query(AuthorizationCode)
            .filter(AuthorizationCode.code == code)
            .first()
        )

        if not auth_code:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_GRANT,
                description="The authorization code is invalid or has been used",
            )

        if auth_code.expires_at < datetime.now(UTC).replace(tzinfo=None):
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_GRANT,
                description="The authorization code has expired",
            )

        # Validate client_id matches
        if auth_code.client_id != client.client_id:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_GRANT,
                description="Client ID mismatch",
            )
        # Validate redirect_uri matches if it was provided in the authorization request
        if auth_code.redirect_uri:
            if not redirect_uri:
                raise OAuthError(
                    error_code=OAuthErrorCode.INVALID_GRANT,
                    description="Missing required parameter: redirect_uri",
                )
            if auth_code.redirect_uri != redirect_uri:
                raise OAuthError(
                    error_code=OAuthErrorCode.INVALID_GRANT,
                    description="Redirect URI mismatch",
                )

        # PKCE validation
        if auth_code.code_challenge:
            if not code_verifier:
                raise OAuthError(
                    error_code=OAuthErrorCode.INVALID_GRANT,
                    description="Missing code_verifier for PKCE",
                )

            if not (43 <= len(code_verifier) <= 128):
                raise OAuthError(
                    error_code=OAuthErrorCode.INVALID_GRANT,
                    description="Code_verifier must be between 43 and 128 characters",
                )

            if not verify_s256_code_verifier(code_verifier, auth_code.code_challenge):
                raise OAuthError(
                    error_code=OAuthErrorCode.INVALID_GRANT,
                    description="Invalid code_verifier",
                )

        # Create access token
        access_token, _ = create_access_token(
            subject=str(auth_code.user_id),
            audience=auth_code.client_id,
            scope=auth_code.scope,
        )

        # Create ID token if openid scope is requested
        id_token = None
        if auth_code.scope and "openid" in auth_code.scope.split():
            id_token = create_id_token(
                subject=str(auth_code.user_id),
                audience=auth_code.client_id,
                nonce=auth_code.nonce,
                access_token=access_token,
            )

        # Create refresh token
        refresh_token = self.create_refresh_token(
            user_id=auth_code.user_id,
            client_id=auth_code.client_id,
            scope=auth_code.scope,
        )

        # Delete the code (single use)
        self.db.delete(auth_code)
        self.db.commit()

        return access_token, id_token, refresh_token, auth_code.scope

    def handle_authorization_code_grant(
        self,
        request_data: TokenRequest,
        client: OAuthClient,
    ):
        """Handle authorization_code grant type."""
        if not request_data.code:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_REQUEST,
                description="Missing required parameter: code",
            )

        # Exchange code for tokens
        access_token, id_token, refresh_token, granted_scope = (
            self.exchange_code_for_tokens(
                code=request_data.code,
                client=client,
                redirect_uri=request_data.redirect_uri,
                code_verifier=request_data.code_verifier,
            )
        )

        response_content = {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            "refresh_token": refresh_token,
            "scope": granted_scope,
        }

        if id_token:
            response_content["id_token"] = id_token

        return create_token_response(content=response_content)

    def handle_refresh_token_grant(
        self,
        request_data: TokenRequest,
        client: OAuthClient,
    ):
        """
        Handle refresh_token grant type per RFC 6749 §6.
        """
        if not request_data.refresh_token:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_REQUEST,
                description="Missing required parameter: refresh_token",
            )

        # Validate refresh token
        token_record = validate_refresh_token(
            db=self.db,
            token=request_data.refresh_token,
            client_id=client.client_id,
        )

        # Handle scope - must be subset of original scope
        if request_data.scope:
            original_scopes = set(token_record.scope.split())
            requested_scopes = set(request_data.scope.split())
            if not requested_scopes.issubset(original_scopes):
                raise OAuthError(
                    error_code=OAuthErrorCode.INVALID_SCOPE,
                    description="Requested scope exceeds original grant",
                )
            final_scope = request_data.scope
        else:
            final_scope = token_record.scope

        # Rotate refresh token
        new_refresh_token = rotate_refresh_token(self.db, token_record)

        # Create new access token
        access_token, _ = create_access_token(
            subject=str(token_record.user_id),
            audience=client.client_id,
            scope=final_scope,
        )

        return create_token_response(
            content={
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_SECONDS,
                "refresh_token": new_refresh_token,
                "scope": final_scope,
            }
        )

    def revoke_token(
        self,
        token: str,
        token_type_hint: Optional[str] = None,
        client_id: Optional[str] = None,
    ):
        """
        Revoke an access or refresh token per RFC 7009.
        """
        # Try to find the token in refresh tokens
        refresh_token = (
            self.db.query(RefreshToken).filter(RefreshToken.token == token).first()
        )

        if refresh_token:
            if refresh_token.client_id == client_id:
                revoke_token_chain(self.db, refresh_token, reason="user_revoked")
            return
