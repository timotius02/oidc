import uuid

from fastapi import Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.oauth.errors import OAuthError, OAuthErrorCode
from app.oauth.jwt import verify_token


class UserInfoService:
    def __init__(self, db: Session = Depends(get_db)):
        self.db = db

    def get_userinfo_claims(
        self,
        access_token: str,
        dpop_header: str | None = None,
        method: str = "GET",
        uri: str = "",
    ) -> dict:
        """
        Get user claims from UserInfo endpoint.

        Args:
            access_token: Bearer or DPoP-bound token from Authorization header
            dpop_header: DPoP proof JWT from the DPoP request header, if present
            method: HTTP method of the request (for DPoP proof validation)
            uri: Full request URI (for DPoP proof validation)

        Returns:
            Dictionary of claims based on granted scopes

        Raises:
            OAuthError: If invalid token, user not found, or DPoP proof missing/invalid
        """
        from jose import jwt as jose_jwt

        try:
            unverified = jose_jwt.get_unverified_claims(access_token)
            audience = unverified.get("aud")
        except Exception:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_GRANT,
                description="Invalid token format",
            )

        if not audience:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_GRANT,
                description="Invalid token: missing audience",
            )

        try:
            token_payload = verify_token(access_token, audience)
        except Exception:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_GRANT,
                description="Invalid or expired access token",
            )

        cnf = token_payload.get("cnf")
        if cnf:
            if not dpop_header:
                raise OAuthError(
                    error_code=OAuthErrorCode.INVALID_GRANT,
                    description="DPoP proof required for DPoP-bound token",
                )
            try:
                from app.oauth.dpop import verify_dpop_proof_for_resource

                verify_dpop_proof_for_resource(
                    dpop_header=dpop_header,
                    access_token=access_token,
                    public_key_jwk=cnf["jwk"],
                    method=method,
                    uri=uri,
                )
            except Exception as e:
                raise OAuthError(
                    error_code=OAuthErrorCode.INVALID_DPOP_PROOF,
                    description=f"Invalid DPoP proof: {e}",
                )

        scope = token_payload.get("scope", "")
        granted_scopes = set(scope.split()) if scope else set()
        if "openid" not in granted_scopes:
            raise OAuthError(
                error_code=OAuthErrorCode.INSUFFICIENT_SCOPE,
                description="Access token not issued for UserInfo scope",
            )

        subject = token_payload.get("sub")
        if not subject:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_GRANT,
                description="Invalid token: missing subject",
            )

        try:
            subject_uuid = uuid.UUID(subject)
        except ValueError:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_GRANT,
                description="Invalid token: invalid subject format",
            )

        user = self.db.query(User).filter(User.id == subject_uuid).first()

        if not user:
            raise OAuthError(
                error_code=OAuthErrorCode.INVALID_GRANT,
                description="User not found",
            )

        claims = {"sub": str(user.id)}

        if "profile" in granted_scopes:
            if user.name:
                claims["name"] = user.name
            if user.given_name:
                claims["given_name"] = user.given_name
            if user.family_name:
                claims["family_name"] = user.family_name

        if "email" in granted_scopes:
            claims["email"] = user.email

        return claims
