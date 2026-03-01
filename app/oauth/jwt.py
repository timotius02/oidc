import base64
import hashlib
import uuid
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import serialization
from jose import jwt
from sqlalchemy.orm import Session

from app.oauth.errors import OAuthError, OAuthErrorCode
from app.oauth.models import RefreshToken

from ..config import settings


class RSAKey:
    def __init__(self, private_path: str, public_path: str, kid: str):
        self.kid = kid
        with open(private_path) as f:
            self.private_key = f.read()
        with open(public_path) as f:
            self.public_key = f.read()
        self._public_key_obj = None

    @property
    def public_key_obj(self):
        if self._public_key_obj is None:
            self._public_key_obj = serialization.load_pem_public_key(
                self.public_key.encode()
            )
        return self._public_key_obj

    def to_jwk(self) -> dict:
        from cryptography.hazmat.primitives.asymmetric import rsa

        pubkey = self.public_key_obj
        if not isinstance(pubkey, rsa.RSAPublicKey):
            raise ValueError("Only RSA keys are supported for JWK conversion")
        numbers = pubkey.public_numbers()

        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": base64.urlsafe_b64encode(numbers.n.to_bytes(256, byteorder="big"))
            .rstrip(b"=")
            .decode(),
            "e": base64.urlsafe_b64encode(numbers.e.to_bytes(4, byteorder="big"))
            .rstrip(b"=")
            .decode(),
        }


# Load current (signing) key
CURRENT_KEY = RSAKey(
    private_path=settings.PRIVATE_KEY_PATH,
    public_path=settings.PUBLIC_KEY_PATH,
    kid=settings.CURRENT_KEY_ID,
)

# Load next key (for rotation) if files exist
try:
    NEXT_KEY = RSAKey(
        private_path=settings.NEXT_PRIVATE_KEY_PATH,
        public_path=settings.NEXT_PUBLIC_KEY_PATH,
        kid=settings.NEXT_KEY_ID,
    )
    KEYS = [CURRENT_KEY, NEXT_KEY]
except FileNotFoundError:
    KEYS = [CURRENT_KEY]
    NEXT_KEY = None


def create_access_token(subject: str, audience: str, scope: str) -> tuple[str, str]:
    """
    Create a JWT access token with jti for identification.

    Returns:
        Tuple of (access_token, jti)
    """
    now = datetime.utcnow()
    jti = str(uuid.uuid4())

    payload = {
        "iss": settings.JWT_ISSUER,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(seconds=settings.ACCESS_TOKEN_EXPIRE_SECONDS),
        "scope": scope,
        "jti": jti,
    }

    headers = {"kid": CURRENT_KEY.kid}
    token = jwt.encode(
        payload, CURRENT_KEY.private_key, algorithm="RS256", headers=headers
    )
    return token, jti


def verify_token(token: str, audience: str) -> dict:
    # Try each key to find the correct one
    for key in KEYS:
        try:
            payload = jwt.decode(
                token,
                key.public_key,
                algorithms=["RS256"],
                audience=audience,
                issuer=settings.JWT_ISSUER,
            )
            return payload
        except jwt.JWTError:
            continue

    # If no key worked, raise an error
    raise jwt.JWTError("Token verification failed with all available keys")


def get_token_jti(token: str) -> str:
    """Extract jti from token without full validation (for revocation lookup)."""
    unverified = jwt.get_unverified_claims(token)
    return unverified.get("jti", "")


def compute_at_hash(access_token: str) -> str:
    """
    Compute at_hash claim for ID token per OIDC Core §3.2.2.9.

    SHA256 hash of the access token, left-truncated to 128 bits,
    then base64url-encoded.
    """
    sha256_hash = hashlib.sha256(access_token.encode()).digest()
    truncated = sha256_hash[:16]
    return base64.urlsafe_b64encode(truncated).rstrip(b"=").decode()


def create_id_token(
    subject: str,
    audience: str,
    nonce: str | None = None,
    access_token: str | None = None,
) -> str:
    """
    Create an OIDC ID token JWT.

    Required claims per OpenID Connect Core §2:
    - iss: Issuer identifier
    - sub: Subject identifier (user ID)
    - aud: Audience (client ID)
    - exp: Expiration time
    - iat: Issued at time
    - at_hash: Access token hash (if access_token provided)

    Optional claims:
    - nonce: Value to bind ID token to authentication request
    """
    now = datetime.utcnow()

    payload = {
        "iss": settings.JWT_ISSUER,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(seconds=settings.ID_TOKEN_EXPIRE_SECONDS),
    }

    if nonce:
        payload["nonce"] = nonce

    if access_token:
        payload["at_hash"] = compute_at_hash(access_token)

    headers = {"kid": CURRENT_KEY.kid}
    token = jwt.encode(
        payload, CURRENT_KEY.private_key, algorithm="RS256", headers=headers
    )
    return token


def revoke_token_chain(
    db: Session,
    refresh_token: RefreshToken,
    reason: str = "security_event",
) -> None:
    """
    Revoke a refresh token and all tokens in its chain.

    This is called when a replay attack is detected or user revokes access.

    Args:
        db: Database session
        refresh_token: The token to revoke
        reason: Reason for revocation
    """
    # Revoke current token
    refresh_token.is_active = "revoked"
    refresh_token.revoked_at = datetime.utcnow()
    refresh_token.revoked_reason = reason

    # Revoke all tokens in the chain (both parents and children)
    # Find parent chain
    current = refresh_token
    while current and current.parent_token_id:
        parent = (
            db.query(RefreshToken)
            .filter(RefreshToken.id == current.parent_token_id)
            .first()
        )
        if parent and parent.is_active == "true":
            parent.is_active = "revoked"
            parent.revoked_at = datetime.utcnow()
            parent.revoked_reason = f"chain_revocation: {reason}"
        current = parent

    # Find child chain
    current = refresh_token
    while current and current.replaced_by_token_id:
        child = (
            db.query(RefreshToken)
            .filter(RefreshToken.id == current.replaced_by_token_id)
            .first()
        )
        if child and child.is_active == "true":
            child.is_active = "revoked"
            child.revoked_at = datetime.utcnow()
            child.revoked_reason = f"chain_revocation: {reason}"
        current = child

    db.commit()


def rotate_refresh_token(
    db: Session,
    refresh_token: RefreshToken,
) -> str:
    """
    Rotate a refresh token - create new token and mark old as replaced.

    Per OAuth 2.0 Security BCP, refresh tokens should be single-use.

    Args:
        db: Database session
        refresh_token: The current valid refresh token

    Returns:
        New refresh token string
    """
    # Import here to avoid circular import (service.py imports from jwt.py)
    from app.oauth.service import create_refresh_token as service_create_refresh_token

    # Create new token using service layer (creates database record)
    new_token = service_create_refresh_token(
        db=db,
        user_id=str(refresh_token.user_id),
        client_id=refresh_token.client_id,
        scope=refresh_token.scope,
        parent_token_id=str(refresh_token.id),
    )

    # Mark old token as replaced
    refresh_token.is_active = "replaced"

    # Get the new token record to update replaced_by
    # The new token was just created in the database by service_create_refresh_token
    new_token_record = (
        db.query(RefreshToken).filter(RefreshToken.token == new_token).first()
    )
    refresh_token.replaced_by_token_id = new_token_record.id

    db.commit()

    return new_token


def validate_refresh_token(
    db: Session,
    token: str,
    client_id: str,
) -> RefreshToken:
    """
    Validate a refresh token.

    Args:
        db: Database session
        token: Refresh token string
        client_id: Client identifier for binding check

    Returns:
        RefreshToken if valid

    Raises:
        OAuthError if token is invalid, expired, or revoked
    """
    refresh_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()

    if not refresh_token:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_GRANT,
            description="Invalid refresh token",
        )

    # Check client binding
    if refresh_token.client_id != client_id:
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_GRANT,
            description="Refresh token client mismatch",
        )

    # Check expiration
    if refresh_token.expires_at < datetime.utcnow():
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_GRANT,
            description="Refresh token has expired",
        )

    # Check if active
    if refresh_token.is_active != "true":
        # Potential replay attack - revoke entire chain
        revoke_token_chain(db, refresh_token)
        raise OAuthError(
            error_code=OAuthErrorCode.INVALID_GRANT,
            description="Refresh token has been revoked",
        )

    return refresh_token
