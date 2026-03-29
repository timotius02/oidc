import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Optional

from jose import jwt


def compute_at_hash(access_token: str) -> str:
    """
    Compute the access token hash as per RFC 9449 Section 7.1.

    The hash is the left-most half of the hash computed over the ASCII
    representation of the access token value, encoded as base64url.
    """
    # Use SHA-256 for hashing
    hash_input = access_token.encode("ascii")
    hash_digest = hashlib.sha256(hash_input).digest()

    # Take the left-most half (128 bits for SHA-256)
    half_hash = hash_digest[: len(hash_digest) // 2]

    # Base64url encode without padding
    return base64.urlsafe_b64encode(half_hash).rstrip(b"=").decode()


def compute_jwk_thumbprint(jwk: dict) -> str:
    """
    Compute the JWK thumbprint as per RFC 7638.

    This is a deterministic hash of a JWK used for the cnf claim.
    """
    # RFC 7638 defines the thumbprint as a hash of the JWK with
    # fields in a specific order: kty, n, e for RSA keys
    thumbprint_fields = {}
    for key in ["kty", "n", "e", "crv", "x", "y"]:
        if key in jwk:
            thumbprint_fields[key] = jwk[key]

    # Sort keys for deterministic output
    thumbprint_json = json.dumps(
        thumbprint_fields, sort_keys=True, separators=(",", ":")
    )
    thumbprint_bytes = thumbprint_json.encode("utf-8")

    # SHA-256 hash
    hash_digest = hashlib.sha256(thumbprint_bytes).digest()

    # Base64url encode without padding
    return base64.urlsafe_b64encode(hash_digest).rstrip(b"=").decode()


def load_jwk(jwk_input: str | dict) -> dict:
    """
    Load a JWK from string or dict format.

    Accepts:
    - A JWK dict (as returned by jose_jwk)
    - A JSON string of a JWK
    """
    if isinstance(jwk_input, dict):
        return jwk_input

    return json.loads(jwk_input)


def get_public_key_from_jwk(jwk: dict):
    """Load a public key from a JWK."""
    if jwk.get("kty") == "EC":
        x = int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "="), byteorder="big")
        y = int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "="), byteorder="big")

        from cryptography.hazmat.primitives.asymmetric import ec

        public_key = ec.EllipticCurvePublicKey(ec.SECP256R1(), x, y)
        return public_key
    elif jwk.get("kty") == "RSA":
        n = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "="), byteorder="big")
        e = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "="), byteorder="big")

        from cryptography.hazmat.primitives.asymmetric import rsa

        public_key = rsa.RSAPublicKey(n, e)
        return public_key

    raise ValueError(f"Unsupported key type: {jwk.get('kty')}")


def verify_dpop_proof(
    proof: str,
    audience: str,
    method: str = "POST",
    uri: str = "https://authorization-server.example.com/oauth/token",
    access_token: Optional[str] = None,
) -> tuple[bool, dict]:
    """
    Verify a DPoP proof JWT as per RFC 9449 Section 7.2.

    Returns:
        Tuple of (is_valid, public_key_jwk)

    Raises:
        jwt.JWTError if the proof is invalid
    """
    # Extract public key from proof header (jwk claim in header)
    unverified_header = jwt.get_unverified_header(proof)
    public_jwk = unverified_header.get("jwk")

    if not public_jwk:
        raise jwt.JWTError("DPoP proof missing jwk header")

    public_key = get_public_key_from_jwk(public_jwk)

    if public_jwk.get("kty") == "EC":
        alg = ["ES256"]
    elif public_jwk.get("kty") == "RSA":
        alg = ["RS256"]
    else:
        raise ValueError(f"Unsupported key type: {public_jwk.get('kty')}")

    try:
        payload = jwt.decode(proof, public_key, algorithms=alg, audience=audience)
    except jwt.JWTError as e:
        raise jwt.JWTError(f"DPoP proof verification failed: {e}")

    if payload.get("htm") != method:
        raise jwt.JWTError(f"Method mismatch")
    if payload.get("htu") != uri:
        raise jwt.JWTError(f"URL mismatch")
    if access_token:
        expected_at_hash = compute_at_hash(access_token)
        if payload.get("ath") != expected_at_hash:
            raise jwt.JWTError("Access token hash mismatch")

    return True, public_jwk


def verify_dpop_proof_for_resource(
    dpop_header: str,
    access_token: str,
    public_key_jwk: str | dict,
) -> bool:
    """
    Verify a DPoP proof for resource server access.

    Args:
        dpop_header: The DPoP header value from the request
        access_token: The access token being used
        public_key_jwk: The client's public key in JWK format

    Returns:
        True if verification succeeds
    """
    public_jwk = load_jwk(public_key_jwk)

    if public_jwk.get("kty") == "EC":
        alg = ["ES256"]
    elif public_jwk.get("kty") == "RSA":
        alg = ["RS256"]
    else:
        raise ValueError(f"Unsupported key type: {public_jwk.get('kty')}")

    public_key = get_public_key_from_jwk(public_jwk)

    # Decode the DPoP proof (but don't verify audience for resource server)
    try:
        unverified = jwt.get_unverified_claims(dpop_header)

        # Verify using public key
        payload = jwt.decode(
            dpop_header,
            public_key,
            algorithms=alg,
            options={"verify_aud": False},
        )
    except jwt.JWTError as e:
        raise jwt.JWTError(f"DPoP proof verification failed: {e}")

    # Verify ath matches the access token being used
    expected_at_hash = compute_at_hash(access_token)
    if unverified.get("ath") != expected_at_hash:
        raise jwt.JWTError("Access token hash (ath) mismatch")

    # Verify the timestamp is not too old (max 60 seconds)
    iat = unverified.get("iat")
    if iat:
        now = datetime.now(UTC).timestamp()
        if abs(now - iat) > 60:
            raise jwt.JWTError("DPoP proof timestamp too old")

    return True
