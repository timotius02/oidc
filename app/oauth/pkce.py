"""
PKCE (Proof Key for Code Exchange) implementation per RFC 7636.

This module provides functions for PKCE code challenge verification
as specified in RFC 7636 Section 4.6.

References:
- RFC 7636: https://tools.ietf.org/html/rfc7636
"""

import base64
import hashlib
import secrets


def verify_s256_code_verifier(code_verifier: str, code_challenge: str) -> bool:
    """
    Verify a code_verifier against a code_challenge using S256 method.

    Per RFC 7636 Section 4.6:
    - code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))

    Args:
        code_verifier: The code verifier string sent by the client
        code_challenge: The stored code challenge from authorization request

    Returns:
        True if verification succeeds, False otherwise

    Example:
        >>> # Client generates verifier and challenge
        >>> verifier = secrets.token_urlsafe(32)
        >>> challenge = base64.urlsafe_b64encode(
        ...     hashlib.sha256(verifier.encode()).digest()
        ... ).decode().rstrip('=')
        >>> verify_s256_code_verifier(verifier, challenge)
        True
    """
    # Compute SHA256 hash of the code_verifier
    sha256_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()

    # Base64url encode without padding
    b64_encoded = base64.urlsafe_b64encode(sha256_hash).decode("ascii")
    computed_challenge = b64_encoded.rstrip("=")

    # Use constant-time comparison to prevent timing attacks.
    # A timing attack exploits minute differences in comparison execution time.
    # If we used `==`, the comparison would short-circuit on first mismatched byte,
    # revealing which characters are correct. An attacker could measure response
    # times to guess the code_verifier byte-by-byte, compromising the PKCE flow.
    return secrets.compare_digest(computed_challenge, code_challenge)
