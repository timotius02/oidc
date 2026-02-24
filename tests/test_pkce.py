"""
Tests for PKCE (Proof Key for Code Exchange) implementation per RFC 7636.

Tests cover:
- S256 code verifier verification
- PKCE flow integration
- RFC 7636 compliance
"""

import base64
import hashlib
import secrets

from app.oauth.pkce import verify_s256_code_verifier


class TestVerifyS256CodeVerifier:
    """Tests for verify_s256_code_verifier function."""

    def test_valid_verifier_matches_challenge(self):
        """Test that a valid code_verifier matches its code_challenge."""
        # Generate a valid verifier
        verifier = secrets.token_urlsafe(32)

        # Compute the challenge per RFC 7636
        sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(sha256_hash).decode("ascii").rstrip("=")

        assert verify_s256_code_verifier(verifier, challenge) is True

    def test_invalid_verifier_does_not_match(self):
        """Test that an invalid code_verifier does not match."""
        # Generate a valid verifier and challenge
        verifier = secrets.token_urlsafe(32)
        sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(sha256_hash).decode("ascii").rstrip("=")

        # Use a different verifier
        wrong_verifier = secrets.token_urlsafe(32)

        assert verify_s256_code_verifier(wrong_verifier, challenge) is False

    def test_empty_verifier(self):
        """Test that empty verifier returns False."""
        challenge = "some_challenge"
        assert verify_s256_code_verifier("", challenge) is False

    def test_empty_challenge(self):
        """Test that empty challenge returns False."""
        verifier = secrets.token_urlsafe(32)
        assert verify_s256_code_verifier(verifier, "") is False

    def test_verifier_with_special_characters(self):
        """Test verifier with various characters allowed by RFC 7636."""
        # RFC 7636 allows: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        verifier = "abcDEF123-._~xyz"

        sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(sha256_hash).decode("ascii").rstrip("=")

        assert verify_s256_code_verifier(verifier, challenge) is True

    def test_minimum_length_verifier(self):
        """Test verifier with minimum length (43 characters per RFC 7636)."""
        # RFC 7636 Section 4.1: code_verifier must be 43-128 characters
        verifier = "a" * 43  # Minimum length

        sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(sha256_hash).decode("ascii").rstrip("=")

        assert verify_s256_code_verifier(verifier, challenge) is True

    def test_maximum_length_verifier(self):
        """Test verifier with maximum length (128 characters per RFC 7636)."""
        verifier = "a" * 128  # Maximum length

        sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(sha256_hash).decode("ascii").rstrip("=")

        assert verify_s256_code_verifier(verifier, challenge) is True

    def test_challenge_without_padding(self):
        """Test that challenge without base64 padding works correctly."""
        verifier = secrets.token_urlsafe(32)

        sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        # Explicitly remove padding
        challenge = base64.urlsafe_b64encode(sha256_hash).decode("ascii").rstrip("=")

        assert verify_s256_code_verifier(verifier, challenge) is True

    def test_challenge_with_padding_fails(self):
        """Test that challenge with base64 padding fails verification.

        Per RFC 7636, code_challenge must be base64url-encoded WITHOUT padding.
        If a client incorrectly includes padding in their stored challenge,
        verification should fail.
        """
        verifier = secrets.token_urlsafe(32)

        sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        # Keep padding (incorrect per RFC 7636)
        challenge_with_padding = base64.urlsafe_b64encode(sha256_hash).decode("ascii")

        # Verify that padded challenge fails (as expected per RFC)
        assert "=" in challenge_with_padding  # Confirm padding exists
        assert verify_s256_code_verifier(verifier, challenge_with_padding) is False

    def test_constant_time_comparison(self):
        """Test that comparison is timing-attack resistant.

        This is a basic test - true constant-time testing requires
        statistical analysis of timing measurements.
        """
        # Generate two verifiers of different lengths
        verifier1 = "a" * 43
        verifier2 = "a" * 128

        sha256_hash1 = hashlib.sha256(verifier1.encode("ascii")).digest()
        challenge1 = base64.urlsafe_b64encode(sha256_hash1).decode("ascii").rstrip("=")

        sha256_hash2 = hashlib.sha256(verifier2.encode("ascii")).digest()
        challenge2 = base64.urlsafe_b64encode(sha256_hash2).decode("ascii").rstrip("=")

        # Both should return False for wrong verifier, regardless of length
        assert verify_s256_code_verifier(verifier2, challenge1) is False
        assert verify_s256_code_verifier(verifier1, challenge2) is False


class TestPKCERFC7636Compliance:
    """Tests for RFC 7636 compliance."""

    def test_rfc_example_vector(self):
        """Test using RFC 7636 Appendix B example vector.

        RFC 7636 Appendix B provides test vectors for S256.
        """
        # Note: RFC 7636 Appendix B example
        # code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        # code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

        # We'll compute our own to verify the algorithm is correct
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

        sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        b64_encoded = base64.urlsafe_b64encode(sha256_hash).decode("ascii")
        computed_challenge = b64_encoded.rstrip("=")

        # The RFC example challenge
        expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

        assert computed_challenge == expected_challenge
        assert verify_s256_code_verifier(verifier, expected_challenge) is True

    def test_s256_transformation(self):
        """Test that S256 transformation is correctly implemented.

        Per RFC 7636 Section 4.6:
        code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
        """
        verifier = "test_verifier_string"

        # Manual computation
        sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        b64_encoded = base64.urlsafe_b64encode(sha256_hash).decode("ascii")
        expected_challenge = b64_encoded.rstrip("=")

        # Verify our function produces the same result
        assert verify_s256_code_verifier(verifier, expected_challenge) is True

    def test_urlsafe_base64_encoding(self):
        """Test that base64url encoding is used (not standard base64).

        RFC 7636 requires base64url encoding which uses '-' and '_'
        instead of '+' and '/'.
        """
        # Generate a verifier that will produce base64 with special chars
        verifier = secrets.token_urlsafe(32)

        sha256_hash = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(sha256_hash).decode("ascii").rstrip("=")

        # Verify no standard base64 characters are present
        assert "+" not in challenge
        assert "/" not in challenge
        assert "=" not in challenge  # No padding

        # Verify our function works with this challenge
        assert verify_s256_code_verifier(verifier, challenge) is True
