"""
Unit tests for OAuth 2.0 RFC 6749 error handling.

Tests cover:
- OAuthErrorCode enum values
- OAuthError exception
- create_authorization_error_response function
- create_token_error_response function
"""

from urllib.parse import parse_qs, urlparse

from app.oauth.errors import (
    OAuthError,
    OAuthErrorCode,
    create_authorization_error_response,
    create_token_error_response,
)


class TestOAuthErrorCode:
    """Tests for OAuthErrorCode enum."""

    def test_authorization_endpoint_error_codes(self):
        """Test that all authorization endpoint error codes are defined."""
        assert OAuthErrorCode.INVALID_REQUEST.value == "invalid_request"
        assert OAuthErrorCode.UNAUTHORIZED_CLIENT.value == "unauthorized_client"
        assert OAuthErrorCode.ACCESS_DENIED.value == "access_denied"
        assert (
            OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE.value
            == "unsupported_response_type"
        )
        assert OAuthErrorCode.INVALID_SCOPE.value == "invalid_scope"
        assert OAuthErrorCode.SERVER_ERROR.value == "server_error"
        assert OAuthErrorCode.TEMPORARILY_UNAVAILABLE.value == "temporarily_unavailable"

    def test_token_endpoint_error_codes(self):
        """Test that all token endpoint error codes are defined."""
        assert OAuthErrorCode.INVALID_CLIENT.value == "invalid_client"
        assert OAuthErrorCode.INVALID_GRANT.value == "invalid_grant"
        assert OAuthErrorCode.UNSUPPORTED_GRANT_TYPE.value == "unsupported_grant_type"


class TestOAuthError:
    """Tests for OAuthError exception."""

    def test_oauth_error_with_description(self):
        """Test OAuthError with description."""
        error = OAuthError(
            error_code=OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE,
            description="Only 'code' response type is supported",
        )
        assert error.error_code == OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE
        assert error.description == "Only 'code' response type is supported"
        assert str(error) == "Only 'code' response type is supported"

    def test_oauth_error_without_description(self):
        """Test OAuthError without description uses error code value."""
        error = OAuthError(error_code=OAuthErrorCode.INVALID_REQUEST)
        assert error.error_code == OAuthErrorCode.INVALID_REQUEST
        assert error.description is None
        assert str(error) == "invalid_request"

    def test_oauth_error_with_all_fields(self):
        """Test OAuthError with all fields."""
        error = OAuthError(
            error_code=OAuthErrorCode.INVALID_REQUEST,
            description="Missing required parameter",
            uri="https://example.com/errors#invalid_request",
            state="abc123",
        )
        assert error.error_code == OAuthErrorCode.INVALID_REQUEST
        assert error.description == "Missing required parameter"
        assert error.uri == "https://example.com/errors#invalid_request"
        assert error.state == "abc123"


class TestCreateAuthorizationErrorResponse:
    """Tests for create_authorization_error_response function."""

    def test_basic_error_response(self):
        """Test basic error response with required parameters only."""
        response = create_authorization_error_response(
            redirect_uri="https://client.example.com/callback",
            error_code=OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE,
        )

        assert response.status_code == 302

        parsed = urlparse(response.headers["location"])
        query_params = parse_qs(parsed.query)

        assert parsed.scheme == "https"
        assert parsed.netloc == "client.example.com"
        assert parsed.path == "/callback"
        assert query_params["error"] == ["unsupported_response_type"]

    def test_error_response_with_description(self):
        """Test error response with description."""
        response = create_authorization_error_response(
            redirect_uri="https://client.example.com/callback",
            error_code=OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE,
            description="Only 'code' response type is supported",
        )

        parsed = urlparse(response.headers["location"])
        query_params = parse_qs(parsed.query)

        assert query_params["error"] == ["unsupported_response_type"]
        assert query_params["error_description"] == [
            "Only 'code' response type is supported"
        ]

    def test_error_response_with_state(self):
        """Test error response includes state parameter."""
        response = create_authorization_error_response(
            redirect_uri="https://client.example.com/callback",
            error_code=OAuthErrorCode.INVALID_REQUEST,
            state="xyz123",
        )

        parsed = urlparse(response.headers["location"])
        query_params = parse_qs(parsed.query)

        assert query_params["error"] == ["invalid_request"]
        assert query_params["state"] == ["xyz123"]

    def test_error_response_with_all_parameters(self):
        """Test error response with all parameters."""
        response = create_authorization_error_response(
            redirect_uri="https://client.example.com/callback",
            error_code=OAuthErrorCode.ACCESS_DENIED,
            description="User denied access",
            state="abc456",
        )

        parsed = urlparse(response.headers["location"])
        query_params = parse_qs(parsed.query)

        assert query_params["error"] == ["access_denied"]
        assert query_params["error_description"] == ["User denied access"]
        assert query_params["state"] == ["abc456"]

    def test_error_response_url_encoding(self):
        """Test that special characters are URL encoded."""
        response = create_authorization_error_response(
            redirect_uri="https://client.example.com/callback",
            error_code=OAuthErrorCode.INVALID_REQUEST,
            description="Missing required parameter: client_id",
        )

        # The description should be URL encoded
        assert (
            "Missing%20required%20parameter%3A%20client_id"
            in response.headers["location"]
        )

    def test_error_response_with_existing_query_params(self):
        """Test error response when redirect_uri has existing query params."""
        response = create_authorization_error_response(
            redirect_uri="https://client.example.com/callback?foo=bar",
            error_code=OAuthErrorCode.INVALID_REQUEST,
        )

        # Should use & instead of ? for appending error params
        assert response.headers["location"].startswith(
            "https://client.example.com/callback?foo=bar&"
        )
        assert "error=invalid_request" in response.headers["location"]


class TestCreateTokenErrorResponse:
    """Tests for create_token_error_response function."""

    def test_basic_token_error_response(self):
        """Test basic token error response with required parameters only."""
        response = create_token_error_response(error_code=OAuthErrorCode.INVALID_GRANT)

        assert response.status_code == 400
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Pragma"] == "no-cache"

    def test_token_error_response_with_description(self):
        """Test token error response with description."""
        response = create_token_error_response(
            error_code=OAuthErrorCode.INVALID_GRANT,
            description="The authorization code has expired",
        )

        import json

        body = json.loads(response.body)

        assert body["error"] == "invalid_grant"
        assert body["error_description"] == "The authorization code has expired"

    def test_token_error_response_with_uri(self):
        """Test token error response with error URI."""
        response = create_token_error_response(
            error_code=OAuthErrorCode.INVALID_CLIENT,
            description="Client authentication failed",
            uri="https://example.com/errors#invalid_client",
        )

        import json

        body = json.loads(response.body)

        assert body["error"] == "invalid_client"
        assert body["error_description"] == "Client authentication failed"
        assert body["error_uri"] == "https://example.com/errors#invalid_client"

    def test_token_error_response_headers(self):
        """Test that token error response has required headers per RFC 6749."""
        response = create_token_error_response(
            error_code=OAuthErrorCode.INVALID_REQUEST
        )

        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Pragma"] == "no-cache"

    def test_token_error_response_all_error_codes(self):
        """Test token error response works with all error codes."""
        import json

        for error_code in OAuthErrorCode:
            response = create_token_error_response(error_code=error_code)
            body = json.loads(response.body)
            assert body["error"] == error_code.value
