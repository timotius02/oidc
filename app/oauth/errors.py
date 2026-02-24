"""
OAuth 2.0 RFC 6749 compliant error handling.

This module provides error types and response utilities for OAuth 2.0
authorization server implementations as defined in RFC 6749.

References:
- Section 4.1.2.1: Authorization Error Response
- Section 5.2: Token Error Response
"""

from enum import Enum
from typing import Optional
from urllib.parse import quote

from fastapi.responses import RedirectResponse, JSONResponse


class OAuthErrorCode(str, Enum):
    """
    OAuth 2.0 error codes as defined in RFC 6749.

    Error codes for authorization endpoint (Section 4.1.2.1):
    - invalid_request
    - unauthorized_client
    - access_denied
    - unsupported_response_type
    - invalid_scope
    - server_error
    - temporarily_unavailable

    Additional error codes for token endpoint (Section 5.2):
    - invalid_client
    - invalid_grant
    - unsupported_grant_type
    """

    # Authorization endpoint errors
    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    ACCESS_DENIED = "access_denied"
    UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
    INVALID_SCOPE = "invalid_scope"
    SERVER_ERROR = "server_error"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"

    # Token endpoint errors (additional)
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"


class OAuthError(Exception):
    """
    Base OAuth error exception.

    This exception can be raised to indicate OAuth-related errors
    and can be converted to appropriate error responses.

    Attributes:
        error_code: The OAuth error code enum value
        description: Optional human-readable error description
        uri: Optional URI pointing to error documentation
        state: The state parameter from the original request (if any)
    """

    def __init__(
        self,
        error_code: OAuthErrorCode,
        description: Optional[str] = None,
        uri: Optional[str] = None,
        state: Optional[str] = None
    ):
        self.error_code = error_code
        self.description = description
        self.uri = uri
        self.state = state
        super().__init__(description or error_code.value)


def create_authorization_error_response(
    redirect_uri: str,
    error_code: OAuthErrorCode,
    description: Optional[str] = None,
    state: Optional[str] = None
) -> RedirectResponse:
    """
    Create a redirect response with OAuth error parameters.

    As per RFC 6749 Section 4.1.2.1, when an error occurs at the
    authorization endpoint, the server MUST redirect the user-agent
    back to the client's redirect URI with error parameters.

    Args:
        redirect_uri: The client's registered redirect URI
        error_code: The OAuth error code enum value
        description: Optional human-readable error description
        state: The state parameter from the original request (if provided)

    Returns:
        RedirectResponse (302) with error parameters in the query string

    Example:
        >>> response = create_authorization_error_response(
        ...     redirect_uri="https://client.example.com/callback",
        ...     error_code=OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE,
        ...     description="Only 'code' response type is supported",
        ...     state="xyz123"
        ... )
        >>> # Redirects to: https://client.example.com/callback?error=unsupported_response_type&error_description=...&state=xyz123
    """
    params = {"error": error_code.value}

    if description:
        params["error_description"] = description

    if state:
        params["state"] = state

    # Build the query string with URL-encoded values
    query_string = "&".join(
        f"{key}={quote(value, safe='')}"
        for key, value in params.items()
    )

    # Determine separator based on whether redirect_uri already has query params
    separator = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{separator}{query_string}"

    return RedirectResponse(location, status_code=302)


def create_token_error_response(
    error_code: OAuthErrorCode,
    description: Optional[str] = None,
    uri: Optional[str] = None
) -> JSONResponse:
    """
    Create a JSON error response for the token endpoint.

    As per RFC 6749 Section 5.2, when an error occurs at the token
    endpoint, the server MUST respond with HTTP 400 Bad Request and
    a JSON body containing the error details.

    Args:
        error_code: The OAuth error code enum value
        description: Optional human-readable error description
        uri: Optional URI pointing to error documentation

    Returns:
        JSONResponse with HTTP 400 status and appropriate headers

    Example:
        >>> response = create_token_error_response(
        ...     error_code=OAuthErrorCode.INVALID_GRANT,
        ...     description="The authorization code has expired"
        ... )
        >>> # Returns HTTP 400 with body: {"error": "invalid_grant", "error_description": "..."}
    """
    content = {"error": error_code.value}

    if description:
        content["error_description"] = description

    if uri:
        content["error_uri"] = uri

    return JSONResponse(
        status_code=400,
        content=content,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache"
        }
    )


def register_oauth_exception_handlers(app) -> None:
    """
    Register OAuth exception handlers with the FastAPI application.

    This function registers the OAuthError exception handler, keeping
    OAuth-specific error handling logic within the oauth module for
    better domain encapsulation.

    Args:
        app: The FastAPI application instance

    Example:
        >>> from fastapi import FastAPI
        >>> from app.oauth.errors import register_exception_handlers
        >>> app = FastAPI()
        >>> register_exception_handlers(app)
    """

    @app.exception_handler(OAuthError)
    async def oauth_error_handler(request, exc: OAuthError):
        """Handle OAuth errors and return proper error responses."""
        return create_token_error_response(
            error_code=exc.error_code,
            description=exc.description,
            uri=exc.uri
        )
